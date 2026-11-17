#!/usr/bin/env bash
# tests/run_tests.sh — tests statiques et fonctionnels du bundle (sans Wazuh ; root non requis)
# Prérequis : bash, python3, xmllint (libxml2-utils), yara, jq ; shellcheck facultatif.
#   bash tests/run_tests.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
export LC_ALL=C.UTF-8
PASS=0; FAIL=0
t() { # t "nom" commande...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "  [OK]   $name"; PASS=$((PASS+1)); else echo "  [FAIL] $name"; echo "$out" | sed 's/^/         /' | head -20; FAIL=$((FAIL+1)); fi
}
need() { command -v "$1" >/dev/null || { echo "[SKIP-FATAL] outil manquant : $1"; exit 2; }; }
for c in python3 xmllint yara jq; do need "$c"; done
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SCRIPTS=(install.sh lib/*.sh steps/*.sh tools/*.sh agents/*.sh grafana/*.sh)
# Environnement isolé pour la bibliothèque (aucune écriture dans /etc ou /root)
export BUNDLE_STATE_DIR="$TMP/state" BUNDLE_SECRETS_DIR="$TMP/secrets" BUNDLE_LOG_DIR="$TMP/log"
L() { bash -c 'source lib/common.sh; '"$1"; }

echo "== 1. Syntaxe et qualité des scripts"
for f in "${SCRIPTS[@]}"; do t "bash -n $f" bash -n "$f"; done
t "python : ossec_conf.py, alerteur SMS" python3 -m py_compile lib/ossec_conf.py configs/manager/wazuh-sms-alerter.py
if command -v shellcheck >/dev/null; then t "shellcheck (niveau warning)" shellcheck -S warning -x "${SCRIPTS[@]}"; else echo "  [SKIP] shellcheck absent"; fi
t "aucune référence à bundle.conf ni au pare-feu nftables" bash -c '! grep -rnE "(^|[^-])bundle\.conf|load_conf|nft |nftables\.conf|render_nft" install.sh lib steps tools agents grafana'
t "chaque étape a un en-tête explicatif (install.sh --explain)" bash -c 'for f in steps/*.sh; do [[ "$(sed -n 2p "$f")" == "# "* ]] || { echo "$f"; exit 1; }; done'
t "les étapes s'arrêtent à la première erreur (set -e)" bash -c 'for f in steps/0*.sh steps/10_*.sh; do grep -q "^set -euo pipefail" "$f" || { echo "$f"; exit 1; }; done'
t "aucune erreur masquée par >/dev/null sur apt-get" bash -c '! grep -rnE "apt-get[^|]*>/dev/null" steps tools agents'

echo "== 2. XML et JSON"
wrap() { { echo "<r>"; cat "$1"; echo "</r>"; } | xmllint --noout -; }
t "bundle_rules.xml" xmllint --noout configs/manager/bundle_rules.xml
sed 's#__YARA_REGEX__#^(/var/www|/tmp)/#' configs/manager/malware_rules.xml > "$TMP/malware_rules.xml"
t "malware_rules.xml (après substitution)" xmllint --noout "$TMP/malware_rules.xml"
t "malware_decoders.xml" wrap configs/manager/malware_decoders.xml
for g in configs/groups/*/agent.conf; do t "groupe $(basename "$(dirname "$g")")" wrap "$g"; done
t "dashboard Grafana (JSON)" python3 -c "import json; d=json.load(open('configs/grafana/dashboards/wazuh-soc.json')); assert d['panels']"
t "identifiants de règles uniques, dans 100500-100599, avec description" python3 - "$TMP/malware_rules.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
ids = []
for f in ["configs/manager/bundle_rules.xml", sys.argv[1]]:
    for r in ET.parse(f).getroot().iter("rule"):
        i = int(r.get("id")); ids.append(i)
        assert 100500 <= i <= 100599, f"{i} hors plage"
        assert r.findtext("description"), f"{i} sans description"
dup = {i for i in ids if ids.count(i) > 1}
assert not dup, f"doublons : {dup}"
PY
t "chaque règle est documentée dans docs/REGLES.md" bash -c 'for i in $(grep -ho "rule id=\"[0-9]*\"" configs/manager/*.xml | grep -o "[0-9]*"); do grep -q "$i" docs/REGLES.md || { echo "règle $i absente de docs/REGLES.md"; exit 1; }; done'
t "rule_tests.txt : format ids|ligne" bash -c 'grep -v "^#" configs/manager/rule_tests.txt | grep -v "^$" | grep -vqE "^[0-9,]+\|.+" && exit 1 || exit 0'

echo "== 3. ossec_conf.py (modification contrôlée de ossec.conf)"
cp tests/fixtures/ossec.conf "$TMP/o.conf"
OC() { python3 lib/ossec_conf.py "$TMP/o.conf" "$@"; }
printf '<white_list>10.1.1.1</white_list>\n' > "$TMP/wl.xml"
printf '<active-response>\n  <command>firewall-drop</command>\n</active-response>\n' > "$TMP/ar.xml"
t "ajout d'un bloc balisé" OC block global whitelist "$TMP/wl.xml"
t "idempotent : 2e ajout = aucun doublon" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf block global whitelist '"$TMP"'/wl.xml | grep -q inchangé && [[ $(grep -c "10.1.1.1" '"$TMP"'/o.conf) == 1 ]]'
printf '<white_list>10.2.2.2</white_list>\n' > "$TMP/wl2.xml"
t "remplacement du bloc (relance avec d'autres valeurs)" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf block global whitelist '"$TMP"'/wl2.xml && ! grep -q 10.1.1.1 '"$TMP"'/o.conf && grep -q 10.2.2.2 '"$TMP"'/o.conf'
t "bloc dans la dernière section <ossec_config>" OC block ossec_config ar "$TMP/ar.xml"
t "set : valeur existante modifiée" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf set auth use_password yes && grep -q "<use_password>yes</use_password>" '"$TMP"'/o.conf'
t "set : balise d'une autre section non touchée (email_alert_level dans <alerts>)" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf set alerts email_alert_level 10 && grep -q "<log_alert_level>3</log_alert_level>" '"$TMP"'/o.conf && grep -q "<email_alert_level>10</email_alert_level>" '"$TMP"'/o.conf'
t "setmulti : plusieurs destinataires" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf setmulti global email_to a@x.fr b@y.fr && [[ $(grep -c "<email_to>" '"$TMP"'/o.conf) == 2 ]]'
t "les commentaires ne sont pas modifiés" bash -c 'grep -q "<!-- Choose between" '"$TMP"'/o.conf && grep -q "active-response options here" '"$TMP"'/o.conf'
t "résultat : XML valide" OC check
t "unblock" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf unblock ar && ! grep -q "BEGIN ar " '"$TMP"'/o.conf'
t "refus d'un bloc XML invalide (fichier inchangé)" bash -c 'cp '"$TMP"'/o.conf '"$TMP"'/o.before; printf "<a>" > '"$TMP"'/bad.xml; ! python3 lib/ossec_conf.py '"$TMP"'/o.conf block global x '"$TMP"'/bad.xml && cmp -s '"$TMP"'/o.conf '"$TMP"'/o.before'
t "refus d'une valeur contenant < > &" bash -c '! python3 lib/ossec_conf.py '"$TMP"'/o.conf set global email_from "a<b"'
t "section absente : erreur explicite" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/o.conf set inexistante x 1 2>&1 | grep -q "section <inexistante> absente"'
# Migration depuis la v2 : bloc non balisé (cause de doublons « yara_linux »)
cp tests/fixtures/ossec.conf "$TMP/v2.conf"
python3 - "$TMP/v2.conf" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = """  <!-- ===== wazuh-bundle : commandes et Active Response ===== -->
  <command>
    <name>yara_linux</name>
    <executable>yara.sh</executable>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>yara_linux</command>
    <rules_id>100501,100502</rules_id>
  </active-response>
"""
i = s.rfind("</ossec_config>"); s = s[:i] + old + s[i:]
s = s.replace("<list>etc/lists/audit-keys</list>", "<list>etc/lists/audit-keys</list>\n    <list>etc/lists/malware-sha256</list>")
open(p, "w").write(s)
PY
t "migration v2 : bloc non balisé et liste retirés" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/v2.conf migrate-v2 && ! grep -q yara_linux '"$TMP"'/v2.conf && ! grep -q malware-sha256 '"$TMP"'/v2.conf && python3 lib/ossec_conf.py '"$TMP"'/v2.conf check'
t "migration v2 : rejouable" bash -c 'python3 lib/ossec_conf.py '"$TMP"'/v2.conf migrate-v2 | grep -q "aucun reliquat"'

echo "== 4. Bibliothèque : exécution explicite, questions, secrets"
t "run : affiche la commande et « réussi »" bash -c 'out="$(bash -c "source lib/common.sh; run \"essai\" echo bonjour")"; grep -q "\$ echo bonjour" <<< "$out" && grep -q "│ bonjour" <<< "$out" && grep -q "réussi" <<< "$out"'
t "run : échec = arrêt, code retour et diagnostic affichés" bash -c 'out="$(bash -c "source lib/common.sh; run \"essai\" ls /nexistepas; echo APRES" 2>&1)"; rc=$?; (( rc != 0 )) && ! grep -q APRES <<< "$out" && grep -q "ÉCHEC (code retour 2)" <<< "$out" && grep -q "Arrêt de l.étape" <<< "$out"'
t "run --allow-fail : échec signalé, code renvoyé, pas d'arrêt" bash -c 'out="$(bash -c "source lib/common.sh; run --allow-fail \"essai\" false; echo RC=\$?" 2>&1)"; grep -q "RC=1" <<< "$out" && grep -q "toléré explicitement" <<< "$out"'
t "run --secret : arguments masqués" bash -c 'out="$(bash -c "source lib/common.sh; run --secret \"essai\" echo MOTDEPASSE" 2>&1)"; grep -q "arguments masqués" <<< "$out" && ! grep -q "\$ echo MOTDEPASSE" <<< "$out"'
t "run : diagnostic commande introuvable (127)" bash -c 'bash -c "source lib/common.sh; run --allow-fail x commande_inexistante_42" 2>&1 | grep -q "introuvable"'
t "run : diagnostic connexion refusée" bash -c 'bash -c "source lib/common.sh; run --allow-fail x bash -c \"echo curl: Connection refused; exit 7\"" 2>&1 | grep -q "n.écoute pas"'
t "ask : valeur saisie + validation (redemande si invalide)" bash -c 'printf "999.1.1.1\n10.0.0.5\n" | bash -c "source lib/common.sh; ask IPX \"IP\" \"\" v_ipv4 >/dev/null 2>&1; echo \$IPX" | grep -qx 10.0.0.5'
t "ask : réponse mémorisée puis proposée par défaut" bash -c 'printf "\n" | bash -c "source lib/common.sh; ask IPX \"IP\" \"\" v_ipv4 >/dev/null 2>&1; echo \$IPX" | grep -qx 10.0.0.5'
t "ask : mode non interactif = réponse mémorisée" bash -c 'BUNDLE_NONINTERACTIVE=1 bash -c "source lib/common.sh; ask IPX \"IP\" \"\" v_ipv4 >/dev/null; echo \$IPX" </dev/null | grep -qx 10.0.0.5'
t "ask : mode non interactif sans valeur = refus" bash -c '! BUNDLE_NONINTERACTIVE=1 bash -c "source lib/common.sh; ask INCONNU \"x\" \"\" v_nonempty" </dev/null >/dev/null 2>&1'
t "ask_yes_no" bash -c 'printf "oui\n" | bash -c "source lib/common.sh; ask_yes_no YN \"?\" non >/dev/null && echo O" | grep -qx O'
t "ask_choice : par numéro" bash -c 'printf "2\n" | bash -c "source lib/common.sh; ask_choice CH \"?\" a \"a|A\" \"b|B\" >/dev/null; echo \$CH" | grep -qx b'
t "answers.env : 600 et relisible" bash -c '[[ "$(stat -c %a "$BUNDLE_STATE_DIR/answers.env")" == 600 ]] && bash -c "source lib/common.sh; [[ \$(ans_get CH) == b ]]"'
t "secrets : caractères spéciaux conservés, fichier 600" bash -c 'bash -c "source lib/common.sh; secret_set K \"a b\\\"c\\\$d'"'"'e\"; [[ \"\$(secret_get K)\" == \"a b\\\"c\\\$d'"'"'e\" ]]" && [[ "$(stat -c %a "$BUNDLE_SECRETS_DIR/secrets.env")" == 600 ]]'
t "validateurs IP/CIDR/e-mail/téléphone" L 'v_ip_list "10.0.0.1 10.0.0.0/24" && ! v_ip_or_cidr 10.0.0.0/33 >/dev/null && v_email_list "a@b.fr c@d.org" && ! v_email x >/dev/null && v_phone_list "+24101020304" && ! v_phone_list 0601 >/dev/null'
t "dirs_to_regex : échappement" bash -c '[[ "$(bash -c "source lib/common.sh; dirs_to_regex /var/www/ /tmp /home/a.b")" == "^(/var/www|/tmp|/home/a\\.b)/" ]]'
t "regex YARA générée compatible PCRE (python re)" python3 -c "
import re; r=re.compile(r'^(/var/www|/tmp|/home/a\.b)/'); assert r.search('/var/www/x.php') and r.search('/tmp/a') and not r.search('/home/aXb/f') and not r.search('/etc/passwd')"
t "flux réseau : tableau généré depuis les réponses" bash -c 'bash -c "source lib/common.sh; ans_set MANAGER_IP 10.9.9.9; ans_set GRAFANA_MODE remote; ans_set GRAFANA_REMOTE_IPS 10.9.9.60; network_flows" | grep -q "10.9.9.60" '

echo "== 4b. Redémarrage du manager (régression : wazuh-control status renvoie 1 si un démon optionnel est arrêté)"
mkdir -p "$TMP/fw/bin" "$TMP/fw/logs" "$TMP/fbin"; : > "$TMP/fw/logs/ossec.log"
printf '#!/bin/sh\nexit 0\n' > "$TMP/fbin/systemctl"
cat > "$TMP/fw/bin/wazuh-control" <<'EOF'
#!/bin/sh
printf 'wazuh-clusterd not running...\nwazuh-modulesd is running...\nwazuh-remoted is running...\nwazuh-analysisd is running...\nwazuh-maild not running...\nwazuh-db is running...\n'
exit 1
EOF
chmod +x "$TMP/fbin/systemctl" "$TMP/fw/bin/wazuh-control"
t "wazuh_restart : démons optionnels arrêtés = manager considéré actif (set -euo pipefail)" \
  env PATH="$TMP/fbin:$PATH" OSSEC_DIR="$TMP/fw" bash -c 'set -euo pipefail; source lib/common.sh; wazuh_restart'
sed -i 's/wazuh-analysisd is running/wazuh-analysisd not running/' "$TMP/fw/bin/wazuh-control"
t "wazuh_restart : analysisd arrêté = échec détecté" bash -c '! env PATH="'"$TMP"'/fbin:$PATH" OSSEC_DIR="'"$TMP"'/fw" timeout 200 bash -c "source lib/common.sh; sleep() { :; }; wazuh_restart" >/dev/null 2>&1'
t "output_has : ignore le code retour et ne coupe pas le tube" L 'output_has "b" bash -c "echo a; echo b; exit 3" && ! output_has "z" echo a && output_has "^x" bash -c "yes x | head -100000"'
t "aucun « commande | grep -q » dans les scripts (faux négatifs en pipefail)" bash -c '! grep -rnE "\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q" install.sh lib steps tools agents grafana --include=*.sh | grep -vE "^[^:]+:[0-9]+:[[:space:]]*#"'

echo "== 5. E-mail : paramètres Postfix des 3 modes"
E() { bash -c 'source lib/email.sh; postfix_settings '"$*"; }
t "gmail : 587, TLS vérifié, authentification" bash -c 'o="$(bash -c "source lib/email.sh; postfix_settings gmail smtp.gmail.com 587 verify oui")"; grep -qx "relayhost = \[smtp.gmail.com\]:587" <<< "$o" && grep -qx "smtp_tls_security_level = secure" <<< "$o" && grep -qx "smtp_sasl_auth_enable = yes" <<< "$o" && grep -qx "inet_interfaces = loopback-only" <<< "$o"'
t "entreprise SMTPS 465 : wrappermode" bash -c 'bash -c "source lib/email.sh; postfix_settings entreprise mail.x.fr 465 smtps oui" | grep -qx "smtp_tls_wrappermode = yes"'
t "entreprise STARTTLS sans vérification : encrypt" bash -c 'bash -c "source lib/email.sh; postfix_settings entreprise mail.x.fr 587 encrypt oui" | grep -qx "smtp_tls_security_level = encrypt"'
t "relais : pas d'authentification, TLS opportuniste" bash -c 'o="$(bash -c "source lib/email.sh; postfix_settings relais relay.x.local 25 may non")"; grep -qx "smtp_sasl_auth_enable = no" <<< "$o" && grep -qx "smtp_tls_security_level = may" <<< "$o" && ! grep -q sasl_password_maps <<< "$o"'
t "mode TLS inconnu refusé" bash -c '! bash -c "source lib/email.sh; postfix_settings relais h 25 bidon non" >/dev/null 2>&1'

echo "== 6. Règles YARA de base"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar test.txt"
printf '<?php eval(base64_decode($_POST["x"])); ?>' > "$TMP/shell.php"
echo "bonjour" > "$TMP/clean.txt"
t "les règles compilent" yara -w configs/yara/bundle_rules.yar /dev/null
t "EICAR détecté" bash -c 'yara -w configs/yara/bundle_rules.yar "'"$TMP"'/eicar test.txt" | grep -q EICAR_Test_File'
t "webshell PHP détecté" bash -c 'yara -w configs/yara/bundle_rules.yar '"$TMP"'/shell.php | grep -q PHP_Webshell'
t "fichier propre non détecté" bash -c '[[ -z "$(yara -w configs/yara/bundle_rules.yar '"$TMP"'/clean.txt)" ]]'

echo "== 7. Réponse active yara.sh (agent)"
run_ar() { # run_ar fichier [max_mb] -> écrit dans $TMP/ar.log
  jq -nc --arg f "$1" --arg r "$ROOT/configs/yara/bundle_rules.yar" --arg m "${2:-100}" \
    '{command:"add",parameters:{extra_args:["-yara_path","auto","-yara_rules",$r,"-max_size_mb",$m],alert:{syscheck:{path:$f}}}}' \
   | YARA_LOG_FILE="$TMP/ar.log" bash agents/yara.sh
}
: > "$TMP/ar.log"
t "EICAR (chemin avec espace) : détection" run_ar "$TMP/eicar test.txt"
t "ligne au format du décodeur" grep -Eq "^wazuh-yara: INFO - Scan result: EICAR_Test_File $TMP/eicar test.txt\$" "$TMP/ar.log"
: > "$TMP/ar.log"; run_ar "$TMP/clean.txt"; run_ar "$TMP/absent.txt"
t "rien pour un fichier propre ou absent" test ! -s "$TMP/ar.log"
head -c 2097152 /dev/zero > "$TMP/big.bin"; cat "$TMP/eicar test.txt" >> "$TMP/big.bin"
: > "$TMP/ar.log"; run_ar "$TMP/big.bin" 1
t "fichier plus gros que max_size_mb ignoré" test ! -s "$TMP/ar.log"
: > "$TMP/ar.log"
jq -nc '{command:"add",parameters:{extra_args:["-yara_path","auto","-yara_rules","/nexiste/pas.yar"],alert:{syscheck:{path:"/etc/hostname"}}}}' | YARA_LOG_FILE="$TMP/ar.log" bash agents/yara.sh
t "règles absentes : erreur explicite (alerte 100512)" grep -q "wazuh-yara: ERROR - règles YARA introuvables" "$TMP/ar.log"
t "décodeurs (PCRE2) compatibles avec la sortie, y compris les espaces" python3 - "$TMP/ar.log" <<'PY'
import re
r = re.compile(r"wazuh-yara: (INFO) - Scan result: (\S+) (.+)$")
m = r.search("wazuh-yara: INFO - Scan result: EICAR_Test_File /var/www/a b.txt")
assert m and m.group(2) == "EICAR_Test_File" and m.group(3) == "/var/www/a b.txt"
e = re.compile(r"wazuh-yara: (ERROR) - (.+)$")
assert e.search(open(__import__("sys").argv[1]).read())
PY

echo "== 8. Mise à jour hashes + YARA (simulation locale)"
mkdir -p "$TMP/sim/out"
python3 -c "
import hashlib
print('# test'); [print(hashlib.sha256(str(i).encode()).hexdigest().upper()) for i in range(80)]" > "$TMP/sim/hashes.txt"
printf 'rule Extra_Ok { condition: false }\n' > "$TMP/sim/ok.yar"
printf 'rule Cassee { condition: \n' > "$TMP/sim/bad.yar"
cat > "$TMP/sim/answers.env" <<ENV
MALWARE_HASH_ENABLE=oui
MALWARE_HASH_URL=file://$TMP/sim/hashes.txt
YARA_ENABLE=oui
YARA_SOURCES="file://$TMP/sim/ok.yar file://$TMP/sim/bad.yar file://$TMP/sim/absent.yar"
ENV
run_upd() { ANSWERS_FILE="$TMP/sim/answers.env" SECRETS_FILE="$TMP/sim/none" BASE_RULES="$ROOT/configs/yara/bundle_rules.yar" \
  LIST="$TMP/sim/out/list" SHARED="$TMP/sim/out/yara.yar" LIST_OPTS="-m 640" SHARED_OPTS="-m 660" \
  RESTART_CMD="touch $TMP/sim/restarted" bash tools/update_malware.sh > "$TMP/sim/upd.log" 2>&1; echo $? > "$TMP/sim/rc"; }
run_upd
t "code 2 (partiel) car une source est cassée et une absente" grep -qx 2 "$TMP/sim/rc"
t "chaque source ignorée est expliquée dans le journal" bash -c 'grep -q "ne compile pas" '"$TMP"'/sim/upd.log && grep -q "injoignable" '"$TMP"'/sim/upd.log'
t "liste de hashes : 80 entrées au format CDB" bash -c '[[ "$(wc -l < '"$TMP"'/sim/out/list)" == 80 ]] && grep -Eq "^[a-f0-9]{64}:$" '"$TMP"'/sim/out/list'
t "source YARA valide ajoutée, cassée ignorée" bash -c 'grep -q Extra_Ok '"$TMP"'/sim/out/yara.yar && ! grep -q Cassee '"$TMP"'/sim/out/yara.yar'
t "jeu final YARA compile" yara -w "$TMP/sim/out/yara.yar" /dev/null
t "manager redémarré (liste modifiée)" test -f "$TMP/sim/restarted"
sed -i "s#^YARA_SOURCES=.*#YARA_SOURCES=\"file://$TMP/sim/ok.yar\"#" "$TMP/sim/answers.env"
rm -f "$TMP/sim/restarted"; run_upd
t "2e exécution : code 0, pas de redémarrage inutile" bash -c 'grep -qx 0 '"$TMP"'/sim/rc && test ! -f '"$TMP"'/sim/restarted'
python3 -c "
import zipfile; z=zipfile.ZipFile('$TMP/sim/h.zip','w'); z.write('$TMP/sim/hashes.txt','full_sha256.txt'); z.close()"
sed -i "s#^MALWARE_HASH_URL=.*#MALWARE_HASH_URL=file://$TMP/sim/h.zip#" "$TMP/sim/answers.env"; rm -f "$TMP/sim/out/list"; run_upd
t "export ZIP de MalwareBazaar accepté" bash -c '[[ "$(wc -l < '"$TMP"'/sim/out/list)" == 80 ]]'

echo "== 9. Purge des fichiers locaux et sauvegarde"
mkdir -p "$TMP/ossec/alerts/2020/Jan" "$TMP/ossec/alerts/2026/Nov"
touch -d '400 days ago' "$TMP/ossec/alerts/2020/Jan/ossec-alerts-01.json.gz"
touch "$TMP/ossec/alerts/2026/Nov/ossec-alerts-16.json.gz" "$TMP/ossec/alerts/alerts.json"
touch -d '400 days ago' "$TMP/ossec/alerts/alerts.json"
printf 'RET_LOCAL_DAYS=180\nRET_LOCAL_ARCHIVES_DAYS=30\n' > "$TMP/purge.env"
P() { ANSWERS_FILE="$TMP/purge.env" OSSEC_LOGS="$TMP/ossec" bash tools/purge_local_logs.sh "$@"; }
t "simulation : rien supprimé" bash -c 'ANSWERS_FILE='"$TMP"'/purge.env OSSEC_LOGS='"$TMP"'/ossec bash tools/purge_local_logs.sh --dry-run | grep -q "simulation" && test -f '"$TMP"'/ossec/alerts/2020/Jan/ossec-alerts-01.json.gz'
P >/dev/null
t "fichier ancien supprimé, récent conservé" bash -c 'test ! -e '"$TMP"'/ossec/alerts/2020/Jan/ossec-alerts-01.json.gz && test -f '"$TMP"'/ossec/alerts/2026/Nov/ossec-alerts-16.json.gz'
t "fichier courant alerts.json jamais supprimé (même ancien)" test -f "$TMP/ossec/alerts/alerts.json"
t "sans réponses de l'étape 05 : erreur explicite" bash -c 'ANSWERS_FILE=/nexiste bash tools/purge_local_logs.sh 2>&1 | grep -q "étape 05"'

echo "== 10. Grafana : provision.sh (simulation, binaires factices)"
mkdir -p "$TMP/gbin" "$TMP/g/prov" "$TMP/g/dash" "$TMP/g/plugins"
printf '#!/bin/sh\nexit 0\n' > "$TMP/gbin/grafana-cli"; cp "$TMP/gbin/grafana-cli" "$TMP/gbin/systemctl"; chmod +x "$TMP/gbin/grafana-cli" "$TMP/gbin/systemctl"
printf -- '-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n' > "$TMP/g/ca.pem"
run_prov() {
  PATH="$TMP/gbin:$PATH" IDX_URL="https://127.0.0.1:1" RO_PW="pw123" CA_FILE="$TMP/g/ca.pem" DASH_SRC="$ROOT/configs/grafana/dashboards" \
  OPENSEARCH_DS_VERSION="2.19.0" DS_IS_DEFAULT="$1" GRAFANA_PROV_DIR="$TMP/g/prov" GRAFANA_DASH_DIR="$TMP/g/dash" \
  GRAFANA_PLUGINS_DIR="$TMP/g/plugins" GRAFANA_RESTART_WAIT=0 bash grafana/provision.sh
}
t "provision.sh s'exécute (Grafana factice)" run_prov false
t "datasource : URL, grafana_ro, CA fournie, pas de skipVerify" bash -c 'f='"$TMP"'/g/prov/datasources/wazuh-opensearch.yaml; grep -q "url: https://127.0.0.1:1" $f && grep -q "basicAuthUser: grafana_ro" $f && grep -q TESTCA $f && ! grep -qi skipverify $f'
t "provision.sh refuse un environnement incomplet" bash -c '! IDX_URL=x bash grafana/provision.sh >/dev/null 2>&1'

echo "== 11. Alerteur SMS (déduplication, niveau, plafond)"
t "test_sms.py" python3 tests/test_sms.py

echo "== 12. install.sh"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  for n in 00 01 02 03 04 05 06 07 08 09 10 99; do t "install.sh --explain $n" bash -c 'bash install.sh --explain '"$n"' | grep -q "Étape '"$n"'"'; done
else echo "  [SKIP] install.sh --explain (root requis)"; fi

echo; echo "Résultat : $PASS OK, $FAIL échec(s)"; (( FAIL == 0 ))
