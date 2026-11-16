#!/usr/bin/env bash
# tests/run_tests.sh — tests statiques et fonctionnels du bundle (sans Wazuh, sans root)
# Prérequis : bash, python3, xmllint (libxml2-utils), yara, jq ; shellcheck facultatif.
#   ./tests/run_tests.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
export LC_ALL=C.UTF-8
PASS=0; FAIL=0
t() { # t "nom" commande...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "  [OK]   $name"; PASS=$((PASS+1)); else echo "  [FAIL] $name"; echo "$out" | sed 's/^/         /' | head -15; FAIL=$((FAIL+1)); fi
}
need() { command -v "$1" >/dev/null || { echo "[SKIP-FATAL] outil manquant : $1"; exit 2; }; }
for c in python3 xmllint yara jq; do need "$c"; done
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SCRIPTS=(install.sh bash/lib/*.sh bash/manager/*.sh bash/agents/*.sh bash/grafana/*.sh)

echo "== 1. Syntaxe des scripts"
for f in "${SCRIPTS[@]}"; do t "bash -n $f" bash -n "$f"; done
t "python SMS compile" python3 -m py_compile configs/manager/wazuh-sms-alerter.py
if command -v shellcheck >/dev/null; then t "shellcheck (niveau warning)" shellcheck -S warning -x "${SCRIPTS[@]}"; else echo "  [SKIP] shellcheck absent"; fi

echo "== 2. XML et JSON"
wrap() { { echo "<r>"; cat "$1"; echo "</r>"; } | xmllint --noout -; }
sed 's#__YARA_REGEX__#^/(var/www|tmp)/#' configs/manager/bundle_rules.xml > "$TMP/rules.xml"
t "bundle_rules.xml" xmllint --noout "$TMP/rules.xml"
t "bundle_decoders.xml" wrap configs/manager/bundle_decoders.xml
t "manager_blocks.xml" wrap configs/manager/manager_blocks.xml
for g in configs/groups/*/agent.conf; do t "groupe $(basename "$(dirname "$g")")" wrap "$g"; done
t "dashboard Grafana (JSON)" python3 -c "import json,sys; d=json.load(open('configs/grafana/dashboards/wazuh-soc.json')); assert len(d['panels'])>0"
ids="$(grep -o 'rule id="[0-9]*"' configs/manager/bundle_rules.xml | sort | uniq -d)"
t "identifiants de règles uniques" test -z "$ids"

echo "== 3. Configuration"
t "bundle.conf.example sourçable" bash -c 'set -u; source bundle.conf.example; : "$MANAGER_IP" "$RETENTION_DAYS" "$SMS_MAX_PER_HOUR"'
t "load_conf refuse A_COMPLETER" bash -c 'cp bundle.conf.example '"$TMP"'/b.conf; BUNDLE_CONF='"$TMP"'/b.conf; source bash/lib/common.sh; ! (load_conf) 2>/dev/null'
t "secret_set/secret_get" bash -c 'source bash/lib/common.sh; SECRETS_DIR='"$TMP"'/s; SECRETS_FILE=$SECRETS_DIR/secrets.env; secret_set K "a b\"c\$d"; [[ "$(secret_get K)" == "a b\"c\$d" ]]'

# Commentaires : uniquement des lignes entières au-dessus des variables, jamais de # en fin de ligne
t "bundle.conf.example : pas de commentaire en fin de ligne" python3 - <<'PYEOF'
import re, sys
bad = [(n, l.rstrip()) for n, l in enumerate(open("bundle.conf.example", encoding="utf-8"), 1)
       if l.strip() and not l.lstrip().startswith("#") and not re.fullmatch(r'[A-Z_0-9]+="[^"]*"\s*', l)]
sys.exit("lignes non conformes : %s" % bad if bad else 0)
PYEOF
conf_with() { # conf_with fichier_sortie 'CLE=valeur'... -> bundle.conf valide + surcharges
  local out="$1"; shift; sed 's/A_COMPLETER/10.0.0.1/' bundle.conf.example > "$out"
  local kv; for kv in "$@"; do sed -i "s|^${kv%%=*}=.*|${kv%%=*}=\"${kv#*=}\"|" "$out"; done
}
try_conf() { BUNDLE_CONF="$1" bash -c 'source bash/lib/common.sh; load_conf'; }
refused() { ! BUNDLE_CONF="$1" bash -c 'source bash/lib/common.sh; load_conf' >/dev/null 2>&1; }
conf_with "$TMP/c_local.conf"
conf_with "$TMP/c_remote_ok.conf" GRAFANA_MODE=remote "GRAFANA_REMOTE_IPS=10.0.0.60/32 10.0.0.61"
conf_with "$TMP/c_remote_noip.conf" GRAFANA_MODE=remote
conf_with "$TMP/c_remote_badip.conf" GRAFANA_MODE=remote "GRAFANA_REMOTE_IPS=n-importe-quoi"
conf_with "$TMP/c_badmode.conf" GRAFANA_MODE=ailleurs
conf_with "$TMP/c_off.conf" GRAFANA_ENABLE=false GRAFANA_MODE=remote
t "Grafana local : conf valide" try_conf "$TMP/c_local.conf"
t "Grafana remote + IP : conf valide" try_conf "$TMP/c_remote_ok.conf"
t "Grafana remote sans IP : refusé" refused "$TMP/c_remote_noip.conf"
t "Grafana remote IP invalide : refusé" refused "$TMP/c_remote_badip.conf"
t "GRAFANA_MODE invalide : refusé" refused "$TMP/c_badmode.conf"
t "Grafana désactivé : GRAFANA_REMOTE_IPS non exigé" try_conf "$TMP/c_off.conf"
grep -v '^GRAFANA_MODE\|^GRAFANA_REMOTE_IPS' "$TMP/c_local.conf" > "$TMP/c_old.conf"
t "ancien bundle.conf (sans GRAFANA_MODE) = local" bash -c 'BUNDLE_CONF='"$TMP"'/c_old.conf; source bash/lib/common.sh; load_conf; grafana_is_local'

echo "== 3b. Pare-feu (génération des règles, sans les appliquer)"
fw() { BUNDLE_CONF="$1" bash -c 'source bash/lib/common.sh; source bash/lib/firewall_rules.sh; load_conf; render_nft_rules'; }
fw "$TMP/c_local.conf"     > "$TMP/fw_local.nft"
fw "$TMP/c_remote_ok.conf" > "$TMP/fw_remote.nft"
fw "$TMP/c_off.conf"       > "$TMP/fw_off.nft"
t "pare-feu local : 3000 ouvert aux admins, pas de 9200" bash -c 'grep -q "dport { 22, 443, 3000 }" '"$TMP"'/fw_local.nft && ! grep -q 9200 '"$TMP"'/fw_local.nft'
t "pare-feu remote : 3000 fermé" bash -c '! grep -q 3000 '"$TMP"'/fw_remote.nft && grep -q "dport { 22, 443 }" '"$TMP"'/fw_remote.nft'
t "pare-feu remote : 9200 limité à la machine Grafana" bash -c 'grep -q "set grafana4 .*10.0.0.60/32,10.0.0.61" '"$TMP"'/fw_remote.nft && grep -q "ip saddr @grafana4 tcp dport 9200 accept" '"$TMP"'/fw_remote.nft'
t "pare-feu Grafana désactivé : ni 3000 ni 9200" bash -c '! grep -Eq "3000|9200|grafana" '"$TMP"'/fw_off.nft'
if command -v nft >/dev/null && nft -c -f "$TMP/fw_local.nft" >/dev/null 2>&1; then
  for v in local remote off; do t "nft -c : règles $v valides" nft -c -f "$TMP/fw_$v.nft"; done
else echo "  [SKIP] nft absent ou non autorisé (vérification de syntaxe nftables)"; fi

echo "== 3c. Grafana : provision.sh (simulation, binaires factices)"
mkdir -p "$TMP/gbin" "$TMP/g/prov" "$TMP/g/dash" "$TMP/g/plugins"
printf '#!/bin/sh\nexit 0\n' > "$TMP/gbin/grafana-cli"; cp "$TMP/gbin/grafana-cli" "$TMP/gbin/systemctl"; chmod +x "$TMP/gbin/grafana-cli" "$TMP/gbin/systemctl"
printf -- '-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n' > "$TMP/g/ca.pem"
run_prov() { # run_prov <DS_IS_DEFAULT>
  PATH="$TMP/gbin:$PATH" IDX_URL="https://127.0.0.1:1" RO_PW="pw123" CA_FILE="$TMP/g/ca.pem" DASH_SRC="$ROOT/configs/grafana/dashboards" \
  OPENSEARCH_DS_VERSION="2.19.0" DS_IS_DEFAULT="$1" GRAFANA_PROV_DIR="$TMP/g/prov" GRAFANA_DASH_DIR="$TMP/g/dash" \
  GRAFANA_PLUGINS_DIR="$TMP/g/plugins" GRAFANA_RESTART_WAIT=0 bash bash/grafana/provision.sh
}
t "provision.sh s'exécute (Grafana factice)" run_prov false
t "datasource : URL indexer, utilisateur grafana_ro, CA fournie, pas de skipVerify" bash -c 'f='"$TMP"'/g/prov/datasources/wazuh-opensearch.yaml; grep -q "url: https://127.0.0.1:1" $f && grep -q "basicAuthUser: grafana_ro" $f && grep -q "TESTCA" $f && ! grep -qi skipverify $f'
t "datasource : isDefault suit DS_IS_DEFAULT" grep -q "isDefault: false" "$TMP/g/prov/datasources/wazuh-opensearch.yaml"
t "dashboard copié + provider déclaré" bash -c '[[ -s '"$TMP"'/g/dash/wazuh-soc.json ]] && grep -q "path: '"$TMP"'/g/dash" '"$TMP"'/g/prov/dashboards/wazuh.yaml'
t "provision.sh refuse un environnement incomplet" bash -c '! IDX_URL=x bash bash/grafana/provision.sh >/dev/null 2>&1'
if python3 -c "import yaml" 2>/dev/null; then
  t "datasource : YAML valide" python3 -c "import yaml; d=yaml.safe_load(open('$TMP/g/prov/datasources/wazuh-opensearch.yaml')); assert d['datasources'][0]['uid']=='wazuh-opensearch'"
else echo "  [SKIP] PyYAML absent (validation YAML)"; fi

echo "== 4. YARA"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.txt"
printf '<?php eval(base64_decode($_POST["x"])); ?>' > "$TMP/shell.php"
echo "bonjour" > "$TMP/clean.txt"
t "règles YARA compilent" yara -w configs/yara/bundle_rules.yar /dev/null
t "EICAR détecté" bash -c 'yara -w configs/yara/bundle_rules.yar '"$TMP"'/eicar.txt | grep -q EICAR_Test_File'
t "webshell PHP détecté" bash -c 'yara -w configs/yara/bundle_rules.yar '"$TMP"'/shell.php | grep -q PHP_Webshell'
t "fichier propre non détecté" bash -c '[[ -z "$(yara -w configs/yara/bundle_rules.yar '"$TMP"'/clean.txt)" ]]'

echo "== 5. Script Active Response yara.sh"
run_ar() { # run_ar fichier -> écrit dans $TMP/ar.log
  echo "{\"command\":\"add\",\"parameters\":{\"extra_args\":[\"-yara_path\",\"$(dirname "$(command -v yara)")\",\"-yara_rules\",\"$ROOT/configs/yara/bundle_rules.yar\"],\"alert\":{\"syscheck\":{\"path\":\"$1\"}}}}" \
   | YARA_LOG_FILE="$TMP/ar.log" bash bash/agents/yara.sh
}
: > "$TMP/ar.log"
t "yara.sh : exécution sur EICAR" run_ar "$TMP/eicar.txt"
t "yara.sh : résultat au format du décodeur" grep -Eq '^wazuh-yara: INFO - Scan result: EICAR_Test_File '"$TMP"'/eicar.txt$' "$TMP/ar.log"
: > "$TMP/ar.log"; run_ar "$TMP/clean.txt"; run_ar "$TMP/absent.txt"
t "yara.sh : rien pour fichier propre/absent" test ! -s "$TMP/ar.log"
t "décodeur (regex) compatible avec la sortie" python3 - "$TMP/eicar.txt" <<'PY'
import re,sys
line="wazuh-yara: INFO - Scan result: EICAR_Test_File /tmp/eicar.txt"
assert re.search(r"wazuh-yara: (\S+) - Scan result: (\S+) (\S+)", line)
PY

echo "== 6. Mise à jour hashes + YARA (simulation locale)"
mkdir -p "$TMP/sim"
python3 -c "
import hashlib
print('# test'); [print(hashlib.sha256(str(i).encode()).hexdigest().upper()) for i in range(80)]" > "$TMP/sim/hashes.txt"
printf 'MALWARE_HASH_URL="file://%s/sim/hashes.txt"\nABUSECH_AUTH_KEY=""\nBASE_RULES="%s/configs/yara/bundle_rules.yar"\n' "$TMP" "$ROOT" > "$TMP/sim/update.env"
printf 'rule Extra_Ok { condition: false }\n' > "$TMP/sim/ok.yar"
printf 'rule Cassee { condition: \n' > "$TMP/sim/bad.yar"
printf 'file://%s/sim/ok.yar\nfile://%s/sim/bad.yar\nfile://%s/sim/absent.yar\n' "$TMP" "$TMP" "$TMP" > "$TMP/sim/sources.txt"
mkdir -p "$TMP/sim/out"
run_upd() { ENV_FILE="$TMP/sim/update.env" SOURCES_FILE="$TMP/sim/sources.txt" LIST="$TMP/sim/out/list" SHARED="$TMP/sim/out/yara.yar" \
  LIST_OPTS="-m 640" SHARED_OPTS="-m 660" RESTART_CMD="touch $TMP/sim/restarted" bash bash/manager/update_malware.sh > "$TMP/sim/upd.log" 2>&1; }
t "update_malware.sh s'exécute" run_upd
t "liste de hashes : 80 entrées au format CDB" bash -c '[[ "$(wc -l < '"$TMP"'/sim/out/list)" == 80 ]] && grep -Eq "^[a-f0-9]{64}:$" '"$TMP"'/sim/out/list'
t "source YARA valide ajoutée" grep -q "Extra_Ok" "$TMP/sim/out/yara.yar"
t "source YARA cassée ignorée" bash -c '! grep -q Cassee '"$TMP"'/sim/out/yara.yar'
t "jeu final YARA compile" yara -w "$TMP/sim/out/yara.yar" /dev/null
t "manager redémarré (liste modifiée)" test -f "$TMP/sim/restarted"
rm -f "$TMP/sim/restarted"; run_upd
t "2e exécution : pas de redémarrage inutile" test ! -f "$TMP/sim/restarted"

echo "== 7. Daemon SMS (déduplication, niveau, plafond)"
t "test_sms.py" python3 tests/test_sms.py

echo; echo "Résultat : $PASS OK, $FAIL échec(s)"; (( FAIL == 0 ))
