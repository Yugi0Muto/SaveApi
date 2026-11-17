#!/usr/bin/env bash
# Détection de malwares, installation et configuration guidées (aucune connaissance de YARA requise) :
#   A. liste de hashes : compare l'empreinte de chaque fichier ajouté/modifié à une liste publique
#      d'empreintes de malwares connus (abuse.ch MalwareBazaar), mise à jour chaque nuit ;
#   B. YARA : analyse le CONTENU des fichiers ajoutés/modifiés dans des répertoires choisis
#      (webshells, scripts malveillants, mineurs de cryptomonnaie, fichier de test EICAR…).
# Installe YARA 4.5.8 (dernière version stable) sur le manager, configure Wazuh (règles, réponse
# active, groupe feat-yara), planifie la mise à jour quotidienne et teste toute la chaîne.
# Guide complet : docs/YARA.md
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 06 "Détection de malwares (YARA + hashes)"
require_wazuh

explain <<'TXT'
YARA en 5 phrases :
  - YARA est un outil gratuit qui recherche des MOTIFS dans le contenu des fichiers.
  - Une « règle YARA » décrit un malware : « si le fichier contient ce texte ou cette suite d'octets,
    c'est probablement tel malware ». Exemple : un fichier PHP qui exécute une commande reçue par le web.
  - Wazuh surveille des répertoires (module FIM). Quand un fichier y apparaît ou change, le manager
    demande à l'agent concerné de l'analyser avec YARA (« réponse active »).
  - Si une règle correspond, l'agent le signale et une alerte de niveau 12 apparaît (règle 100511).
  - Le fichier n'est NI supprimé NI déplacé : c'est un outil de détection ; la décision reste humaine.
Ce que l'étape va faire :
  1. installer YARA sur ce serveur (pour valider les règles avant de les distribuer) ;
  2. vous demander quels répertoires analyser sur les agents ;
  3. configurer Wazuh, distribuer les règles aux agents du groupe « feat-yara » ;
  4. tester la chaîne complète (fichier de test EICAR, totalement inoffensif).
Sur chaque agent Linux concerné : bash agents/install_agent_linux.sh … --yara (installe YARA + le script).
TXT

ask_yes_no YARA_ENABLE "Activer l'analyse YARA ?" oui || true
explain <<'TXT'
Liste de hashes (indépendante de YARA) : chaque fichier ajouté/modifié dans un répertoire surveillé
par Wazuh a son empreinte SHA256 comparée à ~des centaines de milliers d'empreintes de malwares récents
publiées par abuse.ch (MalwareBazaar). Correspondance = alerte de niveau 14 (règle 100500).
Elle détecte uniquement des fichiers IDENTIQUES à un malware connu (pas de variante) ; YARA est
complémentaire. abuse.ch demande une clé gratuite (« Auth-Key ») : https://auth.abuse.ch/
TXT
ask_yes_no MALWARE_HASH_ENABLE "Activer la liste de hashes malveillants ?" oui || true
if [[ "$YARA_ENABLE" == non && "$MALWARE_HASH_ENABLE" == non ]]; then
  ossec_begin
  run "Désactivation de la réponse active YARA" ossec_conf unblock yara-command
  run "Désactivation de la réponse active YARA" ossec_conf unblock yara-active-response
  run "Retrait de la déclaration de la liste de hashes" ossec_conf unblock malware-list
  rules_deploy "-:$OSSEC_DIR/etc/rules/bundle_00_malware_rules.xml" "-:$OSSEC_DIR/etc/decoders/bundle_malware_decoders.xml" || die "Retrait refusé par Wazuh."
  ossec_commit
  run "Retrait de la mise à jour planifiée" rm -f /etc/cron.d/wazuh-bundle-malware
  log_ok "Détection de malwares désactivée."; exit 0
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- 1. YARA sur le manager
if [[ "$YARA_ENABLE" == oui ]]; then
  section "1. Installation de YARA sur ce serveur"
  bash "$BUNDLE_ROOT/tools/install_yara.sh" || die "Installation de YARA en échec (voir ci-dessus)."
  YARA_BIN="$(command -v /usr/local/bin/yara || command -v yara)"

  section "2. Répertoires analysés sur les agents"
  explain <<'TXT'
Analyser TOUT le disque serait trop lent. On analyse les endroits où un attaquant dépose ses fichiers :
  /var/www               fichiers des sites web (webshells)
  /tmp /var/tmp /dev/shm répertoires temporaires, utilisés pour lancer des outils malveillants
  /home                  dossiers des utilisateurs
Surveillance « temps réel » = analyse immédiate (idéal pour les petits répertoires très exposés).
Surveillance « planifiée » = lors du contrôle périodique (gros répertoires : économise les ressources).
TXT
  ask YARA_DIRS_REALTIME "Répertoires analysés en TEMPS RÉEL (séparés par des espaces)" "/var/www /tmp /var/tmp /dev/shm" v_abs_paths
  ask YARA_DIRS_SCHEDULED "Répertoires analysés au contrôle PLANIFIÉ (vide si aucun)" "/home" ""
  [[ -z "$YARA_DIRS_SCHEDULED" ]] || v_abs_paths "$YARA_DIRS_SCHEDULED" >/dev/null || die "Répertoires planifiés invalides : relancer l'étape."
  ask YARA_MAX_SIZE_MB "Taille maximale d'un fichier analysé (Mo) — au-delà il est ignoré" 100 "v_int 1 2048"

  section "3. Règles YARA supplémentaires (facultatif)"
  explain <<'TXT'
Le bundle fournit des règles de base (configs/yara/bundle_rules.yar : EICAR, webshells PHP,
reverse shells, mineurs de cryptomonnaie). Vous pouvez y ajouter des règles publiques, par URL
d'un fichier .yar brut. Chaque fichier est COMPILÉ avant d'être accepté ; un fichier invalide est
ignoré et signalé. Exemple reconnu (Florian Roth, signature-base) :
  https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar
Attention : plus de règles = plus de détections mais aussi plus de faux positifs à examiner.
TXT
  ask YARA_SOURCES "URL de fichiers de règles .yar supplémentaires (séparées par des espaces, vide si aucune)" "" ""
  for u in $YARA_SOURCES; do [[ "$u" =~ ^https:// ]] || die "« $u » : seules les URL https:// sont acceptées. Relancer l'étape."; done
  run "Installation des règles de base du bundle" install -D -m 644 "$BUNDLE_ROOT/configs/yara/bundle_rules.yar" "$STATE_DIR/yara_base_rules.yar"
  run "Compilation des règles de base (contrôle)" "$YARA_BIN" -w "$STATE_DIR/yara_base_rules.yar" /dev/null
fi

if [[ "$MALWARE_HASH_ENABLE" == oui ]]; then
  section "Liste de hashes : source"
  ask MALWARE_HASH_URL "URL de la liste d'empreintes SHA256" "https://bazaar.abuse.ch/export/txt/sha256/recent/" v_nonempty
  if ! secret_get ABUSECH_AUTH_KEY >/dev/null; then
    if ask_yes_no ABUSECH_HAS_KEY "Avez-vous une clé Auth-Key abuse.ch (gratuite, https://auth.abuse.ch/) ?" non; then
      ask_secret ABUSECH_AUTH_KEY "Clé Auth-Key abuse.ch"
    else
      log_warn "Sans clé, abuse.ch peut refuser le téléchargement : la mise à jour le signalera chaque nuit (journal /var/log/wazuh-bundle/malware.log)."
    fi
  fi
fi

# ---------------------------------------------------------------- 4. Configuration Wazuh
section "4. Configuration de Wazuh"
install -d -o wazuh -g wazuh "$OSSEC_DIR/etc/lists"
if [[ ! -s "$OSSEC_DIR/etc/lists/malware-sha256" ]]; then
  # Une liste CDB vide est refusée par Wazuh : entrée factice (aucun fichier n'a cette empreinte)
  echo "0000000000000000000000000000000000000000000000000000000000000000:placeholder" > "$TMP/list"
  run "Création d'une liste de hashes initiale (remplie par la mise à jour)" install -o wazuh -g wazuh -m 660 "$TMP/list" "$OSSEC_DIR/etc/lists/malware-sha256"
fi
# Expression régulière des répertoires analysés (pour les règles 100501/100502)
regex='^/__aucun__/'
[[ "$YARA_ENABLE" == oui ]] && regex="$(dirs_to_regex $YARA_DIRS_REALTIME $YARA_DIRS_SCHEDULED)"
log_info "Expression des répertoires analysés : $regex"
sed "s#__YARA_REGEX__#${regex//\\/\\\\}#g" "$BUNDLE_ROOT/configs/manager/malware_rules.xml" > "$TMP/malware_rules.xml"
grep -q "__YARA_REGEX__" "$TMP/malware_rules.xml" && die "Substitution de l'expression YARA incomplète."

ossec_begin
echo "<list>etc/lists/malware-sha256</list>" > "$TMP/list.xml"
run "Déclaration de la liste de hashes dans <ruleset>" ossec_conf block ruleset malware-list "$TMP/list.xml"
if [[ "$YARA_ENABLE" == oui ]]; then
  cat > "$TMP/cmd.xml" <<XML
<command>
  <name>yara_linux</name>
  <executable>yara.sh</executable>
  <extra_args>-yara_path auto -yara_rules /var/ossec/etc/shared/yara_rules.yar -max_size_mb ${YARA_MAX_SIZE_MB}</extra_args>
  <timeout_allowed>no</timeout_allowed>
</command>
XML
  cat > "$TMP/ar.xml" <<'XML'
<active-response>
  <disabled>no</disabled>
  <command>yara_linux</command>
  <location>local</location>
  <rules_id>100501,100502</rules_id>
</active-response>
XML
  run "Commande de réponse active yara_linux" ossec_conf block ossec_config yara-command "$TMP/cmd.xml"
  run "Réponse active : analyse YARA sur les règles 100501/100502" ossec_conf block ossec_config yara-active-response "$TMP/ar.xml"
else
  run "Pas de YARA : retrait de la commande" ossec_conf unblock yara-command
  run "Pas de YARA : retrait de la réponse active" ossec_conf unblock yara-active-response
fi
if ! rules_deploy "$TMP/malware_rules.xml:$OSSEC_DIR/etc/rules/bundle_00_malware_rules.xml" \
                  "$BUNDLE_ROOT/configs/manager/malware_decoders.xml:$OSSEC_DIR/etc/decoders/bundle_malware_decoders.xml"; then
  ossec_restore; die "Configuration refusée par Wazuh : règles et ossec.conf restaurés."
fi
if ! wazuh_restart; then ossec_restore; wazuh_restart || true; die "Le manager ne démarre pas : ossec.conf restauré."; fi

# ---------------------------------------------------------------- 5. Groupe feat-yara
if [[ "$YARA_ENABLE" == oui ]]; then
  section "5. Groupe d'agents feat-yara"
  { echo "<!-- Généré par wazuh-bundle (étape 06) : répertoires analysés par YARA. Modifier : relancer l'étape 06. -->"
    echo "<agent_config os=\"Linux\">"; echo "  <syscheck>"
    for d in $YARA_DIRS_REALTIME; do echo "    <directories check_all=\"yes\" realtime=\"yes\">${d}</directories>"; done
    for d in $YARA_DIRS_SCHEDULED; do echo "    <directories check_all=\"yes\">${d}</directories>"; done
    echo "  </syscheck>"; echo "</agent_config>"; } > "$TMP/feat-yara.conf"
  run "Configuration du groupe feat-yara" cat "$TMP/feat-yara.conf"
  if ! output_has "^[[:space:]]*feat-yara \(" "$OSSEC_DIR/bin/agent_groups" -l; then
    run "Création du groupe feat-yara" "$OSSEC_DIR/bin/agent_groups" -a -g feat-yara -q
  fi
  run "Installation de la configuration du groupe" install -o wazuh -g wazuh -m 660 "$TMP/feat-yara.conf" "$OSSEC_DIR/etc/shared/feat-yara/agent.conf"
  run "Vérification de la configuration centralisée" "$OSSEC_DIR/bin/verify-agent-conf"
fi

# ---------------------------------------------------------------- 6. Mise à jour quotidienne
section "6. Mise à jour quotidienne des hashes et des règles"
run "Installation de l'outil de mise à jour" install -m 750 "$BUNDLE_ROOT/tools/update_malware.sh" /usr/local/sbin/wazuh-bundle-update-malware
printf '# wazuh-bundle (étape 06) : mise à jour quotidienne des hashes malveillants et des règles YARA\n30 3 * * * root /usr/local/sbin/wazuh-bundle-update-malware >> /var/log/wazuh-bundle/malware.log 2>&1\n' > "$TMP/cron"
run "Planification quotidienne (03:30)" install -m 644 "$TMP/cron" /etc/cron.d/wazuh-bundle-malware
mkdir -p "$LOG_DIR"
if ! run --allow-fail "Première mise à jour (téléchargements)" /usr/local/sbin/wazuh-bundle-update-malware; then
  if (( RUN_RC == 2 )); then
    log_warn "Mise à jour PARTIELLE : une source n'a pas pu être utilisée (détail ci-dessus). Les règles de base sont en place."
    confirm "Continuer malgré tout (la mise à jour sera retentée chaque nuit) ?" || die "Arrêt : corriger l'accès aux sources puis relancer l'étape 06."
  else die "La mise à jour a échoué (voir ci-dessus)."; fi
fi

# ---------------------------------------------------------------- 7. Tests
section "7. Tests de la chaîne de détection"
if [[ "$YARA_ENABLE" == oui ]]; then
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar test.txt"
  run "Test 1 : les règles distribuées détectent le fichier de test EICAR" "$YARA_BIN" -w "$OSSEC_DIR/etc/shared/feat-yara/yara_rules.yar" "$TMP/eicar test.txt"
  grep -q EICAR <<< "$RUN_OUTPUT" || die "Les règles distribuées ne détectent pas EICAR."
  echo "100511|wazuh-yara: INFO - Scan result: EICAR_Test_File /var/www/html/eicar test.txt" > "$TMP/t.txt"
  echo "100512|wazuh-yara: ERROR - binaire yara introuvable sur l'agent" >> "$TMP/t.txt"
  logtest_file "$TMP/t.txt" || die "Le manager ne transforme pas un résultat YARA en alerte : voir ci-dessus."
fi
log_ok "Détection de malwares configurée."
cat <<TXT

  Test réel (recette, RECETTE.md n°11) sur un agent Linux du groupe feat-yara :
    printf '%s' 'X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /tmp/eicar.txt
  -> alerte 100511 (niveau 12) dans le dashboard en quelques secondes. Supprimer ensuite le fichier.
  Journal des mises à jour : /var/log/wazuh-bundle/malware.log
TXT
