#!/usr/bin/env bash
# Recette automatique du serveur (lecture seule : ne modifie rien).
# Vérifie chaque élément configuré par les étapes précédentes, selon les réponses données :
# services, ports, configuration Wazuh, règles (rejouées avec wazuh-logtest), indexer et rétention,
# détection de malwares, e-mail, SMS, Grafana, sauvegardes, agents. Chaque échec indique l'étape à relancer.
# Code retour 0 = aucun échec.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 99 "Recette automatique"
P=0; F=0; W=0
pass() { log_ok "$*"; P=$((P+1)); }
fail() { log_err "$*"; F=$((F+1)); }
warn() { log_warn "$*"; W=$((W+1)); }
check() { # check "libellé OK" "libellé échec (piste)" commande...
  local okmsg="$1" komsg="$2"; shift 2
  echo "  ${DIM}\$ $*${NC}"
  if "$@" >/dev/null 2>&1; then pass "$okmsg"; else fail "$komsg"; fi
}
a() { ans_get "$1"; }

section "Services"
for s in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
  check "$s actif" "$s inactif : systemctl status $s ; journalctl -u $s -n 50" systemctl is-active --quiet "$s"
done
[[ "$(a SMS_ENABLE)" == oui ]] && check "wazuh-sms-alerter actif" "wazuh-sms-alerter inactif (étape 08) : journalctl -u wazuh-sms-alerter" systemctl is-active --quiet wazuh-sms-alerter
[[ "$(a EMAIL_ENABLE)" == oui ]] && check "postfix actif" "postfix inactif (étape 07)" systemctl is-active --quiet postfix
[[ "$(a GRAFANA_ENABLE)" == oui && "$(a GRAFANA_MODE)" == local ]] && check "grafana-server actif" "grafana-server inactif (étape 09)" systemctl is-active --quiet grafana-server

section "Ports en écoute"
for p in 1514 1515 443 9200 55000; do
  check "port $p en écoute" "port $p absent : le service correspondant est arrêté" output_has "[:.]${p}[[:space:]]" ss -tlnH
done

section "Configuration Wazuh"
if wazuh_config_check >/tmp/.wb-check 2>&1; then pass "configuration acceptée par Wazuh (analysisd/remoted/authd/execd -t)"
else fail "configuration refusée par Wazuh :"; sed 's/^/    /' /tmp/.wb-check | grep -iE "error|critical|✘" | head -10; fi
rm -f /tmp/.wb-check
check "enrôlement protégé par mot de passe" "enrôlement SANS mot de passe (étape 03)" grep -q "<use_password>yes</use_password>" "$OSSEC_CONF"
check "liste blanche du bundle présente" "liste blanche absente (étape 03)" ossec_conf hasblock whitelist
if [[ "$(a AR_ENABLE)" == oui ]]; then
  check "réponse active force brute SSH présente" "réponse active absente (étape 03)" ossec_conf hasblock ar-ssh-bruteforce
fi
for g in "$BUNDLE_ROOT"/configs/groups/*/; do g="$(basename "$g")"
  check "groupe $g configuré" "groupe $g absent (étape 03)" test -f "$OSSEC_DIR/etc/shared/$g/agent.conf"
done
check "règles du bundle déployées" "règles du bundle absentes (étape 04)" test -f "$OSSEC_DIR/etc/rules/bundle_10_rules.xml"
[[ -f "$OSSEC_DIR/etc/rules/bundle_rules.xml" ]] && fail "ancien fichier de règles v2 encore présent (doublons) : relancer l'étape 04"

section "Règles (rejouées avec wazuh-logtest)"
if logtest_file "$BUNDLE_ROOT/configs/manager/rule_tests.txt"; then pass "règles du bundle fonctionnelles"; else fail "au moins une règle ne se déclenche pas (étape 04)"; fi

section "Indexer et rétention"
if indexer_api GET /_cluster/health > /tmp/.wb-h 2>&1; then
  st="$(grep -o '"status":"[a-z]*"' /tmp/.wb-h | cut -d'"' -f4)"
  case "$st" in green) pass "cluster indexer : green";; yellow) warn "cluster indexer : yellow (acceptable en mono-nœud si des répliques sont configurées)";; *) fail "cluster indexer : ${st:-inconnu}";; esac
else fail "indexer injoignable ($(indexer_url)) : $(tail -2 /tmp/.wb-h | tr '\n' ' ')"; fi
rm -f /tmp/.wb-h
if [[ -n "$(a RET_ALERTS_DAYS)" ]]; then
  check "politique de rétention des alertes ($(a RET_ALERTS_DAYS) j)" "politique wazuh-bundle-alerts absente (étape 05)" indexer_api GET /_plugins/_ism/policies/wazuh-bundle-alerts
  check "purge des fichiers locaux planifiée" "purge locale non planifiée (étape 05)" test -f /etc/cron.d/wazuh-bundle-purge
else warn "rétention non configurée (étape 05) : le disque finira par se remplir"; fi
use=$(df --output=pcent /var | tail -1 | tr -dc '0-9'); (( use < 80 )) && pass "disque /var : ${use}%" || warn "disque /var : ${use}% (> 80 %) : revoir la rétention (étape 05)"

section "Détection de malwares"
if [[ "$(a YARA_ENABLE)" == oui || "$(a MALWARE_HASH_ENABLE)" == oui ]]; then
  check "règles malware déployées" "règles malware absentes (étape 06)" test -f "$OSSEC_DIR/etc/rules/bundle_00_malware_rules.xml"
  check "mise à jour quotidienne planifiée" "mise à jour non planifiée (étape 06)" test -f /etc/cron.d/wazuh-bundle-malware
  n=$(grep -c ':$' "$OSSEC_DIR/etc/lists/malware-sha256" 2>/dev/null || echo 0)
  [[ "$(a MALWARE_HASH_ENABLE)" == oui ]] && { (( n > 50 )) && pass "liste de hashes : $n empreintes" || warn "liste de hashes vide ou presque ($n) : voir /var/log/wazuh-bundle/malware.log"; }
fi
if [[ "$(a YARA_ENABLE)" == oui ]]; then
  check "YARA installé sur le manager" "YARA absent (étape 06)" bash -c 'command -v /usr/local/bin/yara || command -v yara'
  check "règles YARA distribuées (groupe feat-yara)" "règles YARA absentes (étape 06)" test -s "$OSSEC_DIR/etc/shared/feat-yara/yara_rules.yar"
  echo "100511|wazuh-yara: INFO - Scan result: EICAR_Test_File /tmp/eicar test.txt" > /tmp/.wb-yara
  if logtest_file /tmp/.wb-yara >/dev/null 2>&1; then pass "un résultat YARA produit bien l'alerte 100511"; else fail "le résultat YARA ne produit pas l'alerte 100511 (étape 06)"; fi
  rm -f /tmp/.wb-yara
fi

section "Alertes"
if [[ "$(a EMAIL_ENABLE)" == oui ]]; then
  check "e-mails activés dans Wazuh" "email_notification n'est pas à yes (étape 07)" grep -q "<email_notification>yes</email_notification>" "$OSSEC_CONF"
  q="$(postqueue -p 2>/dev/null | tail -1)"
  [[ "$q" == *"Mail queue is empty"* || -z "$q" ]] && pass "file d'attente Postfix vide" || warn "e-mails en attente dans Postfix : postqueue -p ($q)"
fi

section "Sauvegardes"
if [[ -n "$(a BACKUP_DIR)" ]]; then
  check "sauvegarde planifiée" "sauvegarde non planifiée (étape 10)" test -f /etc/cron.d/wazuh-bundle-backup
  last="$(find "$(a BACKUP_DIR)" -name 'wazuh-config-*.tar.gz' -mtime -2 2>/dev/null | head -1)"
  [[ -n "$last" ]] && pass "sauvegarde récente : $last" || warn "aucune sauvegarde de moins de 2 jours dans $(a BACKUP_DIR)"
else warn "sauvegarde non configurée (étape 10)"; fi

section "Agents"
"$OSSEC_DIR/bin/agent_control" -l 2>/dev/null | sed -n '1,40p'
act=$("$OSSEC_DIR/bin/agent_control" -l 2>/dev/null | grep -v "ID: 000" | grep -c "Active" || true)
(( act > 0 )) && pass "$act agent(s) actif(s)" || warn "aucun agent actif (installer les agents : agents/install_agent_*.sh)"

echo
network_flows
echo
echo "${BOLD}Résultat : $P OK, $W avertissement(s), $F échec(s)${NC}"
(( F == 0 ))
