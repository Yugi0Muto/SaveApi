#!/usr/bin/env bash
# wazuh-bundle-backup — archive quotidienne de la configuration (étape 10). Paramètres : answers.env.
set -euo pipefail
ANSWERS="${ANSWERS_FILE:-${BUNDLE_STATE_DIR:-/etc/wazuh-bundle}/answers.env}"
[[ -r "$ANSWERS" ]] || { echo "$(date '+%F %T') ERREUR : $ANSWERS illisible (étape 10 non exécutée ?)"; exit 1; }
# shellcheck disable=SC1090
source "$ANSWERS"
: "${BACKUP_DIR:?absent de answers.env : relancer l étape 10}" "${BACKUP_KEEP_DAYS:?absent de answers.env}"
umask 077; mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
F="$BACKUP_DIR/wazuh-config-$(hostname)-$(date +%Y%m%d-%H%M).tar.gz"
paths=(/var/ossec/etc /var/ossec/api/configuration /var/ossec/active-response/bin
       /etc/wazuh-indexer /etc/wazuh-dashboard /etc/filebeat /etc/wazuh-bundle /root/.wazuh-bundle
       /etc/postfix /etc/ssh/sshd_config.d/00-wazuh-bundle.conf /etc/cron.d
       /etc/grafana /var/lib/grafana/grafana.db /etc/systemd/system/wazuh-sms-alerter.service)
existing=(); for p in "${paths[@]}"; do [[ -e "$p" ]] && existing+=("$p"); done
# tar code 1 = un fichier a changé pendant la lecture (journal en cours d'écriture) : archive valide
rc=0; tar -czf "$F" "${existing[@]}" 2> "$F.err" || rc=$?
if (( rc > 1 )); then echo "$(date '+%F %T') ERREUR tar (code $rc) : $(cat "$F.err")"; rm -f "$F" "$F.err"; exit 1; fi
rm -f "$F.err"
tar -tzf "$F" >/dev/null || { echo "$(date '+%F %T') ERREUR : archive illisible $F"; exit 1; }
deleted=$(find "$BACKUP_DIR" -name 'wazuh-config-*.tar.gz' -mtime +"$BACKUP_KEEP_DAYS" -print -delete | wc -l)
echo "$(date '+%F %T') sauvegarde OK : $F ($(du -h "$F" | cut -f1)) ; $deleted ancienne(s) supprimée(s)"
logger "wazuh-bundle-backup: $F"
