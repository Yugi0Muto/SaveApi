#!/usr/bin/env bash
# Sauvegarde quotidienne de la CONFIGURATION (pas des alertes) : ossec.conf, règles, listes, groupes,
# certificats, configuration de l'indexer/dashboard/Grafana/Postfix/SSH, réponses et secrets du bundle.
# Permet de reconstruire le serveur à l'identique. Les archives contiennent des clés et mots de passe :
# leur copie hors du serveur doit être chiffrée.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 10 "Sauvegarde de la configuration"

explain <<'TXT'
Chaque nuit (02:30), une archive .tar.gz de la configuration est créée dans le dossier choisi.
Les archives plus anciennes que la durée choisie sont supprimées.
Le dossier est réservé à root (droits 700) : les archives contiennent des certificats et des mots de passe.
Important : une sauvegarde restée sur le serveur ne protège pas d'une panne de disque ; prévoir une
copie chiffrée ailleurs (NAS, autre site).
TXT
ask BACKUP_DIR "Dossier des sauvegardes" /var/backups/wazuh v_abs_paths
ask BACKUP_KEEP_DAYS "Conserver les sauvegardes combien de jours ?" 14 "v_int 1 3650"

run "Installation de l'outil de sauvegarde" install -m 750 "$BUNDLE_ROOT/tools/backup.sh" /usr/local/sbin/wazuh-bundle-backup
printf '# wazuh-bundle (étape 10) : sauvegarde quotidienne de la configuration\n30 2 * * * root /usr/local/sbin/wazuh-bundle-backup >> /var/log/wazuh-bundle/backup.log 2>&1\n' > /tmp/.wb-backup.cron
run "Planification quotidienne (02:30)" install -m 644 /tmp/.wb-backup.cron /etc/cron.d/wazuh-bundle-backup
rm -f /tmp/.wb-backup.cron
mkdir -p "$LOG_DIR"
run "Première sauvegarde" /usr/local/sbin/wazuh-bundle-backup
run "Contenu du dossier de sauvegarde" ls -lh "$BACKUP_DIR"
log_ok "Sauvegarde quotidienne à 02:30, conservation ${BACKUP_KEEP_DAYS} jours, dans $BACKUP_DIR"
log_warn "Mettre en place une copie CHIFFRÉE hors serveur (ex. rsync/sftp vers le serveur de sauvegarde)."
