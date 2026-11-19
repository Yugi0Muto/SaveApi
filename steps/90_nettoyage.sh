#!/usr/bin/env bash
# Nettoie le serveur pour repartir sur une installation neuve (après un échec de l'étape 02, par exemple).
# Deux niveaux au choix :
#   - wazuh   : désinstalle Wazuh (manager, indexer, dashboard, filebeat) et ce que le bundle a greffé
#               dessus (tâches planifiées, outils, service SMS). Les réponses déjà données sont gardées :
#               on relance directement l'étape 02.
#   - complet : idem + réponses et secrets du bundle, et en option Grafana, le swap et /etc/hosts.
# Avant toute suppression, la configuration et les secrets sont archivés dans /root (root uniquement).
# Jamais touchés : le durcissement SSH (étape 01), Postfix (étape 07), YARA, les journaux du bundle.
# Étape volontairement absente de « Tout exécuter » : elle ne se lance qu'à la demande.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 90 "Nettoyage pour une nouvelle installation"

WAZUH_PKGS=(wazuh-manager wazuh-indexer wazuh-dashboard filebeat)
WAZUH_DIRS=(/var/ossec /etc/wazuh-indexer /usr/share/wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer
            /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard
            /etc/filebeat /usr/share/filebeat /var/lib/filebeat /var/log/filebeat)
BUNDLE_FILES=(/etc/cron.d/wazuh-bundle-purge /etc/cron.d/wazuh-bundle-malware /etc/cron.d/wazuh-bundle-backup
              /usr/local/sbin/wazuh-bundle-purge-logs /usr/local/sbin/wazuh-bundle-update-malware
              /usr/local/sbin/wazuh-bundle-backup
              /etc/systemd/system/wazuh-sms-alerter.service /usr/local/bin/wazuh-sms-alerter.py)

pkg_present() { # paquet installé, même à moitié (échec d'installation)
  local st; st="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"
  [[ -n "$st" && "$st" != *not-installed* && "$st" != "unknown ok not-installed" ]]
}

# ── État actuel ──────────────────────────────────────────────────────────────────────────────
section "Ce qui est présent sur ce serveur"
found=0
for p in "${WAZUH_PKGS[@]}"; do
  if pkg_present "$p"; then echo "  - paquet $p ($(dpkg-query -W -f='${Version} ${Status}' "$p"))"; found=1; fi
done
for d in "${WAZUH_DIRS[@]}" "${BUNDLE_FILES[@]}"; do [[ -e "$d" ]] && { echo "  - $d"; found=1; }; done
for d in /root/wazuh-install-*; do [[ -d "$d" ]] && { echo "  - $d (dossier de travail de l'étape 02)"; found=1; }; done
[[ -f "$ANSWERS_FILE" ]] && echo "  - réponses du bundle : $ANSWERS_FILE"
[[ -d "$SECRETS_DIR" ]] && echo "  - secrets du bundle : $SECRETS_DIR"
(( found )) || log_info "Aucun composant Wazuh ni tâche du bundle détecté."

explain <<'TXT'
  wazuh   : désinstalle Wazuh et les ajouts du bundle qui en dépendent (tâches planifiées, outils,
            service SMS). Les réponses (IP, choix…) sont gardées : relancer ensuite l'étape 02.
            Les agents déjà enrôlés devront être ré-enrôlés (nouvelles clés, nouveaux certificats).
  complet : idem + efface les réponses et les secrets du bundle (recommencer à l'étape 00) ;
            propose aussi de retirer Grafana, le fichier d'échange (swap) et les noms ajoutés à
            /etc/hosts par le bundle.
Dans les deux cas, une archive (configuration Wazuh, réponses, secrets) est créée AVANT dans /root.
TXT
ask_choice CLEAN_LEVEL "Niveau de nettoyage" wazuh \
  "wazuh|Wazuh uniquement — garder les réponses (recommandé pour relancer l'étape 02)" \
  "complet|Tout ce que le bundle a installé — repartir de l'étape 00" \
  "abandon|Ne rien faire"
[[ "$CLEAN_LEVEL" == abandon ]] && { log_info "Aucune modification."; exit 0; }

rm_grafana=non; rm_swap=non; rm_hosts=non
if [[ "$CLEAN_LEVEL" == complet ]]; then
  pkg_present grafana && confirm "Désinstaller aussi Grafana (et ses tableaux de bord) ?" && rm_grafana=oui
  [[ -f /etc/sysctl.d/99-wazuh-bundle-swap.conf ]] && confirm "Retirer le fichier d'échange /swapfile créé par l'étape 02 ?" && rm_swap=oui
  grep -q '# wazuh-bundle$' /etc/hosts 2>/dev/null && confirm "Retirer les noms ajoutés à /etc/hosts par le bundle ?" && rm_hosts=oui
fi

[[ "$NONINTERACTIVE" == 1 ]] && die "Mode non interactif : le nettoyage exige une confirmation saisie à la main."
log_warn "Les données Wazuh (alertes, agents enrôlés, configuration) seront SUPPRIMÉES de ce serveur."
typed=""; _read typed "  ${BOLD}?${NC} Taper NETTOYER pour confirmer : "
[[ "$typed" == NETTOYER ]] || die "Confirmation absente : rien n'a été modifié."

# ── 1. Archive de sécurité ───────────────────────────────────────────────────────────────────
section "Archive de sécurité"
ARCHIVE="/root/wazuh-bundle-avant-nettoyage-$(date +%Y%m%d-%H%M%S).tar.gz"
to_save=()
for d in /var/ossec/etc /etc/wazuh-indexer/certs /etc/wazuh-dashboard "$STATE_DIR" "$SECRETS_DIR"; do [[ -e "$d" ]] && to_save+=("$d"); done
if (( ${#to_save[@]} )); then
  run "Archive de la configuration et des secrets (root uniquement)" \
    bash -c 'umask 077; tar -czf "$0" --ignore-failed-read --warning=no-file-changed "$@"; rc=$?; [ "$rc" -le 1 ] && test -s "$0"' "$ARCHIVE" "${to_save[@]}"
  log_ok "Archive : $ARCHIVE (contient des mots de passe : à conserver en lieu sûr ou à supprimer)."
else
  log_info "Rien à archiver."
fi

# ── 2. Ajouts du bundle qui dépendent de Wazuh ───────────────────────────────────────────────
section "Tâches planifiées, outils et service SMS du bundle"
if output_has '^wazuh-sms-alerter' systemctl list-unit-files; then
  run --allow-fail "Arrêt du service SMS" systemctl disable --now wazuh-sms-alerter || true
fi
for f in "${BUNDLE_FILES[@]}"; do [[ -e "$f" ]] && run "Suppression de $f" rm -f "$f"; done
id wazuh-sms >/dev/null 2>&1 && run "Suppression de l'utilisateur système wazuh-sms" userdel wazuh-sms
[[ -f "$STATE_DIR/sms.env" ]] && run "Suppression des paramètres du service SMS" rm -f "$STATE_DIR/sms.env"
run "Rechargement de systemd" systemctl daemon-reload

# ── 3. Wazuh ─────────────────────────────────────────────────────────────────────────────────
section "Désinstallation de Wazuh"
for s in wazuh-dashboard filebeat wazuh-manager wazuh-indexer; do
  if output_has "^$s\.service" systemctl list-unit-files; then
    run --allow-fail "Arrêt de $s" systemctl disable --now "$s" || true
  fi
done
present=(); for p in "${WAZUH_PKGS[@]}"; do pkg_present "$p" && present+=("$p"); done
if (( ${#present[@]} )); then
  if ! run --allow-fail --hint "Paquet à moitié installé : on force la suppression juste après." \
      "Suppression des paquets ${present[*]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${present[@]}"; then
    run "Suppression forcée des paquets ${present[*]}" dpkg --purge --force-remove-reinstreq --force-depends "${present[@]}"
  fi
else
  log_info "Aucun paquet Wazuh installé."
fi
pgrep -u wazuh-indexer >/dev/null 2>&1 && run --allow-fail "Arrêt des processus restants de l'indexer" pkill -u wazuh-indexer || true
for d in "${WAZUH_DIRS[@]}"; do [[ -e "$d" ]] && run "Suppression de $d" rm -rf -- "$d"; done
for d in /root/wazuh-install-*; do [[ -d "$d" ]] && run "Suppression du dossier de travail $d" rm -rf -- "$d"; done
for f in /etc/systemd/system/wazuh-manager.service.d /etc/systemd/system/wazuh-indexer.service.d /etc/systemd/system/wazuh-dashboard.service.d; do
  [[ -e "$f" ]] && run "Suppression de $f" rm -rf -- "$f"
done
[[ -f /etc/apt/sources.list.d/wazuh.list ]] && run "Retrait du dépôt APT Wazuh" rm -f /etc/apt/sources.list.d/wazuh.list
[[ -f /var/log/wazuh-install.log ]] && run "Ancien journal de l'installateur mis de côté" \
  mv /var/log/wazuh-install.log "/var/log/wazuh-install.log.$(date +%Y%m%d-%H%M%S)"
run "Rechargement de systemd" systemctl daemon-reload

# ── 4. Réponses et secrets ───────────────────────────────────────────────────────────────────
section "Réponses et secrets du bundle"
if [[ "$CLEAN_LEVEL" == complet ]]; then
  for d in "$STATE_DIR" "$SECRETS_DIR"; do [[ "$d" == /*/* ]] || die "Chemin inattendu « $d » : suppression refusée."; done
  [[ -d "$STATE_DIR" ]] && run "Suppression des réponses ($STATE_DIR)" rm -rf -- "$STATE_DIR"
  [[ -d "$SECRETS_DIR" ]] && run "Suppression des secrets ($SECRETS_DIR)" rm -rf -- "$SECRETS_DIR"
else
  # Secrets propres à l'ancienne installation (régénérés par l'étape 02 et suivantes)
  for f in "$SECRETS_DIR/wazuh-install-files.tar" "$SECRETS_DIR/wazuh-passwords.txt"; do
    [[ -f "$f" ]] && run "Suppression de $f (ancienne installation)" rm -f "$f"
  done
  if [[ -f "$SECRETS_FILE" ]]; then
    tmp="$(mktemp "$SECRETS_DIR/.secrets.XXXXXX")"
    grep -vE '^(INDEXER_ADMIN_PASSWORD|GRAFANA_RO_PASSWORD)=' "$SECRETS_FILE" > "$tmp" || true
    chmod 600 "$tmp"; mv -f "$tmp" "$SECRETS_FILE"
    log_ok "Mots de passe de l'ancien indexer retirés de $SECRETS_FILE."
  fi
  if [[ -f "$ANSWERS_FILE" ]]; then
    tmp="$(mktemp "$STATE_DIR/.answers.XXXXXX")"
    grep -vE '^(WAZUH_VERSION|API_FIX|HW_FIX|PUBIP_FIX)=' "$ANSWERS_FILE" > "$tmp" || true
    chmod 600 "$tmp"; mv -f "$tmp" "$ANSWERS_FILE"
    log_ok "Réponses conservées (IP, choix) ; version et solutions de l'ancienne installation oubliées."
  fi
fi

# ── 5. Options du nettoyage complet ──────────────────────────────────────────────────────────
if [[ "$rm_grafana" == oui ]]; then
  section "Grafana"
  run --allow-fail "Arrêt de Grafana" systemctl disable --now grafana-server || true
  run "Suppression du paquet Grafana" env DEBIAN_FRONTEND=noninteractive apt-get purge -y grafana
  for d in /etc/grafana /var/lib/grafana /var/log/grafana /etc/apt/sources.list.d/grafana.list /etc/apt/keyrings/grafana.gpg; do
    [[ -e "$d" ]] && run "Suppression de $d" rm -rf -- "$d"
  done
fi
if [[ "$rm_swap" == oui ]]; then
  section "Fichier d'échange"
  if grep -qx /swapfile <<< "$(swapon --show=NAME --noheadings 2>/dev/null || true)"; then
    run "Désactivation de /swapfile" swapoff /swapfile
  fi
  backup_file /etc/fstab
  run "Retrait de /swapfile de /etc/fstab" sed -i '\#^/swapfile[[:space:]]#d' /etc/fstab
  run "Suppression de /swapfile" rm -f /swapfile
  run "Suppression du réglage vm.swappiness du bundle" rm -f /etc/sysctl.d/99-wazuh-bundle-swap.conf
fi
if [[ "$rm_hosts" == oui ]]; then
  section "/etc/hosts"
  backup_file /etc/hosts
  run "Retrait des lignes « # wazuh-bundle »" sed -i '/# wazuh-bundle$/d' /etc/hosts
fi

# ── Bilan ────────────────────────────────────────────────────────────────────────────────────
section "Bilan"
left=0
for p in "${WAZUH_PKGS[@]}"; do pkg_present "$p" && { log_warn "Paquet encore présent : $p"; left=1; }; done
for d in "${WAZUH_DIRS[@]}"; do [[ -e "$d" ]] && { log_warn "Encore présent : $d"; left=1; }; done
(( left == 0 )) || die "Nettoyage incomplet : voir les lignes ci-dessus."
log_ok "Serveur nettoyé (niveau : $CLEAN_LEVEL)."
if [[ "$CLEAN_LEVEL" == complet ]]; then
  echo "  Suite : relancer l'installation depuis l'étape 00 (bash install.sh)."
else
  echo "  Suite : relancer l'étape 02 (bash install.sh --step 02), puis les étapes 03 et suivantes."
fi
echo "  Non modifiés : durcissement SSH (étape 01), Postfix (étape 07), YARA, journaux $LOG_DIR."
[[ -n "${ARCHIVE:-}" && -f "$ARCHIVE" ]] && echo "  Archive de sécurité : $ARCHIVE"
