#!/usr/bin/env bash
# wazuh-bundle-purge-logs — supprime les fichiers d'alertes/archives du manager plus vieux que la durée choisie
# (étape 05). Durées lues dans /etc/wazuh-bundle/answers.env. Option --dry-run : affiche sans supprimer.
set -euo pipefail
ANSWERS="${ANSWERS_FILE:-${BUNDLE_STATE_DIR:-/etc/wazuh-bundle}/answers.env}"
LOGS="${OSSEC_LOGS:-${OSSEC_DIR:-/var/ossec}/logs}"
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1
[[ -r "$ANSWERS" ]] || { echo "$(date '+%F %T') ERREUR : $ANSWERS illisible (étape 05 non exécutée ?)"; exit 1; }
# shellcheck disable=SC1090
source "$ANSWERS"
: "${RET_LOCAL_DAYS:?RET_LOCAL_DAYS absent de $ANSWERS : relancer l étape 05}"
: "${RET_LOCAL_ARCHIVES_DAYS:?RET_LOCAL_ARCHIVES_DAYS absent de $ANSWERS : relancer l étape 05}"

purge() { # purge dossier jours
  local dir="$1" days="$2" n=0 f
  [[ -d "$dir" ]] || { echo "$(date '+%F %T') $dir absent : rien à faire"; return 0; }
  # Uniquement les fichiers ROTÉS (sous-dossiers AAAA/Mois) : jamais alerts.json/alerts.log du jour
  while IFS= read -r -d '' f; do
    n=$((n+1))
    if (( DRY )); then echo "  [simulation] supprimerait $f"; else rm -f -- "$f"; fi
  done < <(find "$dir" -mindepth 3 -type f -mtime +"$days" -print0)
  (( DRY )) || find "$dir" -mindepth 1 -type d -empty -delete
  echo "$(date '+%F %T') $dir : $n fichier(s) de plus de $days jours $( ((DRY)) && echo 'à supprimer (simulation)' || echo supprimé\(s\))"
}
purge "$LOGS/alerts" "$RET_LOCAL_DAYS"
purge "$LOGS/archives" "$RET_LOCAL_ARCHIVES_DAYS"
