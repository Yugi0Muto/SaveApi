#!/usr/bin/env bash
# install.sh — assistant d'installation du serveur Wazuh (à lancer SUR le serveur, en root)
#
#   bash install.sh                  menu interactif
#   bash install.sh --all            toutes les étapes dans l'ordre (s'arrête à la première erreur)
#   bash install.sh --step 03        une seule étape
#   bash install.sh --step 90        nettoyage pour une nouvelle installation (désinstalle Wazuh)
#   bash install.sh --explain 06     explique ce que fait une étape, sans rien exécuter
#   bash install.sh --flows          affiche les flux réseau à faire ouvrir sur le pare-feu de l'entreprise
#   bash install.sh --non-interactive --step 07
#                                    rejoue une étape avec les réponses déjà données (aucune question)
#
# Aucune configuration à éditer : chaque étape pose ses questions. Les réponses sont mémorisées dans
# /etc/wazuh-bundle/answers.env et proposées par défaut à la relance. Journal complet : /var/log/wazuh-bundle/
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
STEPS_DIR="$SCRIPT_DIR/steps"

declare -A LABEL=(
 [00]="Préflight : questions de base et contrôles (ne modifie rien)"
 [01]="Durcissement SSH (optionnel, mesure par mesure)"
 [02]="Installation de Wazuh (manager, indexer, dashboard)"
 [03]="Configuration du manager (enrôlement, liste blanche, réponse active, groupes)"
 [04]="Règles de détection du bundle (+ auto-test)"
 [05]="Politique de rétention des alertes"
 [06]="Détection de malwares : YARA + liste de hashes"
 [07]="Alertes e-mail (Gmail / SMTP entreprise / relais)"
 [08]="Alertes SMS (Africa's Talking)"
 [09]="Grafana (local ou distant)"
 [10]="Sauvegarde quotidienne de la configuration"
 [90]="Nettoyage pour une nouvelle installation (désinstalle Wazuh ; à la demande)"
 [99]="Recette automatique (vérification complète)" )
ORDER=(00 01 02 03 04 05 06 07 08 09 10 99)
# Étapes hors « Tout exécuter » : seulement à la demande (menu ou --step)
EXTRA_STEPS=(90)

step_file() { local f; f="$(ls "$STEPS_DIR/${1}_"*.sh 2>/dev/null | head -1)"; [[ -n "$f" ]] || die "Étape $1 inconnue."; echo "$f"; }

explain_step() { # affiche l'en-tête de description du script (lignes "#" du début)
  local f; f="$(step_file "$1")"
  echo "${BOLD}Étape $1 — ${LABEL[$1]}${NC}"
  sed -n '2,/^set -/p' "$f" | grep '^#' | sed 's/^# \{0,1\}/  /'
}

run_step() {
  local n="$1" f rc
  f="$(step_file "$n")"
  set +e; BUNDLE_NONINTERACTIVE="$NONINTERACTIVE" bash "$f"; rc=$?; set -e
  if (( rc == 0 )); then log_ok "Étape $n terminée."
  else log_err "Étape $n en ÉCHEC (code $rc). Les messages ci-dessus indiquent la commande fautive et une piste. Journal : $LOG_FILE"; fi
  return $rc
}

require_root
mkdir -p "$LOG_DIR"; chmod 750 "$LOG_DIR"
LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
# Tout ce qui s'affiche est aussi journalisé (les saisies masquées ne sont pas affichées, donc pas journalisées)
exec > >(tee -a "$LOG_FILE") 2>&1
export BUNDLE_COLOR=1

ACTION=""; ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) ACTION=all; shift;;
    --step) ACTION=step; ARG="${2:?numéro d étape attendu}"; shift 2;;
    --explain) ACTION=explain; ARG="${2:?numéro d étape attendu}"; shift 2;;
    --flows) ACTION=flows; shift;;
    --non-interactive) NONINTERACTIVE=1; shift;;
    -h|--help) sed -n '2,14p' "$0"; exit 0;;
    *) die "Argument inconnu : $1 (voir --help)";;
  esac
done
log_info "wazuh-bundle v$BUNDLE_VERSION — journal : $LOG_FILE"

case "$ACTION" in
  all)     for n in "${ORDER[@]}"; do run_step "$n" || exit 1; done; exit 0;;
  step)    run_step "$ARG"; exit $?;;
  explain) explain_step "$ARG"; exit 0;;
  flows)   network_flows; exit 0;;
esac

while true; do
  echo
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║        WAZUH BUNDLE v$BUNDLE_VERSION — installation du serveur            ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  for n in "${ORDER[@]}"; do printf "  %s) %s\n" "$n" "${LABEL[$n]}"; done
  echo "  ── à la demande ──"
  for n in "${EXTRA_STEPS[@]}"; do printf "  %s) %s\n" "$n" "${LABEL[$n]}"; done
  echo "  a) Tout exécuter dans l'ordre   e) Expliquer une étape   f) Flux réseau à ouvrir   q) Quitter"
  read -rp "Choix : " c || exit 0
  case "$c" in
    q) exit 0;;
    a) for n in "${ORDER[@]}"; do run_step "$n" || break; done; pause;;
    e) read -rp "Numéro de l'étape : " n; [[ -n "${LABEL[$n]:-}" ]] && explain_step "$n" || echo "Étape inconnue"; pause;;
    f) network_flows; pause;;
    *) if [[ -n "${LABEL[$c]:-}" ]]; then run_step "$c" || true; pause; else echo "Choix invalide"; fi;;
  esac
done
