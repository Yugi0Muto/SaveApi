#!/usr/bin/env bash
# 02_firewall.sh — pare-feu nftables du serveur Wazuh, par segment
# Protection anti-verrouillage : annulation automatique après 90 s sans confirmation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/firewall_rules.sh"
require_root; load_conf
command -v nft >/dev/null || apt-get install -y nftables >/dev/null

RULES=/etc/nftables.conf
backup_file "$RULES"
render_nft_rules > /tmp/nft.new
nft -c -f /tmp/nft.new || die "Règles nftables invalides."

log_warn "Application des règles. Si la session SSH est coupée, tout est annulé automatiquement dans 90 secondes."
( sleep 90; nft delete table inet wazuh_bundle 2>/dev/null; logger "wazuh-bundle: pare-feu annulé (pas de confirmation)" ) &
GUARD=$!
nft -f /tmp/nft.new
echo
read -rp "La connexion fonctionne-t-elle toujours (SSH + Dashboard depuis un poste admin) ? Taper OUI : " ans
if [[ "$ans" == "OUI" ]]; then
  kill "$GUARD" 2>/dev/null || true
  install -m 600 /tmp/nft.new "$RULES"; rm -f /tmp/nft.new
  systemctl enable --now nftables >/dev/null
  log_ok "Pare-feu actif et persistant ($RULES)."
else
  kill "$GUARD" 2>/dev/null || true
  nft delete table inet wazuh_bundle 2>/dev/null || true
  die "Pare-feu annulé. Vérifier ADMIN_CIDRS dans bundle.conf."
fi
flux_admin="TCP 22, 443"; flux_internet="packages.wazuh.com, GitHub (règles YARA), abuse.ch"; flux_grafana=""
if grafana_is_local; then
  flux_admin="TCP 22, 443, 3000"; flux_internet="packages.wazuh.com, apt.grafana.com, GitHub (règles YARA), abuse.ch"
elif grafana_is_remote; then
  flux_grafana="  Machine Grafana ($GRAFANA_REMOTE_IPS) -> $MANAGER_IP : TCP 9200 (indexer, lecture seule)"
fi
cat <<MSG

Flux à faire ouvrir par l'équipe réseau (voir documentation, section Flux) :
  Employés/Serveurs/DMZ -> $MANAGER_IP : TCP 1514, TCP 1515
  Postes admin          -> $MANAGER_IP : ${flux_admin}
${flux_grafana}
  $MANAGER_IP -> Internet (HTTPS 443) : ${flux_internet}
  $MANAGER_IP -> relais SMTP / API SMS selon les options activées
MSG
