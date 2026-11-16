#!/usr/bin/env bash
# firewall_rules.sh — génération du jeu de règles nftables (fonction pure : n'applique rien, testable sans root)
# Requiert : load_conf déjà exécuté (ADMIN_CIDRS, SERVERS_CIDR, EMPLOYEES_CIDR, DMZ_CIDR, GRAFANA_*).

_nft_join() { local IFS=,; echo "$*"; }

render_nft_rules() {
  local admin_set agent_set
  admin_set="$(_nft_join $ADMIN_CIDRS)"
  agent_set="$(_nft_join $SERVERS_CIDR $EMPLOYEES_CIDR $DMZ_CIDR)"

  # Grafana : local = port 3000 pour les admins ; remote = l'indexer (9200) n'est joignable que par la machine Grafana
  local admin_ports="22, 443" admin_comment="Administration : SSH, Dashboard Wazuh" grafana_set="" grafana_rule=""
  if grafana_is_local; then
    admin_ports="22, 443, 3000"; admin_comment="Administration : SSH, Dashboard Wazuh, Grafana"
  elif grafana_is_remote; then
    grafana_set="  set grafana4 { type ipv4_addr; flags interval; elements = { $(_nft_join $GRAFANA_REMOTE_IPS) } }"
    grafana_rule="    # Grafana distant : lecture de l'indexer (9200) uniquement depuis la machine Grafana
    ip saddr @grafana4 tcp dport 9200 accept"
  fi

  cat <<NFT
#!/usr/sbin/nft -f
# Généré par wazuh-bundle — ne pas éditer à la main (modifier bundle.conf puis relancer l'étape 02)
flush ruleset
table inet wazuh_bundle {
  set admin4  { type ipv4_addr; flags interval; elements = { ${admin_set} } }
  set agents4 { type ipv4_addr; flags interval; elements = { ${agent_set} } }
${grafana_set}

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    meta l4proto icmp icmp type echo-request limit rate 10/second accept
    meta l4proto ipv6-icmp accept
    # ${admin_comment}
    ip saddr @admin4 tcp dport { ${admin_ports} } accept
${grafana_rule}
    # Agents (serveurs, employés, DMZ) : événements 1514 et enrôlement 1515
    ip saddr @agents4 tcp dport { 1514, 1515 } accept
    # Tout le reste est journalisé (limité) puis refusé
    limit rate 5/minute log prefix "nft-wazuh-drop: " counter drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
NFT
}
