#!/usr/bin/env bash
# Pose les questions de base (adresse IP du serveur, postes d'administration) puis contrôle que la machine
# convient : système, ressources, ports, accès Internet, horloge. Ne modifie RIEN sur le système
# (seules les réponses sont mémorisées dans /etc/wazuh-bundle/answers.env).
# Un point bloquant arrête l'étape ; un point « recommandé » non respecté demande confirmation.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
source "$BUNDLE_ROOT/lib/cleanup.sh"
require_root
step_header 00 "Préflight"

explain <<'TXT'
Le serveur Wazuh doit avoir une adresse IP FIXE : les agents s'y connectent par cette adresse
et elle est utilisée dans les certificats. Les « postes d'administration » sont les machines
des administrateurs : elles ne seront jamais bloquées par la réponse active (étape 03) et
figureront dans le tableau des flux réseau à transmettre à l'équipe pare-feu.
TXT

def_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
ask MANAGER_IP "Adresse IP fixe de CE serveur Wazuh" "${def_ip:-}" v_ipv4
ask ADMIN_IPS "IP ou réseaux (CIDR) des postes d'administration, séparés par des espaces" "" v_ip_list_req

fail=0; warns=()
ok()   { log_ok "$*"; }
ko()   { log_err "$*"; fail=1; }
soft() { log_warn "$*"; warns+=("$*"); }

section "Système"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID}-${VERSION_ID%%.*}" in
  debian-12|debian-13|ubuntu-22|ubuntu-24) ok "Système supporté : $PRETTY_NAME";;
  *) ko "Système non validé : $PRETTY_NAME (supportés : Debian 12/13, Ubuntu 22.04/24.04)";;
esac
command -v python3 >/dev/null && ok "python3 présent ($(python3 --version 2>&1))" || ko "python3 manquant : apt-get install -y python3"
command -v curl >/dev/null && ok "curl présent" || ko "curl manquant : apt-get install -y curl"

section "Ressources (recommandations Wazuh pour un serveur tout-en-un)"
ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
if (( ram_mb < 3800 )); then ko "RAM ${ram_mb} Mo : insuffisant (4 Go minimum, 8 Go recommandés)"
elif (( ram_mb < 7500 )); then soft "RAM ${ram_mb} Mo (< 8 Go recommandés en production)"
else ok "RAM : ${ram_mb} Mo"; fi
cpus=$(nproc); (( cpus >= 4 )) && ok "CPU : $cpus" || soft "CPU : $cpus (< 4 recommandés)"
disk_gb=$(df -BG --output=avail /var | tail -1 | tr -dc '0-9')
if (( disk_gb < 30 )); then ko "Disque /var : ${disk_gb} Go libres (30 Go minimum)"
elif (( disk_gb < 100 )); then soft "Disque /var : ${disk_gb} Go libres (< 100 Go recommandés ; dépend de la rétention, étape 05)"
else ok "Disque /var : ${disk_gb} Go libres"; fi

section "Réseau"
if output_has "inet ${MANAGER_IP//./\\.}/" ip -4 addr show; then ok "L'adresse $MANAGER_IP est bien configurée sur ce serveur"
else ko "L'adresse $MANAGER_IP n'est PAS configurée sur ce serveur (ip -4 addr)"; fi
if output_has "inet ${MANAGER_IP//./\\.}/.*dynamic" ip -4 addr show; then
  soft "L'adresse $MANAGER_IP est attribuée par DHCP : la rendre fixe (ou réservée sur le serveur DHCP)"
fi
if wazuh_installed; then
  ok "Wazuh est déjà installé : contrôle des ports ignoré (ils sont utilisés par Wazuh)."
else
  scan="$(trace_scan)"
  for p in 443 1514 1515 9200 55000; do
    if grep -q "^wazuh|port|$p|" <<< "$scan"; then soft "Port $p occupé par un reste d'installation Wazuh : l'étape 00b le libérera"
    elif output_has "[:.]${p}[[:space:]]" ss -tlnH; then ko "Port $p déjà utilisé : $(ss -tlnpH "sport = :$p" | awk '{print $6}' | head -1)"
    else ok "Port $p libre"; fi
  done
  n_traces="$(grep -cE '^(wazuh|system|bundle|firewall|grafana)\|' <<< "$scan" || true)"
  if (( n_traces > 0 )); then soft "$n_traces trace(s) d'une installation précédente détectée(s) : l'étape 00b les liste et les nettoie"
  else ok "Aucune trace d'installation précédente"; fi
fi
for url in https://packages.wazuh.com https://github.com; do
  if curl -sS -o /dev/null -m 10 -I "$url" 2>/tmp/.pf.err; then ok "Accès HTTPS à $url"
  else soft "Pas d'accès HTTPS à $url : $(head -1 /tmp/.pf.err) (proxy ou pare-feu sortant ?)"; fi
done
rm -f /tmp/.pf.err

section "Horloge"
if output_has '^yes$' timedatectl show -p NTPSynchronized --value; then ok "Horloge synchronisée (NTP)"
else soft "Horloge NON synchronisée : les alertes seraient mal datées (installer chrony ou activer systemd-timesyncd)"; fi
ok "Fuseau horaire : $(timedatectl show -p Timezone --value 2>/dev/null || echo inconnu) (utilisé par la règle « connexion hors heures »)"

echo
if (( fail )); then die "Préflight : au moins un point BLOQUANT ci-dessus (lignes [ERREUR]). Corriger puis relancer l'étape 00."; fi
if (( ${#warns[@]} )); then
  log_warn "${#warns[@]} recommandation(s) non respectée(s) :"; printf '    - %s\n' "${warns[@]}"
  confirm "Continuer malgré ces avertissements ?" || die "Arrêt à la demande de l'utilisateur."
fi
log_ok "Préflight OK."
