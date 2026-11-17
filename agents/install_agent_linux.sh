#!/usr/bin/env bash
# install_agent_linux.sh — installe et enrôle un agent Wazuh sur une machine Linux (Debian/Ubuntu).
# Toutes les informations manquantes sont demandées (aucun fichier à éditer). La configuration
# (fichiers et journaux surveillés) vient ensuite du MANAGER, via les groupes de l'agent.
#
# Interactif :      sudo bash agents/install_agent_linux.sh
# Automatisé :      sudo bash agents/install_agent_linux.sh --manager-ip 10.10.10.20 --segment dmz \
#                        --role web --name dmz-web01 --version 4.14.10-1 --yara --password-file /root/pw
# Options : --whodata (audit « qui a modifié »), --deb-path FICHIER.deb (machine sans Internet),
#           --yara-method source|package
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Sur l'agent, les réponses sont mémorisées à part de celles d'un éventuel manager
export BUNDLE_STATE_DIR="${BUNDLE_STATE_DIR:-/etc/wazuh-bundle-agent}"
source "$SCRIPT_DIR/../lib/common.sh"
require_root

MANAGER_IP=""; SEGMENT=""; ROLE=""; NAME=""; VERSION=""; YARA=""; WHODATA=""; PWFILE=""; DEB=""; YARA_METHOD=""
while [[ $# -gt 0 ]]; do case "$1" in
  --manager-ip) MANAGER_IP="$2"; shift 2;; --segment) SEGMENT="$2"; shift 2;; --role) ROLE="$2"; shift 2;;
  --name) NAME="$2"; shift 2;; --version) VERSION="$2"; shift 2;; --yara) YARA=oui; shift;; --whodata) WHODATA=oui; shift;;
  --password-file) PWFILE="$2"; shift 2;; --deb-path) DEB="$2"; shift 2;; --yara-method) YARA_METHOD="$2"; shift 2;;
  -h|--help) sed -n '2,12p' "$0"; exit 0;; *) die "Argument inconnu : $1 (voir --help)";;
esac; done

step_header A "Installation d'un agent Wazuh Linux"
if pkg_installed wazuh-agent; then
  log_warn "Un agent est déjà installé ($(dpkg-query -W -f='${Version}' wazuh-agent)) : rien n'est modifié."
  echo "  Pour réinstaller : apt-get purge wazuh-agent puis relancer ce script."; exit 0
fi

explain <<'TXT'
L'agent envoie au serveur Wazuh les journaux et les changements de fichiers de cette machine.
Il appartient à des GROUPES qui déterminent ce qui est surveillé :
  segment (dmz | servers | employees), système (os-linux), rôle (web | db | admin), options.
TXT
[[ -n "$MANAGER_IP" ]] || ask AGENT_MANAGER_IP "Adresse IP du serveur Wazuh" "" v_ipv4
MANAGER_IP="${MANAGER_IP:-$AGENT_MANAGER_IP}"; v_ipv4 "$MANAGER_IP" >/dev/null || die "IP du manager invalide : $MANAGER_IP"
[[ -n "$SEGMENT" ]] || { ask_choice AGENT_SEGMENT "Segment réseau de cette machine" servers \
  "servers|SERVEURS" "employees|EMPLOYÉS (postes de travail)" "dmz|DMZ (exposé à Internet)"; SEGMENT="$AGENT_SEGMENT"; }
[[ "$SEGMENT" =~ ^(dmz|servers|employees)$ ]] || die "Segment invalide : $SEGMENT"
[[ -n "$ROLE" ]] || { ask_choice AGENT_ROLE "Rôle de cette machine" generic \
  "generic|Aucun rôle particulier" "web|Serveur web (nginx/apache)" "db|Base de données (MySQL/PostgreSQL)" "admin|Poste/serveur d'administration"; ROLE="$AGENT_ROLE"; }
[[ "$ROLE" =~ ^(web|db|admin|generic)$ ]] || die "Rôle invalide : $ROLE"
[[ -n "$NAME" ]] || { ask AGENT_NAME "Nom de l'agent (unique, visible dans le dashboard)" "$(hostname -s)" v_nonempty; NAME="$AGENT_NAME"; }
if [[ -z "$VERSION" ]]; then
  explain <<'TXT'
La version de l'agent doit être INFÉRIEURE OU ÉGALE à celle du manager.
Sur le serveur Wazuh : dpkg-query -W wazuh-manager   (ex : 4.14.10-1)
TXT
  ask AGENT_VERSION "Version de l'agent à installer (ex : 4.14.10-1)" "" v_nonempty; VERSION="$AGENT_VERSION"
fi
if [[ -z "$YARA" ]]; then
  explain <<'TXT'
YARA analyse le contenu des fichiers déposés dans les répertoires exposés (sites web, /tmp…) à la
recherche de malwares (voir docs/YARA.md). Recommandé pour les serveurs web et la DMZ.
TXT
  ask_yes_no AGENT_YARA "Activer l'analyse de malwares YARA sur cette machine ?" "$([[ "$SEGMENT" == dmz || "$ROLE" == web ]] && echo oui || echo non)" && YARA=oui || YARA=non
fi
if [[ -z "$WHODATA" ]]; then
  ask_yes_no AGENT_WHODATA "Activer whodata (savoir QUEL utilisateur modifie les fichiers sensibles ; installe auditd) ?" non && WHODATA=oui || WHODATA=non
fi

if [[ -n "$PWFILE" ]]; then REGPW="$(cat "$PWFILE")"
elif [[ -n "${WAZUH_REG_PASSWORD:-}" ]]; then REGPW="$WAZUH_REG_PASSWORD"
else IFS= read -rs -p "  ${BOLD}?${NC} Mot de passe d'enrôlement (sur le serveur : grep AUTHD_PASSWORD /root/.wazuh-bundle/secrets.env) : " REGPW; echo; fi
[[ -n "$REGPW" ]] || die "Mot de passe d'enrôlement vide."

GROUPS_CSV="seg-${SEGMENT},os-linux"
[[ "$ROLE" != generic ]] && GROUPS_CSV+=",role-${ROLE}"
[[ "$YARA" == oui ]] && GROUPS_CSV+=",feat-yara"
[[ "$WHODATA" == oui ]] && GROUPS_CSV+=",opt-whodata"
log_info "Groupes de l'agent : $GROUPS_CSV"

section "Prérequis"
for p in 1514 1515; do
  run --hint "Le pare-feu de l'entreprise doit autoriser cette machine -> $MANAGER_IP TCP $p (voir « bash install.sh --flows » sur le serveur)." \
    "Joignabilité du manager $MANAGER_IP:$p" timeout 5 bash -c "</dev/tcp/$MANAGER_IP/$p"
done
pkg_install curl gpg ca-certificates
if [[ ! -f /var/log/auth.log ]]; then
  log_info "/var/log/auth.log absent (journald seul) : rsyslog est nécessaire pour que Wazuh lise les connexions."
  pkg_install rsyslog; run "Démarrage de rsyslog" systemctl enable --now rsyslog
fi
[[ "$YARA" == oui ]] && { pkg_install jq; bash "$SCRIPT_DIR/../tools/install_yara.sh" ${YARA_METHOD:+--method "$YARA_METHOD"} || die "Installation de YARA en échec."; }
[[ "$WHODATA" == oui ]] && { pkg_install auditd audispd-plugins; run "Démarrage d'auditd" systemctl enable --now auditd; }

section "Installation de l'agent"
envs=(WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$NAME" WAZUH_AGENT_GROUP="$GROUPS_CSV" WAZUH_REGISTRATION_PASSWORD="$REGPW")
if [[ -n "$DEB" ]]; then
  run --secret "Installation depuis $DEB" env "${envs[@]}" dpkg -i "$DEB"
else
  run_sh "Clé de signature du dépôt Wazuh" "curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg"
  run_sh "Déclaration du dépôt Wazuh" "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list"
  run "Mise à jour de l'index des paquets" apt-get update
  run --secret --hint "Version inexistante ? apt-cache madison wazuh-agent" "Installation de wazuh-agent=$VERSION" \
    env "${envs[@]}" DEBIAN_FRONTEND=noninteractive apt-get install -y "wazuh-agent=${VERSION}"
fi
run "Blocage des mises à jour automatiques de l'agent (le manager doit être mis à jour en premier)" apt-mark hold wazuh-agent
if [[ "$YARA" == oui ]]; then
  run "Installation du script d'analyse YARA (réponse active)" install -o root -g wazuh -m 750 "$SCRIPT_DIR/yara.sh" /var/ossec/active-response/bin/yara.sh
fi
run "Rechargement de systemd" systemctl daemon-reload
run "Activation de l'agent au démarrage" systemctl enable wazuh-agent
run "Démarrage de l'agent" systemctl restart wazuh-agent

log_info "Attente de la connexion au manager (60 s max)…"
for _ in $(seq 1 30); do
  if grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null; then
    log_ok "Agent $NAME connecté (groupes : $GROUPS_CSV). Côté serveur : /var/ossec/bin/agent_control -l"; exit 0
  fi
  sleep 2
done
log_err "Pas de connexion au manager. Dernières erreurs de l'agent :"
grep -E "ERROR|WARNING" /var/ossec/logs/ossec.log | tail -10 | sed 's/^/  │ /'
cat <<TXT
  Causes fréquentes :
    - « Invalid password »            : mot de passe d'enrôlement incorrect ;
    - « Invalid group »               : groupe absent du manager (étape 03/06 non exécutée) ;
    - « Agent version must be lower » : version de l'agent supérieure à celle du manager ;
    - « Unable to connect »           : flux 1514/1515 bloqué par le pare-feu.
TXT
exit 1
