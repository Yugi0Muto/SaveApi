#!/usr/bin/env bash
# Installe Wazuh (manager + indexer + dashboard) sur ce serveur avec l'assistant officiel wazuh-install.sh.
# Question clé : sur quelle adresse l'indexer (base des alertes, port 9200) doit-il écouter ?
#   - 127.0.0.1 (recommandé) : l'indexer n'est joignable que depuis le serveur lui-même ;
#   - l'IP du serveur        : nécessaire seulement si Grafana est installé sur une AUTRE machine.
# Le choix est inscrit dans les certificats : il se fait AVANT l'installation.
# Les mots de passe générés sont copiés dans /root/.wazuh-bundle/ (root uniquement).
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 02 "Installation de Wazuh"
need_answer MANAGER_IP 00

if wazuh_installed; then
  ver="$(dpkg-query -W -f='${Version}' wazuh-manager)"
  log_ok "Wazuh est déjà installé (wazuh-manager $ver) : installation ignorée."
  ans_set WAZUH_VERSION "$ver"
  host="$(grep -E '^[[:space:]]*network\.host' /etc/wazuh-indexer/opensearch.yml 2>/dev/null | head -1 | sed -E 's/.*:[[:space:]]*"?([^"]+)"?.*/\1/')"
  case "$host" in ""|0.0.0.0) host=127.0.0.1;; esac
  ans_set INDEXER_HOST "$host"; log_info "Adresse de l'indexer détectée : $host (network.host de opensearch.yml)"
  if ! secret_get INDEXER_ADMIN_PASSWORD >/dev/null; then
    explain <<'TXT'
Le bundle a besoin du mot de passe de l'utilisateur « admin » de l'indexer (fichier
wazuh-passwords.txt généré lors de l'installation de Wazuh) pour configurer la rétention
et Grafana. Il sera conservé dans /root/.wazuh-bundle/secrets.env (root uniquement).
TXT
    ask_secret INDEXER_ADMIN_PASSWORD "Mot de passe de l'utilisateur admin de l'indexer"
  fi
  run --hint "Mot de passe admin incorrect, ou indexer arrêté (systemctl status wazuh-indexer)." \
    "Test de connexion à l'indexer" indexer_api GET /
  exit 0
fi

explain <<'TXT'
L'installation « tout-en-un » met sur ce serveur :
  - wazuh-manager   : reçoit les événements des agents et applique les règles (ports 1514/1515) ;
  - wazuh-indexer   : base de données des alertes (OpenSearch, port 9200) ;
  - wazuh-dashboard : interface web (port 443).
Durée : 10 à 20 minutes. Le script officiel de Wazuh est téléchargé puis affiché (empreinte SHA256)
avant d'être exécuté.
TXT
ask WAZUH_BRANCH "Branche de Wazuh à installer" "4.14" v_version_branch
ask_choice INDEXER_HOST_MODE "Adresse d'écoute de l'indexer (port 9200)" local \
  "local|127.0.0.1 — recommandé : la base n'est pas exposée sur le réseau" \
  "reseau|${MANAGER_IP} — requis uniquement pour un Grafana installé sur une autre machine"
if [[ "$INDEXER_HOST_MODE" == local ]]; then INDEXER_HOST=127.0.0.1; else INDEXER_HOST="$MANAGER_IP"; fi
ans_set INDEXER_HOST "$INDEXER_HOST"

pkg_install curl tar gpg jq python3 ca-certificates
WORK="$(mktemp -d /root/wazuh-install-XXXXXX)"
cd "$WORK"
run --hint "Vérifier l'accès HTTPS à packages.wazuh.com et que la branche $WAZUH_BRANCH existe." \
  "Téléchargement de l'assistant officiel Wazuh $WAZUH_BRANCH" curl -fSL -o wazuh-install.sh "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"
run "Empreinte du script téléchargé (à comparer si votre politique l'exige)" sha256sum wazuh-install.sh
confirm "Lancer l'installation de Wazuh maintenant ?" || die "Installation annulée par l'utilisateur (le script reste dans $WORK)."

if [[ "$INDEXER_HOST" == 127.0.0.1 ]]; then
  run --hint "Journal détaillé : /var/log/wazuh-install.log" \
    "Installation tout-en-un (indexer sur 127.0.0.1)" bash wazuh-install.sh -a
else
  explain <<TXT
Mode « indexer sur ${MANAGER_IP} » : on suit la procédure officielle pas à pas avec un fichier
config.yml qui déclare l'adresse ${MANAGER_IP} pour l'indexer, le manager et le dashboard
(les certificats sont générés pour cette adresse).
TXT
  cat > config.yml <<YML
nodes:
  indexer:
    - name: node-1
      ip: "${MANAGER_IP}"
  server:
    - name: wazuh-1
      ip: "${MANAGER_IP}"
  dashboard:
    - name: dashboard
      ip: "${MANAGER_IP}"
YML
  run "Fichier config.yml utilisé" cat config.yml
  run "Génération des certificats et des mots de passe" bash wazuh-install.sh --generate-config-files
  run "Installation de l'indexer" bash wazuh-install.sh --wazuh-indexer node-1
  run "Initialisation du cluster de l'indexer" bash wazuh-install.sh --start-cluster
  run "Installation du manager (serveur Wazuh)" bash wazuh-install.sh --wazuh-server wazuh-1
  run "Installation du dashboard" bash wazuh-install.sh --wazuh-dashboard dashboard
fi

[[ -f wazuh-install-files.tar ]] || die "wazuh-install-files.tar absent : l'installation n'a pas produit ses fichiers (voir /var/log/wazuh-install.log)."
mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
run "Copie de l'archive des certificats et mots de passe (root uniquement)" install -m 600 wazuh-install-files.tar "$SECRETS_DIR/wazuh-install-files.tar"
run_sh "Extraction du fichier des mots de passe" "umask 077; tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > '$SECRETS_DIR/wazuh-passwords.txt'"
pw="$(grep -A1 "indexer_username: 'admin'" "$SECRETS_DIR/wazuh-passwords.txt" | grep indexer_password | sed "s/.*'\(.*\)'.*/\1/")"
[[ -n "$pw" ]] || die "Mot de passe admin introuvable dans $SECRETS_DIR/wazuh-passwords.txt"
secret_set INDEXER_ADMIN_PASSWORD "$pw"
cd /; run "Nettoyage du dossier de travail" rm -rf "$WORK"

ver="$(dpkg-query -W -f='${Version}' wazuh-manager)"; ans_set WAZUH_VERSION "$ver"
for s in wazuh-manager wazuh-indexer wazuh-dashboard; do run "État du service $s" systemctl is-active "$s"; done
run --hint "Le certificat de l'indexer doit contenir l'adresse $INDEXER_HOST." "Test de connexion à l'indexer ($(indexer_url))" indexer_api GET /

log_ok "Wazuh $ver installé."
cat <<TXT

  Dashboard     : https://${MANAGER_IP}   (utilisateur : admin)
  Mots de passe : $SECRETS_DIR/wazuh-passwords.txt (root uniquement)
  Version       : $ver — les agents doivent avoir une version INFÉRIEURE OU ÉGALE à celle du manager.
TXT
log_warn "Copier wazuh-passwords.txt dans le coffre de mots de passe de l'entreprise."
