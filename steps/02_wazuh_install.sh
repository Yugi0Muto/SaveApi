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

WAZUH_PKGS=(wazuh-manager wazuh-indexer wazuh-dashboard filebeat)
WAZUH_DIRS=(/var/ossec /etc/filebeat /var/lib/filebeat /usr/share/filebeat /etc/wazuh-indexer /var/lib/wazuh-indexer
            /usr/share/wazuh-indexer /var/log/wazuh-indexer /etc/wazuh-dashboard /usr/share/wazuh-dashboard
            /var/lib/wazuh-dashboard)
wazuh_complete() { local p; for p in "${WAZUH_PKGS[@]}"; do pkg_installed "$p" || return 1; done; }
# Restes : paquet présent dans n'importe quel état (installé, à moitié, fichiers de config restants) ou dossier
wazuh_remnants() {
  local p st d
  for p in "${WAZUH_PKGS[@]}"; do
    st="$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null || true)"
    [[ -n "$st" && "$st" != "un "* && "$st" != "pn "* ]] && echo "paquet $p (état dpkg : ${st// /})"
  done
  for d in "${WAZUH_DIRS[@]}"; do [[ -e "$d" ]] && echo "dossier $d"; done
  return 0
}

# Lance wazuh-install.sh : sortie rendue lisible par tools/wazuh_install_filter.py (journal brut complet
# dans /var/log/wazuh-install.log) ; en cas d'échec : extrait du journal, pistes, ARRÊT.
wazuh_install() {
  local desc="$1"; shift
  local rc
  echo "${BOLD}▶ ${desc}${NC}"
  echo "  ${DIM}\$ bash wazuh-install.sh $*${NC}   ${DIM}(journal détaillé : /var/log/wazuh-install.log)${NC}"
  set +e
  bash wazuh-install.sh "$@" 2>&1 | python3 "$BUNDLE_ROOT/tools/wazuh_install_filter.py"
  rc=${PIPESTATUS[0]}
  set -e
  if (( rc == 0 )); then echo "  ${GREEN}✔ réussi${NC} : ${desc}"; return 0; fi
  echo "  ${RED}✘ ÉCHEC${NC} (code retour $rc) : ${desc}"
  echo "  Dernières lignes du journal détaillé (/var/log/wazuh-install.log) :"
  tail -20 /var/log/wazuh-install.log 2>/dev/null | sed "s/^/  ${DIM}│${NC} /"
  local left; left="$(wazuh_remnants)"
  if [[ -n "$left" ]]; then
    echo "  ${YELLOW}Restes encore présents sur le système :${NC}"; sed 's/^/    - /' <<< "$left"
    echo "  ${YELLOW}Piste :${NC} relancer l'étape 02 : elle propose de nettoyer ces restes avant de réinstaller."
  fi
  die "Installation de Wazuh en échec. Lire les lignes « ✘ » et « ? » ci-dessus : elles donnent la cause."
}

clean_remnants() { # nettoyage complet d'une installation précédente ou partielle (après confirmation)
  local left="$1"
  explain <<TXT
Des éléments d'une installation précédente de Wazuh sont présents :
$(sed 's/^/  - /' <<< "$left")
L'installateur officiel ne sait pas installer par-dessus : il échoue (ex. « wazuh-keystore : Aucun
fichier », « wazuh-manager could not be started ») puis annule tout. Il faut d'abord nettoyer.
Le nettoyage SUPPRIME les données et la configuration de Wazuh présentes sur CE serveur (alertes,
certificats, règles). Les réponses et secrets du bundle sont conservés.
TXT
  confirm "Nettoyer complètement l'installation précédente de Wazuh sur ce serveur ?" \
    || die "Installation impossible tant que les restes sont présents (voir la liste ci-dessus)."
  [[ -f wazuh-install.sh ]] && run --allow-fail "Désinstallation officielle (wazuh-install.sh -u)" bash wazuh-install.sh -u || true
  local svc; for svc in wazuh-dashboard filebeat wazuh-manager wazuh-indexer; do
    systemctl list-unit-files "$svc.service" >/dev/null 2>&1 && systemctl stop "$svc" 2>/dev/null || true
  done
  local present=() p
  for p in "${WAZUH_PKGS[@]}"; do [[ -n "$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | grep -v '^[up]n' || true)" ]] && present+=("$p"); done
  (( ${#present[@]} )) && run "Purge des paquets restants : ${present[*]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${present[@]}"
  local d; for d in "${WAZUH_DIRS[@]}"; do [[ -e "$d" ]] && run "Suppression de $d" rm -rf -- "$d"; done
  left="$(wazuh_remnants)"
  [[ -z "$left" ]] || die "Nettoyage incomplet, restes : $left"
  log_ok "Système nettoyé : l'installation peut repartir de zéro."
}

if wazuh_complete; then
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
left="$(wazuh_remnants)"
if [[ -n "$left" ]]; then clean_remnants "$left"; else log_ok "Aucun reste d'installation précédente : système propre."; fi
confirm "Lancer l'installation de Wazuh maintenant ?" || die "Installation annulée par l'utilisateur (le script reste dans $WORK)."

if [[ "$INDEXER_HOST" == 127.0.0.1 ]]; then
  wazuh_install "Installation tout-en-un (indexer sur 127.0.0.1)" -a
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
  wazuh_install "Génération des certificats et des mots de passe" --generate-config-files
  wazuh_install "Installation de l'indexer" --wazuh-indexer node-1
  wazuh_install "Initialisation du cluster de l'indexer" --start-cluster
  wazuh_install "Installation du manager (serveur Wazuh)" --wazuh-server wazuh-1
  wazuh_install "Installation du dashboard" --wazuh-dashboard dashboard
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
