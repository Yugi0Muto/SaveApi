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

source "$BUNDLE_ROOT/lib/cleanup.sh"
source "$BUNDLE_ROOT/lib/indexer_expose.sh"
WAZUH_PKGS=(wazuh-manager wazuh-indexer wazuh-dashboard filebeat)
wazuh_complete() { local p; for p in "${WAZUH_PKGS[@]}"; do pkg_installed "$p" || return 1; done; }
blocking_traces() { trace_scan | grep -E '^(wazuh|conflict|system)\|' | cut -d'|' -f2- | sed 's/|/ : /; s/|/ — /' || true; }

# Lance wazuh-install.sh : sortie rendue lisible par tools/wazuh_install_filter.py (journal brut complet
# dans /var/log/wazuh-install.log) ; en cas d'échec : extrait du journal, pistes, ARRÊT.
wazuh_install() {
  local desc="$1"; shift
  local rc since before
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  before="$(wc -l < /var/log/wazuh-install.log 2>/dev/null || echo 0)"
  echo "${BOLD}▶ ${desc}${NC}"
  echo "  ${DIM}\$ bash wazuh-install.sh $*${NC}   ${DIM}(journal détaillé : /var/log/wazuh-install.log)${NC}"
  set +e
  bash wazuh-install.sh "$@" 2>&1 | python3 "$BUNDLE_ROOT/tools/wazuh_install_filter.py"
  rc=${PIPESTATUS[0]}
  set -e
  if (( rc == 0 )); then echo "  ${GREEN}✔ réussi${NC} : ${desc}"; return 0; fi
  echo "  ${RED}✘ ÉCHEC${NC} (code retour $rc) : ${desc}"
  install_failure_report "$since" "$before"
  die "Installation de Wazuh en échec. La cause est dans le diagnostic ci-dessus (section « Pourquoi »)."
}

# Diagnostic après échec : l'installateur a souvent déjà tout désinstallé (et effacé ossec.log) ; les preuves
# restent dans le journal système (journalctl), le journal du noyau (manque de mémoire) et le journal de
# l'installateur. Tout est affiché ET archivé pour pouvoir être transmis.
install_failure_report() {
  local since="$1" before="$2" diag f
  diag="$(mktemp -d)"
  section "Diagnostic de l'échec"
  # l'installateur peut recréer son journal à chaque tentative : alors on le prend en entier
  (( $(wc -l < /var/log/wazuh-install.log 2>/dev/null || echo 0) < before )) && before=0
  # mots de passe masqués (l'installateur peut les écrire dans son journal)
  tail -n +"$((before+1))" /var/log/wazuh-install.log 2>/dev/null \
    | sed -E -e "s/([Pp]ass(word)?[^:=]*[:=][[:space:]]*'?)[^' ]+/\1***masqué***/g" \
          -e "s/([Pp]assword (for|of) [^ ]+ (user )?[^ ]* ?is )[^ ]+/\1***masqué***/g" > "$diag/wazuh-install-cette-tentative.log" || true
  journalctl --since "$since" --no-pager -u wazuh-manager -u wazuh-indexer -u filebeat -u wazuh-dashboard \
    > "$diag/journal-services.log" 2>&1 || true
  journalctl -k --since "$since" --no-pager > "$diag/journal-noyau.log" 2>&1 || true
  { free -h; echo; df -h /var /tmp; echo; nproc; echo; cat /etc/os-release; } > "$diag/ressources.txt" 2>&1 || true

  echo "${BOLD}  Pourquoi — services Wazuh (journalctl depuis $since) :${NC}"
  f="$(grep -iE 'error|fail|critical|exception|denied|killed|timeout|timed out|exit-code|status=[1-9]' \
       "$diag/journal-services.log" | grep -v 'Started\|Starting' | tail -25 || true)"
  if [[ -n "$f" ]]; then sed "s/^/  ${DIM}│${NC} /" <<< "$f"; else echo "  │ (aucune ligne d'erreur des services dans le journal système)"; fi

  echo "${BOLD}  Pourquoi — installateur (lignes d'erreur de cette tentative) :${NC}"
  f="$(grep -iE 'ERROR|WARNING|could not|failed|denied|No such file|Aucun fichier|timeout' \
       "$diag/wazuh-install-cette-tentative.log" | tail -25 || true)"
  if [[ -n "$f" ]]; then sed "s/^/  ${DIM}│${NC} /" <<< "$f"; else tail -15 "$diag/wazuh-install-cette-tentative.log" | sed "s/^/  ${DIM}│${NC} /"; fi

  if grep -qiE "start operation timed out|result 'timeout'" "$diag/journal-services.log"; then
    echo "  ${RED}✘ Un service Wazuh a mis trop de temps à démarrer : systemd l'a abandonné (délai dépassé).${NC}"
    echo "  ${YELLOW}Cause :${NC} ressources insuffisantes ($(free -h | awk '/Mem:/{print $2}') de RAM, $(nproc) CPU) : l'indexer (Java)"
    echo "          occupe la machine pendant que le manager démarre."
    echo "  ${YELLOW}Solution :${NC} 8 Go de RAM et 4 CPU recommandés. À défaut, relancer l'étape 02 : le délai de démarrage"
    echo "          est porté à 15 minutes (vérifier : systemctl show wazuh-manager -p TimeoutStartUSec)."
  fi
  if grep -qiE 'out of memory|oom-kill|killed process' "$diag/journal-noyau.log"; then
    echo "  ${RED}✘ Le noyau a tué un processus faute de MÉMOIRE (OOM) pendant l'installation.${NC}"
    grep -iE 'out of memory|killed process' "$diag/journal-noyau.log" | tail -3 | sed "s/^/  ${DIM}│${NC} /"
    echo "  ${YELLOW}Piste :${NC} 8 Go de RAM minimum pour manager + indexer + dashboard sur un même serveur ;"
    echo "          ou réduire la mémoire de l'indexer (-Xms/-Xmx dans /etc/wazuh-indexer/jvm.options) après installation."
  fi
  echo "${BOLD}  Ressources :${NC} $(free -h | awk '/Mem:/{print "RAM " $2 " (disponible " $7 ")"}'), $(nproc) CPU, " \
       "/var libre : $(df -h --output=avail /var | tail -1 | tr -d ' ')"

  local left; left="$(blocking_traces)"
  if [[ -n "$left" ]]; then
    echo "  ${YELLOW}Restes laissés par l'installateur :${NC}"; sed 's/^/    - /' <<< "$left"
    echo "  ${YELLOW}Avant de relancer :${NC} l'étape 02 lancera le nettoyage (00b) automatiquement."
  fi
  local arch; arch="/root/wazuh-diag-$(date +%Y%m%d-%H%M%S).tar.gz"
  ( umask 077; tar -czf "$arch" -C "$diag" . ) && echo "  ${BOLD}Diagnostic complet archivé :${NC} $arch (à transmettre au support ; mots de passe masqués)"
  rm -rf "$diag"
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
explain <<TXT
Où sera Grafana (tableau de bord de supervision, étape 09) ?
  - pas de Grafana, ou Grafana sur CE serveur : la base des alertes (indexer, port 9200) reste
    accessible uniquement depuis ce serveur (127.0.0.1). Recommandé : rien n'est exposé ;
  - Grafana sur une AUTRE machine : l'indexer doit aussi écouter sur ${MANAGER_IP}. Le bundle fait
    l'installation tout-en-un puis ouvre l'indexer sur cette adresse (nouveau certificat), et le
    pare-feu de l'entreprise ne doit autoriser le port 9200 QUE depuis la machine Grafana.
TXT
ask_choice INDEXER_HOST_MODE "Grafana sera-t-il installé sur une autre machine ?" local \
  "local|Non (pas de Grafana, ou Grafana sur ce serveur) — indexer sur 127.0.0.1, recommandé" \
  "reseau|Oui — ouvrir aussi l'indexer sur ${MANAGER_IP}:9200"
if [[ "$INDEXER_HOST_MODE" == local ]]; then INDEXER_HOST=127.0.0.1; else INDEXER_HOST="$MANAGER_IP"; fi
ans_set INDEXER_HOST "$INDEXER_HOST"

pkg_install curl tar gpg jq python3 ca-certificates
WORK="$(mktemp -d /root/wazuh-install-XXXXXX)"
cd "$WORK"
run --hint "Vérifier l'accès HTTPS à packages.wazuh.com et que la branche $WAZUH_BRANCH existe." \
  "Téléchargement de l'assistant officiel Wazuh $WAZUH_BRANCH" curl -fSL -o wazuh-install.sh "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"
run "Empreinte du script téléchargé (à comparer si votre politique l'exige)" sha256sum wazuh-install.sh
# Le serveur doit être vierge de toute installation précédente (sinon l'installateur échoue puis annule tout)
if [[ -n "$(blocking_traces)" ]]; then
  log_warn "Des traces d'une installation précédente sont présentes : passage par l'étape 00b (nettoyage)."
  bash "$BUNDLE_ROOT/steps/00b_cleanup.sh" || die "Nettoyage non terminé : l'installation ne peut pas commencer."
  cd "$WORK"
else log_ok "Aucune trace d'installation précédente : système propre."; fi

# Délai de démarrage : systemd abandonne un service qui met plus de 90 s à démarrer. Sur un serveur
# modeste (4 Go / 2 CPU), le premier démarrage du manager dépasse ce délai pendant que l'indexer (Java)
# occupe la machine : l'installateur conclut à un échec et annule tout. On laisse 15 minutes.
section "Délai de démarrage des services Wazuh"
ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo); cpus=$(nproc)
log_info "Ressources : ${ram_mb} Mo de RAM, ${cpus} CPU (recommandé : 8 Go, 4 CPU)."
for u in wazuh-manager wazuh-indexer wazuh-dashboard; do
  run "Délai de démarrage de $u porté à 15 minutes (surcharge systemd)" install -D -m 644 /dev/stdin \
    "/etc/systemd/system/$u.service.d/$BUNDLE_DROPIN" <<'UNIT'
# Ajouté par wazuh-bundle (étape 02) : premier démarrage lent sur un serveur aux ressources limitées.
[Service]
TimeoutStartSec=900
UNIT
done
run "Prise en compte par systemd" systemctl daemon-reload
if (( ram_mb < 7500 || cpus < 4 )); then
  log_warn "Serveur sous les recommandations : l'installation sera LENTE (prévoir 30 à 45 min) et l'exploitation limitée."
  log_warn "Pour la production : 8 Go de RAM et 4 CPU (augmenter la machine virtuelle si possible)."
fi
confirm "Lancer l'installation de Wazuh maintenant ?" || die "Installation annulée par l'utilisateur (le script reste dans $WORK)."

# Toujours l'installation tout-en-un officielle (la plus éprouvée). La procédure « en plusieurs commandes »
# échoue de façon intermittente (« The Wazuh API user wazuh does not exist ») : elle n'est plus utilisée.
wazuh_install "Installation tout-en-un de Wazuh" -a

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
if [[ "$INDEXER_HOST" != 127.0.0.1 ]]; then
  section "Ouverture de l'indexer sur $INDEXER_HOST (Grafana distant)"
  expose_indexer "$INDEXER_HOST"
fi
run --hint "Le certificat de l'indexer doit contenir l'adresse $INDEXER_HOST." "Test de connexion à l'indexer ($(indexer_url))" indexer_api GET /

log_ok "Wazuh $ver installé."
cat <<TXT

  Dashboard     : https://${MANAGER_IP}   (utilisateur : admin)
  Mots de passe : $SECRETS_DIR/wazuh-passwords.txt (root uniquement)
  Version       : $ver — les agents doivent avoir une version INFÉRIEURE OU ÉGALE à celle du manager.
TXT
log_warn "Copier wazuh-passwords.txt dans le coffre de mots de passe de l'entreprise."
