#!/usr/bin/env bash
# lib/common.sh — bibliothèque partagée du wazuh-bundle (sourcée par install.sh, les étapes et les outils)
#
# Principes :
#   * Toute commande qui modifie le système passe par `run` : la commande est AFFICHÉE, sa sortie est
#     affichée, son code retour est vérifié. En cas d'échec : diagnostic + pistes, puis ARRÊT.
#   * Toute valeur de configuration est demandée par `ask*` (question + valeur par défaut + validation).
#     Les réponses sont mémorisées dans $ANSWERS_FILE (généré par le script, jamais à éditer à la main)
#     pour être proposées par défaut lors d'une relance et être lues par les tâches planifiées.
#   * Les secrets (mots de passe, clés API) sont stockés à part, dans $SECRETS_FILE (root, 600).
# shellcheck disable=SC2034

BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BUNDLE_VERSION="3.0.0"
STATE_DIR="${BUNDLE_STATE_DIR:-/etc/wazuh-bundle}"
ANSWERS_FILE="$STATE_DIR/answers.env"
SECRETS_DIR="${BUNDLE_SECRETS_DIR:-/root/.wazuh-bundle}"
SECRETS_FILE="$SECRETS_DIR/secrets.env"
LOG_DIR="${BUNDLE_LOG_DIR:-/var/log/wazuh-bundle}"
OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
INDEXER_CA="/etc/wazuh-indexer/certs/root-ca.pem"
# 1 = ne poser aucune question : réutiliser les réponses mémorisées (ou les valeurs par défaut)
NONINTERACTIVE="${BUNDLE_NONINTERACTIVE:-0}"

# ------------------------------------------------------------------ affichage
if [[ -t 1 || "${BUNDLE_COLOR:-0}" == 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'
  CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; DIM=""; NC=""
fi
log_info() { echo "${BLUE}[INFO]${NC} $*"; }
log_ok()   { echo "${GREEN}[ OK ]${NC} $*"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo "${RED}[ERREUR]${NC} $*" >&2; }
die()      { log_err "$*"; exit 1; }

# explain <<'TXT' ... TXT  : bloc d'explication (pourquoi on fait ce qu'on fait)
explain() { echo; sed "s/^/  ${CYAN}│${NC} /"; echo; }

step_header() { # step_header NN "Titre"
  echo
  echo "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
  echo "${BOLD}  Étape $1 — $2${NC}"
  echo "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
}
section() { echo; echo "${BOLD}── $* ──${NC}"; }

require_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Ce script doit être lancé en root (sudo -i)."; }

# ------------------------------------------------------------------ exécution explicite
# run [--hint "piste"] [--allow-fail] [--secret] [--quiet] "but de la commande" commande args...
#   --hint        piste de résolution affichée en cas d'échec
#   --allow-fail  l'échec est toléré EXPLICITEMENT : run renvoie le code d'erreur au lieu d'arrêter
#                 (à utiliser dans un `if run --allow-fail ...; then`)
#   --secret      n'affiche pas les arguments (ils contiennent un secret)
#   --quiet       n'affiche la sortie qu'en cas d'échec (sortie très volumineuse, ex. compilation)
# Variables positionnées : RUN_RC (code retour), RUN_OUTPUT (sortie complète, stdout+stderr)
RUN_RC=0; RUN_OUTPUT=""
run() {
  local hint="" allow_fail=0 secret=0 quiet=0
  while [[ "${1:-}" == --* ]]; do
    case "$1" in
      --hint) hint="$2"; shift 2;;
      --allow-fail) allow_fail=1; shift;;
      --secret) secret=1; shift;;
      --quiet) quiet=1; shift;;
      *) die "run : option inconnue $1";;
    esac
  done
  local desc="$1"; shift
  local shown
  if (( secret )); then shown="$1 … (arguments masqués : ils contiennent un secret)"
  else shown="$(printf '%q ' "$@")"; shown="${shown% }"; fi
  echo "${BOLD}▶ ${desc}${NC}"
  echo "  ${DIM}\$ ${shown}${NC}"
  local out errexit=0 rc
  out="$(mktemp)"
  [[ $- == *e* ]] && errexit=1
  set +e
  if (( quiet )); then
    "$@" >"$out" 2>&1; rc=$?
  else
    "$@" 2>&1 | tee "$out" | sed -u "s/^/  ${DIM}│${NC} /"; rc=${PIPESTATUS[0]}
  fi
  (( errexit )) && set -e
  RUN_RC=$rc; RUN_OUTPUT="$(cat "$out")"
  if (( rc == 0 )); then
    echo "  ${GREEN}✔ réussi${NC} (code retour 0)"; rm -f "$out"; return 0
  fi
  (( quiet )) && tail -40 "$out" | sed "s/^/  ${DIM}│${NC} /"
  echo "  ${RED}✘ ÉCHEC${NC} (code retour $rc) : ${desc}"
  diagnose "$out" "$rc" "$1"
  [[ -n "$hint" ]] && echo "  ${YELLOW}Piste :${NC} $hint"
  rm -f "$out"
  if (( allow_fail )); then log_warn "Échec toléré explicitement par le script : on continue."; return "$rc"; fi
  die "Arrêt de l'étape : « ${desc} » a échoué. Corriger la cause puis relancer l'étape (elle est rejouable)."
}

# run_sh "but" 'commande shell avec tubes ou redirections'  (affiche la ligne shell telle quelle)
run_sh() {
  local opts=()
  while [[ "${1:-}" == --* ]]; do
    if [[ "$1" == --hint ]]; then opts+=("$1" "$2"); shift 2; else opts+=("$1"); shift; fi
  done
  run "${opts[@]}" "$1" bash -o pipefail -c "$2"
}

# Diagnostic automatique : reconnaît les erreurs courantes et propose une solution
diagnose() { # diagnose fichier_sortie code commande
  local f="$1" rc="$2" cmd="$3" found=0
  _d() { echo "  ${YELLOW}Diagnostic :${NC} $1"; found=1; }
  case "$rc" in
    127) _d "commande « $cmd » introuvable : le paquet qui la fournit n'est pas installé (ou PATH incomplet).";;
    126) _d "« $cmd » n'est pas exécutable (droits ou montage noexec).";;
    124) _d "délai dépassé (timeout) : service lent ou réseau bloqué.";;
  esac
  grep -qiE "Could not resolve host|Temporary failure (in name resolution|resolving)|Name or service not known" "$f" &&
    _d "résolution DNS impossible : vérifier /etc/resolv.conf et l'accès au serveur DNS."
  grep -qiE "Connection refused" "$f" && _d "connexion refusée : le service distant n'écoute pas sur ce port (service arrêté, mauvais port)."
  grep -qiE "Connection timed out|timed out|Network is unreachable|No route to host" "$f" &&
    _d "pas de réponse réseau : un pare-feu filtre probablement le flux (voir « Flux réseau » dans le README)."
  grep -qiE "SSL certificate problem|certificate verify failed|unable to get local issuer|no alternative certificate subject name matches" "$f" &&
    _d "certificat TLS refusé : l'adresse utilisée n'est pas dans le certificat, ou la CA fournie n'est pas la bonne."
  grep -qiE "Could not get lock|dpkg was interrupted|Unable to acquire the dpkg frontend lock" "$f" &&
    _d "gestionnaire de paquets occupé ou interrompu : attendre la fin des mises à jour automatiques (unattended-upgrades) ou lancer « dpkg --configure -a »."
  grep -qiE "Unable to locate package|has no installation candidate" "$f" &&
    _d "paquet introuvable : lancer « apt-get update » et vérifier les dépôts (/etc/apt/sources.list*)."
  grep -qiE "No space left on device" "$f" && _d "disque plein : libérer de l'espace (df -h)."
  grep -qiE "Permission denied" "$f" && _d "permission refusée : droits du fichier, ou commande lancée sans root."
  grep -qiE "HTTP 401|Unauthorized" "$f" && _d "authentification refusée (401) : mot de passe incorrect ou utilisateur inexistant."
  grep -qiE "HTTP 403|Forbidden" "$f" && _d "accès interdit (403) : droits insuffisants, ou proxy/pare-feu sortant qui bloque."
  grep -qiE "Address already in use" "$f" && _d "port déjà utilisé par un autre programme : « ss -tlnp » pour l'identifier."
  grep -qiE "535 5\.7\.8|Username and Password not accepted|authentication failed" "$f" &&
    _d "authentification SMTP refusée : identifiant ou mot de passe incorrect (Gmail : utiliser un mot de passe d'application)."
  (( found )) || echo "  ${YELLOW}Diagnostic :${NC} lire la sortie ci-dessus ; la dernière ligne contient généralement la cause."
}

# ------------------------------------------------------------------ réponses mémorisées
ans_get() { # ans_get CLE -> valeur (vide si absente)
  [[ -f "$ANSWERS_FILE" ]] || return 0
  # shellcheck disable=SC1090
  ( set +u; source "$ANSWERS_FILE"; printf '%s' "${!1:-}" )
}
ans_set() { # ans_set CLE VALEUR
  mkdir -p "$STATE_DIR"; chmod 750 "$STATE_DIR"
  [[ -f "$ANSWERS_FILE" ]] || printf '# Réponses du wazuh-bundle, générées par les questions des étapes.\n# Ne pas éditer à la main : relancer l étape concernée.\n' > "$ANSWERS_FILE"
  chmod 600 "$ANSWERS_FILE"
  local tmp; tmp="$(mktemp "$STATE_DIR/.answers.XXXXXX")"
  grep -v "^$1=" "$ANSWERS_FILE" > "$tmp" || true
  printf '%s=%q\n' "$1" "$2" >> "$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$ANSWERS_FILE"
}
# load_answer CLE [défaut] : charge une réponse déjà donnée dans la variable CLE (sans poser de question)
load_answer() { local v; v="$(ans_get "$1")"; [[ -n "$v" ]] || v="${2:-}"; printf -v "$1" '%s' "$v"; }
# need_answer CLE "étape" : la valeur DOIT exister (posée par une étape précédente)
need_answer() { local v; v="$(ans_get "$1")"; [[ -n "$v" ]] || die "Valeur $1 inconnue : exécuter d'abord l'étape $2."; printf -v "$1" '%s' "$v"; }

_read() { # _read variable "invite"
  local __v
  if ! IFS= read -r -p "$2" __v; then die "Entrée standard fermée : impossible de poser la question."; fi
  printf -v "$1" '%s' "$__v"
}

# ask CLE "Question" "défaut" ["validateur args"]
ask() {
  local key="$1" q="$2" def="${3:-}" validator="${4:-}" saved val msg
  saved="$(ans_get "$key")"; [[ -n "$saved" ]] && def="$saved"
  while true; do
    if [[ "$NONINTERACTIVE" == 1 ]]; then
      val="$def"; echo "  ? $q : ${val} (réponse mémorisée / par défaut)"
    else
      _read val "  ${BOLD}?${NC} $q${def:+ [$def]} : "; val="${val:-$def}"
    fi
    val="$(printf '%s' "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [[ -n "$validator" ]]; then
      local -a vc; read -ra vc <<< "$validator"
      if ! msg="$("${vc[@]}" "$val" 2>&1)"; then
        log_err "Valeur refusée : ${msg}"
        [[ "$NONINTERACTIVE" == 1 ]] && die "Mode non interactif : la valeur de $key est invalide."
        continue
      fi
    fi
    break
  done
  ans_set "$key" "$val"; printf -v "$key" '%s' "$val"
}

# ask_yes_no CLE "Question" oui|non  -> code 0 si oui ; mémorise "oui"/"non" dans CLE
ask_yes_no() {
  local key="$1" q="$2" def="${3:-non}" saved a
  saved="$(ans_get "$key")"; [[ -n "$saved" ]] && def="$saved"
  while true; do
    if [[ "$NONINTERACTIVE" == 1 ]]; then a="$def"; echo "  ? $q : $a (réponse mémorisée / par défaut)"
    else _read a "  ${BOLD}?${NC} $q (oui/non) [$def] : "; a="${a:-$def}"; fi
    case "${a,,}" in
      o|oui|y|yes) a=oui; break;;
      n|non|no) a=non; break;;
      *) log_err "Répondre oui ou non."; [[ "$NONINTERACTIVE" == 1 ]] && die "Réponse invalide pour $key";;
    esac
  done
  ans_set "$key" "$a"; printf -v "$key" '%s' "$a"
  [[ "$a" == oui ]]
}

# ask_choice CLE "Question" défaut "cle1|Libellé 1" "cle2|Libellé 2" ...  -> mémorise la clé choisie
ask_choice() {
  local key="$1" q="$2" def="$3"; shift 3
  local saved a i=1 opt keys=()
  saved="$(ans_get "$key")"; [[ -n "$saved" ]] && def="$saved"
  echo "  ${BOLD}?${NC} $q"
  for opt in "$@"; do keys+=("${opt%%|*}"); echo "      $i) ${opt#*|}"; i=$((i+1)); done
  while true; do
    if [[ "$NONINTERACTIVE" == 1 ]]; then a="$def"; echo "    choix : $a (réponse mémorisée / par défaut)"
    else _read a "    Choix (numéro ou nom) [$def] : "; a="${a:-$def}"; fi
    if [[ "$a" =~ ^[0-9]+$ ]] && (( a >= 1 && a <= ${#keys[@]} )); then a="${keys[$((a-1))]}"; fi
    local k ok=0; for k in "${keys[@]}"; do [[ "$k" == "$a" ]] && ok=1; done
    (( ok )) && break
    log_err "Choix invalide."; [[ "$NONINTERACTIVE" == 1 ]] && die "Choix invalide pour $key"
  done
  ans_set "$key" "$a"; printf -v "$key" '%s' "$a"
}

# confirm "Question" -> code 0 si oui (non mémorisé ; en non interactif : non)
confirm() {
  local a
  [[ "$NONINTERACTIVE" == 1 ]] && { echo "  ? $1 : non (mode non interactif)"; return 1; }
  _read a "  ${BOLD}?${NC} $1 (oui/non) [non] : "
  [[ "${a,,}" =~ ^(o|oui|y|yes)$ ]]
}
pause() { [[ "$NONINTERACTIVE" == 1 ]] || { local _; _read _ "Entrée pour continuer..."; }; }

# ------------------------------------------------------------------ validateurs (affichent la raison du refus)
v_nonempty() { [[ -n "$1" ]] || { echo "valeur obligatoire"; return 1; }; }
v_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || { echo "« $1 » n'est pas une adresse IPv4 (ex : 10.10.10.20)"; return 1; }
  local o; for o in "${BASH_REMATCH[@]:1}"; do (( o <= 255 )) || { echo "octet $o > 255"; return 1; }; done
}
v_ip_or_cidr() {
  local ip="${1%/*}" m
  v_ipv4 "$ip" >/dev/null || { echo "« $1 » n'est ni une IPv4 ni un CIDR (ex : 10.10.10.0/24)"; return 1; }
  if [[ "$1" == */* ]]; then m="${1#*/}"; [[ "$m" =~ ^[0-9]{1,2}$ ]] && (( m <= 32 )) || { echo "masque invalide dans « $1 »"; return 1; }; fi
}
v_ip_list() { # liste (séparée par des espaces) d'IP/CIDR, éventuellement vide
  local x; for x in $1; do v_ip_or_cidr "$x" || return 1; done
}
v_ip_list_req() { [[ -n "$1" ]] || { echo "au moins une adresse est requise"; return 1; }; v_ip_list "$1"; }
v_int() { # v_int MIN MAX valeur
  [[ "$3" =~ ^[0-9]+$ ]] && (( $3 >= $1 && $3 <= $2 )) || { echo "entier attendu entre $1 et $2"; return 1; }
}
v_email() { [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || { echo "« $1 » n'est pas une adresse e-mail"; return 1; }; }
v_email_list() { [[ -n "$1" ]] || { echo "au moins une adresse"; return 1; }; local e; for e in $1; do v_email "$e" || return 1; done; }
v_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "« $1 » n'est pas un nom d'hôte ou une IP"; return 1; }; }
v_port() { v_int 1 65535 "$1"; }
v_phone_list() { [[ -n "$1" ]] || { echo "au moins un numéro"; return 1; }; local p; for p in $1; do [[ "$p" =~ ^\+[0-9]{8,15}$ ]] || { echo "« $p » : format international attendu (+241XXXXXXXX)"; return 1; }; done; }
v_abs_paths() { [[ -n "$1" ]] || { echo "au moins un répertoire"; return 1; }; local p; for p in $1; do [[ "$p" == /* && "$p" != *[\<\>\&,]* ]] || { echo "« $p » : chemin absolu attendu (sans < > & ,)"; return 1; }; done; }
v_url() { # URL https:// (ou file:// pour un miroir local), sans espace ni caractère parasite (] [ < > " ')
  [[ "$1" == https://* || "$1" == file://* ]] || { echo "l'URL doit commencer par https://"; return 1; }
  case "$1" in *[][\<\>\"\'[:space:]]*) echo "« $1 » contient un caractère interdit (espace, crochet, guillemet, < >) : erreur de copier-coller ?"; return 1;; esac
}
v_version_branch() { [[ "$1" =~ ^4\.[0-9]{1,2}$ ]] || { echo "branche attendue au format 4.NN (ex : 4.14)"; return 1; }; }

# ------------------------------------------------------------------ secrets (root 600, jamais affichés)
secret_set() { # secret_set CLE VALEUR
  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"; touch "$SECRETS_FILE"; chmod 600 "$SECRETS_FILE"
  local tmp; tmp="$(mktemp "$SECRETS_DIR/.secrets.XXXXXX")"
  grep -v "^$1=" "$SECRETS_FILE" > "$tmp" || true
  printf '%s=%q\n' "$1" "$2" >> "$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$SECRETS_FILE"
}
secret_get() { # secret_get CLE -> valeur ; code 1 si absente
  [[ -f "$SECRETS_FILE" ]] || return 1
  local v
  # shellcheck disable=SC1090
  v="$( set +u; source "$SECRETS_FILE"; printf '%s' "${!1:-}" )"
  [[ -n "$v" ]] || return 1
  printf '%s' "$v"
}
# ask_secret CLE "Question" : saisie masquée (deux fois), conservation possible de la valeur existante
ask_secret() {
  local key="$1" q="$2" a b
  if secret_get "$key" >/dev/null; then
    if [[ "$NONINTERACTIVE" == 1 ]]; then echo "  ? $q : (secret existant conservé)"; printf -v "$key" '%s' "$(secret_get "$key")"; return 0; fi
    if ! confirm "$q : un secret est déjà enregistré. Le remplacer ?"; then printf -v "$key" '%s' "$(secret_get "$key")"; return 0; fi
  fi
  [[ "$NONINTERACTIVE" == 1 ]] && die "Mode non interactif : le secret $key n'est pas enregistré."
  while true; do
    IFS= read -rs -p "  ${BOLD}?${NC} $q (saisie masquée) : " a || die "Entrée fermée"; echo
    IFS= read -rs -p "    Confirmer : " b || die "Entrée fermée"; echo
    [[ -n "$a" ]] || { log_err "Valeur vide."; continue; }
    [[ "$a" == "$b" ]] || { log_err "Les deux saisies diffèrent."; continue; }
    break
  done
  secret_set "$key" "$a"; printf -v "$key" '%s' "$a"
  log_ok "Secret enregistré dans $SECRETS_FILE (root uniquement)."
}
# Le "|| true" est nécessaire : head ferme le tube, tr reçoit SIGPIPE (code 141).
gen_password() { local p; p="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)"; printf '%s' "$p"; }

# ------------------------------------------------------------------ fichiers et paquets
backup_file() { # backup_file FICHIER -> LAST_BACKUP
  LAST_BACKUP=""
  if [[ -f "$1" ]]; then
    LAST_BACKUP="${1}.bak.$(date +%Y%m%d-%H%M%S)"
    run "Sauvegarde de $1 avant modification" cp -p "$1" "$LAST_BACKUP"
  fi
}
# output_has MOTIF commande... : vrai si la sortie de la commande contient le motif (ERE).
# La sortie est d'abord capturée : le code retour de la commande est ignoré (ex. « wazuh-control status »
# renvoie 1 dès qu'un démon optionnel est arrêté) et « grep -q » ne coupe pas le tube (SIGPIPE).
# Ne jamais écrire « commande | grep -q » dans un script en « set -o pipefail ».
output_has() { local pat="$1" out; shift; out="$("$@" 2>/dev/null || true)"; grep -Eq -- "$pat" <<< "$out"; }
pkg_installed() { output_has "install ok installed" dpkg-query -W -f='${Status}' "$1"; }
pkg_install() { # pkg_install paquet... (n'installe que les absents)
  local missing=() p
  for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
  if (( ${#missing[@]} == 0 )); then log_ok "Paquets déjà présents : $*"; return 0; fi
  run --hint "Vérifier l'accès aux dépôts APT (proxy ? DNS ?)" "Mise à jour de l'index des paquets" apt-get update
  run --hint "Lire le message d'apt ci-dessus ; « apt-get -f install » répare souvent les dépendances cassées" \
    "Installation des paquets : ${missing[*]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

# ------------------------------------------------------------------ Wazuh manager
wazuh_installed() { pkg_installed wazuh-manager; }
require_wazuh() { wazuh_installed || die "wazuh-manager n'est pas installé : exécuter d'abord l'étape 02."; }

# ossec_conf ARGS... : modification contrôlée de ossec.conf (voir lib/ossec_conf.py)
ossec_conf() { python3 "$BUNDLE_ROOT/lib/ossec_conf.py" "$OSSEC_CONF" "$@"; }

# Vérifie la configuration avec les outils Wazuh eux-mêmes (aucun redémarrage)
wazuh_config_check() {
  local d ok=0
  for d in wazuh-analysisd wazuh-remoted wazuh-authd wazuh-execd; do
    [[ -x "$OSSEC_DIR/bin/$d" ]] || continue
    run --allow-fail --hint "Le message ci-dessus indique la balise ou la règle fautive (fichier et ligne)." \
      "Test de configuration par $d" "$OSSEC_DIR/bin/$d" -t || ok=1
  done
  return $ok
}

# Redémarre le manager et vérifie réellement que les démons tournent (sinon : extrait d'ossec.log)
wazuh_restart() {
  local before
  before="$(wc -l < "$OSSEC_DIR/logs/ossec.log" 2>/dev/null || echo 0)"
  run --allow-fail "Redémarrage du manager Wazuh" systemctl restart wazuh-manager || true
  # « wazuh-control status » renvoie 1 dès qu'un démon OPTIONNEL est arrêté (clusterd, maild,
  # agentlessd, integratord, csyslogd : normal sur un serveur seul) : on lit sa sortie, pas son code.
  local i st errs
  for i in $(seq 1 45); do
    st="$("$OSSEC_DIR/bin/wazuh-control" status 2>&1 || true)"
    if grep -q "wazuh-analysisd is running" <<< "$st" && grep -q "wazuh-remoted is running" <<< "$st" &&
       systemctl is-active --quiet wazuh-manager; then
      log_ok "wazuh-manager actif (analysisd et remoted démarrés, vérifié en $((i*2)) s)."; return 0
    fi
    sleep 2
  done
  log_err "Le manager ne démarre pas correctement (analysisd ou remoted arrêté après 90 s)."
  errs="$(tail -n +"$((before+1))" "$OSSEC_DIR/logs/ossec.log" 2>/dev/null | grep -E "ERROR|CRITICAL" | tail -20 || true)"
  if [[ -n "$errs" ]]; then echo "  Erreurs relevées dans ossec.log depuis le redémarrage :"; sed 's/^/  │ /' <<< "$errs"
  else echo "  Aucune ligne ERROR/CRITICAL dans ossec.log depuis le redémarrage."; fi
  echo "  État des démons :"; sed 's/^/  │ /' <<< "$st"
  run --allow-fail "Journal systemd du manager" journalctl -u wazuh-manager -n 20 --no-pager || true
  return 1
}

# Transaction sur ossec.conf : ossec_begin ; modifications ; ossec_commit
OSSEC_BAK=""
ossec_begin() { require_wazuh; backup_file "$OSSEC_CONF"; OSSEC_BAK="$LAST_BACKUP"; }
ossec_restore() {
  [[ -n "$OSSEC_BAK" && -f "$OSSEC_BAK" ]] || return 0
  log_warn "Restauration de la configuration précédente ($OSSEC_BAK)."
  cp -p "$OSSEC_BAK" "$OSSEC_CONF"
}
ossec_commit() {
  if ! wazuh_config_check; then
    ossec_restore
    die "Configuration refusée par Wazuh : ossec.conf a été restauré, le manager n'a PAS été redémarré."
  fi
  if ! wazuh_restart; then
    ossec_restore; wazuh_restart || true
    die "Le manager ne démarrait pas avec la nouvelle configuration : ossec.conf restauré."
  fi
}

# Déploiement transactionnel de fichiers de règles/décodeurs :
#   rules_deploy "src:dest" ...   puis validation Wazuh ; restauration de l'état précédent en cas d'échec.
#   Une destination dont la source est "-" est SUPPRIMÉE (ex. fichiers de l'ancienne version).
rules_deploy() {
  local pair src dst snap; snap="$(mktemp -d)"
  for pair in "$@"; do
    dst="${pair#*:}"
    [[ -f "$dst" ]] && cp -p "$dst" "$snap/$(echo "$dst" | tr '/' '_')"
  done
  for pair in "$@"; do
    src="${pair%%:*}"; dst="${pair#*:}"
    if [[ "$src" == "-" ]]; then
      [[ -f "$dst" ]] && run "Suppression de l'ancien fichier $dst" rm -f "$dst"
    else
      run "Installation de $dst" install -o wazuh -g wazuh -m 660 "$src" "$dst"
    fi
  done
  if wazuh_config_check; then rm -rf "$snap"; return 0; fi
  log_warn "Règles refusées par Wazuh : retour à l'état précédent."
  for pair in "$@"; do
    dst="${pair#*:}"; rm -f "$dst"
    [[ -f "$snap/$(echo "$dst" | tr '/' '_')" ]] && cp -p "$snap/$(echo "$dst" | tr '/' '_')" "$dst"
  done
  rm -rf "$snap"; return 1
}

# logtest_file FICHIER : rejoue chaque cas « ids|ligne » avec wazuh-logtest ; code 0 si tous passent
logtest_file() {
  local ids line out got n=0 bad=0
  while IFS='|' read -r ids line; do
    [[ -z "$ids" || "$ids" == \#* ]] && continue
    n=$((n+1))
    echo "${BOLD}▶ Test de règle : attendu ${ids}${NC}"
    echo "  ${DIM}\$ echo '${line}' | $OSSEC_DIR/bin/wazuh-logtest${NC}"
    out="$(printf '%s\n' "$line" | timeout 60 "$OSSEC_DIR/bin/wazuh-logtest" 2>&1 || true)"
    got="$(grep -oE "id: '[0-9]+'" <<< "$out" | tail -1 | grep -oE '[0-9]+' || true)"
    if [[ ",$ids," == *",$got,"* ]]; then echo "  ${GREEN}✔ règle $got déclenchée${NC}"
    else
      bad=$((bad+1)); echo "  ${RED}✘ règle obtenue : ${got:-aucune}${NC} — sortie de wazuh-logtest :"
      sed "s/^/  ${DIM}│${NC} /" <<< "$out" | tail -25
    fi
  done < "$1"
  (( bad == 0 )) && log_ok "$n test(s) de règles réussi(s)." || log_err "$bad test(s) de règles sur $n en échec."
  return $(( bad > 0 ))
}

# dirs_to_regex /var/www /tmp ... -> ^(/var/www|/tmp)/   (caractères spéciaux échappés, pour PCRE2)
dirs_to_regex() {
  local d parts=()
  for d in "$@"; do d="${d%/}"; parts+=("$(sed 's/[][()*+?^$|{}.\\]/\\&/g' <<< "$d")"); done
  (IFS='|'; printf '^(%s)/' "${parts[*]}")
}

# ------------------------------------------------------------------ indexer (OpenSearch)
indexer_url() { local h; h="$(ans_get INDEXER_HOST)"; printf 'https://%s:9200' "${h:-127.0.0.1}"; }
# indexer_api MÉTHODE /chemin [corps-json] : affiche la réponse + "HTTP nnn" ; code 0 si 2xx
indexer_api() {
  local method="$1" path="$2" body="${3:-}" pw code resp args=()
  pw="$(secret_get INDEXER_ADMIN_PASSWORD)" || { echo "mot de passe admin de l'indexer inconnu (étape 02)"; return 1; }
  pw="${pw//\\/\\\\}"; pw="${pw//\"/\\\"}"
  resp="$(mktemp)"
  args=(-sS -g -m 60 -K - --cacert "$INDEXER_CA" -X "$method" -o "$resp" -w '%{http_code}')
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  if ! code="$(printf 'user = "admin:%s"\n' "$pw" | curl "${args[@]}" "$(indexer_url)$path")"; then
    cat "$resp"; rm -f "$resp"; return 1
  fi
  cat "$resp"; echo; echo "HTTP $code"; rm -f "$resp"
  [[ "$code" =~ ^2 ]]
}

# ism_attach POLITIQUE MOTIF : applique une politique ISM aux index EXISTANTS qui correspondent au motif.
#   - aucun index (ex. wazuh-archives-* tant que l'archivage n'est pas activé) : rien à faire, les futurs
#     index recevront la politique automatiquement (ism_template) ;
#   - index sans politique : _ism/add ; index déjà gérés : _ism/change_policy (nouvelle version).
ism_attach() {
  local id="$1" pattern="$2" list n
  run --hint "Vérifier l'étape 02 (mot de passe admin) et que wazuh-indexer est actif." \
    "Index existants correspondant à $pattern" indexer_api GET "/_cat/indices/${pattern}?h=index&s=index"
  list="$(grep -vE '^(HTTP [0-9]+)?[[:space:]]*$' <<< "$RUN_OUTPUT" || true)"
  n="$(grep -c . <<< "$list" || true)"
  if [[ -z "$list" ]]; then
    log_info "Aucun index $pattern pour l'instant : rien à rattacher. Les futurs index recevront automatiquement la politique $id."
    return 0
  fi
  log_info "$n index $pattern trouvé(s)."
  run "Rattachement des index $pattern sans politique à $id" indexer_api POST "/_plugins/_ism/add/${pattern}" "{\"policy_id\":\"${id}\"}"
  if ! run --allow-fail "Mise à jour des index $pattern déjà gérés (nouvelle version de $id)" \
         indexer_api POST "/_plugins/_ism/change_policy/${pattern}" "{\"policy_id\":\"${id}\"}"; then
    # « no documents to get » : aucun de ces index n'était encore géré par ISM -> rien à mettre à jour
    if grep -q "no documents to get" <<< "$RUN_OUTPUT"; then
      log_info "Aucun index $pattern n'était déjà géré par ISM : rien à mettre à jour (ce n'est pas une erreur)."
    else
      die "Mise à jour de la politique des index $pattern impossible (réponse ci-dessus)."
    fi
  fi
}

# ------------------------------------------------------------------ flux réseau (documentation pour l'équipe pare-feu)
network_flows() {
  local mip admins gmode gips ehost eport sms
  mip="$(ans_get MANAGER_IP)"; admins="$(ans_get ADMIN_IPS)"
  gmode="$(ans_get GRAFANA_MODE)"; gips="$(ans_get GRAFANA_REMOTE_IPS)"
  ehost="$(ans_get EMAIL_SMTP_HOST)"; eport="$(ans_get EMAIL_SMTP_PORT)"; sms="$(ans_get SMS_ENABLE)"
  cat <<TXT
Flux réseau à autoriser sur le pare-feu de l'entreprise (le bundle ne configure AUCUN pare-feu)
Serveur Wazuh : ${mip:-<IP du serveur>}

  Source                         Destination              Port            Rôle
  ------------------------------ ------------------------ --------------- -----------------------------------
  Tous les agents (3 segments)   serveur Wazuh            TCP 1514        envoi des événements des agents
  Tous les agents (3 segments)   serveur Wazuh            TCP 1515        enrôlement (inscription) des agents
  Postes d'administration        serveur Wazuh            TCP 443         interface web (Wazuh Dashboard)
  Postes d'administration        serveur Wazuh            TCP 22          administration SSH
TXT
  [[ -n "$admins" ]] && echo "    (postes d'administration déclarés : $admins)"
  if [[ "$gmode" == local ]]; then
    echo "  Postes d'administration        serveur Wazuh            TCP 3000        Grafana (installé sur le serveur)"
  elif [[ "$gmode" == remote ]]; then
    echo "  Machine Grafana (${gips})  serveur Wazuh    TCP 9200        lecture de l'indexer (UNIQUEMENT cette machine)"
  fi
  cat <<TXT
  Serveur Wazuh                  Internet                 TCP 443         paquets Wazuh/Debian, règles YARA (GitHub), abuse.ch
TXT
  [[ -n "$ehost" ]] && echo "  Serveur Wazuh                  ${ehost}  TCP ${eport}   envoi des alertes e-mail"
  [[ "$sms" == oui ]] && echo "  Serveur Wazuh                  api.africastalking.com   TCP 443         envoi des alertes SMS"
  cat <<TXT

  À NE PAS ouvrir : 9200 (indexer) et 55000 (API Wazuh) depuis les segments employés et DMZ.
TXT
}
