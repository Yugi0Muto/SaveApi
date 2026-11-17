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
explain <<'TXT'
Branche 4.14 = dernière branche stable de Wazuh (version 4.14.10 au 17/11/2026 ; la 5.0 n'est
encore qu'en préversion). L'assistant d'une branche installe toujours la DERNIÈRE version de cette
branche : la version exacte est affichée après le téléchargement.
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
WIA_VERSION="$(sed -n 's/^readonly wazuh_version="\(.*\)"$/\1/p' wazuh-install.sh | head -1)"
log_info "Version de Wazuh installée par cet assistant : ${WIA_VERSION:-inconnue}"
cp wazuh-install.sh wazuh-install.sh.orig
confirm "Lancer l'installation de Wazuh maintenant ?" || die "Installation annulée par l'utilisateur (le script reste dans $WORK)."

# ── Erreur connue « The Wazuh API user wazuh does not exist » (github.com/wazuh/wazuh/issues/24587) ──
# L'assistant change les mots de passe de l'API juste après avoir démarré wazuh-manager ; si l'API
# ne répond pas encore, il ne trouve pas les utilisateurs « wazuh » et « wazuh-wui ». Le menu de
# solutions n'est proposé QUE si ce message apparaît.
API_ERR_RE="The Wazuh API user [^ ]+ does not exist|User [^ ]+ is not registered in Wazuh API"
API_URL="https://localhost:55000"
DASH_WAZUH_YML=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

api_token() { # api_token UTILISATEUR MOT_DE_PASSE -> jeton JWT (code 1 si refusé ou API absente)
  local t
  t="$(curl -sk --max-time 10 -u "$1:$2" -X POST "$API_URL/security/user/authenticate?raw=true" 2>/dev/null || true)"
  [[ "$t" == eyJ* ]] || return 1
  printf '%s' "$t"
}
file_api_password() { # file_api_password UTILISATEUR -> mot de passe API du fichier wazuh-passwords.txt
  tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
    | grep -A1 "api_username: '$1'" | grep api_password | sed "s/.*'\(.*\)'.*/\1/"
}
api_check() { # l'API accepte-t-elle wazuh-wui avec le mot de passe généré ?
  local pw; pw="$(file_api_password wazuh-wui)"
  [[ -n "$pw" ]] && api_token wazuh-wui "$pw" >/dev/null
}

apply_patches() { # reconstruit wazuh-install.sh depuis l'original + les corrections de PATCHES
  cp wazuh-install.sh.orig wazuh-install.sh
  local p
  for p in "${PATCHES[@]}"; do patch_installer "${p%%:*}" "${p#*:}"; done
}

patch_installer() { # patch_installer attente SECONDES | sansapi - | ippublique -
  python3 - "$@" <<'PYP'
import sys, re
mode = sys.argv[1]
path = "wazuh-install.sh"
s = open(path).read()
if mode == "attente":
    delay = int(sys.argv[2])
    anchor = "function installCommon_changePasswords() {\n"
    if s.count(anchor) != 1:
        sys.exit("fonction installCommon_changePasswords introuvable : correctif non applicable à cette version")
    helper = f"""function bundle_waitApi() {{
    # Ajout wazuh-bundle : attendre que l'API Wazuh réponde et connaisse ses utilisateurs
    if [ -z "${{wazuh}}" ] && [ -z "${{AIO}}" ]; then return 0; fi
    local waited=0 tok users
    common_logger "[wazuh-bundle] Attente de l'API Wazuh avant le changement des mots de passe (max {delay}s)."
    while [ "${{waited}}" -lt {delay} ]; do
        tok=$(curl -s -k --max-time 10 -u "${{adminUser}}:${{adminPassword}}" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
        if [[ "${{tok}}" == eyJ* ]]; then
            users=$(curl -s -k --max-time 10 -H "Authorization: Bearer ${{tok}}" "https://localhost:55000/security/users")
            if grep -q '"username": *"wazuh-wui"' <<< "${{users}}" && grep -q '"username": *"wazuh"' <<< "${{users}}"; then
                common_logger "[wazuh-bundle] API Wazuh prête après ${{waited}}s."
                sleep 10
                return 0
            fi
        fi
        sleep 5
        waited=$((waited+5))
    done
    common_logger -w "[wazuh-bundle] L'API Wazuh ne répond toujours pas après {delay}s : on continue quand même."
}}

"""
    s = s.replace(anchor, helper + anchor + "    bundle_waitApi\n", 1)
elif mode == "sansapi":
    anchor = "function installCommon_changePasswordApi() {\n"
    if s.count(anchor) != 1:
        sys.exit("fonction installCommon_changePasswordApi introuvable : correctif non applicable à cette version")
    s = s.replace(anchor, anchor + '    common_logger "[wazuh-bundle] Changement des mots de passe de l\'API reporté après l\'installation."\n    return 0\n', 1)
elif mode == "ippublique":
    pat = re.compile(r'common_logger -e "The IP \$\{ip\} is public\."\n(\s*)exit 1\n')
    s, n = pat.subn(lambda m: 'common_logger -w "[wazuh-bundle] The IP ${ip} is public: accepted on purpose (filter port 9200 on the firewall)."\n', s)
    if n == 0:
        sys.exit("contrôle « IP publique » introuvable : correctif non applicable à cette version")
else:
    sys.exit("mode inconnu")
open(path, "w").write(s)
PYP
}

show_patch() {
  log_info "Modifications apportées à l'assistant :"
  diff -u wazuh-install.sh.orig wazuh-install.sh | sed "s/^/    /" || true
}

install_attempt() { # install_attempt [-o] : lance l'installation ; INSTALL_RC et INSTALL_LOG
  local ow=("$@") log="$WORK/attempt.log" rc=0
  : > "$log"
  if [[ "$INDEXER_HOST" == 127.0.0.1 ]]; then
    run --allow-fail --hint "Journal détaillé : /var/log/wazuh-install.log" \
      "Installation tout-en-un (indexer sur 127.0.0.1)" bash wazuh-install.sh -a "${ow[@]}" "${EXTRA[@]}" || rc=$?
    printf '%s\n' "$RUN_OUTPUT" >> "$log"
  else
    if (( ${#ow[@]} == 0 )); then
      explain <<TXT
Mode « indexer sur ${NODE_ADDR} » : on suit la procédure officielle pas à pas avec un fichier
config.yml qui déclare l'adresse ${NODE_ADDR} pour l'indexer, le manager et le dashboard
(les certificats sont générés pour cette adresse).
TXT
    fi
    cat > config.yml <<YML
nodes:
  indexer:
    - name: node-1
      ip: "${NODE_ADDR}"
  server:
    - name: wazuh-1
      ip: "${NODE_ADDR}"
  dashboard:
    - name: dashboard
      ip: "${NODE_ADDR}"
YML
    rm -f wazuh-install-files.tar
    run "Fichier config.yml utilisé" cat config.yml
    local -a steps=(
      "Génération des certificats et des mots de passe|--generate-config-files"
      "Installation de l'indexer|--wazuh-indexer node-1 ${ow[*]} ${EXTRA[*]}"
      "Initialisation du cluster de l'indexer|--start-cluster"
      "Installation du manager (serveur Wazuh)|--wazuh-server wazuh-1 ${ow[*]} ${EXTRA[*]}"
      "Installation du dashboard|--wazuh-dashboard dashboard ${ow[*]} ${EXTRA[*]}")
    local st args
    for st in "${steps[@]}"; do
      read -ra args <<< "${st#*|}"
      run --allow-fail "${st%%|*}" bash wazuh-install.sh "${args[@]}" || rc=$?
      printf '%s\n' "$RUN_OUTPUT" >> "$log"
      (( rc == 0 )) || break
    done
  fi
  INSTALL_RC=$rc; INSTALL_LOG="$log"
}

api_passwords_after() { # pose les mots de passe API de wazuh-passwords.txt une fois l'API prête
  local max="$1" waited=0 tok wui_pw wz_pw admin_pw=wazuh id u pw
  wui_pw="$(file_api_password wazuh-wui)"; wz_pw="$(file_api_password wazuh)"
  [[ -n "$wui_pw" && -n "$wz_pw" ]] || { log_err "Mots de passe de l'API absents de wazuh-install-files.tar."; return 1; }
  log_info "Attente de l'API Wazuh ($API_URL), au plus ${max}s..."
  while (( waited < max )); do
    if tok="$(api_token wazuh wazuh)"; then admin_pw=wazuh; break; fi
    if tok="$(api_token wazuh "$wz_pw")"; then admin_pw="$wz_pw"; break; fi
    sleep 5; waited=$((waited+5))
  done
  [[ -n "${tok:-}" ]] || { log_err "L'API Wazuh n'a pas répondu en ${max}s (systemctl status wazuh-manager)."; return 1; }
  log_ok "API Wazuh prête après ${waited}s."
  for u in wazuh-wui wazuh; do
    if [[ $u == wazuh-wui ]]; then pw="$wui_pw"; else pw="$wz_pw"; fi
    [[ $u == wazuh && "$admin_pw" == "$wz_pw" ]] && { log_ok "Utilisateur API wazuh : mot de passe déjà à jour."; continue; }
    id=""
    for _ in $(seq 1 24); do
      id="$(curl -sk --max-time 10 -H "Authorization: Bearer $tok" "$API_URL/security/users" \
        | jq -r --arg u "$u" '.data.affected_items[]? | select(.username==$u) | .id' 2>/dev/null || true)"
      [[ -n "$id" ]] && break; sleep 5
    done
    [[ -n "$id" ]] || { log_err "Utilisateur API $u toujours introuvable."; return 1; }
    run --secret --quiet "Mot de passe de l'utilisateur API $u" bash -o pipefail -c \
      'curl -sk --max-time 30 -X PUT -H "Authorization: Bearer $1" -H "Content-Type: application/json" -d "$(jq -cn --arg p "$2" "{password:\$p}")" "$3" | jq -e ".error == 0" >/dev/null' \
      _ "$tok" "$pw" "$API_URL/security/users/$id"
  done
  if [[ -f "$DASH_WAZUH_YML" ]]; then
    backup_file "$DASH_WAZUH_YML"
    WUI_PW="$wui_pw" python3 - "$DASH_WAZUH_YML" <<'PYD'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'(?m)^(\s*password:\s*).*$', lambda m: m.group(1) + '"' + os.environ["WUI_PW"] + '"', s)
open(p, "w").write(s)
PYD
    log_ok "Mot de passe de wazuh-wui inscrit dans $DASH_WAZUH_YML."
    run "Redémarrage du dashboard" systemctl restart wazuh-dashboard
  fi
}

# ── Erreurs connues : un menu de solutions n'est proposé QUE si l'une d'elles apparaît ──
HW_RE="does not meet the recommended minimum hardware requirements"
PUBIP_RE="The IP [^ ]+ is public"
EXTRA=(); PATCHES=(); NODE_ADDR="$MANAGER_IP"
v_fqdn() { [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]] || { echo "nom DNS complet attendu (ex : wazuh.lan)"; return 1; }; }
known_error() { # -> hw | pubip | api | (rien)
  if grep -Eq "$HW_RE" "$INSTALL_LOG"; then echo hw
  elif grep -Eq "$PUBIP_RE" "$INSTALL_LOG"; then echo pubip
  elif grep -Eq "$API_ERR_RE" "$INSTALL_LOG"; then echo api
  fi
}
add_patch() { local p; for p in "${PATCHES[@]}"; do [[ "$p" == "$1" ]] && return 0; done; PATCHES+=("$1"); }
del_patch() { local p keep=(); for p in "${PATCHES[@]}"; do [[ "$p" == "$1"* ]] || keep+=("$p"); done; PATCHES=("${keep[@]}"); }
add_extra() { local e; for e in "${EXTRA[@]}"; do [[ "$e" == "$1" ]] && return 0; done; EXTRA+=("$1"); }
retry() { # relance avec les corrections en cours
  if (( ${#PATCHES[@]} )); then run "Corrections de l'assistant : ${PATCHES[*]}" apply_patches; show_patch
  else cp wazuh-install.sh.orig wazuh-install.sh; fi
  install_attempt -o
}
make_swap() { # make_swap GO : fichier d'échange /swapfile (persistant)
  local gb="$1" avail_gb
  if grep -qx /swapfile <<< "$(swapon --show=NAME --noheadings 2>/dev/null || true)"; then log_ok "/swapfile est déjà actif."; return 0; fi
  avail_gb=$(( $(df --output=avail -k / | tail -1) / 1024 / 1024 ))
  (( avail_gb > gb + 5 )) || die "Espace disque insuffisant pour ${gb} Go de swap (${avail_gb} Go libres sur /)."
  [[ -e /swapfile ]] && die "/swapfile existe déjà mais n'est pas actif : le vérifier à la main (swapon /swapfile)."
  run "Création du fichier d'échange de ${gb} Go" bash -c "fallocate -l ${gb}G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((gb*1024)) status=none"
  run "Droits du fichier d'échange (root uniquement)" chmod 600 /swapfile
  run "Formatage du fichier d'échange" mkswap /swapfile
  run "Activation du fichier d'échange" swapon /swapfile
  if ! grep -qE '^/swapfile[[:space:]]' /etc/fstab; then
    backup_file /etc/fstab
    run_sh "Activation au démarrage (/etc/fstab)" "echo '/swapfile none swap sw 0 0' >> /etc/fstab"
  fi
  run_sh "Swap utilisé en dernier recours (vm.swappiness=10)" "echo 'vm.swappiness=10' > /etc/sysctl.d/99-wazuh-bundle-swap.conf && sysctl -q -p /etc/sysctl.d/99-wazuh-bundle-swap.conf"
  run "Mémoire disponible" free -h
}

install_attempt
attempt=1
while kind="$(known_error)"; [[ -n "$kind" ]]; do
  echo
  (( attempt <= 5 )) || die "Erreur toujours présente après $attempt tentatives. Journal : /var/log/wazuh-install.log"
  [[ "$NONINTERACTIVE" == 1 && $attempt -gt 1 ]] && die "Mode non interactif : une erreur connue persiste après la première solution."
  attempt=$((attempt+1))
  case "$kind" in
  hw)
    cores="$(nproc)"; ram_mb="$(free -m | awk 'NR==2{print $2}')"; swap_mb="$(free -m | awk '/^Swap/{print $2}')"
    log_warn "Erreur connue détectée : ressources sous le minimum recommandé par Wazuh."
    explain <<TXT
Ce serveur : ${cores} cœur(s), ${ram_mb} Mo de RAM, ${swap_mb} Mo de swap.
Wazuh demande au moins 2 cœurs et 4 Go de RAM pour l'indexer et le dashboard (contrôle sur la RAM
totale, seuil 3 700 Mo). L'option officielle -i permet de passer outre : l'installation fonctionne
mais l'indexer (Java) risque d'être lent ou arrêté par manque de mémoire sous forte charge.
Un fichier d'échange (swap) évite cet arrêt brutal ; il ne compense pas un processeur trop faible.
Rien n'a encore été installé.
TXT
    ask_choice HW_FIX "Solution à essayer" swap \
      "swap|Créer un fichier d'échange (swap) puis relancer en ignorant le contrôle (-i) — recommandé" \
      "ignorer|Relancer en ignorant le contrôle (-i), sans autre changement" \
      "abandon|Arrêter l'étape (rien n'est modifié)"
    case "$HW_FIX" in
      abandon) die "Arrêt demandé." ;;
      swap) ask SWAP_GB "Taille du fichier d'échange, en Go" "4" "v_int 1 32"; make_swap "$SWAP_GB" ;;
    esac
    add_extra -i
    retry ;;
  pubip)
    log_warn "Erreur connue détectée : $(grep -Eo "$PUBIP_RE" "$INSTALL_LOG" | head -1)"
    explain <<TXT
L'assistant Wazuh refuse d'inscrire une adresse IP publique (${NODE_ADDR}) dans les certificats,
pour éviter d'exposer l'indexer sur Internet. Ce contrôle ne concerne que les adresses IP : un nom
DNS est accepté. Rien n'a encore été installé.
TXT
    ask_choice PUBIP_FIX "Solution à essayer" ippublique \
      "ippublique|Garder ${MANAGER_IP} avec une copie de l'assistant qui accepte l'IP publique (filtrer le port 9200 au pare-feu)" \
      "nom|Utiliser un nom DNS (ex : wazuh.lan) qui pointe vers ${MANAGER_IP} ; le serveur Grafana devra aussi le résoudre" \
      "local|Revenir à l'indexer sur 127.0.0.1 (Grafana devra alors être sur ce serveur)" \
      "abandon|Arrêter l'étape (rien n'est modifié)"
    case "$PUBIP_FIX" in
      abandon) die "Arrêt demandé." ;;
      ippublique) add_patch "ippublique:-"; NODE_ADDR="$MANAGER_IP" ;;
      nom)
        ask WAZUH_NODE_NAME "Nom DNS du serveur Wazuh" "wazuh.lan" v_fqdn
        if [[ "$(getent ahostsv4 "$WAZUH_NODE_NAME" | awk 'NR==1{print $1}')" != "$MANAGER_IP" ]]; then
          backup_file /etc/hosts
          run_sh "Déclaration de $WAZUH_NODE_NAME → $MANAGER_IP dans /etc/hosts" \
            "sed -i '/[[:space:]]${WAZUH_NODE_NAME//./\\.}\([[:space:]]\|\$\)/d' /etc/hosts && echo '${MANAGER_IP} ${WAZUH_NODE_NAME} # wazuh-bundle' >> /etc/hosts"
        fi
        log_warn "Le serveur Grafana devra résoudre $WAZUH_NODE_NAME (DNS de l'entreprise ou ligne « ${MANAGER_IP} ${WAZUH_NODE_NAME} » dans son /etc/hosts)."
        del_patch ippublique; NODE_ADDR="$WAZUH_NODE_NAME" ;;
      local) del_patch ippublique; ans_set INDEXER_HOST_MODE local ;;
    esac
    if [[ "$PUBIP_FIX" == local ]]; then INDEXER_HOST=127.0.0.1; else INDEXER_HOST="$NODE_ADDR"; fi
    ans_set INDEXER_HOST "$INDEXER_HOST"
    retry ;;
  api)
    log_warn "Erreur connue détectée : $(grep -Eo "$API_ERR_RE" "$INSTALL_LOG" | sort -u | paste -sd ';' | sed 's/;/ ; /g')"
    explain <<TXT
L'assistant Wazuh a voulu changer les mots de passe de l'API (utilisateurs « wazuh » et
« wazuh-wui ») avant que l'API ne soit prête : il ne les a pas trouvés.
Code retour de l'installateur : ${INSTALL_RC} (s'il n'est pas 0, l'assistant a déjà désinstallé ce
qu'il avait posé). Le script d'origine reste dans $WORK/wazuh-install.sh.orig ; les corrections
ne s'appliquent qu'à la copie de ce dossier.
TXT
    opts=(
      "attente|Relancer avec un assistant corrigé qui attend que l'API soit prête avant de changer les mots de passe (recommandé)"
      "sansapi|Relancer en laissant l'assistant ignorer l'API, puis poser nous-mêmes les mots de passe de l'API"
      "relance|Relancer l'installation telle quelle (-o), l'erreur étant intermittente")
    def=attente
    if (( INSTALL_RC == 0 )); then
      opts=("corriger|Garder l'installation et poser maintenant les mots de passe de l'API (sans réinstaller)" "${opts[@]}")
      def=corriger
    fi
    opts+=("abandon|Arrêter l'étape (le dossier de travail est conservé)")
    ans_set API_FIX ""
    ask_choice API_FIX "Solution à essayer" "$def" "${opts[@]}"
    case "$API_FIX" in
      abandon) die "Arrêt demandé. Le dossier de travail $WORK est conservé." ;;
      corriger)
        api_passwords_after 300 || die "Les mots de passe de l'API n'ont pas pu être posés."
        : > "$INSTALL_LOG" ;;
      attente)
        ask API_WAIT "Attente maximale de l'API, en secondes" "300" "v_int 60 1800"
        del_patch attente; del_patch sansapi; add_patch "attente:$API_WAIT"
        retry ;;
      sansapi)
        del_patch attente; add_patch "sansapi:-"
        retry
        if (( INSTALL_RC == 0 )); then
          api_passwords_after 600 || die "Les mots de passe de l'API n'ont pas pu être posés."
          : > "$INSTALL_LOG"
        fi ;;
      relance) del_patch attente; del_patch sansapi; retry ;;
    esac
    if (( INSTALL_RC == 0 )) && [[ -z "$(known_error)" ]]; then
      run --hint "Mot de passe de wazuh-wui refusé : relancer l'étape et choisir une autre solution." \
        "Vérification : l'API accepte wazuh-wui avec le mot de passe généré" api_check
    fi ;;
  esac
done
(( INSTALL_RC == 0 )) || die "L'installation de Wazuh a échoué (code $INSTALL_RC). Journal détaillé : /var/log/wazuh-install.log"

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
