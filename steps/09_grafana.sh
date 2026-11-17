#!/usr/bin/env bash
# Grafana (optionnel) : tableau de bord « Wazuh — Vue SOC » alimenté par l'indexer.
#   local  : Grafana est installé sur CE serveur (port 3000) ;
#   remote : Grafana existe déjà sur une AUTRE machine : l'étape prépare l'indexer et génère un kit
#            à copier et installer sur cette machine. L'indexer doit alors écouter sur l'IP du serveur
#            (choix fait à l'étape 02).
# Dans les deux cas, Grafana lit l'indexer avec un utilisateur dédié en LECTURE SEULE (grafana_ro).
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 09 "Grafana"
require_wazuh
need_answer MANAGER_IP 00

if ! ask_yes_no GRAFANA_ENABLE "Mettre en place un tableau de bord Grafana ?" non; then
  log_info "Grafana non utilisé (le Wazuh Dashboard reste disponible sur https://$MANAGER_IP)."; exit 0
fi
explain <<'TXT'
Le Wazuh Dashboard (https://IP-du-serveur) suffit pour l'analyse. Grafana est utile pour un écran de
supervision ou pour regrouper Wazuh avec d'autres sources. Grafana lit l'indexer avec l'utilisateur
« grafana_ro », limité à la LECTURE des index wazuh-alerts-* (il ne peut rien modifier).
TXT
ask_choice GRAFANA_MODE "Où se trouve Grafana ?" local \
  "local|Sur CE serveur (installé par le bundle, port 3000)" "remote|Sur une AUTRE machine (Grafana déjà installé)"
IDX="$(indexer_url)"
DASH_SRC="$BUNDLE_ROOT/configs/grafana/dashboards"

if [[ "$GRAFANA_MODE" == remote ]]; then
  ask GRAFANA_REMOTE_IPS "IP de la machine Grafana (pour le tableau des flux réseau)" "" v_ip_list_req
  if [[ "$(ans_get INDEXER_HOST)" == 127.0.0.1 ]]; then
    explain <<TXT
L'indexer de ce serveur n'écoute que sur 127.0.0.1 : la machine Grafana ne peut pas s'y connecter.
Le bundle peut l'ouvrir sur ${MANAGER_IP} : nouveau certificat (même autorité, adresse ajoutée),
écoute sur 127.0.0.1 et ${MANAGER_IP}, test HTTPS ; retour automatique à l'état d'origine en cas d'échec.
TXT
    confirm "Ouvrir l'indexer sur ${MANAGER_IP}:9200 pour la machine Grafana ?" \
      || die "Grafana distant impossible tant que l'indexer n'écoute que sur 127.0.0.1 (ou choisir Grafana « local »)."
    source "$BUNDLE_ROOT/lib/indexer_expose.sh"
    expose_indexer "$MANAGER_IP"
    ans_set INDEXER_HOST "$MANAGER_IP"; ans_set INDEXER_HOST_MODE reseau
  fi
fi

# OpenSearch : version réelle (nécessaire au plugin de Grafana)
run --hint "Vérifier l'étape 02." "Version de l'indexer" indexer_api GET /
osv="$(grep -o '"number" *: *"[0-9.]*"' <<< "$RUN_OUTPUT" | head -1 | grep -o '[0-9][0-9.]*')"
[[ -n "$osv" ]] || die "Version de l'indexer illisible dans la réponse ci-dessus."
log_info "Version OpenSearch de l'indexer : $osv"

# ---------------------------------------------------------------- utilisateur lecture seule
section "Utilisateur de l'indexer en lecture seule (grafana_ro)"
RO_PW="$(secret_get GRAFANA_RO_PASSWORD || true)"
[[ -n "$RO_PW" ]] || { RO_PW="$(gen_password)"; secret_set GRAFANA_RO_PASSWORD "$RO_PW"; }
run "Rôle grafana_read (lecture de wazuh-alerts-*)" indexer_api PUT /_plugins/_security/api/roles/grafana_read \
  '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}'
run --secret "Utilisateur grafana_ro (mot de passe dans $SECRETS_FILE)" indexer_api PUT /_plugins/_security/api/internalusers/grafana_ro \
  "{\"password\":\"${RO_PW}\",\"backend_roles\":[]}"
run "Association grafana_ro -> grafana_read" indexer_api PUT /_plugins/_security/api/rolesmapping/grafana_read '{"users":["grafana_ro"]}'

if [[ "$GRAFANA_MODE" == local ]]; then
  section "Installation de Grafana sur ce serveur"
  if ! pkg_installed grafana; then
    pkg_install apt-transport-https gpg curl
    run "Création du dossier des clés APT" mkdir -p /etc/apt/keyrings
    run_sh --hint "Accès HTTPS à apt.grafana.com requis." "Clé de signature du dépôt Grafana" \
      "curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg"
    run_sh "Déclaration du dépôt Grafana" \
      "echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' > /etc/apt/sources.list.d/grafana.list"
    pkg_install grafana
  fi
  GPW="$(secret_get GRAFANA_ADMIN_PASSWORD || true)"
  [[ -n "$GPW" ]] || { GPW="$(gen_password)"; secret_set GRAFANA_ADMIN_PASSWORD "$GPW"; }
  run "Démarrage de Grafana" systemctl enable --now grafana-server
  sleep 5
  run --secret "Mot de passe de l'administrateur Grafana" grafana-cli admin reset-admin-password "$GPW"
  run "Datasource + dashboards" env IDX_URL="$IDX" RO_PW="$RO_PW" CA_FILE="$INDEXER_CA" DASH_SRC="$DASH_SRC" \
    OPENSEARCH_DS_VERSION="$osv" DS_IS_DEFAULT=true bash "$BUNDLE_ROOT/grafana/provision.sh"
  log_ok "Grafana : http://${MANAGER_IP}:3000  (admin / mot de passe : grep GRAFANA_ADMIN_PASSWORD $SECRETS_FILE)"
  log_warn "Grafana est en HTTP : réserver le port 3000 aux postes d'administration (pare-feu) ou le placer derrière un proxy HTTPS."
  exit 0
fi

# ---------------------------------------------------------------- kit pour Grafana distant
section "Kit pour la machine Grafana distante"
run --hint "network.host de /etc/wazuh-indexer/opensearch.yml" "L'indexer écoute sur ${MANAGER_IP}:9200" \
  output_has "(^|[^0-9.])(${MANAGER_IP//./\\.}|0\\.0\\.0\\.0|\\*|\\[::\\]):9200[[:space:]]" ss -tlnH
KIT_NAME="wazuh-grafana-kit"; KIT_FILE="$SECRETS_DIR/$KIT_NAME.tar.gz"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
KIT="$WORK/$KIT_NAME"; mkdir -p "$KIT/dashboards"
install -m 644 "$INDEXER_CA" "$KIT/root-ca.pem"
cp "$DASH_SRC"/*.json "$KIT/dashboards/"
install -m 755 "$BUNDLE_ROOT/grafana/provision.sh" "$KIT/provision.sh"
{ printf 'IDX_URL=%q\n' "$IDX"; printf 'RO_PW=%q\n' "$RO_PW"; printf 'OPENSEARCH_DS_VERSION=%q\n' "$osv"
  # Un Grafana existant a souvent déjà une source par défaut : ne pas en imposer une seconde
  printf 'DS_IS_DEFAULT=false\n'; } > "$KIT/kit.env"
chmod 600 "$KIT/kit.env"
cat > "$KIT/install.sh" <<'SH'
#!/usr/bin/env bash
# À lancer EN ROOT sur la machine Grafana (Grafana doit déjà y être installé).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Lancer en root (sudo -i)." >&2; exit 1; }
# shellcheck disable=SC1091
source "$HERE/kit.env"
export IDX_URL RO_PW OPENSEARCH_DS_VERSION DS_IS_DEFAULT
export CA_FILE="$HERE/root-ca.pem" DASH_SRC="$HERE/dashboards"
exec bash "$HERE/provision.sh"
SH
chmod 755 "$KIT/install.sh"
run_sh "Création du kit (contient le mot de passe de grafana_ro : root uniquement)" "umask 077; tar -czf '$KIT_FILE' -C '$WORK' '$KIT_NAME'"
cat <<MSG

Sur la machine Grafana (${GRAFANA_REMOTE_IPS}), Grafana étant déjà installé :
  1. Copier le kit par un canal sûr (il contient un mot de passe), puis le supprimer après usage :
       scp $KIT_FILE utilisateur@<machine-grafana>:/tmp/
  2. En root SUR LA MACHINE GRAFANA :
       cd /tmp && tar -xzf $KIT_NAME.tar.gz && bash $KIT_NAME/install.sh
Flux réseau à ouvrir : ${GRAFANA_REMOTE_IPS} -> ${MANAGER_IP} TCP 9200 (UNIQUEMENT depuis cette machine).
MSG
