#!/usr/bin/env bash
# 06_grafana.sh — Grafana (local OU distant) : utilisateur indexer lecture seule + datasource + dashboard
#   GRAFANA_MODE=local  : installe Grafana sur cette machine et le configure
#   GRAFANA_MODE=remote : prépare l'indexer et génère un kit à installer sur la machine Grafana
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
[[ "$GRAFANA_ENABLE" == "true" ]] || { log_warn "GRAFANA_ENABLE=false : étape ignorée."; exit 0; }
IDX="https://${MANAGER_IP}:9200"
INDEXER_CA="/etc/wazuh-indexer/certs/root-ca.pem"
DASH_SRC="$BUNDLE_ROOT/configs/grafana/dashboards"
KIT_NAME="wazuh-grafana-kit"
KIT_FILE="$SECRETS_DIR/$KIT_NAME.tar.gz"

# ---- 1. (local) Installation de Grafana + mot de passe admin ----
if grafana_is_local; then
  if ! systemctl list-unit-files | grep -q '^grafana-server'; then
    apt-get install -y apt-transport-https wget gpg >/dev/null
    mkdir -p /etc/apt/keyrings
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
    apt-get update -qq; apt-get install -y grafana >/dev/null
  fi
  GPW="$(secret_get GRAFANA_ADMIN_PASSWORD || true)"
  [[ -n "$GPW" ]] || { GPW="$(gen_password)"; secret_set GRAFANA_ADMIN_PASSWORD "$GPW"; }
  systemctl enable --now grafana-server; sleep 5
  grafana-cli admin reset-admin-password "$GPW" >/dev/null
else
  log_info "Grafana DISTANT (${GRAFANA_REMOTE_IPS}) : aucune installation sur ce serveur."
fi

# ---- 2. Utilisateur indexer en LECTURE SEULE pour Grafana (local ET distant) ----
RO_PW="$(secret_get GRAFANA_RO_PASSWORD || true)"
[[ -n "$RO_PW" ]] || { RO_PW="$(gen_password)"; secret_set GRAFANA_RO_PASSWORD "$RO_PW"; }
indexer_curl -X PUT "$IDX/_plugins/_security/api/roles/grafana_read" -H 'Content-Type: application/json' -d \
 '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}' >/dev/null
indexer_curl -X PUT "$IDX/_plugins/_security/api/internalusers/grafana_ro" -H 'Content-Type: application/json' -d \
 "{\"password\":\"${RO_PW}\",\"backend_roles\":[]}" >/dev/null
indexer_curl -X PUT "$IDX/_plugins/_security/api/rolesmapping/grafana_read" -H 'Content-Type: application/json' -d \
 '{"users":["grafana_ro"]}' >/dev/null
log_ok "Utilisateur indexer grafana_ro (lecture seule sur wazuh-alerts-*)"

# ---- 3a. Local : datasource + dashboards sur cette machine ----
if grafana_is_local; then
  IDX_URL="$IDX" RO_PW="$RO_PW" CA_FILE="$INDEXER_CA" DASH_SRC="$DASH_SRC" \
  OPENSEARCH_DS_VERSION="$OPENSEARCH_DS_VERSION" DS_IS_DEFAULT=true \
    bash "$BUNDLE_ROOT/bash/grafana/provision.sh"
  log_ok "Grafana : http://${MANAGER_IP}:3000  (admin / mot de passe dans $SECRETS_FILE : GRAFANA_ADMIN_PASSWORD)"
  log_warn "Grafana est en HTTP : le placer derrière un reverse proxy HTTPS avant tout usage hors segment administration."
  exit 0
fi

# ---- 3b. Distant : contrôle de l'écoute de l'indexer puis génération du kit ----
if ! ss -tlnH | awk '{print $4}' | grep -Eq "(^|[^0-9.])(${MANAGER_IP//./\\.}|0\\.0\\.0\\.0|\\*|\\[::\\]):9200$"; then
  log_warn "L'indexer n'écoute pas sur ${MANAGER_IP}:9200 : une machine distante ne pourra pas s'y connecter."
  log_warn "Vérifier network.host dans /etc/wazuh-indexer/opensearch.yml (doit être ${MANAGER_IP} ou 0.0.0.0)."
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
KIT="$WORK/$KIT_NAME"; mkdir -p "$KIT/dashboards"
install -m 644 "$INDEXER_CA" "$KIT/root-ca.pem"
cp "$DASH_SRC"/*.json "$KIT/dashboards/"
install -m 755 "$BUNDLE_ROOT/bash/grafana/provision.sh" "$KIT/provision.sh"
{
  printf 'IDX_URL=%q\n' "$IDX"
  printf 'RO_PW=%q\n' "$RO_PW"
  printf 'OPENSEARCH_DS_VERSION=%q\n' "$OPENSEARCH_DS_VERSION"
  # Un Grafana existant a souvent déjà une source par défaut : ne pas en imposer une seconde
  printf 'DS_IS_DEFAULT=%q\n' "false"
} > "$KIT/kit.env"
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

mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
( umask 077; tar -czf "$KIT_FILE" -C "$WORK" "$KIT_NAME" )
chmod 600 "$KIT_FILE"
log_ok "Kit Grafana généré : $KIT_FILE"
cat <<MSG

Sur la machine Grafana (${GRAFANA_REMOTE_IPS}), Grafana étant déjà installé :
  1. Copier le kit (il contient un mot de passe : canal sûr, puis le supprimer après usage) :
       scp $KIT_FILE  utilisateur@<machine-grafana>:/tmp/
  2. Puis, en root SUR LA MACHINE GRAFANA :
       cd /tmp && tar -xzf $KIT_NAME.tar.gz && bash $KIT_NAME/install.sh
Prérequis réseau : <machine-grafana> -> ${MANAGER_IP} : TCP 9200 (déjà ouvert par l'étape 02 pour ${GRAFANA_REMOTE_IPS}).
Relancer cette étape régénère le kit avec le même mot de passe.
MSG
