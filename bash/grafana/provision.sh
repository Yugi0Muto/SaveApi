#!/usr/bin/env bash
# provision.sh — provisionne le datasource OpenSearch (Wazuh) et les dashboards dans un Grafana DÉJÀ installé.
# Utilisé par l'étape 06 (Grafana local) et par le kit généré pour un Grafana distant.
# Autonome : ne dépend pas de common.sh (il doit pouvoir tourner sur la machine Grafana).
#
# Variables obligatoires :
#   IDX_URL                 URL de l'indexer Wazuh, ex: https://10.10.10.10:9200
#   RO_PW                   mot de passe de l'utilisateur indexer grafana_ro
#   CA_FILE                 certificat racine (root-ca.pem) de l'indexer
#   DASH_SRC                dossier contenant les dashboards *.json
#   OPENSEARCH_DS_VERSION   version OpenSearch réelle de l'indexer
# Variables facultatives :
#   DS_IS_DEFAULT           true|false : datasource par défaut (défaut: true ; false si Grafana a déjà d'autres sources)
#   GRAFANA_PROV_DIR        défaut /etc/grafana/provisioning
#   GRAFANA_DASH_DIR        défaut /var/lib/grafana/dashboards/wazuh
#   GRAFANA_PLUGINS_DIR     défaut /var/lib/grafana/plugins
#   GRAFANA_RESTART_CMD     défaut "systemctl restart grafana-server"
set -euo pipefail

: "${IDX_URL:?IDX_URL manquant}" "${RO_PW:?RO_PW manquant}" "${CA_FILE:?CA_FILE manquant}"
: "${DASH_SRC:?DASH_SRC manquant}" "${OPENSEARCH_DS_VERSION:?OPENSEARCH_DS_VERSION manquant}"
DS_IS_DEFAULT="${DS_IS_DEFAULT:-true}"
PROV="${GRAFANA_PROV_DIR:-/etc/grafana/provisioning}"
DASH_DIR="${GRAFANA_DASH_DIR:-/var/lib/grafana/dashboards/wazuh}"
PLUGINS_DIR="${GRAFANA_PLUGINS_DIR:-/var/lib/grafana/plugins}"
RESTART_CMD="${GRAFANA_RESTART_CMD:-systemctl restart grafana-server}"
PLUGIN="grafana-opensearch-datasource"

info() { echo "[INFO] $*"; }
ok()   { echo "[ OK ] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[FAIL] $*" >&2; exit 1; }

[[ -f "$CA_FILE" ]] || die "Certificat introuvable : $CA_FILE"
compgen -G "$DASH_SRC/*.json" >/dev/null || die "Aucun dashboard (*.json) dans $DASH_SRC"
command -v grafana-cli >/dev/null || die "grafana-cli introuvable : Grafana n'est pas installé sur cette machine."

# ---- 1. Plugin OpenSearch ----
if [[ ! -d "$PLUGINS_DIR/$PLUGIN" ]]; then
  info "Installation du plugin $PLUGIN"
  grafana-cli plugins install "$PLUGIN" || die "Plugin non installable (réseau bloqué ?)."
fi

# ---- 2. Datasource provisionnée (certificat vérifié, pas de tlsSkipVerify) ----
mkdir -p "$PROV/datasources" "$PROV/dashboards" "$DASH_DIR"
CA="$(sed 's/^/        /' "$CA_FILE")"
DS_FILE="$PROV/datasources/wazuh-opensearch.yaml"
cat > "$DS_FILE" <<YAML
apiVersion: 1
datasources:
  - name: Wazuh-OpenSearch
    uid: wazuh-opensearch
    type: grafana-opensearch-datasource
    access: proxy
    url: ${IDX_URL}
    basicAuth: true
    basicAuthUser: grafana_ro
    isDefault: ${DS_IS_DEFAULT}
    editable: false
    jsonData:
      flavor: opensearch
      version: "${OPENSEARCH_DS_VERSION}"
      database: "wazuh-alerts-4.x-*"
      timeField: "@timestamp"
      pplEnabled: false
      tlsAuthWithCACert: true
      timeInterval: "10s"
    secureJsonData:
      basicAuthPassword: "${RO_PW}"
      tlsCACert: |
${CA}
YAML
chmod 640 "$DS_FILE"

# ---- 3. Dashboards ----
cat > "$PROV/dashboards/wazuh.yaml" <<YAML
apiVersion: 1
providers:
  - name: "Wazuh"
    folder: "Wazuh"
    type: file
    updateIntervalSeconds: 30
    options:
      path: ${DASH_DIR}
YAML
cp "$DASH_SRC"/*.json "$DASH_DIR/"
if getent group grafana >/dev/null 2>&1; then
  chown root:grafana "$DS_FILE"
  chown -R grafana:grafana "$DASH_DIR"
fi

# ---- 4. Redémarrage ----
$RESTART_CMD; sleep "${GRAFANA_RESTART_WAIT:-5}"
systemctl is-active --quiet grafana-server || die "Grafana ne démarre pas : journalctl -u grafana-server -n 30"

# ---- 5. Contrôle de joignabilité de l'indexer depuis CETTE machine (avertissement seulement) ----
code="$(printf 'user = "grafana_ro:%s"\n' "$RO_PW" \
  | curl -sS -g -m 10 -K - --cacert "$CA_FILE" -o /dev/null -w '%{http_code}' "${IDX_URL}/wazuh-alerts-*/_count" 2>/dev/null || true)"
if [[ "$code" == "200" ]]; then
  ok "Indexer joignable depuis cette machine (${IDX_URL}), utilisateur grafana_ro valide."
else
  warn "Indexer NON joignable depuis cette machine (${IDX_URL}, HTTP '${code:-aucun}')."
  warn "Vérifier : pare-feu (9200 ouvert à cette IP), certificat (l'adresse de l'URL doit figurer dans le certificat), réseau."
fi
ok "Datasource « Wazuh-OpenSearch » et dashboards provisionnés."
