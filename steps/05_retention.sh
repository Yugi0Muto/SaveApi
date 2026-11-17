#!/usr/bin/env bash
# Définit et applique la politique de rétention, en deux endroits :
#   1. l'indexer (base consultée par le dashboard et Grafana) : politique ISM qui SUPPRIME les index
#      plus vieux que N jours (alertes, archives, statistiques) ;
#   2. le disque du manager (/var/ossec/logs/alerts et /archives) : Wazuh y garde une copie
#      quotidienne compressée des alertes SANS JAMAIS LA SUPPRIMER ; une tâche quotidienne la purge.
# La politique retenue est affichée et écrite dans /etc/wazuh-bundle/RETENTION.txt.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 05 "Politique de rétention"
require_wazuh

explain <<'TXT'
Pourquoi une politique de rétention :
  - sans elle, le disque se remplit et l'indexer se met en lecture seule (plus aucune alerte enregistrée) ;
  - la durée doit couvrir le délai de détection d'un incident (souvent découvert des semaines après)
    et vos obligations (contrats, réglementation : souvent 6 à 12 mois pour les journaux de sécurité).
Ordre de grandeur : ~1 à 5 Go par jour pour 100 agents selon l'activité (à surveiller les premiers jours).
Recommandation : indexer 90 jours (recherche rapide) + fichiers compressés plus longtemps si l'espace le permet
(les fichiers compressés prennent ~10 fois moins de place et peuvent être ré-importés en cas d'enquête).
TXT

ask RET_ALERTS_DAYS "Alertes dans l'indexer (wazuh-alerts-*) : conserver combien de jours ?" 90 "v_int 7 3650"
ask RET_ARCHIVES_DAYS "Archives dans l'indexer (wazuh-archives-*, tous les événements si activés) : jours ?" 30 "v_int 1 3650"
ask RET_MONITORING_DAYS "Statistiques internes (wazuh-monitoring-*, wazuh-statistics-*) : jours ?" 30 "v_int 1 3650"
ask RET_LOCAL_DAYS "Fichiers d'alertes compressés sur le disque du manager (/var/ossec/logs/alerts) : jours ?" 180 "v_int 7 3650"
ask RET_LOCAL_ARCHIVES_DAYS "Fichiers d'archives sur le disque du manager (/var/ossec/logs/archives) : jours ?" 30 "v_int 1 3650"

# ---------------------------------------------------------------- 1. Indexer : politiques ISM
section "1. Indexer : politiques de suppression (ISM)"
explain <<'TXT'
L'indexer crée un index par jour (ex : wazuh-alerts-4.x-2026.11.16). Une politique ISM
(Index State Management) fait passer chaque index de l'état « hot » (consultable) à « delete »
quand il atteint l'âge choisi. Les nouveaux index reçoivent la politique automatiquement
(ism_template) ; les index existants y sont rattachés par le script.
TXT
put_policy() { # put_policy id jours "motifs json" "description"
  local id="$1" days="$2" patterns="$3" desc="$4" body cur seq term q=""
  body=$(cat <<JSON
{"policy":{"description":"wazuh-bundle : ${desc} supprimees apres ${days} jours",
 "default_state":"hot",
 "states":[
  {"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"${days}d"}}]},
  {"name":"delete","actions":[{"delete":{}}],"transitions":[]}],
 "ism_template":[{"index_patterns":${patterns},"priority":100}]}}
JSON
)
  # Une politique existante ne peut être remplacée qu'en fournissant sa version (seq_no / primary_term)
  if cur="$(indexer_api GET "/_plugins/_ism/policies/$id" 2>/dev/null)"; then
    seq="$(grep -o '"_seq_no":[0-9]*' <<< "$cur" | head -1 | cut -d: -f2)"
    term="$(grep -o '"_primary_term":[0-9]*' <<< "$cur" | head -1 | cut -d: -f2)"
    [[ -n "$seq" && -n "$term" ]] && q="?if_seq_no=${seq}&if_primary_term=${term}"
    log_info "Politique $id existante : mise à jour."
  fi
  run "Politique $id : ${desc} supprimées après ${days} jours" indexer_api PUT "/_plugins/_ism/policies/${id}${q}" "$body"
}
run --hint "Vérifier l'étape 02 (mot de passe admin) et que wazuh-indexer est actif." "Connexion à l'indexer" indexer_api GET /_cluster/health
put_policy wazuh-bundle-alerts "$RET_ALERTS_DAYS" '["wazuh-alerts-*"]' "alertes"
put_policy wazuh-bundle-archives "$RET_ARCHIVES_DAYS" '["wazuh-archives-*"]' "archives"
put_policy wazuh-bundle-monitoring "$RET_MONITORING_DAYS" '["wazuh-monitoring-*","wazuh-statistics-*"]' "statistiques"
ism_attach wazuh-bundle-alerts "wazuh-alerts-*"
ism_attach wazuh-bundle-archives "wazuh-archives-*"
ism_attach wazuh-bundle-monitoring "wazuh-monitoring-*"
ism_attach wazuh-bundle-monitoring "wazuh-statistics-*"
# Politique de la v2 du bundle : remplacée par les politiques ci-dessus
if indexer_api GET /_plugins/_ism/policies/wazuh-retention >/dev/null 2>&1; then
  run --allow-fail "Suppression de l'ancienne politique v2 « wazuh-retention »" indexer_api DELETE /_plugins/_ism/policies/wazuh-retention || true
fi

# ---------------------------------------------------------------- 2. Disque du manager
section "2. Disque du manager : purge des fichiers anciens"
explain <<'TXT'
Chaque nuit, Wazuh compresse les alertes de la veille dans /var/ossec/logs/alerts/AAAA/Mois/
(et les archives dans /var/ossec/logs/archives/ si elles sont activées), mais ne les supprime jamais.
Une tâche quotidienne (04:15) supprimera les fichiers plus vieux que la durée choisie.
Le journal de chaque purge est dans /var/log/wazuh-bundle/purge.log.
TXT
run "Installation de l'outil de purge" install -m 750 "$BUNDLE_ROOT/tools/purge_local_logs.sh" /usr/local/sbin/wazuh-bundle-purge-logs
cat > /tmp/wazuh-bundle-purge.cron <<CRON
# wazuh-bundle (étape 05) : purge quotidienne des fichiers d'alertes et d'archives anciens
15 4 * * * root /usr/local/sbin/wazuh-bundle-purge-logs >> /var/log/wazuh-bundle/purge.log 2>&1
CRON
run "Planification quotidienne (04:15)" install -m 644 /tmp/wazuh-bundle-purge.cron /etc/cron.d/wazuh-bundle-purge
rm -f /tmp/wazuh-bundle-purge.cron
mkdir -p "$LOG_DIR"
run "Simulation : fichiers qui SERAIENT supprimés aujourd'hui (rien n'est supprimé)" /usr/local/sbin/wazuh-bundle-purge-logs --dry-run

# ---------------------------------------------------------------- 3. Politique écrite
cat > "$STATE_DIR/RETENTION.txt" <<TXT
Politique de rétention appliquée par wazuh-bundle le $(date '+%F %T')

  Données                                        Emplacement                       Durée
  ---------------------------------------------- --------------------------------- ----------
  Alertes (consultables dans le dashboard)       indexer : wazuh-alerts-*          ${RET_ALERTS_DAYS} jours
  Archives (tous les événements, si activées)    indexer : wazuh-archives-*        ${RET_ARCHIVES_DAYS} jours
  Statistiques internes Wazuh                    indexer : wazuh-monitoring/statistics-*  ${RET_MONITORING_DAYS} jours
  Alertes compressées (preuves, ré-importables)  /var/ossec/logs/alerts/           ${RET_LOCAL_DAYS} jours
  Archives compressées                           /var/ossec/logs/archives/         ${RET_LOCAL_ARCHIVES_DAYS} jours
  Sauvegardes de configuration                   voir étape 10                     (BACKUP_KEEP_DAYS)

Mécanismes : politiques ISM wazuh-bundle-* (indexer) ; /etc/cron.d/wazuh-bundle-purge (disque).
Modifier : relancer « bash install.sh --step 05 ».
TXT
chmod 644 "$STATE_DIR/RETENTION.txt"
run "Politique de rétention retenue" cat "$STATE_DIR/RETENTION.txt"
log_ok "Rétention en place. Vérification visuelle : Dashboard > Index Management > Policies."
