#!/usr/bin/env bash
# Alertes SMS via l'API Africa's Talking (optionnel).
# Un petit service (wazuh-sms-alerter, utilisateur système dédié, sans droits d'écriture) lit les alertes
# en continu et envoie un SMS pour chaque alerte de niveau suffisant, avec :
#   - déduplication : même machine + même règle = un seul SMS pendant N secondes ;
#   - plafond horaire : au-delà, les SMS sont retenus et un SMS de synthèse est envoyé.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 08 "Alertes SMS"
require_wazuh

if ! ask_yes_no SMS_ENABLE "Envoyer les alertes critiques par SMS (Africa's Talking) ?" non; then
  if output_has '^wazuh-sms-alerter' systemctl list-unit-files; then
    run "Arrêt du service SMS" systemctl disable --now wazuh-sms-alerter
  fi
  log_ok "Alertes SMS désactivées."; exit 0
fi

explain <<'TXT'
Prérequis : un compte Africa's Talking (https://account.africastalking.com) :
  - « Nom d'utilisateur » de l'application ; « sandbox » = environnement de test (AUCUN SMS réellement livré) ;
  - clé API de l'application (Settings > API Key) ;
  - crédit SMS sur le compte de production.
Flux réseau : serveur Wazuh -> api.africastalking.com TCP 443.
Conseil : réserver les SMS aux alertes de niveau 12 et plus (incidents probables).
TXT
ask SMS_USERNAME "Nom d'utilisateur Africa's Talking (sandbox pour tester)" sandbox v_nonempty
ask_secret AT_API_KEY "Clé API Africa's Talking"
ask SMS_TO "Numéros destinataires, format international (+241…), séparés par des espaces" "" v_phone_list
ask SMS_ALERT_LEVEL "Niveau minimal des alertes envoyées par SMS" 12 "v_int 3 15"
ask SMS_MAX_PER_HOUR "Nombre maximal de SMS par heure" 20 "v_int 1 500"
ask SMS_DEDUP_SECONDS "Délai de déduplication (secondes)" 300 "v_int 0 86400"

api_host=api.africastalking.com; [[ "$SMS_USERNAME" == sandbox ]] && api_host=api.sandbox.africastalking.com
run --hint "Autoriser le flux sortant HTTPS vers $api_host (proxy ? pare-feu ?)" \
  "Joignabilité de l'API ($api_host)" curl -sS -o /dev/null -m 15 -w 'HTTP %{http_code}\n' "https://$api_host/"

if ! id wazuh-sms >/dev/null 2>&1; then
  run "Création de l'utilisateur système wazuh-sms (sans shell, groupe wazuh pour lire les alertes)" useradd -r -s /usr/sbin/nologin -g wazuh wazuh-sms
fi
install -d -m 750 -o root -g wazuh "$STATE_DIR"
tmp="$(mktemp)"
cat > "$tmp" <<ENV
AT_USERNAME=${SMS_USERNAME}
AT_API_KEY=${AT_API_KEY}
SMS_TO="${SMS_TO}"
SMS_ALERT_LEVEL=${SMS_ALERT_LEVEL}
SMS_MAX_PER_HOUR=${SMS_MAX_PER_HOUR}
SMS_DEDUP_SECONDS=${SMS_DEDUP_SECONDS}
ENV
run "Fichier de paramètres du service (root:wazuh, 640 — contient la clé API)" install -m 640 -o root -g wazuh "$tmp" "$STATE_DIR/sms.env"
rm -f "$tmp"
run "Installation du programme d'envoi" install -m 755 "$BUNDLE_ROOT/configs/manager/wazuh-sms-alerter.py" /usr/local/bin/wazuh-sms-alerter.py
run "Installation du service systemd" install -m 644 "$BUNDLE_ROOT/configs/manager/wazuh-sms-alerter.service" /etc/systemd/system/wazuh-sms-alerter.service
run "Rechargement de systemd" systemctl daemon-reload
run "Activation et (re)démarrage du service" systemctl enable wazuh-sms-alerter
run "Redémarrage du service" systemctl restart wazuh-sms-alerter
sleep 3
run --hint "Journal du service : journalctl -u wazuh-sms-alerter -n 30" "Le service doit être actif" systemctl is-active wazuh-sms-alerter
run "Dernières lignes du journal du service" journalctl -u wazuh-sms-alerter -n 5 --no-pager

if confirm "Envoyer un SMS de test maintenant ?"; then
  run --hint "Vérifier la clé API, le nom d'utilisateur et le crédit du compte." "SMS de test" \
    env SMS_ENV="$STATE_DIR/sms.env" python3 "$BUNDLE_ROOT/configs/manager/wazuh-sms-alerter.py" --test
fi
[[ "$SMS_USERNAME" == sandbox ]] && log_warn "Mode sandbox : l'API répond mais AUCUN SMS n'est livré. Pour la production : relancer l'étape avec le vrai nom d'utilisateur et la clé de production."
log_ok "Alertes SMS actives (niveau >= $SMS_ALERT_LEVEL, max $SMS_MAX_PER_HOUR/heure)."
