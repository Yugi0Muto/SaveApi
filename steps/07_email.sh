#!/usr/bin/env bash
# Alertes par e-mail, trois modes au choix :
#   gmail      : un compte Gmail avec « mot de passe d'application » (smtp.gmail.com:587, TLS) ;
#   entreprise : le serveur SMTP de l'entreprise (Exchange, Office 365, Zimbra…), avec ou sans
#                authentification, STARTTLS (587) ou SMTPS (465) ;
#   relais     : un relais SMTP interne qui accepte les messages du serveur Wazuh sans mot de passe (25).
# Wazuh ne sait envoyer qu'à un serveur SMTP local sans chiffrement ni mot de passe : on installe donc
# Postfix, limité à 127.0.0.1, qui transmet les e-mails au serveur choisi (chiffrement, authentification).
# Chaque maillon est testé : connexion réseau, TLS, envoi réel d'un e-mail, configuration Wazuh.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
source "$BUNDLE_ROOT/lib/email.sh"
require_root
step_header 07 "Alertes e-mail"
require_wazuh

if ! ask_yes_no EMAIL_ENABLE "Envoyer les alertes importantes par e-mail ?" oui; then
  ossec_begin
  run "Désactivation des e-mails Wazuh" ossec_conf set global email_notification no
  ossec_commit; log_ok "Alertes e-mail désactivées."; exit 0
fi

explain <<'TXT'
Chaîne d'envoi :  Wazuh (alerte)  ->  Postfix local (127.0.0.1:25)  ->  serveur d'envoi choisi  ->  destinataires
Postfix n'écoute QUE sur 127.0.0.1 : il ne peut pas servir de relais à d'autres machines.
TXT
ask_choice EMAIL_MODE "Comment les e-mails doivent-ils être envoyés ?" entreprise \
  "gmail|Compte Gmail (mot de passe d'application)" \
  "entreprise|Serveur SMTP de l'entreprise (avec ou sans identifiant)" \
  "relais|Relais SMTP interne sans authentification"

case "$EMAIL_MODE" in
gmail)
  explain <<'TXT'
Gmail refuse le mot de passe habituel du compte pour l'envoi SMTP. Il faut un « mot de passe
d'application » (16 caractères), à créer ainsi :
  1. se connecter au compte Google qui enverra les alertes (idéalement un compte dédié, ex. soc.alertes@gmail.com) ;
  2. activer la validation en deux étapes : https://myaccount.google.com/security ;
  3. créer le mot de passe d'application : https://myaccount.google.com/apppasswords (nom : « Wazuh ») ;
  4. copier les 16 caractères affichés (les espaces sont ignorés).
Limites Gmail : ~500 e-mails/jour ; l'expéditeur affiché est toujours l'adresse Gmail.
Flux réseau : serveur Wazuh -> smtp.gmail.com TCP 587.
TXT
  EMAIL_SMTP_HOST=smtp.gmail.com; EMAIL_SMTP_PORT=587; EMAIL_TLS=verify; EMAIL_AUTH=oui
  ans_set EMAIL_SMTP_HOST "$EMAIL_SMTP_HOST"; ans_set EMAIL_SMTP_PORT "$EMAIL_SMTP_PORT"; ans_set EMAIL_TLS verify; ans_set EMAIL_AUTH oui
  ask EMAIL_SMTP_USER "Adresse Gmail qui envoie les alertes" "" v_email
  ask_secret EMAIL_SMTP_PASSWORD "Mot de passe d'application Gmail (16 caractères)"
  EMAIL_SMTP_PASSWORD="${EMAIL_SMTP_PASSWORD// /}"; secret_set EMAIL_SMTP_PASSWORD "$EMAIL_SMTP_PASSWORD"
  [[ ${#EMAIL_SMTP_PASSWORD} -eq 16 ]] || log_warn "Le mot de passe saisi ne fait pas 16 caractères : est-ce bien un mot de passe d'APPLICATION ?"
  EMAIL_FROM="$EMAIL_SMTP_USER"; ans_set EMAIL_FROM "$EMAIL_FROM"
  ;;
entreprise)
  explain <<'TXT'
Informations à demander à l'administrateur de la messagerie :
  - nom du serveur SMTP (ex : smtp.entreprise.local, smtp.office365.com) et port :
      587 = soumission avec STARTTLS (le plus courant)    465 = SMTPS (chiffré dès la connexion)
  - un compte d'envoi (identifiant + mot de passe) si le serveur l'exige ;
  - l'adresse d'expéditeur autorisée pour ce compte (souvent identique à l'identifiant).
Flux réseau : serveur Wazuh -> serveur SMTP, sur le port choisi.
TXT
  ask EMAIL_SMTP_HOST "Nom ou IP du serveur SMTP" "" v_host
  ask EMAIL_SMTP_PORT "Port" 587 v_port
  ask_choice EMAIL_TLS "Chiffrement de la connexion" "$([[ "$EMAIL_SMTP_PORT" == 465 ]] && echo smtps || echo verify)" \
    "verify|STARTTLS obligatoire + certificat vérifié (recommandé)" \
    "encrypt|STARTTLS obligatoire, certificat NON vérifié (CA interne non installée sur ce serveur)" \
    "smtps|SMTPS (port 465) + certificat vérifié" \
    "none|Aucun chiffrement (déconseillé : le mot de passe circulerait en clair)"
  if ask_yes_no EMAIL_AUTH "Le serveur exige-t-il un identifiant et un mot de passe ?" oui; then
    ask EMAIL_SMTP_USER "Identifiant SMTP" "" v_nonempty
    ask_secret EMAIL_SMTP_PASSWORD "Mot de passe SMTP de $EMAIL_SMTP_USER"
    [[ "$EMAIL_TLS" == none ]] && log_warn "Authentification SANS chiffrement : le mot de passe circulera en clair sur le réseau."
  fi
  def_from="wazuh@$(hostname -d 2>/dev/null || echo entreprise.local)"; [[ "${EMAIL_SMTP_USER:-}" == *@* ]] && def_from="$EMAIL_SMTP_USER"
  ask EMAIL_FROM "Adresse d'expéditeur des alertes" "$def_from" v_email
  ;;
relais)
  explain <<'TXT'
Un relais interne accepte les e-mails d'adresses IP autorisées, sans mot de passe (port 25).
Demander à l'administrateur de la messagerie d'AUTORISER l'adresse IP du serveur Wazuh sur le relais.
Le chiffrement est utilisé si le relais le propose (STARTTLS opportuniste).
TXT
  ask EMAIL_SMTP_HOST "Nom ou IP du relais SMTP" "" v_host
  ask EMAIL_SMTP_PORT "Port" 25 v_port
  ask_choice EMAIL_TLS "Chiffrement" may "may|Si le relais le propose (recommandé)" "verify|Obligatoire + certificat vérifié" "none|Aucun"
  EMAIL_AUTH=non; ans_set EMAIL_AUTH non
  ask EMAIL_FROM "Adresse d'expéditeur des alertes" "wazuh@$(hostname -d 2>/dev/null || echo entreprise.local)" v_email
  ;;
esac
ask EMAIL_TO "Destinataires des alertes (séparés par des espaces)" "" v_email_list
explain <<'TXT'
Niveau minimal : seules les alertes de ce niveau ou plus partent par e-mail.
   10 = suspect (recommandé pour commencer)   12 = incident probable   14 = malware confirmé
Plafond horaire : au-delà, Wazuh regroupe les alertes (évite d'inonder la messagerie lors d'une attaque).
TXT
ask EMAIL_ALERT_LEVEL "Niveau minimal des alertes envoyées par e-mail" 10 "v_int 3 15"
ask EMAIL_MAX_PER_HOUR "Nombre maximal d'e-mails par heure" 30 "v_int 1 1000"

# ---------------------------------------------------------------- 1. Réseau et TLS
section "1. Joignabilité du serveur d'envoi"
if ! pkg_installed postfix; then
  # Pré-réponse aux questions d'installation de Postfix (configuration remplacée ensuite par postconf)
  run_sh "Pré-configuration de l'installation de Postfix" \
    "printf 'postfix postfix/main_mailer_type select Internet Site\npostfix postfix/mailname string %s\n' \"\$(hostname -f 2>/dev/null || hostname)\" | debconf-set-selections"
fi
pkg_install postfix libsasl2-modules bsd-mailx openssl ca-certificates
run --hint "Le pare-feu doit autoriser : serveur Wazuh -> ${EMAIL_SMTP_HOST} TCP ${EMAIL_SMTP_PORT}. Vérifier aussi le nom (DNS)." \
  "Connexion TCP à ${EMAIL_SMTP_HOST}:${EMAIL_SMTP_PORT}" timeout 10 bash -c "</dev/tcp/${EMAIL_SMTP_HOST}/${EMAIL_SMTP_PORT}"
case "$EMAIL_TLS" in
  verify|encrypt)
    run --allow-fail --hint "Le serveur ne propose peut-être pas STARTTLS sur ce port, ou son certificat n'est pas reconnu (CA interne)." \
      "Négociation STARTTLS et certificat du serveur" timeout 20 openssl s_client -brief -starttls smtp -connect "${EMAIL_SMTP_HOST}:${EMAIL_SMTP_PORT}" -servername "$EMAIL_SMTP_HOST" -verify_return_error </dev/null \
      || [[ "$EMAIL_TLS" == encrypt ]] || die "TLS refusé alors que la vérification du certificat est demandée. Choisir « encrypt » si le serveur utilise une CA interne, ou installer cette CA (/usr/local/share/ca-certificates + update-ca-certificates).";;
  smtps)
    run --hint "Vérifier que le port 465 est bien du SMTPS." \
      "Connexion SMTPS et certificat du serveur" timeout 20 openssl s_client -brief -connect "${EMAIL_SMTP_HOST}:${EMAIL_SMTP_PORT}" -servername "$EMAIL_SMTP_HOST" -verify_return_error </dev/null;;
esac

# ---------------------------------------------------------------- 2. Postfix
section "2. Postfix (relais local vers ${EMAIL_SMTP_HOST})"
backup_file /etc/postfix/main.cf
postfix_settings "$EMAIL_MODE" "$EMAIL_SMTP_HOST" "$EMAIL_SMTP_PORT" "$EMAIL_TLS" "$EMAIL_AUTH" > "$STATE_DIR/postfix.settings"
run "Paramètres Postfix qui vont être appliqués" cat "$STATE_DIR/postfix.settings"
while IFS= read -r kv; do run "postconf : ${kv%% =*}" postconf -e "$kv"; done < "$STATE_DIR/postfix.settings"
if [[ "$EMAIL_AUTH" == oui ]]; then
  pw="$(secret_get EMAIL_SMTP_PASSWORD)"
  ( umask 077; printf '[%s]:%s %s:%s\n' "$EMAIL_SMTP_HOST" "$EMAIL_SMTP_PORT" "$EMAIL_SMTP_USER" "$pw" > /etc/postfix/sasl_passwd )
  run "Compilation du fichier d'identifiants Postfix (root, 600)" postmap /etc/postfix/sasl_passwd
  run "Droits du fichier d'identifiants" chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
else
  rm -f /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
fi
run "Contrôle de la configuration Postfix" postfix check
run "Redémarrage de Postfix" systemctl restart postfix
run "Postfix démarré au boot" systemctl enable postfix

# ---------------------------------------------------------------- 3. E-mail de test
section "3. Envoi d'un e-mail de test"
start="$(date +%s)"; token="wazuh-bundle-test-$start"
{
  printf 'From: %s\nTo: %s\nSubject: [WAZUH] test de configuration %s\n\n' "$EMAIL_FROM" "${EMAIL_TO// /, }" "$token"
  printf 'E-mail de test envoyé par wazuh-bundle (étape 07) depuis %s le %s.\nMode : %s via %s:%s\n' "$(hostname)" "$(date)" "$EMAIL_MODE" "$EMAIL_SMTP_HOST" "$EMAIL_SMTP_PORT"
} > /tmp/.wazuh-mail-test
# shellcheck disable=SC2086
run "Remise du message de test à Postfix" sendmail -f "$EMAIL_FROM" $EMAIL_TO < /tmp/.wazuh-mail-test
rm -f /tmp/.wazuh-mail-test
log_info "Attente du résultat de l'envoi (60 s max)…"
result=""
for _ in $(seq 1 30); do
  sleep 2
  result="$(journalctl --since "@$start" -o cat SYSLOG_IDENTIFIER=postfix/smtp 2>/dev/null | grep -E 'status=(sent|deferred|bounced)' || true)"
  [[ -z "$result" && -f /var/log/mail.log ]] && result="$(grep -E 'postfix/smtp.*status=(sent|deferred|bounced)' /var/log/mail.log | tail -5 || true)"
  [[ -n "$result" ]] && break
done
if [[ -z "$result" ]]; then
  run --allow-fail "File d'attente Postfix" postqueue -p || true
  die "Aucun résultat d'envoi après 60 s. Consulter : journalctl -u postfix -n 50 ; postqueue -p"
fi
echo "$result" | sed 's/^/  │ /'
if grep -q 'status=sent' <<< "$result" && ! grep -qE 'status=(deferred|bounced)' <<< "$result"; then
  log_ok "E-mail de test ACCEPTÉ par ${EMAIL_SMTP_HOST}. Vérifier la réception (et le dossier spam) : objet « $token »."
else
  echo "$result" > /tmp/.wazuh-mail-res; diagnose /tmp/.wazuh-mail-res 1 postfix; rm -f /tmp/.wazuh-mail-res
  run --allow-fail "Messages en attente" postqueue -p || true
  die "Le serveur d'envoi a refusé ou différé le message (ligne « status= » ci-dessus). Corriger puis relancer l'étape 07 ; vider la file : postsuper -d ALL"
fi

# ---------------------------------------------------------------- 4. Wazuh
section "4. Configuration de Wazuh"
ossec_begin
run "Activation des e-mails" ossec_conf set global email_notification yes
run "Serveur SMTP utilisé par Wazuh : Postfix local" ossec_conf set global smtp_server localhost
run "Expéditeur" ossec_conf set global email_from "$EMAIL_FROM"
# shellcheck disable=SC2086
run "Destinataires" ossec_conf setmulti global email_to $EMAIL_TO
run "Plafond horaire" ossec_conf set global email_maxperhour "$EMAIL_MAX_PER_HOUR"
run "Niveau minimal" ossec_conf set alerts email_alert_level "$EMAIL_ALERT_LEVEL"
ossec_commit
run --allow-fail "Démon d'envoi des e-mails de Wazuh (wazuh-maild)" bash -c "$OSSEC_DIR/bin/wazuh-control status | grep maild" || true
log_ok "Alertes e-mail actives : niveau >= $EMAIL_ALERT_LEVEL, au plus $EMAIL_MAX_PER_HOUR e-mails/heure, vers : $EMAIL_TO"
