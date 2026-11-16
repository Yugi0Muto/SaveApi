#!/usr/bin/env bash
# lib/email.sh — génération des paramètres Postfix pour les 3 modes d'envoi (fonction pure, testable sans root)
#
# postfix_settings MODE HÔTE PORT TLS AUTH
#   MODE : gmail | entreprise | relais
#   TLS  : verify   = chiffrement obligatoire + certificat vérifié (nom du serveur + autorité reconnue)
#          encrypt  = chiffrement obligatoire, certificat non vérifié (CA interne non installée)
#          smtps    = connexion chiffrée dès l'ouverture (port 465), certificat vérifié
#          may      = chiffrement si le serveur le propose (relais interne)
#          none     = aucun chiffrement (déconseillé)
#   AUTH : oui | non
# Sortie : une ligne « paramètre = valeur » par réglage, à appliquer avec postconf -e.
postfix_settings() {
  local mode="$1" host="$2" port="$3" tls="$4" auth="$5"
  echo "inet_interfaces = loopback-only"
  echo "inet_protocols = ipv4"
  echo "relayhost = [${host}]:${port}"
  echo "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
  echo "smtp_tls_loglevel = 1"
  case "$tls" in
    verify)  echo "smtp_tls_security_level = secure"; echo "smtp_tls_wrappermode = no";;
    smtps)   echo "smtp_tls_security_level = secure"; echo "smtp_tls_wrappermode = yes";;
    encrypt) echo "smtp_tls_security_level = encrypt"; echo "smtp_tls_wrappermode = no";;
    may)     echo "smtp_tls_security_level = may"; echo "smtp_tls_wrappermode = no";;
    none)    echo "smtp_tls_security_level = none"; echo "smtp_tls_wrappermode = no";;
    *) echo "ERREUR: mode TLS inconnu $tls" >&2; return 1;;
  esac
  if [[ "$auth" == oui ]]; then
    echo "smtp_sasl_auth_enable = yes"
    echo "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    echo "smtp_sasl_security_options = noanonymous"
    echo "smtp_sasl_tls_security_options = noanonymous"
  else
    echo "smtp_sasl_auth_enable = no"
  fi
  [[ "$mode" =~ ^(gmail|entreprise|relais)$ ]] || { echo "ERREUR: mode inconnu $mode" >&2; return 1; }
}
