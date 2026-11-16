#!/usr/bin/env bash
# Durcissement SSH du serveur Wazuh — ENTIÈREMENT OPTIONNEL.
# Chaque mesure est expliquée (but, risque, prérequis) puis proposée individuellement (oui/non).
# Les mesures retenues sont écrites dans UN seul fichier : /etc/ssh/sshd_config.d/00-wazuh-bundle.conf
# (la configuration d'origine n'est pas modifiée). La syntaxe est testée (sshd -t) avant rechargement ;
# la session en cours n'est jamais coupée. Retour arrière : relancer l'étape et choisir « supprimer ».
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 01 "Durcissement SSH (optionnel)"
DROPIN=/etc/ssh/sshd_config.d/00-wazuh-bundle.conf

explain <<'TXT'
SSH est la porte d'administration du serveur qui centralise la sécurité de l'entreprise :
le compromettre donne accès à toutes les alertes. Les mesures ci-dessous réduisent ce risque.
Rien n'est imposé : chaque mesure est proposée séparément, avec son risque.
Les valeurs sont placées dans un fichier « drop-in » lu AVANT la configuration principale
(dans sshd, la première valeur lue l'emporte), ce qui permet un retour arrière simple.
TXT

command -v sshd >/dev/null || { log_warn "Serveur OpenSSH absent : rien à durcir."; exit 0; }

if [[ -f "$DROPIN" ]]; then
  log_info "Un durcissement du bundle est déjà en place :"; sed 's/^/    /' "$DROPIN"
  ask_choice SSH_EXISTING_ACTION "Que faire ?" garder \
    "garder|Le conserver tel quel et quitter" "refaire|Reposer les questions et le remplacer" "supprimer|Le supprimer (retour à la configuration d'origine)"
  case "$SSH_EXISTING_ACTION" in
    garder) log_ok "Durcissement SSH conservé."; exit 0;;
    supprimer)
      run "Suppression du durcissement du bundle" rm -f "$DROPIN"
      run "Vérification de la configuration SSH restante" sshd -t
      if systemctl is-active --quiet ssh; then run "Rechargement de SSH" systemctl reload ssh
      elif systemctl is-active --quiet sshd; then run "Rechargement de SSH" systemctl reload sshd; fi
      log_ok "Durcissement supprimé."; exit 0;;
  esac
fi

ask_yes_no SSH_HARDEN "Voulez-vous durcir la configuration SSH de ce serveur ?" non || { log_info "Durcissement SSH non appliqué (choix de l'utilisateur)."; exit 0; }

if ! grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
  die "/etc/ssh/sshd_config ne contient pas « Include /etc/ssh/sshd_config.d/*.conf » : le fichier du bundle ne serait pas lu. Ajouter cette ligne en tête de /etc/ssh/sshd_config puis relancer."
fi

# Comptes d'administration (membres de sudo, hors root) et présence de clés SSH
admins="$(getent group sudo | cut -d: -f4 | tr ',' ' ')"
admins_with_key=""
for u in $admins; do
  h="$(getent passwd "$u" | cut -d: -f6)"
  [[ -s "$h/.ssh/authorized_keys" ]] && admins_with_key+="$u "
done
log_info "Comptes du groupe sudo : ${admins:-aucun}  —  avec clé SSH : ${admins_with_key:-aucun}"
log_info "Vous êtes connecté en tant que : ${SUDO_USER:-$(logname 2>/dev/null || echo root)}"

lines=()
add() { lines+=("$@"); }

section "Mesure 1/7 — Connexion directe de root"
explain <<'TXT'
But    : obliger à se connecter avec un compte nominatif puis « sudo » (traçabilité : on sait QUI
         a fait quoi) et retirer la cible n°1 des attaques par force brute (le compte root).
Choix  : no               = root ne peut plus se connecter en SSH.
         prohibit-password = root seulement avec une clé SSH (pas de mot de passe).
Risque : si aucun autre compte sudo ne fonctionne, vous perdez l'accès SSH. Tester d'abord
         une connexion avec votre compte nominatif + sudo.
TXT
if [[ -z "$admins" ]]; then
  log_warn "Aucun compte sudo hors root : mesure NON proposée (vous perdriez l'accès). Créer un compte : adduser NOM && usermod -aG sudo NOM"
else
  ask_choice SSH_ROOT_LOGIN "Connexion SSH de root" inchange \
    "inchange|Ne pas modifier" "prohibit-password|root uniquement par clé SSH" "no|root interdit en SSH"
  [[ "$SSH_ROOT_LOGIN" != inchange ]] && add "# Mesure 1 : connexion directe de root" "PermitRootLogin $SSH_ROOT_LOGIN"
fi

section "Mesure 2/7 — Authentification par mot de passe"
explain <<'TXT'
But    : n'accepter que les clés SSH. Un mot de passe peut être deviné ou volé ; une clé non.
         Rend les attaques par force brute sans effet.
Risque : un administrateur sans clé SSH installée ne pourra plus se connecter.
Prérequis vérifié : au moins un compte sudo avec ~/.ssh/authorized_keys.
TXT
if [[ -z "$admins_with_key" ]]; then
  log_warn "Aucun compte sudo avec clé SSH : mesure NON proposée. Installer une clé : ssh-copy-id NOM@${MANAGER_IP:-serveur}"
else
  if ask_yes_no SSH_DISABLE_PASSWORD "Désactiver l'authentification par mot de passe (clés uniquement) ?" non; then
    add "# Mesure 2 : clés SSH uniquement" "PasswordAuthentication no" "KbdInteractiveAuthentication no"
  fi
fi

section "Mesure 3/7 — Tentatives et délai de connexion"
explain <<'TXT'
But    : MaxAuthTries 4 = au plus 4 essais par connexion ; LoginGraceTime 30 = 30 secondes pour
         s'authentifier. Ralentit la force brute et libère les connexions abandonnées.
Risque : très faible. Un client avec beaucoup de clés chargées peut atteindre la limite
         (solution : ssh -o IdentitiesOnly=yes -i ~/.ssh/ma_cle).
TXT
ask_yes_no SSH_LIMIT_TRIES "Appliquer MaxAuthTries 4 et LoginGraceTime 30 ?" oui && add "# Mesure 3 : tentatives et délai" "MaxAuthTries 4" "LoginGraceTime 30"

section "Mesure 4/7 — Mots de passe vides"
explain <<'TXT'
But    : interdire la connexion d'un compte sans mot de passe (PermitEmptyPasswords no).
Risque : aucun pour un usage normal (c'est déjà la valeur par défaut ; on la fixe explicitement).
TXT
ask_yes_no SSH_NO_EMPTY "Interdire explicitement les mots de passe vides ?" oui && add "# Mesure 4 : mots de passe vides" "PermitEmptyPasswords no"

section "Mesure 5/7 — Redirection graphique X11"
explain <<'TXT'
But    : un serveur SIEM n'a pas d'interface graphique ; la redirection X11 (X11Forwarding)
         est une surface d'attaque inutile.
Risque : aucun, sauf si vous lancez des applications graphiques via SSH (improbable ici).
TXT
ask_yes_no SSH_NO_X11 "Désactiver la redirection X11 ?" oui && add "# Mesure 5 : pas de X11" "X11Forwarding no"

section "Mesure 6/7 — Déconnexion des sessions inactives"
explain <<'TXT'
But    : fermer une session SSH restée ouverte et sans réponse (poste verrouillé, réseau coupé)
         après 10 minutes : ClientAliveInterval 300 + ClientAliveCountMax 2.
Risque : une session réellement inactive sera fermée (enregistrer son travail, utiliser tmux).
TXT
ask_yes_no SSH_IDLE_TIMEOUT "Fermer les sessions sans réponse après 10 minutes ?" oui && add "# Mesure 6 : sessions inactives" "ClientAliveInterval 300" "ClientAliveCountMax 2"

section "Mesure 7/7 — Liste des comptes autorisés"
explain <<'TXT'
But    : seuls les comptes listés peuvent se connecter en SSH (AllowUsers). Un compte de service
         ou un compte créé par un attaquant ne pourra pas se connecter.
Risque : ÉLEVÉ en cas d'oubli : un compte absent de la liste perd l'accès SSH.
         Le script refuse une liste qui n'inclut pas votre propre compte.
TXT
me="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
if ask_yes_no SSH_ALLOW_USERS_ENABLE "Restreindre SSH à une liste de comptes ?" non; then
  ask SSH_ALLOW_USERS "Comptes autorisés (séparés par des espaces)" "$me" v_nonempty
  [[ " $SSH_ALLOW_USERS " == *" $me "* ]] || die "Votre compte ($me) n'est pas dans la liste : vous perdriez l'accès. Relancer l'étape."
  for u in $SSH_ALLOW_USERS; do getent passwd "$u" >/dev/null || die "Le compte « $u » n'existe pas sur ce serveur."; done
  add "# Mesure 7 : comptes autorisés" "AllowUsers $SSH_ALLOW_USERS"
fi

if (( ${#lines[@]} == 0 )); then log_info "Aucune mesure retenue : rien n'est modifié."; exit 0; fi

section "Application"
tmp="$(mktemp)"
{ echo "# Généré par wazuh-bundle (étape 01) le $(date '+%F %T'). Retour arrière : supprimer ce fichier puis « systemctl reload ssh »."
  printf '%s\n' "${lines[@]}"; } > "$tmp"
echo "Contenu qui sera écrit dans $DROPIN :"; sed 's/^/    /' "$tmp"
confirm "Appliquer ces mesures ?" || { rm -f "$tmp"; die "Annulé : rien n'a été modifié."; }
[[ -f "$DROPIN" ]] && backup_file "$DROPIN"
run "Installation du fichier de durcissement" install -m 644 "$tmp" "$DROPIN"
rm -f "$tmp"
if ! run --allow-fail --hint "Le fichier du bundle est retiré automatiquement." "Test de la configuration SSH (sshd -t)" sshd -t; then
  run "Retrait du fichier invalide" rm -f "$DROPIN"
  die "Configuration SSH invalide : rien n'a été appliqué."
fi
if systemctl is-active --quiet ssh; then run "Rechargement de SSH (les sessions ouvertes ne sont pas coupées)" systemctl reload ssh
elif systemctl is-active --quiet sshd; then run "Rechargement de SSH (les sessions ouvertes ne sont pas coupées)" systemctl reload sshd
else log_info "SSH est activé à la demande (socket) : la configuration s'applique à la prochaine connexion."; fi
run_sh "Valeurs effectivement appliquées par sshd" "sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|maxauthtries|logingracetime|permitemptypasswords|x11forwarding|clientaliveinterval|clientalivecountmax|allowusers) '"

log_ok "Durcissement SSH appliqué."
log_warn "AVANT de fermer cette session : ouvrir une NOUVELLE connexion SSH et vérifier qu'elle fonctionne (et que sudo fonctionne)."
