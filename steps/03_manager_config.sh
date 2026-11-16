#!/usr/bin/env bash
# Configure le manager Wazuh :
#   1. enrôlement des agents protégé par mot de passe (port 1515) ;
#   2. liste blanche : adresses jamais bloquées par la réponse active ;
#   3. réponse active (optionnelle) : blocage temporaire, SUR L'AGENT attaqué, d'une IP qui force SSH ;
#   4. groupes d'agents et configuration centralisée (configs/groups/*/agent.conf).
# Toutes les modifications de ossec.conf sont balisées, validées par Wazuh (wazuh-analysisd -t, …)
# AVANT redémarrage ; en cas d'échec, ossec.conf est restauré automatiquement.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 03 "Configuration du manager"
require_wazuh
need_answer MANAGER_IP 00
need_answer ADMIN_IPS 00
run --hint "Démarrer le manager : systemctl start wazuh-manager ; erreurs : tail -50 $OSSEC_DIR/logs/ossec.log" \
  "Le manager doit être actif avant modification" systemctl is-active wazuh-manager

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ossec_begin
run "Nettoyage des reliquats de la version 2 du bundle (doublons possibles)" ossec_conf migrate-v2

# ---------------------------------------------------------------- 1. Enrôlement
section "1. Enrôlement des agents"
explain <<'TXT'
Un agent s'inscrit auprès du manager sur le port 1515. Sans mot de passe, N'IMPORTE QUELLE
machine du réseau peut s'inscrire et envoyer de faux événements. Avec un mot de passe, seules
les machines installées par vos soins (script agents/install_agent_*.sh) peuvent s'inscrire.
Le mot de passe est stocké dans /var/ossec/etc/authd.pass (lu par Wazuh) et dans le coffre du bundle.
TXT
if secret_get AUTHD_PASSWORD >/dev/null; then
  AUTH_PW="$(secret_get AUTHD_PASSWORD)"; log_ok "Mot de passe d'enrôlement existant conservé."
else
  ask_choice AUTHD_PW_MODE "Mot de passe d'enrôlement" generer "generer|Générer un mot de passe aléatoire (24 caractères)" "saisir|Le saisir moi-même"
  if [[ "$AUTHD_PW_MODE" == generer ]]; then AUTH_PW="$(gen_password)"; secret_set AUTHD_PASSWORD "$AUTH_PW"
  else ask_secret AUTHD_PASSWORD "Mot de passe d'enrôlement"; AUTH_PW="$AUTHD_PASSWORD"; fi
fi
printf '%s' "$AUTH_PW" > "$TMP/authd.pass"
run "Installation de authd.pass (root:wazuh, 640)" install -o root -g wazuh -m 640 "$TMP/authd.pass" "$OSSEC_DIR/etc/authd.pass"
run "Activation de l'enrôlement par mot de passe" ossec_conf set auth use_password yes

# ---------------------------------------------------------------- 2. Liste blanche
section "2. Liste blanche (adresses jamais bloquées)"
explain <<'TXT'
La réponse active peut bloquer une adresse IP qui attaque. Pour éviter de se bloquer soi-même,
certaines adresses ne le sont JAMAIS : ce serveur, les postes d'administration, et les équipements
dont le blocage couperait le service (passerelles, DNS, scanners de vulnérabilités, supervision).
TXT
ask WHITELIST_EXTRA "Autres IP/CIDR à ne jamais bloquer (passerelles, DNS, scanners…), vide si aucune" "" v_ip_list
{ for ip in "$MANAGER_IP" $ADMIN_IPS $WHITELIST_EXTRA; do echo "<white_list>${ip}</white_list>"; done; } | sort -u > "$TMP/wl.xml"
run "Contenu de la liste blanche" cat "$TMP/wl.xml"
run "Écriture de la liste blanche dans <global>" ossec_conf block global whitelist "$TMP/wl.xml"

# ---------------------------------------------------------------- 3. Réponse active
section "3. Réponse active contre la force brute SSH"
explain <<'TXT'
Quand un agent Linux subit une attaque par force brute SSH (règles Wazuh 5712 : essais sur des
comptes inexistants, 5763 : échecs répétés), le manager ordonne à CET AGENT de bloquer l'adresse
attaquante dans SON propre pare-feu local (commande firewall-drop, iptables/nftables) pendant
une durée limitée, puis de la débloquer automatiquement.
Ce n'est PAS le pare-feu de l'entreprise : celui-ci n'est jamais modifié par le bundle.
Risque : bloquer un utilisateur légitime qui se trompe de mot de passe (durée limitée ;
la liste blanche ci-dessus n'est jamais bloquée).
TXT
if ask_yes_no AR_ENABLE "Activer le blocage automatique des IP qui forcent SSH ?" oui; then
  ask AR_TIMEOUT "Durée du blocage en secondes" "600" "v_int 60 86400"
  cat > "$TMP/ar.xml" <<XML
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712,5763</rules_id>
  <timeout>${AR_TIMEOUT}</timeout>
</active-response>
XML
  run "Ajout de la réponse active (blocage ${AR_TIMEOUT} s)" ossec_conf block ossec_config ar-ssh-bruteforce "$TMP/ar.xml"
  run --hint "La commande firewall-drop fait partie de la configuration Wazuh par défaut ; si elle a été supprimée, la recréer." \
    "Vérification : la commande firewall-drop est définie" grep -q "<name>firewall-drop</name>" "$OSSEC_CONF"
else
  run "Désactivation de la réponse active du bundle" ossec_conf unblock ar-ssh-bruteforce
fi

# ---------------------------------------------------------------- 4. Validation + redémarrage
section "4. Validation et redémarrage"
ossec_commit

# ---------------------------------------------------------------- 5. Groupes
section "5. Groupes d'agents (configuration centralisée)"
explain <<'TXT'
Chaque agent appartient à plusieurs groupes ; le manager lui envoie la configuration de chacun :
  seg-servers | seg-employees | seg-dmz  : segment réseau (fréquence du contrôle d'intégrité)
  os-linux | os-windows                  : fichiers et journaux surveillés selon le système
  role-web | role-db | role-admin        : surveillance propre au rôle de la machine
  opt-whodata                            : « qui a modifié ce fichier ? » (audit détaillé)
  feat-yara                              : analyse YARA (créé à l'étape 06)
Pour modifier la surveillance : éditer configs/groups/<groupe>/agent.conf puis relancer l'étape 03.
TXT
existing="$("$OSSEC_DIR/bin/agent_groups" -l 2>&1 || true)"
for g in "$BUNDLE_ROOT"/configs/groups/*/; do
  name="$(basename "$g")"
  run --hint "Valider le XML : xmllint --noout <(echo '<r>'; cat $g/agent.conf; echo '</r>')" \
    "Contrôle XML de $name/agent.conf" python3 -c 'import sys,xml.etree.ElementTree as E; E.fromstring("<r>"+open(sys.argv[1]).read()+"</r>")' "$g/agent.conf"
  if grep -Eq "^[[:space:]]*${name} \(" <<< "$existing"; then log_ok "Groupe $name : existe déjà"
  else run --hint "wazuh-db doit être actif (wazuh-control status)." "Création du groupe $name" "$OSSEC_DIR/bin/agent_groups" -a -g "$name" -q; fi
  [[ -d "$OSSEC_DIR/etc/shared/$name" ]] || die "Le dossier $OSSEC_DIR/etc/shared/$name n'a pas été créé par agent_groups."
  run "Installation de la configuration du groupe $name" install -o wazuh -g wazuh -m 660 "$g/agent.conf" "$OSSEC_DIR/etc/shared/$name/agent.conf"
done
run_sh "Vérification de la configuration centralisée (verify-agent-conf)" "$OSSEC_DIR/bin/verify-agent-conf"
run "Liste des groupes" "$OSSEC_DIR/bin/agent_groups" -l

log_ok "Manager configuré."
cat <<TXT

  Mot de passe d'enrôlement (pour installer les agents) : grep AUTHD_PASSWORD $SECRETS_FILE
  Installer un agent Linux  : bash agents/install_agent_linux.sh   (questions interactives)
  Installer un agent Windows: agents/install_agent_windows.ps1 (PowerShell administrateur)
TXT
