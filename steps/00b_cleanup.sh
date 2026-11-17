#!/usr/bin/env bash
# Vérifie que le serveur est VIERGE de toute installation précédente de Wazuh — faite avec le bundle
# (v2 ou v3) ou à la main — et le nettoie si besoin, AVANT l'installation (étape 02).
# 1. inventaire en lecture seule : paquets (même à moitié installés ou « désinstallés » avec leur
#    configuration), dossiers, services systemd orphelins, dépôt APT, comptes système, processus et ports,
#    installation dpkg interrompue, traces du bundle (tâches planifiées, outils, secrets périmés),
#    pare-feu nftables de la v2, provisionnement Grafana, logiciels tiers en conflit ;
# 2. explication de chaque catégorie, puis nettoyage catégorie par catégorie, après confirmation ;
# 3. nouvel inventaire : l'étape ne réussit que si plus rien ne bloque l'installation.
# Conservés : vos réponses, le durcissement SSH, les sauvegardes, les journaux. Les mots de passe de
# l'ancienne installation sont ARCHIVÉS (pas supprimés). Un logiciel tiers n'est jamais supprimé d'office.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
source "$BUNDLE_ROOT/lib/cleanup.sh"
require_root
step_header 00b "Nettoyage : traces d'une installation précédente"

if pkg_installed wazuh-manager && pkg_installed wazuh-indexer && pkg_installed wazuh-dashboard && pkg_installed filebeat \
   && systemctl is-active --quiet wazuh-manager && [[ "${CLEANUP_FORCE:-0}" != 1 ]]; then
  explain <<'TXT'
Wazuh est installé et fonctionne sur ce serveur : cette étape ne le touche pas.
Pour repartir de zéro volontairement (réinstallation complète), relancer :
  CLEANUP_FORCE=1 bash install.sh --step 00b
TXT
  log_ok "Installation Wazuh en service : aucun nettoyage nécessaire."; exit 0
fi

explain <<'TXT'
Pourquoi cette étape : l'installateur officiel de Wazuh ne sait pas installer par-dessus les restes
d'une installation précédente. Il échoue au milieu (ex. « wazuh-keystore : Aucun fichier »,
« wazuh-manager could not be started ») puis annule tout. Un serveur propre évite ces échecs.
L'inventaire ci-dessous est en LECTURE SEULE ; rien n'est supprimé sans votre confirmation.
TXT

declare -A TITLE=(
  [wazuh]="Composants Wazuh restants — BLOQUANT"
  [conflict]="Logiciels tiers en conflit — BLOQUANT (jamais supprimés automatiquement)"
  [system]="Gestionnaire de paquets — BLOQUANT"
  [bundle]="Traces du bundle liées à l'ancienne installation"
  [firewall]="Pare-feu de la version 2 du bundle"
  [grafana]="Grafana local : provisionnement Wazuh"
  [keep]="Conservé volontairement (aucune action)"
)
ORDER_CAT=(wazuh conflict system bundle firewall grafana keep)

report() { # affiche l'inventaire ; renvoie le nombre de traces hors « keep »
  local scan cat n=0 c
  scan="$(trace_scan)"
  section "Inventaire"
  echo "  ${DIM}(lecture seule : dpkg-query, systemd, /etc/passwd, ss, ps, fichiers)${NC}"
  for cat in "${ORDER_CAT[@]}"; do
    c="$(grep "^$cat|" <<< "$scan" || true)"
    [[ -z "$c" ]] && continue
    local col="$YELLOW"; [[ "$cat" =~ ^(wazuh|conflict|system)$ ]] && col="$RED"; [[ "$cat" == keep ]] && col="$GREEN"
    echo "  ${col}${BOLD}${TITLE[$cat]}${NC}"
    while IFS='|' read -r _ kind target detail; do
      printf '    %s%-8s%s %s — %s\n' "$DIM" "$kind" "$NC" "$target" "$detail"
    done <<< "$c"
    [[ "$cat" != keep ]] && n=$((n + $(grep -c . <<< "$c")))
  done
  (( n == 0 )) && log_ok "Aucune trace d'une installation précédente : le système est propre."
  SCAN="$scan"; return 0
}
items() { grep "^$1|$2|" <<< "$SCAN" | cut -d'|' -f3 || true; }

report
if ! grep -qvE '^keep\|' <<< "$SCAN"; then exit 0; fi
[[ "$NONINTERACTIVE" == 1 ]] && die "Traces détectées (voir l'inventaire) : le nettoyage demande une confirmation, relancer l'étape 00b en mode interactif."

# ---------------------------------------------------------------- Wazuh + gestionnaire de paquets
if grep -qE '^(wazuh|system)\|' <<< "$SCAN"; then
  section "Nettoyage des composants Wazuh"
  explain <<'TXT'
Ce nettoyage SUPPRIME de CE serveur : les paquets Wazuh (manager, indexer, dashboard, Filebeat, agent),
leurs données (alertes, index), leur configuration (règles, certificats), leurs services, leur dépôt APT
et leurs comptes système. C'est l'équivalent d'une réinstallation du système pour la partie Wazuh.
Les sauvegardes déjà faites (/var/backups/wazuh) ne sont pas touchées.
TXT
  confirm "Supprimer TOUS les composants Wazuh listés ci-dessus ?" || die "Nettoyage refusé : l'installation (étape 02) ne pourra pas réussir tant que ces traces existent."
  if grep -q '^system|dpkg|' <<< "$SCAN"; then
    run --hint "Lire le message de dpkg ; souvent une installation interrompue par une coupure." \
      "Reprise de l'installation de paquets interrompue" env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
  fi
  for u in "${WZ_UNITS[@]}"; do
    if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
      run --allow-fail "Arrêt et désactivation du service $u" systemctl disable --now "$u" || true
    fi
  done
  held="$(items system hold)"
  # shellcheck disable=SC2086
  [[ -n "$held" ]] && run "Déblocage des paquets (apt-mark unhold)" apt-mark unhold $held
  pkgs=(); for p in "${WZ_PKGS[@]}"; do [[ -n "$(_pkg_state "$p")" ]] && pkgs+=("$p"); done
  (( ${#pkgs[@]} )) && run --hint "Si un script de désinstallation échoue : dpkg --remove --force-remove-reinstreq <paquet>" \
    "Purge des paquets : ${pkgs[*]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${pkgs[@]}"
  for pid in $(items wazuh proc); do
    kill -0 "$pid" 2>/dev/null && run --allow-fail "Arrêt du processus orphelin $pid" kill "$pid" || true
  done
  for d in "${WZ_DIRS[@]}" $(items wazuh unit) $(items wazuh apt); do
    [[ -e "$d" ]] && run "Suppression de $d" rm -rf -- "$d"
  done
  [[ -n "$(items wazuh unit)" ]] && run "Rechargement de systemd" systemctl daemon-reload
  for u in "${WZ_USERS[@]}"; do
    getent passwd "$u" >/dev/null && run --allow-fail "Suppression du compte système $u" userdel "$u" || true
    getent group "$u" >/dev/null && run --allow-fail "Suppression du groupe $u" groupdel "$u" || true
  done
  run --allow-fail "Mise à jour de l'index des paquets (dépôt Wazuh retiré)" apt-get update || true
fi

# ---------------------------------------------------------------- bundle
if grep -q '^bundle|' <<< "$SCAN"; then
  section "Traces du bundle"
  explain <<'TXT'
Tâches planifiées, outils et fichiers générés pour l'ancienne installation : ils seront réinstallés par
les étapes concernées. Les mots de passe de l'ancienne installation (fichiers et secrets) sont
ARCHIVÉS dans /root/.wazuh-bundle/ancienne-installation-<date>/ puis retirés : la nouvelle installation
en génère de nouveaux. Vos réponses aux questions sont conservées (sauf version et adresse de l'indexer,
redéterminées à l'étape 02).
TXT
  if confirm "Nettoyer les traces du bundle (avec archivage des mots de passe) ?"; then
    arch="$SECRETS_DIR/ancienne-installation-$(date +%Y%m%d-%H%M%S)"
    if [[ -n "$(items bundle secret)$(items bundle archive)" ]]; then
      run "Archivage des secrets et mots de passe de l'ancienne installation" install -d -m 700 "$arch"
      [[ -f "$SECRETS_FILE" ]] && run "Copie de secrets.env dans l'archive" cp -p "$SECRETS_FILE" "$arch/"
      for f in $(items bundle archive); do run "Archivage de $(basename "$f")" mv "$f" "$arch/"; done
      for k in $(items bundle secret); do run "Retrait du secret périmé $k" sed -i "/^$k=/d" "$SECRETS_FILE"; done
    fi
    for k in $(items bundle answer); do run "Retrait de la réponse périmée $k" sed -i "/^$k=/d" "$ANSWERS_FILE"; done
    if [[ -e /etc/systemd/system/wazuh-sms-alerter.service ]]; then
      run --allow-fail "Arrêt du service SMS" systemctl disable --now wazuh-sms-alerter || true
    fi
    for f in $(items bundle file); do [[ -e "$f" ]] && run "Suppression de $f" rm -f -- "$f"; done
    getent passwd wazuh-sms >/dev/null && run --allow-fail "Suppression du compte wazuh-sms" userdel wazuh-sms || true
    systemctl daemon-reload
  else log_info "Traces du bundle conservées."; fi
fi

# ---------------------------------------------------------------- pare-feu v2
if grep -q '^firewall|' <<< "$SCAN"; then
  section "Pare-feu de la version 2 du bundle"
  explain <<'TXT'
La version 2 du bundle posait un pare-feu nftables sur ce serveur (« flush ruleset » : il remplaçait
toutes les règles). La version 3 ne gère plus aucun pare-feu : c'est le pare-feu de l'entreprise qui
filtre (voir « bash install.sh --flows »). Garder ces règles peut bloquer des flux nécessaires.
Attention : si l'entreprise compte sur ce pare-feu LOCAL, répondre non et le reprendre à son compte.
TXT
  if confirm "Retirer le pare-feu nftables posé par la v2 du bundle ?"; then
    [[ -n "$(items firewall nft)" ]] && run "Retrait de la table nftables wazuh_bundle" nft delete table inet wazuh_bundle
    if [[ -n "$(items firewall file)" ]]; then
      run "Mise de côté de /etc/nftables.conf (v2)" mv /etc/nftables.conf "/etc/nftables.conf.wazuh-bundle-v2.$(date +%Y%m%d)"
      run_sh "Remise d'une configuration nftables neutre" "printf '#!/usr/sbin/nft -f\nflush ruleset\n' > /etc/nftables.conf && chmod 755 /etc/nftables.conf"
      run --allow-fail "Désactivation du chargement nftables au démarrage" systemctl disable nftables || true
    fi
  else log_warn "Pare-feu v2 conservé : vérifier qu'il autorise les flux de « bash install.sh --flows »."; fi
fi

# ---------------------------------------------------------------- Grafana
if grep -q '^grafana|' <<< "$SCAN"; then
  section "Grafana : provisionnement Wazuh"
  if confirm "Retirer la source de données et les tableaux de bord Wazuh de Grafana (reprovisionnés par l'étape 09) ?"; then
    for f in $(items grafana file); do run "Suppression de $f" rm -rf -- "$f"; done
    systemctl is-active --quiet grafana-server && run --allow-fail "Redémarrage de Grafana" systemctl restart grafana-server || true
  fi
fi

# ---------------------------------------------------------------- conflits tiers : explication seulement
if grep -q '^conflict|' <<< "$SCAN"; then
  section "Logiciels tiers en conflit"
  explain <<'TXT'
Ces logiciels ne viennent pas de Wazuh : le bundle ne les supprime pas. Ils occupent un port nécessaire
(443 dashboard, 1514/1515 agents, 9200 indexer, 55000 API) ou jouent le même rôle que l'indexer.
Décider avec leur responsable : les arrêter, les déplacer sur un autre serveur, ou changer leur port.
Identifier le programme : ss -tlnp 'sport = :PORT'
TXT
fi

# ---------------------------------------------------------------- vérification finale
section "Vérification finale"
report
if grep -qE '^(wazuh|conflict|system)\|' <<< "$SCAN"; then
  die "Des traces BLOQUANTES subsistent (en rouge ci-dessus) : l'installation (étape 02) échouerait. Les traiter puis relancer l'étape 00b."
fi
log_ok "Serveur prêt pour une installation neuve de Wazuh (étape 02)."
