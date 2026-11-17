#!/usr/bin/env bash
# lib/cleanup.sh — détection et nettoyage des traces d'une installation précédente de Wazuh
# (faite avec le bundle ou à la main). Sourcé par l'étape 00b et par l'étape 02.
#
# trace_scan affiche une ligne par trace : CATÉGORIE|TYPE|CIBLE|DÉTAIL
#   wazuh     : composant Wazuh (paquet, dossier, service, dépôt, compte…) — BLOQUANT : l'installateur
#               officiel échoue s'il en reste (« wazuh-keystore : Aucun fichier », etc.) ;
#   bundle    : état du bundle lié à l'ancienne installation (tâches planifiées, outils, secrets périmés) ;
#   firewall  : pare-feu nftables posé par la version 2 du bundle ;
#   grafana   : fichiers de provisionnement Wazuh dans un Grafana local ;
#   conflict  : logiciel tiers qui occupe un port ou entre en conflit (Elasticsearch…) — jamais supprimé
#               automatiquement : à traiter par l'administrateur ;
#   system    : état du gestionnaire de paquets (installation interrompue, paquets bloqués) ;
#   keep      : élément CONSERVÉ volontairement (durcissement SSH, sauvegardes, journaux, réponses).
# Pour les tests : CLEAN_ROOT préfixe tous les chemins ; CLEAN_FAKE_DPKG / CLEAN_FAKE_SS / CLEAN_FAKE_PS
# remplacent dpkg-query, ss et ps par le contenu d'un fichier.

CLEAN_ROOT="${CLEAN_ROOT:-}"
WZ_PKGS=(wazuh-manager wazuh-indexer wazuh-dashboard filebeat wazuh-agent)
CONFLICT_PKGS=(elasticsearch kibana opensearch opensearch-dashboards logstash graylog-server)
WZ_DIRS=(/var/ossec /etc/filebeat /var/lib/filebeat /usr/share/filebeat /var/log/filebeat
         /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer /var/log/wazuh-indexer
         /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /var/log/wazuh-dashboard)
WZ_UNITS=(wazuh-manager wazuh-indexer wazuh-dashboard filebeat wazuh-agent wazuh-indexer-performance-analyzer)
WZ_APT=(/etc/apt/sources.list.d/wazuh.list /usr/share/keyrings/wazuh.gpg /etc/apt/trusted.gpg.d/wazuh.gpg)
WZ_USERS=(wazuh wazuh-indexer wazuh-dashboard)
WZ_PORTS=(443 1514 1515 9200 55000)
BUNDLE_CRONS=(/etc/cron.d/wazuh-bundle-malware /etc/cron.d/wazuh-bundle-purge /etc/cron.d/wazuh-bundle-backup)
BUNDLE_TOOLS=(/usr/local/sbin/wazuh-bundle-update-malware /usr/local/sbin/wazuh-bundle-purge-logs
              /usr/local/sbin/wazuh-bundle-backup /usr/local/bin/wazuh-sms-alerter.py
              /etc/systemd/system/wazuh-sms-alerter.service)
# Réponses et secrets propres à l'installation précédente (les autres réponses sont des préférences : conservées)
STALE_ANSWERS=(WAZUH_VERSION INDEXER_HOST)
STALE_SECRETS=(INDEXER_ADMIN_PASSWORD GRAFANA_RO_PASSWORD)
BUNDLE_DROPIN="wazuh-bundle-timeout.conf"

_r() { printf '%s%s' "$CLEAN_ROOT" "$1"; }
_pkg_state() { # état dpkg abrégé (ii, rc, iU…) ou vide si absent
  if [[ -n "${CLEAN_FAKE_DPKG:-}" ]]; then awk -v p="$1" '$1==p{print $2}' "$CLEAN_FAKE_DPKG"; return; fi
  local st; st="$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null || true)"; st="${st// /}"
  [[ -z "$st" || "$st" == un || "$st" == pn ]] || echo "$st"
}
_listening() { # lignes « port processus » des ports en écoute
  if [[ -n "${CLEAN_FAKE_SS:-}" ]]; then cat "$CLEAN_FAKE_SS"; return; fi
  ss -tlnpH 2>/dev/null | awk '{n=split($4,a,":"); proc=$6; sub(/.*\(\("/,"",proc); sub(/".*/,"",proc); print a[n], proc}'
}
_procs() {
  if [[ -n "${CLEAN_FAKE_PS:-}" ]]; then cat "$CLEAN_FAKE_PS"; return; fi
  ps -eo pid=,user=,args= 2>/dev/null
}

trace_scan() {
  local p st d u port proc f k
  # --- Wazuh : paquets, dossiers, services, dépôt, comptes, processus
  for p in "${WZ_PKGS[@]}"; do
    st="$(_pkg_state "$p")"
    if [[ -n "$st" ]]; then
      case "$st" in
        ii) d="installé";; rc) d="désinstallé, fichiers de configuration restants";; *) d="installation incomplète ou cassée";;
      esac
      [[ "$p" == wazuh-agent ]] && d="$d — un agent ne doit pas être installé sur le serveur Wazuh"
      echo "wazuh|pkg|$p|$d (état dpkg $st)"
    fi
  done
  for d in "${WZ_DIRS[@]}"; do [[ -e "$(_r "$d")" ]] && echo "wazuh|dir|$d|dossier restant"; done
  for u in "${WZ_UNITS[@]}"; do
    for f in "/etc/systemd/system/$u.service" "/lib/systemd/system/$u.service" "/usr/lib/systemd/system/$u.service"; do
      [[ -e "$(_r "$f")" ]] && [[ -z "$(_pkg_state "$u")" ]] && echo "wazuh|unit|$f|service systemd orphelin (paquet absent)"
    done
    # surcharges systemd : celle du bundle (délai de démarrage) est conservée, les autres sont des restes
    f="/etc/systemd/system/$u.service.d"
    if [[ -d "$(_r "$f")" ]]; then
      for k in "$(_r "$f")"/*; do
        [[ -e "$k" ]] || continue
        if [[ "$(basename "$k")" == "$BUNDLE_DROPIN" ]]; then echo "keep|file|$f/$BUNDLE_DROPIN|délai de démarrage allongé par le bundle (serveur aux ressources limitées)"
        elif [[ -z "$(_pkg_state "$u")" ]]; then echo "wazuh|unit|$f/$(basename "$k")|surcharge systemd d'une ancienne installation"; fi
      done
    fi
  done
  for f in "${WZ_APT[@]}"; do [[ -e "$(_r "$f")" ]] && echo "wazuh|apt|$f|dépôt ou clé APT d'une ancienne installation (l'installateur le recrée)"; done
  for u in "${WZ_USERS[@]}"; do
    grep -q "^$u:" "$(_r /etc/passwd)" 2>/dev/null && echo "wazuh|user|$u|compte système restant"
  done
  _procs | grep -E '/var/ossec/|wazuh-indexer|wazuh-dashboard|/usr/share/filebeat' | grep -v grep \
    | while read -r pid user args; do echo "wazuh|proc|$pid|processus encore actif ($user) : ${args:0:80}"; done
  # --- conflits : logiciels tiers, ports occupés par autre chose que Wazuh
  for p in "${CONFLICT_PKGS[@]}"; do
    st="$(_pkg_state "$p")"; [[ "$st" == ii ]] && echo "conflict|pkg|$p|logiciel tiers installé (mêmes ports ou même rôle que l'indexer Wazuh)"
  done
  while read -r port proc; do
    [[ -z "$port" ]] && continue
    for p in "${WZ_PORTS[@]}"; do
      if [[ "$port" == "$p" ]]; then
        case "$proc" in
          wazuh*|java|filebeat|node|ossec*|python3*|"") echo "wazuh|port|$port|port $port occupé par ${proc:-un processus Wazuh}";;
          *) echo "conflict|port|$port|port $port occupé par « $proc » (nécessaire à Wazuh)";;
        esac
      fi
    done
  done < <(_listening)
  # --- gestionnaire de paquets
  if [[ -z "${CLEAN_FAKE_DPKG:-}" ]]; then
    [[ -n "$(dpkg --audit 2>/dev/null)" ]] && echo "system|dpkg|dpkg|installation de paquets interrompue (dpkg --audit)"
    for p in $(apt-mark showhold 2>/dev/null | grep -E '^(wazuh|filebeat)' || true); do
      echo "system|hold|$p|paquet bloqué (apt-mark hold)"
    done
  fi
  # --- bundle : état lié à l'ancienne installation
  for f in "${BUNDLE_CRONS[@]}" "${BUNDLE_TOOLS[@]}"; do [[ -e "$(_r "$f")" ]] && echo "bundle|file|$f|installé par le bundle pour l'ancienne installation (réinstallé par les étapes)"; done
  grep -q '^wazuh-sms:' "$(_r /etc/passwd)" 2>/dev/null && echo "bundle|user|wazuh-sms|compte du service SMS (recréé par l'étape 08)"
  f="$(_r "${STATE_DIR:-/etc/wazuh-bundle}")"
  for k in yara_base_rules.yar sms.env postfix.settings RETENTION.txt; do
    [[ -e "$f/$k" ]] && echo "bundle|file|${STATE_DIR:-/etc/wazuh-bundle}/$k|fichier généré pour l'ancienne installation"
  done
  if [[ -f "$f/answers.env" ]]; then
    for k in "${STALE_ANSWERS[@]}"; do grep -q "^$k=" "$f/answers.env" && echo "bundle|answer|$k|réponse liée à l'ancienne installation (redéterminée à l'étape 02)"; done
  fi
  f="$(_r "${SECRETS_DIR:-/root/.wazuh-bundle}")"
  if [[ -d "$f" ]]; then
    for k in "${STALE_SECRETS[@]}"; do grep -q "^$k=" "$f/secrets.env" 2>/dev/null && echo "bundle|secret|$k|mot de passe de l'ancienne installation (régénéré)"; done
    for k in wazuh-passwords.txt wazuh-install-files.tar wazuh-grafana-kit.tar.gz; do
      [[ -e "$f/$k" ]] && echo "bundle|archive|${SECRETS_DIR:-/root/.wazuh-bundle}/$k|mots de passe / certificats de l'ancienne installation (archivés, pas supprimés)"
    done
  fi
  # --- pare-feu de la v2 du bundle
  if [[ -z "$CLEAN_ROOT" ]] && command -v nft >/dev/null && nft list table inet wazuh_bundle >/dev/null 2>&1; then
    echo "firewall|nft|inet wazuh_bundle|pare-feu nftables chargé par la version 2 du bundle"
  fi
  grep -q 'wazuh-bundle' "$(_r /etc/nftables.conf)" 2>/dev/null && echo "firewall|file|/etc/nftables.conf|règles de pare-feu écrites par la version 2 du bundle"
  # --- Grafana local : provisionnement Wazuh
  for f in /etc/grafana/provisioning/datasources/wazuh-opensearch.yaml /etc/grafana/provisioning/dashboards/wazuh.yaml /var/lib/grafana/dashboards/wazuh; do
    [[ -e "$(_r "$f")" ]] && echo "grafana|file|$f|source de données / tableaux de bord Wazuh (reprovisionnés par l'étape 09)"
  done
  # --- conservé volontairement
  [[ -e "$(_r /etc/ssh/sshd_config.d/00-wazuh-bundle.conf)" ]] && echo "keep|file|/etc/ssh/sshd_config.d/00-wazuh-bundle.conf|durcissement SSH (indépendant de Wazuh ; retrait : étape 01)"
  [[ -d "$(_r /var/backups/wazuh)" ]] && echo "keep|dir|/var/backups/wazuh|sauvegardes de configuration (peuvent servir à comparer ou restaurer)"
  [[ -d "$(_r /var/log/wazuh-bundle)" ]] && echo "keep|dir|/var/log/wazuh-bundle|journaux du bundle"
  [[ -f "$(_r "${STATE_DIR:-/etc/wazuh-bundle}/answers.env")" ]] && echo "keep|file|${STATE_DIR:-/etc/wazuh-bundle}/answers.env|vos réponses (proposées par défaut à la réinstallation)"
  [[ -f "$(_r /etc/postfix/main.cf)" ]] && grep -q 'relayhost' "$(_r /etc/postfix/main.cf)" 2>/dev/null && echo "keep|file|/etc/postfix/main.cf|Postfix (reconfiguré par l'étape 07)"
  return 0
}

# Vrai s'il reste une trace bloquante pour une installation neuve
traces_blocking() { local s; s="$(trace_scan)"; grep -qE '^(wazuh|conflict|system)\|' <<< "$s"; }
