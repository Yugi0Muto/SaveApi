#!/bin/bash
# Wazuh Active Response — analyse YARA d'un fichier (agents Linux) — wazuh-bundle
# Installé par agents/install_agent_linux.sh dans /var/ossec/active-response/bin/yara.sh
#
# Fonctionnement : quand un fichier est ajouté/modifié dans un répertoire surveillé, le manager
# déclenche la règle 100501/100502 et demande à l'agent d'exécuter ce script. Le script reçoit
# l'alerte (JSON) sur l'entrée standard, analyse le fichier avec YARA et écrit le résultat dans
# active-responses.log ; l'agent renvoie cette ligne au manager -> règle 100511 (malware) ou 100512 (erreur).
# Paramètres (extra_args de la commande yara_linux, étape 06) :
#   -yara_path auto|DOSSIER  -yara_rules FICHIER  -max_size_mb N
LOG_FILE="${YARA_LOG_FILE:-/var/ossec/logs/active-responses.log}"
log() { echo "wazuh-yara: $1 - $2" >> "$LOG_FILE"; }

read -r INPUT_JSON
command -v jq >/dev/null 2>&1 || { log ERROR "jq absent sur l'agent (apt-get install -y jq)"; exit 1; }

ACTION=$(jq -r '.command // "add"' <<< "$INPUT_JSON")
arg() { jq -r --arg k "$1" '.parameters.extra_args as $a | ($a | index($k)) as $i | if $i == null then empty else $a[$i+1] end' <<< "$INPUT_JSON"; }
YARA_PATH="$(arg -yara_path)"
YARA_RULES="$(arg -yara_rules)"
MAX_MB="$(arg -max_size_mb)"; [[ "$MAX_MB" =~ ^[0-9]+$ ]] || MAX_MB=100
FILENAME=$(jq -r '.parameters.alert.syscheck.path // empty' <<< "$INPUT_JSON")

[[ "$ACTION" == "add" ]] || exit 0
[[ -n "$YARA_RULES" ]] || { log ERROR "paramètre -yara_rules manquant (commande yara_linux, étape 06)"; exit 1; }
# Binaire : chemin donné, sinon /usr/local/bin (YARA compilé) puis /usr/bin (paquet)
YARA_BIN=""
for c in "${YARA_PATH:+$YARA_PATH/yara}" /usr/local/bin/yara /usr/bin/yara; do
  [[ -n "$c" && "$c" != auto/yara && -x "$c" ]] && { YARA_BIN="$c"; break; }
done
[[ -n "$YARA_BIN" ]] || { log ERROR "binaire yara introuvable sur l'agent (bash tools/install_yara.sh)"; exit 1; }
[[ -r "$YARA_RULES" ]] || { log ERROR "règles YARA introuvables : $YARA_RULES (l'agent est-il dans le groupe feat-yara ?)"; exit 1; }
[[ -n "$FILENAME" && "$FILENAME" != -* ]] || exit 0     # pas de chemin, ou chemin ressemblant à une option
[[ -f "$FILENAME" ]] || exit 0                          # supprimé entre-temps
size=$(stat -c %s -- "$FILENAME" 2>/dev/null || echo 0)
(( size <= MAX_MB*1024*1024 )) || exit 0               # trop gros : ignoré (paramètre max_size_mb)

base="$(basename -- "$FILENAME")"; ext=""
[[ "$base" == *.* ]] && ext=".${base##*.}"

# Variables externes attendues par certaines règles communautaires (signature-base…)
out="$(timeout 60 "$YARA_BIN" -w \
      -d filename="$base" -d filepath="$FILENAME" -d extension="$ext" -d filetype="" -d owner="" \
      "$YARA_RULES" "$FILENAME" 2>&1)"
rc=$?
(( rc == 124 )) && { log ERROR "délai dépassé (60 s) pendant l'analyse de $FILENAME"; exit 1; }
if (( rc != 0 )); then log ERROR "yara a échoué (code $rc) : $(head -1 <<< "$out")"; exit 1; fi

# Une ligne par règle correspondante : « NomDeRègle /chemin/du fichier »
while IFS= read -r line; do
  [[ -n "$line" ]] && log INFO "Scan result: $line"
done <<< "$out"
exit 0
