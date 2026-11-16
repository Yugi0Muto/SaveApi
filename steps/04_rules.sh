#!/usr/bin/env bash
# Déploie les règles de détection du bundle (configs/manager/bundle_rules.xml) et les AUTO-TESTE.
# Les règles complètent les quelque 4 000 règles fournies par Wazuh : modifications de fichiers
# sensibles Linux (clés SSH, sudoers, cron, comptes), connexions root, effacement de journaux Windows,
# ajout à un groupe administrateur, nouveaux services, désactivation de Defender…
# Détail de chaque règle (but, déclencheur, niveau, test) : docs/REGLES.md
# Les règles « malware » (hashes, YARA) sont déployées par l'étape 06.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
step_header 04 "Règles de détection"
require_wazuh

explain <<'TXT'
Comment Wazuh produit une alerte :
  1. un agent envoie un événement (ligne de journal, fichier modifié, événement Windows) ;
  2. un DÉCODEUR en extrait les champs (utilisateur, IP source, fichier…) ;
  3. les RÈGLES sont évaluées ; la plus précise qui correspond donne l'alerte et son NIVEAU (0 à 15).
Les règles du bundle « spécialisent » des règles Wazuh existantes et relèvent le niveau des
situations importantes pour l'entreprise. Niveaux utilisés :
   8 = à examiner   10 = suspect   12 = incident probable   14 = incident (malware confirmé)
Les alertes e-mail (étape 07) et SMS (étape 08) se déclenchent à partir d'un niveau que vous choisirez.
TXT

run "Résumé des règles qui vont être déployées" \
  python3 - "$BUNDLE_ROOT/configs/manager/bundle_rules.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.fromstring("<r>" + open(sys.argv[1], encoding="utf-8").read() + "</r>")
for r in root.iter("rule"):
    print(f"  {r.get('id')}  niveau {r.get('level'):>2}  {r.findtext('description')}")
PY

R="$OSSEC_DIR/etc/rules"; D="$OSSEC_DIR/etc/decoders"
# La v2 du bundle utilisait bundle_rules.xml / bundle_decoders.xml : retirés (identifiants désormais
# répartis entre bundle_10_rules.xml et bundle_00_malware_rules.xml, sinon doublons refusés par Wazuh).
rules_deploy \
  "$BUNDLE_ROOT/configs/manager/bundle_rules.xml:$R/bundle_10_rules.xml" \
  "-:$R/bundle_rules.xml" \
  "-:$D/bundle_decoders.xml" \
  || die "Règles refusées par Wazuh (message ci-dessus : fichier et ligne). L'état précédent a été restauré."
wazuh_restart || die "Le manager ne redémarre pas après le déploiement des règles."

section "Auto-test des règles (wazuh-logtest)"
explain <<'TXT'
wazuh-logtest rejoue une ligne de journal d'exemple et indique quelle règle se déclenche.
C'est la preuve que la règle est chargée et fonctionne, sans attendre un vrai incident.
TXT
logtest_file "$BUNDLE_ROOT/configs/manager/rule_tests.txt" \
  || die "Les règles sont actives et valides, mais au moins une ne se déclenche pas comme prévu : voir la sortie ci-dessus et docs/REGLES.md."
log_ok "Règles du bundle déployées et testées. Liste et explications : docs/REGLES.md"
