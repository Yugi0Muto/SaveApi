# wazuh-bundle v2 — déploiement Wazuh en production

Bundle d'installation et de configuration d'un SIEM Wazuh (all-in-one) pour une entreprise
organisée en trois segments : **SERVEURS**, **EMPLOYÉS**, **DMZ**.

> Statut : première version à **recetter**. Chaque étape est idempotente et s'arrête à la
> première erreur. Voir `RECETTE.md` pour le plan de test.

## Contenu
| Étape | Script | Rôle |
|---|---|---|
| 00 | `00_preflight.sh` | Contrôles (OS, RAM, disque, ports, NTP, réseau). Ne modifie rien. |
| 01 | `01_base_setup.sh` | Durcissement SSH sûr + installation Wazuh all-in-one |
| 02 | `02_firewall.sh` | Pare-feu nftables par segment, avec annulation automatique (90 s) |
| 03 | `03_manager_config.sh` | Enrôlement par mot de passe, liste blanche, groupes, règles |
| 04 | `04_malware_detection.sh` | YARA + liste de hashes, mise à jour quotidienne |
| 05 | `05_retention.sh` | Suppression des alertes > N jours |
| 06 | `06_grafana.sh` | Grafana **local ou distant**, utilisateur indexer lecture seule, dashboard |
| 07 | `07_email_alerts.sh` | Email via relais SMTP interne |
| 08 | `08_sms_alerts.sh` | SMS (Africa's Talking), dédup + plafond |
| 09 | `09_backup.sh` | Sauvegarde quotidienne de la configuration |
| 99 | `99_verify.sh` | Recette automatique |

Agents : `bash/agents/install_agent_linux.sh`, `bash/agents/install_agent_windows.ps1`.

## Démarrage rapide (serveur Debian/Ubuntu neuf)
```bash
sudo -i
apt-get update && apt-get install -y git
git clone https://github.com/VOTRE_COMPTE/wazuh-bundle.git /opt/wazuh-bundle
cd /opt/wazuh-bundle
git checkout v2.0.0            # en production : toujours un tag, jamais la branche principale
cp bundle.conf.example bundle.conf && chmod 600 bundle.conf
nano bundle.conf               # remplir TOUTES les valeurs A_COMPLETER
bash install.sh --step 00      # préflight ; corriger jusqu'à "Préflight OK"
bash install.sh                # menu, ou : bash install.sh --all
```
**Ne pas faire** `curl ... | sudo bash` : ces scripts s'exécutent en root, relire le code avant de les lancer.

## Démarrage (archive ZIP)
```bash
sudo -i
cd wazuh-bundle-v2
cp bundle.conf.example bundle.conf && chmod 600 bundle.conf
nano bundle.conf            # remplir TOUTES les valeurs A_COMPLETER
bash install.sh --step 00   # corriger jusqu'à "Préflight OK"
bash install.sh             # menu, ou : bash install.sh --all
```

## Grafana sur une autre machine
Dans `bundle.conf`, deux variables pilotent l'emplacement de Grafana :

```
GRAFANA_ENABLE="true"
GRAFANA_MODE="remote"                 # local (défaut) = sur ce serveur ; remote = autre machine
GRAFANA_REMOTE_IPS="10.10.10.60/32"   # IP/CIDR de la machine Grafana (obligatoire en remote)
```

| | `local` | `remote` |
|---|---|---|
| Grafana installé par le bundle | oui (sur le serveur Wazuh) | non (déjà présent sur l'autre machine) |
| Pare-feu (étape 02) | 3000 ouvert aux `ADMIN_CIDRS` | 3000 fermé ; **9200 ouvert uniquement à `GRAFANA_REMOTE_IPS`** |
| Étape 06 | installe Grafana, crée `grafana_ro`, provisionne datasource + dashboard | crée `grafana_ro` et **génère un kit** `/root/.wazuh-bundle/wazuh-grafana-kit.tar.gz` |

Mode `remote`, après l'étape 06 :
```bash
scp /root/.wazuh-bundle/wazuh-grafana-kit.tar.gz utilisateur@machine-grafana:/tmp/
# puis, en root sur la machine Grafana (Grafana déjà installé) :
cd /tmp && tar -xzf wazuh-grafana-kit.tar.gz && bash wazuh-grafana-kit/install.sh
```
Le kit contient un mot de passe (lecture seule sur `wazuh-alerts-*`) : le transférer par un canal sûr et le supprimer
ensuite. Le script installe le plugin OpenSearch, déclare le datasource (certificat vérifié) et les dashboards, puis
teste la connexion à l'indexer. Il ne marque pas le datasource comme « par défaut » pour ne pas perturber un Grafana existant.

Points d'attention : l'indexer doit écouter sur `MANAGER_IP` (ou `0.0.0.0`) — vérifié par l'étape 06 ; l'adresse
`MANAGER_IP` doit figurer dans le certificat de l'indexer ; Grafana est un composant séparé à sauvegarder et durcir de son côté.

## Configuration centralisée par groupes
Un agent appartient à plusieurs groupes ; la configuration est poussée par le manager.
`seg-dmz|servers|employees` + `os-linux|windows` + `role-web|db|admin` + `feat-yara` + `opt-whodata`.
Modifier `configs/groups/<groupe>/agent.conf` puis relancer l'étape 03.

## Format de bundle.conf
Chaque commentaire est sur sa propre ligne, **au-dessus** de la variable concernée (jamais de `#` en fin de ligne).

## Fichiers sensibles (jamais dans Git)
`bundle.conf` (contient des adresses internes) et `/root/.wazuh-bundle/` (mots de passe, kit Grafana distant).

## Tests (sans Wazuh, sans root)
```bash
sudo apt-get install -y yara jq shellcheck libxml2-utils
bash tests/run_tests.sh
```
Vérifie : syntaxe et shellcheck, XML/JSON, règles YARA (EICAR, webshell), script Active Response,
mise à jour des hashes/règles (simulation), daemon SMS. Exécutés aussi par GitHub Actions à chaque push.
Les tests ne remplacent pas la recette sur un vrai serveur (`RECETTE.md`).

## Publication : bonnes pratiques
- `bundle.conf` et les secrets sont exclus par `.gitignore` : ne jamais les forcer (`git add -f`).
- Dépôt **privé** recommandé si la configuration décrit votre architecture réelle.
- Versionner par tags (`v2.0.1`...) et déployer uniquement des tags testés.
- Choisir une licence (fichier `LICENSE`) avant de rendre le dépôt public.
