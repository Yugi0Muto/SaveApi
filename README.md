# wazuh-bundle v3 : déploiement Wazuh en production

Assistant d'installation et de configuration d'un SIEM Wazuh tout-en-un (manager, indexer et dashboard sur un
même serveur), pour une entreprise organisée en trois segments : **SERVEURS**, **EMPLOYÉS** et **DMZ**.

Principes de cette version :

- **Aucun fichier de configuration à éditer.** Chaque étape pose ses questions, propose une valeur par défaut,
  valide la réponse et explique chaque choix.
- **Chaque commande est visible.** Pour chaque commande, l'assistant affiche ce qu'elle fait, la commande
  elle-même, sa sortie et son code retour. En cas d'échec, il affiche un diagnostic et une piste de solution,
  puis **s'arrête**. Il ne continue jamais en silence.
- **Chaque étape se vérifie et se rejoue.** Une modification de Wazuh est validée par Wazuh lui-même
  (`wazuh-analysisd -t`…) avant tout redémarrage. Si elle est refusée, le retour en arrière est automatique.
- **Aucun pare-feu n'est configuré.** L'entreprise administre le sien. Le bundle fournit le tableau des flux
  réseau à autoriser.

## Démarrage

Sur un serveur Debian 12/13 ou Ubuntu 22.04/24.04 neuf, avec une **IP fixe** :

```bash
sudo -i
apt-get update && apt-get install -y git
```

```bash
git clone https://github.com/VOTRE_COMPTE/wazuh-bundle.git /opt/wazuh-bundle
```

```bash
cd /opt/wazuh-bundle && bash install.sh
```

Le menu propose chaque étape, `a` pour tout enchaîner, `e` pour l'explication d'une étape, `f` pour les flux
réseau. Autres modes :

```bash
bash install.sh --step 07                    # une seule étape
bash install.sh --explain 06                 # ce que fait l'étape, sans rien exécuter
bash install.sh --flows                      # flux réseau à transmettre à l'équipe pare-feu
bash install.sh --non-interactive --step 05  # rejouer avec les réponses déjà données
```

Ne faites pas `curl … | sudo bash` : ces scripts s'exécutent en root, relisez le code avant de les lancer.
En production, déployez toujours un **tag** testé (`git checkout v3.0.0`).

## Guide d'installation et de passation (PDF)

[`docs/Guide_installation_passation_wazuh-bundle.pdf`](docs/Guide_installation_passation_wazuh-bundle.pdf) contient :

- l'architecture ;
- l'installation pas à pas ;
- l'exploitation : routines, emplacements, opérations courantes, dépannage ;
- les règles et la rétention ;
- une fiche de passation à signer.

Pour le régénérer après une modification :

```bash
python3 docs/guide/build_pdf.py
```

## Manuel d'exploitation (à remettre au client)

[`docs/Manuel_exploitation_SIEM_Wazuh.pdf`](docs/Manuel_exploitation_SIEM_Wazuh.pdf) est centré sur les gestes
de l'exploitant. Il contient un exercice pratique par chapitre et une page de repères à cocher. Il couvre :

- le coup d'œil quotidien ;
- l'analyse d'une alerte ;
- l'ajout de machines ;
- la configuration de la surveillance ;
- l'écriture de règles et de décodeurs ;
- les réglages ;
- l'entretien et le dépannage.

Pour le régénérer :

```bash
python3 docs/manuel/build_manuel.py
```

## Tableaux de bord Grafana

| Tableau de bord | Fichier | Usage |
|---|---|---|
| **Wazuh — Poste de commande** | `configs/grafana/dashboards/wazuh-overview.json` | Vue d'ensemble (détaillée ci-dessous) |
| Wazuh — Vue SOC | `configs/grafana/dashboards/wazuh-soc.json` | Vue détaillée historique |

Le poste de commande se lit de haut en bas :

- six indicateurs : incidents probables, suspects, malware, IP bloquées, total, machines actives ;
- la tendance par gravité ;
- les machines, règles et IP les plus fréquentes ;
- la table « À traiter » ;
- deux rangées repliées : malware et fichiers, connexions et blocages.

Un filtre « Machine » s'applique à toute la page. Les deux tableaux de bord sont provisionnés par l'étape 09.
Le poste de commande est généré par `grafana/build_dashboard.py` : modifiez ce script, puis régénérez le JSON :

```bash
python3 grafana/build_dashboard.py
```

## Les étapes

| Étape | Rôle | Questions principales |
|---|---|---|
| 00 Préflight | Contrôles (OS, ressources, ports, Internet, NTP). Ne modifie rien. | IP du serveur, postes d'administration |
| 00b Nettoyage | Repère et nettoie les restes d'une installation précédente : paquets dans n'importe quel état, dossiers, services orphelins, dépôt, comptes, ports, traces du bundle, pare-feu v2. Les mots de passe anciens sont archivés ; un logiciel tiers n'est jamais supprimé d'office. | confirmation par catégorie |
| 01 SSH | Durcissement **optionnel**, mesure par mesure (7 mesures expliquées, risques, retour arrière) | oui/non par mesure |
| 02 Wazuh | Installation officielle (`wazuh-install.sh`), branche 4.14 | adresse d'écoute de l'indexer |
| 03 Manager | Enrôlement par mot de passe, liste blanche, réponse active, groupes d'agents | IP jamais bloquées, durée de blocage |
| 04 Règles | Déploiement + **auto-test** des règles du bundle (`docs/REGLES.md`) | |
| 05 Rétention | Politique ISM de l'indexer + purge des fichiers locaux | durées de conservation |
| 06 YARA | YARA **4.5.8** (vérifié), liste de hashes abuse.ch, mises à jour, test EICAR (`docs/YARA.md`) | répertoires, sources |
| 07 E-mail | **Gmail**, **SMTP entreprise** ou **relais**, tests de bout en bout | mode, serveur, destinataires, niveau |
| 08 SMS | Africa's Talking, dédoublonnage + plafond | numéros, niveau |
| 09 Grafana | Local ou distant, utilisateur lecture seule | emplacement |
| 10 Sauvegarde | Archive quotidienne de la configuration | dossier, durée |
| 99 Recette | Vérification complète, lecture seule | |

Les agents s'installent avec `agents/install_agent_linux.sh` (questions interactives) et
`agents/install_agent_windows.ps1`.

## Où sont les réglages ?

| Fichier | Contenu | Droits |
|---|---|---|
| `/etc/wazuh-bundle/answers.env` | Réponses aux questions. Généré par l'assistant, **ne pas éditer** : relancer l'étape. Sert aussi de valeur par défaut à la relance et aux tâches planifiées. | root, 600 |
| `/root/.wazuh-bundle/secrets.env` | Mots de passe et clés API (indexer, enrôlement, SMTP, abuse.ch, SMS, Grafana) | root, 600 |
| `/root/.wazuh-bundle/wazuh-passwords.txt` | Mots de passe générés par Wazuh | root, 600 |
| `/etc/wazuh-bundle/RETENTION.txt` | Politique de rétention appliquée | lisible |
| `/var/log/wazuh-bundle/` | Journal complet de chaque exécution de `install.sh` et des tâches quotidiennes | root |

Tout ce que le bundle ajoute à `ossec.conf` est encadré par `<!-- wazuh-bundle:BEGIN nom -->` et
`<!-- wazuh-bundle:END nom -->`. Une relance remplace ce bloc sans jamais le dupliquer.

## Pare-feu : flux réseau à autoriser

Le bundle **ne configure aucun pare-feu**. Transmettez ce tableau à l'équipe réseau.
`bash install.sh --flows` l'affiche avec vos adresses.

| Source | Destination | Port | Rôle |
|---|---|---|---|
| Agents (3 segments) | serveur Wazuh | TCP 1514 | événements des agents |
| Agents (3 segments) | serveur Wazuh | TCP 1515 | enrôlement des agents |
| Postes d'administration | serveur Wazuh | TCP 443 | Wazuh Dashboard |
| Postes d'administration | serveur Wazuh | TCP 22 | SSH |
| Postes d'administration | serveur Wazuh | TCP 3000 | Grafana local (étape 09) |
| Machine Grafana distante | serveur Wazuh | TCP 9200 | indexer, **uniquement** cette machine |
| Serveur Wazuh | Internet | TCP 443 | paquets, GitHub (YARA), abuse.ch, API SMS |
| Serveur Wazuh | serveur SMTP | TCP 587 / 465 / 25 | alertes e-mail |

**À ne pas ouvrir** depuis les segments employés et DMZ : 9200 (indexer) et 55000 (API Wazuh).

La **réponse active** de l'étape 03 n'est pas un pare-feu d'entreprise. Elle bloque temporairement une IP
attaquante dans le pare-feu **local de l'agent attaqué** (iptables/nftables), puis la débloque. Elle reste
optionnelle et ne bloque jamais les adresses de la liste blanche.

## Groupes d'agents (configuration centralisée)

Un agent appartient à plusieurs groupes, et le manager lui envoie la configuration de chacun.
`seg-dmz|servers|employees` + `os-linux|windows` + `role-web|db|admin` + `feat-yara` + `opt-whodata`.
Pour modifier la surveillance, éditez `configs/groups/<groupe>/agent.conf` puis relancez l'étape 03.
Le groupe `feat-yara` est généré par l'étape 06.

## Mise à jour depuis la v2

La v2 utilisait `bundle.conf` et un pare-feu nftables. Elle ajoutait aussi à `ossec.conf` des blocs sans
marqueurs, ce qui pouvait **dupliquer la commande `yara_linux`** à la relance et rendre la configuration
invalide. La v3 nettoie ces reliquats automatiquement :

- l'étape 03 retire les anciens blocs de `ossec.conf` (commande `migrate-v2`) ;
- l'étape 04 retire les anciens fichiers `bundle_rules.xml` et `bundle_decoders.xml` ;
- l'étape 05 remplace l'ancienne politique `wazuh-retention`.

L'ancien pare-feu n'est **pas** supprimé automatiquement. Si vous voulez le retirer :

```bash
nft delete table inet wazuh_bundle
```

```bash
systemctl disable nftables
```

Pensez aussi à nettoyer `/etc/nftables.conf`.

Autres corrections de la v3 sur le manager :

- les scripts utilisent l'adresse réelle de l'indexer (`127.0.0.1` par défaut), au lieu d'appeler
  `https://IP:9200` alors qu'il n'écoute que sur 127.0.0.1 ;
- la règle de hash lit le bon champ (`sha256`) ;
- les erreurs de création de groupes ne sont plus masquées ;
- un changement de durée de rétention est réellement appliqué (mise à jour de la politique ISM existante) ;
- les fichiers d'alertes locaux, jamais purgés auparavant, sont désormais purgés.

## Tests (sans Wazuh)

```bash
sudo apt-get install -y yara jq shellcheck libxml2-utils
```

```bash
bash tests/run_tests.sh
```

La suite vérifie : syntaxe et shellcheck, absence d'erreurs masquées, XML/JSON, unicité et documentation des
règles, `ossec_conf.py` (ajout, remplacement, idempotence, migration v2, refus d'un XML invalide), exécution
explicite (`run`), questions et validations, paramètres Postfix des 3 modes, règles YARA, script de réponse
active, mises à jour (simulation), purge, Grafana et daemon SMS. GitHub Actions la lance à chaque push.
Ces tests ne remplacent pas la recette sur un vrai serveur (`RECETTE.md`).

## Publication : bonnes pratiques

- `answers.env`, `secrets.env` et les sauvegardes ne doivent jamais être versionnés (`.gitignore`).
- Préférez un dépôt **privé** si la documentation décrit votre architecture réelle.
- Versionnez par tags et ne déployez que des tags testés.
