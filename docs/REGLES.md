# Règles de détection du wazuh-bundle

Wazuh fournit environ 4 000 règles (authentification, web, systèmes, conformité…). Le bundle **ajoute**
des règles ciblées pour les situations importantes d'une PME à trois segments (serveurs, employés, DMZ),
et **relève le niveau** de certaines situations pour qu'elles déclenchent les alertes e-mail et SMS.

## Comment une alerte est produite

```
agent ──événement──▶ décodeur (extrait les champs) ──▶ règles (la plus précise gagne) ──▶ alerte de niveau N
```

- **Décodeur** : lit l'événement brut et en extrait des champs : utilisateur, IP source, fichier, EventID Windows…
- **Règle** : condition sur ces champs. `<if_sid>X</if_sid>` signifie « seulement si la règle Wazuh X vient de
  correspondre ». Le bundle *spécialise* donc des règles existantes au lieu de tout réécrire.
- **Niveau** (0 à 15) : gravité. Les repères du bundle sont les suivants.

| Niveau | Signification | Notification par défaut |
|---|---|---|
| 3 | information (déclencheur technique) | aucune |
| 7–8 | à examiner (changement inhabituel) | dashboard |
| 10 | suspect | e-mail (seuil par défaut de l'étape 07) |
| 12 | incident probable | e-mail + SMS (seuil par défaut de l'étape 08) |
| 14 | incident (malware connu) | e-mail + SMS |

Pour changer un niveau, éditez `configs/manager/bundle_rules.xml` puis relancez l'étape 04. L'étape
valide la règle avec Wazuh avant de l'activer et revient en arrière en cas d'erreur.

## Règles « malware » (étape 06), identifiants 100500 à 100519

| ID | Niv. | Déclencheur | But / explication |
|---|---|---|---|
| 100500 | 14 | Fichier ajouté/modifié (Wazuh 550/554) dont l'empreinte SHA256 figure dans `etc/lists/malware-sha256` | Malware **connu** (liste abuse.ch MalwareBazaar mise à jour chaque nuit). Ne détecte que les copies exactes. |
| 100501 | 3 | Fichier **ajouté** (554) dans un répertoire analysé par YARA | Déclencheur technique : lance la réponse active `yara_linux` sur l'agent. |
| 100502 | 3 | Fichier **modifié** (550) dans un répertoire analysé par YARA | Idem. |
| 100510 | 0 | Toute ligne `wazuh-yara:` (décodeur `yara_bundle`) | Regroupement technique, pas d'alerte. |
| 100511 | 12 | Ligne `wazuh-yara: INFO - Scan result: <règle> <fichier>` | **Malware détecté par YARA** : le fichier correspond à une règle YARA (webshell, reverse shell, mineur, EICAR…). |
| 100512 | 7 | Ligne `wazuh-yara: ERROR - …` | Le scanner n'a pas pu fonctionner sur l'agent : yara absent, règles absentes, délai dépassé. **À corriger, sinon l'agent n'est plus protégé.** |

Test : écrivez le fichier EICAR (inoffensif) sur un agent du groupe `feat-yara`, voir `RECETTE.md` n°11.

## Linux : fichiers sensibles (module FIM, groupe `os-linux`), identifiants 100551 à 100556

Parents : Wazuh **550** (somme de contrôle modifiée) et **554** (fichier ajouté). Les fichiers sont surveillés
en temps réel par le groupe `os-linux`.

| ID | Niv. | Fichier(s) | Pourquoi c'est important | MITRE |
|---|---|---|---|---|
| 100551 | 10 | `~/.ssh/authorized_keys` (root et utilisateurs) | Ajouter une clé SSH donne un accès permanent sans mot de passe : technique de persistance classique. | T1098.004 |
| 100552 | 10 | `/etc/sudoers`, `/etc/sudoers.d/*` | Modification des droits d'administration. | T1548.003 |
| 100553 | 8 | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/` | Une tâche planifiée relance un programme malveillant même après nettoyage. | T1053.003 |
| 100554 | 8 | Nouveau `/etc/systemd/system/*.service` ou `*.timer` | Un nouveau service est un autre moyen de persistance. | T1543.002 |
| 100555 | 10 | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Création de compte, changement de mot de passe ou ajout à un groupe (sudo…). Le contenu de `shadow` n'est **jamais** copié dans l'alerte (`nodiff`). | T1136.001 |
| 100556 | 12 | `/etc/ld.so.preload` | Ce fichier est presque toujours vide ; le modifier permet de cacher des processus (rootkit). | T1574.006 |

Une modification légitime (installation de paquet, ajout d'un administrateur) déclenche aussi ces règles.
C'est voulu : chaque changement de ce type doit pouvoir être rapproché d'une action connue.

## Linux : connexions SSH, identifiants 100560 et 100561

| ID | Niv. | Déclencheur | Explication |
|---|---|---|---|
| 100560 | 8 | Wazuh 5715 (connexion SSH réussie) avec l'utilisateur `root` | La connexion directe de root empêche de savoir **qui** agit. Si l'étape 01 a interdit root (`PermitRootLogin no`), cette alerte ne devrait jamais apparaître sur le serveur Wazuh. |
| 100561 | 10 | 100560 entre 19:00 et 07:00 (heure du **serveur Wazuh**) | Connexion root hors heures ouvrables : fréquent lors d'une intrusion. |

Testée automatiquement par `wazuh-logtest` (fichier `configs/manager/rule_tests.txt`) aux étapes 04 et 99.

## Windows : journaux d'événements (groupe `os-windows`), identifiants 100520 à 100541

`<if_group>windows</if_group>` : la règle est évaluée après toute règle Windows de Wazuh, puis filtrée sur
l'**EventID**. Les événements sont collectés par le groupe `os-windows` (requête sur le journal Sécurité +
journaux Système et Defender complets).

| ID | Niv. | EventID | Explication | MITRE |
|---|---|---|---|---|
| 100520 | 12 | 1102 (Sécurité) / 104 (Système) | **Journal effacé** : un attaquant efface ses traces. Rarement légitime. | T1070.001 |
| 100521 | 12 | 4728 / 4732 / 4756 vers Administrateurs, Admins du domaine… | Compte ajouté à un **groupe privilégié** (noms anglais et français reconnus). | T1098 |
| 100522 | 8 | 7045 | **Nouveau service installé** (persistance, outils d'administration à distance). | T1543.003 |
| 100523 | 8 | 4698 | **Tâche planifiée créée**. Nécessite l'audit « Autres événements d'accès aux objets » (GPO). | T1053.005 |
| 100524 | 10 | 4719 | **Politique d'audit modifiée** : la journalisation peut avoir été réduite pour passer inaperçu. | T1562.002 |
| 100540 | 12 | Defender 1116 / 1117 | Windows Defender a **détecté ou traité une menace**. | T1204 |
| 100541 | 12 | Defender 5001 / 5010 / 5012 | **Protection Defender désactivée** (temps réel, antispyware, antivirus). | T1562.001 |

Ces règles se testent sur un poste Windows (voir `RECETTE.md`). Exemple sans risque pour 100520 : la commande
`wevtutil cl Application`, lancée en administrateur sur un poste de test, efface le journal Application.
Windows inscrit alors l'événement 104 dans le journal Système, ce qui déclenche l'alerte 100520.

## Règles Wazuh natives utilisées par le bundle

| ID Wazuh | Rôle dans le bundle |
|---|---|
| 5712 | Force brute SSH sur des comptes inexistants : déclenche la **réponse active** (blocage, étape 03). |
| 5763 | Force brute SSH, échecs répétés : déclenche la **réponse active** (blocage, étape 03). |
| 550 / 554 | Fichier modifié / ajouté (FIM) : parents des règles 100500 à 100502 et 100551 à 100556. |
| 5715 | Connexion SSH réussie : parent des règles 100560 et 100561. |

Wazuh fournit aussi nativement, entre autres : échecs de connexion multiples, puis succès (corrélation par IP),
création de compte Linux, sudo, vulnérabilités (inventaire des paquets) et configuration CIS (SCA).

## Ajouter une règle

1. Éditez `configs/manager/bundle_rules.xml` avec un identifiant libre entre 100525 et 100599, une `<description>`
   et un `<mitre>` si possible.
2. Si la règle se déclenche sur une ligne de journal, ajoutez un cas dans `configs/manager/rule_tests.txt`
   (format `id|ligne`).
3. Documentez-la ici. `tests/run_tests.sh` vérifie que chaque règle est documentée.
4. Lancez `bash install.sh --step 04`. L'étape valide la règle, revient en arrière en cas d'erreur, puis teste la règle.
