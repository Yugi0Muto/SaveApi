# Plan de recette (à dérouler après installation)

Pour chaque ligne, notez OK, KO ou un commentaire. La commande `bash install.sh --step 99` vérifie
automatiquement l'essentiel côté serveur. Ce plan couvre en plus ce qui ne se teste que depuis le réseau ou les agents.

| # | Test | Commande / action | Résultat attendu |
|---|---|---|---|
| 1 | Préflight | `bash install.sh --step 00` | « Préflight OK » |
| 1b | Serveur vierge | `bash install.sh --step 00b` | « Serveur prêt pour une installation neuve » |
| 2 | Recette serveur | `bash install.sh --step 99` | 0 échec |
| 3 | SSH (si étape 01 appliquée) | Nouvelle session SSH avec le compte admin + `sudo -v` | Connexion et sudo OK |
| 4 | Flux admin | Ouvrir `https://IP` depuis un poste ADMIN | Page de connexion |
| 5 | Flux non-admin | Même URL depuis un poste employé (selon le pare-feu de l'entreprise) | Refusé / timeout |
| 6 | Agent Linux DMZ | `bash agents/install_agent_linux.sh` (segment dmz, rôle web, YARA oui) | « Agent … connecté » |
| 7 | Agent Linux serveurs | idem, segment servers, rôle db | Connecté |
| 8 | Agent Windows employé | `install_agent_windows.ps1 -ManagerIP … -Segment employees …` | Connecté |
| 9 | Groupes | `/var/ossec/bin/agent_groups -s -i <ID>` | Groupes attendus |
| 10 | FIM | Sur un agent Linux : `echo test >> /etc/sudoers.d/test-recette` puis le supprimer | Alerte 100552 |
| 11 | YARA | Sur l'agent DMZ : `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt` | Alerte 100511 niveau 12 |
| 12 | Hash malveillant | Ajouter `<sha256 d'un fichier test>:` dans `/var/ossec/etc/lists/malware-sha256`, `systemctl restart wazuh-manager`, copier le fichier dans un répertoire surveillé | Alerte 100500 niveau 14 |
| 13 | Clé SSH | Sur un agent : ajouter une ligne dans `/root/.ssh/authorized_keys` | Alerte 100551 |
| 14 | Connexion root | `ssh root@agent` (si autorisé) | Alerte 100560 (100561 hors heures) |
| 15 | Defender | Fichier EICAR sur un poste Windows | Alerte 100540 |
| 16 | Journal effacé | Poste Windows de test, en admin : `wevtutil cl Application` | Alerte 100520 |
| 17 | Force brute + réponse active | 6 échecs SSH vers un agent depuis une IP NON whitelistée | Alerte 5763, IP bloquée 10 min sur l'agent (`iptables -L -n` ou `nft list ruleset`) |
| 18 | Liste blanche | Même test depuis une IP whitelistée | AUCUN blocage |
| 19 | E-mail | Déclencher le test 11 (niveau 12 ≥ seuil e-mail) | E-mail reçu ; `journalctl -t postfix/smtp` : `status=sent` |
| 20 | SMS | Alerte ≥ niveau SMS | SMS reçu (hors sandbox) ; une 2e alerte identique est ignorée |
| 21 | Grafana local | `http://IP:3000` depuis un poste ADMIN | Dashboard « Wazuh — Vue SOC » avec données |
| 21b | Grafana distant | Kit installé sur la machine Grafana | « Indexer joignable » puis dashboard avec données |
| 22 | Rétention | Dashboard > Index Management > Policies ; `cat /etc/wazuh-bundle/RETENTION.txt` | Politiques `wazuh-bundle-*` aux durées choisies |
| 23 | Purge locale | `/usr/local/sbin/wazuh-bundle-purge-logs --dry-run` | Liste cohérente, rien de supprimé |
| 24 | Sauvegarde | `ls -l /var/backups/wazuh` | Archive du jour |
| 25 | Redémarrage | `reboot` puis `bash install.sh --step 99` | 0 échec |
| 26 | Relance | Relancer `bash install.sh --step 03` puis `--step 06` | Aucun doublon dans `ossec.conf` (blocs « inchangé ») |
