# Installation manuelle du SIEM Wazuh (sans les scripts)

Ce guide reproduit, commande par commande, ce que fait l'assistant `install.sh`. Il sert quand on veut
tout maîtriser, ou quand un script bloque. Chaque partie se termine par une **vérification** : ne passez à la
suivante que si elle est bonne.

- **Prérequis** : Debian 12/13 ou Ubuntu 22.04/24.04 neuf, **8 Go de RAM et 4 CPU** (4 Go et 2 CPU au strict
  minimum), IP fixe, accès HTTPS sortant, et la session en **root** (`sudo -i`).
- **Fichiers de configuration** (règles, groupes, YARA) : on les prend dans le dossier du bundle,
  `/opt/wazuh-bundle`, que l'on clone une seule fois. Aucun script n'est lancé.

```bash
apt-get update && apt-get install -y git curl jq python3 ca-certificates
git clone https://github.com/Yugi0Muto/wazuh.git /opt/wazuh-bundle
```

**À adapter puis coller une fois au début de chaque session SSH.** Toutes les commandes du guide
utilisent ces variables.

```bash
export IP=10.10.10.20                         # IP fixe de CE serveur Wazuh
export ADMIN_IPS="10.10.10.50 10.10.10.51"   # postes d'administration (jamais bloqués)
export B=/opt/wazuh-bundle                    # dossier du bundle
```

**Une fois Wazuh installé (partie 2)**, coller aussi ce bloc au début de chaque session SSH. Il donne le
mot de passe admin de l'indexer et la petite fonction `idx` qu'utilisent les parties 5, 9 et 13 :

```bash
export ADMIN_PW="$(grep -A1 "indexer_username: 'admin'" /root/.wazuh-bundle/wazuh-passwords.txt | grep indexer_password | sed "s/.*'\(.*\)'.*/\1/")"
idx() { curl -s -u "admin:$ADMIN_PW" --cacert /etc/wazuh-indexer/certs/root-ca.pem -H 'Content-Type: application/json' "$@"; echo; }
```

Ordre des parties : 0 → 1 → 2 → 3 sont nécessaires ; les suivantes peuvent se faire dans l'ordre que vous
voulez.

| Partie | Contenu | Obligatoire |
|---|---|---|
| 0 | Vérifications préalables | oui |
| 1 | Serveur propre (restes d'une installation précédente) | oui si Wazuh a déjà été tenté |
| 2 | Installation de Wazuh (tout-en-un) | oui |
| 3 | Configuration du manager (enrôlement, liste blanche, blocage, groupes) | oui |
| 4 | Règles de détection | recommandé |
| 5 | Rétention des alertes | recommandé |
| 6 | Détection de malwares (YARA + hashes) | recommandé |
| 7 | Alertes e-mail | selon besoin |
| 8 | Alertes SMS | selon besoin |
| 9 | Grafana | selon besoin |
| 10 | Sauvegarde quotidienne | recommandé |
| 11 | Durcissement SSH | optionnel |
| 12 | Agents (machines surveillées) | oui |
| 13 | Recette | oui |

> **Règle d'or pour `ossec.conf`** : avant toute modification, faites une copie ; après, faites valider par Wazuh
> **avant** de redémarrer. Si la validation échoue, remettez la copie.
>
> ```bash
> cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.$(date +%F-%H%M)
> /var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK"
> systemctl restart wazuh-manager && systemctl is-active wazuh-manager
> ```

---

## 0. Vérifications préalables

```bash
. /etc/os-release; echo "$PRETTY_NAME"           # Debian 12/13 ou Ubuntu 22.04/24.04
free -h; nproc; df -h /var                       # 8 Go / 4 CPU / 100 Go recommandés
ip -4 addr | grep "inet $IP/"                    # l'IP doit être sur ce serveur (et fixe)
timedatectl show -p NTPSynchronized --value      # doit afficher yes
ss -tlnp | grep -E ':(443|1514|1515|9200|55000)\b'   # doit n'afficher RIEN
curl -sI https://packages.wazuh.com | head -1    # doit répondre (HTTP/…)
```

Si l'horloge n'est pas synchronisée : `apt-get install -y systemd-timesyncd && timedatectl set-ntp true`.

---

## 1. Serveur propre (si Wazuh a déjà été installé ou tenté)

L'installateur officiel **échoue s'il reste des éléments d'une tentative précédente** (« wazuh-keystore :
Aucun fichier », « wazuh-manager could not be started », etc.) puis annule tout. On repart donc de zéro.

**Vérifier :**

```bash
dpkg -l | grep -E 'wazuh|filebeat'                       # paquets, y compris « rc » (config restante)
ls -d /var/ossec /etc/filebeat /etc/wazuh-* /var/lib/wazuh-* /usr/share/wazuh-* 2>/dev/null
ss -tlnp | grep -E ':(443|1514|1515|9200|55000)\b'
```

**Nettoyer.** Cela supprime toutes les données et la configuration Wazuh de CE serveur.

```bash
systemctl disable --now wazuh-dashboard filebeat wazuh-manager wazuh-indexer 2>/dev/null
apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard filebeat wazuh-agent 2>/dev/null
apt-get purge -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat wazuh-agent
rm -rf /var/ossec /etc/filebeat /var/lib/filebeat /usr/share/filebeat /var/log/filebeat \
       /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer /var/log/wazuh-indexer \
       /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard /var/log/wazuh-dashboard \
       /etc/apt/sources.list.d/wazuh.list /usr/share/keyrings/wazuh.gpg
rm -f /lib/systemd/system/wazuh-indexer-performance-analyzer.service \
      /usr/lib/systemd/system/wazuh-indexer-performance-analyzer.service
systemctl daemon-reload
pkill -f /usr/share/wazuh-indexer; pkill -f /usr/share/filebeat; pkill -f /var/ossec   # processus orphelins
userdel wazuh 2>/dev/null; userdel wazuh-indexer 2>/dev/null; userdel wazuh-dashboard 2>/dev/null
dpkg --configure -a && apt-get update
```

Si une ancienne version du bundle avait posé un pare-feu (`nft list table inet wazuh_bundle` répond), le
retirer : `nft delete table inet wazuh_bundle`, puis remettre un `/etc/nftables.conf` neutre ou celui de
l'entreprise.

**Vérification** : les trois commandes de vérification ci-dessus n'affichent plus rien (hors lignes `un`).

---

## 2. Installation de Wazuh (tout-en-un)

**Si le serveur a moins de 8 Go ou moins de 4 CPU**, allonger d'abord le délai de démarrage des services.
Sinon, systemd abandonne le manager au bout de 90 s (« start operation timed out ») et l'installateur annule tout.

```bash
for u in wazuh-manager wazuh-indexer wazuh-dashboard; do
  mkdir -p /etc/systemd/system/$u.service.d
  printf '[Service]\nTimeoutStartSec=900\n' > /etc/systemd/system/$u.service.d/timeout.conf
done
systemctl daemon-reload
```

**Installer** (15 à 45 minutes) :

```bash
mkdir -p /root/wazuh-install && cd /root/wazuh-install
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh
bash wazuh-install.sh -a
```

À la fin, l'installateur affiche l'utilisateur `admin` et son mot de passe. **Ranger les mots de passe** :

```bash
mkdir -p /root/.wazuh-bundle && chmod 700 /root/.wazuh-bundle
install -m 600 wazuh-install-files.tar /root/.wazuh-bundle/
tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > /root/.wazuh-bundle/wazuh-passwords.txt
chmod 600 /root/.wazuh-bundle/wazuh-passwords.txt
export ADMIN_PW="$(grep -A1 "indexer_username: 'admin'" /root/.wazuh-bundle/wazuh-passwords.txt | grep indexer_password | sed "s/.*'\(.*\)'.*/\1/")"
```

**Vérification :**

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat     # 4 × active
curl -s -u "admin:$ADMIN_PW" --cacert /etc/wazuh-indexer/certs/root-ca.pem https://127.0.0.1:9200/ | jq .version.number
dpkg-query -W wazuh-manager                                                  # version (à noter pour les agents)
```

Dashboard : `https://IP-du-serveur` (utilisateur `admin`). Copiez `wazuh-passwords.txt` dans le coffre de
mots de passe de l'entreprise.

En cas d'échec, la cause est presque toujours dans :
`journalctl -u wazuh-manager -n 50 --no-pager` et `grep -nE "ERROR|could not" /var/log/wazuh-install.log | tail`.
Avant de relancer, refaire la partie 1.

**Erreur « Your system does not meet the recommended minimum hardware requirements »** : moins de
2 cœurs ou de 3 700 Mo de RAM. Sans changer le matériel : créer un fichier d'échange puis relancer avec
`-i` (ignore le contrôle ; l'indexer risque d'être lent) :

```bash
fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
bash wazuh-install.sh -a -i
```

**Erreur « The IP x.x.x.x is public »** (mode pas à pas avec `config.yml`) : l'assistant refuse une IP
publique dans les certificats. Au choix : indexer sur 127.0.0.1 (`-a`), ou un nom DNS à la place de l'IP
dans `config.yml` (ex. `wazuh.lan`, déclaré dans `/etc/hosts` du serveur et de Grafana) — le contrôle ne
porte que sur les adresses IP. L'étape 02 propose aussi une copie de l'assistant qui accepte l'IP
publique (filtrer alors le port 9200 au pare-feu).

**Erreur « The Wazuh API user wazuh does not exist » / « … wazuh-wui does not exist »**
([wazuh/wazuh#24587](https://github.com/wazuh/wazuh/issues/24587)). L'assistant change les mots de passe
de l'API avant que celle-ci ne soit prête. L'étape 02 du bundle propose alors des solutions au choix ;
à la main :

- *L'installation s'est terminée (code 0) mais le dashboard indique « API down »* : poser les mots de
  passe de l'API depuis `wazuh-passwords.txt` (utilisateurs `wazuh-wui` puis `wazuh`, via
  `PUT https://localhost:55000/security/users/<id>` authentifié en `wazuh:wazuh`), recopier celui de
  `wazuh-wui` dans `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` (`password:`), puis
  `systemctl restart wazuh-dashboard`.
- *L'installation a échoué* : dans une copie de `wazuh-install.sh`, ajouter au début de la fonction
  `installCommon_changePasswords` une boucle qui attend que
  `curl -sk -u wazuh:wazuh -X POST "https://localhost:55000/security/user/authenticate?raw=true"`
  renvoie un jeton (`eyJ…`), puis relancer `bash wazuh-install.sh -a -o`. Relancer simplement avec `-o`
  suffit parfois (erreur intermittente).

---

## 3. Configuration du manager

### 3.1 Enrôlement protégé par mot de passe

Sans ce mot de passe, n'importe quelle machine du réseau peut s'inscrire comme agent.

```bash
export ENROL_PW="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"; echo "Mot de passe d'enrôlement : $ENROL_PW"
printf '%s' "$ENROL_PW" > /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass
printf 'AUTHD_PASSWORD=%q\n' "$ENROL_PW" >> /root/.wazuh-bundle/secrets.env && chmod 600 /root/.wazuh-bundle/secrets.env
```

Dans `/var/ossec/etc/ossec.conf`, section `<auth>`, passer `<use_password>no</use_password>` à `yes` :

```bash
cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.$(date +%F-%H%M)
sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' /var/ossec/etc/ossec.conf
grep -n use_password /var/ossec/etc/ossec.conf
```

### 3.2 Liste blanche, puis blocage automatique de la force brute SSH

Ouvrir `ossec.conf` (`nano /var/ossec/etc/ossec.conf`). Dans la **première** section `<global>`, avant
`</global>`, ajouter une ligne par adresse : le serveur lui-même, les postes d'administration, puis les
passerelles, DNS et scanners de l'entreprise.

```xml
    <white_list>10.10.10.20</white_list>
    <white_list>10.10.10.50</white_list>
    <white_list>10.10.10.1</white_list>
```

Juste avant la **dernière** ligne `</ossec_config>`, ajouter le blocage automatique. Il bloque l'IP
attaquante 10 minutes, sur la machine attaquée seulement :

```xml
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5763</rules_id>
    <timeout>600</timeout>
  </active-response>
```

```bash
/var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK" && systemctl restart wazuh-manager && systemctl is-active wazuh-manager
```

### 3.3 Groupes d'agents (configuration centralisée)

```bash
for g in $B/configs/groups/*/; do
  name=$(basename "$g")
  /var/ossec/bin/agent_groups -a -g "$name" -q
  install -o wazuh -g wazuh -m 660 "$g/agent.conf" /var/ossec/etc/shared/$name/agent.conf
done
/var/ossec/bin/verify-agent-conf
/var/ossec/bin/agent_groups -l
```

**Vérification** : `verify-agent-conf` ne signale aucune erreur, et la liste montre `seg-servers`,
`seg-employees`, `seg-dmz`, `os-linux`, `os-windows`, `role-web`, `role-db`, `role-admin` et `opt-whodata`.

---

## 4. Règles de détection

```bash
install -o wazuh -g wazuh -m 660 $B/configs/manager/bundle_rules.xml /var/ossec/etc/rules/bundle_10_rules.xml
/var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK" && systemctl restart wazuh-manager
```

**Vérification** : on rejoue une ligne de journal, et la règle 100560 doit apparaître.

```bash
echo 'Nov 16 10:00:00 srv sshd[1234]: Accepted password for root from 10.0.0.5 port 50000 ssh2' | /var/ossec/bin/wazuh-logtest | grep "id:"
```

Description de chaque règle : `docs/REGLES.md`.

---

## 5. Rétention des alertes

### 5.1 Base des alertes (indexer) : suppression après N jours

```bash
idx() { curl -s -u "admin:$ADMIN_PW" --cacert /etc/wazuh-indexer/certs/root-ca.pem -H 'Content-Type: application/json' "$@"; echo; }
policy() { # policy NOM JOURS MOTIF
  idx -X PUT "https://127.0.0.1:9200/_plugins/_ism/policies/$1" -d "{\"policy\":{\"description\":\"suppression apres $2 jours\",
   \"default_state\":\"hot\",\"states\":[
   {\"name\":\"hot\",\"actions\":[],\"transitions\":[{\"state_name\":\"delete\",\"conditions\":{\"min_index_age\":\"$2d\"}}]},
   {\"name\":\"delete\",\"actions\":[{\"delete\":{}}],\"transitions\":[]}],
   \"ism_template\":[{\"index_patterns\":[\"$3\"],\"priority\":100}]}}"
}
policy wazuh-bundle-alerts     90 'wazuh-alerts-*'
policy wazuh-bundle-archives   30 'wazuh-archives-*'
policy wazuh-bundle-monitoring 30 'wazuh-monitoring-*'
idx -X POST 'https://127.0.0.1:9200/_plugins/_ism/add/wazuh-alerts-*' -d '{"policy_id":"wazuh-bundle-alerts"}'
```

S'il n'existe encore aucun index `wazuh-archives-*`, c'est normal : la politique s'appliquera aux futurs index.

### 5.2 Fichiers d'alertes sur le disque (jamais purgés par Wazuh)

```bash
mkdir -p /etc/wazuh-bundle && chmod 750 /etc/wazuh-bundle
printf 'RET_LOCAL_DAYS=180\nRET_LOCAL_ARCHIVES_DAYS=30\n' >> /etc/wazuh-bundle/answers.env && chmod 600 /etc/wazuh-bundle/answers.env
install -m 750 $B/tools/purge_local_logs.sh /usr/local/sbin/wazuh-bundle-purge-logs
mkdir -p /var/log/wazuh-bundle
echo '15 4 * * * root /usr/local/sbin/wazuh-bundle-purge-logs >> /var/log/wazuh-bundle/purge.log 2>&1' > /etc/cron.d/wazuh-bundle-purge
/usr/local/sbin/wazuh-bundle-purge-logs --dry-run
```

**Vérification** : `idx 'https://127.0.0.1:9200/_plugins/_ism/policies'` liste les trois politiques
`wazuh-bundle-*`.

---

## 6. Détection de malwares (YARA + liste de hashes)

### 6.1 Sur le serveur

```bash
apt-get install -y yara && yara --version                  # (version de la distribution ; voir docs/YARA.md pour compiler 4.5.8)
install -D -m 644 $B/configs/yara/bundle_rules.yar /etc/wazuh-bundle/yara_base_rules.yar
yara -w /etc/wazuh-bundle/yara_base_rules.yar /dev/null && echo "RÈGLES YARA OK"

# liste de hashes (vide au départ, remplie chaque nuit)
echo "0000000000000000000000000000000000000000000000000000000000000000:placeholder" > /var/ossec/etc/lists/malware-sha256
chown wazuh:wazuh /var/ossec/etc/lists/malware-sha256 && chmod 660 /var/ossec/etc/lists/malware-sha256

# règles et décodeurs « malware » : répertoires analysés par YARA dans l'expression
sed 's#__YARA_REGEX__#^(/var/www|/tmp|/var/tmp|/dev/shm|/home)/#' $B/configs/manager/malware_rules.xml \
  > /var/ossec/etc/rules/bundle_00_malware_rules.xml
install -m 660 $B/configs/manager/malware_decoders.xml /var/ossec/etc/decoders/bundle_malware_decoders.xml
chown wazuh:wazuh /var/ossec/etc/rules/bundle_00_malware_rules.xml /var/ossec/etc/decoders/bundle_malware_decoders.xml
```

Dans `ossec.conf` :

- dans la section `<ruleset>`, ajouter `<list>etc/lists/malware-sha256</list>` à côté des autres `<list>` ;
- avant la **dernière** ligne `</ossec_config>`, ajouter :

```xml
  <command>
    <name>yara_linux</name>
    <executable>yara.sh</executable>
    <extra_args>-yara_path auto -yara_rules /var/ossec/etc/shared/yara_rules.yar -max_size_mb 100</extra_args>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>yara_linux</command>
    <location>local</location>
    <rules_id>100501,100502</rules_id>
  </active-response>
```

```bash
/var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK" && systemctl restart wazuh-manager
```

**Groupe `feat-yara`**, qui reçoit la liste des répertoires analysés et les règles YARA :

```bash
/var/ossec/bin/agent_groups -a -g feat-yara -q
cat > /var/ossec/etc/shared/feat-yara/agent.conf <<'EOF'
<agent_config os="Linux">
  <syscheck>
    <directories check_all="yes" realtime="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/tmp</directories>
    <directories check_all="yes" realtime="yes">/var/tmp</directories>
    <directories check_all="yes" realtime="yes">/dev/shm</directories>
    <directories check_all="yes">/home</directories>
  </syscheck>
</agent_config>
EOF
chown wazuh:wazuh /var/ossec/etc/shared/feat-yara/agent.conf && chmod 660 /var/ossec/etc/shared/feat-yara/agent.conf
install -o wazuh -g wazuh -m 660 /etc/wazuh-bundle/yara_base_rules.yar /var/ossec/etc/shared/feat-yara/yara_rules.yar
```

**Mise à jour chaque nuit** des hashes abuse.ch et des règles. Une clé gratuite est à créer sur
https://auth.abuse.ch/ :

```bash
read -rsp "Clé Auth-Key abuse.ch : " K; echo; printf 'ABUSECH_AUTH_KEY=%q\n' "$K" >> /root/.wazuh-bundle/secrets.env
cat >> /etc/wazuh-bundle/answers.env <<'EOF'
YARA_ENABLE=oui
MALWARE_HASH_ENABLE=oui
MALWARE_HASH_URL='https://mb-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv'
YARA_SOURCES=''
EOF
install -m 750 $B/tools/update_malware.sh /usr/local/sbin/wazuh-bundle-update-malware
echo '30 3 * * * root /usr/local/sbin/wazuh-bundle-update-malware >> /var/log/wazuh-bundle/malware.log 2>&1' > /etc/cron.d/wazuh-bundle-malware
/usr/local/sbin/wazuh-bundle-update-malware --test-hashes      # « source valide » attendu (sinon la cause est affichée)
/usr/local/sbin/wazuh-bundle-update-malware
```

**Vérification** : une ligne de résultat YARA doit déclencher la règle 100511.

```bash
echo 'wazuh-yara: INFO - Scan result: EICAR_Test_File /tmp/eicar.txt' | /var/ossec/bin/wazuh-logtest | grep "id:"
```

### 6.2 Sur chaque agent Linux qui doit être analysé (groupe `feat-yara`)

```bash
apt-get install -y yara jq
install -o root -g wazuh -m 750 /chemin/vers/wazuh-bundle/agents/yara.sh /var/ossec/active-response/bin/yara.sh
```

---

## 7. Alertes e-mail

Wazuh n'envoie qu'à un serveur SMTP local sans chiffrement. On installe donc **Postfix**, limité à
127.0.0.1, qui relaie vers le serveur d'envoi choisi.

```bash
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $(hostname -f)" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules bsd-mailx
postconf -e "inet_interfaces = loopback-only" "inet_protocols = ipv4" \
            "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt" "smtp_tls_loglevel = 1"
```

Choisir **un** des trois modes :

| Mode | Commandes |
|---|---|
| **Gmail** (compte avec validation en 2 étapes et *mot de passe d'application* de 16 caractères : myaccount.google.com/apppasswords) | `postconf -e "relayhost = [smtp.gmail.com]:587" "smtp_tls_security_level = secure" "smtp_sasl_auth_enable = yes" "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" "smtp_sasl_security_options = noanonymous" "smtp_sasl_tls_security_options = noanonymous"` |
| **SMTP de l'entreprise** (587 STARTTLS ; pour 465, ajouter `smtp_tls_wrappermode = yes`) | idem avec `relayhost = [smtp.entreprise.fr]:587` ; `encrypt` à la place de `secure` si le serveur utilise une autorité interne |
| **Relais interne sans mot de passe** (le relais doit autoriser l'IP du serveur Wazuh) | `postconf -e "relayhost = [relais.entreprise.local]:25" "smtp_tls_security_level = may" "smtp_sasl_auth_enable = no"` |

Pour Gmail ou un SMTP authentifié, déclarer l'identifiant (le mot de passe est saisi au clavier) :

```bash
read -rp "Serveur:port (ex. smtp.gmail.com:587) : " S; read -rp "Identifiant : " U; read -rsp "Mot de passe : " P; echo
printf '[%s]:%s %s:%s\n' "${S%%:*}" "${S##*:}" "$U" "$P" > /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd && postmap /etc/postfix/sasl_passwd && chmod 600 /etc/postfix/sasl_passwd.db
```

```bash
postfix check && systemctl restart postfix && systemctl enable postfix
echo "Test Wazuh $(date)" | mail -s "[WAZUH] test" -r expediteur@entreprise.fr destinataire@entreprise.fr
sleep 10; journalctl -t postfix/smtp -n 5 --no-pager      # « status=sent » attendu
```

Dans `ossec.conf`, section `<global>` : mettre `<email_notification>yes</email_notification>`,
`<smtp_server>localhost</smtp_server>`, l'expéditeur dans `<email_from>`, une ligne `<email_to>` par
destinataire et `<email_maxperhour>30</email_maxperhour>`. Dans la section `<alerts>`, mettre
`<email_alert_level>10</email_alert_level>`. Puis :

```bash
/var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK" && systemctl restart wazuh-manager
```

---

## 8. Alertes SMS (Africa's Talking, optionnel)

```bash
useradd -r -s /usr/sbin/nologin -g wazuh wazuh-sms
read -rsp "Clé API Africa's Talking : " K; echo
cat > /etc/wazuh-bundle/sms.env <<EOF
AT_USERNAME=sandbox
AT_API_KEY=$K
SMS_TO="+241XXXXXXXX"
SMS_ALERT_LEVEL=12
SMS_MAX_PER_HOUR=20
SMS_DEDUP_SECONDS=300
EOF
chown root:wazuh /etc/wazuh-bundle/sms.env && chmod 640 /etc/wazuh-bundle/sms.env
chgrp wazuh /etc/wazuh-bundle && chmod 750 /etc/wazuh-bundle
install -m 755 $B/configs/manager/wazuh-sms-alerter.py /usr/local/bin/wazuh-sms-alerter.py
install -m 644 $B/configs/manager/wazuh-sms-alerter.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now wazuh-sms-alerter && systemctl is-active wazuh-sms-alerter
SMS_ENV=/etc/wazuh-bundle/sms.env python3 /usr/local/bin/wazuh-sms-alerter.py --test     # SMS de test
```

Remplacer `sandbox` (aucun SMS n'est livré) par le nom d'utilisateur de production, et adapter les numéros.

---

## 9. Grafana (sur ce serveur, optionnel)

```bash
mkdir -p /etc/apt/keyrings
curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg
echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' > /etc/apt/sources.list.d/grafana.list
apt-get update && apt-get install -y grafana && systemctl enable --now grafana-server

# utilisateur de l'indexer en LECTURE SEULE pour Grafana
export RO_PW="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
printf 'GRAFANA_RO_PASSWORD=%q\n' "$RO_PW" >> /root/.wazuh-bundle/secrets.env
idx -X PUT https://127.0.0.1:9200/_plugins/_security/api/roles/grafana_read \
  -d '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}'
idx -X PUT https://127.0.0.1:9200/_plugins/_security/api/internalusers/grafana_ro -d "{\"password\":\"$RO_PW\",\"backend_roles\":[]}"
idx -X PUT https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/grafana_read -d '{"users":["grafana_ro"]}'

# source de données + tableaux de bord (Poste de commande et Vue SOC)
OSV=$(idx https://127.0.0.1:9200/ | jq -r .version.number)
IDX_URL=https://127.0.0.1:9200 RO_PW="$RO_PW" CA_FILE=/etc/wazuh-indexer/certs/root-ca.pem \
DASH_SRC=$B/configs/grafana/dashboards OPENSEARCH_DS_VERSION="$OSV" DS_IS_DEFAULT=true bash $B/grafana/provision.sh
grafana-cli admin reset-admin-password "$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 | tee /dev/stderr)"; echo
```

Le dernier mot de passe affiché est celui du compte `admin` de Grafana : notez-le. Grafana est accessible
sur `http://IP:3000` (port à n'ouvrir qu'aux postes d'administration).

---

## 10. Sauvegarde quotidienne de la configuration

```bash
printf 'BACKUP_DIR=/var/backups/wazuh\nBACKUP_KEEP_DAYS=14\n' >> /etc/wazuh-bundle/answers.env
install -m 750 $B/tools/backup.sh /usr/local/sbin/wazuh-bundle-backup
echo '30 2 * * * root /usr/local/sbin/wazuh-bundle-backup >> /var/log/wazuh-bundle/backup.log 2>&1' > /etc/cron.d/wazuh-bundle-backup
/usr/local/sbin/wazuh-bundle-backup && ls -lh /var/backups/wazuh
```

Copiez régulièrement ces archives, **chiffrées**, hors du serveur : elles contiennent des clés et des mots
de passe.

---

## 11. Durcissement SSH (optionnel)

Vérifiez d'abord qu'un compte nominatif membre de `sudo` peut se connecter. Ensuite :

```bash
cat > /etc/ssh/sshd_config.d/00-wazuh-bundle.conf <<'EOF'
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 30
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
sshd -t && systemctl reload ssh
```

N'ajoutez `PasswordAuthentication no` que si votre compte se connecte par clé SSH. **Testez une nouvelle
connexion SSH avant de fermer la session en cours.**

---

## 12. Agents (machines surveillées)

Récupérer sur le serveur la version de Wazuh et le mot de passe d'enrôlement :

```bash
dpkg-query -W wazuh-manager                          # ex. 4.14.10-1 : la version des agents doit être ≤
grep AUTHD_PASSWORD /root/.wazuh-bundle/secrets.env
```

**Agent Linux (Debian/Ubuntu)**, en root sur la machine. Adaptez les groupes à la machine :
segment + `os-linux`, rôle éventuel, `feat-yara` et/ou `opt-whodata` si besoin.

```bash
apt-get install -y curl gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER="10.10.10.20" WAZUH_AGENT_NAME="$(hostname -s)" WAZUH_AGENT_GROUP="seg-servers,os-linux" \
WAZUH_REGISTRATION_PASSWORD="MOT_DE_PASSE_ENROLEMENT" apt-get install -y wazuh-agent=4.14.10-1
apt-mark hold wazuh-agent
systemctl daemon-reload && systemctl enable --now wazuh-agent
sleep 20; grep "Connected to the server" /var/ossec/logs/ossec.log | tail -1
```

Si `/var/log/auth.log` n'existe pas (système sans rsyslog) : `apt-get install -y rsyslog`.

**Agent Windows** (PowerShell en administrateur) :

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="10.10.10.20" WAZUH_AGENT_NAME="PC-COMPTA-01" `
  WAZUH_AGENT_GROUP="seg-employees,os-windows" WAZUH_REGISTRATION_PASSWORD="MOT_DE_PASSE_ENROLEMENT"
Start-Service WazuhSvc
```

**Vérification**, sur le serveur : `/var/ossec/bin/agent_control -l` (l'agent doit être *Active*) et
`/var/ossec/bin/agent_groups -s -i <ID>`.

---

## 13. Recette

| Contrôle | Commande | Attendu |
|---|---|---|
| Services | `systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat` | 4 × `active` |
| Configuration | `/var/ossec/bin/wazuh-analysisd -t` | aucune erreur |
| Enrôlement protégé | `grep use_password /var/ossec/etc/ossec.conf` | `yes` |
| Indexer | `idx https://127.0.0.1:9200/_cluster/health \| jq .status` | `green` (ou `yellow` en mono-nœud) |
| Rétention | `idx https://127.0.0.1:9200/_plugins/_ism/policies \| jq '.policies[].policy.policy_id'` | 3 politiques `wazuh-bundle-*` |
| Agents | `/var/ossec/bin/agent_control -l` | agents `Active` |
| YARA | fichier EICAR dans `/tmp` d'un agent `feat-yara` | alerte 100511 |
| E-mail | `journalctl -t postfix/smtp -n 5` | `status=sent` |
| Sauvegarde | `ls -l /var/backups/wazuh` | archive du jour |

Fichier EICAR (inoffensif) :
`printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt`

Flux à faire ouvrir sur le pare-feu de l'entreprise :

- agents → serveur : TCP 1514 et 1515 ;
- postes d'administration → serveur : TCP 443 et 22 (et 3000 si Grafana) ;
- serveur → Internet : HTTPS 443 ;
- serveur → serveur SMTP : port choisi.

Ne **jamais** ouvrir les ports 9200 et 55000 depuis les segments employés et DMZ.
