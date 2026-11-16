# Détection de malwares avec YARA : guide pour débutant

## YARA en bref

YARA est un outil libre, maintenu par VirusTotal, qui **recherche des motifs dans le contenu des fichiers**.
Une *règle YARA* décrit les caractéristiques d'un logiciel malveillant :

```yara
rule PHP_Webshell_Exec_User_Input          // nom de la règle (apparaît dans l'alerte)
{
    meta:
        description = "Webshell PHP : exécution de commande depuis une entrée HTTP"
    strings:                                // ce que l'on cherche
        $a = /(system|shell_exec|passthru|exec)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
    condition:                              // quand la règle « correspond »
        $a and filesize < 2MB
}
```

Ce fichier PHP exécute une commande reçue depuis une page web. C'est la signature d'une *porte dérobée*
(webshell) déposée par un attaquant sur un site.

## Comment YARA s'intègre à Wazuh

```
 Agent Linux                                         Serveur Wazuh (manager)
 ───────────                                         ───────────────────────
 1. un fichier apparaît dans /var/www ───FIM───────▶ 2. règle 100501 « fichier ajouté dans un répertoire analysé »
                                                      3. réponse active : « agent, analyse ce fichier avec YARA »
 4. yara.sh analyse le fichier  ◀─────────────────────┘
 5. résultat écrit dans active-responses.log ──────▶ 6. décodeur yara_bundle → règle 100511 (niveau 12)
                                                      7. alerte : dashboard, e-mail, SMS
```

- Le fichier **n'est ni supprimé ni déplacé** : YARA détecte, la décision reste humaine.
- Les règles YARA sont distribuées **par le manager** aux agents du groupe `feat-yara`, dans
  `/var/ossec/etc/shared/yara_rules.yar` sur l'agent. Il n'y a rien à copier à la main.
- YARA est installé **sur le manager** pour compiler et valider chaque règle avant de la distribuer :
  une règle invalide n'atteint jamais les agents.

## Version installée

| Méthode | Version | Emplacement | Quand la choisir |
|---|---|---|---|
| `source` (recommandée) | **4.5.8**, dernière version stable de YARA 4.x | `/usr/local/bin/yara` | Cas général |
| `package` | celle de la distribution (Debian 12 : 4.2.x ; Ubuntu 24.04 : 4.5.0) | `/usr/bin/yara` | Machine sans compilateur ni accès à GitHub |

Avec la méthode `source`, le script `tools/install_yara.sh` :

1. télécharge le tag officiel `v4.5.8` depuis `github.com/VirusTotal/yara` ;
2. **vérifie l'identité du code** : le tag doit pointer exactement sur le commit
   `84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8`, sinon il refuse d'installer ;
3. compile avec les modules `hash`/`pe` (OpenSSL), `magic` et `dotnet`, installe et teste sur le fichier EICAR.

> **YARA-X**, la réécriture en Rust (branche 1.x), est le successeur annoncé de YARA. Le bundle conserve
> YARA 4.x pour sa compatibilité totale avec les règles communautaires existantes et avec le script d'analyse.
> Pour changer de version, modifiez `YARA_VERSION` et `YARA_COMMIT` dans `tools/install_yara.sh`.

## Ce que l'étape 06 vous demande

| Question | Conseil |
|---|---|
| Activer YARA ? | Oui, au moins pour les serveurs web et la DMZ. |
| Liste de hashes ? | Oui. Elle complète YARA en détectant les malwares connus à l'identique. Une clé gratuite est nécessaire : https://auth.abuse.ch/ |
| Répertoires en temps réel | Petits répertoires très exposés : `/var/www /tmp /var/tmp /dev/shm`. |
| Répertoires planifiés | Gros répertoires : `/home`. Ils sont analysés lors du contrôle périodique du segment. |
| Taille maximale | 100 Mo. Les fichiers plus gros sont ignorés : les webshells et scripts sont petits. |
| Règles supplémentaires | Facultatif. Exemple reconnu : `https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar`. Chaque fichier est compilé avant d'être accepté. |

## Sur les agents

```bash
sudo bash agents/install_agent_linux.sh --yara        # ou répondre « oui » à la question YARA
```

Le script installe YARA (même méthode, même version), `jq`, et le script d'analyse
`/var/ossec/active-response/bin/yara.sh`. Il ajoute aussi l'agent au groupe `feat-yara`.

## Tester sans risque : le fichier EICAR

EICAR est un fichier **inoffensif**, reconnu par tous les antivirus, qui sert à tester la détection.

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
```

En quelques secondes, l'alerte **100511** « Malware détecté par YARA : /tmp/eicar.txt — règle EICAR_Test_File »
apparaît. Supprimez ensuite le fichier.

## Dépannage

| Symptôme | Cause probable | Vérification |
|---|---|---|
| Alerte 100512 « binaire yara introuvable » | YARA non installé sur l'agent | `bash tools/install_yara.sh` sur l'agent |
| Alerte 100512 « règles YARA introuvables » | Agent absent du groupe `feat-yara` | Sur le manager : `/var/ossec/bin/agent_groups -s -i <ID>` |
| Pas d'alerte 100501 | Répertoire non surveillé | `/var/ossec/etc/shared/agent.conf` sur l'agent |
| Alerte 100501 sans résultat | Réponse active non exécutée | `tail /var/ossec/logs/active-responses.log` sur l'agent |
| Mise à jour des hashes en échec | Clé abuse.ch absente ou réseau | `/var/log/wazuh-bundle/malware.log` sur le manager |
