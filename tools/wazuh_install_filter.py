#!/usr/bin/env python3
"""wazuh_install_filter.py — rend lisible la sortie de l'installateur officiel wazuh-install.sh.

    bash wazuh-install.sh -a 2>&1 | python3 tools/wazuh_install_filter.py

Rien n'est supprimé : chaque ligne reste affichée (le journal brut complet est aussi dans
/var/log/wazuh-install.log). Le filtre :
  * retire la date répétée en tête de ligne ;
  * transforme « --- Wazuh indexer --- » en titre de phase français, avec la durée de la phase précédente ;
  * affiche les INFO en discret, les WARNING en jaune et les ERROR en rouge, avec une explication en
    français quand le message est connu ;
  * signale les messages d'erreur du shell (« ligne 4712 : … Aucun fichier ») qui précèdent souvent la cause ;
  * termine par un récapitulatif des avertissements et des erreurs.
"""
import os
import re
import sys
import time

COLOR = sys.stdout.isatty() or os.environ.get("BUNDLE_COLOR") == "1"
C = {k: (v if COLOR else "") for k, v in {
    "red": "\033[0;31m", "green": "\033[0;32m", "yellow": "\033[1;33m", "cyan": "\033[0;36m",
    "bold": "\033[1m", "dim": "\033[2m", "nc": "\033[0m"}.items()}

PHASES = {
    "dependencies": "Prérequis : dépendances du système",
    "configuration files": "Certificats et mots de passe",
    "wazuh indexer": "Indexer (base des alertes)",
    "wazuh server": "Manager (serveur Wazuh)",
    "filebeat": "Filebeat (transfert des alertes vers l'indexer)",
    "wazuh dashboard": "Dashboard (interface web)",
    "summary": "Résumé",
    "removing existing wazuh installation": "ANNULATION : l'installateur retire ce qu'il avait installé",
    "uninstalling": "Désinstallation",
}

# (motif, explication) — premier motif reconnu
WARNINGS = [
    (r"does not match with the list of recommended systems",
     "Ce système n'est pas dans la liste officielle de Wazuh. Debian 12/13 et Ubuntu 22.04/24.04 sont "
     "validés par le bundle : avertissement sans conséquence."),
    (r"minimum hardware requirements|not enough", "Ressources en dessous des recommandations Wazuh : "
     "l'installation continue, mais prévoir 8 Go de RAM et 4 processeurs en production."),
]
ERRORS = [
    (r"wazuh-keystore.*(No such file|Aucun fichier)",
     "Le manager Wazuh n'est pas installé alors que Filebeat l'est : reste d'une installation précédente. "
     "Nettoyer l'installation (l'étape 02 le propose) puis relancer."),
    (r"start operation timed out|result 'timeout'|Timeout",
     "Démarrage trop lent : systemd a abandonné le service. Cause habituelle : RAM ou CPU insuffisants "
     "(8 Go et 4 CPU recommandés)."),
    (r"wazuh-manager could not be started",
     "Le manager n'a pas démarré. Si la ligne « wazuh-keystore … Aucun fichier » apparaît juste avant, c'est "
     "un reste d'installation précédente ; sinon : journalctl -u wazuh-manager -n 50."),
    (r"Port (\d+) is being used|port .* in use|Address already in use",
     "Un autre programme utilise ce port : ss -tlnp pour l'identifier (ancienne installation ? autre service web ?)."),
    (r"already installed|existing installation|components.*found",
     "Des composants Wazuh sont déjà présents : nettoyer l'installation précédente puis relancer."),
    (r"could not be started|failed to start|Failed to start",
     "Un service n'a pas démarré : journalctl -u <service> -n 50 (mémoire insuffisante ? configuration ?)."),
    (r"Could not resolve|Failed to connect|Connection refused|timed out|Temporary failure",
     "Problème réseau : le serveur doit joindre packages.wazuh.com en HTTPS (proxy, DNS, pare-feu sortant)."),
    (r"dpkg|apt|lock", "Gestionnaire de paquets occupé ou en erreur : attendre la fin des mises à jour "
                       "automatiques, ou dpkg --configure -a."),
    (r"memory|Cannot allocate", "Mémoire insuffisante : l'indexer demande au moins 4 Go de RAM."),
    (r"[Cc]ertificate", "Problème de certificats : relancer l'installation sur un système nettoyé."),
]

TS = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} ")
LEVEL = re.compile(r"^(INFO|WARNING|ERROR|DEBUG): ?(.*)$")
PHASE = re.compile(r"^-{2,}\s*(.*?)\s*-{2,}$")


def out(s=""):
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def explain(table, msg):
    for pat, txt in table:
        if re.search(pat, msg, re.I):
            return txt
    return None


def main():
    phase, t0, n = None, time.time(), 0
    warns, errs, shell_errs = [], [], []
    st = {"err": False, "rollback": False}

    def close_phase():
        if phase is None:
            return
        if st["rollback"]:
            mark, col = "↺", C["yellow"]
        elif st["err"]:
            mark, col = "✘", C["red"]
        else:
            mark, col = "✔", C["green"]
        out(f"  {col}{mark}{C['nc']} {C['dim']}{phase} — {int(time.time() - t0)} s{C['nc']}")

    for raw in sys.stdin:
        line = TS.sub("", raw.rstrip("\n"))
        if not line.strip():
            continue
        m = LEVEL.match(line)
        if not m:  # message du shell ou d'un sous-programme : souvent la vraie cause
            shell_errs.append(line)
            out(f"  {C['yellow']}?{C['nc']} {line}")
            hint = explain(ERRORS, line)
            if hint:
                out(f"    {C['yellow']}→ {hint}{C['nc']}")
            continue
        lvl, msg = m.groups()
        pm = PHASE.match(msg)
        if pm:
            close_phase()
            st["err"] = False
            name = pm.group(1).lower()
            if name.startswith("removing"):
                st["rollback"] = True
                phase = PHASES[name] if name in PHASES else pm.group(1)
                out(f"{C['red']}▶ {phase}{C['nc']}")
            elif st["rollback"]:
                phase = "Annulation — " + PHASES.get(name, pm.group(1))
                out(f"{C['yellow']}▶ {phase}{C['nc']}")
            else:
                n += 1
                phase = PHASES.get(name, pm.group(1))
                out(f"{C['bold']}▶ Phase {n} : {phase}{C['nc']}")
            t0 = time.time()
            continue
        if lvl == "WARNING":
            warns.append(msg)
            out(f"  {C['yellow']}! {msg}{C['nc']}")
            hint = explain(WARNINGS, msg)
            if hint:
                out(f"    {C['yellow']}→ {hint}{C['nc']}")
        elif lvl == "ERROR":
            errs.append(msg); st["err"] = True
            out(f"  {C['red']}✘ {msg}{C['nc']}")
            hint = explain(ERRORS, msg) or explain(ERRORS, " ".join(shell_errs[-3:]))
            if hint:
                out(f"    {C['red']}→ {hint}{C['nc']}")
        else:
            out(f"    {C['dim']}{msg}{C['nc']}")
    close_phase()
    out()
    out(f"{C['bold']}Récapitulatif de l'installateur :{C['nc']} {len(errs)} erreur(s), {len(warns)} avertissement(s)"
        f"{', ' + str(len(shell_errs)) + ' message(s) du shell' if shell_errs else ''}.")
    for e in errs:
        out(f"  {C['red']}✘ {e}{C['nc']}")
    if st["rollback"]:
        out(f"  {C['yellow']}↺ L'installateur a annulé l'installation et retiré ce qu'il avait posé.{C['nc']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
