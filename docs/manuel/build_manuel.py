#!/usr/bin/env python3
"""Génère docs/Manuel_exploitation_SIEM_Wazuh.pdf — manuel d'exploitation remis au client.

    python3 docs/manuel/build_manuel.py

Orienté gestes : utiliser la plateforme, ajouter des machines, choisir ce qui est surveillé, écrire des règles,
ajuster les réglages, entretenir, dépanner. Chaque chapitre se termine par une mise en pratique sur la vraie
plateforme ; la dernière page récapitule ces gestes.
"""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pdflib import (BLUE, BOLD, CW, DARK, Doc, GREEN, GRID, LIGHT, MONO, NAVY, ORANGE, PANEL, PURPLE, RED, S,  # noqa: E402
                    SANS, TEAL, YELLOW, arrow, c, label, rect)
from reportlab.graphics.shapes import Circle, Drawing, Line, String  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.environ.get("MANUEL_OUT", os.path.join(ROOT, "docs", "Manuel_exploitation_SIEM_Wazuh.pdf"))
DOC_DATE = os.environ.get("GUIDE_DATE", date.today().strftime("%d/%m/%Y"))

d = Doc({
    "title": "Manuel d'exploitation — SIEM Wazuh", "author": "", "subject": "Exploitation du SIEM Wazuh",
    "kicker": "SIEM WAZUH — MANUEL D'EXPLOITATION",
    "title_lines": ["Exploiter et faire évoluer", "votre SIEM en autonomie"],
    "subtitle_lines": ["Utiliser la plateforme au quotidien · ajouter des machines · écrire des règles",
                       "régler les alertes · entretenir · dépanner"],
    "header": "SIEM Wazuh — Manuel d'exploitation", "classif": "Document interne — diffusion restreinte",
    "footer": f"Édition du {DOC_DATE}",
})
p, h2, h3, bullets, steps, code, box, table, ex = d.p, d.h2, d.h3, d.bullets, d.steps, d.code, d.box, d.table, d.exercise

# =================================================================== couverture
d.spacer(10.4 * cm)
fiche = [["Client", ""], ["Prestataire", ""], ["Mise en service", ""],
         ["Serveur Wazuh (nom / IP)", ""], ["Wazuh Dashboard", "https://"], ["Grafana", "http://            :3000"],
         ["Assistant d'installation", "/opt/wazuh-bundle  (version v3)"], ["Coffre des mots de passe", ""],
         ["Référent interne", ""], ["Support du prestataire (jusqu'au)", ""]]
t = Table([[Paragraph(f"<b>{a}</b>", S["cell"]), Paragraph(b, S["cell"])] for a, b in fiche],
          colWidths=[5.6 * cm, CW - 5.6 * cm], rowHeights=[0.78 * cm] * len(fiche))
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, GRID), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
d.raw(t)
d.spacer(10)
p("<b>Comment utiliser ce manuel.</b> Les chapitres vont du quotidien (lire le poste de commande, analyser une "
  "alerte) à l'évolution de la plateforme (nouvelles machines, nouvelles règles). Chacun se termine par un exercice "
  "« À vous » à réaliser sur <i>votre</i> plateforme : c'est en le faisant une fois soi-même que le geste s'acquiert. "
  "La dernière page récapitule ces gestes ; cochez-les au fur et à mesure.", "small")

d.toc()

# =================================================================== 1
d.chapter("1. Vos accès et vos repères",
          "Ce qui sert tous les jours tient sur cette page. Le reste du manuel y renvoie.")
table(["Outil", "Adresse", "Pour quoi faire", "Compte"], [
    ["Grafana — « Wazuh — Poste de commande »", "http://IP:3000", "Le coup d'œil quotidien (chapitre 2)",
     "nominatif (à créer, voir ci-dessous)"],
    ["Wazuh Dashboard", "https://IP", "Rechercher, analyser une alerte, voir les machines (chapitre 3)",
     "nominatif (à créer)"],
    ["Serveur Wazuh en SSH", "ssh compte@IP", "Ajouter une règle, relancer une étape, dépanner", "compte sudo nominatif"],
    ["Assistant", c("/opt/wazuh-bundle"), "Modifier un réglage, vérifier la plateforme", "root (sudo -i)"],
], [0.27, 0.17, 0.33, 0.23])
box("tip", "Créez un compte <b>par personne</b> plutôt que de partager « admin » : on sait ensuite qui a fait quoi. "
    "Wazuh Dashboard : menu ≡ &gt; <i>Indexer management</i> &gt; <i>Security</i> &gt; <i>Internal users</i> &gt; "
    "<i>Create internal user</i>, puis l'associer au rôle voulu (<i>Roles</i> &gt; <i>Mapped users</i>). "
    "Grafana : <i>Administration</i> &gt; <i>Users</i> &gt; <i>New user</i>.")

h2("Les trois commandes à connaître")
table(["Commande (sur le serveur, en root)", "Ce qu'elle fait"], [
    [c("bash /opt/wazuh-bundle/install.sh --step 99"),
     "Vérifie toute la plateforme en lecture seule ; chaque problème indique l'étape à relancer."],
    [c("/var/ossec/bin/agent_control -l"), "Liste les machines surveillées et leur état (Active / Disconnected)."],
    [c("/var/ossec/bin/wazuh-logtest"), "Rejoue une ligne de journal pour voir quelle règle se déclenche "
                                        "(indispensable pour écrire une règle, chapitre 6)."],
], [0.48, 0.52])

h2("Ce qui vous appartient, ce qui est géré par l'assistant")
p("Retenir cette séparation évite de perdre une modification : l'assistant <b>réécrit</b> ses propres fichiers "
  "lorsqu'on relance une étape, mais ne touche jamais aux vôtres.")
table(["À vous — modifiez librement", "Géré par l'assistant — ne pas éditer à la main"], [
    [c("/var/ossec/etc/rules/local_rules.xml") + " : vos règles",
     c("/var/ossec/etc/rules/bundle_*.xml") + " : règles livrées (étapes 04 et 06)"],
    [c("/var/ossec/etc/decoders/local_decoder.xml") + " : vos décodeurs",
     c("/var/ossec/etc/decoders/bundle_*.xml")],
    [c("/var/ossec/etc/lists/") + " : vos listes (IP, comptes…)",
     "Les blocs " + c("<!-- wazuh-bundle:BEGIN … -->") + " de " + c("ossec.conf")],
    [c("configs/groups/<groupe>/agent.conf") + " dans " + c("/opt/wazuh-bundle") + ", puis étape 03",
     c("/var/ossec/etc/shared/<groupe>/agent.conf") + " (recopiés par l'étape 03)"],
    ["Le reste de " + c("ossec.conf") + " (hors blocs balisés)", c("/etc/wazuh-bundle/answers.env") +
     " : vos réponses aux questions — relancer l'étape pour changer"],
], [0.5, 0.5])
box("info", "Avant toute modification d'un fichier de configuration, une copie suffit : " +
    c("cp -p fichier fichier.$(date +%F)") + ". En cas de doute, la sauvegarde de la nuit est dans " +
    c("/var/backups/wazuh/") + " (chapitre 8).")

# =================================================================== 2
d.chapter("2. Le coup d'œil quotidien",
          "Dix minutes par jour sur le poste de commande Grafana suffisent à savoir s'il faut agir.")


def dashboard_drawing():
    W, H = CW, 11.4 * cm
    dr = Drawing(W, H)
    u = W / 24.0; v = H / 36.0  # 24 colonnes, 36 lignes de grille

    def panel(x, y, w, h, title, fill=PANEL, title_col=colors.HexColor("#CCCCDC")):
        X, Y = x * u + 1.5, H - (y + h) * v + 1.5
        rect(dr, X, Y, w * u - 3, h * v - 3, fill, colors.HexColor("#2F333B"), 2)
        if title:
            label(dr, X + 17, Y + h * v - 12, title, 6.3, title_col, True)
        return X, Y

    def badge(n, x, y):
        X, Y = x * u, H - y * v
        dr.add(Circle(X, Y, 7, fillColor=PURPLE, strokeColor=colors.white, strokeWidth=1))
        dr.add(String(X, Y - 2.8, str(n), fontName=BOLD, fontSize=7.5, fillColor=colors.white, textAnchor="middle"))

    rect(dr, 0, 0, W, H, DARK, DARK, 4)
    # bandeau
    X, Y = panel(0, 0, 24, 2, "")
    for i, (col, t) in enumerate([(RED, "≥ 12 incident"), (ORANGE, "10-11 suspect"), (YELLOW, "7-9 surveiller"),
                                  (GREEN, "< 7 info")]):
        rect(dr, X + 50 + i * 95, Y + 8, 7, 7, col, col, 1)
        label(dr, X + 61 + i * 95, Y + 8.5, t, 6.3, colors.HexColor("#CCCCDC"))
    label(dr, X + 6, Y + 8.5, "Lecture :", 6.3, colors.white, True)
    # stats
    for i, (t, col, val) in enumerate([("Incidents probables", RED, "2"), ("Suspects", ORANGE, "7"),
                                       ("Malware", PURPLE, "1"), ("IP bloquées", ORANGE, "4"),
                                       ("Alertes au total", BLUE, "1 284"), ("Machines qui remontent", GREEN, "37")]):
        X, Y = panel(i * 4, 2, 4, 5, "", col)
        label(dr, X + 17, Y + 5 * v - 12, t, 5.4, colors.white, True)
        label(dr, X + 2 * u, Y + 12, val, 15, colors.white, True, "middle")
    # tendance + donut
    X, Y = panel(0, 7, 16, 8, "Alertes dans le temps, par gravité")
    import random
    random.seed(4)
    bw = (16 * u - 20) / 40
    for i in range(40):
        y0 = Y + 8
        for col, mx in [(GREEN, 22), (YELLOW, 8), (ORANGE, 4), (RED, 2)]:
            hgt = random.random() * mx * (1.8 if i in (27, 28) and col in (ORANGE, RED) else 1)
            rect(dr, X + 8 + i * bw, y0, bw - 1.5, hgt, col, col, 0)
            y0 += hgt
    X, Y = panel(16, 7, 8, 8, "Nature des alertes (≥ 7)")
    cx, cy = X + 2.6 * u, Y + 4 * v - 6
    for r_, col in [(26, BLUE), (19, PANEL)]:
        dr.add(Circle(cx, cy, r_, fillColor=col, strokeColor=None))
    for i, t in enumerate(["syscheck", "authentication", "malware", "windows"]):
        label(dr, X + 5.2 * u, Y + 6 * v - i * 10, t, 5.6, colors.HexColor("#CCCCDC"))
    # tops
    for j, t in enumerate(["Machines les plus en alerte", "Règles les plus déclenchées",
                           "IP à l'origine d'échecs de connexion"]):
        X, Y = panel(j * 8, 15, 8, 9, t)
        for k in range(6):
            ln = (8 * u - 70) * (1 - k * 0.15)
            rect(dr, X + 55, Y + 9 * v - 26 - k * 11, ln, 6, [colors.HexColor("#73BF69"), ORANGE, RED][j], None, 1)
            rect(dr, X + 6, Y + 9 * v - 26 - k * 11, 44, 6, colors.HexColor("#3A3E46"), None, 1)
    label(dr, 18, H - 24.75 * v, "Rangée « À traiter »", 6.8, colors.white, True)
    X, Y = panel(0, 25, 24, 10, "Incidents probables et suspects (niveau ≥ 10)")
    heads = ["Date", "Niv.", "Machine", "Règle", "Description", "IP source", "Fichier"]
    xs = [6, 70, 95, 160, 195, 370, 420]
    for hx, ht in zip(xs, heads):
        label(dr, X + hx, Y + 10 * v - 26, ht, 5.8, colors.HexColor("#9FA7B3"), True)
    for k, (lv, col) in enumerate([(12, RED), (12, RED), (10, ORANGE), (10, ORANGE), (11, ORANGE)]):
        yy = Y + 10 * v - 40 - k * 12
        rect(dr, X + 68, yy - 2, 18, 9, col, None, 1)
        label(dr, X + 77, yy, str(lv), 5.8, colors.white, True, "middle")
        rect(dr, X + 6, yy, 55, 5, colors.HexColor("#3A3E46"), None, 1)
        rect(dr, X + 95, yy, 55, 5, colors.HexColor("#3A3E46"), None, 1)
        rect(dr, X + 195, yy, 160, 5, colors.HexColor("#3A3E46"), None, 1)
    label(dr, 18, H - 35.6 * v, "Rangées repliées : Malware et intégrité des fichiers  ·  Connexions et blocages", 6.3,
          colors.HexColor("#CCCCDC"), True)
    for n, (x, y) in enumerate([(0.4, 2.4), (0.4, 7.4), (16.4, 7.4), (0.4, 15.4), (0.4, 25.4), (0.4, 35.0)], 1):
        badge(n, x, y)
    return dr


d.raw(dashboard_drawing())
d.raw(Paragraph("<i>Le tableau de bord « Wazuh — Poste de commande » (Grafana &gt; Dashboards &gt; Wazuh). "
                "Valeurs d'illustration.</i>", S["cap"]))
d.spacer(8)
table(["Zone", "Ce qu'elle dit", "Ce que vous faites"], [
    ["1  Indicateurs", "Faut-il agir ? Les cases rouge, orange et violette comptent les alertes importantes de la "
                       "période ; « Machines qui remontent » compte les machines actives.",
     "Tout chiffre non nul en rouge ou violet : aller en zone 5. Une chute de « Machines qui remontent » : "
     "chapitre 4 (agent déconnecté)."],
    ["2  Tendance", "Volume d'alertes dans le temps, coloré par gravité.",
     "Un pic orange ou rouge : cliquer-glisser dessus pour zoomer ; toute la page suit la période choisie."],
    ["3  Nature", "Familles d'alertes significatives (fichiers, authentification, malware, Windows…).",
     "Repérer une famille inhabituelle (ex. « malware » qui apparaît)."],
    ["4  Qui / quoi", "Machines, règles et IP qui reviennent le plus.",
     "Une règle très bavarde sans incident réel = faux positif à régler (chapitre 6, recette « faire taire »)."],
    ["5  À traiter", "Les 100 dernières alertes de niveau ≥ 10, avec machine, règle, IP, fichier.",
     "Traiter chaque ligne rouge (chapitre 3). Filtrer une colonne avec l'entonnoir de son en-tête."],
    ["6  Rangées repliées", "Détail malware et fichiers sensibles ; connexions et blocages.",
     "Cliquer sur le titre de la rangée pour la déplier."],
], [0.16, 0.4, 0.44])
p("En haut de la page : la <b>période</b> (à droite, 24 h par défaut) et le filtre <b>Machine</b> (à gauche) "
  "s'appliquent à tous les panneaux. Le lundi, élargissez à 72 h pour couvrir le week-end.")

h2("La routine en dix minutes")
steps(["Ouvrir le poste de commande. Zone 1 entièrement verte ou à 0 ? Passer à l'étape 4.",
       "Zone 5 : pour chaque ligne rouge (≥ 12), suivre la conduite du chapitre 3 et noter la décision.",
       "Lignes orange (10-11) : vérifier qu'elles correspondent à une intervention connue (mise à jour, ajout "
       "d'administrateur…) ; sinon, les analyser comme une ligne rouge.",
       "Zone 4 : une règle qui domine le classement depuis plusieurs jours sans incident réel ? Noter-la pour un "
       "réglage (chapitre 6).",
       "Zone 1, « Machines qui remontent » : le nombre est-il habituel ? Sinon, " +
       c("agent_control -l") + " (chapitre 4)."])
box("info", "Les alertes de niveau ≥ 10 arrivent aussi par e-mail (et ≥ 12 par SMS si activé). Le poste de commande "
    "reste la référence : un e-mail peut être filtré comme spam, un SMS retardé.")
ex("lire le poste de commande",
   ["Ouvrir Grafana &gt; Dashboards &gt; Wazuh &gt; « Wazuh — Poste de commande ».",
    "Passer la période à « Last 7 days », puis revenir à 24 h.",
    "Choisir une machine dans le filtre <b>Machine</b> et observer ce qui change, puis revenir à « All ».",
    "Déplier la rangée « Connexions et blocages »."],
   "vous savez dire, pour la période, combien d'incidents probables sont en cours et quelle machine "
   "génère le plus d'alertes.")

# =================================================================== 3
d.chapter("3. Analyser une alerte et décider",
          "Une alerte est une question posée par la plateforme : « ce que je vois est-il normal ? ». "
          "Ce chapitre donne la méthode pour y répondre.")
h2("Retrouver l'alerte et son contexte")
p("Dans le Wazuh Dashboard : menu ≡ &gt; <i>Threat Hunting</i> (onglet <i>Events</i>). La barre de recherche "
  "accepte les requêtes suivantes ; la période se règle en haut à droite.")
table(["Je cherche…", "Requête"], [
    ["Les alertes importantes", c("rule.level >= 10")],
    ["Tout ce qui concerne une machine", c('agent.name : "dmz-web01"')],
    ["Une règle précise", c("rule.id : 100511")],
    ["Ce qu'a fait une adresse IP", c('data.srcip : "203.0.113.45"')],
    ["Les modifications d'un fichier", c('syscheck.path : "/etc/sudoers"')],
    ["Les actions d'un utilisateur", c('data.dstuser : "bob" or data.win.eventdata.targetUserName : "bob"')],
    ["Combiner", c('rule.level >= 7 and agent.name : "srv-db01" and not rule.id : 5402')],
], [0.38, 0.62])
p("Cliquer sur une ligne affiche l'alerte complète. Les champs utiles se lisent toujours de la même façon :")
code('''{
  "timestamp": "2026-11-17T09:41:12.512+0100",          <- QUAND
  "agent": { "id": "004", "name": "dmz-web01" },        <- OÙ : quelle machine
  "rule": {                                             <- QUOI et à quel point c'est grave
     "id": "100511", "level": 12,
     "description": "Malware détecté par YARA : /var/www/html/up/shell.php …",
     "groups": ["yara", "malware", "attack"],
     "mitre": { "id": ["T1204.002"] } },                <- technique d'attaque (MITRE ATT&CK)
  "data": {                                             <- détails propres à la règle
     "yara_rule": "PHP_Webshell_Exec_User_Input", "srcip": "…", "dstuser": "…" },
  "syscheck": { "path": "…", "sha256_after": "…" },     <- pour un fichier : chemin, empreinte
  "full_log": "…"                                       <- la ligne de journal d'origine
}''', "Lire une alerte")

h2("Décider : trois issues possibles")
table(["Constat", "Décision", "Action"], [
    ["Le fait correspond à une intervention connue (maintenance, installation, administrateur identifié).",
     "<b>Légitime</b>", "Noter la référence de l'intervention. Si ce cas se répète chaque semaine : faire taire "
                        "l'alerte pour ce cas précis (chapitre 6)."],
    ["Personne ne sait expliquer le fait, mais rien ne confirme une attaque.", "<b>À investiguer</b>",
     "Contexte : alertes de la même machine et de la même IP ±1 h ; demander au responsable de la machine."],
    ["Malware confirmé, compte inconnu créé, journal effacé, connexion réussie après une rafale d'échecs…",
     "<b>Incident</b>", "Appliquer la procédure d'incident de l'entreprise : isoler la machine du réseau (sans "
                        "l'éteindre), conserver les preuves, prévenir le responsable sécurité."],
], [0.43, 0.15, 0.42])
box("danger", "En cas d'incident, ne supprimez pas le fichier suspect et n'éteignez pas la machine : la mémoire et "
    "les fichiers sont des preuves. Isolez-la du réseau (débrancher le câble, couper le port du commutateur ou "
    "la carte réseau virtuelle).")

h2("Conduites à tenir pour les alertes les plus fréquentes")
table(["Alerte", "Premières vérifications"], [
    ["<b>100511</b> Malware YARA / <b>100500</b> hash connu / <b>100540</b> Defender",
     "Quel fichier, déposé quand, par quel processus ou quel compte (alertes FIM de la même minute) ? Sur un serveur "
     "web : le fichier est-il dans un dossier d'upload ? Considérer comme un incident tant que ce n'est pas un "
     "fichier de test (EICAR)."],
    ["<b>5712 / 5763</b> Force brute SSH (+ <b>651</b> IP bloquée)",
     "IP externe : normal sur une machine exposée, le blocage agit. IP interne : poste compromis ou script mal "
     "configuré — identifier la machine source. Vérifier qu'il n'y a <b>aucune connexion réussie</b> de cette IP "
     "ensuite : " + c('data.srcip : "IP" and rule.groups : authentication_success') + "."],
    ["<b>100551</b> clé SSH, <b>100552</b> sudoers, <b>100555</b> comptes",
     "Ouvrir l'alerte : la section <i>diff</i> montre la ligne ajoutée. Un administrateur l'a-t-il faite ? Sinon "
     "incident (porte dérobée)."],
    ["<b>100553</b> cron, <b>100554</b> service, <b>100522/100523</b> service ou tâche Windows",
     "Le programme lancé est-il connu ? Où est-il situé (" + c("/tmp") + ", profil utilisateur = suspect) ?"],
    ["<b>100520</b> journal Windows effacé, <b>100524</b> audit modifié, <b>100541</b> Defender désactivé",
     "Rarement légitime : qui (champ " + c("win.eventdata.subjectUserName") + ") et pourquoi ? À traiter comme un "
     "incident si personne ne le revendique."],
    ["<b>100512</b> erreur YARA", "Pas une attaque : la machine n'est plus protégée par YARA. Lire le message, "
                                  "corriger (chapitre 9)."],
], [0.3, 0.7])
h2("Débloquer une adresse bloquée par erreur")
p("Le blocage est levé automatiquement après la durée choisie (10 minutes par défaut). Pour qu'une adresse ne soit "
  "<b>plus jamais</b> bloquée, l'ajouter à la liste blanche : " + c("bash install.sh --step 03") +
  " (question « Autres IP à ne jamais bloquer »).")
ex("suivre une alerte de bout en bout",
   ["Sur une machine Linux du groupe <i>feat-yara</i>, créer le fichier de test EICAR (inoffensif) :<br/>" +
    c("printf '%s' 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt"),
    "Le retrouver dans le poste de commande (zone 1 « Malware », zone 5).",
    "Dans Threat Hunting, rechercher " + c("rule.id : 100511") + ", ouvrir l'alerte, repérer machine, fichier, "
    "règle YARA.",
    "Vérifier la réception de l'e-mail d'alerte. Supprimer le fichier."],
   "vous avez retrouvé l'alerte par trois chemins (Grafana, recherche, e-mail) et su dire où et quand le fichier "
   "a été créé.")

# =================================================================== 4
d.chapter("4. Ajouter et gérer les machines",
          "Une machine surveillée exécute un agent. Ce qu'il surveille dépend des groupes qu'on lui donne.")
h2("Choisir les groupes")
table(["Question", "Groupe", "Effet"], [
    ["Dans quel segment est la machine ?", c("seg-servers") + " / " + c("seg-employees") + " / " + c("seg-dmz"),
     "Fréquence du contrôle complet des fichiers : 6 h / 12 h / 2 h."],
    ["Quel système ?", c("os-linux") + " / " + c("os-windows"), "Fichiers sensibles et journaux du système."],
    ["Quel rôle ?", c("role-web") + " / " + c("role-db") + " / " + c("role-admin"),
     "Configuration et journaux du serveur web, de la base, outils d'administration."],
    ["Exposée ou serveur web ?", c("feat-yara"), "Analyse des fichiers déposés (malwares)."],
    ["Fichiers très sensibles ?", c("opt-whodata"), "Indique quel compte a modifié le fichier."],
], [0.3, 0.33, 0.37])
p("Exemple : un serveur web en DMZ reçoit " + c("seg-dmz,os-linux,role-web,feat-yara") +
  " ; un poste de la comptabilité reçoit " + c("seg-employees,os-windows") + ".")

h2("Installer un agent Linux")
p("Copier le dossier de l'assistant sur la machine (ou " + c("git clone") + "), puis :")
code("""sudo bash agents/install_agent_linux.sh
# Questions posées : IP du serveur Wazuh, segment, rôle, nom, version, YARA, whodata,
# mot de passe d'enrôlement.""")
bullets(["<b>Version</b> : celle du serveur ou plus ancienne, jamais plus récente. Sur le serveur : " +
         c("dpkg-query -W wazuh-manager") + ".",
         "<b>Mot de passe d'enrôlement</b> : sur le serveur, " +
         c("grep AUTHD_PASSWORD /root/.wazuh-bundle/secrets.env") + ".",
         "<b>Machine sans Internet</b> : télécharger le paquet " + c(".deb") + " ailleurs et ajouter " +
         c("--deb-path chemin.deb") + "."])
h3("Installer plusieurs machines d'un coup")
code("""# liste.txt : une ligne par machine « nom segment rôle »
# /root/enrol.pw : mot de passe d'enrôlement, présent sur chaque machine (root, 600)
while read -r nom seg role; do
  scp -r /opt/wazuh-bundle "$nom":/tmp/
  ssh -t "$nom" sudo bash /tmp/wazuh-bundle/agents/install_agent_linux.sh \\
      --manager-ip 10.10.10.20 --segment "$seg" --role "$role" --name "$nom" \\
      --version 4.14.9-1 --password-file /root/enrol.pw
done < liste.txt""")
h2("Installer un agent Windows")
code(""".\\install_agent_windows.ps1 -ManagerIP 10.10.10.20 -Segment employees `
    -AgentName PC-COMPTA-01 -Version 4.14.9-1""",
     "PowerShell en administrateur")
p("Pour un parc Windows, le même script se déploie par GPO ou par l'outil de déploiement habituel. Activer aussi, "
  "par GPO, l'audit « Création du processus » et « Autres événements d'accès aux objets » : sans eux, Windows "
  "n'enregistre pas les nouveaux processus ni les tâches planifiées.")

h2("Vérifier, changer, retirer")
table(["Je veux…", "Commande (sur le serveur)"], [
    ["Voir les machines et leur état", c("/var/ossec/bin/agent_control -l")],
    ["Voir les groupes d'une machine", c("/var/ossec/bin/agent_groups -s -i 005")],
    ["Ajouter un groupe à une machine", c("/var/ossec/bin/agent_groups -a -i 005 -g feat-yara -q")],
    ["Retirer un groupe", c("/var/ossec/bin/agent_groups -r -i 005 -g feat-yara -q")],
    ["Retirer une machine (décommissionnée)", c("/var/ossec/bin/manage_agents -r 005") + " puis, sur la machine : " +
     c("apt-get purge wazuh-agent")],
], [0.36, 0.64])
box("info", "Un agent reçoit sa nouvelle configuration en moins d'une minute après un changement de groupe ; "
    "il redémarre de lui-même. Sur la machine, " + c("cat /var/ossec/etc/shared/agent.conf") +
    " montre ce qu'il a reçu.")
h3("Une machine apparaît « Disconnected »")
steps(["Sur la machine : " + c("systemctl status wazuh-agent") + " (Windows : service <i>Wazuh</i>).",
       "Sur la machine : " + c("grep -E 'ERROR|WARN' /var/ossec/logs/ossec.log | tail") + ".",
       "Réseau : la machine doit joindre le serveur en TCP 1514 : " + c("timeout 3 bash -c '</dev/tcp/IP/1514'") + "."])
ex("ajouter une machine",
   ["Choisir une machine de test et décider de ses groupes avec le tableau du début du chapitre.",
    "L'installer avec le script (Linux ou Windows).",
    "Vérifier qu'elle est <i>Active</i> avec " + c("agent_control -l") + " et que ses groupes sont les bons.",
    "Lui ajouter puis lui retirer le groupe " + c("opt-whodata") + "."],
   "la machine apparaît dans le filtre <b>Machine</b> du poste de commande et ses alertes remontent.")

# =================================================================== 5
d.chapter("5. Choisir ce qui est surveillé",
          "La configuration des machines est centralisée par groupe : on la modifie une fois sur le serveur, "
          "toutes les machines du groupe la reçoivent.")
h2("Où et comment modifier")
steps(["Éditer " + c("/opt/wazuh-bundle/configs/groups/<groupe>/agent.conf") + " (pour un nouveau groupe : créer "
       "le dossier " + c("configs/groups/role-mail/") + " et son " + c("agent.conf") + ").",
       "Lancer " + c("bash /opt/wazuh-bundle/install.sh --step 03") + " : l'assistant vérifie la syntaxe, crée les "
       "groupes manquants et distribue la configuration.",
       "Affecter le groupe aux machines concernées (chapitre 4)."])
box("warn", "Ne modifiez pas directement " + c("/var/ossec/etc/shared/<groupe>/agent.conf") + " : l'étape 03 "
    "le remplace par la version de " + c("configs/groups/") + ".")
h2("Surveiller des fichiers et des répertoires")
code("""<agent_config os="Linux">
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">
      /opt/monapp/config</directories>
    <directories check_all="yes">/opt/monapp/bin</directories>
    <ignore>/opt/monapp/config/cache</ignore>
    <ignore type="sregex">\\.tmp$</ignore>
    <nodiff>/opt/monapp/config/secrets.yml</nodiff>
  </syscheck>
</agent_config>""", "configs/groups/role-monapp/agent.conf")
table(["Attribut / balise", "Effet", "Conseil"], [
    [c('realtime="yes"'), "Détection immédiate de l'ajout ou de la modification.", "Petits répertoires sensibles."],
    ["(sans realtime)", "Vérification lors du contrôle périodique du segment (2 à 12 h).", "Gros répertoires."],
    [c('report_changes="yes"'), "L'alerte montre les lignes modifiées (diff).", "Fichiers texte de configuration."],
    [c('whodata="yes"'), "L'alerte indique le compte et le processus (auditd sous Linux).",
     "Quelques fichiers critiques."],
    [c('restrict="motif"'), "Ne surveille que les fichiers dont le nom contient le motif.",
     "Ex. " + c('restrict="authorized_keys"') + "."],
    [c("<ignore>"), "Exclut un chemin (ou un motif avec " + c('type="sregex"') + ").", "Caches, fichiers temporaires."],
    [c("<nodiff>"), "Surveille le fichier mais ne copie jamais son contenu dans l'alerte.",
     "Fichiers contenant des secrets."],
    [c('os="Linux"') + " / " + c('os="Windows"'), "Restreint le bloc à un système.", "Un même groupe peut avoir les deux."],
], [0.25, 0.45, 0.3])
h2("Collecter les journaux d'une application")
code("""<agent_config os="Linux">
  <localfile>                                   <!-- texte : une ligne = un événement -->
    <log_format>syslog</log_format>
    <location>/var/log/monapp/app.log</location>
  </localfile>
  <localfile>                                   <!-- JSON : champs décodés automatiquement -->
    <log_format>json</log_format>
    <location>/var/log/monapp/audit.json</location>
  </localfile>
</agent_config>
<agent_config os="Windows">
  <localfile>
    <log_format>eventchannel</log_format>        <!-- journal d'événements Windows -->
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <query>Event/System[EventID=4104]</query>
  </localfile>
</agent_config>""")
p("Formats courants : " + c("syslog") + " (texte, une ligne par événement), " + c("json") + ", " +
  c("apache") + " (journaux web), " + c("multi-line") + " (événement sur plusieurs lignes), " +
  c("eventchannel") + " (Windows). Le chemin accepte les jokers : " + c("/var/log/monapp/*.log") + ".")
box("tip", "Collecter un journal ne suffit pas toujours à produire des alertes : si aucune règle existante ne "
    "reconnaît ses lignes, il faut un décodeur et une règle (chapitre 6, recette C). Les journaux JSON sont "
    "décodés automatiquement : il ne manque alors que la règle.")
ex("surveiller une application",
   ["Créer le groupe " + c("role-monapp") + " avec la surveillance d'un dossier de configuration de votre choix "
    "(temps réel, avec diff).",
    "Lancer l'étape 03, affecter le groupe à une machine de test.",
    "Modifier un fichier du dossier sur la machine."],
   "une alerte « Integrity checksum changed » (règle 550) apparaît avec la ligne modifiée dans la section diff.")

# =================================================================== 6
d.chapter("6. Écrire vos propres règles",
          "Une règle transforme un événement en alerte. Savoir en écrire, c'est pouvoir adapter la plateforme à ce "
          "qui compte pour l'entreprise — et faire taire ce qui ne compte pas.")
h2("Le principe en une figure")


def pipeline():
    W, H = CW, 3.3 * cm
    dr = Drawing(W, H)
    boxes = [("Événement", "ligne de journal,\nfichier modifié, Windows"), ("Décodeur", "extrait les champs :\nsrcip, user, file…"),
             ("Règles", "la plus précise\nqui correspond gagne"), ("Alerte", "niveau 0 à 15 ;\n0 = pas d'alerte")]
    bw = (W - 3 * 26) / 4
    for i, (t, sub) in enumerate(boxes):
        x = i * (bw + 26)
        rect(dr, x, 8, bw, H - 16, [LIGHT, LIGHT, NAVY, RED][i], NAVY, 5)
        col = colors.white if i >= 2 else NAVY
        label(dr, x + bw / 2, H - 28, t, 9.5, col, True, "middle")
        for k, ln in enumerate(sub.split("\n")):
            label(dr, x + bw / 2, H - 44 - k * 10.5, ln, 7.4, col, False, "middle")
        if i < 3:
            arrow(dr, x + bw + 3, H / 2, x + bw + 23, H / 2)
    return dr


d.raw(pipeline())
d.spacer(6)
p("Une règle se branche presque toujours sur une règle existante (" + c("<if_sid>") + ") et la précise. "
  "Exemple : la règle Wazuh 5715 (« connexion SSH réussie ») + « utilisateur = root » = règle 100560.")
h2("Où écrire, et la méthode en cinq temps")
table(["Fichier", "Contenu", "Identifiants"], [
    [c("/var/ossec/etc/rules/local_rules.xml"), "Vos règles", "<b>101000 à 101999</b> (réservés à l'entreprise)"],
    [c("/var/ossec/etc/decoders/local_decoder.xml"), "Vos décodeurs", "noms libres, préfixés (ex. " + c("monapp") + ")"],
], [0.42, 0.18, 0.4])
steps(["<b>Trouver</b> la ligne de journal ou l'alerte de départ (Threat Hunting, champ " + c("full_log") + ").",
       "<b>Tester</b> cette ligne dans " + c("wazuh-logtest") + " : quelle règle se déclenche déjà, quels champs "
       "sont extraits ?",
       "<b>Écrire</b> la règle (et le décodeur si aucun champ n'est extrait).",
       "<b>Valider</b> : " + c("/var/ossec/bin/wazuh-analysisd -t") + " (aucune sortie d'erreur = syntaxe correcte), "
       "puis rejouer la ligne dans " + c("wazuh-logtest") + ".",
       "<b>Activer</b> : " + c("systemctl restart wazuh-manager") + ", puis surveiller l'alerte quelques jours."])
code("""# /var/ossec/bin/wazuh-logtest
Type one log per line
Nov 17 09:12:44 srv-db01 sshd[2211]: Accepted publickey for root from 10.10.10.50 port 51022

**Phase 1: Completed pre-decoding.        <- en-tête reconnu : date, machine, programme
        program_name: 'sshd'
**Phase 2: Completed decoding.            <- décodeur trouvé, champs extraits
        name: 'sshd'
        dstuser: 'root'
        srcip: '10.10.10.50'
**Phase 3: Completed filtering (rules).   <- règle retenue
        id: '100560'
        level: '8'
        description: 'Linux : connexion SSH directe du compte root depuis 10.10.10.50'
**Alert to be generated.""", "wazuh-logtest : lire le résultat")

h2("Anatomie d'une règle")
code("""<group name="entreprise,">              <!-- groupe(s) ajoutés à l'alerte (filtres, Grafana) -->
  <rule id="101010" level="10">         <!-- identifiant unique, gravité -->
    <if_sid>5715</if_sid>               <!-- se branche sur : connexion SSH réussie -->
    <srcip>!10.10.10.0/24</srcip>       <!-- condition : IP HORS du réseau d'administration -->
    <description>SSH : connexion de $(dstuser) depuis $(srcip), hors réseau admin</description>
    <mitre><id>T1078</id></mitre>       <!-- optionnel : technique MITRE ATT&CK -->
    <group>authentication_success,</group>
  </rule>
</group>""", "local_rules.xml")
table(["Balise", "Rôle", "Exemple"], [
    [c("<if_sid>"), "Ne s'évalue qu'après la ou les règles indiquées.", c("<if_sid>5715,5501</if_sid>")],
    [c("<if_group>"), "Après toute règle d'un groupe.", c("<if_group>authentication_failed</if_group>")],
    [c("<decoded_as>"), "Événements traités par un décodeur donné.", c("<decoded_as>monapp</decoded_as>")],
    [c("<match>"), "Texte présent dans la ligne (| = ou).", c("<match>denied|refused</match>")],
    [c("<regex>"), "Expression régulière sur la ligne.", c('<regex type="pcre2">code=(4|5)\\d\\d</regex>')],
    [c("<srcip> <user> <program_name> <action> <url>"), "Champ standard extrait par le décodeur ("
     + c("!") + " = sauf).", c("<user>^root$|^admin$</user>")],
    [c('<field name="…">'), "Autre champ (JSON, Windows, FIM).", c('<field name="win.system.eventID">^4720$</field>')],
    [c("<list>"), "Valeur présente dans une liste (CDB).", "voir recette E"],
    [c("<time> <weekday>"), "Plage horaire / jours (heure du serveur).", c("<time>20:00-07:00</time>") + " " +
     c("<weekday>weekends</weekday>")],
    [c('frequency="N" timeframe="S"'), "Corrélation : N fois en S secondes…", "voir recette D"],
    [c("<if_matched_sid> <same_srcip/> <same_user/>"), "…d'une règle donnée, même IP / même compte.",
     "voir recette D"],
    [c("<options>"), c("no_email_alert") + " (jamais d'e-mail), " + c("alert_by_email") + " (toujours).",
     c("<options>no_email_alert</options>")],
    [c("$(champ)"), "Insère la valeur d'un champ dans la description.", c("$(srcip) $(dstuser) $(file)")],
], [0.29, 0.36, 0.35])
h3("Choisir le niveau")
table(["Niveau", "Usage", "Notification (réglages actuels)"], [
    ["0", "Ignorer (aucune alerte enregistrée)", "—"],
    ["3 - 6", "Information, contexte", "Recherche uniquement"],
    ["7 - 9", "À examiner", "Poste de commande"],
    ["10 - 11", "Suspect", "+ e-mail"],
    ["12 - 15", "Incident probable / avéré", "+ e-mail + SMS"],
], [0.12, 0.48, 0.4])

h2("Recettes")
h3("A. Relever la gravité d'un cas qui compte pour vous")
code("""<group name="entreprise,">
  <rule id="101000" level="12">
    <if_sid>5715</if_sid>
    <user>^svc_backup$</user>
    <description>Connexion SSH du compte de service svc_backup depuis $(srcip)</description>
  </rule>
</group>""")
h3("B. Faire taire un faux positif — précisément")
p("Ne jamais supprimer ni désactiver une règle entière : créer une règle « fille » de niveau 0 qui ne couvre "
  "<b>que</b> le cas légitime.")
code("""<rule id="101001" level="0">
  <if_sid>100553</if_sid>                       <!-- la règle bavarde : tâche cron modifiée -->
  <field name="file">^/etc/cron.d/sysstat$</field>  <!-- seul ce fichier (sysstat) -->
  <description>Ignoré : mise à jour attendue de /etc/cron.d/sysstat</description>
</rule>""")
h3("C. Reconnaître les journaux d'une application")
p("Ligne à reconnaître (fichier collecté au chapitre 5) :")
code("""2026-11-17 10:02:31 MONAPP LOGIN_FAILED user=bob ip=10.20.0.15""")
code("""<decoder name="monapp">
  <prematch>MONAPP </prematch>                  <!-- repère les lignes de l'application -->
</decoder>

<decoder name="monapp-auth">
  <parent>monapp</parent>
  <!-- chaque ( ) devient un champ, nommé dans l'ordre de <order> -->
  <regex>MONAPP (LOGIN_\\w+) user=(\\S+) ip=(\\S+)</regex>
  <order>action, dstuser, srcip</order>
</decoder>""", "local_decoder.xml")
code("""<group name="entreprise,monapp,">
  <rule id="101020" level="3">
    <decoded_as>monapp</decoded_as>
    <description>MonApp : événement</description>
  </rule>
  <rule id="101021" level="5">
    <if_sid>101020</if_sid>
    <action>LOGIN_FAILED</action>
    <description>MonApp : échec de connexion de $(dstuser) depuis $(srcip)</description>
    <group>authentication_failed,</group>
  </rule>
</group>""", "local_rules.xml")
h3("D. Corréler : plusieurs échecs en peu de temps")
code("""<rule id="101022" level="10" frequency="5" timeframe="120">
  <if_matched_sid>101021</if_matched_sid>       <!-- 5 échecs MonApp… -->
  <same_srcip />                                <!-- …depuis la même IP, en 2 minutes -->
  <description>MonApp : force brute probable depuis $(srcip)</description>
  <group>authentication_failures,attack,</group>
</rule>""")
h3("E. Liste de surveillance (IP ou comptes)")
code("""# 1. la liste : une valeur par ligne, suivie de « : »
cat > /var/ossec/etc/lists/ip-surveillees <<'EOF'
203.0.113.45:
198.51.100.7:
EOF
chown wazuh:wazuh /var/ossec/etc/lists/ip-surveillees

# 2. la déclarer dans ossec.conf, section <ruleset> (en dehors des blocs wazuh-bundle) :
#      <list>etc/lists/ip-surveillees</list>""")
code("""<rule id="101030" level="12">
  <if_group>authentication_success</if_group>
  <list field="srcip" lookup="address_match_key">etc/lists/ip-surveillees</list>
  <description>Connexion réussie depuis une IP sous surveillance : $(srcip)</description>
</rule>""")
p("Après une modification de la liste : " + c("systemctl restart wazuh-manager") + " (les listes sont lues au "
  "démarrage).")
h3("F. Modifier une règle livrée par Wazuh")
p("Copier la règle d'origine <b>entière</b> dans " + c("local_rules.xml") + ", ajouter " + c('overwrite="yes"') +
  ", changer ce qui doit l'être. Pour trouver l'original : " +
  c("grep -rn 'id=\"5402\"' /var/ossec/ruleset/rules/") + ".")
code("""<!-- recopie intégrale de la règle d'origine, seul le niveau change -->
<rule id="5402" level="0" overwrite="yes">
  …  (toutes les balises d'origine, inchangées)  …
</rule>""")

h2("Les erreurs les plus courantes")
table(["Symptôme", "Cause", "Correction"], [
    [c("wazuh-analysisd -t") + " signale une erreur", "Balise mal fermée, caractère " + c("&") + " ou " + c("<") +
     " dans une description, identifiant en double.", "Le message donne le fichier et la ligne. Écrire " +
     c("&amp;") + " pour &amp;."],
    ["La règle ne se déclenche pas dans logtest", "Mauvais " + c("if_sid") + ", champ non extrait, regex trop "
     "stricte.", "Lire la phase 2 de logtest : les champs disponibles y figurent avec leur nom exact."],
    ["Une autre règle gagne", "Une règle plus précise ou plus profonde correspond aussi.",
     "Brancher la vôtre sur celle qui gagne (" + c("if_sid") + " = son identifiant)."],
    ["Le manager ne redémarre pas", "Erreur introduite dans un fichier.", c("tail -30 /var/ossec/logs/ossec.log") +
     " ; corriger ou remettre la copie faite avant modification."],
], [0.27, 0.36, 0.37])
ex("créer, tester et régler une règle",
   ["Écrire la recette A avec un compte réel de votre parc.",
    "Valider avec " + c("wazuh-analysisd -t") + " puis rejouer une ligne " + c("Accepted password for …") +
    " adaptée dans " + c("wazuh-logtest") + ".",
    "Redémarrer le manager ; provoquer l'événement réel ; retrouver l'alerte dans le poste de commande.",
    "Choisir la règle la plus bavarde de la zone 4 et, si elle est légitime, la faire taire avec la recette B pour "
    "le seul cas en cause."],
   "les deux règles apparaissent dans logtest avec le bon identifiant et le bruit a disparu du classement.")

# =================================================================== 7
d.chapter("7. Ajuster les réglages",
          "Les réglages faits à l'installation se modifient en relançant l'étape correspondante : la valeur actuelle "
          "est proposée, seul ce que vous changez est modifié.")
code("""sudo -i
cd /opt/wazuh-bundle
bash install.sh --step 07          # exemple : destinataires et niveau des e-mails
bash install.sh --explain 07       # ce que fait l'étape, sans rien exécuter""")
table(["Je veux changer…", "Étape", "Remarque"], [
    ["Destinataires, niveau ou plafond des e-mails ; serveur d'envoi", "07", "Un e-mail de test est envoyé."],
    ["Numéros, niveau ou plafond des SMS", "08", "Un SMS de test est proposé."],
    ["Durées de conservation", "05", "Appliqué aussi aux données existantes."],
    ["Adresses jamais bloquées ; durée de blocage ; blocage on/off", "03", "—"],
    ["Répertoires analysés par YARA ; règles YARA supplémentaires ; source des hashes", "06",
     "Les règles sont compilées et testées avant distribution."],
    ["Fichiers et journaux surveillés par groupe", "03", "Après édition de " + c("configs/groups/") + " (chapitre 5)."],
    ["Mesures de sécurité SSH du serveur", "01", "Retour arrière possible."],
    ["Sauvegarde : dossier, durée", "10", "—"],
], [0.55, 0.08, 0.37])
box("info", "Une alerte trop fréquente se règle par une règle (chapitre 6, recette B), pas en relevant le seuil "
    "des e-mails : un seuil plus haut ferait aussi disparaître les alertes utiles.")
ex("changer un réglage",
   ["Relancer l'étape 07 et ajouter un destinataire.",
    "Vérifier la réception de l'e-mail de test par ce destinataire."],
   "l'étape se termine par « Alertes e-mail actives » avec la nouvelle liste.")

# =================================================================== 8
d.chapter("8. Garder la plateforme en forme",
          "Quelques gestes réguliers évitent la quasi-totalité des pannes.")
table(["Quand", "Geste", "Comment"], [
    ["Chaque semaine", "Vérifier la plateforme", c("bash install.sh --step 99") + " : 0 échec attendu."],
    ["Chaque semaine", "Lire les tâches de nuit", c("tail /var/log/wazuh-bundle/{malware,purge,backup}.log")],
    ["Chaque semaine", "Espace disque", c("df -h /var") + " : rester sous 80 %."],
    ["Chaque mois", "Copier une sauvegarde hors du serveur et vérifier qu'elle se lit", c("tar -tzf <archive>")],
    ["Chaque mois", "Revoir les règles bavardes (zone 4)", "Chapitre 6, recette B."],
    ["Chaque trimestre", "Mettre à jour Wazuh", "Ci-dessous."],
    ["Chaque trimestre", "Revoir comptes, destinataires, liste blanche", "Chapitre 7."],
    ["Chaque année", "Changer les mots de passe ; tester une restauration", "Ci-dessous."],
], [0.17, 0.4, 0.43])
h2("Tâches automatiques (rien à faire, mais savoir où regarder)")
table(["Heure", "Tâche", "Journal"], [
    ["02:30", "Sauvegarde de la configuration (" + c("/var/backups/wazuh/") + ")", c("/var/log/wazuh-bundle/backup.log")],
    ["03:30", "Mise à jour des empreintes de malwares et des règles YARA", c("/var/log/wazuh-bundle/malware.log")],
    ["04:15", "Suppression des fichiers d'alertes anciens", c("/var/log/wazuh-bundle/purge.log")],
    ["continu", "Suppression des données anciennes de la base", "Wazuh Dashboard &gt; Index Management"],
], [0.1, 0.5, 0.4])
h2("Mettre à jour Wazuh")
steps(["Lire les notes de version de la nouvelle version (documentation.wazuh.com).",
       "Lancer une sauvegarde : " + c("/usr/local/sbin/wazuh-bundle-backup") + ".",
       "Mettre à jour le <b>serveur d'abord</b>, en suivant le guide officiel « Upgrading central components ».",
       "Vérifier : " + c("bash install.sh --step 99") + ".",
       "Mettre à jour les machines ensuite, par lots :"])
code("""apt-mark unhold wazuh-agent
apt-get install -y wazuh-agent=<version>
apt-mark hold wazuh-agent""")
h2("Restaurer une configuration")
code("""A=/var/backups/wazuh/wazuh-config-<serveur>-<date>.tar.gz
tar -tzf "$A" | less                         # voir le contenu
systemctl stop wazuh-manager
tar -xzf "$A" -C / var/ossec/etc             # ex. : configuration Wazuh seule
systemctl start wazuh-manager && bash install.sh --step 99""")
h2("Changer un mot de passe")
table(["Mot de passe", "Procédure"], [
    ["Enrôlement des machines", "Supprimer la ligne " + c("AUTHD_PASSWORD") + " de " +
     c("/root/.wazuh-bundle/secrets.env") + " puis étape 03. Les machines déjà inscrites ne sont pas concernées."],
    ["admin de la base (indexer)", "Outil officiel " + c("wazuh-passwords-tool.sh") + " ; puis supprimer " +
     c("INDEXER_ADMIN_PASSWORD") + " de " + c("secrets.env") + " et relancer l'étape 02, qui le redemande."],
    ["Compte d'envoi e-mail, clé SMS", "Étape 07 ou 08 : accepter de remplacer le secret."],
    ["Comptes nominatifs", "Dans le Wazuh Dashboard et dans Grafana (chapitre 1)."],
], [0.28, 0.72])
ex("vérifier et sauvegarder",
   ["Lancer " + c("bash install.sh --step 99") + " et lire le résultat.",
    "Copier la sauvegarde la plus récente vers l'emplacement de sauvegarde de l'entreprise.",
    "Restaurer, sur une machine de test ou dans un dossier temporaire (" + c("-C /tmp/test") + "), le fichier " +
    c("var/ossec/etc/ossec.conf") + " de cette archive."],
   "la recette affiche 0 échec et vous savez retrouver un fichier de configuration d'une date donnée.")

# =================================================================== 9
d.chapter("9. Quand quelque chose ne va pas",
          "L'assistant explique toujours ce qui échoue ; ce tableau couvre ce qui peut arriver en dehors.")
table(["Symptôme", "Vérifier", "Solution"], [
    ["Plus aucune donnée dans Grafana ou le dashboard", c("systemctl status wazuh-indexer filebeat wazuh-manager"),
     "Redémarrer le service arrêté ; " + c("filebeat test output") + "."],
    ["Les données s'arrêtent et le disque est presque plein", c("df -h /var"),
     "Libérer de l'espace, réduire la conservation (étape 05), puis dans le Dashboard &gt; Dev Tools : " +
     c('PUT _all/_settings {"index.blocks.read_only_allow_delete": null}')],
    ["Une machine « Disconnected »", "Service et journal de l'agent (chapitre 4)", "Réseau 1514, service, version."],
    ["Plus d'e-mails", c("postqueue -p") + " ; " + c("journalctl -t postfix/smtp -n 30"),
     "Code 535 = mot de passe refusé ; relancer l'étape 07."],
    ["Plus de SMS", c("journalctl -u wazuh-sms-alerter -n 30"), "Clé, crédit, mode sandbox : étape 08."],
    ["Alerte 100512 (YARA)", "Message de l'alerte", "YARA absent ou machine hors du groupe feat-yara."],
    ["Liste de malwares non mise à jour", c("wazuh-bundle-update-malware --test-hashes"),
     "La cause est affichée (clé, adresse, réseau) : étape 06."],
    ["Le manager ne démarre plus après une modification", c("tail -30 /var/ossec/logs/ossec.log"),
     "Corriger la ligne indiquée, ou remettre la copie faite avant modification."],
    ["Un administrateur bloqué par la réponse active", "Alerte 651 avec son IP",
     "Attendre la fin du blocage ; ajouter l'IP à la liste blanche (étape 03)."],
], [0.28, 0.35, 0.37])
h2("Avant de demander de l'aide")
p("Rassembler ces éléments fait gagner un temps précieux à quiconque intervient (aucun mot de passe n'est inclus) :")
code("""sudo -i
cd /opt/wazuh-bundle && bash install.sh --step 99 > /root/diag-recette.txt 2>&1
tar -czf /root/diag-$(hostname)-$(date +%F).tar.gz /root/diag-recette.txt \\
    /var/log/wazuh-bundle /var/ossec/logs/ossec.log /var/ossec/etc/ossec.conf \\
    /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml""")
p("Joindre aussi : ce qui a changé récemment, l'heure du premier symptôme, une capture d'écran.")

# =================================================================== annexes
d.chapter("Annexe — Règles livrées",
          "Règles ajoutées à la plateforme lors de l'installation (fichiers bundle_*). Vos règles : 101000 à 101999.")
table(["ID", "Niv.", "Détecte"], [
    ["100500", "14", "Fichier dont l'empreinte est celle d'un malware connu"],
    ["100501-02", "3", "Fichier ajouté/modifié dans un répertoire analysé par YARA (lance l'analyse)"],
    ["100511", "12", "Malware détecté par YARA"], ["100512", "7", "Erreur du scanner YARA sur une machine"],
    ["100520", "12", "Windows : journal d'événements effacé"], ["100521", "12", "Windows : ajout à un groupe administrateur"],
    ["100522", "8", "Windows : nouveau service"], ["100523", "8", "Windows : tâche planifiée créée"],
    ["100524", "10", "Windows : politique d'audit modifiée"],
    ["100540", "12", "Windows Defender : menace détectée"], ["100541", "12", "Windows Defender : protection désactivée"],
    ["100551", "10", "Clé SSH autorisée ajoutée ou modifiée"], ["100552", "10", "Droits sudo modifiés"],
    ["100553", "8", "Tâche cron ajoutée ou modifiée"], ["100554", "8", "Nouveau service systemd"],
    ["100555", "10", "Comptes ou groupes modifiés (passwd, shadow, group)"],
    ["100556", "12", "/etc/ld.so.preload modifié (rootkit)"],
    ["100560", "8", "Connexion SSH du compte root"], ["100561", "10", "Connexion SSH de root hors heures ouvrables"],
    ["5712, 5763", "Wazuh", "Force brute SSH → blocage automatique de l'IP (alerte 651)"],
], [0.14, 0.1, 0.76])

d.chapter("Annexe — Aide-mémoire", "À imprimer et garder près du poste.")
code("""VÉRIFIER        bash /opt/wazuh-bundle/install.sh --step 99
MACHINES        /var/ossec/bin/agent_control -l
                /var/ossec/bin/agent_groups -s -i <ID>            groupes d'une machine
                /var/ossec/bin/agent_groups -a -i <ID> -g <groupe> -q
                /var/ossec/bin/manage_agents -r <ID>              retirer une machine
RÈGLES          nano /var/ossec/etc/rules/local_rules.xml         IDs 101000-101999
                nano /var/ossec/etc/decoders/local_decoder.xml
                /var/ossec/bin/wazuh-analysisd -t                 syntaxe
                /var/ossec/bin/wazuh-logtest                      tester une ligne
                systemctl restart wazuh-manager                   activer
RÉGLAGES        bash install.sh --step NN
                03 blocage/groupes  05 rétention  06 YARA  07 e-mail  08 SMS
SERVICES        systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat
JOURNAUX        tail -f /var/ossec/logs/ossec.log                 serveur Wazuh
                tail -f /var/ossec/logs/alerts/alerts.json        alertes en direct
                /var/log/wazuh-bundle/                            assistant et tâches de nuit
E-MAIL          postqueue -p ; journalctl -t postfix/smtp -n 30
SMS             journalctl -u wazuh-sms-alerter -n 30
SAUVEGARDES     /var/backups/wazuh/       /usr/local/sbin/wazuh-bundle-backup""")
h2("Recherches utiles (Wazuh Dashboard)")
code("""rule.level >= 12                                    incidents probables
rule.level >= 10 and agent.name : "srv-db01"        une machine
rule.id : 100511                                    malware YARA
data.srcip : "203.0.113.45"                         une adresse IP
rule.groups : authentication_failed                 échecs de connexion
syscheck.path : "/etc/sudoers"                      un fichier""")

# =================================================================== repères
d.chapter("Vos repères d'autonomie",
          "Chaque geste ci-dessous a été vu dans un exercice « À vous ». Cochez-le lorsque vous l'avez fait seul, "
          "sur votre plateforme : c'est le meilleur indicateur que l'exploitation est entre vos mains.")
gestes = [
    ("Lire le poste de commande et dire s'il faut agir", "2"),
    ("Retrouver une alerte dans Threat Hunting et lire ses champs", "3"),
    ("Qualifier une alerte : légitime, à investiguer, incident", "3"),
    ("Installer une machine Linux et une machine Windows, avec les bons groupes", "4"),
    ("Changer les groupes d'une machine ; retirer une machine", "4"),
    ("Diagnostiquer une machine « Disconnected »", "4"),
    ("Ajouter la surveillance d'un dossier ou d'un journal d'application", "5"),
    ("Écrire une règle, la valider et la tester avec wazuh-logtest", "6"),
    ("Faire taire un faux positif sans désactiver la règle", "6"),
    ("Écrire un décodeur pour une application", "6"),
    ("Modifier un réglage en relançant une étape (destinataires, rétention…)", "7"),
    ("Lancer la recette et interpréter le résultat", "8"),
    ("Retrouver et restaurer un fichier depuis une sauvegarde", "8"),
    ("Connaître la procédure de mise à jour de Wazuh", "8"),
    ("Rassembler les éléments de diagnostic avant de demander de l'aide", "9"),
]
table(["Geste", "Chap.", "Fait le", "Par"], [[g, ch, "", ""] for g, ch in gestes], [0.6, 0.08, 0.16, 0.16])
d.spacer(6)
table(["Contacts", ""], [["Référent interne", ""], ["Support du prestataire", ""],
                         ["Responsable sécurité (incident)", ""], ["Documentation Wazuh", "https://documentation.wazuh.com"]],
      [0.35, 0.65], zebra=False)

if __name__ == "__main__":
    d.build(OUT)
    print("PDF généré :", OUT)
