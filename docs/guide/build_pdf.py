#!/usr/bin/env python3
"""Génère docs/Guide_installation_passation_wazuh-bundle.pdf (guide d'installation + passation des connaissances).

    python3 docs/guide/build_pdf.py            (prérequis : python3-reportlab ; polices DejaVu si disponibles)

Le contenu est écrit ci-dessous : modifier ce fichier puis régénérer le PDF à chaque évolution du bundle.
"""
import os
import sys
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "Guide_installation_passation_wazuh-bundle.pdf")
VERSION = "3.0.0"
DOC_DATE = os.environ.get("GUIDE_DATE", date.today().strftime("%d/%m/%Y"))

# ------------------------------------------------------------------ polices
FONT_DIR = "/usr/share/fonts/truetype/dejavu"
try:
    pdfmetrics.registerFont(TTFont("Sans", f"{FONT_DIR}/DejaVuSans.ttf"))
    pdfmetrics.registerFont(TTFont("Sans-Bold", f"{FONT_DIR}/DejaVuSans-Bold.ttf"))
    pdfmetrics.registerFont(TTFont("Sans-Oblique", f"{FONT_DIR}/DejaVuSans-Oblique.ttf"))
    pdfmetrics.registerFont(TTFont("Mono", f"{FONT_DIR}/DejaVuSansMono.ttf"))
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans-Oblique", boldItalic="Sans-Bold")
    SANS, BOLD, MONO = "Sans", "Sans-Bold", "Mono"
except Exception:  # polices absentes : polices PDF standard
    SANS, BOLD, MONO = "Helvetica", "Helvetica-Bold", "Courier"

# ------------------------------------------------------------------ charte
NAVY = colors.HexColor("#1F3A5F")
TEAL = colors.HexColor("#2A7F8E")
LIGHT = colors.HexColor("#EEF3F8")
CODEBG = colors.HexColor("#F4F5F7")
GRID = colors.HexColor("#B8C4D2")
WARN_BG = colors.HexColor("#FFF6E0"); WARN_BD = colors.HexColor("#E0A800")
INFO_BG = colors.HexColor("#E8F4F6"); INFO_BD = TEAL
DANGER_BG = colors.HexColor("#FCEBEA"); DANGER_BD = colors.HexColor("#C0392B")

ST = {
    "body": ParagraphStyle("body", fontName=SANS, fontSize=9.5, leading=13.5, spaceAfter=5, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName=SANS, fontSize=8.2, leading=10.8),
    "cell": ParagraphStyle("cell", fontName=SANS, fontSize=8.2, leading=10.6),
    "cellb": ParagraphStyle("cellb", fontName=BOLD, fontSize=8.2, leading=10.6, textColor=colors.white),
    "h1": ParagraphStyle("h1", fontName=BOLD, fontSize=17, leading=21, textColor=NAVY, spaceBefore=4, spaceAfter=10),
    "h2": ParagraphStyle("h2", fontName=BOLD, fontSize=12.5, leading=16, textColor=NAVY, spaceBefore=12, spaceAfter=6),
    "h3": ParagraphStyle("h3", fontName=BOLD, fontSize=10.3, leading=13.5, textColor=TEAL, spaceBefore=8, spaceAfter=4),
    "part": ParagraphStyle("part", fontName=BOLD, fontSize=26, leading=32, textColor=NAVY, alignment=TA_LEFT),
    "bullet": ParagraphStyle("bullet", fontName=SANS, fontSize=9.5, leading=13.2, leftIndent=14, bulletIndent=4, spaceAfter=2),
    "code": ParagraphStyle("code", fontName=MONO, fontSize=8, leading=10.4),
    "toc1": ParagraphStyle("toc1", fontName=BOLD, fontSize=10, leading=15, leftIndent=0),
    "toc2": ParagraphStyle("toc2", fontName=SANS, fontSize=9, leading=12.5, leftIndent=16),
}
PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CONTENT_W = PAGE_W - 2 * MARGIN


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ------------------------------------------------------------------ éléments de contenu
story = []


def part(title, subtitle):
    story.append(NextPageTemplate("part"))
    story.append(PageBreak())
    story.append(Spacer(1, 7 * cm))
    p = Paragraph(title, ST["part"]); p._toc = (0, title); story.append(p)
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(subtitle, ParagraphStyle("ps", parent=ST["body"], fontSize=11.5, leading=16, textColor=TEAL)))
    story.append(NextPageTemplate("normal"))
    story.append(PageBreak())


def h1(t):
    story.append(CondPageBreak(5 * cm))
    p = Paragraph(t, ST["h1"]); p._toc = (1, t); story.append(p)


def h2(t):
    story.append(CondPageBreak(3.5 * cm))
    story.append(Paragraph(t, ST["h2"]))


def h3(t):
    story.append(CondPageBreak(2.5 * cm))
    story.append(Paragraph(t, ST["h3"]))


def p(t):
    story.append(Paragraph(t, ST["body"]))


def bullets(items):
    for it in items:
        story.append(Paragraph(it, ST["bullet"], bulletText="•"))
    story.append(Spacer(1, 3))


def numbered(items):
    for i, it in enumerate(items, 1):
        story.append(Paragraph(it, ST["bullet"], bulletText=f"{i}."))
    story.append(Spacer(1, 3))


def code(text):
    pre = Preformatted(text.strip("\n"), ST["code"])
    t = Table([[pre]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CODEBG), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                           ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.append(t); story.append(Spacer(1, 6))


def note(kind, text):
    bg, bd, label = {"info": (INFO_BG, INFO_BD, "À savoir"), "warn": (WARN_BG, WARN_BD, "Attention"),
                     "danger": (DANGER_BG, DANGER_BD, "Important")}[kind]
    t = Table([[Paragraph(f"<b>{label} :</b> {text}", ST["body"])]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3, bd),
                           ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    story.append(KeepTogether(t)); story.append(Spacer(1, 7))


def table(header, rows, widths, font=None):
    """widths : fractions de la largeur utile."""
    st = ST["cell"] if font is None else ParagraphStyle("c2", parent=ST["cell"], fontName=font)
    data = [[Paragraph(h, ST["cellb"]) for h in header]]
    for r in rows:
        data.append([c if not isinstance(c, str) else Paragraph(c, st) for c in r])
    t = Table(data, colWidths=[w * CONTENT_W for w in widths], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4),
             ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(style))
    story.append(t); story.append(Spacer(1, 8))


def c(s):
    """Fragment de code dans un paragraphe."""
    return f'<font face="{MONO}" size="8.3">{esc(s)}</font>'


# ------------------------------------------------------------------ schéma d'architecture
def architecture():
    W, H = CONTENT_W, 9.2 * cm
    d = Drawing(W, H)

    def box(x, y, w, h, title, lines, fill, stroke=NAVY, tcolor=colors.white):
        d.add(Rect(x, y, w, h, rx=5, ry=5, fillColor=fill, strokeColor=stroke, strokeWidth=0.8))
        d.add(String(x + w / 2, y + h - 13, title, fontName=BOLD, fontSize=8.6, fillColor=tcolor, textAnchor="middle"))
        for i, ln in enumerate(lines):
            d.add(String(x + w / 2, y + h - 26 - i * 10.5, ln, fontName=SANS, fontSize=7.3,
                         fillColor=tcolor, textAnchor="middle"))

    def arrow(x1, y1, x2, y2, label="", col=TEAL):
        d.add(Line(x1, y1, x2, y2, strokeColor=col, strokeWidth=1.2))
        import math
        a = math.atan2(y2 - y1, x2 - x1); s = 6
        d.add(Polygon([x2, y2, x2 - s * math.cos(a - 0.4), y2 - s * math.sin(a - 0.4),
                       x2 - s * math.cos(a + 0.4), y2 - s * math.sin(a + 0.4)], fillColor=col, strokeColor=col))
        if label:
            d.add(String((x1 + x2) / 2, (y1 + y2) / 2 + 4, label, fontName=SANS, fontSize=6.8,
                         fillColor=NAVY, textAnchor="middle"))

    # agents
    seg = [("Segment SERVEURS", ["agents Linux / Windows", "groupes seg-servers"]),
           ("Segment EMPLOYÉS", ["postes Windows / Linux", "groupes seg-employees"]),
           ("Segment DMZ", ["serveurs exposés", "groupes seg-dmz + feat-yara"])]
    for i, (t, ls) in enumerate(seg):
        box(0, H - 2.55 * cm - i * 2.95 * cm, 4.2 * cm, 2.3 * cm, t, ls, LIGHT, tcolor=NAVY)
        arrow(4.2 * cm, H - 1.4 * cm - i * 2.95 * cm, 6.3 * cm, H / 2 + 0.2 * cm - (i - 1) * 0.9 * cm,
              "1514 / 1515" if i == 0 else "")
    # serveur
    sx, sw = 6.3 * cm, 5.4 * cm
    d.add(Rect(sx, 0.35 * cm, sw, H - 0.7 * cm, rx=6, ry=6, fillColor=colors.white, strokeColor=NAVY, strokeWidth=1.2))
    d.add(String(sx + sw / 2, H - 0.85 * cm, "Serveur Wazuh (tout-en-un)", fontName=BOLD, fontSize=9,
                 fillColor=NAVY, textAnchor="middle"))
    box(sx + 0.3 * cm, H - 3.25 * cm, sw - 0.6 * cm, 2.0 * cm, "wazuh-manager",
        ["décodeurs, règles, réponse active", "ports 1514 / 1515"], NAVY)
    box(sx + 0.3 * cm, H - 5.55 * cm, sw - 0.6 * cm, 2.0 * cm, "wazuh-indexer (OpenSearch)",
        ["stockage des alertes, rétention", "port 9200 (127.0.0.1)"], TEAL)
    box(sx + 0.3 * cm, H - 7.85 * cm, sw - 0.6 * cm, 2.0 * cm, "wazuh-dashboard",
        ["interface web d'analyse", "port 443 (administration)"], colors.HexColor("#4A6FA5"))
    arrow(sx + sw / 2, H - 3.25 * cm, sx + sw / 2, H - 3.55 * cm)
    arrow(sx + sw / 2, H - 5.55 * cm, sx + sw / 2, H - 5.85 * cm)
    # sorties
    ox = 12.6 * cm; ow = W - ox
    outs = [("E-mail", ["Postfix local -> Gmail /", "SMTP entreprise / relais"]),
            ("SMS", ["Africa's Talking (443)", "dédoublonnage + plafond"]),
            ("Grafana (option)", ["local :3000 ou distant", "lecture seule grafana_ro"])]
    for i, (t, ls) in enumerate(outs):
        y = H - 2.55 * cm - i * 2.95 * cm
        box(ox, y, ow, 2.3 * cm, t, ls, LIGHT, tcolor=NAVY)
        arrow(sx + sw, y + 1.15 * cm, ox, y + 1.15 * cm)
    story.append(d)
    story.append(Paragraph("<i>Figure 1 — Architecture : trois segments, un serveur Wazuh, trois canaux d'alerte.</i>",
                           ParagraphStyle("cap", parent=ST["small"], alignment=TA_CENTER, textColor=NAVY)))
    story.append(Spacer(1, 8))


# ------------------------------------------------------------------ gabarits de page
class Doc(BaseDocTemplate):
    def __init__(self, fn):
        super().__init__(fn, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=2.2 * cm,
                         bottomMargin=2 * cm, title="wazuh-bundle — Guide d'installation et de passation",
                         author="wazuh-bundle", subject="SIEM Wazuh : installation, exploitation, passation")
        fr = Frame(MARGIN, 2 * cm, CONTENT_W, PAGE_H - 4.2 * cm, id="f")
        self.addPageTemplates([PageTemplate("cover", [fr], onPage=self.cover_page),
                               PageTemplate("normal", [fr], onPage=self.normal_page),
                               PageTemplate("part", [fr], onPage=self.part_page)])

    def afterFlowable(self, f):
        if hasattr(f, "_toc"):
            level, text = f._toc
            key = f"s{id(f)}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=False)
            self.notify("TOCEntry", (level, text, self.page, key))

    @staticmethod
    def cover_page(cv, doc):
        cv.saveState()
        cv.setFillColor(NAVY); cv.rect(0, PAGE_H - 9.5 * cm, PAGE_W, 9.5 * cm, fill=1, stroke=0)
        cv.setFillColor(TEAL); cv.rect(0, PAGE_H - 9.8 * cm, PAGE_W, 0.3 * cm, fill=1, stroke=0)
        cv.setFillColor(colors.white)
        cv.setFont(BOLD, 12); cv.drawString(MARGIN, PAGE_H - 2.6 * cm, "SIEM WAZUH — WAZUH-BUNDLE v" + VERSION)
        cv.setFont(BOLD, 27); cv.drawString(MARGIN, PAGE_H - 4.6 * cm, "Guide d'installation")
        cv.drawString(MARGIN, PAGE_H - 5.8 * cm, "et de passation des connaissances")
        cv.setFont(SANS, 11)
        cv.drawString(MARGIN, PAGE_H - 7.3 * cm, "Déploiement, exploitation et transmission du SIEM de l'entreprise")
        cv.drawString(MARGIN, PAGE_H - 7.95 * cm, "Segments SERVEURS · EMPLOYÉS · DMZ")
        cv.restoreState()

    @staticmethod
    def normal_page(cv, doc):
        cv.saveState()
        cv.setStrokeColor(GRID); cv.setLineWidth(0.5)
        cv.line(MARGIN, PAGE_H - 1.5 * cm, PAGE_W - MARGIN, PAGE_H - 1.5 * cm)
        cv.line(MARGIN, 1.4 * cm, PAGE_W - MARGIN, 1.4 * cm)
        cv.setFont(SANS, 7.5); cv.setFillColor(NAVY)
        cv.drawString(MARGIN, PAGE_H - 1.3 * cm, f"wazuh-bundle v{VERSION} — Guide d'installation et de passation")
        cv.drawRightString(PAGE_W - MARGIN, PAGE_H - 1.3 * cm, "Document interne — diffusion restreinte")
        cv.drawString(MARGIN, 1.0 * cm, f"Version du document : {VERSION} — {DOC_DATE}")
        cv.drawRightString(PAGE_W - MARGIN, 1.0 * cm, f"Page {doc.page}")
        cv.restoreState()

    @staticmethod
    def part_page(cv, doc):
        cv.saveState()
        cv.setFillColor(NAVY); cv.rect(0, 0, 1.2 * cm, PAGE_H, fill=1, stroke=0)
        cv.setFillColor(TEAL); cv.rect(1.2 * cm, 0, 0.15 * cm, PAGE_H, fill=1, stroke=0)
        cv.restoreState()


# =================================================================== CONTENU
# ---------- couverture
story.append(Spacer(1, 9.2 * cm))
cover_rows = [
    ["Entreprise", ""], ["Serveur Wazuh (nom / IP)", ""], ["Rédigé par (cédant)", ""],
    ["Destinataire (repreneur)", ""], ["Date de la passation", ""],
    ["Version du bundle", f"wazuh-bundle v{VERSION} — Wazuh 4.14 — YARA 4.5.8"],
    ["Classification", "Interne — diffusion restreinte (décrit l'architecture de sécurité)"],
]
t = Table([[Paragraph(f"<b>{a}</b>", ST["cell"]), Paragraph(b, ST["cell"])] for a, b in cover_rows],
          colWidths=[5.2 * cm, CONTENT_W - 5.2 * cm], rowHeights=[0.85 * cm] * len(cover_rows))
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, GRID), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
story.append(t)
story.append(Spacer(1, 0.8 * cm))
story.append(Paragraph("<b>Suivi des versions du document</b>", ST["body"]))
t = Table([[Paragraph(h, ST["cellb"]) for h in ["Version", "Date", "Auteur", "Modifications"]],
           [Paragraph(VERSION, ST["cell"]), Paragraph(DOC_DATE, ST["cell"]), Paragraph("", ST["cell"]),
            Paragraph("Création : installation v3, exploitation, passation", ST["cell"])],
           ["", "", "", ""], ["", "", "", ""]],
          colWidths=[2 * cm, 2.6 * cm, 4 * cm, CONTENT_W - 8.6 * cm], rowHeights=[None, None, 0.7 * cm, 0.7 * cm])
t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.5, GRID)]))
story.append(t)
story.append(Spacer(1, 0.6 * cm))
story.append(Paragraph("Les cases vides sont à compléter lors de la passation. Ce document ne contient aucun mot de passe : "
                       "les secrets sont dans le coffre de l'entreprise et sur le serveur (voir § 11).", ST["small"]))

# ---------- sommaire
story.append(NextPageTemplate("normal"))
story.append(PageBreak())
story.append(Paragraph("Sommaire", ST["h1"]))
toc = TableOfContents(levelStyles=[ST["toc1"], ST["toc2"]], dotsMinLevel=0)
story.append(toc)

# =================================================================== PARTIE A
part("Partie A — Comprendre", "Ce que fait le système, comment il est construit, et les principes du bundle.")

h1("1. Objet du document")
p("Ce document accompagne le <b>wazuh-bundle v3</b>, l'assistant qui installe et configure le SIEM Wazuh de "
  "l'entreprise. Il a trois usages :")
bullets(["<b>Installer</b> : dérouler l'installation du serveur et des agents, étape par étape (Partie B) ;",
         "<b>Exploiter</b> : savoir où se trouve chaque élément, quelles tâches tournent seules, comment réagir à un "
         "incident ou à une panne (Partie C) ;",
         "<b>Transmettre</b> : organiser la passation entre la personne qui a installé le système et celle qui le "
         "reprend, avec une fiche signée (Annexe B)."])
p("Public visé : administrateur système ou réseau, analyste SOC. Aucune connaissance préalable de Wazuh ou de YARA "
  "n'est nécessaire ; un glossaire figure en Annexe A.")
note("info", "Le dépôt contient aussi une documentation de référence plus détaillée : " + c("README.md") + ", " +
     c("RECETTE.md") + ", " + c("docs/REGLES.md") + " (règles de détection) et " + c("docs/YARA.md") +
     " (détection de malwares). Ce guide en fait la synthèse.")

h1("2. Architecture")
p("Le SIEM (« Security Information and Event Management ») centralise les événements de sécurité des machines de "
  "l'entreprise, les analyse avec des règles et produit des <b>alertes</b>. L'entreprise est organisée en trois "
  "segments réseau ; chaque machine surveillée exécute un <b>agent</b> Wazuh qui envoie ses événements au serveur.")
architecture()
table(["Composant", "Rôle", "Port(s)", "Service"], [
    ["wazuh-manager", "Reçoit les événements, applique décodeurs et règles, déclenche les réponses actives et "
                      "les e-mails, pousse la configuration aux agents (groupes).", "1514, 1515, 55000 (API)",
     c("wazuh-manager")],
    ["wazuh-indexer", "Base de données des alertes (OpenSearch). Supprime les données anciennes selon la "
                      "politique de rétention.", "9200", c("wazuh-indexer")],
    ["wazuh-dashboard", "Interface web : recherche, tableaux de bord, inventaire, vulnérabilités.", "443",
     c("wazuh-dashboard")],
    ["filebeat", "Transfère les alertes du manager vers l'indexer.", "—", c("filebeat")],
    ["Postfix (option)", "Relais local (127.0.0.1) des e-mails d'alerte vers Gmail / SMTP / relais.", "25 local",
     c("postfix")],
    ["wazuh-sms-alerter (option)", "Envoie les alertes critiques par SMS.", "—", c("wazuh-sms-alerter")],
    ["Grafana (option)", "Écran de supervision « Wazuh — Vue SOC ».", "3000", c("grafana-server")],
    ["Agent Wazuh", "Sur chaque machine : journaux, intégrité des fichiers (FIM), inventaire, réponse active, YARA.",
     "client", c("wazuh-agent") + " / WazuhSvc"],
], [0.2, 0.47, 0.15, 0.18])

h2("2.1 Les groupes d'agents")
p("Un agent appartient à plusieurs <b>groupes</b>. Le manager envoie à chaque agent la configuration de tous ses "
  "groupes : il n'y a rien à configurer sur les machines elles-mêmes.")
table(["Famille", "Groupes", "Ce que le groupe apporte"], [
    ["Segment", "seg-servers, seg-employees, seg-dmz", "Fréquence du contrôle d'intégrité : 6 h, 12 h, 2 h."],
    ["Système", "os-linux, os-windows", "Fichiers sensibles surveillés (/etc, clés SSH, cron…), journaux "
                                        "(auth.log, journaux Sécurité/Système/Defender de Windows)."],
    ["Rôle", "role-web, role-db, role-admin", "Configuration et journaux du serveur web, de la base de données, "
                                               "fichiers d'administration."],
    ["Options", "feat-yara, opt-whodata", "Analyse de malwares YARA (généré par l'étape 06) ; « qui a modifié » "
                                          "(audit détaillé)."],
], [0.14, 0.3, 0.56])

h1("3. Contenu du bundle")
table(["Emplacement", "Contenu"], [
    [c("install.sh"), "Assistant : menu, " + c("--step NN") + ", " + c("--all") + ", " + c("--explain NN") + ", " +
     c("--flows") + ", " + c("--non-interactive") + "."],
    [c("steps/00…10, 99"), "Les étapes d'installation, une par fichier (voir § 7)."],
    [c("lib/common.sh"), "Fonctions communes : exécution explicite (" + c("run") + "), questions (" + c("ask") +
     "), secrets, validation et redémarrage de Wazuh."],
    [c("lib/ossec_conf.py"), "Modification contrôlée et idempotente de " + c("ossec.conf") + " (blocs balisés)."],
    [c("lib/email.sh"), "Paramètres Postfix des trois modes d'envoi."],
    [c("tools/"), "Outils installés sur le serveur : mise à jour malware, purge, sauvegarde, installation de YARA."],
    [c("agents/"), "Installation des agents Linux et Windows ; script d'analyse YARA de l'agent."],
    [c("configs/"), "Règles et décodeurs, groupes d'agents, règles YARA, dashboard Grafana, service SMS."],
    [c("grafana/provision.sh"), "Déclaration de la source de données et des tableaux de bord dans Grafana."],
    [c("docs/"), "Documentation de référence et ce guide (" + c("docs/guide/build_pdf.py") + " le régénère)."],
    [c("tests/run_tests.sh"), "Tests automatiques (sans Wazuh), lancés aussi par GitHub Actions."],
], [0.28, 0.72])

h1("4. Principes de fonctionnement du bundle")
h3("Aucun fichier à éditer : des questions")
p("Chaque étape pose ses questions avec une valeur par défaut, vérifie la réponse (format d'IP, d'e-mail, plage de "
  "valeurs…) et explique le choix. Les réponses sont mémorisées dans " + c("/etc/wazuh-bundle/answers.env") +
  " (root, 600) : à la relance, la réponse précédente est proposée. Ce fichier est <b>généré</b> ; pour changer une "
  "valeur, on relance l'étape concernée.")
h3("Chaque commande est visible ; un échec arrête l'étape")
code("""> Test de connexion à l'indexer
  $ indexer_api GET /
  | curl: (7) Failed to connect to 127.0.0.1 port 9200: Connection refused
  x ÉCHEC (code retour 7) : Test de connexion à l'indexer
  Diagnostic : connexion refusée : le service distant n'écoute pas sur ce port
  Piste : Mot de passe admin incorrect, ou indexer arrêté (systemctl status wazuh-indexer).
[ERREUR] Arrêt de l'étape : … Corriger la cause puis relancer l'étape (elle est rejouable).""")
p("<i>(À l'écran, les symboles sont ▶ pour le but, │ pour la sortie, ✔ réussi / ✘ échec, en couleur.)</i>")
p("Le but, la commande, la sortie et le code retour sont affichés. En cas d'échec, un diagnostic automatique "
  "reconnaît les causes courantes (DNS, réseau, certificat, apt, authentification, SMTP…) et l'étape s'arrête. Tout "
  "est journalisé dans " + c("/var/log/wazuh-bundle/install-AAAAMMJJ-HHMMSS.log") + ".")
h3("Modifications de Wazuh validées, puis restaurées en cas de problème")
numbered(["sauvegarde horodatée de " + c("ossec.conf") + " (" + c("ossec.conf.bak.AAAAMMJJ-HHMMSS") + ") ;",
          "modification par <b>blocs balisés</b> " + c("<!-- wazuh-bundle:BEGIN nom -->") + " … " +
          c("<!-- wazuh-bundle:END nom -->") + " : une relance remplace le bloc, jamais de doublon ;",
          "validation par Wazuh lui-même (" + c("wazuh-analysisd -t") + ", remoted, authd, execd) <b>avant</b> "
          "redémarrage ;",
          "redémarrage puis vérification réelle que les démons tournent ; sinon extrait d'" + c("ossec.log") +
          " et restauration automatique."])
h3("Pas de pare-feu : un tableau des flux")
p("Le bundle ne configure aucun pare-feu : l'entreprise administre le sien. " + c("bash install.sh --flows") +
  " produit le tableau des flux à autoriser (§ 6).")

# =================================================================== PARTIE B
part("Partie B — Installer", "Préparer, installer le serveur étape par étape, installer les agents, recetter.")

h1("5. Prérequis et informations à réunir")
h2("5.1 Serveur")
table(["Élément", "Minimum", "Recommandé (production)"], [
    ["Système", "Debian 12/13, Ubuntu 22.04/24.04 (64 bits)", "Installation neuve, dédiée au SIEM"],
    ["Processeur", "2 cœurs", "4 cœurs ou plus"],
    ["Mémoire", "4 Go", "8 Go ou plus (16 Go au-delà de ~100 agents)"],
    ["Disque " + c("/var"), "30 Go libres", "100 Go ou plus (selon la rétention, § 15)"],
    ["Réseau", "<b>Adresse IP fixe</b>", "IP fixe + nom DNS"],
    ["Heure", "Synchronisée (NTP)", "chrony ou systemd-timesyncd actif"],
    ["Accès sortant", "HTTPS vers packages.wazuh.com", "+ github.com, abuse.ch, serveur SMTP, API SMS"],
], [0.2, 0.36, 0.44])
h2("5.2 Informations à préparer avant de commencer")
p("Réunir ces informations évite d'interrompre l'installation. Les secrets ne sont saisis qu'au clavier, en saisie "
  "masquée.")
table(["Information", "Étape", "Auprès de"], [
    ["IP fixe du serveur Wazuh", "00", "équipe réseau"],
    ["IP / réseaux des postes d'administration", "00", "équipe réseau"],
    ["IP à ne jamais bloquer : passerelles, DNS, scanners, supervision", "03", "équipe réseau"],
    ["Choix : indexer local (127.0.0.1) ou exposé (Grafana sur une autre machine)", "02", "décision projet"],
    ["Durées de conservation des alertes", "05", "RSSI / juridique"],
    ["Clé Auth-Key abuse.ch (gratuite : auth.abuse.ch)", "06", "à créer"],
    ["E-mail : compte Gmail + mot de passe d'application, <b>ou</b> serveur SMTP + compte, <b>ou</b> relais "
     "autorisant l'IP du serveur ; adresses destinataires", "07", "messagerie"],
    ["SMS : identifiant + clé API Africa's Talking, numéros (+241…)", "08", "compte Africa's Talking"],
    ["Grafana : local, ou IP de la machine Grafana existante", "09", "décision projet"],
    ["Dossier et durée des sauvegardes ; cible de copie hors serveur", "10", "équipe sauvegarde"],
], [0.68, 0.08, 0.24])

h1("6. Flux réseau à faire ouvrir")
p("À transmettre à l'équipe pare-feu <b>avant</b> l'installation des agents. La commande " +
  c("bash install.sh --flows") + " affiche ce tableau avec les adresses réelles.")
table(["Source", "Destination", "Port", "Rôle"], [
    ["Tous les agents (3 segments)", "serveur Wazuh", "TCP 1514", "événements des agents"],
    ["Tous les agents (3 segments)", "serveur Wazuh", "TCP 1515", "enrôlement (inscription) des agents"],
    ["Postes d'administration", "serveur Wazuh", "TCP 443", "Wazuh Dashboard"],
    ["Postes d'administration", "serveur Wazuh", "TCP 22", "administration SSH"],
    ["Postes d'administration", "serveur Wazuh", "TCP 3000", "Grafana local (si choisi)"],
    ["Machine Grafana distante", "serveur Wazuh", "TCP 9200", "indexer — <b>uniquement</b> cette machine"],
    ["Serveur Wazuh", "Internet", "TCP 443", "paquets, GitHub (YARA), abuse.ch, API SMS"],
    ["Serveur Wazuh", "serveur SMTP", "TCP 587 / 465 / 25", "alertes e-mail"],
], [0.27, 0.18, 0.18, 0.37])
note("danger", "Ne <b>jamais</b> ouvrir les ports 9200 (indexer) et 55000 (API Wazuh) depuis les segments EMPLOYÉS "
     "et DMZ.")
note("info", "La <b>réponse active</b> (étape 03) n'est pas un pare-feu d'entreprise : elle bloque temporairement "
     "une IP attaquante dans le pare-feu <i>local</i> de l'agent attaqué, puis la débloque automatiquement.")

h1("7. Installation du serveur, étape par étape")
p("En root, sur le serveur :")
code("""sudo -i
apt-get update && apt-get install -y git
git clone <URL-du-dépôt> /opt/wazuh-bundle
cd /opt/wazuh-bundle
git checkout v3.0.0          # en production : toujours un tag testé
bash install.sh              # menu ; ou : bash install.sh --all""")
note("warn", "Ne pas exécuter le bundle par " + c("curl … | sudo bash") + " : les scripts tournent en root, il "
     "faut pouvoir relire le code. Avant de lancer une étape, " + c("bash install.sh --explain NN") +
     " décrit ce qu'elle fait sans rien exécuter.")
p("Chaque étape ci-dessous indique son but, les questions posées et la vérification à faire. Les étapes sont "
  "<b>rejouables</b> : en cas d'échec, corriger la cause indiquée puis relancer " + c("bash install.sh --step NN") + ".")


def step(num, title, but, questions, verif, extra=None):
    h2(f"Étape {num} — {title}")
    p("<b>But :</b> " + but)
    if questions:
        table(["Question posée", "Défaut", "Conseil"], questions, [0.46, 0.14, 0.40])
    if extra:
        extra()
    p("<b>Vérification :</b> " + verif)


step("00", "Préflight", "contrôler la machine (OS, mémoire, disque, ports libres, accès Internet, horloge) et "
     "enregistrer les informations de base. Ne modifie rien.",
     [["Adresse IP fixe de ce serveur", "IP détectée", "Doit être fixe : agents et certificats en dépendent."],
      ["IP/CIDR des postes d'administration", "—", "Ex. " + c("10.10.10.50/32 10.10.10.51/32") + "."]],
     "message « Préflight OK ». Un point bloquant (ERREUR) arrête l'étape ; un point recommandé (WARN) demande "
     "confirmation.")
step("01", "Durcissement SSH (optionnel)", "réduire le risque sur l'accès d'administration. Sept mesures, "
     "chacune expliquée et proposée séparément, écrites dans " + c("/etc/ssh/sshd_config.d/00-wazuh-bundle.conf") + ".",
     [["Connexion de root", "inchangé", c("no") + " si un compte sudo nominatif fonctionne."],
      ["Clés SSH uniquement", "non", "Proposé seulement si un compte sudo possède une clé."],
      ["MaxAuthTries 4 / LoginGraceTime 30", "oui", "Risque très faible."],
      ["Mots de passe vides interdits", "oui", "Valeur par défaut rendue explicite."],
      ["X11Forwarding no", "oui", "Inutile sur un SIEM."],
      ["Déconnexion après 10 min sans réponse", "oui", "Utiliser tmux pour les tâches longues."],
      ["Liste des comptes autorisés (AllowUsers)", "non", "Risque élevé ; le script refuse une liste sans "
                                                          "votre compte."]],
     "<b>ouvrir une nouvelle session SSH et vérifier sudo AVANT de fermer la session en cours.</b> Retour arrière : "
     "relancer l'étape et choisir « supprimer ».")
step("02", "Installation de Wazuh", "installer manager, indexer et dashboard avec l'assistant officiel " + c("wazuh-install.sh") + " (branche 4.14), puis ranger les mots de passe générés.",
     [["Branche de Wazuh", "4.14", "Rester sur la branche validée."],
      ["Adresse d'écoute de l'indexer", "local (127.0.0.1)", "« réseau » uniquement pour un Grafana installé sur "
                                                           "une autre machine."]],
     "services " + c("wazuh-manager") + ", " + c("wazuh-indexer") + ", " + c("wazuh-dashboard") + " actifs ; "
     "connexion à l'indexer réussie ; dashboard accessible en " + c("https://IP-du-serveur") + " (utilisateur " + c("admin") + ", mot de passe dans " + c("/root/.wazuh-bundle/wazuh-passwords.txt") + "). Copier ce fichier "
     "dans le coffre-fort de l'entreprise.")
step("03", "Configuration du manager", "protéger l'enrôlement des agents par mot de passe, définir la liste "
     "blanche, activer la réponse active contre la force brute SSH, créer les groupes d'agents.",
     [["Mot de passe d'enrôlement", "générer", "Aléatoire, 24 caractères ; conservé dans le coffre du bundle."],
      ["IP supplémentaires à ne jamais bloquer", "—", "Passerelles, DNS, scanners, supervision."],
      ["Blocage automatique des IP qui forcent SSH", "oui", "Règles 5712 et 5763 ; blocage sur l'agent."],
      ["Durée du blocage (s)", "600", "10 minutes."]],
     "« Manager configuré » ; " + c("/var/ossec/bin/agent_groups -l") + " liste les groupes. Relancée, l'étape "
     "affiche « bloc … inchangé » (aucun doublon).")
step("04", "Règles de détection", "déployer les règles du bundle (§ 14) et les tester automatiquement avec " + c("wazuh-logtest") + ".", None,
     "« test(s) de règles réussi(s) ». En cas de refus par Wazuh, l'état précédent est restauré.")
step("05", "Politique de rétention", "supprimer automatiquement les données anciennes dans l'indexer (politiques "
     "ISM) et sur le disque du manager (purge quotidienne).",
     [["Alertes dans l'indexer (jours)", "90", "Couvrir le délai de détection d'un incident."],
      ["Archives dans l'indexer (jours)", "30", "Si l'archivage de tous les événements est activé."],
      ["Statistiques internes (jours)", "30", "—"],
      ["Fichiers d'alertes compressés sur disque (jours)", "180", "Preuves ré-importables, ~10× plus compactes."],
      ["Fichiers d'archives sur disque (jours)", "30", "—"]],
     c("cat /etc/wazuh-bundle/RETENTION.txt") + " ; Dashboard &gt; Index Management &gt; Policies : trois "
     "politiques " + c("wazuh-bundle-*") + ".")
step("06", "Détection de malwares (YARA + hashes)", "installer YARA 4.5.8 (code source officiel, identité "
     "vérifiée), configurer l'analyse des fichiers déposés sur les agents et la comparaison avec la liste "
     "d'empreintes abuse.ch, planifier la mise à jour quotidienne, tester avec EICAR.",
     [["Activer YARA / la liste de hashes", "oui / oui", "Les deux sont complémentaires (§ 14)."],
      ["Méthode d'installation de YARA", "source", "« package » si pas de compilateur ni d'accès GitHub."],
      ["Répertoires en temps réel", "/var/www /tmp /var/tmp /dev/shm", "Petits répertoires exposés."],
      ["Répertoires planifiés", "/home", "Gros répertoires."],
      ["Taille maximale analysée (Mo)", "100", "—"],
      ["Sources de règles supplémentaires (URL)", "aucune", "Chaque fichier est compilé avant d'être accepté."],
      ["Clé Auth-Key abuse.ch", "—", "Sans clé, le téléchargement peut être refusé."]],
     "test EICAR et test " + c("wazuh-logtest") + " réussis ; " + c("/var/log/wazuh-bundle/malware.log") + ".")
step("07", "Alertes e-mail", "envoyer les alertes importantes par e-mail via un Postfix local (127.0.0.1) qui "
     "relaie vers le serveur choisi. Wazuh ne sait pas, seul, chiffrer ni s'authentifier.",
     [["Mode d'envoi", "entreprise", "gmail / entreprise / relais (tableau ci-dessous)."],
      ["Destinataires", "—", "Une ou plusieurs adresses (liste de diffusion SOC recommandée)."],
      ["Niveau minimal envoyé", "10", "10 = suspect ; 12 = incident probable."],
      ["E-mails maximum par heure", "30", "Au-delà, Wazuh regroupe."]],
     "l'étape teste la connexion TCP, le chiffrement TLS, puis envoie un vrai e-mail et attend " +
     c("status=sent") + ". Vérifier la réception (et le dossier spam).",
     extra=lambda: table(["Mode", "Serveur / port", "Sécurité", "À préparer"], [
         ["gmail", "smtp.gmail.com : 587", "STARTTLS + certificat vérifié + authentification",
          "Compte Gmail dédié, validation en 2 étapes, <b>mot de passe d'application</b> (16 caractères) créé sur "
          "myaccount.google.com/apppasswords. Limite ~500 e-mails/jour."],
         ["entreprise", "au choix : 587 (STARTTLS) ou 465 (SMTPS)", "TLS vérifié, ou « encrypt » si CA interne ; "
                                                                    "authentification optionnelle",
          "Nom du serveur, port, compte d'envoi, adresse d'expéditeur autorisée."],
         ["relais", "relais interne : 25", "TLS opportuniste ; pas d'authentification",
          "Le relais doit <b>autoriser l'IP du serveur Wazuh</b>."],
     ], [0.11, 0.21, 0.3, 0.38]))
step("08", "Alertes SMS (optionnel)", "envoyer les alertes critiques par SMS (Africa's Talking) via un service "
     "dédié, avec dédoublonnage et plafond horaire.",
     [["Nom d'utilisateur", "sandbox", "« sandbox » = test, aucun SMS livré."],
      ["Clé API", "—", "Saisie masquée."],
      ["Numéros", "—", "Format international : +241XXXXXXXX."],
      ["Niveau minimal", "12", "Réserver les SMS aux incidents probables."],
      ["SMS max / heure ; dédoublonnage (s)", "20 ; 300", "—"]],
     "service " + c("wazuh-sms-alerter") + " actif ; SMS de test reçu (hors sandbox).")
step("09", "Grafana (optionnel)", "écran de supervision « Wazuh — Vue SOC », alimenté par l'indexer via un "
     "utilisateur en <b>lecture seule</b> (" + c("grafana_ro") + ").",
     [["Mettre en place Grafana ?", "non", "Le Wazuh Dashboard suffit pour l'analyse."],
      ["Emplacement", "local", "« remote » : génère un kit à installer sur la machine Grafana existante "
                               "(exige l'indexer en mode « réseau » à l'étape 02)."]],
     "local : " + c("http://IP:3000") + " ; distant : le kit termine par « Indexer joignable ».")
step("10", "Sauvegarde de la configuration", "archiver chaque nuit la configuration (Wazuh, certificats, réponses "
     "et secrets du bundle, Postfix, SSH, Grafana) pour pouvoir reconstruire le serveur.",
     [["Dossier des sauvegardes", "/var/backups/wazuh", "Droits 700 (contient des secrets)."],
      ["Conservation (jours)", "14", "—"]],
     "archive du jour dans le dossier. <b>Mettre en place une copie chiffrée hors du serveur.</b>")
step("99", "Recette automatique", "vérifier en lecture seule tout ce qui a été configuré : services, ports, "
     "configuration, règles (rejouées), indexer, rétention, malware, e-mail, sauvegarde, agents.", None,
     "« Résultat : N OK, N avertissement(s), 0 échec(s) ». Chaque échec indique l'étape à relancer.")

h1("8. Installation des agents")
h2("8.1 Agent Linux (Debian/Ubuntu)")
p("Copier le bundle sur la machine (ou le cloner), puis lancer le script en root. Toutes les informations "
  "manquantes sont demandées : IP du manager, segment, rôle, nom, version, YARA, whodata, mot de passe d'enrôlement.")
code("""sudo bash agents/install_agent_linux.sh            # interactif

# automatisé (exemple : serveur web en DMZ)
sudo bash agents/install_agent_linux.sh --manager-ip 10.10.10.20 --segment dmz \\
     --role web --name dmz-web01 --version 4.14.9-1 --yara --password-file /root/pw""")
bullets(["La version de l'agent doit être <b>inférieure ou égale</b> à celle du manager (" +
         c("dpkg-query -W wazuh-manager") + " sur le serveur).",
         "Mot de passe d'enrôlement, sur le serveur : " + c("grep AUTHD_PASSWORD /root/.wazuh-bundle/secrets.env") + ".",
         "Le paquet est bloqué (" + c("apt-mark hold") + ") : le manager est toujours mis à jour en premier.",
         "Machine sans Internet : " + c("--deb-path wazuh-agent_<version>_amd64.deb") + "."])
h2("8.2 Agent Windows")
p("PowerShell <b>en administrateur</b> :")
code(""".\\install_agent_windows.ps1 -ManagerIP 10.10.10.20 -Segment employees `
    -AgentName PC-COMPTA-01 -Version 4.14.9-1   # -Whodata, -MsiPath, -Sha256 en option""")
p("Pour les règles Windows du bundle, activer par GPO l'audit « Création du processus » (4688) et « Autres "
  "événements d'accès aux objets » (4698).")
h2("8.3 Vérifier un agent")
code("""/var/ossec/bin/agent_control -l            # liste et état des agents (sur le serveur)
/var/ossec/bin/agent_groups -s -i 005     # groupes de l'agent 005
tail -f /var/ossec/logs/ossec.log         # sur l'agent : « Connected to the server »""")

h1("9. Recette")
p("Après l'installation, dérouler le plan de recette (" + c("RECETTE.md") + ") et consigner le résultat. Tests "
  "essentiels :")
table(["#", "Test", "Action", "Résultat attendu"], [
    ["1", "Recette serveur", c("bash install.sh --step 99"), "0 échec"],
    ["2", "Agents", "Installer un agent par segment", "« Agent … connecté »"],
    ["3", "Intégrité", "Agent Linux : " + c("echo x >> /etc/sudoers.d/test") + " puis supprimer", "Alerte 100552"],
    ["4", "YARA", "Agent feat-yara : fichier EICAR dans /tmp", "Alerte 100511 (niveau 12)"],
    ["5", "Defender", "Fichier EICAR sur un poste Windows", "Alerte 100540"],
    ["6", "Force brute", "6 échecs SSH depuis une IP non whitelistée", "Alerte 5763, IP bloquée 10 min"],
    ["7", "Liste blanche", "Même test depuis une IP whitelistée", "Aucun blocage"],
    ["8", "E-mail / SMS", "Déclencher le test 4", "E-mail (et SMS) reçus"],
    ["9", "Rétention", c("cat /etc/wazuh-bundle/RETENTION.txt"), "Durées choisies"],
    ["10", "Redémarrage", c("reboot") + " puis étape 99", "0 échec"],
], [0.05, 0.16, 0.45, 0.34])
p("Fichier EICAR (inoffensif, reconnu par tous les antivirus) :")
code("""printf '%s' 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \\
    > /tmp/eicar.txt""")

# =================================================================== PARTIE C
part("Partie C — Exploiter et transmettre", "Routines, emplacements, opérations courantes, dépannage, règles, "
     "rétention et sécurité.")

h1("10. Routines d'exploitation")
table(["Fréquence", "Action", "Comment"], [
    ["Chaque jour", "Examiner les alertes de niveau ≥ 10", "Dashboard &gt; Threat Hunting (filtre rule.level ≥ 10)."],
    ["Chaque jour", "Vérifier que les agents sont connectés", c("/var/ossec/bin/agent_control -l") +
     " ; Dashboard &gt; Agents."],
    ["Chaque semaine", "Lancer la recette", c("bash install.sh --step 99") + " : 0 échec attendu."],
    ["Chaque semaine", "Lire les journaux des tâches planifiées", c("tail /var/log/wazuh-bundle/{malware,purge,backup}.log")],
    ["Chaque semaine", "Contrôler l'espace disque", c("df -h /var") + " : rester sous 80 %."],
    ["Chaque mois", "Copier une sauvegarde hors serveur et tester sa lecture", c("tar -tzf <archive>")],
    ["Chaque mois", "Revoir les faux positifs ; ajuster les règles", "docs/REGLES.md, étape 04."],
    ["Chaque trimestre", "Mettre à jour Wazuh (manager puis agents)", "§ 13.6."],
    ["Chaque trimestre", "Revoir les comptes, la liste blanche, les destinataires", "Étapes 03, 07, 08."],
    ["Chaque année", "Changer les mots de passe (indexer, enrôlement, SMTP)", "§ 13.7."],
], [0.15, 0.4, 0.45])

h1("11. Où trouver quoi")
table(["Élément", "Emplacement", "Remarque"], [
    ["Réponses aux questions", c("/etc/wazuh-bundle/answers.env"), "root 600 — généré, ne pas éditer"],
    ["Secrets du bundle", c("/root/.wazuh-bundle/secrets.env"), "root 600 — indexer, enrôlement, SMTP, "
                                                                 "abuse.ch, SMS, Grafana"],
    ["Mots de passe Wazuh", c("/root/.wazuh-bundle/wazuh-passwords.txt"), "root 600 — à copier dans le coffre"],
    ["Certificats d'installation", c("/root/.wazuh-bundle/wazuh-install-files.tar"), "root 600"],
    ["Politique de rétention", c("/etc/wazuh-bundle/RETENTION.txt"), "lisible"],
    ["Journaux du bundle", c("/var/log/wazuh-bundle/"), "installation, malware, purge, sauvegarde"],
    ["Configuration Wazuh", c("/var/ossec/etc/ossec.conf"), "blocs du bundle balisés"],
    ["Règles du bundle", c("/var/ossec/etc/rules/bundle_*.xml"), "source : configs/manager/"],
    ["Configuration des groupes", c("/var/ossec/etc/shared/<groupe>/agent.conf"), "source : configs/groups/"],
    ["Liste de hashes", c("/var/ossec/etc/lists/malware-sha256"), "mise à jour chaque nuit"],
    ["Règles YARA distribuées", c("/var/ossec/etc/shared/feat-yara/yara_rules.yar"), "mise à jour chaque nuit"],
    ["Journal du manager", c("/var/ossec/logs/ossec.log"), "erreurs de démarrage"],
    ["Alertes (fichiers)", c("/var/ossec/logs/alerts/"), "purgées selon la rétention"],
    ["Sauvegardes", c("/var/backups/wazuh/"), "par défaut ; root 700"],
    ["Paramètres SMS", c("/etc/wazuh-bundle/sms.env"), "root:wazuh 640 — contient la clé API"],
], [0.25, 0.43, 0.32])
note("danger", "Les fichiers de secrets et les sauvegardes donnent accès à toute la sécurité de l'entreprise : ne "
     "jamais les copier sur un poste personnel, dans un e-mail ou dans Git.")

h1("12. Tâches planifiées")
table(["Heure", "Tâche", "Outil", "Journal"], [
    ["02:30", "Sauvegarde de la configuration", c("/usr/local/sbin/wazuh-bundle-backup"),
     c("/var/log/wazuh-bundle/backup.log")],
    ["03:30", "Mise à jour hashes + règles YARA", c("/usr/local/sbin/wazuh-bundle-update-malware"),
     c("/var/log/wazuh-bundle/malware.log")],
    ["04:15", "Purge des fichiers d'alertes anciens", c("/usr/local/sbin/wazuh-bundle-purge-logs"),
     c("/var/log/wazuh-bundle/purge.log")],
    ["continu", "Rétention de l'indexer", "politiques ISM " + c("wazuh-bundle-*"), "Dashboard &gt; Index Management"],
], [0.1, 0.3, 0.33, 0.27])
p("Les tâches sont déclarées dans " + c("/etc/cron.d/wazuh-bundle-*") + ". Chaque outil peut être lancé à la main "
  "pour tester ; la purge accepte " + c("--dry-run") + " (simulation).")

h1("13. Opérations courantes")
h2("13.1 Modifier un paramètre")
p("Relancer l'étape concernée : la valeur actuelle est proposée par défaut ; il suffit de changer celle voulue.")
code("""bash install.sh --step 07                    # ex. : changer les destinataires e-mail
bash install.sh --non-interactive --step 05  # réappliquer sans question (ex. après restauration)""")
h2("13.2 Ajouter ou retirer un agent")
code("""# ajouter : voir § 8 (agents/install_agent_linux.sh ou install_agent_windows.ps1)
/var/ossec/bin/manage_agents -r 005          # retirer l'agent 005 (sur le serveur)
apt-get purge wazuh-agent                    # puis désinstaller sur la machine""")
h2("13.3 Changer les groupes d'un agent")
code("""/var/ossec/bin/agent_groups -a -i 005 -g role-web -q    # ajouter un groupe
/var/ossec/bin/agent_groups -r -i 005 -g role-web -q    # retirer un groupe""")
h2("13.4 Modifier la surveillance ou les règles")
bullets(["Surveillance : éditer " + c("configs/groups/<groupe>/agent.conf") + " puis " + c("--step 03") +
         " (le groupe feat-yara : relancer " + c("--step 06") + ").",
         "Règles : éditer " + c("configs/manager/bundle_rules.xml") + ", ajouter un cas de test dans " +
         c("configs/manager/rule_tests.txt") + ", documenter dans " + c("docs/REGLES.md") + ", puis " +
         c("--step 04") + ".",
         "Tester une ligne de journal : " + c("/var/ossec/bin/wazuh-logtest") + " (coller la ligne).",
         "Versionner chaque modification dans Git, puis lancer " + c("bash tests/run_tests.sh") + "."])
h2("13.5 Ajouter des règles YARA")
p("Relancer " + c("--step 06") + " et ajouter l'URL d'un fichier " + c(".yar") + " brut ; ou ajouter une règle "
  "dans " + c("configs/yara/bundle_rules.yar") + ". Chaque fichier est compilé avant distribution ; une règle "
  "invalide est ignorée et signalée dans " + c("malware.log") + ".")
h2("13.6 Mettre à jour Wazuh")
numbered(["Lire les notes de version et le guide officiel « Upgrading central components » de la version cible ;",
          "faire une sauvegarde (" + c("/usr/local/sbin/wazuh-bundle-backup") + ") ;",
          "mettre à jour le <b>serveur en premier</b> (indexer, manager, filebeat, dashboard, selon la procédure "
          "officielle) ;",
          "relancer " + c("bash install.sh --step 99") + " ;",
          "mettre à jour les agents ensuite :"])
code("""apt-mark unhold wazuh-agent
apt-get install -y wazuh-agent=<version>
apt-mark hold wazuh-agent""")
h2("13.7 Changer un mot de passe")
table(["Mot de passe", "Procédure"], [
    ["Enrôlement des agents", "Supprimer la ligne " + c("AUTHD_PASSWORD") + " de " + c("secrets.env") + ", relancer " +
     c("--step 03") + " et choisir « saisir » ou « générer ». Les agents déjà inscrits ne sont pas affectés."],
    ["admin de l'indexer", "Outil officiel " + c("wazuh-passwords-tool.sh") + " (documentation Wazuh), puis "
     "supprimer " + c("INDEXER_ADMIN_PASSWORD") + " de " + c("secrets.env") + " et relancer " + c("--step 02") +
     " qui redemande le mot de passe et teste la connexion."],
    ["Compte SMTP / clé SMS", "Relancer " + c("--step 07") + " ou " + c("--step 08") + " et accepter de remplacer "
     "le secret existant."],
    ["grafana_ro", "Supprimer " + c("GRAFANA_RO_PASSWORD") + " de " + c("secrets.env") + ", relancer " +
     c("--step 09") + " (et réinstaller le kit si Grafana est distant)."],
], [0.25, 0.75])
h2("13.8 Restaurer la configuration")
code("""# 1. voir le contenu d'une archive
tar -tzf /var/backups/wazuh/wazuh-config-<serveur>-<date>.tar.gz | less
# 2. restaurer un dossier ciblé (ex. : configuration Wazuh seule)
systemctl stop wazuh-manager
tar -xzf /var/backups/wazuh/wazuh-config-<serveur>-<date>.tar.gz -C / var/ossec/etc
# 3. redémarrer et vérifier
systemctl start wazuh-manager && bash install.sh --step 99""")
note("warn", "Restaurer de préférence des dossiers ciblés ; une restauration complète écrase aussi les certificats, "
     "les réponses et les secrets.")

h1("14. Règles de détection (synthèse)")
p("Wazuh fournit environ 4 000 règles ; le bundle en ajoute pour les situations importantes de l'entreprise et "
  "relève le niveau de certaines. Détail complet (déclencheur, MITRE, test) : " + c("docs/REGLES.md") + ".")
table(["Niveau", "Signification", "Notification par défaut"], [
    ["3", "Information (déclencheur technique)", "aucune"],
    ["7–8", "À examiner", "dashboard"],
    ["10", "Suspect", "e-mail"],
    ["12", "Incident probable", "e-mail + SMS"],
    ["14", "Incident (malware connu)", "e-mail + SMS"],
], [0.12, 0.5, 0.38])
table(["ID", "Niv.", "Détecte"], [
    ["100500", "14", "Fichier dont l'empreinte SHA256 est celle d'un malware connu (abuse.ch)"],
    ["100501–2", "3", "Fichier ajouté/modifié dans un répertoire YARA : lance l'analyse"],
    ["100511", "12", "Malware détecté par YARA"],
    ["100512", "7", "Erreur du scanner YARA sur un agent (agent non protégé)"],
    ["100551", "10", "Clé SSH autorisée ajoutée/modifiée"],
    ["100552", "10", "Droits sudo modifiés"],
    ["100553", "8", "Tâche cron ajoutée/modifiée"],
    ["100554", "8", "Nouveau service systemd"],
    ["100555", "10", "passwd / shadow / group modifiés"],
    ["100556", "12", "/etc/ld.so.preload modifié (rootkit)"],
    ["100560 / 61", "8 / 10", "Connexion SSH de root (hors heures ouvrables : 10)"],
    ["100520", "12", "Windows : journal d'événements effacé"],
    ["100521", "12", "Windows : ajout à un groupe administrateur"],
    ["100522 / 23", "8", "Windows : nouveau service / nouvelle tâche planifiée"],
    ["100524", "10", "Windows : politique d'audit modifiée"],
    ["100540 / 41", "12", "Windows Defender : menace détectée / protection désactivée"],
    ["5712, 5763", "natif", "Force brute SSH : déclenche la réponse active (blocage sur l'agent)"],
], [0.15, 0.1, 0.75])
h2("14.1 Réagir à une alerte critique (niveau ≥ 12)")
numbered(["<b>Qualifier</b> : ouvrir l'alerte dans le dashboard (agent, fichier, utilisateur, IP source, règle) ; "
          "un changement attendu (maintenance) est-il connu ?",
          "<b>Contenir</b> si l'incident est probable : isoler la machine du réseau selon la procédure de "
          "l'entreprise ; ne pas l'éteindre (preuves en mémoire).",
          "<b>Préserver</b> : ne pas supprimer le fichier suspect ; noter heure, machine, alerte.",
          "<b>Escalader</b> au RSSI / prestataire de réponse à incident.",
          "<b>Clore</b> : documenter la cause ; si faux positif, ajuster la règle (§ 13.4)."])

h1("15. Politique de rétention")
table(["Données", "Emplacement", "Durée par défaut", "Mécanisme"], [
    ["Alertes", "indexer : wazuh-alerts-*", "90 jours", "politique ISM wazuh-bundle-alerts"],
    ["Archives (tous les événements)", "indexer : wazuh-archives-*", "30 jours", "wazuh-bundle-archives"],
    ["Statistiques internes", "indexer : monitoring / statistics", "30 jours", "wazuh-bundle-monitoring"],
    ["Alertes compressées (preuves)", c("/var/ossec/logs/alerts/"), "180 jours", "purge quotidienne 04:15"],
    ["Archives compressées", c("/var/ossec/logs/archives/"), "30 jours", "purge quotidienne 04:15"],
    ["Sauvegardes de configuration", c("/var/backups/wazuh/"), "14 jours", "outil de sauvegarde 02:30"],
], [0.26, 0.28, 0.16, 0.3])
p("Les durées réellement appliquées sont dans " + c("/etc/wazuh-bundle/RETENTION.txt") + ". Pour les modifier : " + c("bash install.sh --step 05") + " (la nouvelle durée est appliquée aussi aux index existants).")
note("warn", "Si le disque de l'indexer dépasse ~95 %, OpenSearch passe les index en lecture seule : plus aucune "
     "alerte n'est enregistrée. Libérer de l'espace (réduire la rétention), puis lever le blocage (§ 16).")

h1("16. Dépannage")
table(["Symptôme", "Cause probable", "Vérification / solution"], [
    ["Une étape s'arrête en ÉCHEC", "Voir le diagnostic affiché", "Lire « Diagnostic » et « Piste » ; journal "
     "complet dans /var/log/wazuh-bundle/ ; corriger puis relancer l'étape."],
    ["« Configuration refusée par Wazuh »", "Balise ou règle invalide", "Le message de wazuh-analysisd indique le "
     "fichier et la ligne ; ossec.conf a été restauré automatiquement."],
    ["wazuh-manager ne démarre pas", "Configuration, disque, licence de port", c("tail -50 /var/ossec/logs/ossec.log") +
     " ; " + c("/var/ossec/bin/wazuh-control status") + "."],
    ["Agent jamais connecté", "Flux 1514/1515, mot de passe, groupe, version", "Sur l'agent : " +
     c("grep -E 'ERROR|WARN' /var/ossec/logs/ossec.log") + ". « Invalid password », « Invalid group », « Agent "
     "version must be lower »."],
    ["Agent « Disconnected »", "Machine éteinte, réseau, service arrêté", c("systemctl status wazuh-agent") +
     " sur la machine."],
    ["Dashboard vide / erreur", "Indexer ou filebeat arrêté", c("systemctl status wazuh-indexer filebeat") +
     " ; " + c("filebeat test output") + "."],
    ["Indexer en lecture seule", "Disque plein (> 95 %)", "Libérer de l'espace puis : " +
     c('PUT _all/_settings {"index.blocks.read_only_allow_delete": null}') +
     " (Dashboard &gt; Dev Tools)."],
    ["Pas d'e-mail", "Refus SMTP, file bloquée", c("postqueue -p") + " ; " +
     c("journalctl -t postfix/smtp -n 30") + " ; 535 = identifiants refusés (Gmail : mot de passe d'application)."],
    ["Pas de SMS", "Clé, crédit, mode sandbox", c("journalctl -u wazuh-sms-alerter -n 30") + "."],
    ["Alerte 100512 (YARA)", "YARA ou règles absents sur l'agent", "docs/YARA.md, § Dépannage."],
    ["Liste de hashes vide", "Clé abuse.ch absente, réseau", c("tail /var/log/wazuh-bundle/malware.log") + "."],
    ["Bloqué par la réponse active", "IP non whitelistée", "Ajouter l'IP à la liste blanche (étape 03) ; "
     "déblocage automatique après la durée choisie."],
    ["Perte d'accès SSH au serveur", "Mesure de l'étape 01", "Console (hyperviseur / iDRAC) : supprimer " +
     c("/etc/ssh/sshd_config.d/00-wazuh-bundle.conf") + " puis " + c("systemctl reload ssh") + "."],
], [0.22, 0.25, 0.53])

h1("17. Sécurité et bonnes pratiques")
bullets(["Accès au serveur réservé aux administrateurs nominatifs ; ports 9200/55000 jamais ouverts aux segments "
         "employés et DMZ.",
         "Mots de passe dans le coffre-fort de l'entreprise ; " + c("secrets.env") + " et " +
         c("wazuh-passwords.txt") + " restent root 600.",
         "Copie chiffrée des sauvegardes hors du serveur ; test de restauration au moins une fois par an.",
         "Déployer uniquement des <b>tags</b> Git testés ; " + c("bash tests/run_tests.sh") + " avant chaque tag.",
         "Dépôt Git privé si la documentation décrit l'architecture réelle.",
         "Mettre à jour Wazuh régulièrement (correctifs de sécurité) : serveur d'abord, agents ensuite.",
         "Revue trimestrielle des comptes, de la liste blanche et des destinataires des alertes."])

# =================================================================== ANNEXES
part("Annexes", "Glossaire, fiche de passation, aide-mémoire des commandes.")

h1("Annexe A — Glossaire")
table(["Terme", "Définition"], [
    ["Agent", "Programme Wazuh installé sur une machine surveillée ; envoie ses événements au manager."],
    ["Manager", "Serveur Wazuh qui analyse les événements et produit les alertes."],
    ["Indexer", "Base de données (OpenSearch) où sont stockées et recherchées les alertes."],
    ["Dashboard", "Interface web d'analyse de Wazuh."],
    ["Enrôlement", "Inscription d'un agent auprès du manager (port 1515), protégée par mot de passe."],
    ["Décodeur", "Extrait les champs d'un événement brut (utilisateur, IP, fichier…)."],
    ["Règle", "Condition sur un événement décodé ; produit une alerte d'un certain niveau."],
    ["Niveau", "Gravité d'une alerte, de 0 à 15."],
    ["FIM", "File Integrity Monitoring : détecte l'ajout, la modification, la suppression de fichiers."],
    ["Whodata", "Mode FIM qui indique quel utilisateur et quel processus ont modifié un fichier."],
    ["Réponse active", "Action automatique déclenchée par une règle (blocage d'IP, analyse YARA)."],
    ["Liste blanche", "Adresses jamais bloquées par la réponse active."],
    ["Liste CDB", "Liste clé/valeur utilisée par les règles (ici : empreintes de malwares)."],
    ["ISM", "Index State Management : politiques de l'indexer qui suppriment les index anciens."],
    ["YARA", "Outil qui recherche des motifs caractéristiques de malwares dans le contenu des fichiers."],
    ["EICAR", "Fichier de test inoffensif reconnu par tous les antivirus."],
    ["SHA256", "Empreinte numérique unique d'un fichier."],
    ["MITRE ATT&amp;CK", "Référentiel des techniques d'attaque ; chaque règle du bundle y est rattachée."],
    ["Groupe", "Ensemble d'agents recevant la même configuration centralisée."],
], [0.2, 0.8])

h1("Annexe B — Fiche de passation des connaissances")
p("À compléter et signer par le cédant (personne qui a installé ou exploitait le système) et le repreneur. Chaque "
  "ligne est validée lorsque le repreneur a <b>effectué lui-même</b> l'action au moins une fois.")
h2("B.1 Accès et secrets transmis")
chk = ""  # case laissée vide : à cocher à la main
table(["Élément", "Transmis", "Commentaire"], [
    ["Compte SSH nominatif sur le serveur Wazuh + droits sudo", chk, ""],
    ["Compte nominatif sur le Wazuh Dashboard (pas le compte admin partagé)", chk, ""],
    ["Accès au coffre-fort : wazuh-passwords.txt, mot de passe d'enrôlement", chk, ""],
    ["Accès au dépôt Git du bundle (tags, droits de publication)", chk, ""],
    ["Compte d'envoi e-mail (Gmail / SMTP) et contact de l'équipe messagerie", chk, ""],
    ["Compte Africa's Talking / clé abuse.ch (propriétaire, renouvellement)", chk, ""],
    ["Accès console de secours (hyperviseur, iDRAC/iLO)", chk, ""],
    ["Emplacement de la copie hors serveur des sauvegardes", chk, ""],
], [0.62, 0.1, 0.28])
h2("B.2 Savoir-faire démontré par le repreneur")
table(["Compétence", "Fait", "Date"], [
    ["Expliquer l'architecture (§ 2) et les flux réseau (§ 6)", chk, ""],
    ["Lancer la recette (étape 99) et interpréter le résultat", chk, ""],
    ["Installer un agent Linux et un agent Windows ; vérifier leurs groupes", chk, ""],
    ["Retirer un agent", chk, ""],
    ["Qualifier une alerte de niveau ≥ 12 dans le dashboard (§ 14.1)", chk, ""],
    ["Déclencher et retrouver l'alerte EICAR (100511)", chk, ""],
    ["Modifier un paramètre en relançant une étape (ex. destinataires e-mail)", chk, ""],
    ["Ajouter ou modifier une règle, la tester avec wazuh-logtest", chk, ""],
    ["Lire les journaux des tâches planifiées (§ 12)", chk, ""],
    ["Restaurer un fichier depuis une sauvegarde (§ 13.8)", chk, ""],
    ["Diagnostiquer un agent déconnecté (§ 16)", chk, ""],
    ["Connaître la procédure de mise à jour (§ 13.6) et de changement de mot de passe (§ 13.7)", chk, ""],
], [0.72, 0.08, 0.2])
h2("B.3 Points ouverts et particularités de l'installation")
t = Table([[Paragraph("Écarts au standard, incidents passés, faux positifs connus, chantiers en cours :", ST["cell"])]] +
          [[""] for _ in range(6)], colWidths=[CONTENT_W], rowHeights=[None] + [0.75 * cm] * 6)
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, GRID), ("BACKGROUND", (0, 0), (-1, 0), LIGHT)]))
story.append(t); story.append(Spacer(1, 12))
h2("B.4 Signatures")
sig = Table([[Paragraph("<b>Cédant</b>", ST["cell"]), Paragraph("<b>Repreneur</b>", ST["cell"])],
             [Paragraph("Nom :<br/><br/>Date :<br/><br/>Signature :", ST["cell"]),
              Paragraph("Nom :<br/><br/>Date :<br/><br/>Signature :", ST["cell"])]],
            colWidths=[CONTENT_W / 2] * 2, rowHeights=[None, 3.2 * cm])
sig.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, GRID), ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
                         ("VALIGN", (0, 0), (-1, -1), "TOP")]))
story.append(KeepTogether(sig))

h1("Annexe C — Aide-mémoire des commandes")
h3("Bundle")
code("""bash install.sh                         menu
bash install.sh --step NN               une étape        --explain NN   description
bash install.sh --flows                 flux réseau      --step 99      recette
bash tests/run_tests.sh                 tests du bundle (sans Wazuh)""")
h3("Wazuh (serveur)")
code("""systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat
/var/ossec/bin/wazuh-control status                 état des démons
/var/ossec/bin/wazuh-analysisd -t                   tester la configuration
/var/ossec/bin/wazuh-logtest                        tester une ligne de journal
/var/ossec/bin/agent_control -l                     agents et état
/var/ossec/bin/agent_groups -l                      groupes
/var/ossec/bin/manage_agents -r <ID>                retirer un agent
tail -f /var/ossec/logs/ossec.log                   journal du manager
tail -f /var/ossec/logs/alerts/alerts.json          alertes en direct""")
h3("Tâches et alertes")
code("""/usr/local/sbin/wazuh-bundle-update-malware        mise à jour hashes + YARA
/usr/local/sbin/wazuh-bundle-purge-logs --dry-run   simulation de purge
/usr/local/sbin/wazuh-bundle-backup                 sauvegarde immédiate
postqueue -p ; journalctl -t postfix/smtp -n 30     e-mails
journalctl -u wazuh-sms-alerter -n 30               SMS""")
h3("Agent")
code("""systemctl status wazuh-agent ; tail -f /var/ossec/logs/ossec.log
tail -f /var/ossec/logs/active-responses.log        réponses actives (blocages, YARA)
cat /var/ossec/etc/shared/agent.conf                configuration reçue des groupes""")


# ------------------------------------------------------------------ génération
def main():
    doc = Doc(OUT)
    doc.multiBuild(story)
    print("PDF généré :", OUT)


if __name__ == "__main__":
    sys.exit(main())
