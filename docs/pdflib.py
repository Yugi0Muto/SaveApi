"""docs/pdflib.py — mise en page commune des documents PDF du bundle (reportlab).

Usage : from pdflib import Doc ; d = Doc(titre, sous_titre, version) ; d.h1(...) ; d.p(...) ; d.build(chemin)
Les polices DejaVu sont utilisées si présentes (accents, symboles), sinon les polices PDF standard.
"""
import math

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String

_FD = "/usr/share/fonts/truetype/dejavu"
try:
    pdfmetrics.registerFont(TTFont("Sans", f"{_FD}/DejaVuSans.ttf"))
    pdfmetrics.registerFont(TTFont("Sans-Bold", f"{_FD}/DejaVuSans-Bold.ttf"))
    pdfmetrics.registerFont(TTFont("Sans-Oblique", f"{_FD}/DejaVuSans-Oblique.ttf"))
    pdfmetrics.registerFont(TTFont("Mono", f"{_FD}/DejaVuSansMono.ttf"))
    pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans-Oblique", boldItalic="Sans-Bold")
    SANS, BOLD, MONO = "Sans", "Sans-Bold", "Mono"
except Exception:
    SANS, BOLD, MONO = "Helvetica", "Helvetica-Bold", "Courier"

NAVY = colors.HexColor("#1F3A5F"); TEAL = colors.HexColor("#2A7F8E"); LIGHT = colors.HexColor("#EEF3F8")
CODEBG = colors.HexColor("#F4F5F7"); GRID = colors.HexColor("#B8C4D2")
RED = colors.HexColor("#E02F44"); ORANGE = colors.HexColor("#FF780A"); YELLOW = colors.HexColor("#F2CC0C")
GREEN = colors.HexColor("#56A64B"); BLUE = colors.HexColor("#3274D9"); PURPLE = colors.HexColor("#A352CC")
DARK = colors.HexColor("#181B1F"); PANEL = colors.HexColor("#22252B")
BOXES = {"info": (colors.HexColor("#E8F4F6"), TEAL, "À savoir"),
         "warn": (colors.HexColor("#FFF6E0"), colors.HexColor("#E0A800"), "Attention"),
         "danger": (colors.HexColor("#FCEBEA"), colors.HexColor("#C0392B"), "Important"),
         "tip": (colors.HexColor("#EEF7EC"), GREEN, "Astuce"),
         "do": (colors.HexColor("#F1ECFA"), PURPLE, "À vous")}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CW = PAGE_W - 2 * MARGIN

S = {
    "body": ParagraphStyle("body", fontName=SANS, fontSize=9.6, leading=13.6, spaceAfter=5),
    "small": ParagraphStyle("small", fontName=SANS, fontSize=8.2, leading=10.8),
    "cell": ParagraphStyle("cell", fontName=SANS, fontSize=8.3, leading=10.8),
    "cellb": ParagraphStyle("cellb", fontName=BOLD, fontSize=8.3, leading=10.8, textColor=colors.white),
    "h1": ParagraphStyle("h1", fontName=BOLD, fontSize=17, leading=21, textColor=NAVY, spaceBefore=2, spaceAfter=4),
    "lead": ParagraphStyle("lead", fontName=SANS, fontSize=10.3, leading=14.5, textColor=TEAL, spaceAfter=10),
    "h2": ParagraphStyle("h2", fontName=BOLD, fontSize=12.3, leading=16, textColor=NAVY, spaceBefore=11, spaceAfter=5),
    "h3": ParagraphStyle("h3", fontName=BOLD, fontSize=10.2, leading=13.5, textColor=TEAL, spaceBefore=7, spaceAfter=3),
    "bullet": ParagraphStyle("bullet", fontName=SANS, fontSize=9.6, leading=13.2, leftIndent=14, bulletIndent=4,
                             spaceAfter=2),
    "code": ParagraphStyle("code", fontName=MONO, fontSize=7.9, leading=10.3),
    "toc1": ParagraphStyle("toc1", fontName=BOLD, fontSize=10, leading=16),
    "cap": ParagraphStyle("cap", fontName=SANS, fontSize=8, leading=10.5, alignment=TA_CENTER, textColor=NAVY),
}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def c(s):
    return f'<font face="{MONO}" size="8.3">{esc(s)}</font>'


class _Template(BaseDocTemplate):
    def __init__(self, fn, meta):
        self.meta = meta
        super().__init__(fn, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=2.2 * cm,
                         bottomMargin=2 * cm, title=meta["title"], author=meta.get("author", ""),
                         subject=meta.get("subject", ""))
        fr = Frame(MARGIN, 2 * cm, CW, PAGE_H - 4.2 * cm, id="f")
        self.addPageTemplates([PageTemplate("cover", [fr], onPage=self._cover),
                               PageTemplate("normal", [fr], onPage=self._normal)])

    def afterFlowable(self, f):
        if hasattr(f, "_toc"):
            key = f"s{id(f)}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(f._toc, key, level=0)
            self.notify("TOCEntry", (0, f._toc, self.page, key))

    def _cover(self, cv, doc):
        m = self.meta
        cv.saveState()
        cv.setFillColor(NAVY); cv.rect(0, PAGE_H - 10.5 * cm, PAGE_W, 10.5 * cm, fill=1, stroke=0)
        cv.setFillColor(TEAL); cv.rect(0, PAGE_H - 10.8 * cm, PAGE_W, 0.3 * cm, fill=1, stroke=0)
        cv.setFillColor(colors.white)
        cv.setFont(BOLD, 11.5); cv.drawString(MARGIN, PAGE_H - 2.6 * cm, m["kicker"])
        cv.setFont(BOLD, 28)
        for i, ln in enumerate(m["title_lines"]):
            cv.drawString(MARGIN, PAGE_H - 4.7 * cm - i * 1.25 * cm, ln)
        cv.setFont(SANS, 11)
        for i, ln in enumerate(m["subtitle_lines"]):
            cv.drawString(MARGIN, PAGE_H - 7.7 * cm - i * 0.62 * cm, ln)
        cv.restoreState()

    def _normal(self, cv, doc):
        m = self.meta
        cv.saveState()
        cv.setStrokeColor(GRID); cv.setLineWidth(0.5)
        cv.line(MARGIN, PAGE_H - 1.5 * cm, PAGE_W - MARGIN, PAGE_H - 1.5 * cm)
        cv.line(MARGIN, 1.4 * cm, PAGE_W - MARGIN, 1.4 * cm)
        cv.setFont(SANS, 7.5); cv.setFillColor(NAVY)
        cv.drawString(MARGIN, PAGE_H - 1.3 * cm, m["header"])
        cv.drawRightString(PAGE_W - MARGIN, PAGE_H - 1.3 * cm, m.get("classif", ""))
        cv.drawString(MARGIN, 1.0 * cm, m["footer"])
        cv.drawRightString(PAGE_W - MARGIN, 1.0 * cm, f"Page {doc.page}")
        cv.restoreState()


class Doc:
    def __init__(self, meta):
        self.meta = meta
        self.story = []
        self._pending = []  # titre en attente : il sera gardé sur la même page que l'élément qui le suit

    def _add(self, *flows):
        flows = list(flows)
        if self._pending and flows:
            first = flows.pop(0)
            # ne pas imbriquer deux KeepTogether (reportlab les place alors chacun sur une nouvelle page)
            inner = list(first._content) if isinstance(first, KeepTogether) else [first]
            self.story.append(KeepTogether(self._pending + inner))
            self._pending = []
        self.story.extend(flows)

    # ---- structure
    def toc(self, title="Sommaire"):
        self.story += [NextPageTemplate("normal"), PageBreak(), Paragraph(title, S["h1"]), Spacer(1, 6),
                       TableOfContents(levelStyles=[S["toc1"]], dotsMinLevel=0)]

    def chapter(self, title, lead=None):
        self._flush()
        self.story.append(PageBreak())
        p = Paragraph(title, S["h1"]); p._toc = title
        self.story.append(p)
        if lead:
            self.story.append(Paragraph(lead, S["lead"]))
        else:
            self.story.append(Spacer(1, 6))

    def h2(self, t):
        self._flush()
        self.story.append(CondPageBreak(3.5 * cm))
        self._pending = [Paragraph(t, S["h2"])]

    def h3(self, t):
        if self._pending:          # h2 suivi directement d'un h3 : les garder ensemble avec la suite
            self._pending.append(Paragraph(t, S["h3"]))
            return
        self.story.append(CondPageBreak(2.5 * cm))
        self._pending = [Paragraph(t, S["h3"])]

    def _flush(self):
        if self._pending:
            self.story.extend(self._pending); self._pending = []

    # ---- texte
    def p(self, t, style="body"):
        self._add(Paragraph(t, S[style]))

    def bullets(self, items):
        self._add(*[Paragraph(it, S["bullet"], bulletText="•") for it in items], Spacer(1, 3))

    def steps(self, items):
        self._add(*[Paragraph(it, S["bullet"], bulletText=f"{i}.") for i, it in enumerate(items, 1)], Spacer(1, 3))

    MAX_CODE = 96  # caractères par ligne de code qui tiennent dans la largeur utile

    def code(self, text, title=None):
        for ln in text.strip("\n").splitlines():
            if len(ln) > self.MAX_CODE:
                print(f"[mise en page] ligne de code trop longue ({len(ln)} > {self.MAX_CODE}) : {ln[:60]}…")
        pre = Preformatted(text.strip("\n"), S["code"])
        rows = [[Paragraph(f"<b>{title}</b>", S["small"])], [pre]] if title else [[pre]]
        t = Table(rows, colWidths=[CW])
        st = [("BACKGROUND", (0, 0), (-1, -1), CODEBG), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
              ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
        if title:
            st.append(("LINEBELOW", (0, 0), (-1, 0), 0.4, GRID))
        t.setStyle(TableStyle(st))
        self._add(KeepTogether([t]), Spacer(1, 6))

    def box(self, kind, text, label=None):
        bg, bd, lab = BOXES[kind]
        t = Table([[Paragraph(f"<b>{label or lab} :</b> {text}", S["body"])]], colWidths=[CW])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3, bd),
                               ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        self._add(KeepTogether(t), Spacer(1, 7))

    def exercise(self, title, items, check):
        """Mise en pratique guidée : objectif, étapes, résultat attendu."""
        bg, bd, _ = BOXES["do"]
        rows = [[Paragraph(f"<b>À vous : {title}</b>", S["body"])]]
        for i, it in enumerate(items, 1):
            rows.append([Paragraph(f"{i}. {it}", S["body"])])
        rows.append([Paragraph(f"<b>C'est réussi si :</b> {check}", S["body"])])
        t = Table(rows, colWidths=[CW])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3, bd),
                               ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                               ("TOPPADDING", (0, 0), (0, 0), 7), ("BOTTOMPADDING", (0, -1), (0, -1), 6)]))
        self._add(KeepTogether(t), Spacer(1, 8))

    def table(self, header, rows, widths, zebra=True, header_bg=NAVY):
        data = [[Paragraph(h, S["cellb"]) for h in header]]
        for r in rows:
            data.append([x if not isinstance(x, str) else Paragraph(x, S["cell"]) for x in r])
        t = Table(data, colWidths=[w * CW for w in widths], repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), header_bg), ("GRID", (0, 0), (-1, -1), 0.4, GRID),
              ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4),
              ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if zebra:
            st += [("BACKGROUND", (0, i), (-1, i), LIGHT) for i in range(2, len(data), 2)]
        t.setStyle(TableStyle(st))
        self._add(t, Spacer(1, 8))

    def raw(self, flowable):
        self._add(flowable)

    def spacer(self, h=6):
        self._add(Spacer(1, h))

    def build(self, path):
        self._flush()
        doc = _Template(path, self.meta)
        doc.multiBuild(self.story)


# ---- dessins utilitaires
def arrow(d, x1, y1, x2, y2, col=TEAL, w=1.2):
    d.add(Line(x1, y1, x2, y2, strokeColor=col, strokeWidth=w))
    a = math.atan2(y2 - y1, x2 - x1); s = 5.5
    d.add(Polygon([x2, y2, x2 - s * math.cos(a - 0.42), y2 - s * math.sin(a - 0.42),
                   x2 - s * math.cos(a + 0.42), y2 - s * math.sin(a + 0.42)], fillColor=col, strokeColor=col))


def label(d, x, y, text, size=7.5, color=NAVY, bold=False, anchor="start"):
    d.add(String(x, y, text, fontName=BOLD if bold else SANS, fontSize=size, fillColor=color, textAnchor=anchor))


def rect(d, x, y, w, h, fill, stroke=None, r=3):
    d.add(Rect(x, y, w, h, rx=r, ry=r, fillColor=fill, strokeColor=stroke or fill, strokeWidth=0.6))
