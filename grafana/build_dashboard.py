#!/usr/bin/env python3
"""Génère configs/grafana/dashboards/wazuh-overview.json — « Wazuh — Poste de commande ».

    python3 grafana/build_dashboard.py

Le tableau de bord est décrit ici en Python (plus lisible et plus sûr à modifier que 1 500 lignes de JSON).
Source de données : « Wazuh-OpenSearch » (uid wazuh-opensearch), provisionnée par grafana/provision.sh.
Lecture de haut en bas : 1) faut-il agir ?  2) tendance  3) qui / quoi  4) le détail à traiter.
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "configs", "grafana", "dashboards", "wazuh-overview.json")
DS = {"type": "grafana-opensearch-datasource", "uid": "wazuh-opensearch"}
FLT = "agent.name:${agent:lucene}"  # filtre « machine » appliqué à toutes les requêtes

RED, ORANGE, YELLOW, GREEN, BLUE, PURPLE, GREY = "#E02F44", "#FF780A", "#FADE2A", "#56A64B", "#3274D9", "#A352CC", "#8E8E8E"
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def q(query):
    return f"({query}) AND {FLT}" if query != "*" else FLT


def target(query, metrics, buckets, ref="A", alias=None):
    t = {"refId": ref, "datasource": DS, "queryType": "lucene", "query": q(query), "timeField": "@timestamp",
         "metrics": metrics, "bucketAggs": buckets}
    if alias:
        t["alias"] = alias
    return t


def histo():
    return [{"id": "2", "type": "date_histogram", "field": "@timestamp",
             "settings": {"interval": "auto", "min_doc_count": "0"}}]


def terms(field, size=10):
    return [{"id": "2", "type": "terms", "field": field,
             "settings": {"size": str(size), "order": "desc", "orderBy": "_count", "min_doc_count": "1"}}]


COUNT = [{"id": "1", "type": "count"}]


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}


def stat(title, query, color, x, w, desc, unit="none", calc="sum", tgt=None, steps=None):
    return {
        "id": nid(), "type": "stat", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": 2, "w": w, "h": 5},
        "targets": [tgt or target(query, COUNT, histo())],
        "options": {"reduceOptions": {"calcs": [calc], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "area" if tgt is None else "none",
                    "textMode": "value", "justifyMode": "center", "orientation": "auto", "wideLayout": True},
        "fieldConfig": {"defaults": {"unit": unit, "noValue": "0", "decimals": 0,
                                     "color": {"mode": "thresholds"},
                                     "thresholds": steps or thresholds((None, GREEN), (1, color))},
                        "overrides": []},
    }


def bargauge(title, query, field, x, y, w, h, desc, color, size=10):
    return {
        "id": nid(), "type": "bargauge", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(query, COUNT, terms(field, size))],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
                    "orientation": "horizontal", "displayMode": "gradient", "valueMode": "color",
                    "showUnfilled": True, "namePlacement": "left", "sizing": "auto", "minVizHeight": 14,
                    "maxVizHeight": 22},
        "fieldConfig": {"defaults": {"color": {"mode": "continuous-GrYlRd" if color is None else "fixed",
                                               "fixedColor": color or BLUE},
                                     "min": 0, "noValue": "Aucune donnée", "decimals": 0},
                        "overrides": []},
    }


LEVEL_CELL = {"matcher": {"id": "byName", "options": "rule.level"},
              "properties": [{"id": "displayName", "value": "Niveau"}, {"id": "custom.width", "value": 75},
                             {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                             {"id": "color", "value": {"mode": "thresholds"}},
                             {"id": "thresholds", "value": thresholds((None, GREEN), (7, YELLOW), (10, ORANGE),
                                                                      (12, RED))}]}


def rename(field, label, width=None):
    props = [{"id": "displayName", "value": label}]
    if width:
        props.append({"id": "custom.width", "value": width})
    return {"matcher": {"id": "byName", "options": field}, "properties": props}


def table(title, query, cols, x, y, w, h, desc, size=100):
    names = [c[0] for c in cols]
    return {
        "id": nid(), "type": "table", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(query, [{"id": "1", "type": "raw_data", "settings": {"size": str(size)}}], [])],
        "transformations": [
            {"id": "filterFieldsByName", "options": {"include": {"names": names}}},
            {"id": "organize", "options": {"indexByName": {n: i for i, n in enumerate(names)}}},
        ],
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False},
                    "sortBy": [{"displayName": "Date", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "left", "filterable": True,
                                                "cellOptions": {"type": "auto"}}, "noValue": "—"},
                        "overrides": [LEVEL_CELL if c[0] == "rule.level" else rename(*c) for c in cols]},
    }


def row(title, y, collapsed=False, panels=None):
    r = {"id": nid(), "type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
         "panels": panels or []}
    return r


panels = []

# ---------------------------------------------------------------- bandeau de lecture
panels.append({
    "id": nid(), "type": "text", "title": "", "gridPos": {"x": 0, "y": 0, "w": 24, "h": 2}, "transparent": True,
    "options": {"mode": "html", "content": (
        '<div style="display:flex;gap:18px;align-items:center;font-size:13px;flex-wrap:wrap">'
        '<b style="font-size:15px">Lecture&nbsp;:</b>'
        f'<span><span style="color:{RED}">■</span> ≥ 12 incident probable — à traiter tout de suite</span>'
        f'<span><span style="color:{ORANGE}">■</span> 10–11 suspect — à examiner dans la journée</span>'
        f'<span><span style="color:{YELLOW}">■</span> 7–9 à surveiller</span>'
        f'<span><span style="color:{GREEN}">■</span> &lt; 7 information</span>'
        '<span style="opacity:.7">Période et machine : en haut à droite / en haut à gauche.</span></div>')},
})

# ---------------------------------------------------------------- 1. faut-il agir ?
panels += [
    stat("Incidents probables", "rule.level:>=12", RED, 0, 4,
         "Alertes de niveau 12 et plus sur la période : malware, journal effacé, protection désactivée… "
         "Toute valeur différente de 0 doit être traitée (tableau « À traiter » plus bas)."),
    stat("Suspects", "rule.level:[10 TO 11]", ORANGE, 4, 4,
         "Alertes de niveau 10 et 11 : changement sensible (sudoers, clé SSH, comptes), connexion root hors heures…"),
    stat("Malware", "rule.groups:malware OR rule.id:(100500 OR 100511 OR 100540)", PURPLE, 8, 4,
         "Détections YARA (100511), empreinte connue (100500), Windows Defender (100540)."),
    stat("IP bloquées", "rule.groups:active_response AND rule.id:651", ORANGE, 12, 4,
         "Blocages automatiques par la réponse active (force brute SSH). Une IP interne ici mérite une vérification."),
    stat("Alertes au total", "*", BLUE, 16, 4, "Toutes les alertes enregistrées sur la période (tous niveaux).",
         steps=thresholds((None, BLUE))),
    stat("Machines qui remontent", "*", GREEN, 20, 4,
         "Nombre de machines ayant envoyé au moins une alerte sur la période. Une baisse soudaine = agent arrêté "
         "ou coupure réseau.", calc="count", tgt=target("*", COUNT, terms("agent.name", 1000)),
         steps=thresholds((None, GREEN))),
]

# ---------------------------------------------------------------- 2. tendance
bands = [("rule.level:<7", "Information (< 7)", GREEN), ("rule.level:[7 TO 9]", "À surveiller (7-9)", YELLOW),
         ("rule.level:[10 TO 11]", "Suspect (10-11)", ORANGE), ("rule.level:>=12", "Incident probable (≥ 12)", RED)]
panels.append({
    "id": nid(), "type": "timeseries", "title": "Alertes dans le temps, par gravité",
    "description": "Barres empilées : un pic rouge ou orange est à examiner en priorité. Cliquer-glisser pour zoomer.",
    "datasource": DS, "gridPos": {"x": 0, "y": 7, "w": 16, "h": 8},
    "targets": [target(qr, COUNT, histo(), ref=chr(65 + i), alias=name) for i, (qr, name, _) in enumerate(bands)],
    "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                "tooltip": {"mode": "multi", "sort": "desc"}},
    "fieldConfig": {
        "defaults": {"custom": {"drawStyle": "bars", "fillOpacity": 85, "lineWidth": 0, "stacking": {"mode": "normal"},
                                "barAlignment": 0, "gradientMode": "none", "axisSoftMin": 0},
                     "color": {"mode": "fixed"}, "decimals": 0},
        "overrides": [{"matcher": {"id": "byName", "options": name},
                       "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
                      for _, name, col in bands]},
})
panels.append({
    "id": nid(), "type": "piechart", "title": "Nature des alertes (≥ 7)",
    "description": "Familles de règles (rule.groups) des alertes de niveau 7 et plus.",
    "datasource": DS, "gridPos": {"x": 16, "y": 7, "w": 8, "h": 8},
    "targets": [target("rule.level:>=7", COUNT, terms("rule.groups", 8))],
    "options": {"pieType": "donut", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
                "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value"]},
                "tooltip": {"mode": "single"}, "displayLabels": []},
    "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "decimals": 0}, "overrides": []},
})

# ---------------------------------------------------------------- 3. qui / quoi
panels += [
    bargauge("Machines les plus en alerte (≥ 7)", "rule.level:>=7", "agent.name", 0, 15, 8, 9,
             "Les 10 machines qui génèrent le plus d'alertes significatives : commencer l'analyse par elles.", None),
    bargauge("Règles les plus déclenchées (≥ 7)", "rule.level:>=7", "rule.description", 8, 15, 8, 9,
             "Une règle très bavarde est soit un vrai problème récurrent, soit un faux positif à régler "
             "(voir le manuel : « faire taire un faux positif »).", ORANGE),
    bargauge("IP à l'origine d'échecs de connexion", "rule.groups:authentication_failed OR "
             "rule.groups:authentication_failures", "data.srcip", 16, 15, 8, 9,
             "Adresses sources des échecs d'authentification (SSH, Windows…). Une IP externe en tête = attaque "
             "par force brute ; une IP interne = mot de passe expiré ou compte de service mal configuré.", RED),
]

# ---------------------------------------------------------------- 4. à traiter
panels.append(row("À traiter", 24))
panels.append(table("Incidents probables et suspects (niveau ≥ 10)", "rule.level:>=10",
                    [("@timestamp", "Date", 165), ("rule.level", "Niveau"), ("agent.name", "Machine", 150),
                     ("rule.id", "Règle", 75), ("rule.description", "Description"), ("data.srcip", "IP source", 120),
                     ("syscheck.path", "Fichier", 220)],
                    0, 25, 24, 10,
                    "Les 100 dernières alertes de niveau 10 et plus. Filtrer une colonne avec l'entonnoir de l'en-tête. "
                    "Pour le détail complet : Wazuh Dashboard > Threat Hunting, rechercher rule.id et la machine."))

# ---------------------------------------------------------------- 5. thèmes (repliés)
panels.append(row("Malware et intégrité des fichiers", 35, collapsed=True, panels=[
    table("Détections malware", "rule.groups:malware OR rule.id:(100500 OR 100511 OR 100512 OR 100540 OR 100541)",
          [("@timestamp", "Date", 165), ("rule.level", "Niveau"), ("agent.name", "Machine", 150),
           ("rule.description", "Description"), ("data.yara_rule", "Règle YARA", 170),
           ("syscheck.path", "Fichier", 230)], 0, 36, 12, 9,
          "YARA, liste de hashes, Windows Defender. 100512 = le scanner YARA d'une machine ne fonctionne pas."),
    table("Fichiers sensibles modifiés", "rule.id:(100551 OR 100552 OR 100553 OR 100554 OR 100555 OR 100556)",
          [("@timestamp", "Date", 165), ("rule.level", "Niveau"), ("agent.name", "Machine", 150),
           ("syscheck.path", "Fichier", 230), ("syscheck.event", "Action", 90), ("rule.description", "Description")],
          12, 36, 12, 9, "Clés SSH, sudoers, cron, services, comptes, ld.so.preload. Chaque ligne doit "
                         "correspondre à une intervention connue."),
]))
panels.append(row("Connexions et blocages", 37, collapsed=True, panels=[
    {"id": nid(), "type": "timeseries", "title": "Connexions réussies et échouées",
     "description": "Un pic d'échecs suivi d'un succès depuis la même IP est un signal fort de compromission.",
     "datasource": DS, "gridPos": {"x": 0, "y": 38, "w": 12, "h": 8},
     "targets": [target("rule.groups:authentication_success", COUNT, histo(), "A", "Réussies"),
                 target("rule.groups:authentication_failed OR rule.groups:authentication_failures", COUNT, histo(),
                        "B", "Échouées")],
     "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                 "tooltip": {"mode": "multi"}},
     "fieldConfig": {"defaults": {"custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 15,
                                             "showPoints": "never", "axisSoftMin": 0}, "decimals": 0},
                     "overrides": [{"matcher": {"id": "byName", "options": "Réussies"},
                                    "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": GREEN}}]},
                                   {"matcher": {"id": "byName", "options": "Échouées"},
                                    "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": RED}}]}]}},
    table("Blocages automatiques (réponse active)", "rule.groups:active_response",
          [("@timestamp", "Date", 165), ("agent.name", "Machine", 150), ("data.srcip", "IP bloquée", 130),
           ("rule.description", "Action")], 12, 38, 12, 8,
          "Chaque blocage dure la durée choisie à l'installation puis est levé automatiquement."),
]))

dashboard = {
    "uid": "wazuh-overview",
    "title": "Wazuh — Poste de commande",
    "description": "Vue d'ensemble du SIEM : faut-il agir, tendance, machines et règles en cause, alertes à traiter.",
    "tags": ["wazuh", "soc", "vue d'ensemble"],
    "timezone": "browser", "schemaVersion": 39, "version": 1, "editable": True, "graphTooltip": 1,
    "refresh": "1m", "time": {"from": "now-24h", "to": "now"},
    "timepicker": {"refresh_intervals": ["30s", "1m", "5m", "15m"]},
    "templating": {"list": [{
        "name": "agent", "label": "Machine", "type": "query", "datasource": DS,
        "query": '{"find": "terms", "field": "agent.name", "size": 1000}',
        "refresh": 2, "includeAll": True, "multi": True, "allValue": "*", "sort": 1,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
    }]},
    "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                              "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                              "name": "Annotations & Alerts", "type": "dashboard"}]},
    "links": [{"title": "Tableau détaillé (Vue SOC)", "type": "link", "url": "/d/wazuh-soc", "icon": "dashboard"}],
    "panels": panels,
}

if __name__ == "__main__":
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dashboard, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("Tableau de bord généré :", OUT, f"({len(panels)} panneaux)")
