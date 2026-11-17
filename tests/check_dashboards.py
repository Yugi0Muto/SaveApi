"""Contrôle des tableaux de bord Grafana : JSON valide, uid uniques, identifiants de panneaux uniques,
aucun chevauchement (au niveau principal et dans chaque rangée repliée), source de données Wazuh."""
import glob, json, sys

uids, ok = set(), True
for f in sorted(glob.glob("configs/grafana/dashboards/*.json")):
    d = json.load(open(f, encoding="utf-8"))
    assert d["uid"] not in uids, f"uid en double : {d['uid']}"; uids.add(d["uid"])
    groups = [d["panels"]] + [p.get("panels", []) for p in d["panels"] if p.get("collapsed")]
    ids = []
    for grp in groups:
        cells = {}
        for p in grp:
            ids.append(p["id"]); g = p["gridPos"]
            assert g["x"] + g["w"] <= 24, f"{f}: {p['title']} dépasse 24 colonnes"
            for x in range(g["x"], g["x"] + g["w"]):
                for y in range(g["y"], g["y"] + g["h"]):
                    assert (x, y) not in cells, f"{f}: chevauchement {p['title']} / {cells[(x, y)]}"
                    cells[(x, y)] = p["title"]
            for t in p.get("targets", []):
                assert t["datasource"]["uid"] == "wazuh-opensearch", f"{f}: {p['title']} : source inattendue"
    assert len(ids) == len(set(ids)), f"{f}: identifiants de panneaux en double"
    print(f"{f} : {len(ids)} panneaux OK")
