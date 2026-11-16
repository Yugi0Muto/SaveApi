#!/usr/bin/env python3
"""ossec_conf.py — modifications contrôlées et idempotentes de /var/ossec/etc/ossec.conf

Pourquoi ce script plutôt que sed :
  * ossec.conf contient PLUSIEURS sections <ossec_config> et des commentaires : une substitution
    sed/regex « à l'aveugle » peut toucher le mauvais endroit ou dupliquer un bloc.
  * Ici, chaque bloc ajouté par le bundle est délimité par des marqueurs
        <!-- wazuh-bundle:BEGIN nom -->  ...  <!-- wazuh-bundle:END nom -->
    Relancer une étape REMPLACE le bloc (jamais de doublon), et on sait toujours ce que le bundle a ajouté.
  * Les sections sont repérées en ignorant les commentaires ; le fichier n'est réécrit que s'il change,
    de façon atomique, en conservant propriétaire et droits.
  * La syntaxe XML du résultat est vérifiée avant écriture ; la validation finale est faite par Wazuh
    lui-même (wazuh-analysisd -t, etc.) dans lib/common.sh.

Usage : ossec_conf.py FICHIER COMMANDE ARGS
  block   PARENT NOM FICHIER_CONTENU   crée/remplace le bloc NOM dans la section PARENT
  unblock NOM                          supprime le bloc NOM (s'il existe)
  set     PARENT BALISE VALEUR         fixe <BALISE>VALEUR</BALISE> dans PARENT (créée si absente)
  setmulti PARENT BALISE V1 [V2...]    remplace toutes les <BALISE> de PARENT par une par valeur
  get     PARENT BALISE                affiche les valeurs de <BALISE> dans PARENT
  hasblock NOM                         code 0 si le bloc existe
  migrate-v2                           retire les ajouts non balisés de la version 2 du bundle
  check                                vérifie la syntaxe XML
PARENT = nom de section (global, alerts, auth, ruleset, ...) ou ossec_config (= dernière section).
"""
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

MARK_B = "<!-- wazuh-bundle:BEGIN {} -->"
MARK_E = "<!-- wazuh-bundle:END {} -->"


def fail(msg):
    sys.exit("ERREUR : " + msg)


def well_formed(fragment, what):
    try:
        ET.fromstring("<racine>" + fragment + "</racine>")
    except ET.ParseError as e:
        fail(f"{what} : XML invalide ({e})")


def masked(text):
    """Remplace les commentaires par des espaces (même longueur) pour ne pas y chercher de balises."""
    return re.sub(r"<!--.*?-->", lambda m: " " * len(m.group()), text, flags=re.S)


def section_span(text, parent):
    """(début_contenu, début_balise_fermante) de la section PARENT. ossec_config = la dernière."""
    m = masked(text)
    if parent == "ossec_config":
        close = m.rfind("</ossec_config>")
        if close < 0:
            fail("</ossec_config> introuvable")
        opens = [x.end() for x in re.finditer(r"<ossec_config\s*>", m) if x.end() <= close]
        if not opens:
            fail("<ossec_config> introuvable")
        return opens[-1], close
    o = re.search(r"<%s(\s[^>]*)?>" % re.escape(parent), m)
    if not o:
        fail(f"section <{parent}> absente de ossec.conf")
    c = m.find("</%s>" % parent, o.end())
    if c < 0:
        fail(f"section <{parent}> non fermée")
    return o.end(), c


def indent_of(text, pos):
    line_start = text.rfind("\n", 0, pos) + 1
    return re.match(r"[ \t]*", text[line_start:pos]).group()


def find_block(text, name):
    b, e = MARK_B.format(name), MARK_E.format(name)
    i = text.find(b)
    if i < 0:
        return None
    j = text.find(e, i)
    if j < 0:
        fail(f"marqueur de fin du bloc {name} absent : corriger ossec.conf à la main")
    # inclure l'indentation de la ligne du marqueur de début et le saut de ligne final
    start = text.rfind("\n", 0, i) + 1
    end = j + len(e)
    if text[end:end + 1] == "\n":
        end += 1
    return start, end


def render_block(name, content, indent):
    lines = [indent + MARK_B.format(name)]
    for ln in content.strip("\n").splitlines():
        lines.append((indent + ln) if ln.strip() else "")
    lines.append(indent + MARK_E.format(name))
    return "\n".join(lines) + "\n"


def cmd_block(text, parent, name, content):
    well_formed(content, f"contenu du bloc {name}")
    found = find_block(text, name)
    if found:
        start, end = found
        ind = indent_of(text, text.find(MARK_B.format(name), start))
        new = text[:start] + render_block(name, content, ind) + text[end:]
        return new, f"bloc « {name} » mis à jour" if new != text else f"bloc « {name} » inchangé"
    _, close = section_span(text, parent)
    close_ind = indent_of(text, close)
    ind = close_ind + "  "
    line_start = text.rfind("\n", 0, close) + 1
    if text[line_start:close].strip() == "":   # balise fermante seule sur sa ligne
        new = text[:line_start] + render_block(name, content, ind) + text[line_start:]
    else:
        new = text[:close] + "\n" + render_block(name, content, ind) + close_ind + text[close:]
    return new, f"bloc « {name} » ajouté dans <{parent}>"


def cmd_unblock(text, name):
    found = find_block(text, name)
    if not found:
        return text, f"bloc « {name} » absent (rien à faire)"
    return text[:found[0]] + text[found[1]:], f"bloc « {name} » supprimé"


def check_value(v):
    if any(ch in v for ch in "<>&"):
        fail(f"valeur « {v} » interdite (caractères < > &)")


def cmd_set(text, parent, tag, value):
    check_value(value)
    start, close = section_span(text, parent)
    m = masked(text)
    t = re.search(r"<%s>([^<]*)</%s>" % (re.escape(tag), re.escape(tag)), m[start:close])
    if t:
        a, b = start + t.start(1), start + t.end(1)
        old = text[a:b]
        if old == value:
            return text, f"<{parent}>/<{tag}> déjà à « {value} »"
        return text[:a] + value + text[b:], f"<{parent}>/<{tag}> : « {old} » -> « {value} »"
    ind = indent_of(text, close) + "  "
    line_start = text.rfind("\n", 0, close) + 1
    ins = f"{ind}<{tag}>{value}</{tag}>\n"
    if text[line_start:close].strip() == "":
        new = text[:line_start] + ins + text[line_start:]
    else:
        new = text[:close] + "\n" + ins + indent_of(text, close) + text[close:]
    return new, f"<{parent}>/<{tag}> ajoutée : « {value} »"


def cmd_setmulti(text, parent, tag, values):
    for v in values:
        check_value(v)
    start, close = section_span(text, parent)
    m = masked(text)
    pat = re.compile(r"[ \t]*<%s>[^<]*</%s>[ \t]*\n?" % (re.escape(tag), re.escape(tag)))
    spans = [(start + x.start(), start + x.end()) for x in pat.finditer(m[start:close])]
    ind = indent_of(text, close) + "  "
    ins = "".join(f"{ind}<{tag}>{v}</{tag}>\n" for v in values)
    if spans:
        new = text
        for a, b in reversed(spans[1:]):
            new = new[:a] + new[b:]
        a, b = spans[0]
        new = new[:a] + ins + new[b:]
    else:
        line_start = text.rfind("\n", 0, close) + 1
        new = text[:line_start] + ins + text[line_start:] if text[line_start:close].strip() == "" \
            else text[:close] + "\n" + ins + indent_of(text, close) + text[close:]
    msg = f"<{parent}>/<{tag}> = {', '.join(values)}"
    return new, (msg if new != text else msg + " (inchangé)")


def cmd_get(text, parent, tag):
    start, close = section_span(text, parent)
    m = masked(text)
    for x in re.finditer(r"<%s>([^<]*)</%s>" % (re.escape(tag), re.escape(tag)), m[start:close]):
        print(text[start + x.start(1):start + x.end(1)])


def cmd_migrate_v2(text):
    """Retire ce que la v2 du bundle ajoutait SANS marqueurs (source de doublons, ex. commande yara_linux
    définie deux fois) : le bloc « commandes et Active Response » et la ligne <list> de hashes."""
    msgs = []
    start = text.find("<!-- ===== wazuh-bundle : commandes et Active Response ===== -->")
    if start >= 0:
        anchor = text.find("<rules_id>100501,100502</rules_id>", start)
        end = text.find("</active-response>", anchor) if anchor >= 0 else -1
        if end < 0:
            fail("bloc v2 trouvé mais incomplet : le retirer à la main de ossec.conf")
        end += len("</active-response>")
        line_start = text.rfind("\n", 0, start) + 1
        if text[end:end + 1] == "\n":
            end += 1
        text = text[:line_start] + text[end:]
        msgs.append("bloc v2 « commandes et Active Response » retiré")
    pat = re.compile(r"[ \t]*<list>etc/lists/malware-sha256</list>[ \t]*\n")
    for mm in reversed(list(pat.finditer(text))):
        inside = text.rfind("<!-- wazuh-bundle:BEGIN", 0, mm.start()) > text.rfind("<!-- wazuh-bundle:END", 0, mm.start())
        if not inside:
            text = text[:mm.start()] + text[mm.end():]
            msgs.append("ligne v2 <list>etc/lists/malware-sha256</list> retirée")
    return text, "; ".join(msgs) if msgs else "aucun reliquat de la v2"


def write_atomic(path, text):
    st = os.stat(path)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ossec.conf.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except PermissionError:
        pass
    os.replace(tmp, path)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    path, cmd, args = argv[1], argv[2], argv[3:]
    text = open(path, encoding="utf-8").read()
    if cmd == "check":
        well_formed(re.sub(r"<\?xml[^>]*\?>", "", text), path)
        print("OK : syntaxe XML valide")
        return 0
    if cmd == "get" and len(args) == 2:
        cmd_get(text, *args)
        return 0
    if cmd == "hasblock" and len(args) == 1:
        return 0 if find_block(text, args[0]) else 1
    if cmd == "block" and len(args) == 3:
        new, msg = cmd_block(text, args[0], args[1], open(args[2], encoding="utf-8").read())
    elif cmd == "migrate-v2" and not args:
        new, msg = cmd_migrate_v2(text)
    elif cmd == "unblock" and len(args) == 1:
        new, msg = cmd_unblock(text, args[0])
    elif cmd == "set" and len(args) == 3:
        new, msg = cmd_set(text, *args)
    elif cmd == "setmulti" and len(args) >= 3:
        new, msg = cmd_setmulti(text, args[0], args[1], args[2:])
    else:
        print(__doc__)
        return 2
    if new != text:
        # Le fichier d'origine peut contenir des constructions tolérées par Wazuh mais pas par un parseur
        # XML strict : on vérifie donc seulement que NOTRE modification n'introduit pas d'erreur.
        def ok(t):
            try:
                ET.fromstring("<racine>" + re.sub(r"<\?xml[^>]*\?>", "", t) + "</racine>")
                return True
            except ET.ParseError:
                return False
        if ok(text) and not ok(new):
            fail("la modification rendrait ossec.conf invalide : rien n'a été écrit")
        write_atomic(path, new)
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
