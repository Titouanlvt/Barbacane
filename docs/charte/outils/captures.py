#!/usr/bin/env python3
"""Captures PNG des aperçus de la charte, thèmes Jour et Nuit (Chrome sans tête, Playwright).

Chaque components/<Comp>/preview.html est rendu comme dans le Design System : jetons
(web/jetons.css), bundle.css, puis le contenu de l'aperçu, <html data-theme="…">.

Usage : python3 docs/charte/outils/captures.py [Comp ...]   (sans argument : les maquettes)
Sortie : docs/charte/maquettes/<Comp>-<theme>.png
"""
import pathlib
import re
import sys

from playwright.sync_api import sync_playwright

ICI = pathlib.Path(__file__).resolve().parent.parent
COMP = ICI / "components"
noms = sys.argv[1:] or sorted(p.name for p in COMP.iterdir() if p.name.startswith(("Ecran", "Serveur")))
(ICI / "maquettes").mkdir(exist_ok=True)

with sync_playwright() as pw:
    nav = pw.chromium.launch()
    for nom in noms:
        src = (COMP / nom / "preview.html").read_text(encoding="utf-8")
        m = re.match(r"<!--.*?width=(\d+).*?-->", src)
        largeur = int(m.group(1)) if m else 900
        for theme in ("jour", "nuit"):
            page = nav.new_page(viewport={"width": largeur, "height": 400}, device_scale_factor=1)
            html = (f'<!DOCTYPE html><html lang="fr" data-theme="{theme}"><head><meta charset="utf-8">'
                    f'<base href="{(COMP / nom).as_uri()}/">'
                    f'<link rel="stylesheet" href="{(ICI / "web" / "jetons.css").as_uri()}">'
                    f'<link rel="stylesheet" href="{(COMP / "bundle.css").as_uri()}"></head><body>{src}</body></html>')
            tmp = COMP / nom / ".capture.html"
            tmp.write_text(html, encoding="utf-8")
            page.goto(tmp.as_uri())
            page.wait_for_timeout(2500)
            sortie = ICI / "maquettes" / f"{nom}-{theme}.png"
            page.screenshot(path=str(sortie), full_page=True)
            tmp.unlink()
            page.close()
            print(sortie.relative_to(ICI))
    nav.close()
