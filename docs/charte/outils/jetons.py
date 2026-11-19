#!/usr/bin/env python3
"""Charte Barbacane v2 : source unique = docs/charte/tokens.json.

Produit :
  docs/charte/jetons.toml      jetons à plat, lisibles par le code Rust de la borne (crate `toml`)
  docs/charte/web/jetons.css   variables CSS pour l'interface web du serveur (thème Jour par
                               défaut, Nuit par [data-theme="nuit"] ou préférence système)
et vérifie les contrastes WCAG des couples texte / fond déclarés plus bas (échec = code 1).

Usage : python3 docs/charte/outils/jetons.py [--verifier]   (--verifier : n'écrit rien)
"""
import json
import pathlib
import sys

ICI = pathlib.Path(__file__).resolve().parent.parent
J = json.loads((ICI / "tokens.json").read_text(encoding="utf-8"))
THEMES = [t["id"] for t in J["color"]["themes"]]


def val(tok, theme):
    v = tok["value"]
    return v if isinstance(v, str) else v.get(theme, v[THEMES[0]])


COUL = {t["name"]: t for t in J["color"]["tokens"]}


def rgba(h):
    h = h.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
    return r, g, b, a


def sur(fg, bg):
    """Couleur fg (éventuellement translucide) posée sur bg opaque."""
    r, g, b, a = fg
    return (r * a + bg[0] * (1 - a), g * a + bg[1] * (1 - a), b * a + bg[2] * (1 - a), 1.0)


def lum(c):
    def l(x):
        return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4

    return 0.2126 * l(c[0]) + 0.7152 * l(c[1]) + 0.0722 * l(c[2])


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# Couples à garantir : (texte, [fonds], seuil). 4.5 = texte courant, 3 = grand texte ou
# élément non textuel (bord de champ, anneau de focus, icône d'état).
FONDS_CLAIRS = ["sol-haut", "surface", "sol-bas", "surface-creuse", "surface-haute",
                "dalle-haut", "dalle-bas", "bloc-haut", "bloc-bas"]
COUPLES = [
    ("encre", FONDS_CLAIRS, 4.5),
    ("encre-douce", FONDS_CLAIRS, 4.5),
    ("sur-encre", ["encre", "encre-haut", "encre-bas"], 4.5),
    ("sur-bandeau", ["bandeau"], 4.5),
    ("sur-encre", ["menace", "sain", "analyse"], 4.5),
    ("sain", ["sain-fond", "surface-haute", "surface", "dalle-bas"], 4.5),
    ("alerte", ["alerte-fond", "surface-haute", "surface", "dalle-bas"], 4.5),
    ("menace", ["menace-fond", "surface-haute", "surface", "dalle-bas"], 4.5),
    ("analyse", ["analyse-fond", "surface-haute", "surface", "dalle-bas"], 4.5),
    ("hors-service", ["surface-haute", "dalle-bas"], 4.5),
    ("encre", ["laiton-pale", "sain-fond", "alerte-fond", "menace-fond", "analyse-fond"], 4.5),
    ("laiton", ["sol-haut", "surface", "sol-bas", "surface-haute", "bloc-bas"], 3.0),
    ("trait-fort", ["sol-haut", "surface", "surface-haute", "surface-creuse"], 3.0),
]


def verifier():
    echecs = []
    lignes = []
    for theme in THEMES:
        for fg, fonds, seuil in COUPLES:
            for bg in fonds:
                b = rgba(val(COUL[bg], theme))
                f = sur(rgba(val(COUL[fg], theme)), b)
                r = ratio(f, b)
                lignes.append(f"{theme:5} {fg:13} sur {bg:15} {r:5.2f} (≥ {seuil})")
                if r < seuil:
                    echecs.append(lignes[-1])
    return lignes, echecs


def toml():
    out = ["# GÉNÉRÉ par docs/charte/outils/jetons.py depuis tokens.json : ne pas modifier à la main.",
           f"# Charte Barbacane v{J['version']}.", ""]
    for theme in THEMES:
        out.append(f"[couleur.{theme}]")
        for t in J["color"]["tokens"]:
            out.append(f'{t["name"].replace("-", "_")} = "{val(t, theme)}"')
        out.append("")
    for fam in ("spacing", "radius", "duree"):
        out.append(f"[{ {'spacing': 'espace', 'radius': 'rayon', 'duree': 'duree'}[fam] }]")
        for t in J[fam]["tokens"]:
            v = t["value"]
            n = int(v.removesuffix("ms").removesuffix("px"))
            out.append(f'{t["name"].replace("-", "_")} = {n}')
        out.append("")
    out.append("[courbe]")
    for t in J["courbe"]["tokens"]:
        out.append(f'{t["name"].replace("-", "_")} = "{t["value"]}"')
    out.append("")
    for theme in THEMES:
        out.append(f"[relief.{theme}]")
        for t in J["shadow"]["tokens"]:
            out.append(f'{t["name"].replace("-", "_")} = "{val(t, theme)}"')
        out.append("")
    out.append("[texte]")
    for g in J["type"]["groups"]:
        for s in g["styles"]:
            fam = s.get("family", g["family"])
            out.append(f'{s["name"].replace("-", "_")} = {{ famille = "{fam}", taille = {int(s["fontSize"][:-2])}, '
                       f'interligne = {int(s["lineHeight"][:-2])}, graisse = {s["fontWeight"]} }}')
    return "\n".join(out) + "\n"


def css():
    def bloc(theme):
        lignes = [f"  --{t['name']}: {val(t, theme)};" for t in J["color"]["tokens"]]
        lignes += [f"  --{t['name']}: {val(t, theme)};" for t in J["shadow"]["tokens"]]
        return "\n".join(lignes)

    communs = []
    for fam in ("spacing", "radius", "duree", "courbe"):
        communs += [f"  --{t['name']}: {t['value']};" for t in J[fam]["tokens"]]
    for k, v in J["type"]["families"].items():
        communs.append(f"  --font-{k}: {v};")
    faces = []
    for f in J["type"]["fonts"]:
        faces.append(
            f"@font-face {{ font-family: \"{f['family']}\"; src: url(\"../{f['file']}\") format(\"truetype\"); "
            f"font-weight: {f['weight']}; font-display: swap; }}")
    nuit = bloc("nuit")
    return (
        "/* GÉNÉRÉ par docs/charte/outils/jetons.py depuis tokens.json : ne pas modifier à la main.\n"
        "   Interface web du serveur : charger ce fichier puis ../components/bundle.css.\n"
        "   Polices servies par le serveur lui-même (aucune ressource externe). */\n"
        + "\n".join(faces) + "\n\n"
        f":root, [data-theme=\"jour\"] {{\n  color-scheme: light;\n{bloc('jour')}\n}}\n"
        f"[data-theme=\"nuit\"] {{\n  color-scheme: dark;\n{nuit}\n}}\n"
        f"@media (prefers-color-scheme: dark) {{\n  :root:not([data-theme=\"jour\"]) {{\n    color-scheme: dark;\n"
        + "\n".join("  " + l for l in nuit.splitlines()) + "\n  }\n}\n"
        f":root {{\n" + "\n".join(communs) + "\n}\n"
    )


if __name__ == "__main__":
    lignes, echecs = verifier()
    if "-v" in sys.argv:
        print("\n".join(lignes))
    print(f"contrastes : {len(lignes)} couples vérifiés, {len(echecs)} échec(s)")
    for e in echecs:
        print("  ÉCHEC", e)
    if "--verifier" not in sys.argv:
        (ICI / "jetons.toml").write_text(toml(), encoding="utf-8")
        (ICI / "web").mkdir(exist_ok=True)
        (ICI / "web" / "jetons.css").write_text(css(), encoding="utf-8")
        print("écrits : jetons.toml, web/jetons.css")
    sys.exit(1 if echecs else 0)
