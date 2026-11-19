#!/usr/bin/env python3
"""Séquences 3D pré-calculées de la charte Barbacane v2 (emblème, clé USB, disque, bouclier).

Petit moteur volontairement simple et reproductible (numpy + Pillow, aucun logiciel 3D) :
  - géométrie = prismes (un contour 2D extrudé en profondeur) ;
  - projection orthographique, caméra légèrement au-dessus (tangage) ;
  - une seule lumière, en haut à gauche et un peu devant (la même que celle des ombres CSS) ;
  - ombrage plat par face (ambiante + diffuse), tri du peintre, suréchantillonnage x4 ;
  - ombre de contact floue cuite dans l'image.
Les couleurs viennent de tokens.json : relancer ce script après tout changement de palette.

Sortie : docs/charte/3d/<sequence>-<theme>.png, une BANDE horizontale d'images carrées
(image n à x = n × côté), plus 3d/sequences.json (côté, nombre d'images, cadence conseillée).

Usage : python3 docs/charte/outils/sequences3d.py [cote=240]
"""
import json
import math
import pathlib
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

ICI = pathlib.Path(__file__).resolve().parent.parent
SORTIE = ICI / "3d"
J = json.loads((ICI / "tokens.json").read_text(encoding="utf-8"))
COTE = int(sys.argv[1]) if len(sys.argv) > 1 else 240
SS = 4  # suréchantillonnage

LUMIERE = np.array([-0.55, 0.75, 0.62])
LUMIERE /= np.linalg.norm(LUMIERE)


def coul(nom, theme):
    t = next(t for t in J["color"]["tokens"] if t["name"] == nom)
    v = t["value"] if isinstance(t["value"], str) else t["value"][theme]
    v = v.lstrip("#")[:6]
    return np.array([int(v[i : i + 2], 16) for i in (0, 2, 4)], dtype=float)


def matieres(theme):
    """Matières de l'emblème et des objets, tirées de la palette."""
    nuit = theme == "nuit"
    return {
        # pierre : sombre en Jour (comme le logo plat en encre), claire en Nuit
        "pierre": coul("encre", theme) * (1.0 if nuit else 1.0) + (0 if nuit else 52),
        "laiton": coul("laiton-clair", theme) * (0.92 if nuit else 0.95),
        "porte": coul("surface-creuse", "nuit") * 0.9,
        "socle": coul("trait-fort", theme) * (0.85 if nuit else 1.05),
        "sain": coul("sain", theme),
        "coche": coul("sain-fond", theme),
        "cle": coul("encre", theme) + (0 if nuit else 30),
        "cle-laiton": coul("laiton", theme) * (1.05 if not nuit else 0.95),
        "cle-blanche": coul("dalle-haut", "jour") * 0.97,
        "metal": np.array([196.0, 199, 204]),
        "disque": coul("surface-haute", "jour"),
        "reflet-a": coul("laiton-clair", theme),
        "reflet-b": coul("analyse", "nuit"),
        "moyeu": coul("trait", "jour"),
    }


# ------------------------------------------------------------------ géométrie


def creneaux(x0, x1, y, n, h):
    """Points du sommet crénelé de gauche à droite : n merlons de hauteur h."""
    pts = []
    w = (x1 - x0) / (2 * n - 1)
    for i in range(2 * n - 1):
        xa, xb = x0 + i * w, x0 + (i + 1) * w
        if i % 2 == 0:
            pts += [(xa, y + h), (xb, y + h)]
        else:
            pts += [(xa, y), (xb, y)]
    return pts


def tour(x0, x1, haut, n=3, h=5):
    return [(x0, 0)] + creneaux(x0, x1, haut, n, h) + [(x1, 0)]


def courtine(x0, x1, haut, porte_l, porte_h):
    """Mur crénelé percé d'une porte en arc (contour en U, sans trou)."""
    r = porte_l / 2
    pts = [(x0, 0)] + creneaux(x0, x1, haut, 4, 4) + [(x1, 0), (r, 0), (r, porte_h - r)]
    for k in range(1, 12):
        a = math.pi * k / 12
        pts.append((r * math.cos(a), porte_h - r + r * math.sin(a)))
    pts += [(-r, porte_h - r), (-r, 0)]
    return pts


def rect(x0, y0, x1, y1):
    return [(x0, y0), (x0, y1), (x1, y1), (x1, y0)]


def cercle(cx, cy, r, n=40):
    return [(cx + r * math.cos(2 * math.pi * k / n), cy + r * math.sin(2 * math.pi * k / n)) for k in range(n)]


class Prisme:
    def __init__(self, contour, z0, z1, mat, sy=1.0, dy=0.0, dx=0.0):
        c = [(x + dx, y * sy + dy) for x, y in contour]
        aire = sum(xa * yb - xb * ya for (xa, ya), (xb, yb) in zip(c, c[1:] + c[:1]))
        self.c = c if aire > 0 else c[::-1]  # sens trigonométrique : normales vers l'extérieur
        self.z0, self.z1, self.mat = z0, z1, mat

    def faces(self):
        """(sommets, normale, matière) ; normales explicites (contours concaves)."""
        c = self.c
        yield [(x, y, self.z1) for x, y in c], (0, 0, 1), self.mat
        yield [(x, y, self.z0) for x, y in c], (0, 0, -1), self.mat
        for i in range(len(c)):
            (xa, ya), (xb, yb) = c[i], c[(i + 1) % len(c)]
            l = math.hypot(xb - xa, yb - ya)
            if l < 1e-9:
                continue
            yield ([(xa, ya, self.z1), (xa, ya, self.z0), (xb, yb, self.z0), (xb, yb, self.z1)],
                   ((yb - ya) / l, -(xb - xa) / l, 0), self.mat)


def rot(lacet, tangage):
    a, b = math.radians(lacet), math.radians(tangage)
    ry = np.array([[math.cos(a), 0, math.sin(a)], [0, 1, 0], [-math.sin(a), 0, math.cos(a)]])
    rx = np.array([[1, 0, 0], [0, math.cos(b), -math.sin(b)], [0, math.sin(b), math.cos(b)]])
    return rx @ ry


def rendre(prismes, mats, lacet, tangage, echelle, centre=(0, 0), ombre=True, sol_y=0.0):
    n = COTE * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    R = rot(lacet, tangage)
    k = echelle * SS
    cx, cy = n / 2 + centre[0] * SS, n / 2 + centre[1] * SS

    def proj(p):
        q = R @ np.array(p, dtype=float)
        return (cx + q[0] * k, cy - q[1] * k), q[2]

    if ombre:
        # ombre de contact : ellipse floue sous l'objet, décalée vers la droite (lumière à gauche)
        calque = Image.new("L", (n, n), 0)
        xs = [x for p in prismes for x, _ in p.c]
        l = (max(xs) - min(xs)) * k * 0.62
        (ox, oy), _ = proj((0.08 * (max(xs) - min(xs)), sol_y, -2))
        ImageDraw.Draw(calque).ellipse([ox - l, oy - l * 0.14, ox + l, oy + l * 0.14], fill=110)
        calque = calque.filter(ImageFilter.GaussianBlur(5 * SS))
        noir = Image.new("RGBA", (n, n), (20, 16, 10, 255))
        img.paste(noir, (0, 0), calque)

    faces = []
    for p in prismes:
        for pts, nrm, mat in p.faces():
            P = np.array(pts, dtype=float)
            Q = (R @ P.T).T
            nrm = R @ np.array(nrm, dtype=float)
            if nrm[2] <= 1e-4:  # face cachée
                continue
            d = max(0.0, float(nrm @ LUMIERE))
            base = mats[mat]
            c = np.clip(base * (0.42 + 0.68 * d), 0, 255)
            ecran = [(cx + q[0] * k, cy - q[1] * k) for q in Q]
            faces.append((Q[:, 2].mean(), ecran, tuple(int(v) for v in c) + (255,)))
    faces.sort(key=lambda f: f[0])
    dr = ImageDraw.Draw(img)
    for _, ecran, c in faces:
        dr.polygon(ecran, fill=c)
    return img.resize((COTE, COTE), Image.LANCZOS)


# ------------------------------------------------------------------ objets


def embleme(herse=1.0, montee=(1.0, 1.0, 1.0)):
    """herse : 1 levée, 0 fermée. montee : hauteur relative (tour g, courtine, tour d)."""
    g, m, d = montee
    p = [Prisme(rect(-38, -5, 38, 0), -18, 4, "socle")]
    if m > 0:
        p.append(Prisme(courtine(-15, 15, 45, 15, 25), -11, -3, "pierre", sy=m))
        p.append(Prisme(rect(-15, 0, 15, 30), -17, -15, "porte", sy=m))  # fond de la porte
    if g > 0:
        p.append(Prisme(tour(-31, -13, 56), -14, 0, "pierre", sy=g))
    if d > 0:
        p.append(Prisme(tour(13, 31, 56), -14, 0, "pierre", sy=d))
    if m > 0.99:
        lev = herse * 22  # course de la herse
        for x in (-4.5, 0, 4.5):
            p.append(Prisme(rect(x - 0.9, 0, x + 0.9, 24), -8.2, -6.6, "laiton", dy=lev))
        for y in (5, 11, 17):
            p.append(Prisme(rect(-7.4, y - 0.9, 7.4, y + 0.9), -8.6, -6.4, "laiton", dy=lev))
    return p


def cle(mat="cle"):
    return [
        Prisme([(-24, -9), (-24, 9), (12, 9), (12, -9)], -4, 4, mat),  # corps
        Prisme(rect(12, -6, 26, 6), -3, 3, "metal"),  # embout
        Prisme(rect(16, 1.5, 19, 4), 3, 3.4, "porte"),  # trous de l'embout
        Prisme(rect(21, 1.5, 24, 4), 3, 3.4, "porte"),
        Prisme(cercle(-18, 0, 2.6, 16), 4, 4.6, "laiton" if mat == "cle" else "cle"),  # anneau
    ]


def bouclier_contour():
    pts = [(0, 30), (24, 22), (24, 2)]
    for k in range(1, 12):
        t = k / 12
        pts.append((24 * (1 - t) ** 1.2, 2 - 32 * math.sin(t * math.pi / 2)))
    pts.append((0, -30))
    for x, y in reversed(pts[1:-1]):
        pts.append((-x, y))
    return pts


def bouclier():
    coche = [(-11, 1), (-8, 4), (-5, 1), (8, 14), (11, 11), (-5, -5)]
    return [
        Prisme(bouclier_contour(), -5, 0, "sain"),
        Prisme(coche, 0, 2.2, "coche"),
    ]


# ------------------------------------------------------------------ disque (2D direct)


def disque(angle, mats):
    """Disque optique vu en biais (ellipse 1 : 0,46), tranche visible, deux reflets qui tournent."""
    n = COTE * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    cx, cy, R = n / 2, n / 2 - 4 * SS, n * 0.42
    ry = 0.46
    calque = Image.new("L", (n, n), 0)
    ImageDraw.Draw(calque).ellipse([cx - R * 0.9 + 10 * SS, cy + R * ry + 2 * SS, cx + R * 0.9 + 10 * SS, cy + R * ry + 26 * SS], fill=95)
    img.paste(Image.new("RGBA", (n, n), (20, 16, 10, 255)), (0, 0), calque.filter(ImageFilter.GaussianBlur(6 * SS)))
    dr = ImageDraw.Draw(img)
    ep = 5 * SS
    tranche = tuple(int(v) for v in mats["disque"] * 0.55) + (255,)
    dr.ellipse([cx - R, cy - R * ry + ep, cx + R, cy + R * ry + ep], fill=tranche)
    face = tuple(int(v) for v in mats["disque"] * 0.92) + (255,)
    dr.ellipse([cx - R, cy - R * ry, cx + R, cy + R * ry], fill=face)

    def pt(r, a):
        return (cx + r * math.cos(a), cy + r * ry * math.sin(a))

    for base, coulr in ((0, "reflet-a"), (math.pi, "reflet-b")):
        a0 = math.radians(angle) + base
        poly = [pt(R * 0.36, a0)] + [pt(R * 0.97, a0 + t * 0.5) for t in np.linspace(0, 1, 14)] + [pt(R * 0.36, a0 + 0.5)]
        c = mats[coulr]
        dr.polygon(poly, fill=tuple(int(v) for v in (c * 0.6 + mats["disque"] * 0.4)) + (255,))
    for r, c in ((R * 0.30, mats["moyeu"]), (R * 0.27, mats["disque"] * 0.8), (R * 0.12, None)):
        box = [cx - r, cy - r * ry, cx + r, cy + r * ry]
        if c is None:
            dr.ellipse(box, fill=(0, 0, 0, 0))
        else:
            dr.ellipse(box, fill=tuple(int(v) for v in c) + (255,))
    # arête éclairée en haut à gauche
    dr.arc([cx - R, cy - R * ry, cx + R, cy + R * ry], 190, 260, fill=(255, 255, 255, 170), width=2 * SS)
    return img.resize((COTE, COTE), Image.LANCZOS)


# ------------------------------------------------------------------ séquences


def ease(p):
    return 4 * p ** 3 if p < 0.5 else 1 - (-2 * p + 2) ** 3 / 2


def sequences(theme):
    m = matieres(theme)
    E = 2.6  # échelle de l'emblème (unités → px)
    s = {}
    s["embleme-pivot"] = ([rendre(embleme(), m, -22 + 44 * ease(i / 23), 14, E, (0, 72)) for i in range(24)], 15,
                          "Veille : l'emblème pivote de -22° à +22° puis revient (lecture aller-retour).")
    s["embleme-herse"] = ([rendre(embleme(herse=1 - ease(i / 15)), m, -18, 14, E, (0, 72)) for i in range(16)], 30,
                          "Verdict bloqué : la herse tombe (courbe lourde).")

    def montee(p):
        f = lambda q: max(0.0, min(1.0, ease(max(0.0, q))))
        return (f(p * 2.2), f(p * 2.2 - 0.5), f(p * 2.2 - 0.25))

    s["embleme-construction"] = ([rendre(embleme(herse=0.0 if i < 23 else 1.0, montee=montee(i / 23)), m, -18, 14, E, (0, 72)) for i in range(24)]
                                 + [rendre(embleme(herse=ease(k / 7)), m, -18, 14, E, (0, 72)) for k in range(8)], 15,
                                 "Démarrage : les tours puis la courtine montent du sol, la herse se lève.")
    s["cle"] = ([rendre(cle(), m, 62 - 62 * ease(i / 15), 18, 3.6, (0, 0), sol_y=-9) for i in range(16)], 30,
                "Insertion : la clé à analyser pivote de 62° vers la porte.")
    s["cle-destination"] = ([rendre(cle("cle-laiton"), m, -62 + 62 * ease(i / 15), 18, 3.6, (0, 0), sol_y=-9) for i in range(16)], 30,
                            "Clé de destination (laiton) : pivote de -62° à 0°.")
    s["cle-blanche"] = ([rendre(cle("cle-blanche"), m, 0, 18, 3.6, (0, 0), sol_y=-9)], 1,
                        "Blanchiment : la clé une fois blanchie (une seule image), révélée par une fenêtre qui descend.")
    s["bouclier"] = ([rendre(bouclier(), m, 88 - 88 * ease(i / 13), 8, 3.1, (0, 4), sol_y=-30) for i in range(14)], 30,
                     "Verdict sain : le bouclier pivote de la tranche vers la face.")
    s["disque"] = ([disque(i * 10, m) for i in range(18)], 30,
                   "Disque : 18 images = un demi-tour (reflets symétriques). Boucle 0,6 s.")
    return s


if __name__ == "__main__":
    SORTIE.mkdir(exist_ok=True)
    index = {"cote": COTE, "sequences": {}}
    for theme in ("jour", "nuit"):
        for nom, (images, ips, note) in sequences(theme).items():
            bande = Image.new("RGBA", (COTE * len(images), COTE), (0, 0, 0, 0))
            for i, im in enumerate(images):
                bande.paste(im, (i * COTE, 0))
            # palette de 160 couleurs avec alpha : divise le poids par ~3 sans bandes visibles
            q = bande.quantize(colors=160, method=Image.Quantize.FASTOCTREE)
            chemin = SORTIE / f"{nom}-{theme}.png"
            q.save(chemin, optimize=True)
            index["sequences"].setdefault(nom, {"images": len(images), "ips": ips, "note": note, "poids": {}})
            index["sequences"][nom]["poids"][theme] = chemin.stat().st_size
            print(f"{chemin.name:32} {len(images):3} images  {chemin.stat().st_size // 1024:4} Kio")
    (SORTIE / "sequences.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
