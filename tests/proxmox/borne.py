#!/usr/bin/env python3
"""Pilotage de l'écran d'une VM borne Proxmox (QMP) : capture, lecture (OCR), clic.

  borne.py VMID capture FICHIER.png
  borne.py VMID attendre "texte" [DÉLAI_S] [CAPTURE.png]   # attend que le texte s'affiche
  borne.py VMID cliquer "texte" [CAPTURE.png]              # clique au centre du texte
  borne.py VMID xy X Y                                     # clic à une position absolue
  borne.py VMID lire                                       # texte reconnu à l'écran

Le clic passe par la tablette USB (positions absolues) : `mouse_move` du moniteur
HMP est relatif et part sur la souris PS/2. Lecture par tesseract (fra).
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unicodedata


def qmp(vm, *cmds):
    s = socket.socket(socket.AF_UNIX)
    s.connect(f"/var/run/qemu-server/{vm}.qmp")
    f = s.makefile("rw")
    f.readline()
    out = []
    for c, a in (("qmp_capabilities", None),) + cmds:
        f.write(json.dumps({"execute": c, **({"arguments": a} if a else {})}) + "\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                if "error" in r:
                    raise RuntimeError(f"QMP {c} : {r['error']}")
                out.append(r["return"])
                break
        if c == "input-send-event":
            time.sleep(0.12)
    s.close()
    return out[1:]


def capture(vm, png):
    d = tempfile.mkdtemp()
    ppm = os.path.join(d, "e.ppm")
    qmp(vm, ("screendump", {"filename": ppm}))
    for _ in range(50):
        if os.path.exists(ppm) and os.path.getsize(ppm) > 0:
            break
        time.sleep(0.1)
    time.sleep(0.3)
    with open(ppm, "rb") as f:
        _, l, h, _ = f.read(32).split(maxsplit=3)[:4]
    subprocess.run(["python3", "-c", PPM2PNG, ppm, png], check=True)
    pretraiter(ppm, png)
    os.remove(ppm)
    os.rmdir(d)
    return int(l), int(h)


# PPM → PNG sans dépendance (zlib de la bibliothèque standard)
PPM2PNG = r"""
import sys, zlib, struct
d = open(sys.argv[1], 'rb').read()
p = d.split(maxsplit=4)
l, h, px = int(p[1]), int(p[2]), p[4]
raw = b''.join(b'\x00' + px[y*l*3:(y+1)*l*3] for y in range(h))
c = lambda t, b: struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b))
open(sys.argv[2], 'wb').write(b'\x89PNG\r\n\x1a\n' + c(b'IHDR', struct.pack('>IIBBBBB', l, h, 8, 2, 0, 0, 0))
    + c(b'IDAT', zlib.compress(raw, 6)) + c(b'IEND', b''))
"""


def variante(png, v):
    """Chemin (temporaire) d'une variante OCR de la capture."""
    return os.path.join(tempfile.gettempdir(), "borne-ocr-" + os.path.basename(png) + v)


def pretraiter(ppm, png):
    """Variantes pour l'OCR : niveaux de gris ×2, normale et inversée (textes clairs sur
    boutons foncés), binarisées, dans le dossier temporaire."""
    d = open(ppm, "rb").read()
    p = d.split(maxsplit=4)
    l, h, px = int(p[1]), int(p[2]), p[4]
    g = bytes((px[i] * 3 + px[i + 1] * 6 + px[i + 2]) // 10 for i in range(0, l * h * 3, 3))
    lignes = []
    for y in range(h):
        r = g[y * l:(y + 1) * l]
        r2 = bytes(b for b in r for _ in (0, 1))
        lignes += [r2, r2]
    img = b"".join(lignes)
    entete = f"P5 {l * 2} {h * 2} 255\n".encode()
    # Binarisation : les bordures grises des boutons (≈ 130) et le fond (≈ 244) disparaissent.
    open(variante(png, ".n.pgm"), "wb").write(entete + bytes(0 if v < 70 else 255 for v in img))
    open(variante(png, ".m.pgm"), "wb").write(entete + bytes(0 if v < 150 else 255 for v in img))  # texte gris
    open(variante(png, ".i.pgm"), "wb").write(entete + bytes(0 if v > 240 else 255 for v in img))


def norm(t):
    t = unicodedata.normalize("NFKD", t.lower())
    return "".join(c for c in t if c.isalnum())


def mots(png):
    """Mots reconnus (texte, x, y, l, h) en coordonnées écran, sur les deux variantes."""
    r = []
    for v in (".n.pgm", ".m.pgm", ".i.pgm"):
        tsv = subprocess.run(["tesseract", variante(png, v), "-", "-l", "fra", "--psm", "11", "tsv"],
                             capture_output=True, text=True).stdout
        for ligne in tsv.splitlines()[1:]:
            c = ligne.split("\t")
            if len(c) == 12 and c[11].strip():
                r.append((c[11], int(c[6]) // 2, int(c[7]) // 2, int(c[8]) // 2, int(c[9]) // 2))
    return r


def trouver(png, texte):
    """Position (x, y) du centre de la suite de mots correspondant au texte, ou None."""
    cible = [norm(m) for m in texte.split() if norm(m)]
    w = [m for m in mots(png) if norm(m[0])]
    for i in range(len(w) - len(cible) + 1):
        seq = w[i:i + len(cible)]
        if all(norm(a[0]) == b for a, b in zip(seq, cible)):
            x0 = min(m[1] for m in seq)
            y0 = min(m[2] for m in seq)
            x1 = max(m[1] + m[3] for m in seq)
            y1 = max(m[2] + m[4] for m in seq)
            return (x0 + x1) // 2, (y0 + y1) // 2
    return None


def lire(png):
    return "\n".join(subprocess.run(["tesseract", variante(png, v), "-", "-l", "fra"], capture_output=True,
                                     text=True).stdout for v in (".n.pgm", ".m.pgm", ".i.pgm"))


def clic(vm, x, y, l, h):
    a = lambda axe, v, m: {"type": "abs", "data": {"axis": axe, "value": v * 32767 // (m - 1)}}
    b = lambda d: {"type": "btn", "data": {"button": "left", "down": d}}
    qmp(vm, ("input-send-event", {"events": [a("x", x, l), a("y", y, h)]}),
        ("input-send-event", {"events": [b(True)]}),
        ("input-send-event", {"events": [b(False)]}))


def main():
    vm, op = sys.argv[1], sys.argv[2]
    tmp = os.path.join(tempfile.gettempdir(), f"borne-{vm}.png")
    if op == "capture":
        capture(vm, sys.argv[3])
    elif op == "lire":
        capture(vm, tmp)
        print(lire(tmp))
    elif op == "xy":
        l, h = capture(vm, tmp)
        clic(vm, int(sys.argv[3]), int(sys.argv[4]), l, h)
    elif op == "attendre":
        delai = float(sys.argv[4]) if len(sys.argv) > 4 else 120
        fin = time.time() + delai
        while True:
            capture(vm, tmp)
            if norm(sys.argv[3]) in norm(lire(tmp)):
                if len(sys.argv) > 5:
                    capture(vm, sys.argv[5])
                return
            if time.time() > fin:
                sys.exit(f"ÉCHEC : « {sys.argv[3]} » absent de l'écran après {delai:.0f} s ; écran :\n{lire(tmp)}")
            time.sleep(3)
    elif op == "cliquer":
        for _ in range(5):
            l, h = capture(vm, tmp)
            p = trouver(tmp, sys.argv[3])
            if p:
                if len(sys.argv) > 4:
                    capture(vm, sys.argv[4])
                clic(vm, p[0], p[1], l, h)
                time.sleep(1)
                return
            time.sleep(2)
        sys.exit(f"ÉCHEC : bouton « {sys.argv[3]} » introuvable ; écran :\n{lire(tmp)}")
    elif op == "pin":
        # Chiffres isolés mal lus par l'OCR : position calculée depuis le bouton « effacer »
        # (pavé centré, touches de 60 px espacées de 6 px, voir client/src/keyboard.rs).
        l, h = capture(vm, tmp)
        p = trouver(tmp, "effacer")
        if not p:
            sys.exit(f"ÉCHEC : pavé numérique introuvable ; écran :\n{lire(tmp)}")
        pas, cx = 66, l // 2
        lignes = {"123": 4, "456": 3, "789": 2}
        for c in sys.argv[3]:
            if c == "0":
                x, y = cx, p[1] - pas
            else:
                r = next(k for k in lignes if c in k)
                x, y = cx + (r.index(c) - 1) * pas, p[1] - lignes[r] * pas
            clic(vm, x, y, l, h)
            time.sleep(0.3)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
