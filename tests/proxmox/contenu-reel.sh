#!/bin/bash
# Fabrique des images de clés USB « comme sur le terrain » (à lancer en root sur une VM de
# construction Debian 13 : mkfs.ntfs, mkfs.exfat, mkfs.vfat, sgdisk, 7z, rar, zip, xorriso).
#
#   tests/proxmox/contenu-reel.sh DOSSIER [ISO_LINUX]
#
# DOSSIER/<scénario>.img  image à copier telle quelle sur la clé (dd), comme Etcher ou Rufus ;
# DOSSIER/<scénario>.sains   « sha256  chemin » des fichiers sains attendus en sortie ;
# DOSSIER/<scénario>.pieges  chemins des fichiers qui contiennent l'EICAR (à bloquer).
# ISO_LINUX : vraie ISO hybride (ex. netinst Debian) pour les scénarios Etcher / Rufus.
#
# Scénarios :
#   etcher      ISO hybride copiée brute sur la clé (Etcher, Rufus « mode DD », dd)
#   rufus-fat32 partition FAT32, contenu de l'ISO extrait + EICAR caché (Rufus « mode ISO »)
#   rufus-ntfs  GPT : partition NTFS avec un fichier de 4,5 Go + petite partition UEFI:NTFS (Rufus, Windows)
#   bureau      exFAT : tar, tar.gz, zip, rar, 7z, pdf, docx, pptx, xlsx, docm (macro), images,
#               ISO en tant que fichier ; pour chaque conteneur, une variante piégée par l'EICAR
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
OUT="$(realpath -m "${1:?DOSSIER}")"
ISO_LINUX="${2:-}"
# shellcheck disable=SC2016 # chaîne EICAR littérale
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
T="$(mktemp -d -p /var/tmp contenu.XXXXXX)"; trap 'umount "$T/m" 2>/dev/null || true; rm -rf "$T"' EXIT
mkdir -p "$OUT" "$T/m"

# Image de N Mo avec une table (mbr/gpt) et une partition du type donné, montée sur $T/m.
image() { # fichier taille_Mo table type_fs [étiquette]
    local f=$1 t=$2 table=$3 fs=$4 lab=${5:-CLE} l
    rm -f "$f"; truncate -s "${t}M" "$f"
    if [ "$table" = gpt ]; then sgdisk -o -n 1:2048:0 -t 1:0700 "$f" >/dev/null
    else echo "type=$( [ "$fs" = vfat ] && echo c || echo 7 )" | sfdisk -q "$f"; fi
    l=$(losetup -fP --show "$f")
    for _ in $(seq 20); do [ -b "${l}p1" ] && break; partx -u "$l" 2>/dev/null || true; sleep 0.5; done
    case "$fs" in
        vfat) mkfs.vfat -F32 -n "$lab" "${l}p1" >/dev/null ;;
        ntfs) mkfs.ntfs -Q -L "$lab" "${l}p1" >/dev/null ;;
        exfat) mkfs.exfat -n "$lab" "${l}p1" >/dev/null ;;
    esac
    mount "${l}p1" "$T/m"; echo "$l" > "$T/loop"
}
fermer() { # scénario : manifestes puis démontage
    (cd "$T/m" && find . -type f | sort | sed 's|^\./||' | while read -r p; do
        if grep -aq 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' "$p" || [ -n "$(conteneur_piege "$p")" ]; then echo "$p" >> "$OUT/$1.pieges"
        else sha256sum "$p" >> "$OUT/$1.sains"; fi
    done)
    umount "$T/m"; sync; losetup -d "$(cat "$T/loop")"
}
# Conteneurs compressés ou chiffrés : piégés si leur nom contient « piege » (fabriqués ainsi).
conteneur_piege() { case "$1" in *piege*) echo oui ;; esac; }
rm -f "$OUT"/*.sains "$OUT"/*.pieges

# ------------------------------------------------------------------ documents bureautiques
ooxml() { # fichier.docx|pptx|xlsx|docm  [piege]
    python3 - "$@" "$EICAR" <<'PY'
import sys, zipfile
f, piege, eicar = sys.argv[1], "piege" in sys.argv[2:-1], sys.argv[-1]
ext = f.rsplit(".", 1)[1]
ct = {"docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
      "docm": ("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"),
      "pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
      "xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")}[ext]
with zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", f'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/{ct[0]}" ContentType="{ct[1]}"/></Types>')
    z.writestr("_rels/.rels", f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{ct[0]}"/></Relationships>')
    z.writestr(ct[0], "<?xml version=\"1.0\"?><document>Compte rendu de chantier, semaine 46.</document>")
    if ext == "docm":
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"Attribute VB_Name = \"Module1\"\nSub AutoOpen()\nEnd Sub\n")
    if piege:
        z.writestr("word/media/image1.bin", eicar)
PY
}
pdf() { # fichier [piege] : PDF lisible ; piégé = EICAR en pièce jointe non compressée
    python3 - "$@" "$EICAR" <<'PY'
import sys
f, piege, eicar = sys.argv[1], len(sys.argv) > 3 and sys.argv[2] == "piege", sys.argv[-1]
objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>"]
texte = b"BT /F1 12 Tf 72 760 Td (Devis 2026-0412) Tj ET"
objs.append(b"<< /Length %d >>\nstream\n" % len(texte) + texte + b"\nendstream")
if piege:
    objs.append(b"<< /Type /EmbeddedFile /Length %d >>\nstream\n" % len(eicar) + eicar.encode() + b"\nendstream")
out, offs = bytearray(b"%PDF-1.4\n"), []
for i, o in enumerate(objs, 1):
    offs.append(len(out)); o = o.encode() if isinstance(o, str) else o
    out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
x = len(out)
out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
open(f, "wb").write(out)
PY
}

# ------------------------------------------------------------------ etcher : ISO brute
if [ -n "$ISO_LINUX" ]; then
    cp "$ISO_LINUX" "$OUT/etcher.img"
    mkdir -p "$T/iso"; xorriso -osirrox on -indev "$ISO_LINUX" -extract / "$T/iso" >/dev/null 2>&1
    (cd "$T/iso" && find . -type f | sort | sed 's|^\./||' | while read -r p; do sha256sum "$p"; done) > "$OUT/etcher.sains"
    : > "$OUT/etcher.pieges"
fi

# ------------------------------------------------------------------ rufus-fat32 : ISO extraite
if [ -n "$ISO_LINUX" ]; then
    image "$OUT/rufus-fat32.img" 2048 mbr vfat RUFUS
    cp -rL "$T/iso"/. "$T/m/" 2>/dev/null || true; chmod -R u+w "$T/m"   # Rufus copie la cible des liens
    mkdir -p "$T/m/tools"; printf '%s' "$EICAR" > "$T/m/tools/memtest.efi"   # piège caché parmi l'ISO
    fermer rufus-fat32
fi

# ------------------------------------------------------------------ rufus-ntfs : Windows, fichier > 4 Go
image "$OUT/rufus-ntfs.img" 5200 gpt ntfs ESD-USB
mkdir -p "$T/m/sources" "$T/m/boot" "$T/m/efi/boot"
head -c 4600M /dev/urandom > "$T/m/sources/install.wim"            # > 4 Go : impossible en FAT32
head -c 30M /dev/urandom > "$T/m/sources/boot.wim"
printf '[AutoRun]\nopen=setup.exe\n' > "$T/m/autorun.inf"
head -c 2M /dev/urandom > "$T/m/setup.exe"
printf '%s' "$EICAR" > "$T/m/sources/\$OEM\$.cmd"
fermer rufus-ntfs
# Petite partition « UEFI:NTFS » ajoutée par Rufus après la partition principale
sgdisk -e "$OUT/rufus-ntfs.img" >/dev/null

# ------------------------------------------------------------------ bureau : fichiers courants
image "$OUT/bureau.img" 3000 mbr exfat BUREAU
m="$T/m"; mkdir -p "$m/Documents/Chantier 46" "$m/Archives" "$m/Images" "$m/ISO"
s="$T/src"; mkdir -p "$s/projet/plans"
printf 'Note de chantier\nÉtat : conforme\n' > "$s/projet/note.txt"
head -c 3M /dev/urandom > "$s/projet/plans/plan-rdc.dwg"
printf '%s' "$EICAR" > "$s/eicar.com"
pdf "$m/Documents/devis-0412.pdf"; pdf "$m/Documents/facture-piege.pdf" piege
for e in docx pptx xlsx docm; do ooxml "$m/Documents/Chantier 46/rapport.$e"; ooxml "$m/Documents/Chantier 46/rapport-piege.$e" piege; done
tar -cf "$m/Archives/projet.tar" -C "$s" projet; tar -czf "$m/Archives/projet.tar.gz" -C "$s" projet
tar -czf "$m/Archives/projet-piege.tar.gz" -C "$s" projet eicar.com
(cd "$s" && zip -qr "$m/Archives/projet.zip" projet && zip -qr "$m/Archives/projet-piege.zip" projet eicar.com)
(cd "$s" && rar a -idq "$m/Archives/projet.rar" projet && rar a -idq "$m/Archives/projet-piege.rar" projet eicar.com)
(cd "$s" && 7z a -bd -bso0 "$m/Archives/projet.7z" projet && 7z a -bd -bso0 "$m/Archives/projet-piege.7z" projet eicar.com)
for i in 1 2 3; do head -c 4M /dev/urandom > "$m/Images/photo-$i.jpg"; done
xorriso -as mkisofs -quiet -V DONNEES -o "$m/ISO/donnees.iso" "$s/projet" 2>/dev/null
mkdir -p "$s/isopiege"; cp "$s/eicar.com" "$s/projet/note.txt" "$s/isopiege/"
xorriso -as mkisofs -quiet -V PIEGE -o "$m/ISO/donnees-piege.iso" "$s/isopiege" 2>/dev/null
[ -z "$ISO_LINUX" ] || cp "$ISO_LINUX" "$m/ISO/"
fermer bureau

ls -lh "$OUT"
