#!/bin/bash
# Construit l'ISO d'installation hors ligne de la borne : ISO officielle Debian 13
# « netinst » (système de base) + paquets Barbacane et toutes leurs dépendances.
# À lancer en root sur Debian 13 (ou dans un conteneur debian:trixie), réseau requis
# pendant la construction seulement. L'ISO installe sans aucune question ni réseau.
#
#   systeme/iso/build-iso.sh [--debs DOSSIER] [--cle-publique maj.pub]
#                                     [--clamav DOSSIER] [--yara DOSSIER] [--netinst ISO] [--sortie FICHIER.iso]
#                                     [--verbeux]
#     --debs          paquets usbsas-server, usbsas-hid, barbacane (défaut : construits par build-debs.sh)
#     --cle-publique  clé minisign des mises à jour (défaut : systeme/iso/maj.pub s'il existe)
#     --clamav        base ClamAV initiale (défaut : téléchargée avec freshclam)
#     --yara          règles YARA initiales
#     --netinst       ISO netinst Debian 13 amd64 déjà téléchargée (défaut : dernière version, empreinte vérifiée)
#     --verbeux       affiche tout le détail à l'écran (sinon : dans le journal, à côté de l'ISO)
set -Eeuo pipefail
# « su » sans « - » garde le PATH de l'utilisateur, sans /usr/sbin : debootstrap, mkfs… y sont.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
DEBS='' CLE_PUB='' CLAMAV='' YARA='' NETINST='' SORTIE="$PWD/barbacane.iso" VERBEUX=0
[ -f "$ICI/maj.pub" ] && CLE_PUB="$ICI/maj.pub"
while [ $# -gt 0 ]; do
    case "$1" in
        --debs) DEBS="$(realpath "$2")"; shift 2 ;;
        --cle-publique) CLE_PUB="$(realpath "$2")"; shift 2 ;;
        --clamav) CLAMAV="$(realpath "$2")"; shift 2 ;;
        --yara) YARA="$(realpath "$2")"; shift 2 ;;
        --netinst) NETINST="$(realpath "$2")"; shift 2 ;;
        --sortie) SORTIE="$(realpath -m "$2")"; shift 2 ;;
        --verbeux) VERBEUX=1; shift ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1 (voir --help)" >&2; exit 1 ;;
    esac
done

# ------------------------------------------------------------------ affichage et journal
JOURNAL="${SORTIE%.iso}.log"
DEBUT=$(date +%s)
ETAPE="" ETAPE_DEBUT=0 N=0 TOTAL=6
if [ -t 1 ]; then GRAS=$'\e[1m' VERT=$'\e[32m' ROUGE=$'\e[31m' JAUNE=$'\e[33m' FIN=$'\e[0m'
else GRAS='' VERT='' ROUGE='' JAUNE='' FIN=''; fi
duree() { printf '%d min %02d s' $(($1 / 60)) $(($1 % 60)); }
etape() {
    fin_etape
    N=$((N + 1)) ETAPE="$1" ETAPE_DEBUT=$(date +%s)
    printf '%s[%d/%d]%s %s\n' "$GRAS" "$N" "$TOTAL" "$FIN" "$ETAPE"
    echo "=== [$N/$TOTAL] $ETAPE ($(date -Is))" >> "$JOURNAL"
}
fin_etape() {
    [ -n "$ETAPE" ] || return 0
    printf '      %sOK%s (%s)\n' "$VERT" "$FIN" "$(duree $(($(date +%s) - ETAPE_DEBUT)))"
    ETAPE=""
}
note() { printf '      %s\n' "$*"; echo "--- $*" >> "$JOURNAL"; }
attention() { printf '      %sATTENTION%s : %s\n' "$JAUNE" "$FIN" "$*"; echo "ATTENTION : $*" >> "$JOURNAL"; }
# Commande dont le détail va au journal (à l'écran avec --verbeux).
journal() {
    if [ "$VERBEUX" = 1 ]; then "$@" 2>&1 | tee -a "$JOURNAL"; return "${PIPESTATUS[0]}"
    else "$@" >> "$JOURNAL" 2>&1; fi
}
echec() {
    local code=$?
    trap - ERR
    printf '      %sÉCHEC%s\n\n' "$ROUGE" "$FIN"
    echo "La construction s'est arrêtée à l'étape « ${ETAPE:-préparation} » (code $code)."
    if [ -s "$JOURNAL" ]; then
        echo "Dernières lignes du journal ($JOURNAL) :"
        tail -n 25 "$JOURNAL" | sed 's/^/  │ /'
    fi
    exit "$code"
}
trap echec ERR
mkdir -p "$(dirname "$SORTIE")"
: > "$JOURNAL"

# ------------------------------------------------------------------ vérifications préalables
printf '%s%s%s (journal : %s)\n' "$GRAS" "Construction de l'ISO Barbacane" "$FIN" "$JOURNAL"
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root : « su - » (avec le tiret) ou « sudo -i »." >&2; exit 1; }
if [ -e /etc/pve ]; then
    echo "REFUS : hôte Proxmox VE détecté (/etc/pve). Construisez l'ISO sur un poste ou dans une VM." >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
[ "${VERSION_CODENAME:-}" = trixie ] || attention "système ${PRETTY_NAME:-inconnu} : seul Debian 13 (trixie) est testé"
LIBRE_GO=$(( $(df -Pk "$(dirname "$SORTIE")" | awk 'NR==2 {print $4}') / 1024 / 1024 ))
[ "$LIBRE_GO" -ge 15 ] || { echo "Espace disque insuffisant : $LIBRE_GO Go libres, 15 Go nécessaires." >&2; exit 1; }
getent hosts deb.debian.org >/dev/null || { echo "Réseau indisponible (deb.debian.org introuvable) : nécessaire pendant la construction." >&2; exit 1; }
# Dossier de travail hors de /tmp : souvent monté « nodev », ce que debootstrap signale.
T="$(mktemp -d -p /var/tmp barbacane-iso.XXXXXX)"
trap 'rm -rf "$T"' EXIT
B="$T/iso/barbacane"
mkdir -p "$B/debs"
export DEBIAN_FRONTEND=noninteractive
MIROIR=http://deb.debian.org/debian

# ------------------------------------------------------------------ 1. outils
etape "Outils de construction"
journal apt-get update -qq
journal apt-get install -y -qq --no-install-recommends xorriso debootstrap wget ca-certificates openssl clamav-freshclam

# ------------------------------------------------------------------ 2. paquets Barbacane
etape "Paquets Barbacane (compilation : 10 à 40 min)"
if [ -z "$DEBS" ]; then
    journal "$REPO/systeme/build-debs.sh"
    DEBS="$REPO/systeme/mkosi/paquets"
    note "$(grep -m1 '^Mémoire disponible' "$JOURNAL" || true)"
else
    note "paquets fournis : $DEBS"
fi
for p in usbsas-server usbsas-hid barbacane; do
    ls "$DEBS"/${p}_*.deb >/dev/null 2>&1 || { echo "paquet $p absent de $DEBS" >> "$JOURNAL"; false; }
done

# ------------------------------------------------------------------ 3. ISO Debian
etape "ISO netinst Debian 13 (téléchargement et empreinte)"
if [ -z "$NETINST" ]; then
    URL=https://cdimage.debian.org/debian-cd/current/amd64/iso-cd
    journal wget -q -O "$T/SHA256SUMS" "$URL/SHA256SUMS"
    NOM=$(awk '/-amd64-netinst\.iso$/ { print $2; exit }' "$T/SHA256SUMS")
    journal wget -q -O "$T/$NOM" "$URL/$NOM"
    (cd "$T" && grep " $NOM\$" SHA256SUMS | journal sha256sum -c -)
    NETINST="$T/$NOM"
    note "$NOM (empreinte vérifiée)"
fi

# ------------------------------------------------------------------ 4. dépendances
etape "Dépendances (résolues dans un Debian 13 minimal)"
journal debootstrap --variant=minbase trixie "$T/chroot" "$MIROIR"
echo "deb $MIROIR trixie main contrib non-free non-free-firmware" > "$T/chroot/etc/apt/sources.list"
mkdir -p "$T/chroot/debs"
cp "$DEBS"/usbsas-server_*.deb "$DEBS"/usbsas-hid_*.deb "$DEBS"/barbacane_*.deb "$T/chroot/debs/"
journal chroot "$T/chroot" apt-get update -qq
mapfile -t PAQUETS < <(grep -vE '^\s*(#|$)|^(barbacane|usbsas-server|usbsas-hid)$' "$ICI/paquets.txt")
journal chroot "$T/chroot" sh -c 'apt-get install -y -qq --download-only --no-install-recommends "$@" /debs/*.deb' sh "${PAQUETS[@]}"
cp "$T"/chroot/var/cache/apt/archives/*.deb "$T"/chroot/debs/*.deb "$B/debs/"
note "$(find "$B/debs" -name '*.deb' | wc -l) paquets embarqués"

# ------------------------------------------------------------------ 5. données initiales
etape "Données initiales (base ClamAV, clé de mise à jour)"
mkdir -p "$T/donnees/var/lib/clamav" "$T/donnees/var/lib/barbacane/yara"
if [ -n "$CLAMAV" ]; then
    cp "$CLAMAV"/*.c[lv]d "$T/donnees/var/lib/clamav/"
else
    printf 'DatabaseMirror database.clamav.net\nDatabaseDirectory %s\nDatabaseOwner root\n' \
        "$T/donnees/var/lib/clamav" > "$T/freshclam.conf"
    # --no-dns : version lue directement sur le miroir (pas d'avertissement « DNS Update Info »).
    journal freshclam --config-file="$T/freshclam.conf" --foreground --stdout --no-dns \
        || attention "base ClamAV non téléchargée : la borne refusera tout jusqu'à une mise à jour"
fi
note "base ClamAV : $(find "$T/donnees/var/lib/clamav" -name '*.c[lv]d' | wc -l) fichier(s)"
if [ -n "$YARA" ]; then cp "$YARA"/*.yar "$T/donnees/var/lib/barbacane/yara/"; fi
tar -cf "$B/donnees.tar" -C "$T/donnees" .
if [ -n "$CLE_PUB" ]; then
    cp "$CLE_PUB" "$B/maj.pub"
    note "clé de mise à jour : $CLE_PUB"
else
    attention "aucune clé publique de mise à jour (systeme/iso/maj.pub) : mises à jour impossibles sur les bornes"
fi
# L'installateur exige un mot de passe root : aléatoire, jamais conservé, compte verrouillé ensuite
sed "s|@HACHE_ROOT@|$(head -c 32 /dev/urandom | base64 | openssl passwd -6 -stdin)|" "$ICI/preseed.cfg" > "$B/preseed.cfg"
cp "$ICI/choisir-disque.sh" "$ICI/fin-installation.sh" "$ICI/configurer.sh" "$B/"

# ------------------------------------------------------------------ 6. assemblage
etape "Assemblage de l'ISO"
# Menu de démarrage unique (BIOS et UEFI) : installation automatique après 10 s
PARAMS="auto=true priority=critical preseed/file=/cdrom/barbacane/preseed.cfg locale=fr_FR.UTF-8 keymap=fr --- quiet"
cat > "$T/grub.cfg" <<CFG
set timeout=10
set default=0
menuentry "Installer BARBACANE (EFFACE le disque interne)" {
    linux /install.amd/vmlinuz $PARAMS
    initrd /install.amd/initrd.gz
}
CFG
cat > "$T/isolinux.cfg" <<CFG
default barbacane
prompt 0
timeout 100
say Installation BARBACANE dans 10 s : le disque interne sera EFFACE.
label barbacane
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz $PARAMS
CFG
rm -f "$SORTIE"
# Nom de volume conforme ISO 9660 (majuscules, chiffres, « _ ») : pas d'avertissement xorriso.
journal xorriso -report_about SORRY -indev "$NETINST" -outdev "$SORTIE" -volid BARBACANE \
    -map "$B" /barbacane \
    -map "$T/grub.cfg" /boot/grub/grub.cfg -map "$T/isolinux.cfg" /isolinux/isolinux.cfg \
    -boot_image any replay
fin_etape

# ------------------------------------------------------------------ bilan
trap - ERR
TAILLE=$(du -h "$SORTIE" | cut -f1)
EMPREINTE=$(sha256sum "$SORTIE" | cut -d' ' -f1)
echo
printf '%sISO prête%s en %s\n' "$VERT$GRAS" "$FIN" "$(duree $(($(date +%s) - DEBUT)))"
echo "  fichier  : $SORTIE ($TAILLE)"
echo "  sha256   : $EMPREINTE   (à noter avec la date)"
echo "  journal  : $JOURNAL"
echo "Étape suivante : copier l'ISO sur une clé USB (guide, étape 2)."
