#!/bin/bash
# Construit l'ISO d'installation hors ligne du SERVEUR Barbacane (suite, v2) : ISO officielle
# Debian 13 « netinst » + paquets du serveur et leurs dépendances + image de conteneur de la
# passerelle. Distinct de systeme/iso/build-iso.sh (borne v1), qui n'est NI appelé NI modifié.
# Conception : docs/suite/serveur-iso.md. À lancer en root sur Debian 13, réseau requis pendant la
# construction seulement ; l'ISO installe sans question ni réseau (TPM 2.0 exigé, D9).
#
#   serveur/iso/build-iso-serveur.sh [options]
#     --if-bornes NOM      interface du réseau des bornes      (défaut : enp0s8)
#     --ip-bornes CIDR     son adresse                          (défaut : 10.20.0.1/24)
#     --if-admin NOM       interface d'administration          (défaut : enp0s9)
#     --ip-admin CIDR      son adresse                          (défaut : 10.99.0.1/24)
#     --port-admin N       port de l'interface web (administration seulement, défaut : 443)
#     --port N             port FIXE de la passerelle (défaut : tiré au hasard à l'installation, D4)
#     --source-heure IP    serveur NTP INTERNE (réseau d'administration) ; défaut : aucun
#     --compte-admin NOM   compte d'administration système (défaut : barbadmin)
#     --hache-admin FICH   empreinte crypt(3) du mot de passe initial de ce compte (à changer à la
#                          1re connexion) ; défaut : mot de passe aléatoire affiché UNE fois ici
#     --pki-test DOSSIER   ISO de TEST : embarque la PKI de test (serveur/pki/racine-test.sh) ;
#                          seuls le certificat serveur, sa clé, la CA bornes et sa CRL sont copiés
#     --passerelle BIN     binaire barbacane-passerelle (défaut : cargo build --release)
#     --paquets DOSSIER    paquets .deb déjà résolus (défaut : résolus dans un Debian 13 minimal)
#     --netinst ISO        ISO netinst Debian 13 amd64 (défaut : téléchargée, empreinte vérifiée)
#     --sortie FICHIER     ISO produite (défaut : ./barbacane-serveur.iso)
#     --console-serie      BANC DE TEST : installateur et système installé aussi sur la console série
#                          (ttyS0, installateur en anglais : seules les langues ASCII y sont proposées)
#     --verbeux            détail à l'écran (sinon dans le journal, à côté de l'ISO)
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
IF_BORNES=enp0s8 IP_BORNES=10.20.0.1/24 IF_ADMIN=enp0s9 IP_ADMIN=10.99.0.1/24 PORT_ADMIN=443 PORT=''
SOURCE_HEURE='' COMPTE_ADMIN=barbadmin HACHE_ADMIN_F='' PKI_TEST='' PASSERELLE='' PAQUETS='' NETINST=''
SORTIE="$PWD/barbacane-serveur.iso" VERBEUX=0 CONSOLE_SERIE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --if-bornes) IF_BORNES="$2"; shift 2 ;;
        --ip-bornes) IP_BORNES="$2"; shift 2 ;;
        --if-admin) IF_ADMIN="$2"; shift 2 ;;
        --ip-admin) IP_ADMIN="$2"; shift 2 ;;
        --port-admin) PORT_ADMIN="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --source-heure) SOURCE_HEURE="$2"; shift 2 ;;
        --compte-admin) COMPTE_ADMIN="$2"; shift 2 ;;
        --hache-admin) HACHE_ADMIN_F="$(realpath "$2")"; shift 2 ;;
        --pki-test) PKI_TEST="$(realpath "$2")"; shift 2 ;;
        --passerelle) PASSERELLE="$(realpath "$2")"; shift 2 ;;
        --paquets) PAQUETS="$(realpath "$2")"; shift 2 ;;
        --netinst) NETINST="$(realpath "$2")"; shift 2 ;;
        --sortie) SORTIE="$(realpath -m "$2")"; shift 2 ;;
        --verbeux) VERBEUX=1; shift ;;
        --console-serie) CONSOLE_SERIE=1; shift ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1 (voir --help)" >&2; exit 1 ;;
    esac
done

# ------------------------------------------------------------------ contrôle des paramètres
# Ils entrent dans des fichiers de configuration (shell, nftables, systemd) : formats stricts.
refus() { echo "paramètre refusé : $*" >&2; exit 1; }
ip_ok() { [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
          local o; for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done; }
cidr_ok() { [[ "$1" =~ ^(.+)/([0-9]{1,2})$ ]] || return 1
            local ip=${BASH_REMATCH[1]} n=${BASH_REMATCH[2]}
            ip_ok "$ip" && [ "$n" -ge 8 ] && [ "$n" -le 30 ]; }
nom_ok() { [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }
port_ok() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
nom_ok "$IF_BORNES" || refus "--if-bornes $IF_BORNES"
nom_ok "$IF_ADMIN" || refus "--if-admin $IF_ADMIN"
[ "$IF_BORNES" != "$IF_ADMIN" ] || refus "bornes et administration doivent être deux interfaces distinctes"
cidr_ok "$IP_BORNES" || refus "--ip-bornes $IP_BORNES (a.b.c.d/n attendu)"
cidr_ok "$IP_ADMIN" || refus "--ip-admin $IP_ADMIN (a.b.c.d/n attendu)"
port_ok "$PORT_ADMIN" || refus "--port-admin $PORT_ADMIN"
[ -z "$PORT" ] || { port_ok "$PORT" && [ "$PORT" -ge 1024 ]; } || refus "--port $PORT (1024–65535)"
[ -z "$SOURCE_HEURE" ] || ip_ok "$SOURCE_HEURE" || refus "--source-heure $SOURCE_HEURE (adresse IPv4 attendue)"
[[ "$COMPTE_ADMIN" =~ ^[a-z][a-z0-9-]{1,30}$ ]] || refus "--compte-admin $COMPTE_ADMIN"

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
printf '%s%s%s (journal : %s)\n' "$GRAS" "Construction de l'ISO du SERVEUR Barbacane" "$FIN" "$JOURNAL"
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root : « su - » (avec le tiret) ou « sudo -i »." >&2; exit 1; }
if [ -e /etc/pve ]; then
    echo "REFUS : hôte Proxmox VE détecté (/etc/pve). Construisez l'ISO sur un poste ou dans une VM." >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
[ "${VERSION_CODENAME:-}" = trixie ] || attention "système ${PRETTY_NAME:-inconnu} : seul Debian 13 (trixie) est testé"
LIBRE_GO=$(( $(df -Pk "$(dirname "$SORTIE")" | awk 'NR==2 {print $4}') / 1024 / 1024 ))
[ "$LIBRE_GO" -ge 10 ] || { echo "Espace disque insuffisant : $LIBRE_GO Go libres, 10 Go nécessaires." >&2; exit 1; }
if [ -z "$PAQUETS" ] || [ -z "$NETINST" ]; then
    getent hosts deb.debian.org >/dev/null || { echo "Réseau indisponible (deb.debian.org) : nécessaire pendant la construction." >&2; exit 1; }
fi
T="$(mktemp -d -p "${TMPDIR:-/var/tmp}" barbacane-serveur-iso.XXXXXX)"
trap 'rm -rf "$T"' EXIT
B="$T/iso/barbacane"
mkdir -p "$B/debs"
export DEBIAN_FRONTEND=noninteractive
MIROIR=http://deb.debian.org/debian
VERSION="suite-$(git -C "$REPO" rev-parse --short=12 HEAD 2>/dev/null || date +%Y%m%d)"

# ------------------------------------------------------------------ 1. outils
etape "Outils de construction"
journal apt-get update -qq
journal apt-get install -y -qq --no-install-recommends xorriso debootstrap wget ca-certificates openssl

# ------------------------------------------------------------------ 2. image de la passerelle
etape "Image de conteneur de la passerelle (compilation si nécessaire)"
if [ -z "$PASSERELLE" ]; then
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    command -v cargo >/dev/null || { echo "cargo absent : fournir --passerelle BINAIRE" >> "$JOURNAL"; false; }
    (cd "$REPO" && journal cargo build --release --locked -p barbacane-passerelle)
    PASSERELLE="${CARGO_TARGET_DIR:-$REPO/target}/release/barbacane-passerelle"
fi
[ -x "$PASSERELLE" ] || { echo "binaire introuvable : $PASSERELLE" >> "$JOURNAL"; false; }
# Racine minimale : le binaire et ses seules bibliothèques (ni shell ni gestionnaire de paquets).
R="$T/rootfs"
mkdir -p "$R"
install -m 755 "$PASSERELLE" "$R/barbacane-passerelle"
ldd "$PASSERELLE" | awk '/=> \// { print $3 } /^\t\/.*ld-linux/ { print $1 }' | while read -r lib; do
    mkdir -p "$R$(dirname "$lib")"
    cp -L "$lib" "$R$lib"
done
mkdir -p "$R/pki" "$R/tmp"
tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$T/passerelle.tar" -C "$R" .
note "passerelle : $(sha256sum "$PASSERELLE" | cut -c1-16)…, image $(du -h "$T/passerelle.tar" | cut -f1)"

# ------------------------------------------------------------------ 3. ISO Debian
etape "ISO netinst Debian 13 (téléchargement et empreinte)"
if [ -z "$NETINST" ]; then
    URL=https://cdimage.debian.org/debian-cd/current/amd64/iso-cd
    journal wget -q -O "$T/SHA256SUMS" "$URL/SHA256SUMS"
    NOM=$(awk '/ debian-[0-9.]+-amd64-netinst\.iso$/ { print $2; exit }' "$T/SHA256SUMS")
    journal wget -q -O "$T/$NOM" "$URL/$NOM"
    (cd "$T" && grep " $NOM\$" SHA256SUMS | journal sha256sum -c -)
    NETINST="$T/$NOM"
    note "$NOM (empreinte vérifiée)"
fi

# ------------------------------------------------------------------ 4. dépendances
etape "Paquets du serveur et dépendances (résolus dans un Debian 13 minimal)"
if [ -z "$PAQUETS" ]; then
    journal debootstrap --variant=minbase trixie "$T/chroot" "$MIROIR"
    echo "deb $MIROIR trixie main contrib non-free non-free-firmware" > "$T/chroot/etc/apt/sources.list"
    journal chroot "$T/chroot" apt-get update -qq
    mapfile -t LISTE < <(grep -vE '^\s*(#|$)' "$ICI/paquets-serveur.txt")
    journal chroot "$T/chroot" apt-get install -y -qq --download-only --no-install-recommends "${LISTE[@]}"
    cp "$T"/chroot/var/cache/apt/archives/*.deb "$B/debs/"
else
    cp "$PAQUETS"/*.deb "$B/debs/"
    note "paquets fournis : $PAQUETS"
fi
# Garde-fou : aucun paquet interdit (réseau, accès distant) ne doit être embarqué.
while read -r p; do
    if ls "$B/debs/${p}_"*.deb >/dev/null 2>&1; then echo "paquet interdit embarqué : $p" >> "$JOURNAL"; false; fi
done < "$ICI/fichiers/usr/share/barbacane-serveur/paquets-interdits"
note "$(find "$B/debs" -name '*.deb' | wc -l) paquets embarqués"

# ------------------------------------------------------------------ 5. fichiers du serveur
etape "Fichiers et configuration du serveur"
F="$T/fichiers"
cp -a "$ICI/fichiers" "$F"
install -D -m 755 "$REPO/serveur/sauvegarde/barbacane-sauvegarde" "$F/usr/local/sbin/barbacane-sauvegarde"
install -D -m 644 "$T/passerelle.tar" "$F/usr/share/barbacane-serveur/images/passerelle.tar"
tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$B/fichiers.tar" -C "$F" .
if [ -n "$HACHE_ADMIN_F" ]; then
    HACHE_ADMIN=$(head -n1 "$HACHE_ADMIN_F")
    MDP_AFFICHE=''
else
    MDP_AFFICHE=$(head -c 15 /dev/urandom | base64 | tr '+/' '-_')
    HACHE_ADMIN=$(printf '%s' "$MDP_AFFICHE" | openssl passwd -6 -stdin)
fi
[[ "$HACHE_ADMIN" =~ ^\$(6|y|5|2b)\$[A-Za-z0-9./$]+$ ]] || refus "--hache-admin : empreinte crypt(3) attendue (\$6\$…, \$y\$…)"
cat > "$B/serveur.conf" <<CONF
# Serveur Barbacane : paramètres fixés à la construction de l'ISO ($(date -Is)).
VERSION='$VERSION'
IF_BORNES='$IF_BORNES'
IP_BORNES='$IP_BORNES'
IF_ADMIN='$IF_ADMIN'
IP_ADMIN='$IP_ADMIN'
PORT_ADMIN='$PORT_ADMIN'
PORT='$PORT'
SOURCE_HEURE='$SOURCE_HEURE'
COMPTE_ADMIN='$COMPTE_ADMIN'
HACHE_ADMIN='$HACHE_ADMIN'
CONF
if [ -n "$PKI_TEST" ]; then
    mkdir -p "$B/pki-test"
    cp "$PKI_TEST/serveur/chaine.pem" "$B/pki-test/chaine.pem"
    cp "$PKI_TEST/serveur/cle.pem" "$B/pki-test/cle.pem"
    cp "$PKI_TEST/ca-bornes/cert.pem" "$B/pki-test/ca-bornes.pem"
    cp "$PKI_TEST/ca-bornes/crl.pem" "$B/pki-test/crl-bornes.pem"
    attention "ISO de TEST : PKI de test embarquée (jamais en production)"
fi
# Mot de passe root de l'installateur et phrase de passe TEMPORAIRE du disque : aléatoires,
# jamais conservés ; la phrase est effacée du disque en fin d'installation (TPM + clé de secours).
PHRASE=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
sed -e "s|@HACHE_ROOT@|$(head -c 32 /dev/urandom | base64 | openssl passwd -6 -stdin)|" \
    -e "s|@PHRASE_TEMPORAIRE@|$PHRASE|g" "$ICI/preseed-serveur.cfg" > "$B/preseed.cfg"
unset PHRASE
cp "$REPO/systeme/iso/choisir-disque.sh" "$ICI/fin-installation-serveur.sh" "$ICI/configurer-serveur.sh" "$B/"

# ------------------------------------------------------------------ 6. assemblage
etape "Assemblage de l'ISO"
PARAMS="auto=true priority=critical preseed/file=/cdrom/barbacane/preseed.cfg locale=fr_FR.UTF-8 keymap=fr --- quiet"
# Les paramètres après « --- » sont recopiés dans le GRUB du système installé.
[ "$CONSOLE_SERIE" = 0 ] || PARAMS="auto=true priority=critical preseed/file=/cdrom/barbacane/preseed.cfg locale=en_US.UTF-8 keymap=fr console=ttyS0,115200 --- console=tty0 console=ttyS0,115200 quiet"
cat > "$T/grub.cfg" <<CFG
set timeout=10
set default=0
menuentry "Installer le SERVEUR BARBACANE (EFFACE le disque interne)" {
    linux /install.amd/vmlinuz $PARAMS
    initrd /install.amd/initrd.gz
}
CFG
cat > "$T/isolinux.cfg" <<CFG
default serveur
prompt 0
timeout 100
say Installation du SERVEUR BARBACANE dans 10 s : le disque interne sera EFFACE.
label serveur
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz $PARAMS
CFG
rm -f "$SORTIE"
VOLID=BARBACANE_SERVEUR
[ -z "$PKI_TEST" ] || VOLID=BARBACANE_SERVEUR_TEST
journal xorriso -report_about SORRY -indev "$NETINST" -outdev "$SORTIE" -volid "$VOLID" \
    -map "$B" /barbacane \
    -map "$T/grub.cfg" /boot/grub/grub.cfg -map "$T/isolinux.cfg" /isolinux/isolinux.cfg \
    -boot_image any replay
fin_etape

# ------------------------------------------------------------------ bilan
trap - ERR
echo
printf '%sISO du serveur prête%s en %s\n' "$VERT$GRAS" "$FIN" "$(duree $(($(date +%s) - DEBUT)))"
echo "  fichier  : $SORTIE ($(du -h "$SORTIE" | cut -f1))"
echo "  sha256   : $(sha256sum "$SORTIE" | cut -d' ' -f1)   (à noter avec la date)"
echo "  version  : $VERSION"
echo "  journal  : $JOURNAL"
if [ -n "$MDP_AFFICHE" ]; then
    # Affiché une seule fois, jamais écrit dans le journal ; à changer à la première connexion.
    echo "  compte   : $COMPTE_ADMIN, mot de passe initial : $MDP_AFFICHE   (à noter maintenant)"
fi
