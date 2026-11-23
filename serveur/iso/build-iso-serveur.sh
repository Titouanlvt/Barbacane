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
#     --port N             port FIXE du service mTLS de la passerelle (défaut : tiré à l'installation, D4)
#     --port-enrolement N  port FIXE de l'enrôlement (sans certificat client ; défaut : tiré, distinct)
#     --source-heure IP    serveur NTP INTERNE (réseau d'administration) ; défaut : aucun
#     --compte-admin NOM   compte d'administration système (défaut : barbadmin)
#     --hache-admin FICH   empreinte crypt(3) du mot de passe initial de ce compte (à changer à la
#                          1re connexion) ; défaut : mot de passe aléatoire affiché UNE fois ici
#     --pki-test DOSSIER   ISO de TEST : embarque la PKI de test (serveur/pki/racine-test.sh) ;
#                          copiés : certificat serveur, sa clé, la CA bornes, SA CLÉ (TEST seulement : la
#                          passerelle signe à l'enrôlement) et sa CRL ; CA des administrateurs de TEST,
#                          sa CRL et le compte web initial « admin-01 » lié à administrateurs/admin-01.cert.pem
#     --mdp-web FICHIER    ISO de TEST : mot de passe (1re ligne, 12 caractères au moins) du compte web
#                          admin-01 ; défaut : aléatoire, affiché UNE fois ici
#     --cle-maj-bornes PUB clé PUBLIQUE minisign des mises à jour des bornes (dépôt des .bcu, facultatif)
#     --passerelle BIN     binaire barbacane-passerelle (défaut : cargo build --release) ; barbacane-registre,
#                          barbacane-syslog, barbacane-web et barbacane-audit sont pris dans le même dossier
#     --paquets DOSSIER    paquets .deb déjà résolus (défaut : résolus dans un Debian 13 minimal)
#     --netinst ISO        ISO netinst Debian 13 amd64 (défaut : téléchargée, empreinte vérifiée)
#     --sortie FICHIER     ISO produite (défaut : ./barbacane-serveur.iso)
#     --console-serie      BANC DE TEST : installateur et système installé aussi sur la console série
#                          (ttyS0, installateur en anglais : seules les langues ASCII y sont proposées)
#     --verbeux            détail à l'écran (sinon dans le journal, à côté de l'ISO)
#     --iso-borne-en-ligne ISO  --iso-borne-hors-ligne ISO   ISO des bornes de la MÊME version
#                          (docs/suite/serveur-iso-bornes.md) : embarquées avec leur SHA-256 et l'outil
#                          de remaster ; les deux ensemble ; --sha256-bornes FICHIER (sha256sum) exigé :
#                          empreintes notées hors bande à la construction des ISO des bornes
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
IF_BORNES=enp0s8 IP_BORNES=10.20.0.1/24 IF_ADMIN=enp0s9 IP_ADMIN=10.99.0.1/24 PORT_ADMIN=443 PORT='' PORT_ENROLEMENT=''
SOURCE_HEURE='' COMPTE_ADMIN=barbadmin HACHE_ADMIN_F='' PKI_TEST='' PASSERELLE='' PAQUETS='' NETINST=''
SORTIE="$PWD/barbacane-serveur.iso" VERBEUX=0 CONSOLE_SERIE=0
ISO_EL='' ISO_HL='' SHA_BORNES='' MDP_WEB_F='' CLE_MAJ=''
while [ $# -gt 0 ]; do
    case "$1" in
        --if-bornes) IF_BORNES="$2"; shift 2 ;;
        --ip-bornes) IP_BORNES="$2"; shift 2 ;;
        --if-admin) IF_ADMIN="$2"; shift 2 ;;
        --ip-admin) IP_ADMIN="$2"; shift 2 ;;
        --port-admin) PORT_ADMIN="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --port-enrolement) PORT_ENROLEMENT="$2"; shift 2 ;;
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
        --iso-borne-en-ligne) ISO_EL="$(realpath "$2")"; shift 2 ;;
        --iso-borne-hors-ligne) ISO_HL="$(realpath "$2")"; shift 2 ;;
        --sha256-bornes) SHA_BORNES="$(realpath "$2")"; shift 2 ;;
        --mdp-web) MDP_WEB_F="$(realpath "$2")"; shift 2 ;;
        --cle-maj-bornes) CLE_MAJ="$(realpath "$2")"; shift 2 ;;
        -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
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
[ -z "$PORT_ENROLEMENT" ] || { port_ok "$PORT_ENROLEMENT" && [ "$PORT_ENROLEMENT" -ge 1024 ]; } || refus "--port-enrolement $PORT_ENROLEMENT (1024–65535)"
[ -z "$PORT" ] || [ "$PORT" != "$PORT_ENROLEMENT" ] || refus "--port et --port-enrolement doivent être distincts"
# Port interne de l'interface web (configurer-serveur.sh) : distinct de ceux de la passerelle.
if [ "$PORT_ADMIN" -ge 1024 ]; then PORT_WEB=$PORT_ADMIN; else PORT_WEB=8443; fi
for p in "$PORT" "$PORT_ENROLEMENT"; do [ "$p" != "$PORT_WEB" ] || refus "port $p : réservé à l'interface web ($PORT_WEB)"; done
[ -z "$MDP_WEB_F" ] || [ -n "$PKI_TEST" ] || refus "--mdp-web : ISO de TEST seulement (avec --pki-test)"
[ -z "$CLE_MAJ" ] || grep -q '^untrusted comment: minisign public key' "$CLE_MAJ" || refus "--cle-maj-bornes : clé publique minisign attendue"
[ -z "$SOURCE_HEURE" ] || ip_ok "$SOURCE_HEURE" || refus "--source-heure $SOURCE_HEURE (adresse IPv4 attendue)"
if [ -n "$ISO_EL$ISO_HL" ]; then
    command -v xorriso >/dev/null || refus "xorriso requis pour contrôler les ISO des bornes (apt install xorriso)"
    [ -f "$ISO_EL" ] && [ -f "$ISO_HL" ] || refus "--iso-borne-en-ligne et --iso-borne-hors-ligne : les deux ISO"
    [ -f "$SHA_BORNES" ] || refus "--sha256-bornes FICHIER exigé avec les ISO des bornes"
    [ -n "$PORT" ] && [ -n "$PORT_ENROLEMENT" ] \
        || refus "--port N et --port-enrolement N exigés avec les ISO des bornes (ports figés dans l'ISO générique ; écart à D4, decisions.md)"
    for i in "$ISO_EL" "$ISO_HL"; do
        e=$(sha256sum "$i" | cut -d' ' -f1)
        grep -Eq "^${e}[[:space:]]+\\*?(.*/)?$(basename "$i")\$" "$SHA_BORNES" || refus "$i : empreinte $e absente de $SHA_BORNES"
    done
    "$ICI/../iso-bornes/barbacane-iso-borne" parametres "$ISO_EL" >/dev/null || refus "$ISO_EL : pas une ISO de borne en ligne"
    if xorriso -indev "$ISO_HL" -find /barbacane/en-ligne 2>/dev/null | grep -q en-ligne; then refus "$ISO_HL : profil en ligne, pas l'ISO hors ligne"; fi
    # Les ports figés dans l'ISO générique doivent être ceux de la passerelle de ce serveur.
    W_EL=$(mktemp -d)
    xorriso -osirrox on -indev "$ISO_EL" -extract /barbacane/en-ligne/agent.toml "$W_EL/agent.toml" >/dev/null 2>&1 \
        || { rm -rf "$W_EL"; refus "$ISO_EL : agent.toml illisible"; }
    pe_iso=$(sed -n 's/^port_enrolement = \([0-9]*\)$/\1/p' "$W_EL/agent.toml")
    ps_iso=$(sed -n 's/^port_service = \([0-9]*\)$/\1/p' "$W_EL/agent.toml")
    rm -rf "$W_EL"
    [ "$pe_iso" = "$PORT_ENROLEMENT" ] || refus "ISO en ligne : port_enrolement=${pe_iso:-?}, --port-enrolement $PORT_ENROLEMENT"
    [ "$ps_iso" = "$PORT" ] || refus "ISO en ligne : port_service=${ps_iso:-?}, --port $PORT"
    if xorriso -indev "$ISO_EL" -find /barbacane/en-ligne -name parametres.conf 2>/dev/null | grep -q parametres; then refus "$ISO_EL : ISO personnalisée (jeton) refusée"; fi
fi
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

# ------------------------------------------------------------------ 2. images des services
etape "Binaires du serveur et images de conteneurs (compilation si nécessaire)"
if [ -z "$PASSERELLE" ]; then
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    command -v cargo >/dev/null || { echo "cargo absent : fournir --passerelle BINAIRE" >> "$JOURNAL"; false; }
    (cd "$REPO" && journal cargo build --release --locked -p barbacane-passerelle -p barbacane-web -p barbacane-audit)
    PASSERELLE="${CARGO_TARGET_DIR:-$REPO/target}/release/barbacane-passerelle"
fi
BINS="$(dirname "$PASSERELLE")"
for b in barbacane-passerelle barbacane-registre barbacane-syslog barbacane-web barbacane-audit; do
    [ -x "$BINS/$b" ] || { echo "binaire introuvable : $BINS/$b" >> "$JOURNAL"; false; }
done
# Racine minimale : les binaires et leurs seules bibliothèques (ni gestionnaire de paquets ni
# compilateur). Celle de la passerelle n'a pas de shell ; celle de l'interface web a, en plus, ce
# qu'exige l'outil de remaster des ISO des bornes (bash, xorriso, coreutils, sed, grep).
image() { # NOM FICHIER… (fichiers copiés à leur chemin ; le premier = /barbacane-NOM)
    local nom=$1 r="$T/rootfs-$1" f lib
    shift
    mkdir -p "$r/pki" "$r/tmp"
    install -m 755 "$1" "$r/barbacane-$nom"
    for f in "${@:2}"; do install -D -m 755 "$f" "$r$f"; done
    for f in "$@"; do
        ldd "$f" 2>/dev/null | awk '/=> \// { print $3 } /^\t\/.*ld-linux/ { print $1 }'
    done | sort -u | while read -r lib; do
        mkdir -p "$r$(dirname "$lib")"
        cp -L "$lib" "$r$lib"
    done
    tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$T/$nom.tar" -C "$r" .
    note "$nom : $(sha256sum "$1" | cut -c1-16)…, image $(du -h "$T/$nom.tar" | cut -f1)"
}
image passerelle "$BINS/barbacane-passerelle"
OUTILS_WEB=()
for o in bash xorriso sed grep head tr mktemp rm mv shred sha256sum cut; do
    c=$(command -v "$o") || { echo "outil absent (image web) : $o" >> "$JOURNAL"; false; }
    OUTILS_WEB+=("$(realpath "$c")")
done
install -D -m 755 "$REPO/serveur/iso-bornes/barbacane-iso-borne" "$T/rootfs-web/usr/local/sbin/barbacane-iso-borne"
# Chemins de Debian à /usr fusionné (#!/bin/bash, PATH=/usr/sbin:/usr/bin:/sbin:/bin de l'outil).
ln -s usr/bin "$T/rootfs-web/bin"
image web "$BINS/barbacane-web" "${OUTILS_WEB[@]}"

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
install -D -m 644 "$T/web.tar" "$F/usr/share/barbacane-serveur/images/web.tar"
# Outils en ligne de commande (hors conteneur) : barbacane-registre sous barbacane-svc (enveloppe
# /usr/local/sbin/barbacane-registre), barbacane-audit (root : clé d'audit), barbacane-web pour
# « barbacane-web compte » (ligne du fichier des comptes).
install -D -m 755 "$BINS/barbacane-registre" "$F/usr/local/lib/barbacane-serveur/barbacane-registre"
# Exportateur Syslog (v2.3.0), service système sous barbacane-svc.
install -D -m 755 "$BINS/barbacane-syslog" "$F/usr/local/lib/barbacane-serveur/barbacane-syslog"
install -D -m 755 "$BINS/barbacane-web" "$F/usr/local/lib/barbacane-serveur/barbacane-web"
install -D -m 755 "$BINS/barbacane-audit" "$F/usr/local/sbin/barbacane-audit"
install -D -m 755 "$REPO/serveur/iso-bornes/barbacane-iso-borne" "$F/usr/local/sbin/barbacane-iso-borne"
tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$B/fichiers.tar" -C "$F" .
if [ -n "$ISO_EL" ]; then
    # Hors de fichiers.tar (1 Go chacune) : copiées par fin-installation-serveur.sh.
    mkdir -p "$B/iso-bornes"
    cp "$ISO_EL" "$B/iso-bornes/barbacane-borne-en-ligne.iso"
    cp "$ISO_HL" "$B/iso-bornes/barbacane-borne-hors-ligne.iso"
    (cd "$B/iso-bornes" && sha256sum ./*.iso > SHA256SUMS)
    note "ISO des bornes embarquées : $(tr '\n' ' ' < "$B/iso-bornes/SHA256SUMS")"
fi
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
PORT_ENROLEMENT='$PORT_ENROLEMENT'
SOURCE_HEURE='$SOURCE_HEURE'
COMPTE_ADMIN='$COMPTE_ADMIN'
HACHE_ADMIN='$HACHE_ADMIN'
CONF
if [ -n "$PKI_TEST" ]; then
    mkdir -p "$B/pki-test"
    # La Console est ouverte par l'adresse d'administration : sans elle dans le SAN du certificat
    # serveur, un navigateur ou « curl --cacert racine » refuse la connexion (v2.0.1).
    openssl x509 -in "$PKI_TEST/serveur/cert.pem" -noout -checkip "${IP_ADMIN%/*}" | grep -q 'does match' \
        || refus "--pki-test : certificat serveur sans l'adresse d'administration ${IP_ADMIN%/*} dans son SAN (racine-test.sh --ip-serveur ${IP_ADMIN%/*})"
    cp "$PKI_TEST/serveur/chaine.pem" "$B/pki-test/chaine.pem"
    cp "$PKI_TEST/serveur/cle.pem" "$B/pki-test/cle.pem"
    cp "$PKI_TEST/ca-bornes/cert.pem" "$B/pki-test/ca-bornes.pem"
    # Clé de la CA bornes de TEST : la passerelle signe les certificats des bornes à l'enrôlement.
    # En production, déposée par la cérémonie, jamais dans une ISO (politique-certification.md).
    grep -q "TEST" <(openssl x509 -in "$PKI_TEST/ca-bornes/cert.pem" -noout -subject) \
        || refus "--pki-test : la CA bornes n'est pas une CA de TEST (racine-test.sh) ; clé de production refusée"
    cp "$PKI_TEST/ca-bornes/cle.pem" "$B/pki-test/cle-ca-bornes.pem"
    cp "$PKI_TEST/ca-bornes/crl.pem" "$B/pki-test/crl-bornes.pem"
    # Interface web : CA des administrateurs de TEST (refus sinon) et compte initial admin-01 lié à
    # SON certificat (barbacane-web compte : Argon2id, serveur-web.md §3).
    grep -q "TEST" <(openssl x509 -in "$PKI_TEST/ca-administrateurs/cert.pem" -noout -subject) \
        || refus "--pki-test : la CA administrateurs n'est pas une CA de TEST (racine-test.sh)"
    mkdir -p "$B/web-test"
    cp "$PKI_TEST/ca-administrateurs/cert.pem" "$B/web-test/ca-administrateurs.pem"
    cp "$PKI_TEST/ca-administrateurs/crl.pem" "$B/web-test/crl-administrateurs.pem"
    # Clé de la CA des administrateurs de TEST : la Console émet les certificats (.p12) et publie
    # la CRL des administrateurs (v2.2.0, docs/suite/comptes-administrateurs.md §4).
    cp "$PKI_TEST/ca-administrateurs/cle.pem" "$B/web-test/cle-ca-administrateurs.pem"
    if [ -n "$MDP_WEB_F" ]; then MDP_WEB=$(head -n1 "$MDP_WEB_F"); MDP_WEB_AFFICHE=''
    else MDP_WEB=$(head -c 15 /dev/urandom | base64 | tr '+/' '-_'); MDP_WEB_AFFICHE=$MDP_WEB; fi
    [ "${#MDP_WEB}" -ge 12 ] || refus "--mdp-web : 12 caractères au moins"
    printf '%s\n' "$MDP_WEB" | "$BINS/barbacane-web" compte admin-01 administrateur \
        "$PKI_TEST/administrateurs/admin-01.cert.pem" > "$B/web-test/comptes"
    unset MDP_WEB
    attention "ISO de TEST : PKI de test embarquée (jamais en production)"
fi
[ -z "$CLE_MAJ" ] || cp "$CLE_MAJ" "$B/cle-maj-bornes.pub"
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
if [ -n "${MDP_WEB_AFFICHE:-}" ]; then
    echo "  web TEST : admin-01 (certificat administrateurs/admin-01), mot de passe : $MDP_WEB_AFFICHE   (à noter maintenant)"
fi
