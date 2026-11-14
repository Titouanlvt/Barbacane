#!/bin/bash
# Preuve de bout en bout sur un hôte Proxmox VE, avec de VRAIES clés USB :
#   1. installe l'ISO dans une VM borne neuve (UEFI, SANS carte réseau) ;
#   2. choisit le PIN, enrôle la clé de sortie, active le mode « clés enrôlées » ;
#   3. TRANSFERT : clé inconnue (fichiers sains + EICAR) → clé enrôlée ;
#   4. BLANCHIMENT de la clé inconnue (remplie à nouveau) ;
#   5. récupère rapports et journal de la borne (disque de la VM lu hors ligne) ;
# et vérifie tout : fichiers sains intacts (sha256), EICAR détecté et absent en sortie.
# Termine par « OK » ou « ÉCHEC ».
#
# À lancer en root sur l'hôte Proxmox, les deux clés branchées sur l'hôte :
#   ISO=barbacane.iso SERIE_SOURCE=… SERIE_SORTIE=… barbacane/tests/proxmox/preuve.sh [DOSSIER]
# Variables : VMID (900–999, défaut 910), STOCKAGE (local-zfs), PIN (246813).
# Les clés sont désignées par leur numéro de série USB (jamais un disque de l'hôte) :
# elles sont ENTIÈREMENT EFFACÉES. La VM VMID est détruite puis recréée si elle
# s'appelle « barbacane-borne ».
# Prérequis : tesseract-ocr tesseract-ocr-fra dosfstools exfatprogs xxd.
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../../.." && pwd)"
OUT="$(realpath -m "${1:-$REPO/docs/preuves}")"
VMID=${VMID:-910} STOCKAGE=${STOCKAGE:-local-zfs} PIN=${PIN:-246813}
: "${ISO:?ISO=chemin de l ISO}" "${SERIE_SOURCE:?}" "${SERIE_SORTIE:?}"
B=(python3 "$ICI/borne.py" "$VMID")
# shellcheck disable=SC2016 # chaîne EICAR littérale
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
ECHECS=0
ok() { echo "OK : $*"; }
# si CONDITION… -- message OK -- message ÉCHEC
si() {
    local c=() ; while [ "$1" != -- ]; do c+=("$1"); shift; done; shift
    if "${c[@]}"; then ok "$1"; else ko "$2"; fi
}
ko() { echo "ÉCHEC : $*" >&2; ECHECS=$((ECHECS + 1)); }
etape() { echo; echo "== $*"; }

[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
if [ "$VMID" -lt 900 ] || [ "$VMID" -gt 999 ]; then echo "VMID hors de 900–999" >&2; exit 1; fi
for o in qm tesseract mkfs.vfat xxd sfdisk; do command -v $o >/dev/null || { echo "$o absent" >&2; exit 1; }; done
mkdir -p "$OUT/transfert" "$OUT/blanchiment" "$OUT/borne"
T="$(mktemp -d)"
trap 'umount "$T"/m 2>/dev/null || true; rm -rf "$T"' EXIT
mkdir "$T/m"

# --- clés -----------------------------------------------------------------------------
# Disque (côté hôte) d'une clé désignée par son numéro de série ; refuse tout disque non USB.
disque() {
    local d
    for _ in $(seq 60); do
        d=$(lsblk -dnpo NAME,SERIAL,TRAN | awk -v s="$1" '$2 == s && $3 == "usb" { print $1 }')
        [ -n "$d" ] && { echo "$d"; return; }
        sleep 1
    done
    echo "clé $1 introuvable sur l'hôte" >&2; return 1
}
# Port USB de l'hôte (ex. 1-6) d'une clé, pour la passer à la VM.
port() {
    local f
    for f in /sys/bus/usb/devices/*/serial; do
        [ "$(cat "$f")" = "$1" ] && { basename "$(dirname "$f")"; return; }
    done
    echo "port de la clé $1 introuvable" >&2; return 1
}
brancher() { qm set "$VMID" "-$1" "host=$(port "$2"),usb3=1" >/dev/null; }
debrancher() { qm set "$VMID" --delete "$1" >/dev/null 2>&1 || true; sleep 3; }
# Remplit une clé : FAT32, fichiers sains + EICAR. Liste et sha256 dans $2.
remplir() {
    local d; d=$(disque "$1")
    wipefs -qa "$d"; echo ',,c' | sfdisk -q "$d"; sleep 2
    mkfs.vfat -F32 -n SOURCE "${d}1" >/dev/null
    mount "${d}1" "$T/m"
    mkdir -p "$T/m/docs/sous dossier" "$T/m/photos"
    printf 'Rapport trimestriel BARBACANE\nLigne accentuée : éàç\n' > "$T/m/docs/rapport.txt"
    seq 1 20000 > "$T/m/docs/donnees.csv"
    head -c 300000 /dev/urandom > "$T/m/photos/image.bin"
    printf 'fichier imbriqué\n' > "$T/m/docs/sous dossier/note.txt"
    printf '%s' "$EICAR" > "$T/m/docs/eicar.com"
    (cd "$T/m" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done) > "$2"
    umount "$T/m"; sync
}
# Liste et sha256 des fichiers d'une clé (montée en lecture seule).
inventaire() {
    local d p; d=$(disque "$1")
    sleep 2; partprobe "$d" 2>/dev/null || true; sleep 2
    p=$(lsblk -lnpo NAME,FSTYPE "$d" | awk '$2 != "" { print $1; exit }')
    mount -o ro "$p" "$T/m"
    (cd "$T/m" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done) > "$2"
    cp "$T/m"/rapport-barbacane-* "$3/" 2>/dev/null || true
    umount "$T/m"
}
# Vérifie : fichiers sains identiques, EICAR absent, rapport présent.
verifier() { # $1 avant  $2 après  $3 dossier (rapports)
    local f n=0
    while read -r h f; do
        [ "$f" = docs/eicar.com ] && continue
        if grep -qxF "$h  $f" "$2"; then n=$((n + 1)); else ko "$f absent ou modifié en sortie"; fi
    done < "$1"
    ok "$n fichiers sains intacts (sha256 identiques)"
    if grep -q 'eicar' "$2" || grep -q "$(printf '%s' "$EICAR" | sha256sum | cut -c1-64)" "$2"; then
        ko "EICAR présent en sortie"
    else
        ok "EICAR absent de la clé de sortie"
    fi
    if ls "$3"/rapport-barbacane-*.txt >/dev/null 2>&1; then
        if grep -qi 'eicar' "$3"/rapport-barbacane-*.txt; then ok "rapport : EICAR détecté et refusé"; else ko "rapport sans mention d'EICAR"; fi
    else
        ko "rapport absent de la clé"
    fi
}

# --- 1. VM borne ----------------------------------------------------------------------
etape "1. Installation de l'ISO dans la VM $VMID (UEFI, sans réseau)"
if [ "${REPRISE:-0}" = 1 ] && qm listsnapshot "$VMID" 2>/dev/null | grep -q installee; then
    # Mise au point : borne remise dans l'état « juste installée » sans réinstaller.
    qm stop "$VMID" >/dev/null 2>&1 || true
    qm rollback "$VMID" installee
    qm start "$VMID"
    "${B[@]}" attendre "Branchez la clé USB à analyser" 600 "$OUT/01-accueil.png"
    ok "borne remise à l'état « installée » (instantané)"
else
    if qm status "$VMID" >/dev/null 2>&1; then
        [ "$(qm config "$VMID" | awk '/^name:/ { print $2 }')" = barbacane-borne ] \
            || { echo "VM $VMID existante qui n'est pas barbacane-borne : abandon" >&2; exit 1; }
        qm stop "$VMID" >/dev/null 2>&1 || true
        qm destroy "$VMID" --purge >/dev/null
    fi
    mkdir -p /var/lib/vz/template/iso
    cp "$ISO" /var/lib/vz/template/iso/barbacane-preuve.iso
    qm create "$VMID" --name barbacane-borne --bios ovmf --machine q35 \
        --efidisk0 "$STOCKAGE:1,efitype=4m,pre-enrolled-keys=0" --memory 16384 --cores 2 --cpu host \
        --scsihw virtio-scsi-single --scsi0 "$STOCKAGE:16" \
        --ide2 local:iso/barbacane-preuve.iso,media=cdrom --boot 'order=scsi0;ide2' --vga std --ostype l26 >/dev/null
    qm start "$VMID"
    "${B[@]}" attendre "Branchez la clé USB à analyser" 2400 "$OUT/01-accueil.png"
    ok "installation automatique terminée, interface affichée"
    qm snapshot "$VMID" installee >/dev/null
fi
if qm config "$VMID" | grep -q '^net'; then ko "la VM a une carte réseau"; exit 1; fi
ok "VM sans carte réseau"

# --- 2. Administration ----------------------------------------------------------------
etape "2. PIN, enrôlement de la clé de sortie ($SERIE_SORTIE)"
"${B[@]}" cliquer "Administration"
"${B[@]}" attendre "choisissez le PIN" 30 "$OUT/02-premier-pin.png"
"${B[@]}" pin "$PIN"
"${B[@]}" cliquer "Valider"
"${B[@]}" cliquer "Clés de sortie enrôlées"
brancher usb1 "$SERIE_SORTIE"
"${B[@]}" attendre "$SERIE_SORTIE" 60
"${B[@]}" cliquer "Enrôler"
"${B[@]}" cliquer "Activer"
"${B[@]}" attendre "ACTIVÉ" 30 "$OUT/03-cle-enrolee.png"
ok "clé $SERIE_SORTIE enrôlée, mode clés enrôlées activé"
"${B[@]}" cliquer "Retour au menu"
debrancher usb1
"${B[@]}" cliquer "Quitter le mode administrateur"
"${B[@]}" attendre "Branchez la clé USB à analyser" 30

# --- 3. Transfert ---------------------------------------------------------------------
etape "3. Transfert : clé inconnue ($SERIE_SOURCE) → clé enrôlée ($SERIE_SORTIE)"
D="$OUT/transfert"
remplir "$SERIE_SOURCE" "$D/source.sha256"
brancher usb1 "$SERIE_SOURCE"
"${B[@]}" attendre "Clé détectée" 60 "$D/01-cle-detectee.png"
"${B[@]}" cliquer "Copier vers une autre clé"
"${B[@]}" attendre "Résultat de l'analyse" 3600 "$D/02-resultat-analyse.png"
"${B[@]}" lire > "$D/02-resultat-analyse.txt"
si grep -qi eicar "$D/02-resultat-analyse.txt" -- "écran : EICAR détecté" "écran : EICAR non affiché"
"${B[@]}" cliquer "Choisir la clé de sortie"
brancher usb2 "$SERIE_SORTIE"
"${B[@]}" attendre "Clé de sortie" 60 "$D/03-cle-sortie.png"
"${B[@]}" cliquer "Effacer cette clé"
"${B[@]}" attendre "Vous pouvez retirer les clés" 10800 "$D/04-termine.png"
"${B[@]}" lire > "$D/04-termine.txt"
debrancher usb2; debrancher usb1
inventaire "$SERIE_SORTIE" "$D/sortie.sha256" "$D"
verifier "$D/source.sha256" "$D/sortie.sha256" "$D"
# Clés retirées : la borne revient seule à l'accueil.
"${B[@]}" attendre "Branchez la clé USB à analyser" 60

# --- 4. Blanchiment -------------------------------------------------------------------
etape "4. Blanchiment de la clé $SERIE_SOURCE"
D="$OUT/blanchiment"
remplir "$SERIE_SOURCE" "$D/avant.sha256"
d=$(disque "$SERIE_SOURCE")
taille=$(blockdev --getsize64 "$d")
# Empreinte de la clé entière et extraits hexadécimaux (secteur 0, fichier EICAR).
empreinte() { # $1 avant|apres
    sha256sum "$d" | awk -v t="$taille" '{ print $1 "  clé entière (" t " octets)" }' > "$D/cle-$1.sha256"
    xxd -l 512 "$d" > "$D/cle-$1-secteur0.hex"
    : > "$D/cle-$1-eicar.hex"
    local o
    o=$(head -c 64M "$d" | grep -obaF 'EICAR-STANDARD' | head -1 | cut -d: -f1 || true)
    echo "${o:-aucune}" > "$D/cle-$1-eicar-offset.txt"
    [ -n "$o" ] && xxd -s $((o - 32)) -l 128 "$d" > "$D/cle-$1-eicar.hex"
    return 0
}
empreinte avant
off_avant=$(cat "$D/cle-avant-eicar-offset.txt")
si [ "$off_avant" != aucune ] -- "avant : EICAR présent sur la clé (octet $off_avant)" "avant : EICAR introuvable"
brancher usb1 "$SERIE_SOURCE"
"${B[@]}" attendre "Clé détectée" 60 "$D/01-cle-detectee.png"
"${B[@]}" cliquer "Blanchir cette clé"
"${B[@]}" attendre "Résultat de l'analyse" 3600 "$D/02-resultat-analyse.png"
"${B[@]}" lire > "$D/02-resultat-analyse.txt"
"${B[@]}" cliquer "Blanchir la clé"
"${B[@]}" attendre "Effacer et réécrire" 30 "$D/03-confirmation.png"
"${B[@]}" cliquer "Effacer et réécrire"
"${B[@]}" attendre "Vous pouvez retirer les clés" 10800 "$D/04-termine.png"
"${B[@]}" lire > "$D/04-termine.txt"
debrancher usb1
d=$(disque "$SERIE_SOURCE")
empreinte apres
si [ "$(cut -c1-64 "$D/cle-avant.sha256")" != "$(cut -c1-64 "$D/cle-apres.sha256")" ] \
    -- "empreinte de la clé modifiée par le blanchiment" "clé inchangée après blanchiment"
si [ "$(cat "$D/cle-apres-eicar-offset.txt")" = aucune ] \
    -- "après : aucune trace d'EICAR dans les 64 premiers Mo" "après : EICAR encore présent sur la clé"
inventaire "$SERIE_SOURCE" "$D/apres.sha256" "$D"
verifier "$D/avant.sha256" "$D/apres.sha256" "$D"

# --- 5. Journal et rapports de la borne -----------------------------------------------
etape "5. Journal et rapports de la borne (disque de la VM lu hors ligne)"
qm shutdown "$VMID" --timeout 120 >/dev/null 2>&1 || qm stop "$VMID"
vol=$(pvesm path "$(qm config "$VMID" | awk -F'[ ,]' '/^scsi0:/ { print $2 }')")
racine=$(lsblk -lnpo NAME,FSTYPE "$vol" | awk '$2 == "ext4" { print $1; exit }')
mount -o ro,noload "$racine" "$T/m"
J=(journalctl -D "$T/m/var/log/journal" --no-pager -o short-iso)
"${J[@]}" -u usbsas-server -u barbacane-kiosk -u barbacane-analyzer -u barbacane-admind -u clamav-daemon \
    | grep -v '^-- ' > "$OUT/borne/journal.log" || true
cp "$T/m"/var/lib/usbsas/reports/* "$OUT/borne/" 2>/dev/null || true
umount "$T/m"
si grep -qi eicar "$OUT/borne/journal.log" -- "journal de la borne : EICAR consigné" "journal : EICAR absent"

echo
if [ "$ECHECS" -eq 0 ]; then echo "OK"; else echo "ÉCHEC ($ECHECS)"; exit 1; fi
