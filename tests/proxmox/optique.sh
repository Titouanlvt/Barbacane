#!/bin/bash
# Preuves des disques optiques sur la borne (VM Proxmox installée par preuve.sh, TESTS=installation).
#
#   ISO_TEST=barbacane-optique-test.iso SERIE_SOURCE=… SERIE_SORTIE=… SG=/dev/sg1 \
#       tests/proxmox/optique.sh [DOSSIER]
#
# Étapes (TESTS, défaut : toutes) :
#   image        image ISO multisession (EICAR dans la seule 1re session) en lecteur virtuel :
#                disque → clé, EICAR bloqué, fichiers sains identiques (sha256)
#   lecteur      le vrai lecteur passé à la VM au niveau SCSI (scsi-generic sur $SG, jamais de
#                passthrough PCI : le contrôleur SATA porte aussi le disque système de l'hôte)
#   blanchiment  blanchiment du disque réinscriptible inséré (effacement complet, regravure, relecture)
#   gravure      clé inconnue → disque (fichiers sains gravés, relus par l'hôte, sha256)
#   relecture    disque gravé → clé (sha256 identiques)
#   journal      mesures de durée et vérifications consignées par barbacane-optique
# La borne éjecte le disque après chaque gravure ; ce lecteur ne referme pas son tiroir :
# le script attend qu'une personne le referme (message « FERMEZ LE TIROIR »).
# Le disque est ENTIÈREMENT EFFACÉ ; toute gravure est faite par la borne, jamais par l'hôte.
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
OUT="$(realpath -m "${1:-$REPO/docs/preuves/optique}")"
VMID=${VMID:-921} SG=${SG:-/dev/sg1}
TESTS=${TESTS:-"image lecteur blanchiment gravure relecture journal"}
: "${ISO_TEST:?}" "${SERIE_SOURCE:?}" "${SERIE_SORTIE:?}"
B=(python3 "$ICI/borne.py" "$VMID")
# shellcheck disable=SC2016 # chaîne EICAR littérale
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
ECHECS=0 COURANT=""
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
if [ "$VMID" -lt 900 ] || [ "$VMID" -gt 999 ]; then echo "VMID hors de 900–999" >&2; exit 1; fi
# Garde-fou : jamais de passthrough PCI ; $SG doit être le lecteur optique (type SCSI 5)
[ "$(cat "/sys/class/scsi_generic/$(basename "$SG")/device/type" 2>/dev/null)" = 5 ] \
    || { echo "$SG n'est pas un lecteur optique" >&2; exit 1; }
if qm config "$VMID" | grep -q '^hostpci'; then echo "VM avec passthrough PCI : refus" >&2; exit 1; fi
mkdir -p "$OUT"; R="$OUT/resultats.txt"
T="$(mktemp -d)"; trap 'umount "$T"/m 2>/dev/null || true; rm -rf "$T"' EXIT; mkdir "$T/m"

note() { echo "$1 [$COURANT] : $2" | tee -a "$R"; }
ok() { note OK "$*"; }
ko() { note ÉCHEC "$*" >&2; ECHECS=$((ECHECS + 1)); }
si() { local c=() inv=0; [ "$1" = "!" ] && { inv=1; shift; }
    while [ "$1" != -- ]; do c+=("$1"); shift; done; shift
    local r=0; "${c[@]}" || r=1; if [ $((r ^ inv)) -eq 0 ]; then ok "$1"; else ko "$2"; fi; }
test_actif() { [[ " $TESTS " == *" $1 "* ]]; }
debut() { COURANT=$1; D="$OUT/$1"; mkdir -p "$D"; echo; echo "== $1 : $2"; }
capture() { "${B[@]}" capture "$D/$1.png"; }
lire() { "${B[@]}" lire > "$D/$1.txt"; cat "$D/$1.txt"; }
attendre() { "${B[@]}" attendre "$@"; }
cliquer() { "${B[@]}" cliquer "$@"; }
voir() { "${B[@]}" attendre "$@" >/dev/null 2>&1; }
disque() { local d; for _ in $(seq 60); do
        d=$(lsblk -dnpo NAME,SERIAL,TRAN | awk -v s="$1" '$2 == s && $3 == "usb" { print $1 }')
        if [ -n "$d" ]; then [ "$(lsblk -dbno SIZE "$d")" -gt 0 ] || { eject -t "$d" 2>/dev/null || true; sleep 2; }
            [ "$(lsblk -dbno SIZE "$d")" -gt 0 ] && { echo "$d"; return; }; fi; sleep 1; done
    echo "clé $1 introuvable" >&2; return 1; }
port() { local f; for f in /sys/bus/usb/devices/*/serial; do
        [ "$(cat "$f")" = "$1" ] && { basename "$(dirname "$f")"; return; }; done; return 1; }
brancher() { disque "$2" >/dev/null; qm set "$VMID" "-$1" "host=$(port "$2"),usb3=1" >/dev/null; sleep 4; }
debrancher() { qm set "$VMID" --delete "$1" >/dev/null 2>&1 || true; sleep 4; }
formater() { local d; d=$(disque "$1"); wipefs -qa "$d"; echo "type=c" | sfdisk -q "$d"; sleep 2
    partprobe "$d" 2>/dev/null || true; sleep 1; mkfs.vfat -F32 -n "$2" "${d}1" >/dev/null; mount "${d}1" "$T/m"; }
monter_ro() { local d p; d=$(disque "$1"); sleep 2; partprobe "$d" 2>/dev/null || true; sleep 2
    p=$(lsblk -lnpo NAME,FSTYPE "$d" | awk '$2 != "" { print $1; exit }'); mount -o ro "$p" "$T/m"; }
liste_sha() { (cd "$1" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done); }
mot_de_passe_si_demande() { for _ in $(seq 120); do
        if voir "Archive protégée" 3; then capture 02b-mot-de-passe; "${B[@]}" texte "$1"; cliquer "Valider"; return; fi
        if voir "Résultat de l'analyse" 2; then return; fi; done; }
# Le disque inséré, relu par l'hôte (lecture seule, borne inactive) : contenu et sha256
relire_disque() { # dossier
    # La VM tient le lecteur (scsi-generic) : xorriso sur l'hôte le trouve « busy ». Lecture brute
    # de /dev/sr0 (lecture seule) jusqu'à la fin de la zone lisible, puis examen de l'image.
    rm -rf "$1"; mkdir -p "$1"
    timeout 1200 dd if=/dev/sr0 of="$T/disque.img" bs=2048 status=none 2>/dev/null || true
    xorriso -indev "$T/disque.img" -toc > "$1.toc.txt" 2>&1 || true
    xorriso -osirrox on -indev "$T/disque.img" -extract / "$1" >/dev/null 2>&1 || true
    rm -f "$T/disque.img"
    liste_sha "$1" > "$1.sha256"
}
# Attente d'une personne : le tiroir doit être refermé (lecteur mince sans moteur de fermeture)
tiroir() {
    echo ">>> FERMEZ LE TIROIR DU LECTEUR (disque dedans) — $(date +%T)" | tee -a "$OUT/interventions.txt"
    for _ in $(seq 720); do timeout 20 dd if=/dev/sr0 of=/dev/null bs=2048 count=1 status=none 2>/dev/null && { echo "tiroir refermé $(date +%T)" >> "$OUT/interventions.txt"; sleep 5; return 0; }; sleep 5; done
    ko "tiroir non refermé après 1 h"; return 1
}

{ echo "Date : $(date -Is)"; echo "Commit : $(git -C "$REPO" rev-parse HEAD)"; echo "VM : $VMID ; lecteur : $SG ($(cat /sys/class/scsi_generic/"$(basename "$SG")"/device/{vendor,model} | tr -s ' \n' ' '))"
  echo "Image de test : $ISO_TEST ($(sha256sum "$ISO_TEST" | cut -c1-16)…)"; } > "$OUT/contexte.txt"
qm set "$VMID" --delete usb0,usb1,usb2 >/dev/null 2>&1 || true

# === image : disque virtuel multisession, EICAR seulement dans la 1re session ================
if test_actif image; then
    debut image "image ISO multisession en lecteur virtuel : disque → clé"
    # Un lecteur doit exister au démarrage (pas d'ajout de contrôleur à chaud) ; on change ensuite le disque.
    if ! qm config "$VMID" | grep -q '^ide2:'; then
        qm stop "$VMID" >/dev/null 2>&1 || true
        qm set "$VMID" --ide2 none,media=cdrom >/dev/null; qm start "$VMID"
        attendre "à analyser" 600
    fi
    qm set "$VMID" --ide2 "local:iso/$(basename "$ISO_TEST"),media=cdrom" >/dev/null
    attendre "Disque détecté" 120 "$D/01-disque-detecte.png"
    cliquer "Analyser"
    attendre "Résultat de l'analyse" 1800 "$D/02-resultat-analyse.png"; lire 02-resultat-analyse >/dev/null
    si grep -qi 'menace' "$D/02-resultat-analyse.txt" -- "écran : menace détectée sur le disque" "aucune menace affichée"
    cliquer "Copier vers une clé connue"
    formater "$SERIE_SORTIE" DEST; umount "$T/m"
    brancher usb1 "$SERIE_SORTIE"; attendre "Clé de destination" 60 "$D/03-cle-destination.png"
    cliquer "Effacer cette clé"
    attendre "Vous pouvez retirer" 1800 "$D/04-termine.png"; debrancher usb1
    qm set "$VMID" --ide2 none,media=cdrom >/dev/null
    monter_ro "$SERIE_SORTIE"; liste_sha "$T/m" > "$D/sortie.sha256"; cp "$T/m"/rapport-barbacane-* "$D/" 2>/dev/null || true; umount "$T/m"
    cp "$REPO/docs/preuves/optique/image-test-contenu.sha256" "$D/source.sha256" 2>/dev/null || true
    for f in docs/rapport.txt docs/donnees.csv docs/image.bin docs/nouveau.txt; do
        h=$(awk -v f="$f" '$2 == f { print $1 }' "$D/source.sha256")
        si grep -q "^$h .*${f##*/}$" "$D/sortie.sha256" -- "$f : copié, sha256 identique" "$f absent ou modifié"
    done
    si ! grep -q 'eicar' "$D/sortie.sha256" -- "EICAR (1re session seulement) absent de la clé" "EICAR copié"
    si grep -qi 'session-1/cache/eicar.com' "$D"/rapport-barbacane-*.txt -- "rapport : EICAR trouvé dans la session 1 (masquée par la 2e) et refusé" "rapport sans l'EICAR de la session 1"
fi

# === lecteur : vrai lecteur en scsi-generic ================================================
if test_actif lecteur; then
    debut lecteur "lecteur réel passé à la VM en scsi-generic ($SG), sans passthrough PCI"
    qm stop "$VMID" >/dev/null 2>&1 || true
    qm set "$VMID" --delete ide2 >/dev/null 2>&1 || true
    qm set "$VMID" --args "-device virtio-scsi-pci,id=scsioptique -blockdev driver=host_device,filename=$SG,node-name=optique -device scsi-generic,bus=scsioptique.0,drive=optique" >/dev/null
    qm config "$VMID" > "$D/vm.conf"
    si ! grep -q '^hostpci' "$D/vm.conf" -- "aucun passthrough PCI" "passthrough PCI présent"
    qm start "$VMID"
    if voir "Disque détecté" 600 "$D/01-disque-detecte.png"; then lire 01-disque-detecte >/dev/null
        ok "la borne voit le disque du lecteur réel : $(grep -o 'CD-RW[^)]*)' "$D/01-disque-detecte.txt" | head -1)"
    else ko "disque du lecteur réel non détecté"; fi
fi

# === blanchiment : effacement complet + regravure des fichiers sains + relecture =============
if test_actif blanchiment; then
    debut blanchiment "blanchiment du disque réinscriptible"
    xorriso -indev /dev/sr0 -toc > "$D/disque-avant.toc.txt" 2>&1 || true
    voir "Disque détecté" 60 || ko "écran disque détecté absent"
    cliquer "Analyser"
    mot_de_passe_si_demande secret
    attendre "Résultat de l'analyse" 3600 "$D/02-resultat-analyse.png"; lire 02-resultat-analyse >/dev/null
    cliquer "Blanchir le disque"; attendre "Maintenir pour effacer" 60 "$D/03-confirmation.png"
    "${B[@]}" maintenir "Maintenir pour"; date +%s > "$D/debut"
    sleep 60; capture 04-en-cours; lire 04-en-cours >/dev/null
    attendre "Terminé" 14400 "$D/05-termine.png"; date +%s > "$D/fin"
    ok "blanchiment terminé en $(( $(cat "$D/fin") - $(cat "$D/debut") )) s (effacement complet + gravure + relecture)"
    tiroir; sleep 10
    relire_disque "$D/disque-apres"
    si grep -q "BARBACANE" "$D/disque-apres.toc.txt" -- "relu par l'hôte : une seule session « BARBACANE »" "volume inattendu après blanchiment"
    si [ "$(grep -c 'ISO session' "$D/disque-apres.toc.txt")" -eq 1 ] -- "une seule session (anciennes sessions effacées)" "plusieurs sessions après blanchiment"
    si ! grep -q 'HP-ESXI' "$D/disque-apres.toc.txt" -- "ancien volume HP-ESXI introuvable" "ancien volume encore présent"
    cliquer "Ignorer ce disque" || true
fi

# === gravure : clé inconnue → disque ========================================================
if test_actif gravure; then
    debut gravure "clé inconnue → disque réinscriptible"
    formater "$SERIE_SOURCE" SOURCE
    mkdir -p "$T/m/docs/sous dossier"; printf 'Note gravée\néàç\n' > "$T/m/docs/note.txt"; seq 1 30000 > "$T/m/docs/table.csv"
    head -c 2000000 /dev/urandom > "$T/m/docs/sous dossier/binaire.bin"; printf '%s' "$EICAR" > "$T/m/eicar.com"
    liste_sha "$T/m" > "$D/source.sha256"; umount "$T/m"
    voir "Disque détecté" 30 && cliquer "Ignorer ce disque"
    brancher usb1 "$SERIE_SOURCE"; attendre "Clé détectée" 60 "$D/01-cle-detectee.png"
    cliquer "Analyser"
    attendre "Résultat de l'analyse" 1800 "$D/02-resultat-analyse.png"
    cliquer "Graver sur un disque"
    attendre "Effacer ce disque" 120 "$D/03-disque-destination.png"
    cliquer "Effacer ce disque"; date +%s > "$D/debut"
    sleep 60; capture 04-gravure-en-cours; lire 04-gravure-en-cours >/dev/null
    attendre "Terminé" 14400 "$D/05-termine.png"; date +%s > "$D/fin"; debrancher usb1
    ok "gravure terminée en $(( $(cat "$D/fin") - $(cat "$D/debut") )) s (effacement complet + gravure + relecture par la borne)"
    tiroir; sleep 10
    relire_disque "$D/disque"
    for f in docs/note.txt docs/table.csv "docs/sous dossier/binaire.bin"; do
        h=$(grep "  $f\$" "$D/source.sha256" | cut -c1-64)
        si grep -q "^$h  $f\$" "$D/disque.sha256" -- "$f gravé, relu par l'hôte à l'identique" "$f absent ou différent sur le disque"
    done
    si ! grep -q 'eicar' "$D/disque.sha256" -- "EICAR non gravé" "EICAR gravé"
    si grep -q 'rapport-barbacane' "$D/disque.sha256" -- "rapport gravé avec les fichiers" "rapport absent du disque"
fi

# === relecture : disque gravé → clé =========================================================
if test_actif relecture; then
    debut relecture "disque gravé par la borne → clé de destination"
    voir "Disque détecté" 120 "$D/01-disque-detecte.png" || ko "disque gravé non détecté"
    cliquer "Analyser"
    attendre "Résultat de l'analyse" 1800 "$D/02-resultat-analyse.png"
    cliquer "Copier vers une clé connue"
    formater "$SERIE_SORTIE" DEST; umount "$T/m"
    brancher usb1 "$SERIE_SORTIE"; attendre "Clé de destination" 60
    cliquer "Effacer cette clé"; attendre "Vous pouvez retirer" 1800 "$D/03-termine.png"; debrancher usb1
    monter_ro "$SERIE_SORTIE"; liste_sha "$T/m" > "$D/sortie.sha256"; umount "$T/m"
    for f in docs/note.txt docs/table.csv "docs/sous dossier/binaire.bin"; do
        h=$(grep "  $f\$" "$OUT/gravure/source.sha256" | cut -c1-64)
        si grep -q "^$h .*${f##*/}\$" "$D/sortie.sha256" -- "$f : disque → clé, sha256 identique à la clé d'origine" "$f absent ou modifié"
    done
fi

# === journal : mesures et vérifications de barbacane-optique =================================
if test_actif journal; then
    debut journal "journal de barbacane-optique (disque de la VM lu hors ligne)"
    qm shutdown "$VMID" --timeout 120 >/dev/null 2>&1 || qm stop "$VMID"
    vol=$(pvesm path "$(qm config "$VMID" | awk -F'[ ,]' '/^scsi0:/ { print $2 }')")
    racine=$(lsblk -lnpo NAME,FSTYPE "$vol" | awk '$2 == "ext4" { print $1; exit }')
    mount -o ro,noload "$racine" "$T/m"
    journalctl -D "$T/m/var/log/journal" --no-pager -o short-iso -u barbacane-optique > "$D/journal.log" || true
    umount "$T/m"
    grep 'mesure :' "$D/journal.log" > "$D/mesures.txt" || true
    si grep -q 'bac à sable optique : OK' "$D/journal.log" -- "bac à sable optique fonctionnel" "bac à sable optique en échec"
    si grep -q 'effacement complet' "$D/mesures.txt" -- "durée d'effacement complet mesurée" "aucune mesure d'effacement"
    si grep -q 'gravure' "$D/mesures.txt" -- "durée de gravure mesurée" "aucune mesure de gravure"
    si ! grep -q 'échec' "$D/journal.log" -- "aucun échec consigné par barbacane-optique" "échec consigné (voir journal.log)"
fi

echo; grep -c '^OK' "$R" | xargs echo "Vérifications OK :"
if [ "$ECHECS" -eq 0 ]; then echo "OK"; else grep '^ÉCHEC' "$R"; echo "ÉCHEC ($ECHECS)"; exit 1; fi
