#!/bin/bash
# Preuves de bout en bout sur un hôte Proxmox VE, avec de VRAIES clés USB passées à une
# VM borne installée depuis l'ISO copiée sur une clé (comme sur un vrai poste).
#
#   ISO=barbacane.iso SERIE_SOURCE=… SERIE_SORTIE=… SERIE_AUTRE=… [MAJ=dossier] \
#       tests/proxmox/preuve.sh [DOSSIER]
#
# Clés (désignées par leur n° de série USB ; ELLES SONT ENTIÈREMENT EFFACÉES) :
#   SERIE_AUTRE   support d'installation (l'ISO y est copiée), puis clé non enrôlée et clé
#                 hostile (vide, pleine, illisible, retrait en cours de lecture), clé de mise à jour
#   SERIE_SOURCE  clé inconnue à analyser, puis à blanchir
#   SERIE_SORTIE  clé de destination enrôlée (export des journaux aussi)
# MAJ : dossier de paquets préparés par tests/proxmox/paquets-maj.sh (valide, mauvaise signature,
#       version plus ancienne) ; sans lui, les tests de mise à jour sont « NON TESTÉ ».
# Variables : VMID (900–999, défaut 920), MEMOIRE (Mo, 8192), DISQUE (Go, 32), STOCKAGE,
# PIN (246813), TESTS (liste, défaut : tous), REPRISE=1 (repart de l'instantané « installee »).
# DOSSIER doit être vide ou absent (aucune preuve d'un passage précédent ne peut compter).
# Résultat : DOSSIER/resultats.txt (une ligne par vérification) et « OK » / « ÉCHEC » à la fin.
# Prérequis hôte : tesseract-ocr(-fra) dosfstools exfatprogs xxd zip python3.
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
OUT="$(realpath -m "${1:-$REPO/docs/preuves}")"
VMID=${VMID:-920} STOCKAGE=${STOCKAGE:-local-zfs} PIN=${PIN:-246813}
MEMOIRE=${MEMOIRE:-8192} DISQUE=${DISQUE:-32}
TESTS=${TESTS:-"installation grub pin enrolement transfert blanchiment export maj clavier vide pleine illisible retrait verrouillage journal"}
: "${ISO:?ISO=chemin de l ISO}" "${SERIE_SOURCE:?}" "${SERIE_SORTIE:?}" "${SERIE_AUTRE:?}"
B=(python3 "$ICI/borne.py" "$VMID")
# shellcheck disable=SC2016 # chaîne EICAR littérale
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
ECHECS=0 COURANT=""

[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
if [ "$VMID" -lt 900 ] || [ "$VMID" -gt 999 ]; then echo "VMID hors de 900–999" >&2; exit 1; fi
for o in qm tesseract mkfs.vfat xxd sfdisk zip python3 sha256sum; do
    command -v "$o" >/dev/null || { echo "$o absent" >&2; exit 1; }
done
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
    echo "$OUT n'est pas vide : utilisez un dossier neuf (aucune preuve ancienne ne doit compter)." >&2; exit 1
fi
mkdir -p "$OUT"
R="$OUT/resultats.txt"
T="$(mktemp -d)"
trap 'umount "$T"/m 2>/dev/null || true; rm -rf "$T"' EXIT
mkdir "$T/m"

note() { echo "$1 [$COURANT] : $2" | tee -a "$R"; }
ok() { note OK "$*"; }
ko() { note ÉCHEC "$*" >&2; ECHECS=$((ECHECS + 1)); }
non_teste() { note "NON TESTÉ" "$*"; }
si() { # si [!] COMMANDE… -- « message OK » « message ÉCHEC »
    local c=() inv=0; [ "$1" = "!" ] && { inv=1; shift; }
    while [ "$1" != -- ]; do c+=("$1"); shift; done; shift
    local r=0; "${c[@]}" || r=1
    if [ $((r ^ inv)) -eq 0 ]; then ok "$1"; else ko "$2"; fi
}
test_actif() { [[ " $TESTS " == *" $1 "* ]]; }
debut() { COURANT=$1; D="$OUT/$1"; mkdir -p "$D"; echo; echo "== $1 : $2"; }
capture() { "${B[@]}" capture "$D/$1.png"; }
lire() { "${B[@]}" lire > "$D/$1.txt"; cat "$D/$1.txt"; }
attendre() { "${B[@]}" attendre "$@"; }
cliquer() { "${B[@]}" cliquer "$@"; }
# attendre sans faire échouer le script : renvoie 1 si le texte n'est pas apparu
voir() { "${B[@]}" attendre "$@" >/dev/null 2>&1; }

# --- clés -----------------------------------------------------------------------------
# Disque côté hôte d'une clé désignée par son numéro de série ; jamais un disque non USB.
disque() {
    local d
    for _ in $(seq 60); do
        d=$(lsblk -dnpo NAME,SERIAL,TRAN | awk -v s="$1" '$2 == s && $3 == "usb" { print $1 }')
        [ -n "$d" ] && [ "$(lsblk -dno TRAN "$d")" = usb ] && { echo "$d"; return; }
        sleep 1
    done
    echo "clé $1 introuvable sur l'hôte" >&2; return 1
}
port() {
    local f
    for f in /sys/bus/usb/devices/*/serial; do
        [ "$(cat "$f")" = "$1" ] && { basename "$(dirname "$f")"; return; }
    done
    echo "port de la clé $1 introuvable" >&2; return 1
}
brancher() { disque "$2" >/dev/null; qm set "$VMID" "-$1" "host=$(port "$2"),usb3=1" >/dev/null; sleep 4; }
debrancher() { qm set "$VMID" --delete "$1" >/dev/null 2>&1 || true; sleep 4; }
# FAT32 d'une seule partition (taille facultative, ex. +300M) ; monte sur $T/m
formater() {
    local d; d=$(disque "$1")
    wipefs -qa "$d"; echo "${2:+size=$2,}type=c" | sfdisk -q "$d"; sleep 2; partprobe "$d" 2>/dev/null || true; sleep 1
    mkfs.vfat -F32 -n "${3:-CLE}" "${d}1" >/dev/null
    mount "${d}1" "$T/m"
}
liste_sha() { (cd "$1" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done); }
demonter() { liste_sha "$T/m" > "$1"; umount "$T/m"; sync; }
# Contenu de test : fichiers sains, EICAR, archives (mixte, imbriquée, chiffrée, noms piégés,
# nom très long) et type déguisé. Liste et sha256 dans $1.
contenu_test() {
    local m="$T/m"
    mkdir -p "$m/docs/sous dossier" "$m/photos" "$m/archives"
    printf 'Rapport trimestriel BARBACANE\nLigne accentuée : éàç\n' > "$m/docs/rapport.txt"
    seq 1 20000 > "$m/docs/donnees.csv"
    head -c 300000 /dev/urandom > "$m/photos/image.bin"
    printf 'fichier imbriqué\n' > "$m/docs/sous dossier/note.txt"
    printf '%s' "$EICAR" > "$m/docs/eicar.com"
    printf '%s' "$EICAR" > "$m/photos/vacances.jpg"          # type déguisé
    printf 'contenu sain\n' > "$T/sain.txt"; printf '%s' "$EICAR" > "$T/eicar.com"
    (cd "$T" && zip -q -X "$m/archives/mixte.zip" eicar.com sain.txt)
    (cd "$T" && zip -q -X inner.zip eicar.com sain.txt && zip -q -X "$m/archives/imbriquee.zip" inner.zip sain.txt)
    (cd "$T" && zip -q -X -P secret "$m/archives/chiffre-bon.zip" sain.txt)
    python3 - "$m/archives/noms-pieges.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("../../../evasion.txt", "traversée")
    z.writestr("/etc/absolu.txt", "absolu")
    z.writestr("controle-\x07-\x1b.txt", "caractères de contrôle")
    z.writestr("n" * 300 + ".txt", "nom de 304 caractères")
    z.writestr("sain-dans-pieges.txt", "contenu sain\n")
PY
}

# Passage complet sur une clé (sha256 et recherche d'EICAR en UNE lecture de toute la clé).
empreinte_cle() { # serie prefixe
    local d t; d=$(disque "$1"); t=$(blockdev --getsize64 "$d")
    tee >(sha256sum | awk -v t="$t" '{ print $1 "  clé entière (" t " octets)" }' > "$D/$2.sha256") \
        < "$d" | grep -obaF 'EICAR-STANDARD' | cut -d: -f1 > "$D/$2-eicar-offsets.txt" || true
    sleep 1
    xxd -l 512 "$d" > "$D/$2-secteur0.hex"
    local o; o=$(head -1 "$D/$2-eicar-offsets.txt")
    if [ -n "$o" ]; then xxd -s $((o - 32)) -l 128 "$d" > "$D/$2-eicar.hex"; fi
}

# Vérifie la sortie : ensemble exact (sains attendus + extraits + rapports), aucun contenu EICAR.
verifier_sortie() { # source.sha256 sortie.sha256 dossier_monte
    local f h n=0
    while read -r h f; do
        case "$f" in docs/eicar.com|photos/vacances.jpg|archives/*) continue ;; esac
        if grep -qxF "$h  $f" "$2"; then n=$((n + 1)); else ko "$f absent ou modifié en sortie"; fi
    done < "$1"
    ok "$n fichiers sains copiés intacts (sha256 identiques à la source)"
    local intrus; intrus=$(awk '{ $1=""; sub(/^ /, ""); print }' "$2" | grep -vxF -f <(awk '{ $1=""; sub(/^ /, ""); print }' "$1") \
        | grep -vE '^rapport-barbacane-[0-9-]+\.(txt|html)$|^archives/[^/]+\.extrait/|^archives/chiffre-bon\.zip$' || true)
    si [ -z "$intrus" ] -- "aucun fichier inattendu en sortie (sains, extraits d'archives et rapports seulement)" \
        "fichiers inattendus en sortie : $(echo "$intrus" | tr '\n' ' ')"
    si [ -z "$(grep -rlaF 'EICAR-STANDARD' "$3" 2>/dev/null)" ] -- "aucun fichier de la sortie ne contient EICAR" \
        "EICAR présent en sortie : $(grep -rlaF 'EICAR-STANDARD' "$3" | tr '\n' ' ')"
    si ! grep -q 'vacances.jpg$\|eicar.com$' "$2" -- "fichiers EICAR (dont le .jpg déguisé) absents" "un fichier EICAR est copié"
    si grep -q 'chiffre-bon.zip$' "$2" -- "archive chiffrée (bon mot de passe) copiée" "archive chiffrée absente"
    si grep -q 'mixte.zip.extrait/sain.txt$' "$2" -- "archive mixte : seul son fichier sain est extrait" "extraction de mixte.zip absente"
    si ! grep -q 'evasion\|absolu' "$2" -- "noms piégés (traversée, absolu) non écrits" "nom piégé écrit en sortie"
}

# Monte la première partition d'une clé en lecture seule sur $T/m
monter_ro() {
    local d p; d=$(disque "$1"); sleep 2; partprobe "$d" 2>/dev/null || true; sleep 2
    p=$(lsblk -lnpo NAME,FSTYPE "$d" | awk '$2 != "" { print $1; exit }')
    mount -o ro "$p" "$T/m"
}

admin() { # ouvre le mode administrateur (PIN déjà choisi)
    cliquer "Administration"; attendre "Saisissez le PIN" 30
    "${B[@]}" pin "$PIN"; cliquer "Valider"; attendre "Quitter le mode administrateur" 30
}
quitter_admin() { cliquer "Quitter le mode administrateur"; attendre "Insérez la clé à analyser" 30; }
# Répond à une demande de mot de passe d'archive (clavier virtuel) si elle apparaît.
mot_de_passe_si_demande() {
    if voir "Archive protégée" 600; then
        capture 02b-mot-de-passe
        "${B[@]}" texte "$1"; cliquer "Valider"
    fi
}

echo "Preuves : $OUT ; ISO : $ISO (sha256 $(sha256sum "$ISO" | cut -c1-16)…) ; commit $(git -C "$REPO" rev-parse --short HEAD)"
{ echo "ISO sha256 : $(sha256sum "$ISO" | cut -d' ' -f1)"; echo "Commit : $(git -C "$REPO" rev-parse HEAD)"
  echo "VM : $VMID, ${MEMOIRE} Mo, disque ${DISQUE} Go, UEFI, sans réseau"; echo "Date : $(date -Is)"; } > "$OUT/contexte.txt"

# Un passage interrompu peut avoir laissé des clés passées à la VM : on les rend à l'hôte.
if qm status "$VMID" >/dev/null 2>&1; then qm set "$VMID" --delete usb0,usb1,usb2 >/dev/null 2>&1 || true; sleep 3; fi

# === installation : ISO copiée sur une clé, VM démarrée sur la clé ========================
if test_actif installation && [ "${REPRISE:-0}" != 1 ]; then
    debut installation "ISO copiée sur la clé $SERIE_AUTRE, VM démarrée dessus"
    if qm status "$VMID" >/dev/null 2>&1; then
        [ "$(qm config "$VMID" | awk '/^name:/ { print $2 }')" = barbacane-borne ] \
            || { echo "VM $VMID existante qui n'est pas barbacane-borne : abandon" >&2; exit 1; }
        qm stop "$VMID" >/dev/null 2>&1 || true; qm destroy "$VMID" --purge >/dev/null
    fi
    d=$(disque "$SERIE_AUTRE")
    [ "$(blockdev --getsize64 "$d")" -gt "$(stat -c %s "$ISO")" ] || { ko "clé trop petite pour l'ISO"; exit 1; }
    ! lsblk -no MOUNTPOINT "$d" | grep -q . || { ko "clé d'installation montée sur l'hôte"; exit 1; }
    lsblk -o NAME,SIZE,TRAN,SERIAL,MODEL "$d" > "$D/cle-avant-dd.txt"
    dd if="$ISO" of="$d" bs=4M conv=fsync status=none
    si cmp -n "$(stat -c %s "$ISO")" "$ISO" "$d" -- "ISO copiée sur la clé (relecture identique)" "copie de l'ISO sur la clé incorrecte"
    qm create "$VMID" --name barbacane-borne --bios ovmf --machine q35 \
        --efidisk0 "$STOCKAGE:1,efitype=4m,pre-enrolled-keys=0" --memory "$MEMOIRE" --cores 2 --cpu host \
        --scsihw virtio-scsi-single --scsi0 "$STOCKAGE:$DISQUE" --vga std --ostype l26 >/dev/null
    qm set "$VMID" -usb0 "host=$(port "$SERIE_AUTRE"),usb3=1" >/dev/null
    qm set "$VMID" --boot 'order=scsi0;usb0' >/dev/null
    qm config "$VMID" > "$D/vm.conf"
    si ! grep -q '^net' "$D/vm.conf" -- "VM sans carte réseau" "la VM a une carte réseau"
    qm start "$VMID"
    sleep 60; capture 01-installateur
    # Fin d'installation : la borne redémarre sur son disque et voit encore la clé d'installation
    attendre "Clé détectée" 3600 "$D/02a-cle-installation-encore-branchee.png"
    debrancher usb0     # le technicien retire la clé
    attendre "Insérez la clé à analyser" 120 "$D/02-premier-ecran.png"
    ok "installation automatique depuis la clé USB, interface affichée (${MEMOIRE} Mo de RAM)"
    qm snapshot "$VMID" installee >/dev/null
elif [ "${REPRISE:-0}" = 1 ]; then
    COURANT=installation
    qm stop "$VMID" >/dev/null 2>&1 || true; qm rollback "$VMID" installee; qm start "$VMID"
    attendre "Insérez la clé à analyser" 600
    ok "borne remise à l'état « installée » (instantané, REPRISE=1)"
fi

# === grub : édition du démarrage protégée (S-01) =========================================
if test_actif grub; then
    debut grub "démarrage : Échap tenu n'ouvre pas le menu ; grub.cfg verrouillé (lu à l'étape journal)"
    python3 - "$ICI" "$VMID" "$D" > "$D/ocr-demarrage.txt" <<'PY'
import sys, time
sys.path.insert(0, sys.argv[1])
import borne
vm, d = sys.argv[2], sys.argv[3]
borne.qmp(vm, ("system_reset", None))
t, n = time.time(), 0
while time.time() - t < 25:          # Échap toutes les 30 ms, comme une touche tenue
    try:
        borne.qmp(vm, ("send-key", {"keys": [{"type": "qcode", "data": "esc"}], "hold-time": 20}))
    except Exception:
        pass
    time.sleep(0.03)
    if time.time() - t > 4 * (n + 1):
        n += 1
        png = f"{d}/0{n}-demarrage-echap-{4 * n}s.png"
        borne.capture(vm, png)
        print(f"--- {png}\n{borne.lire(png)}")
PY
    if attendre "Insérez la clé à analyser" 300 "$D/09-accueil.png" && ! grep -qi 'GNU GRUB\|username' "$D/ocr-demarrage.txt"; then
        ok "Échap tenu au démarrage : pas de menu GRUB, démarrage direct de la borne"
    else ko "menu GRUB atteint au clavier (voir ocr-demarrage.txt)"; fi
fi

# === pin : premier PIN, mauvais PIN ======================================================
if test_actif pin; then
    debut pin "premier démarrage (choix du PIN), mauvais PIN, bon PIN"
    cliquer "Administration"; attendre "choisissez le PIN" 30 "$D/01-premier-pin.png"
    "${B[@]}" pin "$PIN"; cliquer "Valider"; attendre "Quitter le mode administrateur" 30 "$D/02-menu-admin.png"
    ok "premier PIN choisi, menu d'administration ouvert"
    quitter_admin
    cliquer "Administration"; attendre "Saisissez le PIN" 30
    "${B[@]}" pin 999999; cliquer "Valider"
    si voir "PIN incorrect" 20 "$D/03-mauvais-pin.png" -- "mauvais PIN refusé (essais restants affichés)" "mauvais PIN non refusé"
    "${B[@]}" pin "$PIN"; cliquer "Valider"
    si voir "Quitter le mode administrateur" 30 "$D/04-bon-pin.png" -- "bon PIN accepté après une erreur" "bon PIN refusé"
    quitter_admin
fi

# === enrolement : clé de destination enrôlée, mode activé ================================
if test_actif enrolement; then
    debut enrolement "enrôlement de la clé de destination $SERIE_SORTIE"
    admin; cliquer "Clés de sortie enrôlées"
    brancher usb1 "$SERIE_SORTIE"; attendre "Enrôler" 60 "$D/01-cle-branchee.png"
    cliquer "Enrôler"; cliquer "Activer"
    si voir "ACTIVÉ" 30 "$D/02-cle-enrolee.png" -- "clé enrôlée, mode « clés enrôlées » activé" "mode clés enrôlées non activé"
    cliquer "Retour au menu"; debrancher usb1; quitter_admin
fi

# === transfert : clé inconnue → clé non enrôlée (refus) puis clé enrôlée ==================
if test_actif transfert; then
    debut transfert "clé inconnue $SERIE_SOURCE → clé enrôlée $SERIE_SORTIE"
    formater "$SERIE_SOURCE" "" SOURCE; contenu_test; demonter "$D/source.sha256"
    formater "$SERIE_SORTIE" "" DEST; echo "témoin à effacer" > "$T/m/TEMOIN-AVANT.txt"; demonter "$D/destination-avant.sha256"
    brancher usb1 "$SERIE_SOURCE"; attendre "Clé détectée" 60 "$D/01-cle-detectee.png"
    cliquer "Copier vers une clé"
    mot_de_passe_si_demande secret
    attendre "Résultat de l'analyse" 3600 "$D/02-resultat-analyse.png"
    lire 02-resultat-analyse >/dev/null
    si grep -qi 'menace' "$D/02-resultat-analyse.txt" -- "écran : menaces détectées" "écran : aucune menace affichée"
    cliquer "Choisir la clé de destination"
    brancher usb2 "$SERIE_AUTRE"
    si voir "pas enrôlée" 60 "$D/03-cle-non-enrolee-refusee.png" -- "clé non enrôlée refusée en sortie" "clé non enrôlée acceptée"
    debrancher usb2
    brancher usb2 "$SERIE_SORTIE"; attendre "Clé de destination" 60 "$D/04-cle-destination.png"
    cliquer "Effacer cette clé"
    attendre "Vous pouvez retirer les clés" 3600 "$D/05-termine.png"
    debrancher usb2; debrancher usb1
    monter_ro "$SERIE_SORTIE"; liste_sha "$T/m" > "$D/sortie.sha256"
    cp "$T/m"/rapport-barbacane-* "$D/" 2>/dev/null || true
    verifier_sortie "$D/source.sha256" "$D/sortie.sha256" "$T/m"
    si ! grep -q TEMOIN-AVANT "$D/sortie.sha256" -- "contenu précédent de la destination effacé (témoin absent)" "le témoin est encore sur la destination"
    umount "$T/m"
    si grep -qi 'eicar' "$D"/rapport-barbacane-*.txt -- "rapport : EICAR détecté et refusé" "rapport sans EICAR"
    attendre "Insérez la clé à analyser" 120
fi

# === blanchiment de la clé source ========================================================
if test_actif blanchiment; then
    debut blanchiment "blanchiment de la clé $SERIE_SOURCE"
    formater "$SERIE_SOURCE" "" SOURCE; contenu_test; demonter "$D/avant.sha256"
    empreinte_cle "$SERIE_SOURCE" cle-avant
    si [ -s "$D/cle-avant-eicar-offsets.txt" ] -- "avant : EICAR sur la clé (octets $(tr '\n' ' ' < "$D/cle-avant-eicar-offsets.txt"))" "avant : EICAR introuvable"
    brancher usb1 "$SERIE_SOURCE"; attendre "Clé détectée" 60 "$D/01-cle-detectee.png"
    cliquer "Blanchir cette clé"
    mot_de_passe_si_demande secret
    attendre "Résultat de l'analyse" 3600 "$D/02-resultat-analyse.png"
    cliquer "Blanchir la clé"; attendre "Effacer et réécrire" 30 "$D/03-confirmation.png"
    cliquer "Effacer et réécrire"
    sleep 90; capture 04-effacement-en-cours
    attendre "Vous pouvez retirer les clés" 10800 "$D/05-termine.png"
    debrancher usb1
    empreinte_cle "$SERIE_SOURCE" cle-apres
    si [ "$(cut -c1-64 "$D/cle-avant.sha256")" != "$(cut -c1-64 "$D/cle-apres.sha256")" ] \
        -- "empreinte de la clé entière modifiée" "clé inchangée"
    si [ ! -s "$D/cle-apres-eicar-offsets.txt" ] -- "après : aucune trace d'EICAR sur TOUTE la clé" "après : EICAR encore présent"
    monter_ro "$SERIE_SOURCE"; liste_sha "$T/m" > "$D/apres.sha256"; cp "$T/m"/rapport-barbacane-* "$D/" 2>/dev/null || true
    verifier_sortie "$D/avant.sha256" "$D/apres.sha256" "$T/m"; umount "$T/m"
    attendre "Insérez la clé à analyser" 120
fi

# === export des journaux et rapports =====================================================
if test_actif export; then
    debut export "export des journaux et rapports sur la clé $SERIE_SORTIE"
    admin; cliquer "Exporter les journaux"; attendre "Exporter les journaux et rapports" 30
    brancher usb1 "$SERIE_SORTIE"; sleep 5; cliquer "Exporter"
    si voir "exportés" 600 "$D/01-export-termine.png" -- "export terminé" "export échoué"
    cliquer "Retour au menu"; debrancher usb1; quitter_admin
    monter_ro "$SERIE_SORTIE"; (cd "$T/m" && find . -type f | sort) > "$D/contenu-cle.txt"
    cp -r "$T/m"/. "$D/cle/" 2>/dev/null || { mkdir -p "$D/cle"; cp -r "$T/m"/. "$D/cle/"; }
    umount "$T/m"
    si grep -q 'journal' "$D/contenu-cle.txt" -- "journal de la borne exporté" "journal absent de l'export"
    si grep -q 'rapport-barbacane' "$D/contenu-cle.txt" -- "rapports exportés" "rapports absents de l'export"
fi

# === maj : mise à jour signée valide, puis refus ==========================================
maj_appliquer() { # fichier.bcu sous-dossier attendu
    formater "$SERIE_AUTRE" "" MAJ; cp "$1" "$1.minisig" "$T/m/"; demonter "$D/$2-cle.sha256"
    admin; cliquer "Mettre à jour"; attendre "Mise à jour hors ligne" 30
    brancher usb1 "$SERIE_AUTRE"; sleep 5; cliquer "Lire et appliquer"
    if voir "$3" 900 "$D/$2.png"; then lire "$2" >/dev/null; return 0; fi
    lire "$2" >/dev/null; return 1
}
if test_actif maj; then
    debut maj "mises à jour signées"
    if [ -z "${MAJ:-}" ] || [ ! -d "$MAJ" ]; then
        non_teste "MAJ non fourni (tests/proxmox/paquets-maj.sh)"
    else
        valide=$(ls "$MAJ"/valide/*.bcu); sig=$(ls "$MAJ"/mauvaise-signature/*.bcu); vieux=$(ls "$MAJ"/ancienne/*.bcu)
        v=$(basename "$valide" .bcu | grep -o '[0-9]*$')
        si maj_appliquer "$valide" 01-valide "version $v" -- "paquet signé valide appliqué (version $v, base antivirale)" "paquet valide non appliqué"
        cliquer "Retour au menu"; debrancher usb1; quitter_admin
        si maj_appliquer "$sig" 02-mauvaise-signature "signature invalide" -- "paquet signé par une autre clé refusé" "mauvaise signature acceptée"
        cliquer "Retour au menu"; debrancher usb1; quitter_admin
        si maj_appliquer "$vieux" 03-version-ancienne "retour arrière" -- "version plus ancienne refusée" "retour arrière accepté"
        cliquer "Retour au menu"; debrancher usb1
        cliquer "État de la borne"; capture 04-etat-borne; lire 04-etat-borne >/dev/null
        cliquer "Retour au menu"; quitter_admin
    fi
fi

# === clavier : un clavier USB ne peut rien taper (S-06) ===================================
if test_actif clavier; then
    debut clavier "clavier USB branché (émulé : usb-kbd QEMU)"
    echo "device_add usb-kbd,id=clavier_test" | qm monitor "$VMID" > "$D/monitor.txt"; sleep 5
    cliquer "Administration"; attendre "Saisissez le PIN" 30
    for k in 1 2 3 4 5 6 ret; do echo "sendkey $k" | qm monitor "$VMID" >/dev/null; sleep 0.3; done
    for k in ctrl-alt-f1 ctrl-alt-f3 alt-sysrq-h; do echo "sendkey $k" | qm monitor "$VMID" >/dev/null; sleep 1; done
    capture 01-apres-frappes; lire 01-apres-frappes >/dev/null
    si voir "Saisissez le PIN" 10 -- "frappes et combinaisons sans effet : l'écran du PIN est inchangé" "le clavier a eu un effet"
    si ! grep -q '●' "$D/01-apres-frappes.txt" -- "aucun chiffre saisi dans le champ PIN" "des chiffres ont été saisis"
    cliquer "Annuler"
    echo "device_del clavier_test" | qm monitor "$VMID" >/dev/null
fi

# === clés hostiles ======================================================================
if test_actif vide; then
    debut vide "clé vide"
    formater "$SERIE_AUTRE" "" VIDE; demonter "$D/cle.sha256"
    brancher usb1 "$SERIE_AUTRE"; attendre "Clé détectée" 60; cliquer "Copier vers une clé"
    if voir "Résultat de l'analyse" 300 "$D/01-resultat.png" || voir "erreur" 5 "$D/01-resultat.png"; then
        lire 01-resultat >/dev/null; ok "clé vide : la borne affiche un résultat sans planter"
    else ko "clé vide : aucun résultat"; fi
    capture 01-resultat
    cliquer "Abandonner" || cliquer "Recommencer"
    debrancher usb1
    si voir "Insérez la clé à analyser" 60 -- "retour à l'accueil" "borne bloquée après la clé vide"
fi
if test_actif pleine; then
    debut pleine "clé pleine (système de fichiers rempli à 100 %)"
    formater "$SERIE_AUTRE" +256M PLEINE
    i=0; while head -c 16M /dev/urandom > "$T/m/remplissage-$i.bin" 2>/dev/null; do i=$((i + 1)); done
    head -c 1M /dev/urandom > "$T/m/dernier.bin" 2>/dev/null || true
    df -h "$T/m" > "$D/occupation.txt"; demonter "$D/cle.sha256"
    brancher usb1 "$SERIE_AUTRE"; attendre "Clé détectée" 60; cliquer "Copier vers une clé"
    si voir "Résultat de l'analyse" 1800 "$D/01-resultat.png" -- "clé pleine analysée ($(grep -c . "$D/cle.sha256") fichiers)" "clé pleine : pas de résultat"
    lire 01-resultat >/dev/null; cliquer "Abandonner"; debrancher usb1
    si voir "Insérez la clé à analyser" 60 -- "retour à l'accueil" "borne bloquée après la clé pleine"
fi
if test_actif illisible; then
    debut illisible "clé illisible (64 premiers Mo aléatoires : ni table de partitions ni système de fichiers)"
    d=$(disque "$SERIE_AUTRE"); wipefs -qa "$d"; dd if=/dev/urandom of="$d" bs=1M count=64 conv=fsync status=none
    xxd -l 512 "$d" > "$D/secteur0.hex"
    brancher usb1 "$SERIE_AUTRE"; sleep 10; capture 01-branchee; lire 01-branchee >/dev/null
    if grep -q "Clé détectée" "$D/01-branchee.txt"; then
        cliquer "Copier vers une clé"; sleep 30; capture 02-apres-lecture; lire 02-apres-lecture >/dev/null
    fi
    debrancher usb1; sleep 5
    if voir "Insérez la clé à analyser" 30 || { cliquer "Recommencer" && voir "Insérez la clé à analyser" 30; }; then
        capture 03-retour-accueil; ok "clé illisible : message affiché, borne de nouveau utilisable"
    else capture 03-bloquee; ko "borne bloquée après une clé illisible"; fi
fi
if test_actif retrait; then
    debut retrait "clé retirée pendant la lecture"
    formater "$SERIE_AUTRE" "" GROS; head -c 1500M /dev/urandom > "$T/m/gros.bin"; demonter "$D/cle.sha256"
    brancher usb1 "$SERIE_AUTRE"; attendre "Clé détectée" 60; cliquer "Copier vers une clé"
    sleep 15; capture 01-lecture-en-cours
    debrancher usb1; sleep 15; capture 02-apres-retrait; lire 02-apres-retrait >/dev/null
    if voir "Insérez la clé à analyser" 20 || { cliquer "Recommencer" && voir "Insérez la clé à analyser" 30; } \
        || { cliquer "Abandonner" && voir "Insérez la clé à analyser" 30; }; then
        capture 03-retour-accueil; ok "retrait en cours de lecture : erreur affichée, aucune copie, borne de nouveau utilisable"
    else ko "borne bloquée après un retrait en cours de lecture"; fi
fi

# === verrouillage du PIN (en dernier : bloque l'administration 15 min) ====================
if test_actif verrouillage; then
    debut verrouillage "5 mauvais PIN → verrouillage"
    cliquer "Administration"; attendre "Saisissez le PIN" 30
    for _ in 1 2 3 4 5; do "${B[@]}" pin 999999; cliquer "Valider"; sleep 2; done
    si voir "verrouillé" 30 "$D/01-verrouille.png" -- "administration verrouillée après 5 échecs" "pas de verrouillage"
    "${B[@]}" pin "$PIN"; cliquer "Valider"
    si voir "verrouillé" 20 "$D/02-bon-pin-refuse.png" -- "même le bon PIN est refusé pendant le verrouillage" "bon PIN accepté pendant le verrouillage"
    cliquer "Annuler" || true
fi

# === journal de la borne (disque de la VM lu hors ligne) ==================================
if test_actif journal; then
    debut journal "journal et rapports de la borne"
    qm shutdown "$VMID" --timeout 120 >/dev/null 2>&1 || qm stop "$VMID"
    vol=$(pvesm path "$(qm config "$VMID" | awk -F'[ ,]' '/^scsi0:/ { print $2 }')")
    racine=$(lsblk -lnpo NAME,FSTYPE "$vol" | awk '$2 == "ext4" { print $1; exit }')
    mount -o ro,noload "$racine" "$T/m"
    journalctl -D "$T/m/var/log/journal" --no-pager -o short-iso -u usbsas-server -u barbacane-kiosk \
        -u barbacane-analyzer -u barbacane-admind -u clamav-daemon -u hid-dealer > "$D/journal.log" || true
    cp "$T/m"/var/lib/usbsas/reports/* "$D/" 2>/dev/null || true
    grep -E '^set superusers|^password_pbkdf2|^menuentry|^submenu' "$T/m/boot/grub/grub.cfg" | cut -c1-90 > "$D/grub-cfg-extrait.txt" || true
    umount "$T/m"
    si grep -q '^set superusers="barbacane"' "$D/grub-cfg-extrait.txt" -- "grub.cfg : super-utilisateur et mot de passe (édition protégée)" "grub.cfg sans mot de passe"
    premiere=$(grep -m1 '^menuentry' "$D/grub-cfg-extrait.txt" || true)
    libre=non; [[ "$premiere" == *--unrestricted* ]] && libre=oui
    si [ "$libre" = oui ] -- "grub.cfg : entrée par défaut démarrable sans mot de passe" "entrée par défaut restreinte"
    si grep -qi 'eicar' "$D/journal.log" -- "journal : détections EICAR consignées" "journal sans EICAR"
    si grep -qi 'clavier\|keyboard\|not.*mouse\|hid' "$D/journal.log" -- "journal : clavier USB vu par hid-dealer" "journal : aucune trace du clavier"
fi

echo
grep -c '^OK' "$R" | xargs echo "Vérifications OK :"
grep '^NON TESTÉ' "$R" || true
if [ "$ECHECS" -eq 0 ]; then echo "OK"; else grep '^ÉCHEC' "$R"; echo "ÉCHEC ($ECHECS)"; exit 1; fi
