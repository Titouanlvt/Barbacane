#!/bin/bash
# Lanceur parallèle des preuves de bout en bout (hôte Proxmox VE, en root).
#
#   ISO=barbacane.iso [CONTENU=dossier] [MAJ=dossier] [VENTOY_REF=dossier] [CONSTRUIRE=1] tests/proxmox/parallele.sh DOSSIER
#
# 1. (CONSTRUIRE=1) construit l'ISO sur la VM bu pendant que les images de test sont préparées ;
# 2. installe UNE borne modèle (VM BASE, 940 par défaut) depuis une clé ÉMULÉE : installation,
#    démarrage verrouillé, PIN, enrôlement de la clé de sortie émulée ; puis en fait un modèle ;
# 3. lance chaque scénario sur son propre clone lié (941, 942…), plusieurs à la fois, chacun avec
#    ses clés émulées (tests/proxmox/preuve.sh, clés « virt:NOM ») ;
# 4. rassemble DOSSIER/resultats.txt (une ligne par vérification, préfixée du scénario).
#
# MODELE_EXISTANT=1 : reprend la borne modèle BASE déjà faite (pas de réinstallation).
# Ressources : laisse à l'hôte au moins 2 cœurs et 8 Go de RAM (PARALLELE, COEURS, MEMOIRE).
# Aucune vraie clé n'est utilisée : la campagne sur vraies clés (preuve.sh) reste la référence
# matérielle ; ce lanceur sert à aller vite et à tout rejouer à chaque correction.
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ICI/../.." && pwd)"
OUT="$(realpath -m "${1:?DOSSIER des preuves (neuf)}")"
BASE=${BASE:-940} STOCKAGE=${STOCKAGE:-nvme} DISQUE=${DISQUE:-64}
MEMOIRE=${MEMOIRE:-8192} COEURS=${COEURS:-3}
VIRT=${VIRT:-/var/lib/vz/barbacane/virt}
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
# Copie figée des scripts : une modification du dépôt pendant le passage ne doit changer ni les
# scénarios ni CE lanceur (bash relit son fichier en cours de route : une réécriture l'a arrêté le
# 17/11/2026). Le lanceur se relance donc depuis sa copie.
if [ -z "${FIGE:-}" ]; then
    [ ! -e "$OUT" ] || [ -z "$(ls -A "$OUT")" ] || { echo "$OUT n'est pas vide" >&2; exit 1; }
    mkdir -p "$OUT"
    cp -r "$ICI" "$OUT/.scripts"
    FIGE=1 exec "$OUT/.scripts/parallele.sh" "$@"
fi
ICI="$OUT/.scripts"

# Parallélisme : ce que permettent les cœurs et la RAM une fois réservés 2 cœurs et 8 Go à l'hôte
coeurs=$(( $(nproc) - 2 )); ram=$(( $(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo) - 8192 ))
max=$(( coeurs / COEURS < ram / MEMOIRE ? coeurs / COEURS : ram / MEMOIRE ))
PARALLELE=${PARALLELE:-$max}
[ "$PARALLELE" -le "$max" ] || PARALLELE=$max
[ "$PARALLELE" -ge 1 ] || { echo "ressources insuffisantes (cœurs $coeurs, RAM libre $ram Mo)" >&2; exit 1; }
echo "Parallélisme : $PARALLELE bornes de $COEURS cœurs et $MEMOIRE Mo (hôte : $(nproc) cœurs)"

# --- 1. ISO ----------------------------------------------------------------------------------
if [ "${CONSTRUIRE:-0}" = 1 ]; then
    F="$REPO/lab/ssh_config"; [ -e "$F" ] || F=/root/BARBACANE/lab/ssh_config
    ISO=${ISO:-/nvme/contenu/iso-parallele/barbacane.iso}; mkdir -p "$(dirname "$ISO")"
    rev=$(git -C "$REPO" rev-parse HEAD)
    echo "Construction de l'ISO ($rev) sur bu…"
    ssh -F "$F" bu "cd ~/barbacane && git fetch -q origin && git checkout -q $rev && . ~/.cargo/env 2>/dev/null; rm -f barbacane.iso; systeme/iso/build-iso.sh --sortie ~/barbacane/barbacane.iso" > "$OUT/construction-iso.log" 2>&1 &
    pid_iso=$!
fi

# Découpage des images de contenus réels : un scénario par image (le plus long : windows, rufus-ntfs)
declare -a GROUPES=()
GROUPES+=("usb:transfert blanchiment export maj clavier verrouillage journal")
GROUPES+=("limites:volumineux vide pleine illisible retrait journal")
if [ -n "${CONTENU:-}" ]; then
    while read -r img; do
        n=$(basename "$img" .img)
        if [ "$n" = ventoy ]; then GROUPES=("ventoy:ventoy journal" "${GROUPES[@]}"); continue; fi; d="$OUT/.contenu/$n"; mkdir -p "$d"
        ln -sf "$img" "$d/"; for x in sains pieges; do ln -sf "$CONTENU/$n.$x" "$d/"; done
        GROUPES=("reel-$n:reel journal" "${GROUPES[@]}")
    done < <(ls -rS "$CONTENU"/*.img)   # du plus petit au plus gros : le plus gros finit en tête
fi

if [ "${CONSTRUIRE:-0}" = 1 ]; then
    wait "$pid_iso" || { echo "construction de l'ISO échouée (construction-iso.log)" >&2; exit 1; }
    scp -q -F "$F" bu:barbacane/barbacane.iso "$ISO"
fi
: "${ISO:?ISO=chemin de l ISO}"
sha256sum "$ISO" | tee "$OUT/iso.sha256"

# Règle du lab : instantané de l'hôte avant de créer des VM
zfs snapshot "rpool/ROOT/pve-1@avant-parallele-$(date +%Y%m%d-%H%M%S)"

# --- 2. borne modèle ---------------------------------------------------------------------------
cles() { echo "SERIE_INSTALL=virt:install SERIE_SOURCE=virt:source SERIE_SORTIE=virt:sortie SERIE_AUTRE=virt:autre"; }
if [ -n "${MODELE_EXISTANT:-}" ]; then
    qm config "$BASE" | grep -q '^template: 1' || { echo "MODELE_EXISTANT : $BASE n'est pas un modèle" >&2; exit 1; }
    debut=$(date +%s); echo "Borne modèle $BASE reprise telle quelle"
else
if qm config "$BASE" 2>/dev/null | grep -q '^template: 1'; then
    [ "$(qm config "$BASE" | awk '/^name:/ { print $2 }')" = barbacane-borne ] || { echo "VM $BASE n'est pas une borne" >&2; exit 1; }
    # Clones liés de l'ancien modèle (bornes de test 941…949) : supprimés d'abord
    for id in $(seq $((BASE + 1)) $((BASE + 9))); do
        if [ "$(qm config "$id" 2>/dev/null | awk '/^name:/ { print $2 }')" = barbacane-borne ]; then
            qm stop "$id" >/dev/null 2>&1 || true; qm destroy "$id" --purge >/dev/null
        fi
    done
    qm destroy "$BASE" --purge >/dev/null
fi
debut=$(date +%s)
rm -rf "${VIRT:?}/$BASE"
# shellcheck disable=SC2046 # mots voulus (VAR=valeur)
env $(cles) VMID="$BASE" STOCKAGE="$STOCKAGE" DISQUE="$DISQUE" MEMOIRE="$MEMOIRE" COEURS="$COEURS" \
    VIRT_DIR="$VIRT/$BASE" ISO="$ISO" TESTS="installation grub pin enrolement" \
    "$ICI/preuve.sh" "$OUT/modele" > "$OUT/modele.log" 2>&1 || { echo "borne modèle en échec (modele.log)" >&2; tail -5 "$OUT/modele.log" >&2; exit 1; }
qm shutdown "$BASE" --timeout 180 >/dev/null 2>&1 || qm stop "$BASE"
qm delsnapshot "$BASE" installee >/dev/null 2>&1 || true   # un modèle ne peut pas avoir d instantané
qm template "$BASE" >/dev/null
echo "Borne modèle prête en $(( $(date +%s) - debut )) s"
fi

# --- 3. scénarios en parallèle ---------------------------------------------------------------
declare -A PID=() NOM=()
vm=$((BASE + 1)); en_cours=0
lancer() { # nom tests vmid
    local nom=$1 tests=$2 id=$3 contenu=""
    case "$nom" in reel-*) contenu="$OUT/.contenu/${nom#reel-}" ;; ventoy) contenu="$CONTENU" ;; esac
    rm -rf "${VIRT:?}/$id"; mkdir -p "$VIRT/$id"
    # shellcheck disable=SC2046
    env $(cles) VMID="$id" CLONE_DE="$BASE" STOCKAGE="$STOCKAGE" MEMOIRE="$MEMOIRE" COEURS="$COEURS" \
        VIRT_DIR="$VIRT/$id" VIRT_TAILLE=12G ISO="$ISO" TESTS="$tests" CONTENU="$contenu" MAJ="${MAJ:-}" VENTOY_REF="${VENTOY_REF:-}" \
        "$ICI/preuve.sh" "$OUT/$nom" > "$OUT/$nom.log" 2>&1 &
    PID[$id]=$!; NOM[$id]=$nom
    echo "$(date +%H:%M) lancé : $nom (VM $id)"
}
libres=()
for g in "${GROUPES[@]}"; do
    nom=${g%%:*} tests=${g#*:}
    while [ "$en_cours" -ge "$PARALLELE" ]; do
        for id in "${!PID[@]}"; do
            if ! kill -0 "${PID[$id]}" 2>/dev/null; then
                wait "${PID[$id]}" && r=OK || r=ÉCHEC
                echo "$(date +%H:%M) fini : ${NOM[$id]} ($r)"; unset "PID[$id]"; en_cours=$((en_cours - 1)); libres+=("$id")
                # Le clone fini garde son disque (espace de travail rempli) : le rendre au pool
                # tout de suite, sinon l'attente d'espace ci-dessous ne se libère jamais.
                qm stop "$id" >/dev/null 2>&1 || true; qm destroy "$id" --purge >/dev/null 2>&1 || true
            fi
        done
        sleep 10
    done
    # Pool plein = VM figées (io-error) : un clone ne part que s'il reste ESPACE_MIN Go libres
    while [ "$(zpool list -Hpo free "$STOCKAGE" 2>/dev/null || echo 0)" -lt $(( ${ESPACE_MIN:-40} * 1024 * 1024 * 1024 )) ]; do
        echo "$(date +%H:%M) attente : moins de ${ESPACE_MIN:-40} Go libres sur $STOCKAGE"; sleep 60
    done
    if [ ${#libres[@]} -gt 0 ]; then id=${libres[0]}; libres=("${libres[@]:1}"); else id=$vm; vm=$((vm + 1)); fi
    lancer "$nom" "$tests" "$id"; en_cours=$((en_cours + 1))
done
for id in "${!PID[@]}"; do wait "${PID[$id]}" && r=OK || r=ÉCHEC; echo "$(date +%H:%M) fini : ${NOM[$id]} ($r)"; done

# --- 4. résultats -------------------------------------------------------------------------------
R="$OUT/resultats.txt"; : > "$R"
for f in "$OUT"/*/resultats.txt; do
    sed "s/^/[$(basename "$(dirname "$f")")] /" "$f" >> "$R"
done
rm -rf "$OUT/.contenu"
echo "Durée totale : $(( $(date +%s) - debut )) s ; OK : $(grep -c '] OK' "$R") ; ÉCHEC : $(grep -c '] ÉCHEC' "$R" || true) ; NON TESTÉ : $(grep -c 'NON TESTÉ' "$R" || true)"
if grep -q '] ÉCHEC' "$R"; then grep '] ÉCHEC' "$R"; exit 1; fi
echo OK
