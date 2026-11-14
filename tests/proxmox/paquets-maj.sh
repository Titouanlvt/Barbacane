#!/bin/bash
# Paquets de mise à jour pour tests/proxmox/preuve.sh, à lancer sur le poste administrateur
# (connecté, outils de docs/administration.md §2.2) :
#   MDP=… tests/proxmox/paquets-maj.sh CLE.key SORTIE
# Produit dans SORTIE :
#   valide/              base ClamAV du jour, version = AAAAMMJJHHMM, signé par CLE.key
#   mauvaise-signature/  même contenu, signé par une autre clé (générée ici, jetée)
#   ancienne/            base ClamAV, version 1 (plus ancienne que toute version appliquée)
# MDP : phrase de passe de CLE.key (lue sur l'entrée standard par minisign).
set -euo pipefail
CLE="$(realpath "${1:?usage : paquets-maj.sh CLE.key SORTIE}")"
SORTIE="$(realpath -m "${2:?usage : paquets-maj.sh CLE.key SORTIE}")"
: "${MDP:?MDP=phrase de passe de la clé}"
PREP="$(cd "$(dirname "$0")/../.." && pwd)/borne/update/barbacane-update-prepare"
mkdir -p "$SORTIE"
[ -z "$(ls -A "$SORTIE")" ] || { echo "$SORTIE n'est pas vide" >&2; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# Base ClamAV téléchargée une fois, réutilisée par les trois paquets
mkdir -p "$T/clamav"
printf 'DatabaseMirror database.clamav.net\nDatabaseDirectory %s\nDatabaseOwner root\n' "$T/clamav" > "$T/freshclam.conf"
freshclam --config-file="$T/freshclam.conf" --foreground --quiet

V=$(date +%Y%m%d%H%M)
printf '%s\n' "$MDP" | "$PREP" --cle "$CLE" --sortie "$SORTIE/valide" --version "$V" --clamav "$T/clamav"
printf '%s\n' "$MDP" | "$PREP" --cle "$CLE" --sortie "$SORTIE/ancienne" --version 1 --clamav "$T/clamav"

# Autre clé : paquet bien formé mais signé par une clé que la borne ne connaît pas
printf 'autre\nautre\n' | minisign -G -p "$T/autre.pub" -s "$T/autre.key" >/dev/null
printf 'autre\n' | "$PREP" --cle "$T/autre.key" --sortie "$SORTIE/mauvaise-signature" --version "$((V + 1))" --clamav "$T/clamav"
ls -l "$SORTIE"/*/
