#!/bin/bash
# Régénère les captures de la documentation sur la borne de développement du lab (VM 950,
# instantané « propre », clés émulées) : parcours complet en thème Jour puis Nuit.
#   tests/ui/captures.sh            → docs/captures/v1/{jour,nuit}/NN-ecran.png
# Variables : VMID (950), CAPTURES_THEMES ("jour nuit"). À lancer sur l'hôte du lab (root). SORTIE (docs/captures/v1).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SORTIE="${SORTIE:-docs/captures/v1}"
VMID=${VMID:-950}
O=$(mktemp -d /root/BARBACANE/captures-XXXXXX)
E=$(mktemp -d /root/BARBACANE/exec-captures-XXXXXX)
git -C "$REPO" archive HEAD | tar x -C "$E"
cd "$E"
timeout 3h env VMID="$VMID" STOCKAGE=nvme DISQUE=32 PROPRE=1 REPRISE=propre \
    VIRT_DIR="/nvme/virt/$VMID" CLE_VIRTUELLE="/nvme/virt/$VMID/autre.img" \
    ISO=/nvme/contenu/iso-test/barbacane-TEST-cle-lab.iso \
    SERIE_INSTALL=virt:install SERIE_SOURCE=virt:source SERIE_SORTIE=virt:sortie SERIE_AUTRE=virt:autre \
    CAPTURES_THEMES="${CAPTURES_THEMES:-jour nuit}" TESTS=captures tests/proxmox/preuve.sh "$O"
for t in ${CAPTURES_THEMES:-jour nuit}; do
    mkdir -p "$REPO/$SORTIE/$t"
    cp "$O/captures-$t"/[0-9][0-9]-*.png "$REPO/$SORTIE/$t/"
done
echo "captures : $REPO/$SORTIE (journal : $O/resultats.txt)"
