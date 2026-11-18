#!/bin/bash
# Correctif rapide pour la borne de DÉVELOPPEMENT du lab (installée depuis l'ISO signée par la clé
# de TEST, ~/cles-test sur bu) : compilation incrémentale sur bu (target/ conservé), paquets
# emballés dans une mise à jour signée, rapportés sur l'hôte. Jamais pour une borne de production.
#   tests/proxmox/correctif.sh [RÉVISION_GIT]   → affiche le chemin du .bcu sur l'hôte
# Puis : REPRISE=propre PROPRE=1 CORRECTIF=<.bcu> TESTS="correctif transfert …" tests/proxmox/preuve.sh …
set -euo pipefail
REV=${1:-origin/integration}
F=${SSH_CONFIG:-/root/BARBACANE/lab/ssh_config}
DEST=${DEST:-/nvme/correctifs}; mkdir -p "$DEST"
N=$(date +%y%m%d%H%M)
# shellcheck disable=SC2029  # variables développées côté hôte, voulu
timeout 40m ssh -F "$F" bu "set -e; . ~/.cargo/env; cd ~/barbacane && timeout 60s git fetch -q origin
    cd ~/iso-test && git fetch -q ~/barbacane +refs/remotes/origin/${REV#origin/}:refs/heads/correctif
    git checkout -q -f correctif && git log --oneline -1
    DEB_REVISION=$N CARGO_BUILD_JOBS=\$((\$(nproc) - 2)) timeout 35m systeme/build-debs.sh > ~/correctif-$N.log 2>&1
    rm -rf ~/correctifs/$N; mkdir -p ~/correctifs/$N
    borne/update/barbacane-update-prepare --cle ~/cles-test/test.key --sans-clamav \
        --debs systeme/mkosi/paquets --sortie ~/correctifs/$N >> ~/correctif-$N.log 2>&1
    ls ~/correctifs/$N" >&2
mkdir -p "$DEST/$N"; timeout 10m scp -q -F "$F" "bu:correctifs/$N/*" "$DEST/$N/"
find "$DEST/$N" -name '*.bcu'
