#!/bin/bash
# Campagne rapide sur VRAIES clés (VM 920) SANS reconstruire l'ISO ni réinstaller :
# instantané « installee » → PIN + enrôlement → instantané « propre » (mémoire comprise),
# restauré avant chaque scénario. Lancement : nohup bash lab/campagne-rapide.sh > logs/campagne-rapide.log 2>&1 &
set -u
REV=${REV:-HEAD}; TESTS=${TESTS:-"grub pin enrolement transfert blanchiment maj ventoy export clavier vide pleine illisible retrait veille verrouillage journal"}
E=/root/BARBACANE/exec-rapide; rm -rf $E; mkdir -p $E
git -C /root/BARBACANE/wt-main archive "$REV" | tar x -C $E; cd $E || exit 1
timeout 2m qm delsnapshot 920 propre >/dev/null 2>&1 || true
O=/root/BARBACANE/campagne-rapide; [ -e $O ] && mv $O "$O-$(date +%H%M%S)"
timeout 8h env VMID=920 STOCKAGE=nvme DISQUE=64 REPRISE="${REPRISE:-1}" PROPRE=1 CONTENU=/nvme/contenu-finale \
    MAJ=/var/lib/vz/barbacane/campagne-20261115c/maj VENTOY_REF=/nvme/contenu/ventoy-ref TESTS="$TESTS" \
    ISO=/nvme/contenu/iso-finale/barbacane.iso SERIE_SOURCE=03020611111524225725 \
    SERIE_SORTIE=0501f66b357c3cb8eaaf6efb1d11265cc6fcdab3ce4e06b163ad06c25b56858f2dd900000000000000000000d8d8d3fcff960b108155810725ae0edb \
    SERIE_INSTALL=0501f66b357c3cb8eaaf6efb1d11265cc6fcdab3ce4e06b163ad06c25b56858f2dd900000000000000000000d8d8d3fcff960b108155810725ae0edb SERIE_AUTRE=virtuelle \
    tests/proxmox/preuve.sh $O; echo FIN=$?
