#!/bin/bash
# Garde-fou Proxmox des paquets : avec /etc/pve, « dpkg -i » de chaque paquet Barbacane échoue
# dans le preinst, AVANT la copie des fichiers (modprobe, udev, PAM, GRUB…).
#
#   tests/garde-fou/paquets.sh DOSSIER_DES_DEB      (root, conteneur jetable de la CI uniquement)
set -euo pipefail
D=${1:?dossier des .deb}
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root (CI)." >&2; exit 1; }
[ -e /etc/pve ] && { echo "Vrai hôte Proxmox détecté : test refusé (CI uniquement)." >&2; exit 1; }
trap 'rmdir /etc/pve 2>/dev/null || true' EXIT
mkdir /etc/pve
echecs=0
for deb in "$D"/barbacane_*.deb "$D"/usbsas-server_*.deb "$D"/usbsas-hid_*.deb; do
    nom=$(dpkg-deb -f "$deb" Package)
    dpkg-deb -I "$deb" preinst >/dev/null 2>&1 || { echo "ÉCHEC $nom : pas de preinst"; echecs=$((echecs + 1)); continue; }
    rc=0; dpkg -i "$deb" > /tmp/garde-fou-dpkg.txt 2>&1 || rc=$?
    # fichiers du paquet présents sur le disque ?
    poses=0
    while read -r f; do [ -f "$f" ] && poses=$((poses + 1)); done < <(dpkg-deb -c "$deb" | awk '$1 !~ /^d/ {sub(/^\./, "", $6); print $6}')
    if [ "$rc" -ne 0 ] && grep -q 'REFUS : hôte Proxmox VE détecté' /tmp/garde-fou-dpkg.txt \
        && ! dpkg -s "$nom" 2>/dev/null | grep -q '^Status: install ok installed' && [ "$poses" -eq 0 ]; then
        echo "OK    $nom : dpkg -i refusé sur un hôte Proxmox, aucun fichier posé"
    else
        echo "ÉCHEC $nom : code $rc, $poses fichier(s) posé(s)"; cat /tmp/garde-fou-dpkg.txt; echecs=$((echecs + 1))
    fi
done
[ "$echecs" -eq 0 ] && echo "GARDE-FOU PAQUETS : OK" || { echo "GARDE-FOU PAQUETS : $echecs échec(s)"; exit 1; }
