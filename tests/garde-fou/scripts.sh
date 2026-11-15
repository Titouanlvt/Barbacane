#!/bin/bash
# Garde-fou Proxmox (docs/incident-proxmox.md) : systeme/install.sh, systeme/iso/configurer.sh et les
# scripts preinst des paquets refusent de tourner quand /etc/pve existe, AVANT toute action.
#
#   sudo tests/garde-fou/scripts.sh
#
# À lancer en root sur une machine jetable (CI) : le script crée puis retire /etc/pve.
# JAMAIS sur un vrai hôte Proxmox (il le refuse d'ailleurs). Les commandes qui modifient le
# système (apt-get, dpkg, systemctl, install, passwd, sed, update-grub…) sont remplacées par des
# témoins qui notent leur appel : avec /etc/pve, aucun témoin ne doit être appelé ; sans /etc/pve
# (contrôle), le premier témoin est appelé puis arrête le script.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root (CI)." >&2; exit 1; }
if [ -e /etc/pve ] && [ ! -e /run/garde-fou-test ]; then
    echo "Vrai hôte Proxmox détecté : test refusé (CI uniquement)." >&2; exit 1
fi

T=$(mktemp -d); trap 'rm -rf "$T"; rm -f /run/garde-fou-test; rmdir /etc/pve 2>/dev/null || true' EXIT
mkdir "$T/bin"
for c in apt-get apt dpkg dpkg-divert systemctl install passwd sed update-grub freshclam rfkill \
         chown adduser addgroup barbacane-admind grub-mkpasswd-pbkdf2 curl; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/appels"\nexit 99\n' "$c" "$T" > "$T/bin/$c"
    chmod 755 "$T/bin/$c"
done
echos=0
ok() { echo "OK    $*"; }
ko() { echo "ÉCHEC $*"; echos=$((echos + 1)); }

lancer() { # lancer COMMANDE… : rc dans $rc, sorties dans $T/sortie
    rm -f "$T/appels"; rc=0
    PATH="$T/bin:$PATH" "$@" > "$T/sortie" 2>&1 || rc=$?
}

# --- avec /etc/pve : refus immédiat, aucune commande appelée
touch /run/garde-fou-test; mkdir -p /etc/pve
for s in "$REPO/systeme/install.sh --sans-rar --debs /inexistant" "$REPO/systeme/iso/configurer.sh" \
         "$REPO/systeme/deb/preinst install" "$REPO/noyau/usbsas-hid/debian/preinst install" \
         "$REPO/noyau/usbsas-usbsas/debian/preinst install"; do
    read -r -a cmd <<< "$s"
    lancer "${cmd[@]}"
    n=${cmd[0]#"$REPO"/}
    if [ "$rc" -ne 0 ] && grep -q 'REFUS : hôte Proxmox VE détecté' "$T/sortie" && [ ! -s "$T/appels" ]; then
        ok "$n refuse sur un hôte Proxmox (code $rc, aucune commande lancée)"
    else
        ko "$n : code $rc, appels : $(cat "$T/appels" 2>/dev/null | tr '\n' ';')"; cat "$T/sortie"
    fi
done

# --- contrôle sans /etc/pve : le garde-fou laisse passer (premier témoin appelé)
rmdir /etc/pve; rm -f /run/garde-fou-test
for s in "$REPO/systeme/install.sh --sans-rar --debs /inexistant" "$REPO/systeme/iso/configurer.sh"; do
    read -r -a cmd <<< "$s"
    lancer "${cmd[@]}"
    n=${cmd[0]#"$REPO"/}
    if [ -s "$T/appels" ] && ! grep -q 'REFUS' "$T/sortie"; then
        ok "$n passe le garde-fou hors Proxmox (premier appel : $(head -1 "$T/appels"))"
    else
        ko "$n bloqué hors Proxmox (code $rc)"; cat "$T/sortie"
    fi
done
for s in systeme/deb/preinst noyau/usbsas-hid/debian/preinst noyau/usbsas-usbsas/debian/preinst; do
    lancer "$REPO/$s" install
    if [ "$rc" -eq 0 ]; then ok "$s accepte hors Proxmox"; else ko "$s refuse hors Proxmox (code $rc)"; fi
done

[ "$echos" -eq 0 ] && echo "GARDE-FOU : OK" || { echo "GARDE-FOU : $echos échec(s)"; exit 1; }
