#!/bin/bash
# Borne installée depuis une ISO PERSONNALISÉE par le serveur, dans QEMU, SANS aucune saisie ni
# modification du disque : passerelle de TEST → jeton créé par le registre → remaster de l'ISO
# générique (serveur/iso-bornes/barbacane-iso-borne) → installation sans carte réseau → premier
# démarrage (QEMU user, DHCP) → l'agent dépose sa demande avec le jeton de l'ISO → validation
# par empreinte → battement ; le jeton est absent du disque ensuite (supprimé par l'agent).
# Usage : qemu-personnalisee.sh ISO_GENERIQUE DOSSIER PKI PASSERELLE REGISTRE
#   ISO générique : --serveur 10.0.2.2 --port-enrolement 43118 --port-service 43117, CA de PKI.
#   Root, KVM, qemu, ovmf, qemu-utils, xorriso.
set -euo pipefail
[ $# -eq 5 ] || { echo "usage : $0 ISO DOSSIER PKI PASSERELLE REGISTRE" >&2; exit 2; }
ISO="$(realpath "$1")" W="$(realpath -m "$2")" PKI="$(realpath "$3")" P="$(realpath "$4")" R="$(realpath "$5")"
OUTIL="$(cd "$(dirname "$0")/../.." && pwd)/serveur/iso-bornes/barbacane-iso-borne"
PE=43118 PS=43117
mkdir -p "$W"
for p in $PE $PS; do ! ss -Htln "sport = :$p" | grep -q . || { echo "port $p déjà utilisé" >&2; exit 1; }; done
modprobe nbd max_part=16
NBD=''
for n in 9 8 7 6 5; do
    if [ "$(cat "/sys/block/nbd$n/size" 2>/dev/null || echo 1)" = 0 ]; then NBD=/dev/nbd$n; break; fi
done
[ -n "$NBD" ] || { echo "aucun nbd libre" >&2; exit 1; }
PIDS=()
# shellcheck disable=SC2317,SC2329  # appelée par trap
fin() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; umount "$W/rw" 2>/dev/null || true; qemu-nbd -d "$NBD" >/dev/null 2>&1 || true; }
trap fin EXIT
cat > "$W/passerelle.conf" <<C
adresse = 127.0.0.1
port = $PS
port_enrolement = $PE
chaine_serveur = $PKI/serveur/chaine.pem
cle_serveur = $PKI/serveur/cle.pem
ca_bornes = $PKI/ca-bornes/cert.pem
cle_ca_bornes = $PKI/ca-bornes/cle.pem
crl_bornes = $PKI/ca-bornes/crl.pem
registre = $W/registre
C
"$P" "$W/passerelle.conf" > "$W/passerelle.log" 2>&1 & PIDS+=($!)
sleep 1
echo "== jeton (registre) et ISO personnalisée (remaster)"
rm -f "$W/perso.iso"
"$R" "$W/passerelle.conf" jeton labo-7 | grep -E '^[0-9]+-[A-Z2-7]{26}$' | "$OUTIL" personnaliser "$ISO" "$W/perso.iso" labo-7
ko=0
OVMF=/usr/share/ovmf/OVMF.fd
qemu-img create -q -f qcow2 "$W/disque.qcow2" 16G
commun=(-enable-kvm -cpu host -m 4096 -smp 2 -bios "$OVMF" -vga std -display none
    -drive "file=$W/disque.qcow2,if=none,id=disque" -device "virtio-blk-pci,drive=disque,bootindex=1"
    -device qemu-xhci)
echo "== installation (sans carte réseau)"
xorriso -osirrox on -indev "$W/perso.iso" -extract /install.amd/vmlinuz "$W/vmlinuz" \
    -extract /install.amd/initrd.gz "$W/initrd.gz" -extract /boot/grub/grub.cfg "$W/grub.cfg" >/dev/null 2>&1
params=$(awk '$1 == "linux" { $1 = ""; $2 = ""; print; exit }' "$W/grub.cfg")
params=${params/locale=fr_FR.UTF-8/locale=en_US.UTF-8}
timeout 20m qemu-system-x86_64 "${commun[@]}" -nic none -no-reboot -serial "file:$W/installation.log" \
    -kernel "$W/vmlinuz" -initrd "$W/initrd.gz" -append "${params/---/console=ttyS0,115200 ---}" \
    -drive "if=none,id=cle,format=raw,readonly=on,file=$W/perso.iso" -device "usb-storage,drive=cle" \
    || { echo "ÉCHEC : installation interrompue" >&2; tail -c 3000 "$W/installation.log"; exit 1; }
# L'ISO personnalisée est détruite après usage (comme le prévoit la procédure).
shred -u "$W/perso.iso"
echo "== premier démarrage (réseau QEMU user, DHCP), AUCUNE saisie"
qemu-system-x86_64 "${commun[@]}" -nic user,model=virtio-net-pci -serial "file:$W/demarrage.log" \
    -monitor "unix:$W/mon.sock,server,nowait" &
VM=$!; PIDS+=("$VM")
ID=''
for _ in $(seq 60); do
    "$R" "$W/passerelle.conf" demandes > "$W/demandes.txt" || true
    ID=$(awk '/^demande /{print $2; exit}' "$W/demandes.txt")
    [ -z "$ID" ] || break
    sleep 10
done
if [ -z "$ID" ]; then
    echo "ÉCHEC : aucune demande reçue de la borne en 10 min" >&2; ko=1
else
    cat "$W/demandes.txt"
    if grep -q 'labo-7' "$W/demandes.txt"; then echo "OK : demande déposée sans saisie, site du jeton (labo-7)"; else echo "ÉCHEC : site" >&2; ko=1; fi
    EMPREINTE=$(sed -n 's/^  empreinte  //p' "$W/demandes.txt" | tr -d ' ')
    "$R" "$W/passerelle.conf" valider "$ID" "$EMPREINTE" borne-perso | tee "$W/validation.txt"
    vu=0
    for _ in $(seq 30); do
        "$R" "$W/passerelle.conf" supervision > "$W/supervision.txt" || true
        if grep -q 'active' "$W/supervision.txt" && ! grep -q 'vue=jamais' "$W/supervision.txt"; then vu=1; break; fi
        sleep 10
    done
    cat "$W/supervision.txt"
    if [ "$vu" = 1 ]; then echo "OK : battement de la borne visible dans la supervision"; else echo "ÉCHEC : aucun battement" >&2; ko=1; fi
fi
echo system_powerdown | socat - "UNIX-CONNECT:$W/mon.sock" >/dev/null 2>&1 || true
for _ in $(seq 60); do kill -0 "$VM" 2>/dev/null || break; sleep 2; done
kill "$VM" 2>/dev/null || true
echo "== inspection du disque installé (lecture seule)"
qemu-nbd -r -c "$NBD" "$W/disque.qcow2"; sleep 2
mkdir -p "$W/rw"; mount -o ro,noload "$(lsblk -lnpo NAME,FSTYPE "$NBD" | awk '$2 == "ext4" { print $1; exit }')" "$W/rw"
if [ -e "$W/rw/var/lib/barbacane-agent/jeton" ]; then echo "ÉCHEC : jeton encore sur le disque" >&2; ko=1; else echo "OK : jeton supprimé du disque après la réponse du serveur"; fi
if [ -s "$W/rw/var/lib/barbacane-agent/chaine.pem" ]; then echo "OK : certificat installé"; else echo "ÉCHEC : certificat absent" >&2; ko=1; fi
echo "QEMU PERSONNALISÉE FIN $ko"
exit $ko
