#!/bin/bash
# Borne EN LIGNE dans QEMU, face à une passerelle de TEST lancée sur la machine hôte du test :
#   installation SANS carte réseau → jeton déposé sur le disque → premier démarrage avec réseau
#   QEMU « user » (la machine hôte est 10.0.2.2 vue de la borne, DHCP) → l'agent dépose sa
#   demande → validation par barbacane-registre → battement visible dans la supervision ;
#   depuis la borne, root lui-même ne peut joindre ni un autre port, ni le serveur hors agent.
# Usage : qemu-en-ligne.sh ISO_EN_LIGNE DOSSIER PKI PASSERELLE REGISTRE
#   ISO construite avec --serveur 10.0.2.2 --port-enrolement 43118 --port-service 43117 et la
#   CA serveur de PKI (serveur/pki/racine-test.sh). Root, KVM, qemu, ovmf, qemu-utils, socat.
set -euo pipefail
[ $# -eq 5 ] || { echo "usage : $0 ISO DOSSIER PKI PASSERELLE REGISTRE" >&2; exit 2; }
ISO="$(realpath "$1")" W="$(realpath -m "$2")" PKI="$(realpath "$3")" P="$(realpath "$4")" R="$(realpath "$5")"
PE=43118 PS=43117
mkdir -p "$W"
"$(dirname "$0")/en-ligne.sh" "$ISO" 10.0.2.2 $PE $PS
for p in $PE $PS; do ! ss -Htln "sport = :$p" | grep -q . || { echo "port $p déjà utilisé" >&2; exit 1; }; done
# Périphérique nbd libre (d'autres tests peuvent tourner en même temps)
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
OVMF=/usr/share/ovmf/OVMF.fd
qemu-img create -q -f qcow2 "$W/disque.qcow2" 16G
commun=(-enable-kvm -cpu host -m 4096 -smp 2 -bios "$OVMF" -vga std -display none
    -drive "file=$W/disque.qcow2,if=none,id=disque" -device "virtio-blk-pci,drive=disque,bootindex=1"
    -device qemu-xhci)

echo "== installation (sans carte réseau)"
xorriso -osirrox on -indev "$ISO" -extract /install.amd/vmlinuz "$W/vmlinuz" \
    -extract /install.amd/initrd.gz "$W/initrd.gz" -extract /boot/grub/grub.cfg "$W/grub.cfg" >/dev/null 2>&1
params=$(awk '$1 == "linux" { $1 = ""; $2 = ""; print; exit }' "$W/grub.cfg")
params=${params/locale=fr_FR.UTF-8/locale=en_US.UTF-8}
timeout 20m qemu-system-x86_64 "${commun[@]}" -nic none -no-reboot -serial "file:$W/installation.log" \
    -kernel "$W/vmlinuz" -initrd "$W/initrd.gz" -append "${params/---/console=ttyS0,115200 ---}" \
    -drive "if=none,id=cle,format=raw,readonly=on,file=$ISO" -device "usb-storage,drive=cle" \
    || { echo "ÉCHEC : installation interrompue" >&2; tail -c 3000 "$W/installation.log"; exit 1; }

echo "== passerelle de test, jeton déposé sur le disque, sonde (test uniquement)"
"$P" "$W/passerelle.conf" > "$W/passerelle.log" 2>&1 & PIDS+=($!)
sleep 1
JETON=$("$R" "$W/passerelle.conf" jeton site-1 | grep -E '^[0-9]+-[A-Z2-7]{26}$')
qemu-nbd -c "$NBD" "$W/disque.qcow2"; sleep 2
mkdir -p "$W/rw"
mount "$(lsblk -lnpo NAME,FSTYPE "$NBD" | awk '$2 == "ext4" { print $1; exit }')" "$W/rw"
uid=$(awk -F: '$1 == "barbacane-agent" { print $3 ":" $4 }' "$W/rw/etc/passwd")
[ -n "$uid" ] || { echo "ÉCHEC : compte barbacane-agent absent" >&2; exit 1; }
install -d -m 0700 -o "${uid%:*}" -g "${uid#*:}" "$W/rw/var/lib/barbacane-agent"
printf '%s\n' "$JETON" > "$W/rw/var/lib/barbacane-agent/jeton"
chown "$uid" "$W/rw/var/lib/barbacane-agent/jeton"; chmod 600 "$W/rw/var/lib/barbacane-agent/jeton"
cat > "$W/rw/etc/systemd/system/diag-en-ligne.service" <<'FIN'
[Service]
Type=simple
ExecStart=/bin/bash -c 'while :; do { date -u; systemctl is-active barbacane-agent nftables systemd-networkd; ip -4 -br addr; nft list ruleset; ss -tnp; cat /run/barbacane-agent/etat.json; ls -l /var/lib/barbacane-agent; systemctl show barbacane-agent -p IPAddressAllow -p IPAddressDeny -p User -p CapabilityBoundingSet; for c in "10.0.2.2/22" "10.0.2.2/43117" "10.0.2.3/53"; do if timeout 5 bash -c "echo > /dev/tcp/${c%%/*}/${c##*/}" 2>/dev/null; then echo "SORTIE root vers $c : OUVERTE"; else echo "SORTIE root vers $c : bloquée"; fi; done; journalctl -b -u barbacane-agent --no-pager | tail -n 20; } > /var/log/diag-en-ligne.tmp 2>&1; mv /var/log/diag-en-ligne.tmp /var/log/diag-en-ligne.txt; sleep 20; done'
[Install]
WantedBy=multi-user.target
FIN
ln -sf ../diag-en-ligne.service "$W/rw/etc/systemd/system/multi-user.target.wants/diag-en-ligne.service"
umount "$W/rw"; qemu-nbd -d "$NBD" >/dev/null; sleep 1

echo "== premier démarrage (réseau QEMU user, DHCP)"
qemu-system-x86_64 "${commun[@]}" -nic user,model=virtio-net-pci -serial "file:$W/demarrage.log" \
    -monitor "unix:$W/mon.sock,server,nowait" &
VM=$!; PIDS+=("$VM")
ko=0
ID='' EMPREINTE=''
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
    EMPREINTE=$(sed -n 's/^  empreinte  //p' "$W/demandes.txt" | tr -d ' ')
    # Au lab, l'empreinte « affichée par la borne » est relue après coup dans etat.json (sonde).
    "$R" "$W/passerelle.conf" valider "$ID" "$EMPREINTE" borne-qemu | tee "$W/validation.txt"
    vu=0
    for _ in $(seq 30); do
        "$R" "$W/passerelle.conf" supervision > "$W/supervision.txt" || true
        if grep -q 'active' "$W/supervision.txt" && ! grep -q 'vue=jamais' "$W/supervision.txt"; then vu=1; break; fi
        sleep 10
    done
    cat "$W/supervision.txt"
    if [ "$vu" = 1 ]; then echo "OK : battement de la borne visible dans la supervision"
    else echo "ÉCHEC : aucun battement de la borne" >&2; ko=1; fi
fi
sleep 30
echo "screendump $W/ecran.png -f png" | socat - "UNIX-CONNECT:$W/mon.sock" >/dev/null || true
sleep 2
echo system_powerdown | socat - "UNIX-CONNECT:$W/mon.sock" >/dev/null || true
for _ in $(seq 60); do kill -0 "$VM" 2>/dev/null || break; sleep 2; done
kill "$VM" 2>/dev/null || true

echo "== inspection du disque installé"
qemu-nbd -r -c "$NBD" "$W/disque.qcow2"; sleep 2
mount -o ro,noload "$(lsblk -lnpo NAME,FSTYPE "$NBD" | awk '$2 == "ext4" { print $1; exit }')" "$W/rw"
cp "$W/rw/var/log/diag-en-ligne.txt" "$W/diag-en-ligne.txt" || true
cat "$W/diag-en-ligne.txt" || true
d="$W/diag-en-ligne.txt"
if grep -q '"mode": "connectee"' "$d"; then echo "OK : agent connecté (etat.json)"; else echo "ÉCHEC : agent non connecté" >&2; ko=1; fi
for c in "10.0.2.2/22" "10.0.2.2/43117" "10.0.2.3/53"; do
    if grep -q "SORTIE root vers $c : bloquée" "$d"; then echo "OK : sortie root vers $c bloquée"
    else echo "ÉCHEC : sortie root vers $c non bloquée" >&2; ko=1; fi
done
if grep -q 'IPAddressAllow=10.0.2.2/32' "$d"; then echo "OK : service restreint à 10.0.2.2/32"; else echo "ÉCHEC : IPAddressAllow" >&2; ko=1; fi
if grep -qE '^-rw------- .* cle\.pem$' "$d"; then echo "OK : clé de la borne 0600"; else echo "ÉCHEC : clé de la borne" >&2; ko=1; fi
J=(journalctl -D "$W/rw/var/log/journal" --no-pager)
"${J[@]}" -o short -u barbacane-kiosk > "$W/kiosque.log" || true
n=$(grep -c "Started barbacane-kiosk.service" "$W/kiosque.log" || true)
if [ "$n" -ge 1 ] && [ "$n" -le 2 ]; then echo "OK : interface démarrée ($n)"; else echo "ÉCHEC : interface ($n démarrages)" >&2; ko=1; fi
exit $ko
