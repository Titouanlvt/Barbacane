#!/bin/bash
# Garde-fou du profil hors ligne (conception suite §10, décision D12) : ouvre l'ISO de la borne
# hors ligne SANS l'installer et échoue si elle contient
#   - l'agent réseau de la suite (barbacane-agent) ou tout fichier « agent » Barbacane ;
#   - un paquet réseau (démon, client de configuration, accès distant, découverte) ;
#   - une règle de pare-feu autorisant une sortie autre que la boucle locale.
# Usage : tests/iso/hors-ligne.sh barbacane.iso   (prérequis : xorriso, dpkg-deb)
set -euo pipefail
ISO=$(realpath "$1")
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
ko=0
echec() { echo "ÉCHEC : $*" >&2; ko=1; }

# Paquets que l'installation pose sur la borne : /barbacane/debs (fin-installation.sh les installe
# tous). Le pool de l'ISO netinst Debian (/pool) n'est pas modifié ; il n'est utilisé que pour le
# système de base, sans tasksel ni réseau (vérifié plus bas dans le preseed) : on n'y interdit rien,
# et tests/iso/qemu.sh contrôle en plus les paquets réellement installés.
xorriso -indev "$ISO" -find /barbacane/debs -name '*.deb' 2>/dev/null | tr -d "'" | sed 's|.*/||' | sort -u > "$W/debs.txt"
n=$(wc -l < "$W/debs.txt")
[ "$n" -gt 100 ] || { echo "ÉCHEC : liste des paquets de l'ISO vide ou incomplète ($n)" >&2; exit 1; }
echo "paquets installés par Barbacane : $n"

# Paquets réseau interdits sur la borne hors ligne (même liste dans tests/iso/qemu.sh).
INTERDITS='barbacane-agent
openssh-server
openssh-client
dropbear
network-manager
connman
wpasupplicant
iwd
avahi-daemon
avahi-autoipd
samba
nfs-common
rpcbind
chrony
ntpsec
ntp
openntpd
cups-daemon
telnet
rsh-server
xrdp
x11vnc
tigervnc-standalone-server
wireguard-tools
openvpn
strongswan
podman
docker.io'
while read -r p; do
    [ -n "$p" ] || continue
    if grep -q "^${p}_" "$W/debs.txt"; then echec "paquet réseau interdit dans l'ISO hors ligne : $p"; fi
done <<< "$INTERDITS"

# Aucun fichier « agent » dans les paquets Barbacane (binaire, unité systemd, configuration).
for d in barbacane usbsas-server usbsas-hid; do
    f=$(grep "^${d}_" "$W/debs.txt" | head -1) || true
    [ -n "$f" ] || { echec "paquet $d absent de l'ISO"; continue; }
    chemin=$(xorriso -indev "$ISO" -find / -name "$f" 2>/dev/null | tr -d "'" | head -1)
    xorriso -osirrox on -indev "$ISO" -extract "$chemin" "$W/$f" >/dev/null 2>&1
    dpkg-deb -c "$W/$f" | awk '{print $6}' > "$W/$d.fichiers"
    if grep -Ei 'agent|/etc/systemd/network|/etc/network/interfaces\.d|NetworkManager' "$W/$d.fichiers"; then
        echec "le paquet $d contient un fichier réseau ou « agent »"
    fi
    if [ "$d" = barbacane ]; then
        mkdir -p "$W/b"; dpkg-deb -x "$W/$f" "$W/b"
        nft=$(find "$W/b" -name 'nftables.conf' | head -1)
        [ -n "$nft" ] || { echec "nftables.conf absent du paquet barbacane"; continue; }
        # Politique de sortie : drop ; seule règle acceptée : la boucle locale.
        sed -n '/chain output/,/}/p' "$nft" > "$W/output.txt"
        grep -q 'policy drop' "$W/output.txt" || echec "nftables : politique de sortie différente de drop"
        if grep -E '\baccept\b' "$W/output.txt" | grep -v 'oif "lo" accept' | grep -q .; then
            echec "nftables : règle de sortie autorisant autre chose que la boucle locale"
        fi
        grep -Eq 'policy (accept)' "$nft" && echec "nftables : une chaîne a une politique accept"
    fi
done

# Preseed : réseau désactivé, aucune tâche ni paquet supplémentaire tirés du pool netinst.
xorriso -osirrox on -indev "$ISO" -extract /barbacane/preseed.cfg "$W/preseed.cfg" >/dev/null 2>&1
grep -q '^d-i netcfg/enable boolean false' "$W/preseed.cfg" || echec "preseed : réseau non désactivé (netcfg/enable)"
grep -q '^d-i pkgsel/run_tasksel boolean false' "$W/preseed.cfg" || echec "preseed : tasksel actif"
if grep -E '^d-i pkgsel/include' "$W/preseed.cfg" | grep -q .; then echec "preseed : pkgsel/include tire des paquets du pool"; fi

[ "$ko" = 0 ] && echo "OK : ISO hors ligne sans agent, sans paquet réseau, sortie bloquée (boucle locale seule)"
exit "$ko"
