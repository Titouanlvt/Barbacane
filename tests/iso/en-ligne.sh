#!/bin/bash
# Garde-fou du profil EN LIGNE (conception suite §10, D12) : ouvre l'ISO de la borne en ligne
# SANS l'installer et échoue si
#   - l'agent (paquet barbacane-agent, binaire, service durci) est absent ;
#   - un autre paquet réseau est présent (même liste que tests/iso/hors-ligne.sh, sauf l'agent) ;
#   - le pare-feu accepte une connexion entrante, ou une sortie autre que adresse:ports du
#     serveur (pour le seul compte barbacane-agent ; DHCP pour systemd-network si --reseau dhcp) ;
#   - la CA épinglée ne correspond pas à l'empreinte inscrite dans la configuration de l'agent ;
#   - l'installation elle-même utilise le réseau (preseed).
# Usage : tests/iso/en-ligne.sh barbacane-en-ligne.iso SERVEUR PORT_ENROLEMENT PORT_SERVICE
#   (prérequis : xorriso, dpkg-deb, openssl ; nft en root pour la vérification de syntaxe)
set -euo pipefail
[ $# -eq 4 ] || { echo "usage : $0 ISO SERVEUR PORT_ENROLEMENT PORT_SERVICE" >&2; exit 2; }
ISO=$(realpath "$1") SERVEUR=$2 PE=$3 PS=$4
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
ko=0
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
extraire() { xorriso -osirrox on -indev "$ISO" -extract "$1" "$2" >/dev/null 2>&1; }

xorriso -indev "$ISO" -find /barbacane/debs -name '*.deb' 2>/dev/null | tr -d "'" | sed 's|.*/||' | sort -u > "$W/debs.txt"
n=$(wc -l < "$W/debs.txt")
[ "$n" -gt 100 ] || { echo "ÉCHEC : liste des paquets de l'ISO vide ou incomplète ($n)" >&2; exit 1; }
echo "paquets installés par Barbacane : $n"

# 1. L'agent et son service durci
f=$(grep '^barbacane-agent_' "$W/debs.txt" | head -1) || true
if [ -z "$f" ]; then
    echec "paquet barbacane-agent absent de l'ISO en ligne"
else
    extraire "/barbacane/debs/$f" "$W/$f"
    mkdir -p "$W/agent"; dpkg-deb -x "$W/$f" "$W/agent"
    [ -x "$W/agent/usr/bin/barbacane-agent" ] || echec "binaire barbacane-agent absent du paquet"
    u="$W/agent/usr/lib/systemd/system/barbacane-agent.service"
    if [ -f "$u" ]; then
        for l in 'User=barbacane-agent' 'IPAddressDeny=any' 'CapabilityBoundingSet=' 'NoNewPrivileges=yes' \
                 'ProtectSystem=strict' 'RestrictAddressFamilies=AF_INET AF_UNIX' 'PrivateDevices=yes'; do
            grep -qx "$l" "$u" || echec "service barbacane-agent : « $l » absent"
        done
        if grep -E '^(AmbientCapabilities|CapabilityBoundingSet)=.+' "$u" | grep -q .; then echec "service barbacane-agent : capacité accordée"; fi
    else
        echec "unité barbacane-agent.service absente du paquet"
    fi
fi

# 2. Aucun autre paquet réseau (démon, client de configuration, accès distant, découverte)
INTERDITS='openssh-server openssh-client dropbear network-manager connman wpasupplicant iwd avahi-daemon
avahi-autoipd samba nfs-common rpcbind chrony ntpsec ntp openntpd cups-daemon telnet rsh-server xrdp x11vnc
tigervnc-standalone-server wireguard-tools openvpn strongswan podman docker.io isc-dhcp-client dhcpcd-base'
for p in $INTERDITS; do
    if grep -q "^${p}_" "$W/debs.txt"; then echec "paquet réseau interdit dans l'ISO en ligne : $p"; fi
done

# 3. Fichiers propres au profil en ligne
for x in agent.toml ca-serveur.pem nftables.conf 10-barbacane.network serveur.conf fin-en-ligne.sh; do
    extraire "/barbacane/en-ligne/$x" "$W/$x" || true
    [ -s "$W/$x" ] || echec "/barbacane/en-ligne/$x absent"
done
[ "$ko" = 0 ] || exit 1

# 3a. Pare-feu : rien en entrée (sauf réponses du serveur), sortie vers le serveur seul
nft="$W/nftables.conf"
for c in input forward output; do
    sed -n "/chain $c {/,/}/p" "$nft" > "$W/$c.txt"
    grep -q 'policy drop' "$W/$c.txt" || echec "nftables : chaîne $c sans politique drop"
done
grep -Eq 'policy accept' "$nft" && echec "nftables : une chaîne a une politique accept"
grep -q 'accept' "$W/forward.txt" && echec "nftables : transfert accepté"
sp="ip saddr $SERVEUR tcp sport { $PE, $PS } ct state established accept"
dhcp_in="udp sport 67 udp dport 68 ct state established accept"
grep -E '\baccept\b' "$W/input.txt" | sed 's/^ *//' | while read -r l; do
    case "$l" in
        'iif "lo" accept'|"$sp"|"$dhcp_in") ;;
        *) echo "ÉCHEC : nftables : entrée acceptée hors réponses du serveur : $l" >&2; echo x >> "$W/ko" ;;
    esac
done
grep -q 'ct state new' "$W/input.txt" && echec "nftables : connexion entrante acceptée"
dp="ip daddr $SERVEUR tcp dport { $PE, $PS } meta skuid \"barbacane-agent\" ct state { new, established } accept"
dhcp_out='udp sport 68 udp dport 67 meta skuid "systemd-network" accept'
grep -E '\baccept\b' "$W/output.txt" | sed 's/^ *//' | while read -r l; do
    case "$l" in
        'oif "lo" accept'|"$dp"|"$dhcp_out") ;;
        *) echo "ÉCHEC : nftables : sortie autorisée hors serveur : $l" >&2; echo x >> "$W/ko" ;;
    esac
done
[ -e "$W/ko" ] && ko=1
grep -qF "$dp" "$W/output.txt" || echec "nftables : sortie vers $SERVEUR:{$PE,$PS} absente"
if grep -qF "$dhcp_out" "$W/output.txt"; then
    grep -qx 'DHCP=ipv4' "$W/10-barbacane.network" || echec "exception DHCP du pare-feu sans DHCP configuré"
fi
# Syntaxe (root) : comptes inexistants ici remplacés par root pour la seule vérification
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null; then
    sed -e 's/skuid "[a-z-]*"/skuid 0/' -e '/^flush ruleset/d' "$nft" > "$W/nft-syntaxe.conf"
    nft -c -f "$W/nft-syntaxe.conf" || echec "nftables : syntaxe refusée par nft -c"
fi

# 3b. Service restreint à l'adresse du serveur
if [ "$(grep -c '^IPAddressAllow=' "$W/serveur.conf")" != 1 ] || ! grep -qx "IPAddressAllow=$SERVEUR/32" "$W/serveur.conf"; then
    echec "serveur.conf : IPAddressAllow=$SERVEUR/32 attendu, seul"
fi

# 3c. CA épinglée = empreinte de la configuration ; adresse et ports cohérents
[ "$(grep -c -- '-----BEGIN CERTIFICATE-----' "$W/ca-serveur.pem")" = 1 ] || echec "ca-serveur.pem : un seul certificat attendu"
grep -q 'PRIVATE KEY' "$W/ca-serveur.pem" && echec "ca-serveur.pem contient une clé privée"
e=$(openssl x509 -in "$W/ca-serveur.pem" -outform DER | sha256sum | cut -d' ' -f1)
grep -qx "empreinte_ca_serveur = \"$e\"" "$W/agent.toml" || echec "agent.toml : empreinte de la CA différente de ca-serveur.pem ($e)"
grep -qx "adresse = \"$SERVEUR\"" "$W/agent.toml" || echec "agent.toml : adresse du serveur différente de $SERVEUR"
grep -qx "port_enrolement = $PE" "$W/agent.toml" || echec "agent.toml : port d'enrôlement différent de $PE"
grep -qx "port_service = $PS" "$W/agent.toml" || echec "agent.toml : port de service différent de $PS"

# 3d. Réseau : IPv4 seul, aucune découverte
for l in 'LinkLocalAddressing=no' 'IPv6AcceptRA=no' 'LLDP=no' 'EmitLLDP=no'; do
    grep -qx "$l" "$W/10-barbacane.network" || echec "10-barbacane.network : « $l » absent"
done

# 4. Installation sans réseau ; étape en ligne après la fin d'installation commune
extraire /barbacane/preseed.cfg "$W/preseed.cfg"
grep -q '^d-i netcfg/enable boolean false' "$W/preseed.cfg" || echec "preseed : réseau actif pendant l'installation"
grep -q '^d-i pkgsel/run_tasksel boolean false' "$W/preseed.cfg" || echec "preseed : tasksel actif"
if grep -E '^d-i pkgsel/include' "$W/preseed.cfg" | grep -q .; then echec "preseed : pkgsel/include tire des paquets du pool"; fi
grep -qx 'd-i preseed/late_command string sh /cdrom/barbacane/fin-installation.sh && sh /cdrom/barbacane/en-ligne/fin-en-ligne.sh' "$W/preseed.cfg" \
    || echec "preseed : late_command en ligne attendu"

[ "$ko" = 0 ] && echo "OK : ISO en ligne avec l'agent durci ; rien en entrée ; sortie vers $SERVEUR:{$PE,$PS} seulement (agent)"
exit "$ko"
