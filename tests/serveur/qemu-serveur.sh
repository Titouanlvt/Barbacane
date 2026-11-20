#!/bin/bash
# shellcheck disable=SC2015,SC2054 # « test && ok || echec » : ok ne peut pas échouer ; virgules = options QEMU
# Installe l'ISO du SERVEUR Barbacane dans une machine virtuelle UEFI avec un TPM 2.0 logiciel
# (swtpm, marqué comme tel dans les preuves, D9), démarre le système installé, puis vérifie :
#   disque chiffré (LUKS2 AES-XTS 512 bits, jetons TPM2 et secours, phrase d'installation effacée),
#   déverrouillage par le TPM seul (et refus sans TPM), pare-feu en liste blanche (vu de l'intérieur
#   ET de l'extérieur), aucune route par défaut, services démarrés (dont la passerelle dans Podman
#   sans root), aucun paquet interdit, chrony sans source externe, journal persistant.
#
#   tests/serveur/qemu-serveur.sh ISO DOSSIER [PKI]
#     ISO    construite pour ce banc :
#            serveur/iso/build-iso-serveur.sh --ip-bornes 10.0.2.15/24 --ip-admin 10.0.3.15/24 \
#              --pki-test PKI --hache-admin FICHIER
#     PKI    dossier de serveur/pki/racine-test.sh (certificat de borne pour l'essai mTLS) ; sans lui,
#            la passerelle doit être « en attente de PKI » (condition non remplie, pas d'échec).
# Prérequis (root) : qemu-system-x86, ovmf, qemu-utils, swtpm, cryptsetup, socat, openssl, xorriso, KVM.
set -euo pipefail
ISO="$(realpath "$1")"
W="$(realpath -m "$2")"
PKI="${3:+$(realpath "$3")}"
mkdir -p "$W"
ko=0
ok() { echo "OK : $*"; }
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
for o in qemu-system-x86_64 qemu-img qemu-nbd swtpm cryptsetup socat openssl xorriso; do
    command -v "$o" >/dev/null || { echo "prérequis absent : $o" >&2; exit 2; }
done
OVMF=/usr/share/ovmf/OVMF.fd
mon() { echo "$2" | socat - "UNIX-CONNECT:$W/$1" >/dev/null 2>&1 || true; }
# Texte lisible d'une console série (séquences d'échappement retirées).
lisible() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1" | tr -d '\r'; }

# ------------------------------------------------------------------ 0. ISO (sans l'installer)
echo "== contrôle de l'ISO"
xorriso -osirrox on -indev "$ISO" -extract /barbacane/preseed.cfg "$W/preseed.cfg" \
    -extract /barbacane/serveur.conf "$W/serveur.conf" -extract /install.amd/vmlinuz "$W/vmlinuz" \
    -extract /install.amd/initrd.gz "$W/initrd.gz" -extract /boot/grub/grub.cfg "$W/grub.cfg" >/dev/null 2>&1
xorriso -osirrox on -indev "$ISO" -extract /barbacane/fichiers.tar "$W/fichiers.tar" >/dev/null 2>&1
tar -xf "$W/fichiers.tar" -C "$W" ./usr/share/barbacane-serveur/paquets-interdits
INTERDITS="$W/usr/share/barbacane-serveur/paquets-interdits"
xorriso -indev "$ISO" -find /barbacane/debs -name '*.deb' 2>/dev/null | tr -d "'" | sed 's|.*/||; s|_.*||' | sort -u > "$W/debs.txt"
n=$(wc -l < "$W/debs.txt")
[ "$n" -gt 50 ] || { echo "ÉCHEC : liste des paquets de l'ISO vide ($n)" >&2; exit 1; }
if grep -xFf "$INTERDITS" "$W/debs.txt"; then echec "paquet interdit dans l'ISO"; else ok "ISO : $n paquets, aucun interdit"; fi
grep -q '^d-i netcfg/enable boolean false' "$W/preseed.cfg" && ok "preseed : aucun réseau à l'installation" || echec "preseed : réseau actif"
grep -q '^d-i partman-auto/method string crypto' "$W/preseed.cfg" && grep -q '^d-i partman-crypto/keysize string 512' "$W/preseed.cfg" \
    && ok "preseed : disque chiffré, clé de 512 bits (AES-256-XTS)" || echec "preseed : chiffrement du disque absent"
PHRASE=$(sed -n 's/^d-i partman-crypto\/passphrase password //p' "$W/preseed.cfg")
grep -q "^IP_BORNES='10.0.2.15/24'" "$W/serveur.conf" && grep -q "^IP_ADMIN='10.0.3.15/24'" "$W/serveur.conf" \
    || { echo "ISO non construite pour ce banc (--ip-bornes 10.0.2.15/24 --ip-admin 10.0.3.15/24)" >&2; exit 2; }
IF_BORNES=$(sed -n "s/^IF_BORNES='\(.*\)'/\1/p" "$W/serveur.conf")
IF_ADMIN=$(sed -n "s/^IF_ADMIN='\(.*\)'/\1/p" "$W/serveur.conf")
[ "$IF_BORNES" = enp0s8 ] && [ "$IF_ADMIN" = enp0s9 ] || { echo "interfaces attendues : enp0s8 (bornes), enp0s9 (admin)" >&2; exit 2; }

# ------------------------------------------------------------------ machine virtuelle
rm -rf "$W/tpm"; mkdir -p "$W/tpm"
qemu-img create -q -f qcow2 "$W/disque.qcow2" 24G
tpm() { # démarre swtpm pour UNE exécution de QEMU (il s'arrête à la déconnexion)
    rm -f "$W/swtpm.sock"
    swtpm socket --tpm2 --tpmstate "dir=$W/tpm" --ctrl "type=unixio,path=$W/swtpm.sock" --terminate \
        --log "file=$W/swtpm.log" &
    for _ in $(seq 50); do [ -S "$W/swtpm.sock" ] && return 0; sleep 0.1; done
    echo "swtpm n'a pas démarré" >&2; exit 1
}
AVEC_TPM=(-chardev "socket,id=chrtpm,path=$W/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
# Deux réseaux isolés (restrict=on : aucune sortie possible) ; interfaces enp0s8 (bornes), enp0s9 (admin).
commun=(-enable-kvm -cpu host -m 4096 -smp 2 -bios "$OVMF" -vga std -display none
    -drive "file=$W/disque.qcow2,if=none,id=disque" -device "virtio-blk-pci,drive=disque,bootindex=1"
    -netdev user,id=nb,restrict=on,net=10.0.2.0/24 -device virtio-net-pci,netdev=nb,addr=0x8
    -netdev user,id=na,restrict=on,net=10.0.3.0/24 -device virtio-net-pci,netdev=na,addr=0x9
    -device qemu-xhci)

# ------------------------------------------------------------------ 1. installation
echo "== installation (sans intervention, TPM logiciel swtpm)"
params=$(awk '$1 == "linux" { $1 = ""; $2 = ""; print; exit }' "$W/grub.cfg")
params=${params/locale=fr_FR.UTF-8/locale=en_US.UTF-8}
# Console série pour l'installateur ET (paramètres après « --- », recopiés par l'installateur) pour
# le système installé : l'état du serveur y est lu.
params=${params/---/console=ttyS0,115200 --- console=tty0 console=ttyS0,115200}
tpm
debut=$(date +%s)
timeout 40m qemu-system-x86_64 "${commun[@]}" "${AVEC_TPM[@]}" -no-reboot -serial "file:$W/installation.log" \
    -kernel "$W/vmlinuz" -initrd "$W/initrd.gz" -append "$params" \
    -drive "if=none,id=cle,format=raw,readonly=on,file=$ISO" -device "usb-storage,drive=cle" \
    -monitor "unix:$W/mon-install.sock,server,nowait" &
PID=$!
while kill -0 $PID 2>/dev/null; do sleep 60; mon mon-install.sock "screendump $W/installateur.ppm"; done
if ! wait $PID; then
    echo "ÉCHEC : installation interrompue, fin de la console :" >&2
    lisible "$W/installation.log" | grep -v '^\s*$' | awk '!vu[$0]++' | tail -n 60
    exit 1
fi
echo "installation : $(( ($(date +%s) - debut) / 60 )) min"
if lisible "$W/installation.log" | grep -q 'barbacane-serveur : fin d.installation : terminée'; then
    ok "installation terminée (fin-installation-serveur.sh jusqu'au bout)"
else
    echec "fin d'installation du serveur non terminée"; lisible "$W/installation.log" | grep 'barbacane-serveur' | tail -n 20
fi

# ------------------------------------------------------------------ 2. démarrage avec le TPM
echo "== premier démarrage (déverrouillage par le TPM)"
tpm
qemu-system-x86_64 "${commun[@]}" "${AVEC_TPM[@]}" -serial "file:$W/demarrage.log" \
    -monitor "unix:$W/mon.sock,server,nowait" &
PID=$!
lu=0
for _ in $(seq 120); do
    sleep 5
    if lisible "$W/demarrage.log" | grep -q '=== BARBACANE-ETAT FIN'; then lu=1; break; fi
    kill -0 $PID 2>/dev/null || break
done
mon mon.sock "screendump $W/ecran.ppm"
lisible "$W/demarrage.log" | sed -n '/=== BARBACANE-ETAT DEBUT/,/=== BARBACANE-ETAT FIN/p' > "$W/etat.txt"
if [ "$lu" = 1 ]; then
    ok "démarré sans phrase de passe (TPM) : état du serveur lu sur la console"
else
    echec "état du serveur jamais affiché (déverrouillage TPM ou démarrage en échec)"
    lisible "$W/demarrage.log" | grep -v '^\s*$' | tail -n 40
fi
section() { awk -v s="--- $1" '$0 == s { p = 1; next } /^--- / { p = 0 } /^=== / { p = 0 } p' "$W/etat.txt"; }

# Vu de l'extérieur : seul le port de la passerelle répond, et seulement sur l'interface « bornes ».
PORT=$(section pare-feu | sed -n "s/.*iifname \"$IF_BORNES\" ip daddr 10.0.2.15 tcp dport \([0-9]*\) ct state new accept.*/\1/p" | head -1)
if [ -n "$PORT" ] && [ "$PORT" -ge 20000 ] && [ "$PORT" -le 60000 ]; then ok "port de la passerelle tiré à l'installation : $PORT (D4)"
else echec "port de la passerelle introuvable dans le pare-feu ($PORT)"; PORT=1; fi
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47001-10.0.2.15:$PORT"
mon mon.sock "hostfwd_add na tcp:127.0.0.1:47002-10.0.3.15:$PORT"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47003-10.0.2.15:443"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47004-10.0.2.15:22"
essai_tls() { # port [options openssl] → sortie du client
    { printf 'GET /sante HTTP/1.1\r\nHost: serveur\r\nConnection: close\r\n\r\n'; sleep 3; } \
        | timeout 15 openssl s_client -connect "127.0.0.1:$1" -tls1_3 -quiet "${@:2}" 2>&1 || true
}
if [ -n "$PKI" ]; then
    r=$(essai_tls 47001 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" -CAfile "$PKI/racine/cert.pem")
    if grep -q '"etat":"ok"' <<<"$r"; then ok "passerelle joignable depuis le réseau des bornes, borne mTLS acceptée : $(grep -o '{.*}' <<<"$r")"
    else echec "passerelle : borne valide non servie : $(tail -n 3 <<<"$r")"; fi
    r=$(essai_tls 47001 -CAfile "$PKI/racine/cert.pem")
    if grep -q '"etat":"ok"' <<<"$r"; then echec "passerelle : client SANS certificat servi"; else ok "passerelle : client sans certificat refusé"; fi
    r=$(essai_tls 47002 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" -CAfile "$PKI/racine/cert.pem")
    if grep -q '"etat":"ok"' <<<"$r"; then echec "passerelle joignable depuis le réseau d'ADMINISTRATION"; else ok "passerelle injoignable depuis le réseau d'administration"; fi
fi
# 443 et 22 sur l'interface bornes : filtrés (aucun octet en retour, même à une requête).
for p in 47003 47004; do
    n=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 6; } | timeout 10 socat - "TCP:127.0.0.1:$p" 2>/dev/null | wc -c)
    [ "$n" = 0 ] && ok "port redirigé $p (443/22 sur l'interface bornes) : aucune réponse" || echec "port $p : $n octets reçus"
done
sleep 2
mon mon.sock system_powerdown
for _ in $(seq 60); do kill -0 $PID 2>/dev/null || break; sleep 2; done
kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true

# ------------------------------------------------------------------ 3. état vu de l'intérieur
echo "== état du serveur (console)"
cat "$W/etat.txt"
# Disque : volume racine chiffré, AES-XTS 512 bits
section disque | grep -q 'cipher: *aes-xts-plain64' && section disque | grep -q 'keysize: *512 bits' \
    && ok "racine sur volume ouvert aes-xts-plain64, 512 bits" || echec "volume chiffré : algorithme ou taille inattendus"
section disque | grep -q 'type: *LUKS2' && ok "volume LUKS2" || echec "volume non LUKS2"
# Routes
if section routes | grep -q '^default'; then echec "route par défaut présente"; else ok "aucune route par défaut : $(section routes | tr '\n' ';')"; fi
# Pare-feu : trois chaînes à politique drop ; aucune acceptation hors liste blanche
nft=$(section pare-feu)
for ch in entree transit sortie; do
    awk -v c="chain $ch" '$0 ~ c { p = 1 } p && /policy/ { print; exit }' <<<"$nft" | grep -q 'policy drop' \
        && ok "pare-feu : chaîne $ch, politique drop" || echec "pare-feu : chaîne $ch sans politique drop"
done
autorises=$(grep -E '\baccept\b' <<<"$nft" | sed 's/^[[:space:]]*//' | sort)
attendu=$(printf '%s\n' 'ct state established,related accept' 'ct state established,related accept' 'iif "lo" accept' \
    "iifname \"$IF_ADMIN\" tcp dport 443 ct state new accept" \
    "iifname \"$IF_BORNES\" ip daddr 10.0.2.15 tcp dport $PORT ct state new accept" 'oif "lo" accept' | sort)
[ "$autorises" = "$attendu" ] && ok "pare-feu : 6 règles d'acceptation, toutes attendues" \
    || { echec "pare-feu : règles d'acceptation inattendues"; diff <(echo "$attendu") <(echo "$autorises") || true; }
grep -qE 'udp dport 123|dport 53' <<<"$nft" && echec "pare-feu : NTP ou DNS sortant autorisé"
# Écoute : passerelle (relayée par pasta) seulement sur l'adresse « bornes » ; rien d'autre que la boucle locale
ecoute=$(section ecoute)
autres=$(grep -vE '^(127\.|\[::1\])' <<<"$ecoute" | grep -v "^10.0.2.15:$PORT$" || true)
[ -z "$autres" ] && ok "écoute réseau : $(tr '\n' ' ' <<<"$ecoute")" || echec "ports en écoute inattendus : $autres"
# Heure
h=$(section heure)
if grep -qE '^[[:space:]]*(server|pool|peer)' <<<"$h"; then echec "chrony : source réseau configurée"; else ok "chrony : aucune source externe configurée"; fi
grep -q 'Number of sources = 0\|^MS Name' <<<"$h" && ! grep -qE '^\^|^=' <<<"$h" \
    && ok "chrony : aucune source active ($(grep -m1 'Stratum' <<<"$h" | tr -s ' '))" || echec "chrony : sources actives : $h"
# Services
s=$(section services)
for u in nftables chrony systemd-networkd systemd-journald auditd; do
    grep -q "^$u active$" <<<"$s" && ok "service $u actif" || echec "service $u : $(grep "^$u " <<<"$s")"
done
grep -q '^user@[0-9]* active$' <<<"$s" && ok "gestionnaire systemd de barbacane-svc actif (linger)" || echec "session de barbacane-svc inactive"
grep -q '^utilisateur:barbacane-images active' <<<"$s" && ok "images chargées depuis l'ISO" || echec "images non chargées : $(grep images <<<"$s")"
if [ -n "$PKI" ]; then
    grep -q '^utilisateur:barbacane-passerelle active' <<<"$s" && ok "passerelle active (Podman sans root)" || echec "passerelle : $(grep passerelle <<<"$s")"
    c=$(section conteneurs)
    grep -q 'readonly=true privileged=false caps=\[\]' <<<"$c" && ok "conteneur : racine en lecture seule, non privilégié, aucune capacité" \
        || echec "conteneur : options de confinement inattendues : $c"
    u=$(section processus-passerelle | awk 'NR == 1 { print $1 }')
    [ -n "$u" ] && [ "$u" != root ] && ok "processus de la passerelle exécuté par « $u » (pas root)" || echec "processus de la passerelle : « $u »"
else
    grep -q '^utilisateur:barbacane-passerelle inactive condition=no' <<<"$s" && ok "passerelle en attente de PKI (sans échec)" \
        || echec "passerelle sans PKI : $(grep passerelle <<<"$s")"
fi
grep -q '^ALERTE : paquet interdit' "$W/etat.txt" && echec "paquet interdit installé" || ok "aucun paquet interdit installé ($(section paquets | head -1))"
section journal | grep -q '/var/log/journal/' && ok "journal persistant (/var/log/journal)" || echec "journal non persistant"
grep -q '=== BARBACANE-ETAT FIN alertes=0' "$W/etat.txt" && ok "état : aucune alerte" || echec "état : alertes"

# ------------------------------------------------------------------ 4. sans TPM : pas de déverrouillage
echo "== démarrage SANS TPM (doit s'arrêter sur la demande de clé)"
qemu-system-x86_64 "${commun[@]}" -serial "file:$W/sans-tpm.log" -monitor "unix:$W/mon2.sock,server,nowait" &
PID=$!
demande=0
for _ in $(seq 36); do
    sleep 5
    lisible "$W/sans-tpm.log" | grep -qi 'passphrase\|recovery key\|phrase de passe' && { demande=1; break; }
done
sleep 20
lisible "$W/sans-tpm.log" | grep -q 'BARBACANE-ETAT' && echec "le serveur a démarré SANS TPM" \
    || { [ "$demande" = 1 ] && ok "sans TPM : démarrage bloqué à la demande de clé" || echec "sans TPM : ni démarrage ni demande de clé vue"; }
kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true

# ------------------------------------------------------------------ 5. disque vu de l'extérieur
echo "== en-tête LUKS du disque (sans clé)"
modprobe nbd max_part=8
qemu-nbd -r -c /dev/nbd0 "$W/disque.qcow2"
trap 'qemu-nbd -d /dev/nbd0 >/dev/null 2>&1 || true' EXIT
sleep 2
luks=$(lsblk -lnpo NAME,FSTYPE /dev/nbd0 | awk '$2 == "crypto_LUKS" { print $1; exit }')
if [ -z "$luks" ]; then
    echec "aucune partition LUKS sur le disque"
else
    cryptsetup luksDump "$luks" > "$W/luksdump.txt"
    grep -q '^Version: *2' "$W/luksdump.txt" && ok "en-tête LUKS2" || echec "en-tête non LUKS2"
    grep -q 'aes-xts-plain64' "$W/luksdump.txt" && grep -q 'Key: *512 bits' "$W/luksdump.txt" \
        && ok "AES-XTS, clé de 512 bits" || echec "chiffrement inattendu"
    grep -q 'systemd-tpm2' "$W/luksdump.txt" && ok "jeton systemd-tpm2 (PCR $(awk '/tpm2-hash-pcrs:/ { print $2; exit }' "$W/luksdump.txt"))" || echec "jeton TPM2 absent"
    grep -q 'systemd-recovery' "$W/luksdump.txt" && ok "jeton de clé de secours" || echec "clé de secours absente"
    n=$(grep -cE '^  [0-9]+: luks2' "$W/luksdump.txt")
    [ "$n" = 2 ] && ok "2 emplacements de clé (TPM + secours)" || echec "$n emplacements de clé (2 attendus)"
    if printf '%s' "$PHRASE" | cryptsetup open --test-passphrase --key-file=- "$luks" 2>/dev/null; then
        echec "la phrase de passe d'installation (présente dans l'ISO) ouvre ENCORE le disque"
    else
        ok "phrase de passe d'installation effacée du disque"
    fi
    n_ext4=$(lsblk -lnpo NAME,FSTYPE /dev/nbd0 | awk '$2 == "ext4"' | wc -l)
    [ "$n_ext4" = 1 ] && ok "une seule partition en clair (/boot)" || echec "$n_ext4 partitions ext4 en clair"
fi
echo "TPM : logiciel (swtpm $(swtpm --version 2>&1 | head -1 | awk '{ print $NF }')), banc de test uniquement"
[ "$ko" = 0 ] && echo "SERVEUR QEMU : OK"
exit "$ko"
