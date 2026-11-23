#!/bin/bash
# shellcheck disable=SC2015,SC2054 # « test && ok || echec » : ok ne peut pas échouer ; virgules = options QEMU
# Installe l'ISO du SERVEUR Barbacane dans une machine virtuelle UEFI avec un TPM 2.0 logiciel
# (swtpm, marqué comme tel dans les preuves, D9), démarre le système installé, puis vérifie :
#   disque chiffré (LUKS2 AES-XTS 512 bits, jetons TPM2 et secours, phrase d'installation effacée),
#   déverrouillage par le TPM seul (et refus sans TPM), pare-feu en liste blanche (vu de l'intérieur
#   ET de l'extérieur), aucune route par défaut, services démarrés (dont la passerelle dans Podman
#   sans root), aucun paquet interdit, chrony sans source externe, journal persistant.
#
#   tests/serveur/qemu-serveur.sh ISO DOSSIER [PKI [MDP_WEB]]
#     ISO    construite pour ce banc :
#            serveur/iso/build-iso-serveur.sh --if-bornes ens8 --ip-bornes 10.0.2.15/24 --if-admin ens9 --ip-admin 10.0.3.15/24 \
#              --pki-test PKI --hache-admin FICHIER --console-serie
#     PKI    dossier de serveur/pki/racine-test.sh --ip-serveur 10.0.3.15 (certificat de borne pour l'essai mTLS) ; sans lui,
#            la passerelle doit être « en attente de PKI » (condition non remplie, pas d'échec).
#     MDP_WEB fichier du mot de passe du compte web admin-01 (--mdp-web à la construction) : connexion
#            complète à l'interface web (sinon : page de connexion seulement).
#   MDP_ADMIN=FICHIER (v2.3.0) : mot de passe initial du compte d'administration système (--hache-admin
#            à la construction) : parcours « journal » (tests/serveur/qemu-journal.sh) avec la console
#            série : Syslog TLS/mTLS et en clair vers un collecteur de test, coupure et reprise,
#            conservation par double validation, horloge avancée, purges, vérification de la chaîne.
# Interface web : servie sur 10.0.3.15:443 (administration) avec le certificat admin-01 de TEST,
# refusée sans certificat, injoignable depuis le réseau des bornes et sur son port interne (8443).
# Prérequis (root) : qemu-system-x86, ovmf, qemu-utils, swtpm, cryptsetup, socat, openssl, xorriso, KVM.
set -euo pipefail
ISO="$(realpath "$1")"
W="$(realpath -m "$2")"
PKI="${3:+$(realpath "$3")}"
MDP_WEB="${4:+$(realpath "$4")}"
mkdir -p "$W"
ko=0
ok() { echo "OK : $*"; }
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
for o in qemu-system-x86_64 qemu-img qemu-nbd swtpm cryptsetup socat openssl xorriso curl mkfs.ext4; do
    command -v "$o" >/dev/null || { echo "prérequis absent : $o" >&2; exit 2; }
done
OVMF=/usr/share/ovmf/OVMF.fd
mon() { echo "$2" | socat - "UNIX-CONNECT:$W/$1" >/dev/null 2>&1 || true; }
# Texte lisible d'une console série (séquences d'échappement retirées).
lisible() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1" | tr -d '\r'; }

# ------------------------------------------------------------------ 0. ISO (sans l'installer)
echo "== contrôle de l'ISO"
xorriso -osirrox on -indev "$ISO" -extract /barbacane/preseed.cfg "$W/preseed.cfg" \
    -extract /barbacane/serveur.conf "$W/serveur.conf" -extract /boot/grub/grub.cfg "$W/grub.cfg" >/dev/null 2>&1
xorriso -osirrox on -indev "$ISO" -extract /barbacane/fichiers.tar "$W/fichiers.tar" >/dev/null 2>&1
tar -xf "$W/fichiers.tar" -C "$W" ./usr/share/barbacane-serveur/paquets-interdits
INTERDITS="$W/usr/share/barbacane-serveur/paquets-interdits"
xorriso -indev "$ISO" -find /barbacane/debs -name '*.deb' 2>/dev/null | tr -d "'" | sed 's|.*/||; s|_.*||' | sort -u > "$W/debs.txt"
n=$(wc -l < "$W/debs.txt")
[ "$n" -gt 50 ] || { echo "ÉCHEC : liste des paquets de l'ISO vide ($n)" >&2; exit 1; }
if grep -xFf "$INTERDITS" "$W/debs.txt"; then echec "paquet interdit dans l'ISO"; else ok "ISO : $n paquets, aucun interdit"; fi
grep -q '^d-i netcfg/enable boolean false' "$W/preseed.cfg" && ok "preseed : aucun réseau à l'installation" || echec "preseed : réseau actif"
grep -q '^d-i partman-auto/method string crypto' "$W/preseed.cfg" && grep -q '^d-i partman-crypto/keysize string 256' "$W/preseed.cfg" \
    && ok "preseed : disque chiffré, AES-256 (clé XTS de 512 bits : partman double 256)" || echec "preseed : chiffrement du disque absent"
PHRASE=$(sed -n 's/^d-i partman-crypto\/passphrase password //p' "$W/preseed.cfg")
grep -q "^IP_BORNES='10.0.2.15/24'" "$W/serveur.conf" && grep -q "^IP_ADMIN='10.0.3.15/24'" "$W/serveur.conf" \
    || { echo "ISO non construite pour ce banc (--ip-bornes 10.0.2.15/24 --ip-admin 10.0.3.15/24)" >&2; exit 2; }
IF_BORNES=$(sed -n "s/^IF_BORNES='\(.*\)'/\1/p" "$W/serveur.conf")
IF_ADMIN=$(sed -n "s/^IF_ADMIN='\(.*\)'/\1/p" "$W/serveur.conf")
# Machine QEMU « pc » : les cartes en 0x8 et 0x9 se nomment ens8 et ens9 (emplacement ACPI).
[ "$IF_BORNES" = ens8 ] && [ "$IF_ADMIN" = ens9 ] || { echo "interfaces attendues : ens8 (bornes), ens9 (admin)" >&2; exit 2; }

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
# Deux réseaux isolés (restrict=on : aucune sortie possible) ; interfaces ens8 (bornes), ens9 (admin).
commun=(-enable-kvm -cpu host -m 4096 -smp 2 -bios "$OVMF" -vga std -display none
    -drive "file=$W/disque.qcow2,if=none,id=disque" -device "virtio-blk-pci,drive=disque,bootindex=1"
    -netdev user,id=nb,restrict=on,net=10.0.2.0/24 -device virtio-net-pci,netdev=nb,addr=0x8
    -netdev "user,id=na,restrict=on,net=10.0.3.0/24,guestfwd=tcp:10.0.3.100:6514-cmd:socat -t 10 - TCP:127.0.0.1:16514,guestfwd=tcp:10.0.3.100:5514-cmd:socat -t 10 - TCP:127.0.0.1:15514"
    -device virtio-net-pci,netdev=na,addr=0x9
    -device qemu-xhci)

# ------------------------------------------------------------------ 1. installation
echo "== installation (sans intervention, TPM logiciel swtpm)"
# Démarrage par le micrologiciel sur l'ISO (shim et GRUB de l'ISO), comme sur un vrai serveur : le
# PCR 7 mesuré pendant l'installation (scellement) est alors celui des démarrages suivants (le shim
# y mesure SbatLevel ; un démarrage direct du noyau par QEMU le contourne et le TPM refuserait ensuite).
grep -q 'console=ttyS0' "$W/grub.cfg" || { echo "ISO construite sans --console-serie : banc impossible" >&2; exit 2; }
tpm
debut=$(date +%s)
timeout 40m qemu-system-x86_64 "${commun[@]}" "${AVEC_TPM[@]}" -no-reboot -serial "file:$W/installation.log" \
    -drive "if=none,id=cle,format=raw,readonly=on,file=$ISO" -device "usb-storage,drive=cle,bootindex=2" \
    -monitor "unix:$W/mon-install.sock,server,nowait" &
PID=$!
# Toute boîte « [!!] » (erreur ou question critique) bloque l'installation sans réponse : arrêt immédiat.
while kill -0 $PID 2>/dev/null; do
    sleep 30; mon mon-install.sock "screendump $W/installateur.ppm"
    if lisible "$W/installation.log" | grep -q '\[!!\]'; then
        sleep 5; kill $PID 2>/dev/null || true; break
    fi
    # Avec le TPM émulé, QEMU ne s'arrête pas toujours seul au redémarrage final malgré -no-reboot.
    if lisible "$W/installation.log" | grep -q 'Requesting system reboot'; then
        sleep 10; mon mon-install.sock quit; sleep 5; break
    fi
done
if lisible "$W/installation.log" | grep -q 'Requesting system reboot'; then
    wait $PID 2>/dev/null || true
elif ! wait $PID; then
    echo "ÉCHEC : installation interrompue, fin de la console :" >&2
    lisible "$W/installation.log" | grep -v '^\s*$' | awk '!vu[$0]++' | tail -n 60
    exit 1
fi
echo "installation : $(( ($(date +%s) - debut) / 60 )) min"
if lisible "$W/installation.log" | grep -q 'barbacane-serveur : fin d.installation : terminée'; then
    ok "installation terminée (fin-installation-serveur.sh jusqu'au bout)"
else
    echo "ÉCHEC : fin d'installation du serveur non terminée :" >&2
    lisible "$W/installation.log" | grep -v '1\*installer' | grep -A25 'barbacane-serveur' | tail -n 40
    exit 1
fi

# ------------------------------------------------------------------ 2. démarrage avec le TPM
echo "== premier démarrage (déverrouillage par le TPM)"
tpm
# Console série journalisée ET joignable (socket) : parcours v2.3.0 (compte d'administration système).
# Disque « support » (ext4) : sauvegardes du parcours v2.3.0.
qemu-img create -q -f raw "$W/support.img" 128M
mkfs.ext4 -q -F "$W/support.img"
qemu-system-x86_64 "${commun[@]}" "${AVEC_TPM[@]}" \
    -chardev "socket,id=serie,path=$W/serie.sock,server=on,wait=off,logfile=$W/demarrage.log" -serial chardev:serie \
    -drive "file=$W/support.img,if=none,id=support,format=raw" -device virtio-blk-pci,drive=support \
    -monitor "unix:$W/mon.sock,server,nowait" &
PID=$!
lu=0
for _ in $(seq 120); do
    sleep 5
    if lisible "$W/demarrage.log" | grep -q '=== BARBACANE-ETAT FIN'; then lu=1; break; fi
    kill -0 $PID 2>/dev/null || break
done
mon mon.sock "screendump $W/ecran.ppm"
# Sur la console, chaque ligne du service porte le préfixe « [ t] barbacane-serveur-etat[pid]: ».
lisible "$W/demarrage.log" | sed -nE 's/^.*barbacane-serveur-etat\[[0-9]+\]: //p' \
    | sed -n '/=== BARBACANE-ETAT DEBUT/,/=== BARBACANE-ETAT FIN/p' > "$W/etat.txt"
if [ "$lu" = 1 ]; then
    ok "démarré sans phrase de passe (TPM) : état du serveur lu sur la console"
else
    echo "ÉCHEC : état du serveur jamais affiché (déverrouillage TPM ou démarrage en échec) :" >&2
    lisible "$W/demarrage.log" | grep -v '^\s*$' | tail -n 60
    kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true
    exit 1
fi
section() { awk -v s="--- $1" '$0 == s { p = 1; next } /^--- / { p = 0 } /^=== / { p = 0 } p' "$W/etat.txt"; }

# Vu de l'extérieur : seul le port de la passerelle répond, et seulement sur l'interface « bornes ».
# Deux ports (service mTLS et enrôlement, D4), affichés par nft sous forme d'ensemble trié.
read -r PA PB < <(section pare-feu | sed -n "s/.*iifname \"$IF_BORNES\" ip daddr 10.0.2.15 tcp dport { \([0-9]*\), \([0-9]*\) } ct state new accept.*/\1 \2/p" | head -1) || true
if [ -n "${PA:-}" ] && [ -n "${PB:-}" ] && [ "$PA" -ge 20000 ] && [ "$PB" -le 60000 ] && [ "$PA" != "$PB" ]; then
    ok "ports de la passerelle tirés à l'installation : $PA et $PB (D4)"
else echec "ports de la passerelle introuvables dans le pare-feu (${PA:-?} ${PB:-?})"; PA=1 PB=2; fi
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47001-10.0.2.15:$PA"
mon mon.sock "hostfwd_add na tcp:127.0.0.1:47002-10.0.3.15:$PA"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47005-10.0.2.15:$PB"
mon mon.sock "hostfwd_add na tcp:127.0.0.1:47006-10.0.3.15:$PB"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47003-10.0.2.15:443"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47004-10.0.2.15:22"
mon mon.sock "hostfwd_add na tcp:127.0.0.1:47010-10.0.3.15:443"
mon mon.sock "hostfwd_add na tcp:127.0.0.1:47011-10.0.3.15:8443"
mon mon.sock "hostfwd_add nb tcp:127.0.0.1:47012-10.0.2.15:8443"
essai_tls() { # port [options openssl] → sortie du client
    { printf 'GET /sante HTTP/1.1\r\nHost: serveur\r\nConnection: close\r\n\r\n'; sleep 3; } \
        | timeout 15 openssl s_client -connect "127.0.0.1:$1" -tls1_3 -quiet "${@:2}" 2>&1 || true
}
if [ -n "$PKI" ]; then
    # Le port de service est l'un des deux (ordre de l'ensemble nft) : on essaie les deux.
    # Chaîne du serveur vérifiée contre la racine de TEST et le nom attendu par les bornes (nom_serveur).
    V=(-CAfile "$PKI/racine/cert.pem" -verify_return_error -verify_hostname passerelle.barbacane.invalid)
    r=$(essai_tls 47001 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" "${V[@]}")
    if ! grep -q '"etat":"ok"' <<<"$r"; then
        r=$(essai_tls 47005 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" "${V[@]}")
    fi
    if grep -q '"etat":"ok"' <<<"$r"; then ok "passerelle joignable depuis le réseau des bornes, borne mTLS acceptée, chaîne vérifiée contre la racine : $(grep -o '{.*}' <<<"$r")"
    else echec "passerelle : borne valide non servie : $(tail -n 3 <<<"$r")"; fi
    r=$(essai_tls 47001 -CAfile "$PKI/racine/cert.pem"; essai_tls 47005 -CAfile "$PKI/racine/cert.pem")
    if grep -q '"etat":"ok"' <<<"$r"; then echec "passerelle : client SANS certificat servi"; else ok "passerelle : client sans certificat refusé"; fi
    r=$(essai_tls 47002 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" -CAfile "$PKI/racine/cert.pem"; essai_tls 47006 -cert "$PKI/bornes/borne-01.cert.pem" -key "$PKI/bornes/borne-01.cle.pem" -CAfile "$PKI/racine/cert.pem")
    if grep -q '"etat":"ok"' <<<"$r"; then echec "passerelle joignable depuis le réseau d'ADMINISTRATION"; else ok "passerelle injoignable depuis le réseau d'administration"; fi
fi
# v2.2.0 : comptes de la Console, double validation, D13, rôle lecture seule (après la connexion
# d'admin-01, cookies dans $W/cookies). Chaque .p12 est relu par openssl (MAC et chiffrement).
U=https://127.0.0.1:47010
champ() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }
gras() { grep -o "$2[^<]*<b class=\"b-mono\">[^<]*" "$1" | sed 's/.*<b class="b-mono">//' | head -1; }
requete() { # CERT CLE JAR SORTIE CHEMIN [champs…] → code HTTP (GET si aucun champ)
    local c=$1 k=$2 j=$3 o=$4 ch=$5; shift 5
    local d=(); for x in "$@"; do d+=(--data-urlencode "$x"); done
    curl --silent --max-time 30 --insecure --cert "$c" --key "$k" -b "$j" -c "$j" -o "$o" -w '%{http_code}' "${d[@]}" "$U$ch" 2>/dev/null || true
}
A1=("$PKI/administrateurs/admin-01.cert.pem" "$PKI/administrateurs/admin-01.cle.pem" "$W/cookies")
p12_vers_pem() { # PAGE NOM IDENTITÉ… : télécharge le .p12 (une fois), le relit, écrit NOM.cert.pem/NOM.cle.pem
    local page=$1 nom=$2; shift 2
    local mdp jeton
    mdp=$(gras "$page" "Mot de passe du fichier .p12")
    jeton=$(champ "$page" jeton)
    code=$(requete "$@" "$W/$nom.p12" /comptes/p12 "csrf=$(champ "$page" csrf)" "jeton=$jeton")
    code2=$(requete "$@" /dev/null /comptes/p12 "csrf=$(champ "$page" csrf)" "jeton=$jeton")
    openssl pkcs12 -in "$W/$nom.p12" -passin "pass:$mdp" -clcerts -nokeys -out "$W/$nom.cert.pem" 2>/dev/null \
        && openssl pkcs12 -in "$W/$nom.p12" -passin "pass:$mdp" -nocerts -nodes -out "$W/$nom.cle.pem" 2>/dev/null \
        && [ "$code" = 200 ] && [ "$code2" = 404 ] \
        && ok "$nom : .p12 téléchargé une seule fois (puis $code2), relu par openssl (PBES2 AES-256, MAC SHA-256)" \
        || echec "$nom : .p12 (téléchargement $code puis $code2, ou openssl refuse)"
}
premiere_connexion() { # NOM MDP_PROVISOIRE NOUVEAU
    local n=$1 c="$W/$1.cert.pem" k="$W/$1.cle.pem" j="$W/cookies-$1"
    rm -f "$j"
    requete "$c" "$k" "$j" "$W/cx-$n.html" /connexion >/dev/null
    code=$(requete "$c" "$k" "$j" /dev/null /connexion "csrf=$(champ "$W/cx-$n.html" csrf)" "identifiant=$n" "mot_de_passe=$2")
    code2=$(curl --silent --insecure --cert "$c" --key "$k" -b "$j" -o /dev/null -w '%{http_code} %{redirect_url}' "$U/tableau" 2>/dev/null || true)
    requete "$c" "$k" "$j" "$W/mdp-$n.html" /mot-de-passe >/dev/null
    code3=$(requete "$c" "$k" "$j" /dev/null /mot-de-passe "csrf=$(champ "$W/mdp-$n.html" csrf)" "actuel=$2" "nouveau=$3" "confirmation=$3")
    code4=$(requete "$c" "$k" "$j" "$W/tableau-$n.html" /tableau)
    [ "$code" = 303 ] && [[ "$code2" == "303 "*"/mot-de-passe" ]] && [ "$code3" = 303 ] && [ "$code4" = 200 ] \
        && ok "$n : connexion au mot de passe provisoire, changement imposé ($code2), nouveau mot de passe accepté, tableau 200" \
        || echec "$n : première connexion (connexion $code, tableau $code2, changement $code3, puis $code4)"
}
parcours_comptes() {
    requete "${A1[@]}" "$W/comptes.html" /comptes >/dev/null
    S1=$(champ "$W/comptes.html" csrf)
    grep -q 'migration-2.1.0' "$W/comptes.html" && ok "comptes : admin-01 importé du fichier v2.1.0 (migration au premier démarrage)" \
        || echec "comptes : admin-01 non migré"
    code=$(requete "${A1[@]}" /dev/null /comptes/creer "identifiant=pirate" "role=administrateur")
    [ "$code" = 403 ] && ok "comptes : création sans jeton anti-CSRF refusée (403)" || echec "comptes : POST sans CSRF : $code"
    code=$(requete "${A1[@]}" "$W/creation-02.html" /comptes/creer "csrf=$S1" "identifiant=admin-02" "role=administrateur")
    P2=$(gras "$W/creation-02.html" "Mot de passe provisoire")
    [ "$code" = 200 ] && [ -n "$P2" ] && grep -q 'sans second administrateur' "$W/creation-02.html" \
        && ok "comptes : second administrateur admin-02 créé par le seul administrateur (amorçage journalisé)" \
        || echec "comptes : création d'admin-02 : HTTP $code"
    p12_vers_pem "$W/creation-02.html" admin-02 "${A1[@]}"
    premiere_connexion admin-02 "$P2" "Phrase de passe du banc, deuxième administrateur"
    A2=("$W/admin-02.cert.pem" "$W/admin-02.cle.pem" "$W/cookies-admin-02")
    S2=$(champ "$W/tableau-admin-02.html" csrf)
    code=$(requete "${A2[@]}" "$W/demande-lect.html" /comptes/creer "csrf=$S2" "identifiant=lect" "role=lecture")
    D=$(champ "$W/demande-lect.html" demande)
    code2=$(requete "${A2[@]}" "$W/auto.html" /validations/valider "csrf=$S2" "demande=$D")
    [ "$code" = 200 ] && [ "$code2" = 400 ] && grep -q 'second administrateur' "$W/auto.html" \
        && ok "double validation : demande d'admin-02, auto-validation refusée (400)" || echec "double validation : demande $code, auto-validation $code2"
    code=$(requete "${A1[@]}" "$W/creation-lect.html" /validations/valider "csrf=$S1" "demande=$D")
    # Séparation des remises : le .p12 au validateur (admin-01), le mot de passe provisoire au demandeur.
    requete "${A2[@]}" "$W/comptes-02.html" /comptes >/dev/null
    code2=$(requete "${A2[@]}" "$W/remise-lect.html" /comptes/remise "csrf=$S2" "jeton=$(champ "$W/comptes-02.html" jeton)")
    PL=$(gras "$W/remise-lect.html" "Mot de passe provisoire")
    [ "$code" = 200 ] && [ "$code2" = 200 ] && [ -n "$PL" ] && ! grep -q 'Mot de passe provisoire (' "$W/creation-lect.html" \
        && ok "double validation : « lect » (lecture seule) créé par admin-01 ; .p12 au validateur, mot de passe provisoire au demandeur" \
        || echec "double validation : validation par admin-01 : HTTP $code, remise $code2"
    p12_vers_pem "$W/creation-lect.html" lect "${A1[@]}"
    premiere_connexion lect "$PL" "Phrase de passe du banc, consultation"
    AL=("$W/lect.cert.pem" "$W/lect.cle.pem" "$W/cookies-lect")
    SL=$(champ "$W/tableau-lect.html" csrf)
    c1=$(requete "${AL[@]}" /dev/null /comptes); c2=$(requete "${AL[@]}" /dev/null /audit)
    c3=$(requete "${AL[@]}" /dev/null /sites/mode "csrf=$SL" "site=labo" "mode=aucun")
    c4=$(requete "${AL[@]}" /dev/null /enrolement/jeton "csrf=$SL" "site=labo")
    [ "$c1$c2$c3$c4" = 403403403403 ] && ok "rôle lecture seule : comptes, journal, réglage de site et jeton refusés (403)" \
        || echec "rôle lecture seule : $c1 $c2 $c3 $c4"
    # D13 : site en mode Aucun → activation de la quarantaine refusée ; quarantaine active → Aucun refusé.
    code=$(requete "${A1[@]}" /dev/null /sites/mode "csrf=$S1" "site=labo" "mode=aucun")
    code2=$(requete "${A1[@]}" "$W/q1.html" /quarantaine/activer "csrf=$S1")
    [ "$code" = 200 ] && [ "$code2" = 400 ] && grep -q 'D13' "$W/q1.html" \
        && ok "D13 : site « labo » en mode Aucun, activation de la quarantaine refusée (400, message D13)" || echec "D13 : activation avec site Aucun : $code $code2"
    requete "${A1[@]}" /dev/null /sites/mode "csrf=$S1" "site=labo" "mode=identification" >/dev/null
    requete "${A1[@]}" "$W/q2.html" /quarantaine/activer "csrf=$S1" >/dev/null
    code=$(requete "${A2[@]}" "$W/q3.html" /quarantaine/valider "csrf=$S2" "demande=$(champ "$W/q2.html" demande)")
    code2=$(requete "${A1[@]}" "$W/q4.html" /sites/mode "csrf=$S1" "site=labo" "mode=aucun")
    [ "$code" = 200 ] && grep -q '>Active<' "$W/q3.html" && [ "$code2" = 400 ] && grep -q 'D13' "$W/q4.html" \
        && ok "D13 : quarantaine activée par double validation (admin-01 puis admin-02), mode Aucun alors refusé (400)" \
        || echec "D13 : activation $code, mode Aucun $code2"
    code=$(requete "${A1[@]}" "$W/q5.html" /quarantaine/desactiver "csrf=$S1")
    code2=$(requete "${A1[@]}" "$W/q6.html" /sites/mode "csrf=$S1" "site=labo" "mode=aucun")
    [ "$code" = 200 ] && grep -q 'Désactivée' "$W/q5.html" && [ "$code2" = 200 ] \
        && ok "quarantaine désactivée par un seul administrateur (journalisé), mode Aucun de nouveau permis" \
        || echec "désactivation de la quarantaine : $code, mode Aucun $code2"
}
if [ -n "$PKI" ]; then
    A=(--silent --show-error --max-time 20 --insecure --cert "$PKI/administrateurs/admin-01.cert.pem" --key "$PKI/administrateurs/admin-01.cle.pem")
    : > "$W/connexion.html"
    for _ in $(seq 24); do # l'interface peut finir de démarrer après l'affichage de l'état
        code=$(curl "${A[@]}" -o "$W/connexion.html" -c "$W/cookies" -w '%{http_code}' https://127.0.0.1:47010/connexion 2>"$W/curl.err" || true)
        [ "$code" = 000 ] || break
        sleep 5
    done
    if [ "$code" = 200 ] && grep -q 'name="mot_de_passe"' "$W/connexion.html"; then
        ok "interface web servie sur 10.0.3.15:443 (administration) au certificat admin-01 de TEST : page de connexion, HTTP 200"
    else echec "interface web avec certificat admin-01 : HTTP ${code:-?} $(cat "$W/curl.err")"; fi
    # Chaîne HTTPS de la Console vérifiée contre la RACINE de TEST seule, par l'adresse d'administration
    # (SAN IP:10.0.3.15, racine-test.sh --ip-serveur) : sans --insecure.
    code=$(curl --silent --show-error --max-time 20 --cacert "$PKI/racine/cert.pem" --cert "$PKI/administrateurs/admin-01.cert.pem" \
        --key "$PKI/administrateurs/admin-01.cle.pem" --connect-to 10.0.3.15:443:127.0.0.1:47010 -o /dev/null -w '%{http_code}' \
        https://10.0.3.15/connexion 2>"$W/curl-ca.err" || true)
    if [ "$code" = 200 ]; then ok "interface web : certificat HTTPS vérifié contre la racine de TEST (chaîne complète, SAN 10.0.3.15)"
    else echec "interface web : vérification contre la racine (curl --cacert) : HTTP $code $(cat "$W/curl-ca.err")"; fi
    # Refus par le serveur (alerte TLS « certificate required »), pas un simple service absent.
    r=$(curl --silent --show-error --max-time 20 --insecure -o /dev/null -w '%{http_code}' https://127.0.0.1:47010/connexion 2>&1 || true)
    # TLS 1.3 : l'alerte suit la poignée de main ; relayée par pasta et le réseau QEMU, le client voit
    # souvent seulement la fermeture (« unexpected eof ») : refus aussi, jamais de réponse HTTP.
    grep -qi 'alert\|certificate required\|unexpected eof' <<<"$r" && ! grep -q '^[1-5][0-9][0-9]$' <<<"$r" && ok "interface web : client SANS certificat refusé à la poignée de main TLS ($(grep -oi 'tlsv13 alert [a-z ]*\|certificate required\|unexpected eof' <<<"$r" | head -1))" \
        || echec "interface web sans certificat : $r"
    code=$(curl "${A[@]}" -o /dev/null -w '%{http_code}' https://127.0.0.1:47011/connexion 2>/dev/null || true)
    [ "$code" = 000 ] && ok "interface web : port interne 8443 injoignable (seul 443 est publié et ouvert)" || echec "port interne 8443 servi en direct : HTTP $code"
    code=$(curl "${A[@]}" -o /dev/null -w '%{http_code}' https://127.0.0.1:47012/connexion 2>/dev/null || true)
    [ "$code" = 000 ] && ok "interface web injoignable depuis le réseau des bornes" || echec "interface web servie sur le réseau des bornes : HTTP $code"
    if [ -n "$MDP_WEB" ]; then
        rm -f "$W/cookies"
        curl "${A[@]}" -c "$W/cookies" -o "$W/connexion.html" https://127.0.0.1:47010/connexion 2>/dev/null || true
        csrf=$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$W/connexion.html" 2>/dev/null | head -1 || true)
        code=$(curl "${A[@]}" -b "$W/cookies" -c "$W/cookies" -o /dev/null -w '%{http_code}' \
            --data-urlencode "csrf=$csrf" --data-urlencode identifiant=admin-01 --data-urlencode "mot_de_passe@-" \
            https://127.0.0.1:47010/connexion 2>/dev/null < <(head -n 1 "$MDP_WEB" | tr -d '\r\n') || true)
        code2=$(curl "${A[@]}" -b "$W/cookies" -o "$W/tableau.html" -w '%{http_code}' https://127.0.0.1:47010/tableau 2>/dev/null || true)
        if [ "$code2" = 200 ] && grep -q "Bornes actives" "$W/tableau.html"; then
            ok "interface web : connexion admin-01 (certificat + mot de passe Argon2id, HTTP $code) puis tableau de bord HTTP 200"
        else echec "interface web : connexion admin-01 (POST $code, tableau $code2)"; fi
        parcours_comptes
        if [ -n "${MDP_ADMIN:-}" ]; then
            # shellcheck source=tests/serveur/qemu-journal.sh
            . "$(dirname "$0")/qemu-journal.sh"
            parcours_journal
        fi
    fi
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
# v2.3.0 : sortie vers la seule cible Syslog validée (ensemble « syslog », vide à l'installation).
regle_syslog=$(grep -E '\baccept\b' <<<"$nft" | grep '@syslog' | sed 's/^[[:space:]]*//' || true)
grep -qE "^oifname \"$IF_ADMIN\" meta skuid [^ ]+ ip daddr \. meta l4proto \. th dport @syslog ct state new accept$" <<<"$regle_syslog" \
    && ok "pare-feu : sortie Syslog limitée à l'ensemble « syslog », au compte barbacane-svc et à l'interface d'administration" \
    || echec "pare-feu : règle de sortie Syslog absente ou inattendue : $regle_syslog"
awk '/set syslog/ { s = 1 } s && /elements/ { e = 1 } s && /}/ { exit } END { exit e }' <<<"$nft" \
    && ok "pare-feu : ensemble syslog vide à l'installation (aucune sortie)" || echec "pare-feu : ensemble syslog non vide à l'installation"
autorises=$(grep -E '\baccept\b' <<<"$nft" | grep -v 'type nat hook' | grep -v '@syslog' | sed 's/^[[:space:]]*//' | sort || true)
attendu=$(printf '%s\n' 'ct state established,related accept' 'ct state established,related accept' 'iif "lo" accept' \
    "iifname \"$IF_ADMIN\" ip daddr 10.0.3.15 tcp dport 443 ct state new accept" \
    "iifname \"$IF_BORNES\" ip daddr 10.0.2.15 tcp dport { $PA, $PB } ct state new accept" 'oif "lo" accept' | sort)
[ "$autorises" = "$attendu" ] && ok "pare-feu : 6 règles d'acceptation, toutes attendues" \
    || { echec "pare-feu : règles d'acceptation inattendues"; diff <(echo "$attendu") <(echo "$autorises") || true; }
grep -qE 'udp dport 123|dport 53' <<<"$nft" && echec "pare-feu : NTP ou DNS sortant autorisé"
# Écoute : passerelle (relayée par pasta) seulement sur l'adresse « bornes » ; rien d'autre que la boucle locale
ecoute=$(section ecoute)
autres=$(grep -vE '^(127\.|\[::1\])' <<<"$ecoute" | grep -vE "^10.0.2.15:($PA|$PB)$" | grep -vx '10.0.3.15:443' || true)
[ -z "$autres" ] && ok "écoute réseau : $(tr '\n' ' ' <<<"$ecoute")" || echec "ports en écoute inattendus : $autres"
# Heure
h=$(section heure)
if grep -qE '^[[:space:]]*(server|pool|peer)' <<<"$h"; then echec "chrony : source réseau configurée"; else ok "chrony : aucune source externe configurée"; fi
# Une ligne de source commence par « ^ » (serveur), « = » (pair) ou « # » (horloge de référence)
# suivi de son état ; la ligne de séparation « ===… » n'en est pas une.
grep -q '^MS Name' <<<"$h" && ! grep -qE '^[\^=#][*+x?~ -] ' <<<"$h" \
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
    grep -q '^utilisateur:barbacane-web active' <<<"$s" && ok "interface web active (Podman sans root)" || echec "interface web : $(grep 'barbacane-web' <<<"$s")"
    grep -qx '10.0.3.15:443' <<<"$ecoute" && ok "interface web en écoute sur l'adresse d'administration seulement (10.0.3.15:443, publié par pasta sans root)" \
        || echec "interface web : écoute 10.0.3.15:443 absente"
    c=$(section conteneurs)
    for n in barbacane-passerelle barbacane-web; do
        grep -q "^$n readonly=true privileged=false caps=\[\]" <<<"$c" && ok "conteneur $n : racine en lecture seule, non privilégié, aucune capacité" \
            || echec "conteneur $n : options de confinement inattendues : $c"
    done
    for n in passerelle web; do
        u=$(section "processus-$n" | awk 'NR == 1 { print $1 }')
        [ -n "$u" ] && [ "$u" != root ] && ok "processus barbacane-$n exécuté par « $u » (pas root)" || echec "processus barbacane-$n : « $u »"
    done
    section registre | grep -q '^Aucune demande en attente\.$' && ok "barbacane-registre utilisable (sudo, sous barbacane-svc) : aucune demande en attente" \
        || echec "barbacane-registre : $(section registre | head -3)"
else
    grep -q '^utilisateur:barbacane-passerelle inactive condition=no' <<<"$s" && ok "passerelle en attente de PKI (sans échec)" \
        || echec "passerelle sans PKI : $(grep passerelle <<<"$s")"
    grep -q '^utilisateur:barbacane-web inactive condition=no' <<<"$s" && ok "interface web en attente de la CA des administrateurs (sans échec)" \
        || echec "interface web sans PKI : $(grep 'barbacane-web' <<<"$s")"
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
NBD=${NBD:-/dev/nbd0} # autre périphérique si un autre banc tourne en même temps
qemu-nbd -r -c "$NBD" "$W/disque.qcow2"
trap 'qemu-nbd -d "$NBD" >/dev/null 2>&1 || true' EXIT
sleep 2
luks=$(lsblk -lnpo NAME,FSTYPE "$NBD" | awk '$2 == "crypto_LUKS" { print $1; exit }')
if [ -z "$luks" ]; then
    echec "aucune partition LUKS sur le disque"
else
    cryptsetup luksDump "$luks" > "$W/luksdump.txt"
    grep -qE '^Version:[[:space:]]*2$' "$W/luksdump.txt" && ok "en-tête LUKS2" || echec "en-tête non LUKS2"
    grep -q 'aes-xts-plain64' "$W/luksdump.txt" && grep -q 'Key: *512 bits' "$W/luksdump.txt" \
        && ok "AES-XTS, clé de 512 bits" || echec "chiffrement inattendu"
    id_tpm=$(awk '/^  [0-9]+: systemd-tpm2/ { sub(":", "", $1); print $1; exit }' "$W/luksdump.txt")
    if [ -n "$id_tpm" ]; then
        pcr=$(cryptsetup token export --token-id "$id_tpm" "$luks" | grep -o '"tpm2-pcrs":\[[0-9,]*\]' || true)
        [ "$pcr" = '"tpm2-pcrs":[7]' ] && ok "jeton systemd-tpm2 lié au PCR 7 ($pcr)" || echec "jeton TPM2 : PCR inattendus ($pcr)"
    else
        echec "jeton TPM2 absent"
    fi
    grep -q 'systemd-recovery' "$W/luksdump.txt" && ok "jeton de clé de secours" || echec "clé de secours absente"
    n=$(grep -cE '^  [0-9]+: luks2' "$W/luksdump.txt")
    [ "$n" = 2 ] && ok "2 emplacements de clé (TPM + secours)" || echec "$n emplacements de clé (2 attendus)"
    if printf '%s' "$PHRASE" | cryptsetup open --test-passphrase --key-file=- "$luks" 2>/dev/null; then
        echec "la phrase de passe d'installation (présente dans l'ISO) ouvre ENCORE le disque"
    else
        ok "phrase de passe d'installation effacée du disque"
    fi
    n_ext4=$(lsblk -lnpo NAME,FSTYPE "$NBD" | awk '$2 == "ext4"' | wc -l)
    [ "$n_ext4" = 1 ] && ok "une seule partition en clair (/boot)" || echec "$n_ext4 partitions ext4 en clair"
fi
echo "TPM : logiciel (swtpm $(swtpm --version 2>&1 | head -1 | awk '{ print $NF }')), banc de test uniquement"
[ "$ko" = 0 ] && echo "SERVEUR QEMU : OK"
exit "$ko"
