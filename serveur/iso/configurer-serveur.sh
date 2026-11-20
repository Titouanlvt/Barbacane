#!/bin/bash
# Configuration du SERVEUR Barbacane, exécutée dans le système installé (in-target) par
# fin-installation-serveur.sh. Conception et justification de chaque mesure :
# docs/suite/serveur-iso.md. Idempotent autant que possible ; toute erreur arrête l'installation.
set -Eeuo pipefail
trap 'echo "ÉCHEC de configurer-serveur.sh, ligne $LINENO : $BASH_COMMAND" >&2' ERR
# Garde-fou : jamais sur un hôte Proxmox VE (docs/incident-proxmox.md).
if [ -e /etc/pve ]; then
    echo "REFUS : hôte Proxmox VE détecté (/etc/pve)." >&2
    exit 1
fi
C=/etc/barbacane-serveur
# shellcheck source=/dev/null
. "$C/serveur.conf"
: "${IF_BORNES:?}" "${IP_BORNES:?}" "${IF_ADMIN:?}" "${IP_ADMIN:?}" "${PORT_ADMIN:?}" "${VERSION:?}" "${COMPTE_ADMIN:?}"
SVC=barbacane-svc
DONNEES=/var/lib/barbacane-serveur
etape() { echo "barbacane-serveur : $*"; echo "barbacane-serveur : $*" > /dev/console 2>/dev/null || true; }

echo "$VERSION" > "$C/version"

# ------------------------------------------------------------------ 0. paquets interdits (réseau, accès distant)
mapfile -t presents < <(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' | awk '$1 == "ii" { print $2 }' \
    | grep -xFf /usr/share/barbacane-serveur/paquets-interdits || true)
if [ "${#presents[@]}" -gt 0 ]; then
    etape "retrait des paquets interdits : ${presents[*]}"
    apt-get purge -y -q -o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/nonexistent "${presents[@]}"
fi

# ------------------------------------------------------------------ 1. disque : TPM 2.0 (D9)
etape "scellement du disque au TPM"
[ -e /dev/tpmrm0 ] || { echo "REFUS : aucun TPM 2.0 (/dev/tpmrm0) : exigé pour le serveur (D9)" >&2; exit 1; }
nom=$(awk '!/^#/ && NF >= 2 { print $1; exit }' /etc/crypttab)
src=$(awk '!/^#/ && NF >= 2 { print $2; exit }' /etc/crypttab)
if [ -z "$nom" ] || [ -z "$src" ]; then echo "ÉCHEC : /etc/crypttab vide (disque non chiffré ?)" >&2; exit 1; fi
case "$src" in UUID=*) dev="/dev/disk/by-uuid/${src#UUID=}" ;; *) dev="$src" ;; esac
cryptsetup isLuks --type luks2 "$dev" || { echo "ÉCHEC : $dev n'est pas un volume LUKS2" >&2; exit 1; }
PASSWORD=$(cat /run/barbacane/phrase)
export PASSWORD
mkdir -p /run/cryptsetup
# Clé de secours (si le TPM ou la carte mère est remplacé) : sur le disque chiffré seulement,
# lisible par root ; à transcrire (coffre) puis détruire (barbacane-serveur-etat le rappelle).
if ! cryptsetup luksDump "$dev" | grep -q systemd-recovery; then
    umask 077
    systemd-cryptenroll --recovery-key "$dev" > /root/cle-de-secours-luks.txt
    umask 022
fi
# Scellé au PCR 7 (état du démarrage sécurisé) ; docs/suite/serveur-iso.md §3 (limites).
cryptsetup luksDump "$dev" | grep -q systemd-tpm2 \
    || systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$dev"
# La phrase temporaire de l'installateur (identique pour toutes les installations d'une même ISO)
# est effacée : restent le TPM et la clé de secours.
systemd-cryptenroll --wipe-slot=password "$dev"
unset PASSWORD
# Volume ouvert par systemd-cryptsetup dans l'initramfs (dracut) avec le TPM ; pas de « discard »
# (il révélerait l'occupation du disque).
printf '# Barbacane : disque scellé au TPM (systemd-cryptenroll), clé de secours en dernier recours\n%s %s none luks,tpm2-device=auto\n' \
    "$nom" "$src" > /etc/crypttab
cat > /etc/dracut.conf.d/90-barbacane-serveur.conf <<'FIN'
# Initramfs systemd : déverrouillage LUKS2 par le TPM (systemd-cryptsetup, tpm2-device=auto).
hostonly="yes"
add_dracutmodules+=" systemd crypt systemd-cryptsetup tpm2-tss lvm "
FIN
for k in /lib/modules/*; do
    v=${k##*/}
    dracut -f "/boot/initrd.img-$v" "$v"
done

# ------------------------------------------------------------------ 2. réseau : deux interfaces, aucune route par défaut
etape "réseau et pare-feu"
for s in networking NetworkManager wpa_supplicant ssh systemd-resolved; do
    systemctl mask "$s.service" 2>/dev/null || true
done
rm -f /etc/network/interfaces.d/* 2>/dev/null || true
mkdir -p /etc/systemd/network
ecrire_reseau() { # fichier interface adresse rôle
    cat > "$1" <<FIN
# Barbacane : interface « $4 ». Adresse fixe, AUCUNE passerelle (pas de route par défaut, D1).
[Match]
Name=$2

[Network]
Address=$3
DHCP=no
LinkLocalAddressing=no
IPv6AcceptRA=no
LLMNR=no
MulticastDNS=no
FIN
}
ecrire_reseau /etc/systemd/network/10-bornes.network "$IF_BORNES" "$IP_BORNES" bornes
ecrire_reseau /etc/systemd/network/20-admin.network "$IF_ADMIN" "$IP_ADMIN" administration
systemctl enable systemd-networkd.service
# Port de la passerelle tiré au hasard à l'installation (D4) : 20000–60000, hors ports connus.
if [ -z "${PORT:-}" ]; then
    while :; do
        PORT=$(shuf -i 20000-60000 -n 1)
        grep -qE "[[:space:]]$PORT/(tcp|udp)" /etc/services || break
    done
fi
echo "$PORT" > "$C/port-passerelle"
ip_bornes=${IP_BORNES%/*}
if [ -n "${SOURCE_HEURE:-}" ]; then
    sortie_heure="oifname \"$IF_ADMIN\" ip daddr $SOURCE_HEURE udp dport 123 accept"
else
    sortie_heure="# aucune source d'heure réseau (horloge locale de référence)"
fi
sed -e "s|@IF_BORNES@|$IF_BORNES|g" -e "s|@IF_ADMIN@|$IF_ADMIN|g" -e "s|@IP_BORNES@|$ip_bornes|g" \
    -e "s|@PORT@|$PORT|g" -e "s|@PORT_ADMIN@|$PORT_ADMIN|g" -e "s|@SORTIE_HEURE@|$sortie_heure|" \
    /usr/share/barbacane-serveur/nftables.conf.modele > /etc/nftables.conf
chmod 600 /etc/nftables.conf
nft -c -f /etc/nftables.conf
systemctl enable nftables.service

# ------------------------------------------------------------------ 3. heure de référence (§3.11)
etape "heure (chrony, sans source Internet)"
if [ -n "${SOURCE_HEURE:-}" ]; then
    src_heure="server $SOURCE_HEURE iburst"
else
    src_heure="# aucune source : horloge locale (à régler à la mise en service, docs/suite/serveur-iso.md §6)"
fi
sed "s|@SOURCE_HEURE@|$src_heure|" /usr/share/barbacane-serveur/chrony.conf.modele > /etc/chrony/chrony.conf
rm -f /etc/chrony/sources.d/* /etc/chrony/conf.d/* 2>/dev/null || true
systemctl mask systemd-timesyncd.service 2>/dev/null || true
systemctl enable chrony.service

# ------------------------------------------------------------------ 4. journaux, audit, durcissement
etape "journaux, audit, durcissement"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
systemctl enable auditd.service
systemctl mask apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl disable e2scrub_all.timer 2>/dev/null || true
# Paramètres du noyau (guide ANSSI) : appliqués au démarrage (GRUB).
mkdir -p /etc/default/grub.d
# shellcheck disable=SC2016 # « $GRUB_CMDLINE_LINUX » est développé par GRUB, pas ici
echo 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX @CMDLINE@"' \
    | sed "s|@CMDLINE@|$(cat /usr/share/barbacane-serveur/cmdline-anssi)|" > /etc/default/grub.d/90-barbacane-serveur.cfg
chmod 700 /root
sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
passwd -l root >/dev/null

# Compte d'administration système (console seulement, pas d'accès réseau : aucun serveur SSH).
# Mot de passe initial fourni à la construction, à changer à la première connexion.
if ! id "$COMPTE_ADMIN" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo,systemd-journal,adm -c "Administrateur système Barbacane" "$COMPTE_ADMIN"
fi
usermod -p "$HACHE_ADMIN" "$COMPTE_ADMIN"
chage -d 0 "$COMPTE_ADMIN"
echo 'Defaults logfile=/var/log/sudo.log, use_pty, timestamp_timeout=5' > /etc/sudoers.d/90-barbacane
chmod 440 /etc/sudoers.d/90-barbacane
visudo -cq

# GRUB verrouillé (même mesure que la borne v1, systeme/iso/configurer.sh) : l'entrée par défaut
# démarre seule, l'édition de la ligne du noyau exige un mot de passe que personne ne connaît.
if [ ! -f /etc/grub.d/01_barbacane ]; then
    mdp=$(head -c 32 /dev/urandom | base64)
    hache=$(printf '%s\n%s\n' "$mdp" "$mdp" | grub-mkpasswd-pbkdf2 | awk '/grub\.pbkdf2/ { print $NF }')
    unset mdp
    [ -n "$hache" ] || { echo "ÉCHEC : hachage du mot de passe GRUB" >&2; exit 1; }
    printf '#!/bin/sh\ncat <<FIN\nset superusers="barbacane"\npassword_pbkdf2 barbacane %s\nFIN\n' "$hache" \
        > /etc/grub.d/01_barbacane
    chmod 700 /etc/grub.d/01_barbacane
    if [ ! -e /etc/grub.d/10_linux.debian ]; then
        dpkg-divert --quiet --local --rename --divert /etc/grub.d/10_linux.debian --add /etc/grub.d/10_linux
        chmod -x /etc/grub.d/10_linux.debian
    fi
    printf '#!/bin/sh\n# Barbacane : entrées Debian « --unrestricted » (démarrage sans mot de passe, édition protégée)\n/bin/sh /etc/grub.d/10_linux.debian "$@" | sed "s/^\\([[:space:]]*\\)menuentry /\\1menuentry --unrestricted /"\n' \
        > /etc/grub.d/10_linux
    chmod 755 /etc/grub.d/10_linux
fi
update-grub

# ------------------------------------------------------------------ 5. services : Podman sans root (D11)
etape "services (Podman sans root)"
if ! id "$SVC" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$DONNEES/svc" --shell /usr/sbin/nologin \
        -c "Services Barbacane (Podman sans root)" "$SVC"
fi
grep -q "^$SVC:" /etc/subuid || usermod --add-subuids 200000-265535 --add-subgids 200000-265535 "$SVC"
chmod 750 "$DONNEES/svc"
# Session utilisateur systemd permanente (les conteneurs démarrent sans connexion).
mkdir -p /var/lib/systemd/linger
touch "/var/lib/systemd/linger/$SVC"
H="$DONNEES/svc"
install -d -o "$SVC" -g "$SVC" -m 700 "$H/.config" "$H/.config/containers" "$H/.config/containers/systemd" \
    "$H/.config/systemd" "$H/.config/systemd/user" "$H/pki"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@IP_BORNES@|$ip_bornes|g" -e "s|@PORT@|$PORT|g" \
    /usr/share/barbacane-serveur/barbacane-passerelle.container > "$H/.config/containers/systemd/barbacane-passerelle.container"
sed -e "s|@VERSION@|$VERSION|g" /usr/share/barbacane-serveur/barbacane-images.service \
    > "$H/.config/systemd/user/barbacane-images.service"
# Racine en lecture seule et sans réseau sortant : storage.conf par défaut (overlay natif).
# PKI : en production, déposée par la cérémonie (politique-certification.md) ; une ISO de TEST
# embarque une PKI de test (certificat serveur, CA bornes, CRL ; aucune clé de CA).
if [ -d "$C/pki-test" ]; then
    install -o "$SVC" -g "$SVC" -m 400 "$C"/pki-test/* "$H/pki/"
    printf 'adresse = 0.0.0.0\nport = %s\nchaine_serveur = /pki/chaine.pem\ncle_serveur = /pki/cle.pem\nca_bornes = /pki/ca-bornes.pem\ncrl_bornes = /pki/crl-bornes.pem\n' \
        "$PORT" > "$H/pki/passerelle.conf"
    chown "$SVC:$SVC" "$H/pki/passerelle.conf"
    chmod 400 "$H/pki/passerelle.conf"
    rm -rf "$C/pki-test"
fi
chown -R "$SVC:$SVC" "$H/.config"
systemctl enable barbacane-serveur-etat.service
# Clé de signature des sauvegardes (propre à ce serveur) ; le certificat de la clé de sauvegarde
# (destinataire.pem) est déposé par l'administrateur, la clé privée restant hors du serveur.
[ -f "$C/sauvegarde/signature.cle.pem" ] || /usr/local/sbin/barbacane-sauvegarde cles-signature "$C/sauvegarde"
chmod 700 "$C/sauvegarde"
# Empreinte du mot de passe initial : inutile après création du compte.
sed -i '/^HACHE_ADMIN=/d' "$C/serveur.conf"

etape "configuration terminée (port de la passerelle : $PORT)"
