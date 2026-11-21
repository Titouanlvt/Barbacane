#!/bin/bash
# Configuration du SERVEUR Barbacane, exécutée dans le système installé (in-target) par
# fin-installation-serveur.sh. Conception et justification de chaque mesure :
# docs/suite/serveur-iso.md. Idempotent autant que possible ; toute erreur arrête l'installation.
set -Eeuo pipefail
# Tout le détail sur la console de l'installateur (diagnostic) et dans un journal du système installé.
exec > >(tee -a /var/log/barbacane-serveur-installation.log > /dev/console) 2>&1
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
etape() { echo "barbacane-serveur : $*"; }

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
PASSWORD=$(cat /mnt/barbacane-temp/phrase)
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
# Ports de la passerelle (service mTLS et enrôlement) tirés au hasard à l'installation (D4) :
# 20000–60000, hors ports connus, distincts. Figés à la construction si les ISO des bornes sont
# embarquées (ils sont alors inscrits dans l'ISO générique, contrôlé par build-iso-serveur.sh).
# Port INTERNE de l'interface web (barbacane-web, sans root) : le port d'administration s'il est
# ≥ 1024, sinon 8443, vers lequel nftables redirige le port d'administration (aucun droit sur les
# ports bas pour barbacane-svc, ip_unprivileged_port_start inchangé).
if [ "$PORT_ADMIN" -ge 1024 ]; then PORT_WEB=$PORT_ADMIN; else PORT_WEB=8443; fi
tirer_port() { # PORTS_À_ÉVITER…
    local p e
    while :; do
        p=$(shuf -i 20000-60000 -n 1)
        for e in "$@"; do [ "$p" != "$e" ] || continue 2; done
        ! grep -qE "[[:space:]]$p/(tcp|udp)" /etc/services && break
    done
    echo "$p"
}
[ -n "${PORT:-}" ] || PORT=$(tirer_port "${PORT_ENROLEMENT:-}" "$PORT_WEB")
[ -n "${PORT_ENROLEMENT:-}" ] || PORT_ENROLEMENT=$(tirer_port "$PORT" "$PORT_WEB")
[ "$PORT" != "$PORT_ENROLEMENT" ] || { echo "ÉCHEC : ports service et enrôlement identiques" >&2; exit 1; }
if [ "$PORT" = "$PORT_WEB" ] || [ "$PORT_ENROLEMENT" = "$PORT_WEB" ]; then
    echo "ÉCHEC : port de la passerelle égal au port interne de l'interface web ($PORT_WEB)" >&2; exit 1
fi
echo "$PORT_WEB" > "$C/port-web"
echo "$PORT" > "$C/port-passerelle"
echo "$PORT_ENROLEMENT" > "$C/port-enrolement"
ip_bornes=${IP_BORNES%/*}
ip_admin=${IP_ADMIN%/*}
if [ -n "${SOURCE_HEURE:-}" ]; then
    sortie_heure="oifname \"$IF_ADMIN\" ip daddr $SOURCE_HEURE udp dport 123 accept"
else
    sortie_heure="# aucune source d'heure réseau (horloge locale de référence)"
fi
sed -e "s|@IF_BORNES@|$IF_BORNES|g" -e "s|@IF_ADMIN@|$IF_ADMIN|g" -e "s|@IP_BORNES@|$ip_bornes|g" \
    -e "s|@PORT@|$PORT|g" -e "s|@PORT_ENROLEMENT@|$PORT_ENROLEMENT|g" -e "s|@PORT_ADMIN@|$PORT_ADMIN|g" \
    -e "s|@IP_ADMIN@|$ip_admin|g" -e "s|@PORT_WEB@|$PORT_WEB|g" -e "s|@SORTIE_HEURE@|$sortie_heure|" \
    /usr/share/barbacane-serveur/nftables.conf.modele > /etc/nftables.conf
chmod 600 /etc/nftables.conf
# Contrôle de syntaxe : impossible dans l'installateur si nf_tables n'y est pas chargé (Netlink) ;
# toute autre erreur arrête l'installation. Le banc QEMU vérifie les règles réellement chargées.
if ! sortie=$(nft -c -f /etc/nftables.conf 2>&1); then
    grep -q 'Netlink' <<<"$sortie" || { echo "$sortie" >&2; exit 1; }
    echo "nftables : contrôle reporté au démarrage (nf_tables absent de l'installateur)"
fi
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
    "$H/.config/systemd" "$H/.config/systemd/user" "$H/pki" "$H/etat" "$H/etat/registre" "$H/web" "$H/tmp-web"
# ISO des bornes (lecture seule, montées dans barbacane-web) : dossier présent même vide.
install -d -m 755 "$DONNEES/iso-bornes"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@IP_BORNES@|$ip_bornes|g" -e "s|@PORT@|$PORT|g" \
    -e "s|@PORT_ENROLEMENT@|$PORT_ENROLEMENT|g" /usr/share/barbacane-serveur/barbacane-passerelle.container > "$H/.config/containers/systemd/barbacane-passerelle.container"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@IP_ADMIN@|$ip_admin|g" -e "s|@PORT_WEB@|$PORT_WEB|g" \
    /usr/share/barbacane-serveur/barbacane-web.container > "$H/.config/containers/systemd/barbacane-web.container"
sed -e "s|@VERSION@|$VERSION|g" /usr/share/barbacane-serveur/barbacane-images.service \
    > "$H/.config/systemd/user/barbacane-images.service"
# Racine en lecture seule et sans réseau sortant : storage.conf par défaut (overlay natif).
# PKI : en production, déposée par la cérémonie (politique-certification.md §5) : chaine.pem,
# cle.pem, ca-bornes.pem, cle-ca-bornes.pem (la passerelle SIGNE les certificats des bornes à
# l'enrôlement), crl-bornes.pem initiale dans etat/. Une ISO de TEST embarque la PKI de test
# (serveur/pki/racine-test.sh, y compris la clé de la CA bornes de TEST) ; jamais de clé de
# production dans une ISO. passerelle.conf est écrit dans tous les cas (sans PKI, le quadlet
# reste en « condition non remplie » : ConditionPathExists sur la clé de la CA bornes).
# shellcheck source=/dev/null
. /usr/share/barbacane-serveur/passerelle-conf.sh
ecrire_conf_passerelle "$H/pki/passerelle.conf" "$PORT" "$PORT_ENROLEMENT"
if [ -d "$C/pki-test" ]; then
    install -o "$SVC" -g "$SVC" -m 400 "$C"/pki-test/chaine.pem "$C"/pki-test/cle.pem \
        "$C"/pki-test/ca-bornes.pem "$C"/pki-test/cle-ca-bornes.pem "$H/pki/"
    install -o "$SVC" -g "$SVC" -m 600 "$C"/pki-test/crl-bornes.pem "$H/etat/"
    rm -rf "$C/pki-test"
fi
chown "$SVC:$SVC" "$H/pki/passerelle.conf"
chmod 400 "$H/pki/passerelle.conf"
# Vue hôte des mêmes fichiers pour l'outil barbacane-registre (sous barbacane-svc, hors conteneur).
ecrire_conf_passerelle "$H/registre.conf" "$PORT" "$PORT_ENROLEMENT" "$H/pki" "$H/etat"
chown "$SVC:$SVC" "$H/registre.conf"
chmod 400 "$H/registre.conf"
# Clé de mise à jour des bornes (minisign, PUBLIQUE) : sans elle, tout dépôt de paquet est refusé
# (serveur-maj-audit.md §2.1). Fournie à la construction (--cle-maj-bornes) ou déposée ensuite.
if [ -f "$C/cle-maj-bornes.pub" ]; then
    install -d -o "$SVC" -g "$SVC" -m 700 "$H/etat/registre/maj"
    install -o "$SVC" -g "$SVC" -m 444 "$C/cle-maj-bornes.pub" "$H/etat/registre/maj/cle-bornes.pub"
fi

# Interface web (barbacane-web, serveur-web.md) : web.conf toujours écrit ; clé d'audit P-384
# propre à ce serveur, privée dans /etc/barbacane-serveur/audit (root seul : la passerelle et
# l'interface n'en ont que la clé PUBLIQUE, serveur-maj-audit.md §1, séparation des rôles).
# shellcheck source=/dev/null
. /usr/share/barbacane-serveur/web-conf.sh
ecrire_conf_web "$H/web/web.conf" "$PORT_WEB"
[ -f "$C/audit/cle-audit.pem" ] || /usr/local/sbin/barbacane-audit cle "$C/audit"
chmod 700 "$C/audit"
install -o "$SVC" -g "$SVC" -m 444 "$C/audit/cle-audit.pub" "$H/web/cle-audit.pub"
# CA des administrateurs : déposée par la cérémonie en production (ca-administrateurs.pem,
# crl-administrateurs.pem, comptes) ; une ISO de TEST embarque celle de racine-test.sh et le
# compte initial lié au certificat admin-01 (build-iso-serveur.sh --pki-test).
if [ -d "$C/web-test" ]; then
    install -o "$SVC" -g "$SVC" -m 444 "$C/web-test/ca-administrateurs.pem" "$C/web-test/crl-administrateurs.pem" "$H/web/"
    install -o "$SVC" -g "$SVC" -m 600 "$C/web-test/comptes" "$H/web/comptes"
    rm -rf "$C/web-test"
fi
chown "$SVC:$SVC" "$H/web/web.conf"
chmod 400 "$H/web/web.conf"
chown -R "$SVC:$SVC" "$H/.config"
systemctl enable barbacane-serveur-etat.service
# Clé de signature des sauvegardes (propre à ce serveur) ; le certificat de la clé de sauvegarde
# (destinataire.pem) est déposé par l'administrateur, la clé privée restant hors du serveur.
[ -f "$C/sauvegarde/signature.cle.pem" ] || /usr/local/sbin/barbacane-sauvegarde cles-signature "$C/sauvegarde"
chmod 700 "$C/sauvegarde"
# Empreinte du mot de passe initial : inutile après création du compte.
sed -i '/^HACHE_ADMIN=/d' "$C/serveur.conf"

etape "configuration terminée (passerelle : service $PORT, enrôlement $PORT_ENROLEMENT ; interface web : $ip_admin:$PORT_ADMIN → $PORT_WEB)"
