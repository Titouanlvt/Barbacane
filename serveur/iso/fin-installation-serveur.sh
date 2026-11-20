#!/bin/sh
# Fin d'installation du SERVEUR Barbacane (installateur Debian, busybox) : paquets du serveur et
# dépendances depuis l'ISO, fichiers du serveur, puis configuration du système installé
# (configurer-serveur.sh : TPM, pare-feu, services). Toute erreur arrête l'installation.
set -e
X=/cdrom/barbacane
journal() { logger -t barbacane-serveur "$*"; echo "barbacane-serveur : $*" > /dev/console 2>/dev/null || true; }
journal "fin d'installation : paquets du serveur"
mkdir -p /target/var/cache/barbacane-debs
cp $X/debs/*.deb /target/var/cache/barbacane-debs/
# Aucune source apt (même raison que la borne, systeme/iso/fin-installation.sh : la source
# « cdrom: » fige l'installation). dracut remplace initramfs-tools (déverrouillage TPM2).
in-target sh -c 'apt-get install -y -q --no-install-recommends -o Dir::Etc::SourceList=/dev/null \
    -o Dir::Etc::SourceParts=/nonexistent /var/cache/barbacane-debs/*.deb'
rm -rf /target/var/cache/barbacane-debs
journal "fin d'installation : fichiers du serveur"
tar -xf $X/fichiers.tar -C /target
mkdir -p /target/etc/barbacane-serveur
cp $X/serveur.conf /target/etc/barbacane-serveur/serveur.conf
chmod 600 /target/etc/barbacane-serveur/serveur.conf
if [ -d $X/pki-test ]; then
    mkdir -p /target/etc/barbacane-serveur/pki-test
    cp $X/pki-test/* /target/etc/barbacane-serveur/pki-test/
fi
# Phrase de passe temporaire du disque : transmise à configurer-serveur.sh par un fichier
# en mémoire (tmpfs monté dans la cible hors de /run, que in-target remonte), jamais écrit sur disque.
mkdir -p /target/mnt/barbacane-temp
mount -t tmpfs -o size=1m,mode=700 tmpfs /target/mnt/barbacane-temp
sed -n 's/^d-i partman-crypto\/passphrase password //p' $X/preseed.cfg > /target/mnt/barbacane-temp/phrase
cp $X/configurer-serveur.sh /target/tmp/configurer-serveur.sh
journal "fin d'installation : configuration (TPM, pare-feu, services)"
in-target bash /tmp/configurer-serveur.sh
umount /target/mnt/barbacane-temp
rmdir /target/mnt/barbacane-temp
rm -f /target/tmp/configurer-serveur.sh
journal "fin d'installation : terminée"
