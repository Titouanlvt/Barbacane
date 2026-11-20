#!/bin/bash
# Banc du lab (VM de dev bu, root) : PKI de TEST hors dépôt, ISO serveur de test, installation QEMU.
#   tests/serveur/banc-lab.sh [construire|qemu|tout]   (journal : sortie standard ; fin : « LAB FIN »)
# Le dépôt est attendu dans /travail/serveur-iso ; tout le reste va dans /travail/serveur-lab.
set -u
export TMPDIR=/travail/tmp CARGO_TARGET_DIR=/travail/cible-serveur-iso
L=/travail/serveur-lab; mkdir -p $L
R=/travail/serveur-iso
cd "$R" || exit 1
etape=${1:-tout}
if [ "$etape" != qemu ]; then
  if [ ! -f $L/pki/racine/cert.pem ]; then rm -rf $L/pki; mkdir -p $L/pki; bash serveur/pki/racine-test.sh $L/pki || exit 1; fi
  # Mot de passe initial du compte d'administration du banc (aléatoire, expiré à la 1re connexion).
  [ -f $L/hache ] || head -c 12 /dev/urandom | base64 | openssl passwd -6 -stdin > $L/hache
  P=(); [ -d $L/debs ] && P=(--paquets "$L/debs")
  timeout 60m bash serveur/iso/build-iso-serveur.sh --ip-bornes 10.0.2.15/24 --ip-admin 10.0.3.15/24 \
     --pki-test $L/pki --hache-admin $L/hache --console-serie --netinst /travail/serveur-cache/debian-13.7.0-amd64-netinst.iso \
     "${P[@]}" --sortie $L/serveur-test.iso || { echo "CONSTRUCTION ECHEC"; tail -40 $L/serveur-test.log; exit 1; }
  if [ ! -d $L/debs ]; then mkdir -p $L/debs; xorriso -osirrox on -indev $L/serveur-test.iso -extract /barbacane/debs $L/debs >/dev/null 2>&1; chmod -R u+w $L/debs; fi
  echo "CONSTRUCTION OK"
fi
if [ "$etape" != construire ]; then
  rm -rf $L/qemu
  timeout 90m bash tests/serveur/qemu-serveur.sh $L/serveur-test.iso $L/qemu $L/pki
  echo "QEMU FIN $?"
fi
echo "LAB FIN"
