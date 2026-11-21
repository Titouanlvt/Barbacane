#!/bin/bash
# ISO serveur : la passerelle.conf écrite par configurer-serveur.sh doit être acceptée par la VRAIE
# passerelle (défaut de la v2.0.0 brouillon : port_enrolement, cle_ca_bornes et registre absents,
# la passerelle refusait de démarrer). Exécute la fonction de génération (passerelle-conf.sh, celle
# que source configurer-serveur.sh), vérifie que les chemins sont ceux montés par le quadlet,
# puis fait passer au fichier les contrôles de démarrage (--verifier-config) avec une PKI de TEST.
#   tests/iso/serveur-config.sh [BINAIRE_PASSERELLE]   (défaut : $CARGO_TARGET_DIR|target /debug)
# Prérequis : openssl (racine-test.sh).
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=$(realpath "${1:-${CARGO_TARGET_DIR:-target}/debug/barbacane-passerelle}")
D=serveur/iso/fichiers/usr/share/barbacane-serveur
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
ko=0
echec() { echo "ÉCHEC : $*" >&2; ko=1; }

# 1. configurer-serveur.sh utilise bien cette fonction, avec les deux ports.
grep -q '^\. /usr/share/barbacane-serveur/passerelle-conf\.sh$' serveur/iso/configurer-serveur.sh \
    || echec "configurer-serveur.sh ne source pas passerelle-conf.sh"
# shellcheck disable=SC2016  # motif littéral
grep -q '^ecrire_conf_passerelle "\$H/pki/passerelle.conf" "\$PORT" "\$PORT_ENROLEMENT"$' serveur/iso/configurer-serveur.sh \
    || echec "configurer-serveur.sh n'écrit pas passerelle.conf avec les deux ports"
# shellcheck source=/dev/null
. "$D/passerelle-conf.sh"
mkdir -p "$W/racine/pki" "$W/racine/etat"
ecrire_conf_passerelle "$W/racine/pki/passerelle.conf" 43117 43118
if ecrire_conf_passerelle "$W/x.conf" 43117 43117 2>/dev/null; then echec "ports identiques acceptés"; fi

# 2. Chemins : sous /pki (lecture seule) ou /etat (écriture), les deux montés par le quadlet ;
#    les deux ports publiés par le quadlet et ouverts par le pare-feu.
Q=$D/barbacane-passerelle.container
grep -q '^Volume=%h/pki:/pki:ro$' "$Q" || echec "quadlet : /pki non monté"
grep -q '^Volume=%h/etat:/etat:rw$' "$Q" || echec "quadlet : /etat non monté en écriture"
grep -q '^PublishPort=@IP_BORNES@:@PORT@:@PORT@$' "$Q" || echec "quadlet : port de service non publié"
grep -q '^PublishPort=@IP_BORNES@:@PORT_ENROLEMENT@:@PORT_ENROLEMENT@$' "$Q" || echec "quadlet : port d'enrôlement non publié"
grep -q 'tcp dport { @PORT@, @PORT_ENROLEMENT@ } ct state new accept' "$D/nftables.conf.modele" \
    || echec "nftables : les deux ports ne sont pas ouverts"
for k in chaine_serveur cle_serveur ca_bornes cle_ca_bornes crl_bornes registre; do
    v=$(sed -n "s/^$k = //p" "$W/racine/pki/passerelle.conf")
    [[ "$v" =~ ^/(pki|etat)/ ]] || echec "$k = $v : hors des volumes du quadlet"
done
for k in crl_bornes registre; do # écrits par la passerelle (CRL republiée, registre)
    sed -n "s/^$k = //p" "$W/racine/pki/passerelle.conf" | grep -q '^/etat/' || echec "$k doit être dans /etat (écriture)"
done

# 3. PKI de TEST déposée comme le fait configurer-serveur.sh (noms de build-iso-serveur.sh).
bash serveur/pki/racine-test.sh "$W/pki" >/dev/null 2>&1
cp "$W/pki/serveur/chaine.pem" "$W/racine/pki/chaine.pem"
cp "$W/pki/serveur/cle.pem" "$W/racine/pki/cle.pem"
cp "$W/pki/ca-bornes/cert.pem" "$W/racine/pki/ca-bornes.pem"
cp "$W/pki/ca-bornes/cle.pem" "$W/racine/pki/cle-ca-bornes.pem"
cp "$W/pki/ca-bornes/crl.pem" "$W/racine/etat/crl-bornes.pem"
# Vue du conteneur : /pki et /etat → dossiers temporaires.
sed -e "s| = /pki/| = $W/racine/pki/|" -e "s| = /etat/| = $W/racine/etat/|" \
    "$W/racine/pki/passerelle.conf" > "$W/vue.conf"
if sortie=$("$BIN" --verifier-config "$W/vue.conf" 2>&1); then
    echo "$sortie"
else
    echec "passerelle : configuration refusée : $sortie"
fi
[ -d "$W/racine/etat/registre" ] || echec "registre non créé"

[ "$ko" = 0 ] && echo "OK : passerelle.conf de l'ISO serveur acceptée par la passerelle"
exit "$ko"
