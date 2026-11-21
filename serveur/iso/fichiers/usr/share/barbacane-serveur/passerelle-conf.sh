# shellcheck shell=bash
# Serveur Barbacane : génération de passerelle.conf (sourcé par configurer-serveur.sh et par
# tests/iso/serveur-config.sh, qui fait analyser le résultat par la vraie passerelle).
# Chemins vus DANS le conteneur (barbacane-passerelle.container) :
#   /pki  (lecture seule)  : chaîne et clé du serveur, CA bornes (certificat ET clé : la passerelle
#                            signe les certificats des bornes à l'enrôlement), CRL bornes ;
#   /etat (écriture)       : registre des bornes (registre.json, journal d'audit, mises à jour).
# La CRL est republiée par la passerelle à chaque révocation : elle vit donc dans /etat.
#   ecrire_conf_passerelle FICHIER PORT_SERVICE PORT_ENROLEMENT
ecrire_conf_passerelle() {
    local f=$1 ps=$2 pe=$3
    if ! { [[ "$ps" =~ ^[1-9][0-9]{0,4}$ && "$pe" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$ps" -le 65535 ] \
        && [ "$pe" -le 65535 ] && [ "$ps" != "$pe" ]; }; then
        echo "ÉCHEC : ports de la passerelle invalides ($ps, $pe)" >&2
        return 1
    fi
    cat > "$f" <<FIN
# Écrit par configurer-serveur.sh. Ports : service mTLS et enrôlement (D4).
adresse = 0.0.0.0
port = $ps
port_enrolement = $pe
chaine_serveur = /pki/chaine.pem
cle_serveur = /pki/cle.pem
ca_bornes = /pki/ca-bornes.pem
cle_ca_bornes = /pki/cle-ca-bornes.pem
crl_bornes = /etat/crl-bornes.pem
registre = /etat/registre
FIN
}
