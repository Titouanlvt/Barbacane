# shellcheck shell=bash
# Serveur Barbacane : génération de web.conf (barbacane-web), sourcé par configurer-serveur.sh et
# par tests/iso/serveur-config.sh (qui le fait contrôler par le VRAI binaire, --verifier-config).
# Chemins vus DANS le conteneur (barbacane-web.container) :
#   /pki  (lecture seule) : certificat et clé TLS du serveur, passerelle.conf (registre partagé) ;
#   /web  (lecture seule) : CA et CRL des administrateurs (et, facultative, la clé de la CA des
#                           administrateurs : sans elle la Console n'émet aucun certificat),
#                           comptes au format v2.1.0 (importés une fois), clé PUBLIQUE d'audit ;
#   /etat (écriture)      : registre, comptes de la Console et CRL des administrateurs
#                           (registre/administrateurs, v2.2.0), journal d'audit, quarantaine, ISO personnalisées (partagé
#                           avec la passerelle, verrous flock) ;
#   ISO des bornes et outil de remaster : mêmes chemins que sur l'hôte (défauts de barbacane-web).
#   ecrire_conf_web FICHIER PORT_INTERNE
ecrire_conf_web() {
    local f=$1 p=$2
    if ! { [[ "$p" =~ ^[1-9][0-9]{3,4}$ ]] && [ "$p" -ge 1024 ] && [ "$p" -le 65535 ]; }; then
        echo "ÉCHEC : port interne de l'interface web invalide ($p, 1024–65535)" >&2
        return 1
    fi
    cat > "$f" <<FIN
# Écrit par configurer-serveur.sh. Écoute dans le conteneur ; publiée sur l'adresse
# d'administration seulement (docs/suite/serveur-iso.md §6).
adresse = 0.0.0.0
port = $p
chaine_serveur = /pki/chaine.pem
cle_serveur = /pki/cle.pem
ca_administrateurs = /web/ca-administrateurs.pem
crl_administrateurs = /web/crl-administrateurs.pem
cle_ca_administrateurs = /web/cle-ca-administrateurs.pem
comptes = /web/comptes
passerelle = /pki/passerelle.conf
cle_audit_publique = /web/cle-audit.pub
iso_bornes = /var/lib/barbacane-serveur/iso-bornes
outil_iso_borne = /usr/local/sbin/barbacane-iso-borne
FIN
}
