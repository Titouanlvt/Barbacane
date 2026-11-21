#!/bin/bash
# PKI de TEST Barbacane (politique-certification.md §1–§3, §9 ; décisions D6, D7, D8).
#
#   racine-test.sh [--cas-de-test] [--nom-serveur NOM] [--ip-serveur IP]… [--site SITE] DOSSIER_DE_SORTIE
#
# Produit : racine TEST (P-384) → CA « bornes », CA « serveur » et CA « administrateurs »
#           (P-384, signées SHA-384) → certificat serveur, certificat de borne et certificat
#           d'administrateur (P-256) ; CRL de chaque CA (7 jours). Tous les noms portent
#           « TEST — NE PAS UTILISER EN PRODUCTION ».
# La CA administrateurs est l'ancre de l'interface web (barbacane-web : ca_administrateurs =
# ca-administrateurs/cert.pem, crl_administrateurs = ca-administrateurs/crl.pem) ; le compte
# se lie au certificat par « barbacane-web compte admin-01 administrateur
# administrateurs/admin-01.cert.pem » (docs/suite/serveur-web.md §3).
# --ip-serveur IP : adresse IPv4 ajoutée au SAN du certificat serveur (répétable) ; l'adresse
#                 d'administration de l'ISO serveur (--ip-admin) est requise pour que la Console,
#                 ouverte par son adresse, soit vérifiable contre la racine (curl --cacert).
# --cas-de-test : ajoute une borne et un administrateur révoqués, et une CRL bornes déjà
#                 expirée (tests de la passerelle et de l'interface web).
#
# À lancer sur une VM barbacane-9xx SANS carte réseau (D7). La sortie n'est JAMAIS dans un
# dépôt git : le script refuse. Clés privées en clair (TEST uniquement), droits 0600.
set -euo pipefail

O_TEST="Barbacane TEST — NE PAS UTILISER EN PRODUCTION"
NOM_SERVEUR="passerelle.barbacane.invalid"
SITE="site-1"
CAS_DE_TEST=0
SAN_SERVEUR=""

usage() { echo "usage : $0 [--cas-de-test] [--nom-serveur NOM] [--site SITE] DOSSIER" >&2; exit 2; }
while [ $# -gt 0 ]; do
	case "$1" in
	--cas-de-test) CAS_DE_TEST=1; shift ;;
	--nom-serveur) NOM_SERVEUR="${2:?}"; shift 2 ;;
	--site) SITE="${2:?}"; shift 2 ;;
	--ip-serveur)
		[[ "${2:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "adresse IPv4 invalide" >&2; exit 2; }
		SAN_SERVEUR="${SAN_SERVEUR},IP:$2"; shift 2 ;;
	-*) usage ;;
	*) break ;;
	esac
done
[ $# -eq 1 ] || usage
SORTIE="$1"

# Noms restreints (ils entrent dans des configurations openssl) : pas d'injection possible.
[[ "$NOM_SERVEUR" =~ ^[a-z0-9.-]+$ ]] || { echo "nom de serveur invalide" >&2; exit 2; }
[[ "$SITE" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || { echo "site invalide (a-z, 0-9, -, 1 à 32)" >&2; exit 2; }

mkdir -p "$SORTIE"
SORTIE="$(cd "$SORTIE" && pwd)"
if git -C "$SORTIE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "refus : $SORTIE est dans un dépôt git (aucune clé ne doit y entrer)" >&2
	exit 1
fi
if [ -n "$(ls -A "$SORTIE")" ]; then
	echo "refus : $SORTIE n'est pas vide" >&2
	exit 1
fi
umask 077
cd "$SORTIE"

# Configuration openssl commune (profils de politique-certification.md §3).
cat >openssl.cnf <<CNF
[ req ]
distinguished_name = dn
string_mask = utf8only
utf8 = yes
prompt = no
[ dn ]
CN = inutilise

[ ca ]
default_ca = ca_courante
[ ca_courante ]
dir = \$ENV::CA_DIR
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
new_certs_dir = \$dir/emis
certificate = \$dir/cert.pem
private_key = \$dir/cle.pem
default_md = sha384
policy = politique_libre
unique_subject = no
copy_extensions = none
email_in_dn = no
utf8 = yes
string_mask = utf8only
[ politique_libre ]
CN = supplied
OU = optional
O = supplied

[ v3_racine ]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_ca_bornes ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:.bornes.barbacane.invalid
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_ca_serveur ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:${NOM_SERVEUR}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_ca_administrateurs ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_administrateur ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_serveur ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:${NOM_SERVEUR}${SAN_SERVEUR}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_borne ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = \$ENV::SAN_BORNE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ crl_ext ]
authorityKeyIdentifier = keyid:always
CNF
export OPENSSL_CONF="$SORTIE/openssl.cnf"
export CA_DIR="$SORTIE/racine" SAN_BORNE="DNS:inutilise.bornes.barbacane.invalid"

nouvelle_ca() { # dossier
	mkdir -p "$1/emis"
	: >"$1/index.txt"
	openssl rand -hex 16 >"$1/serial"
	echo 01 >"$1/crlnumber"
}
cle() { # fichier courbe
	openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -pkeyopt ec_param_enc:named_curve -out "$1"
}
signer() { # ca extensions jours demande sortie
	CA_DIR="$SORTIE/$1" openssl ca -batch -notext -extensions "$2" -days "$3" -in "$4" -out "$5"
}

# 1. Racine (10 ans), autosignée.
nouvelle_ca racine
cle racine/cle.pem P-384
openssl req -new -x509 -sha384 -days 3650 -key racine/cle.pem -extensions v3_racine \
	-subj "/CN=Racine Barbacane TEST/O=${O_TEST}" -out racine/cert.pem

# 2. CA intermédiaires (3 ans).
for ca in bornes serveur administrateurs; do
	nouvelle_ca "ca-$ca"
	cle "ca-$ca/cle.pem" P-384
	openssl req -new -sha384 -key "ca-$ca/cle.pem" -subj "/CN=CA ${ca} Barbacane TEST/O=${O_TEST}" -out "ca-$ca/demande.pem"
	signer racine "v3_ca_$ca" 1095 "ca-$ca/demande.pem" "ca-$ca/cert.pem"
done

# 3. Certificat serveur (1 an) et chaîne présentée par la passerelle.
mkdir -p serveur
cle serveur/cle.pem P-256
openssl req -new -sha256 -key serveur/cle.pem -subj "/CN=serveur ${NOM_SERVEUR}/OU=${SITE}/O=${O_TEST}" -out serveur/demande.pem
signer ca-serveur v3_serveur 365 serveur/demande.pem serveur/cert.pem
cat serveur/cert.pem ca-serveur/cert.pem >serveur/chaine.pem

# 4. Certificats de borne (90 jours). La clé réelle sera dans le TPM (hors de ce script).
mkdir -p bornes
borne() { # identifiant
	local uuid
	uuid="$(cat /proc/sys/kernel/random/uuid)"
	cle "bornes/$1.cle.pem" P-256
	openssl req -new -sha256 -key "bornes/$1.cle.pem" -subj "/CN=borne $1/OU=${SITE}/O=${O_TEST}" -out "bornes/$1.demande.pem"
	SAN_BORNE="URI:urn:barbacane:borne:${SITE}:${uuid}, DNS:${uuid}.bornes.barbacane.invalid" \
		signer ca-bornes v3_borne 90 "bornes/$1.demande.pem" "bornes/$1.cert.pem"
}
borne borne-01

# 5. Certificats d'administrateur (1 an), pour l'écoute mTLS de barbacane-web.
mkdir -p administrateurs
administrateur() { # identifiant
	cle "administrateurs/$1.cle.pem" P-256
	openssl req -new -sha256 -key "administrateurs/$1.cle.pem" -subj "/CN=administrateur $1/OU=${SITE}/O=${O_TEST}" -out "administrateurs/$1.demande.pem"
	signer ca-administrateurs v3_administrateur 365 "administrateurs/$1.demande.pem" "administrateurs/$1.cert.pem"
}
administrateur admin-01

# 6. Cas de test : une borne révoquée, puis la CRL (7 jours) et une CRL expirée.
if [ "$CAS_DE_TEST" = 1 ]; then
	borne borne-revoquee
	CA_DIR="$SORTIE/ca-bornes" openssl ca -revoke bornes/borne-revoquee.cert.pem -crl_reason keyCompromise
	administrateur admin-revoque
	CA_DIR="$SORTIE/ca-administrateurs" openssl ca -revoke administrateurs/admin-revoque.cert.pem -crl_reason keyCompromise
fi
CA_DIR="$SORTIE/ca-bornes" openssl ca -gencrl -crldays 7 -crlexts crl_ext -out ca-bornes/crl.pem
CA_DIR="$SORTIE/ca-serveur" openssl ca -gencrl -crldays 7 -crlexts crl_ext -out ca-serveur/crl.pem
CA_DIR="$SORTIE/ca-administrateurs" openssl ca -gencrl -crldays 7 -crlexts crl_ext -out ca-administrateurs/crl.pem
if [ "$CAS_DE_TEST" = 1 ]; then
	CA_DIR="$SORTIE/ca-bornes" openssl ca -gencrl -crlexts crl_ext \
		-crl_lastupdate "$(date -u -d '-10 days' +%Y%m%d%H%M%SZ)" \
		-crl_nextupdate "$(date -u -d '-3 days' +%Y%m%d%H%M%SZ)" -out ca-bornes/crl-expiree.pem
fi

# Contrôles : chaque chaîne se vérifie, les CRL bornes et administrateurs sont valides.
openssl verify -CAfile racine/cert.pem -untrusted ca-serveur/cert.pem serveur/cert.pem >/dev/null
openssl verify -CAfile racine/cert.pem -untrusted ca-bornes/cert.pem bornes/borne-01.cert.pem >/dev/null
cat racine/cert.pem ca-bornes/cert.pem ca-bornes/crl.pem >controle.pem
openssl verify -crl_check -CAfile controle.pem bornes/borne-01.cert.pem >/dev/null
openssl verify -CAfile racine/cert.pem -untrusted ca-administrateurs/cert.pem administrateurs/admin-01.cert.pem >/dev/null
cat racine/cert.pem ca-administrateurs/cert.pem ca-administrateurs/crl.pem >controle.pem
openssl verify -crl_check -CAfile controle.pem administrateurs/admin-01.cert.pem >/dev/null
rm -f controle.pem ./*/demande.pem bornes/*.demande.pem administrateurs/*.demande.pem

echo "PKI de TEST créée dans $SORTIE"
echo "Empreinte SHA-256 de la racine TEST :"
openssl x509 -in racine/cert.pem -noout -fingerprint -sha256
