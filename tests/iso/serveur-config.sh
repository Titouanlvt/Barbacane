#!/bin/bash
# ISO serveur : la passerelle.conf écrite par configurer-serveur.sh doit être acceptée par la VRAIE
# passerelle (défaut de la v2.0.0 brouillon : port_enrolement, cle_ca_bornes et registre absents,
# la passerelle refusait de démarrer). Exécute la fonction de génération (passerelle-conf.sh, celle
# que source configurer-serveur.sh), vérifie que les chemins sont ceux montés par le quadlet,
# puis fait passer au fichier les contrôles de démarrage (--verifier-config) avec une PKI de TEST.
# Idem pour l'interface web (web.conf, web-conf.sh, barbacane-web --verifier-config avec la CA des
# administrateurs de TEST, un compte produit par « barbacane-web compte » et une clé d'audit de
# « barbacane-audit cle ») et pour registre.conf (vue hôte : « barbacane-registre … demandes »).
#   tests/iso/serveur-config.sh [BINAIRE_PASSERELLE]   (défaut : $CARGO_TARGET_DIR|target /debug ;
#     barbacane-web, barbacane-registre et barbacane-audit sont pris dans le même dossier)
# Prérequis : openssl (racine-test.sh).
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=$(realpath "${1:-${CARGO_TARGET_DIR:-target}/debug/barbacane-passerelle}")
BINS=$(dirname "$BIN")
for b in barbacane-web barbacane-registre barbacane-audit; do
    [ -x "$BINS/$b" ] || { echo "ÉCHEC : $BINS/$b absent (cargo build -p barbacane-passerelle -p barbacane-web -p barbacane-audit)" >&2; exit 1; }
done
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
# Adresse d'administration dans le SAN du certificat serveur (Console ouverte par son adresse).
bash serveur/pki/racine-test.sh --ip-serveur 10.99.0.1 "$W/pki" >/dev/null 2>&1
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

# 4. Interface web : configurer-serveur.sh écrit web.conf avec la fonction de web-conf.sh ; quadlet
#    et pare-feu cohérents (adresse et port d'administration, port interne du conteneur).
grep -q '^\. /usr/share/barbacane-serveur/web-conf\.sh$' serveur/iso/configurer-serveur.sh \
    || echec "configurer-serveur.sh ne source pas web-conf.sh"
# shellcheck disable=SC2016  # motif littéral
grep -q '^ecrire_conf_web "\$H/web/web.conf" "\$PORT_WEB"$' serveur/iso/configurer-serveur.sh \
    || echec "configurer-serveur.sh n'écrit pas web.conf"
QW=$D/barbacane-web.container
for l in 'Volume=%h/pki:/pki:ro' 'Volume=%h/web:/web:ro' 'Volume=%h/etat:/etat:rw' \
    'Volume=/var/lib/barbacane-serveur/iso-bornes:/var/lib/barbacane-serveur/iso-bornes:ro' \
    'PublishPort=@IP_ADMIN@:@PORT_ADMIN@:@PORT_WEB@' 'ReadOnly=true' 'DropCapability=all' 'NoNewPrivileges=true' 'Exec=/web/web.conf'; do
    grep -qxF "$l" "$QW" || echec "quadlet web : « $l » absent"
done
grep -q 'iifname "@IF_ADMIN@" ip daddr @IP_ADMIN@ tcp dport @PORT_ADMIN@ ct state new accept' "$D/nftables.conf.modele" \
    || echec "nftables : interface web non ouverte"
# shellcheck source=/dev/null
. "$D/web-conf.sh"
mkdir -p "$W/racine/web"
ecrire_conf_web "$W/racine/web/web.conf" 8443
if ecrire_conf_web "$W/x.conf" 443 2>/dev/null; then echec "port interne < 1024 accepté"; fi
for k in chaine_serveur cle_serveur ca_administrateurs crl_administrateurs cle_ca_administrateurs comptes passerelle cle_audit_publique; do
    v=$(sed -n "s/^$k = //p" "$W/racine/web/web.conf")
    [[ "$v" =~ ^/(pki|web)/ ]] || echec "web : $k = $v : hors des volumes du quadlet"
done
grep -qx 'passerelle = /pki/passerelle.conf' "$W/racine/web/web.conf" || echec "web : passerelle.conf de la passerelle non partagée"
grep -qx 'iso_bornes = /var/lib/barbacane-serveur/iso-bornes' "$W/racine/web/web.conf" || echec "web : ISO des bornes"
grep -qx 'outil_iso_borne = /usr/local/sbin/barbacane-iso-borne' "$W/racine/web/web.conf" || echec "web : outil de remaster"
# Fichiers déposés comme le font build-iso-serveur.sh et configurer-serveur.sh (VRAIS binaires).
cp "$W/pki/ca-administrateurs/cert.pem" "$W/racine/web/ca-administrateurs.pem"
cp "$W/pki/ca-administrateurs/crl.pem" "$W/racine/web/crl-administrateurs.pem"
( umask 077; cp "$W/pki/ca-administrateurs/cle.pem" "$W/racine/web/cle-ca-administrateurs.pem" )
( umask 077; printf 'mot-de-passe-de-test-01\n' | "$BINS/barbacane-web" compte admin-01 administrateur \
    "$W/pki/administrateurs/admin-01.cert.pem" > "$W/racine/web/comptes" ) || echec "barbacane-web compte"
"$BINS/barbacane-audit" cle "$W/audit" >/dev/null || echec "barbacane-audit cle"
cp "$W/audit/cle-audit.pub" "$W/racine/web/cle-audit.pub"
sed -e "s|^passerelle = /pki/passerelle.conf$|passerelle = $W/vue.conf|" -e "s| = /pki/| = $W/racine/pki/|" \
    -e "s| = /web/| = $W/racine/web/|" "$W/racine/web/web.conf" > "$W/vue-web.conf"
if sortie=$("$BINS/barbacane-web" --verifier-config "$W/vue-web.conf" 2>&1); then
    echo "$sortie"
else
    echec "barbacane-web : configuration refusée : $sortie"
fi
# Sans compte valide (fichier lisible par tous) : refus attendu, preuve que le contrôle est réel.
chmod 644 "$W/racine/web/comptes"
if "$BINS/barbacane-web" --verifier-config "$W/vue-web.conf" >/dev/null 2>&1; then echec "web : comptes lisibles par tous acceptés"; fi
chmod 600 "$W/racine/web/comptes"
# Chaîne HTTPS de la Console (v2.0.1) : vraie interface lancée sur la boucle locale, vérifiée contre
# la RACINE de TEST seule (chaîne complète présentée, SAN avec l'adresse d'administration).
PW=$(shuf -i 30000-60000 -n 1)
sed -e "s/^adresse = .*/adresse = 127.0.0.1/" -e "s/^port = .*/port = $PW/" "$W/vue-web.conf" > "$W/vue-web-lo.conf"
"$BINS/barbacane-web" "$W/vue-web-lo.conf" > "$W/web.log" 2>&1 &
PIDW=$!
C=(--silent --max-time 10 --cacert "$W/pki/racine/cert.pem" --cert "$W/pki/administrateurs/admin-01.cert.pem"
    --key "$W/pki/administrateurs/admin-01.cle.pem" -o /dev/null -w '%{http_code}')
code=000
for _ in $(seq 40); do
    code=$(curl "${C[@]}" --connect-to "10.99.0.1:$PW:127.0.0.1:$PW" "https://10.99.0.1:$PW/connexion" 2>/dev/null || true)
    [ "$code" = 000 ] || break
    sleep 0.25
done
if [ "$code" = 200 ]; then echo "Console : HTTPS vérifié contre la racine de TEST (chaîne complète, SAN IP:10.99.0.1)"
else echec "Console : vérification HTTPS contre la racine (curl --cacert) : HTTP $code $(tail -n 3 "$W/web.log")"; fi
# Contre-épreuve : une autre adresse que celle du SAN est refusée par le client (vérification réelle).
code=$(curl "${C[@]}" --connect-to "10.99.0.2:$PW:127.0.0.1:$PW" "https://10.99.0.2:$PW/connexion" 2>/dev/null || true)
[ "$code" = 000 ] || echec "Console : adresse hors SAN acceptée (HTTP $code)"
kill "$PIDW" 2>/dev/null || true; wait "$PIDW" 2>/dev/null || true

# 5. barbacane-registre : vue hôte (registre.conf) des mêmes fichiers.
# shellcheck disable=SC2016  # motif littéral
grep -q '^ecrire_conf_passerelle "\$H/registre.conf" "\$PORT" "\$PORT_ENROLEMENT" "\$H/pki" "\$H/etat"$' serveur/iso/configurer-serveur.sh \
    || echec "configurer-serveur.sh n'écrit pas registre.conf"
grep -q '/var/lib/barbacane-serveur/svc/registre.conf' serveur/iso/fichiers/usr/local/sbin/barbacane-registre \
    || echec "enveloppe barbacane-registre : registre.conf"
ecrire_conf_passerelle "$W/registre.conf" 43117 43118 "$W/racine/pki" "$W/racine/etat"
if sortie=$("$BINS/barbacane-registre" "$W/registre.conf" demandes 2>&1) && grep -qx 'Aucune demande en attente.' <<<"$sortie"; then
    echo "barbacane-registre : $(head -1 <<<"$sortie")"
else
    echec "barbacane-registre (vue hôte) : $sortie"
fi

[ "$ko" = 0 ] && echo "OK : passerelle.conf, web.conf et registre.conf de l'ISO serveur acceptés par les vrais binaires"
exit "$ko"
