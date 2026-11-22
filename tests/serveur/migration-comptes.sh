#!/bin/bash
# shellcheck disable=SC2015 # « test && ok || echec » : ok ne peut pas échouer
# Banc de mise à jour de la Console 2.1.0 → 2.2.0 avec comptes conservés (vrais binaires) :
#   1. fichier des comptes produit par « barbacane-web compte » de la 2.1.0, Console 2.1.0 lancée,
#      connexion d'admin-01 (certificat + mot de passe) ;
#   2. Console 2.2.0 lancée sur les MÊMES fichiers et la MÊME configuration (web.conf de la 2.1.0) :
#      comptes importés sans perte (même mot de passe, même certificat), fichier v2.1.0 intact ;
#   3. web.conf de la 2.2.0 (clé de la CA des administrateurs) : la Console publie la CRL et crée
#      le second administrateur ; redémarrage : rien n'est réimporté, les deux comptes restent.
#   tests/serveur/migration-comptes.sh BINS_2_1_0 BINS_2_2_0 DOSSIER
# BINS_* : dossiers contenant barbacane-web et barbacane-audit de chaque version. Prérequis : openssl, curl.
set -euo pipefail
A=$(realpath "$1"); N=$(realpath "$2"); W=$(realpath -m "$3")
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ko=0
ok() { echo "OK : $*"; }
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
rm -rf "$W"; mkdir -p "$W/web" "$W/etat"
"$REPO/serveur/pki/racine-test.sh" --cas-de-test "$W/pki" >/dev/null
P=$W/pki
cp "$P/ca-administrateurs/cert.pem" "$W/web/ca-administrateurs.pem"
cp "$P/ca-administrateurs/crl.pem" "$W/web/crl-administrateurs.pem"
( umask 077; cp "$P/ca-administrateurs/cle.pem" "$W/web/cle-ca-administrateurs.pem" )
MDP="Banc de migration 2.1.0 vers 2.2.0"
( umask 077; printf '%s\n' "$MDP" | "$A/barbacane-web" compte admin-01 administrateur "$P/administrateurs/admin-01.cert.pem" > "$W/web/comptes" )
"$A/barbacane-audit" cle "$W/audit" >/dev/null
cp "$W/audit/cle-audit.pub" "$W/web/cle-audit.pub"
PG=$(shuf -i 30000-40000 -n 1); PW=$((PG + 1)); PE=$((PG + 2))
cat > "$W/passerelle.conf" <<FIN
adresse = 127.0.0.1
port = $PG
port_enrolement = $PE
chaine_serveur = $P/serveur/chaine.pem
cle_serveur = $P/serveur/cle.pem
ca_bornes = $P/ca-bornes/cert.pem
cle_ca_bornes = $P/ca-bornes/cle.pem
crl_bornes = $P/ca-bornes/crl.pem
registre = $W/etat/registre
FIN
# web.conf tel que l'écrit la 2.1.0 (sans clé de CA).
cat > "$W/web-2.1.0.conf" <<FIN
adresse = 127.0.0.1
port = $PW
chaine_serveur = $P/serveur/chaine.pem
cle_serveur = $P/serveur/cle.pem
ca_administrateurs = $W/web/ca-administrateurs.pem
crl_administrateurs = $W/web/crl-administrateurs.pem
comptes = $W/web/comptes
passerelle = $W/passerelle.conf
cle_audit_publique = $W/web/cle-audit.pub
FIN
{ cat "$W/web-2.1.0.conf"; echo "cle_ca_administrateurs = $W/web/cle-ca-administrateurs.pem"; } > "$W/web-2.2.0.conf"
U=https://127.0.0.1:$PW
PID=''
lancer() { # BINS CONF
    "$1/barbacane-web" "$2" >> "$W/web.log" 2>&1 &
    PID=$!
    for _ in $(seq 40); do
        curl --silent --insecure --max-time 5 --cert "$P/administrateurs/admin-01.cert.pem" --key "$P/administrateurs/admin-01.cle.pem" \
            -o /dev/null "$U/connexion" 2>/dev/null && return 0
        sleep 0.25
    done
    echo "Console non démarrée : $(tail -n 5 "$W/web.log")" >&2; return 1
}
arreter() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap arreter EXIT
C=(--silent --max-time 30 --insecure --cert "$P/administrateurs/admin-01.cert.pem" --key "$P/administrateurs/admin-01.cle.pem")
champ() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }
connexion() { # → code du tableau après connexion (cookies dans $W/jar)
    rm -f "$W/jar"
    curl "${C[@]}" -c "$W/jar" -o "$W/cx.html" "$U/connexion" || true
    curl "${C[@]}" -b "$W/jar" -c "$W/jar" -o /dev/null --data-urlencode "csrf=$(champ "$W/cx.html" csrf)" \
        --data-urlencode identifiant=admin-01 --data-urlencode "mot_de_passe=$MDP" "$U/connexion" || true
    curl "${C[@]}" -b "$W/jar" -o "$W/tableau.html" -w '%{http_code}' "$U/tableau" || true
}
avant=$(sha256sum < "$W/web/comptes")

echo "== 1. Console 2.1.0"
lancer "$A" "$W/web-2.1.0.conf"
[ "$(connexion)" = 200 ] && ok "2.1.0 : admin-01 connecté (certificat + mot de passe), tableau 200" || echec "2.1.0 : connexion"
arreter
[ ! -e "$W/etat/registre/administrateurs/comptes.json" ] && ok "2.1.0 : pas de base de comptes (fichier texte seul)" || echec "2.1.0 : base inattendue"

echo "== 2. Console 2.2.0, même configuration"
lancer "$N" "$W/web-2.1.0.conf"
[ "$(connexion)" = 200 ] && ok "2.2.0 : admin-01 connecté avec le MÊME mot de passe et le MÊME certificat" || echec "2.2.0 : connexion après mise à jour"
curl "${C[@]}" -b "$W/jar" -o "$W/comptes.html" "$U/comptes" || true
grep -q '>admin-01<' "$W/comptes.html" && grep -q 'migration-2.1.0' "$W/comptes.html" \
    && ok "2.2.0 : admin-01 listé dans la Console (créé par migration-2.1.0)" || echec "2.2.0 : compte absent de la page Comptes"
m=$(stat -c %a "$W/etat/registre/administrateurs/comptes.json" 2>/dev/null || echo absent)
[ "$m" = 600 ] && ok "2.2.0 : base registre/administrateurs/comptes.json créée en 0600" || echec "2.2.0 : base des comptes : $m"
[ "$(sha256sum < "$W/web/comptes")" = "$avant" ] && ok "fichier des comptes v2.1.0 intact (retour arrière possible)" || echec "fichier v2.1.0 modifié"
grep -q 'compte(s) importé(s)' "$W/web.log" && ok "journal du service : importation annoncée" || echec "importation non annoncée"
grep -q 'Mot de passe\|argon2' "$W/web.log" && echec "secret dans le journal du service" || ok "aucun secret dans le journal du service"
arreter

echo "== 3. Console 2.2.0, web.conf de la 2.2.0 (clé de la CA)"
lancer "$N" "$W/web-2.2.0.conf"
[ "$(connexion)" = 200 ] && ok "2.2.0 + CA : connexion" || echec "2.2.0 + CA : connexion"
[ -s "$W/etat/registre/administrateurs/crl-administrateurs.pem" ] && ok "CRL des administrateurs publiée par la Console" || echec "CRL non publiée"
curl "${C[@]}" -b "$W/jar" -o "$W/comptes.html" "$U/comptes" || true
code=$(curl "${C[@]}" -b "$W/jar" -o "$W/creation.html" -w '%{http_code}' --data-urlencode "csrf=$(champ "$W/comptes.html" csrf)" \
    --data-urlencode identifiant=admin-02 --data-urlencode role=administrateur "$U/comptes/creer" || true)
[ "$code" = 200 ] && grep -q 'Mot de passe du fichier .p12' "$W/creation.html" && ok "second administrateur créé après la mise à jour" || echec "création : $code"
arreter
lancer "$N" "$W/web-2.2.0.conf"
[ "$(connexion)" = 200 ] && ok "redémarrage : connexion" || echec "redémarrage"
curl "${C[@]}" -b "$W/jar" -o "$W/comptes.html" "$U/comptes" || true
grep -q '>admin-02<' "$W/comptes.html" && ok "redémarrage : admin-01 et admin-02 conservés, aucune réimportation" || echec "redémarrage : admin-02 perdu"
n=$(grep -c 'compte(s) importé(s)' "$W/web.log" || true)
[ "$n" = 1 ] && ok "une seule importation sur trois démarrages en 2.2.0" || echec "$n importations"
arreter
[ "$ko" = 0 ] && echo "MIGRATION COMPTES : OK"
exit "$ko"
