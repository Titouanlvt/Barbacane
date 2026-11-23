#!/bin/bash
# shellcheck disable=SC2015 # « test && ok || echec » : ok ne peut pas échouer
# Banc de mise à jour d'un serveur 2.2.0 → 2.3.0 (vrais binaires des deux versions, mêmes fichiers) :
#   1. 2.2.0 : passerelle, borne de test enrôlée (jeton, demande, validation par barbacane-registre,
#      retrait), 2 rapports de passage, connexion à la Console, journal scellé (schéma 1) ;
#   2. deux rapports « vieillis » de 400 jours (date de réception réécrite : simule un serveur en
#      service depuis plus d'un an) ;
#   3. 2.3.0 sur les MÊMES fichiers : données conservées (passages, comptes, journal), réglage de
#      conservation posé (365 jours) AVEC préavis : la première passe de conservation ne purge RIEN,
#      même les rapports de plus d'un an ; journal 2.2.0 vérifié puis rangé en segment (ancre
#      signée) ; après le préavis (date d'effet échue), seuls les rapports de plus de 365 jours
#      sont purgés, la purge est tracée ; retour arrière : la 2.2.0 signale le journal v2 (jamais
#      de lecture silencieuse).
#   tests/serveur/migration-v230.sh BINS_2_2_0 BINS_2_3_0 DOSSIER
# BINS_* : dossiers contenant barbacane-passerelle, barbacane-registre, barbacane-web et
# barbacane-audit de chaque version. Prérequis : openssl, curl.
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
MDP="Banc de migration 2.2.0 vers 2.3.0"
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
crl_bornes = $W/etat/crl-bornes.pem
registre = $W/etat/registre
FIN
cp "$P/ca-bornes/crl.pem" "$W/etat/crl-bornes.pem"
cat > "$W/web.conf" <<FIN
adresse = 127.0.0.1
port = $PW
chaine_serveur = $P/serveur/chaine.pem
cle_serveur = $P/serveur/cle.pem
ca_administrateurs = $W/web/ca-administrateurs.pem
crl_administrateurs = $W/web/crl-administrateurs.pem
cle_ca_administrateurs = $W/web/cle-ca-administrateurs.pem
comptes = $W/web/comptes
passerelle = $W/passerelle.conf
cle_audit_publique = $W/web/cle-audit.pub
FIN
R=$W/etat/registre J=$R/audit.jsonl
U=https://127.0.0.1:$PW
PIDS=()
arreter() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; PIDS=(); }
trap arreter EXIT
lancer_web() { # BINS
    "$1/barbacane-web" "$W/web.conf" >> "$W/web.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 40); do
        curl --silent --insecure --max-time 5 --cert "$P/administrateurs/admin-01.cert.pem" --key "$P/administrateurs/admin-01.cle.pem" \
            -o /dev/null "$U/connexion" 2>/dev/null && return 0
        sleep 0.25
    done
    echo "Console non démarrée : $(tail -n 5 "$W/web.log")" >&2; return 1
}
C=(--silent --max-time 30 --insecure --cert "$P/administrateurs/admin-01.cert.pem" --key "$P/administrateurs/admin-01.cle.pem")
champ() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }
connexion() {
    rm -f "$W/jar"
    curl "${C[@]}" -c "$W/jar" -o "$W/cx.html" "$U/connexion" || true
    curl "${C[@]}" -b "$W/jar" -c "$W/jar" -o /dev/null --data-urlencode "csrf=$(champ "$W/cx.html" csrf)" \
        --data-urlencode identifiant=admin-01 --data-urlencode "mot_de_passe=$MDP" "$U/connexion" || true
    curl "${C[@]}" -b "$W/jar" -o "$W/tableau.html" -w '%{http_code}' "$U/tableau" || true
}
nb_passages() { grep -c . "$R/passages/index.jsonl" 2>/dev/null || echo 0; }

echo "== 1. Serveur 2.2.0 : borne de test, 4 rapports de passage, Console"
"$A/barbacane-passerelle" "$W/passerelle.conf" >> "$W/passerelle.log" 2>&1 &
PIDS+=($!); sleep 1
H=passerelle.barbacane.invalid
CP=(--silent --max-time 30 --cacert "$P/racine/cert.pem")
jeton=$("$A/barbacane-registre" "$W/passerelle.conf" jeton labo | tail -n 1)
openssl ecparam -name prime256v1 -genkey -noout -out "$W/borne.cle"
openssl req -new -key "$W/borne.cle" -sha256 -subj "/CN=borne" -out "$W/borne.csr"
csr=$(sed ':a;N;$!ba;s/\n/\\n/g' "$W/borne.csr")
r=$(curl "${CP[@]}" --resolve "$H:$PE:127.0.0.1" -H 'Content-Type: application/json' \
    --data "{\"version\":1,\"jeton\":\"${jeton#*-}\",\"csr_pem\":\"$csr\\n\",\"version_logiciel\":\"2.2.0\"}" "https://$H:$PE/enrolement/demande" || true)
id=$(sed -n 's/.*"demande_id":"\([0-9a-f]*\)".*/\1/p' <<<"$r"); emp=$(sed -n 's/.*"empreinte":"\([0-9a-f]*\)".*/\1/p' <<<"$r")
"$A/barbacane-registre" "$W/passerelle.conf" valider "$id" "$emp" borne-migration >/dev/null
r=$(curl "${CP[@]}" --resolve "$H:$PE:127.0.0.1" -H 'Content-Type: application/json' --data "{\"version\":1,\"demande_id\":\"$id\"}" "https://$H:$PE/enrolement/retrait" || true)
printf '%b' "$(sed -n 's/.*"certificat_pem":"\([^"]*\)".*/\1/p' <<<"$r")" > "$W/borne.pem"
n=0
for v in sain menace sain sain; do
    r=$(curl "${CP[@]}" --cert "$W/borne.pem" --key "$W/borne.cle" --resolve "$H:$PG:127.0.0.1" -H 'Content-Type: application/json' \
        --data "{\"version\":1,\"id\":\"$(cat /proc/sys/kernel/random/uuid)\",\"horodatage\":$(date +%s),\"verdict\":\"$v\",\"support\":\"$(printf s | sha256sum | cut -c1-64)\",\"partie\":1,\"parties\":1,\"fichiers\":[{\"taille\":3,\"sha256\":\"$(printf '%064d' 1)\",\"verdict\":\"$v\"}]}" \
        "https://$H:$PG/rapport/passage" || true)
    grep -q '"deja_recu":false' <<<"$r" && n=$((n + 1))
done
[ "$n" = 4 ] && ok "2.2.0 : borne enrôlée par le protocole réel, 4 rapports de passage reçus" || echec "2.2.0 : $n/4 rapports ($r)"
lancer_web "$A"
[ "$(connexion)" = 200 ] && ok "2.2.0 : Console, admin-01 connecté" || echec "2.2.0 : connexion"
arreter
"$A/barbacane-audit" sceller "$J" "$W/audit/cle-audit.pem" >/dev/null
"$A/barbacane-audit" verifier "$J" "$W/audit/cle-audit.pub" >/dev/null && ok "2.2.0 : journal scellé et vérifié ($(wc -l < "$J") lignes, schéma 1)" || echec "2.2.0 : journal"
grep -q '"v":2' "$J" && echec "2.2.0 : ligne de schéma 2 inattendue" || true
# Deux rapports « reçus » il y a 400 jours (serveur en service depuis plus d'un an).
VIEUX=$(( $(date +%s) - 400 * 86400 ))
mapfile -t f < <(find "$R/passages" -name '*.json' | sort | head -2)
for x in "${f[@]}"; do
    sed -i "s/^{\"recu_le\":[0-9]*/{\"recu_le\":$VIEUX/" "$x"
    i=$(basename "$x" .json); i=${i%-*}
    sed -i "/\"id\":\"$i\"/ s/\"recu_le\":[0-9]*/\"recu_le\":$VIEUX/" "$R/passages/index.jsonl"
done
[ "$(grep -c "\"recu_le\":$VIEUX" "$R/passages/index.jsonl")" = 2 ] && ok "2 rapports vieillis de 400 jours (date de réception réécrite)" || echec "vieillissement des rapports"
lignes_avant=$(wc -l < "$J"); comptes_avant=$(sha256sum < "$W/web/comptes")

echo "== 2. Serveur 2.3.0 sur les mêmes fichiers"
"$N/barbacane-passerelle" "$W/passerelle.conf" >> "$W/passerelle.log" 2>&1 &
PIDS+=($!); sleep 1
lancer_web "$N"
[ "$(connexion)" = 200 ] && ok "2.3.0 : Console, admin-01 connecté avec le même mot de passe et le même certificat" || echec "2.3.0 : connexion"
curl "${C[@]}" -b "$W/jar" -o "$W/passages.html" "$U/passages" || true
[ "$(grep -o 'borne-migration' "$W/passages.html" | wc -l)" -ge 4 ] && ok "2.3.0 : les 4 rapports de passage de la 2.2.0 sont affichés" || echec "2.3.0 : passages perdus"
curl "${C[@]}" -b "$W/jar" -o "$W/journal.html" "$U/journal" || true
grep -q '365 jours' "$W/journal.html" && grep -q 'aucune purge avant le' "$W/journal.html" \
    && ok "2.3.0 : conservation posée à 365 jours avec préavis de 7 jours (Console)" || echec "2.3.0 : page Conservation"
grep -q '"conservation_reglee":{"jours":365' "$J" && grep -q 'premier-demarrage-2.3.0' "$J" \
    && ok "2.3.0 : pose du réglage inscrite au journal (premier-demarrage-2.3.0)" || echec "2.3.0 : pose du réglage non journalisée"
[ "$(sha256sum < "$W/web/comptes")" = "$comptes_avant" ] && ok "fichier des comptes inchangé" || echec "fichier des comptes modifié"
o=$("$N/barbacane-registre" "$W/passerelle.conf" conservation)
[ "$(nb_passages)" = 4 ] && grep -q 'préavis' <<<"$o" \
    && ok "première passe de conservation : AUCUNE purge (préavis), même les rapports de 400 jours : « $o »" || echec "première passe : $o ($(nb_passages) passages)"
o=$("$N/barbacane-audit" conservation "$J" "$W/audit/cle-audit.pem" "$R")
grep -q 'préavis' <<<"$o" && ok "2.3.0 : journal d'audit : aucune purge pendant le préavis" || echec "audit pendant le préavis : $o"
"$N/barbacane-audit" tourner "$J" "$W/audit/cle-audit.pem" --forcer >/dev/null
o=$("$N/barbacane-audit" verifier "$J" "$W/audit/cle-audit.pub")
[ -n "$(ls "$R/audit-segments" 2>/dev/null)" ] && grep -q 'Journal intègre' <<<"$o" && [ "$(head -n "$lignes_avant" "$R"/audit-segments/*.jsonl | grep -c '"v":1')" -ge 1 ] \
    && ok "journal 2.2.0 (schéma 1) relu, rangé en segment scellé, chaîne vérifiée de bout en bout : $o" || echec "rotation du journal 2.2.0 : $o"
"$N/barbacane-audit" structurer "$J" srv-migration > "$W/structure.jsonl"
[ "$(wc -l < "$W/structure.jsonl")" -ge "$lignes_avant" ] && head -n 1 "$W/structure.jsonl" | grep -q '"schema":"barbacane.journal/1"' \
    && ok "journal 2.2.0 exporté au format structuré" || echec "format structuré du journal 2.2.0"
# Préavis écoulé (date d'effet ramenée dans le passé) : seuls les rapports de plus de 365 jours partent.
sed -i 's/"effective_le": [0-9]*/"effective_le": 1/' "$R/conservation.json"
o=$("$N/barbacane-registre" "$W/passerelle.conf" conservation)
[ "$(nb_passages)" = 2 ] && grep -q '2 rapport(s) de passage purgé(s)' <<<"$o" \
    && ok "après le préavis : les 2 rapports de 400 jours purgés, les 2 récents gardés" || echec "purge après préavis : $o ($(nb_passages))"
grep -q '"purge":{"objet":"passages","nombre":2' "$J" && ok "purge des passages tracée au journal d'audit" || echec "purge non tracée"
"$N/barbacane-audit" verifier "$J" "$W/audit/cle-audit.pub" >/dev/null && ok "chaîne toujours intègre après la purge" || echec "chaîne après purge"
arreter
echo "== 3. Retour arrière vers la 2.2.0"
set +e; "$A/barbacane-audit" verifier "$J" "$W/audit/cle-audit.pub" > "$W/retour.txt" 2>&1; c=$?; set -e
[ "$c" != 0 ] && ok "retour arrière : la 2.2.0 signale le journal 2.3.0 (code $c : $(head -c 120 "$W/retour.txt")), jamais de lecture silencieuse" \
    || echec "retour arrière : la 2.2.0 accepte un journal qu'elle ne sait pas lire"
[ "$ko" = 0 ] && echo "MIGRATION 2.2.0 → 2.3.0 : OK"
exit "$ko"
