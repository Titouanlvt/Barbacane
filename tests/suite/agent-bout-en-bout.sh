#!/bin/bash
# Bout en bout SANS VM, avec les VRAIS binaires : passerelle de test (PKI de TEST de
# serveur/pki/racine-test.sh) + barbacane-agent ; administration par barbacane-registre.
#   1. jeton → demande déposée → empreinte publiée par l'agent ;
#   2. validation par barbacane-registre (empreinte retapée) → certificat → battement visible
#      dans la supervision ;
#   3. passerelle arrêtée → agent en mode dégradé (il ne s'arrête pas) → passerelle relancée →
#      liaison reprise ;
#   4. révocation → l'agent passe en « refusee » proprement (processus vivant, plus de connexion).
# Administration locale par le VRAI barbacane-admind (dry_run) comme l'écran Administration :
#   jeton saisi → op serveur_jeton ; mise à jour diffusée par le serveur → téléchargée par
#   l'agent → op serveur_appliquer_maj (signature vérifiée avec la clé de la borne) →
#   rapport « appliquee » côté serveur ; paquet signé par une autre clé → refusé, « echec ».
# Usage : tests/suite/agent-bout-en-bout.sh [DOSSIER_DE_TRAVAIL]   (cargo, openssl, minisign,
# zstd, python3)
# CARGO_TARGET_DIR respecté. Journal détaillé dans le dossier de travail.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${1:-$(mktemp -d "${TMPDIR:-/tmp}/agent-e2e-XXXXXX")}
mkdir -p "$W"; W=$(cd "$W" && pwd)
[ -z "$(ls -A "$W")" ] || { echo "dossier de travail non vide : $W" >&2; exit 2; }
CIBLE=${CARGO_TARGET_DIR:-$PWD/target}
PIDS=()
fin() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap fin EXIT
etape() { echo "== $*"; }
echec() { echo "ÉCHEC : $*" >&2; echo "--- passerelle"; tail -n 20 "$W/passerelle.log" >&2 || true; echo "--- agent"; tail -n 20 "$W/agent.log" >&2 || true; exit 1; }

cargo build -q -p barbacane-passerelle --bins -p barbacane-agent -p barbacane-admind
P=$CIBLE/debug/barbacane-passerelle R=$CIBLE/debug/barbacane-registre A=$CIBLE/debug/barbacane-agent
D=$CIBLE/debug/barbacane-admind

etape "PKI de TEST et ports"
bash serveur/pki/racine-test.sh "$W/pki" > "$W/pki.log" 2>&1
port_libre() { local p; while :; do p=$(shuf -i 20000-60000 -n 1); ss -Htln "sport = :$p" | grep -q . || { echo "$p"; return; }; done; }
PS=$(port_libre); PE=$(port_libre); [ "$PS" != "$PE" ] || PE=$((PS + 1))
cat > "$W/passerelle.conf" <<C
adresse = 127.0.0.1
port = $PS
port_enrolement = $PE
chaine_serveur = $W/pki/serveur/chaine.pem
cle_serveur = $W/pki/serveur/cle.pem
ca_bornes = $W/pki/ca-bornes/cert.pem
cle_ca_bornes = $W/pki/ca-bornes/cle.pem
crl_bornes = $W/pki/ca-bornes/crl.pem
registre = $W/registre
C
EMPREINTE_CA=$(openssl x509 -in "$W/pki/ca-serveur/cert.pem" -outform DER | sha256sum | cut -d' ' -f1)
cat > "$W/agent.toml" <<C
adresse = "127.0.0.1"
port_enrolement = $PE
port_service = $PS
ca_serveur = "$W/pki/ca-serveur/cert.pem"
empreinte_ca_serveur = "$EMPREINTE_CA"
etat = "$W/agent"
execution = "$W/run"
periode_retrait_s = 1
reessai_max_s = 2
C
mkdir -p "$W/agent" && chmod 700 "$W/agent"

# barbacane-admind (dry_run) : l'administration locale de la borne, profil en ligne.
mkdir -p "$W/cles" "$W/admind"/{etat,import,clamav,yara,listes,rapports,export}
minisign -G -W -p "$W/cles/bornes.pub" -s "$W/cles/bornes.key" > /dev/null
minisign -G -W -p "$W/cles/autre.pub" -s "$W/cles/autre.key" > /dev/null
cat > "$W/admind.toml" <<C
socket = "$W/admind/admin.sock"
socket_group = "$(id -gn)"
state_dir = "$W/admind/etat"
analyzer_config = "$W/admind/analyzer.toml"
analyzer_url = "http://127.0.0.1:9"
import_dir = "$W/admind/import"
export_dir = "$W/admind/export"
reports_dir = "$W/admind/rapports"
clamav_dir = "$W/admind/clamav"
yara_dir = "$W/admind/yara"
listes_dir = "$W/admind/listes"
update_pubkey = "$W/cles/bornes.pub"
agent_config = "$W/agent.toml"
dry_run = true
C
echo 246813 | "$D" -c "$W/admind.toml" --set-pin > /dev/null
"$D" -c "$W/admind.toml" >> "$W/admind.log" 2>&1 & PIDS+=("$!")
for _ in $(seq 50); do [ -S "$W/admind/admin.sock" ] && break; sleep 0.1; done
adm() { python3 -I -c '
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode()); print(s.makefile().readline().strip())' "$W/admind/admin.sock" "$1"; }
TOK=$(adm '{"op":"login","pin":"246813"}' | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')

lancer_passerelle() { "$P" "$W/passerelle.conf" >> "$W/passerelle.log" 2>&1 & PASSERELLE=$!; PIDS+=("$PASSERELLE"); sleep 1; }
lancer_passerelle
"$A" "$W/agent.toml" >> "$W/agent.log" 2>&1 & AGENT=$!; PIDS+=("$AGENT")

# attendre MODE SECONDES
attendre() {
    local i
    for ((i = 0; i < $2; i++)); do
        grep -q "\"mode\": \"$1\"" "$W/run/etat.json" 2>/dev/null && return 0
        sleep 1
    done
    echec "mode « $1 » non atteint en $2 s (état : $(cat "$W/run/etat.json" 2>/dev/null))"
}
vivant() { kill -0 "$AGENT" 2>/dev/null || echec "l'agent s'est arrêté"; }

etape "1. jeton (barbacane-registre) → saisi sur la borne (admind) → demande déposée"
attendre non_enrolee 10
"$R" "$W/passerelle.conf" jeton site-1 | tee "$W/jeton.txt"
JETON=$(grep -E '^[0-9]+-[A-Z2-7]{26}$' "$W/jeton.txt")
REP=$(adm "{\"op\":\"serveur_jeton\",\"token\":\"$TOK\",\"jeton\":\"12-${JETON#*-}\"}")
echo "jeton d'un autre port : $REP"
echo "$REP" | grep -q '"error".*port' || echec "jeton d'un autre port accepté par admind"
REP=$(adm "{\"op\":\"serveur_jeton\",\"token\":\"$TOK\",\"jeton\":\"$(echo "$JETON" | tr '[:upper:]' '[:lower:]')\"}")
echo "$REP"
echo "$REP" | grep -q '"message"' || echec "jeton refusé par admind : $REP"
attendre attente_validation 20
[ ! -e "$W/agent/jeton" ] || echec "jeton non consommé"
EMPREINTE=$(sed -n 's/.*"empreinte": "\([0-9a-f]\{64\}\)".*/\1/p' "$W/run/etat.json")
[ -n "$EMPREINTE" ] || echec "empreinte non publiée par l'agent"
echo "empreinte affichée par la borne : $EMPREINTE"
adm '{"op":"status"}' | python3 -I -c '
import json, sys
s = json.load(sys.stdin)["serveur"]
print("admind → interface :", json.dumps(s["agent"]["mode"]), s["agent"]["empreinte"])
assert s["agent"]["mode"] == "attente_validation" and s["agent"]["empreinte"] == sys.argv[1]' "$EMPREINTE" \
    || echec "état de l'agent non relayé par admind"
stat -c '%a %n' "$W/agent/cle-attente.pem"
[ "$(stat -c %a "$W/agent/cle-attente.pem")" = 600 ] || echec "clé privée non 0600"
sleep 3
grep -q '"mode": "attente_validation"' "$W/run/etat.json" || echec "certificat sans validation"

etape "2. validation par l'administrateur → battement dans la supervision"
"$R" "$W/passerelle.conf" demandes | tee "$W/demandes.txt"
ID=$(awk '/^demande /{print $2; exit}' "$W/demandes.txt")
AFFICHEE=$(sed -n 's/^  empreinte  //p' "$W/demandes.txt" | tr -d ' ')
[ "$AFFICHEE" = "$EMPREINTE" ] || echec "empreinte du registre ($AFFICHEE) ≠ empreinte de la borne"
"$R" "$W/passerelle.conf" valider "$ID" "$EMPREINTE" borne-e2e | tee "$W/validation.txt"
UUID=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$W/validation.txt")
attendre connectee 20
"$R" "$W/passerelle.conf" supervision | tee "$W/supervision-1.txt" || echec "supervision : alerte après le battement"
grep "$UUID" "$W/supervision-1.txt" | grep -q 'active' || echec "borne absente ou inactive dans la supervision"
if grep "$UUID" "$W/supervision-1.txt" | grep -q 'vue=jamais'; then echec "battement non vu par le serveur"; fi

etape "2 bis. mise à jour diffusée par le serveur → reçue → appliquée par l'administrateur → rapportée"
cp "$W/cles/bornes.pub" "$W/registre/maj/cle-bornes.pub"
serveur/maj/barbacane-plancher-prepare --cle "$W/cles/bornes.key" --version-min 100 --sortie "$W/plancher" > /dev/null
"$R" "$W/passerelle.conf" maj-plancher "$W/plancher/plancher.json"
printf '%s  essai.iso\n' abababababababababababababababababababababababababababababababab > "$W/images.sha256"
preparer() { # VERSION CLÉ
    borne/update/barbacane-update-prepare --cle "$W/cles/$2.key" --sortie "$W/paquet-$1" --version "$1" \
        --sans-clamav --images-officielles "$W/images.sha256" > /dev/null
}
preparer 200 bornes
"$R" "$W/passerelle.conf" maj-deposer "$W/paquet-200/barbacane-maj-200.bcu"
"$R" "$W/passerelle.conf" maj-diffuser 200
prete() {
    local i
    for ((i = 0; i < $1; i++)); do
        python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])).get("mise_a_jour") or {}; sys.exit(0 if m.get("prete") and m.get("version_maj")==int(sys.argv[2]) else 1)' "$W/run/etat.json" "$2" 2>/dev/null && return 0
        sleep 1
    done
    echec "mise à jour $2 non reçue en $1 s (état : $(cat "$W/run/etat.json"))"
}
prete 90 200
cmp "$W/agent/maj/barbacane-maj-200.bcu" "$W/paquet-200/barbacane-maj-200.bcu" || echec "paquet reçu différent"
"$R" "$W/passerelle.conf" maj-etat | tee "$W/maj-etat-1.txt"
grep "$UUID" "$W/maj-etat-1.txt" | grep -q telechargee || echec "téléchargement non suivi par le serveur"
[ "$(adm '{"op":"status"}' | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["update_version"])')" = 0 ] \
    || echec "mise à jour appliquée sans décision de l'administrateur"
REP=$(adm "{\"op\":\"serveur_appliquer_maj\",\"token\":\"$TOK\"}")
echo "$REP"
echo "$REP" | grep -q '"version":200' || echec "application refusée : $REP"
attendu_serveur() { # VERSION ÉTAT SECONDES
    local i
    for ((i = 0; i < $3; i++)); do
        "$R" "$W/passerelle.conf" maj-etat > "$W/maj-etat.txt"
        grep "$UUID" "$W/maj-etat.txt" | grep -q "paquet $1  $2" && { cat "$W/maj-etat.txt"; return 0; }
        sleep 1
    done
    echec "le serveur n'a pas reçu « $2 » pour $1 ($(cat "$W/maj-etat.txt"))"
}
attendu_serveur 200 appliquee 90
[ -z "$(ls -A "$W/agent/maj")" ] || echec "dossier de mise à jour de l'agent non soldé"
# Paquet signé par une AUTRE clé que celle des bornes : le serveur le refuse au dépôt ; on
# simule un serveur compromis en le plaçant directement dans le dossier de l'agent → la borne
# le refuse (sa clé), échec rendu à l'agent.
preparer 300 autre
"$R" "$W/passerelle.conf" maj-deposer "$W/paquet-300/barbacane-maj-300.bcu" && echec "serveur : paquet mal signé accepté"
cp "$W/paquet-300/barbacane-maj-300.bcu" "$W/paquet-300/barbacane-maj-300.bcu.minisig" "$W/agent/maj/"
python3 -I -c 'import hashlib,json,os,sys; p=sys.argv[1]; d=open(p,"rb").read(); json.dump({"version_maj":300,"sha256":hashlib.sha256(d).hexdigest(),"taille":len(d)}, open(os.path.join(os.path.dirname(p),"annonce.json"),"w"))' "$W/agent/maj/barbacane-maj-300.bcu"
REP=$(adm "{\"op\":\"serveur_appliquer_maj\",\"token\":\"$TOK\"}")
echo "$REP"
echo "$REP" | grep -q 'signature invalide' || echec "paquet d'une autre clé non refusé : $REP"
grep -q '"echec"' "$W/agent/maj/resultat.json" || echec "échec non rendu à l'agent"
[ "$(adm '{"op":"status"}' | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["update_version"])')" = 200 ] \
    || echec "version installée modifiée par un paquet refusé"
rm -f "$W/agent/maj/"*

etape "3. serveur arrêté → mode dégradé → reprise"
kill "$PASSERELLE"; wait "$PASSERELLE" 2>/dev/null || true
attendre degradee 90
vivant
cat "$W/run/etat.json"; echo
lancer_passerelle
attendre connectee 20
vivant

etape "4. révocation → mode refusée, agent vivant"
"$R" "$W/passerelle.conf" revoquer "$UUID" volee
attendre refusee 90
sleep 5; vivant
cat "$W/run/etat.json"; echo
"$R" "$W/passerelle.conf" supervision | tee "$W/supervision-2.txt" || true
grep "$UUID" "$W/supervision-2.txt" | grep -q 'révoquée' || echec "borne non révoquée dans la supervision"
# Plus aucune connexion après le refus : le journal de la passerelle ne grossit plus.
n1=$(wc -l < "$W/passerelle.log"); sleep 10; n2=$(wc -l < "$W/passerelle.log")
[ "$n1" = "$n2" ] || echec "l'agent refusé continue de se connecter"
echo "OK : jeton par admind, enrôlement validé, battement supervisé, mise à jour reçue puis appliquée par l'administrateur et rapportée, paquet d'une autre clé refusé, mode dégradé puis reprise, révocation → refusée (dossier : $W)"
