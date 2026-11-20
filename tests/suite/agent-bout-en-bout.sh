#!/bin/bash
# Bout en bout SANS VM, avec les VRAIS binaires : passerelle de test (PKI de TEST de
# serveur/pki/racine-test.sh) + barbacane-agent ; administration par barbacane-registre.
#   1. jeton → demande déposée → empreinte publiée par l'agent ;
#   2. validation par barbacane-registre (empreinte retapée) → certificat → battement visible
#      dans la supervision ;
#   3. passerelle arrêtée → agent en mode dégradé (il ne s'arrête pas) → passerelle relancée →
#      liaison reprise ;
#   4. révocation → l'agent passe en « refusee » proprement (processus vivant, plus de connexion).
# Usage : tests/suite/agent-bout-en-bout.sh [DOSSIER_DE_TRAVAIL]   (cargo, openssl)
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

cargo build -q -p barbacane-passerelle --bins -p barbacane-agent
P=$CIBLE/debug/barbacane-passerelle R=$CIBLE/debug/barbacane-registre A=$CIBLE/debug/barbacane-agent

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

etape "1. jeton (barbacane-registre) → demande déposée"
attendre non_enrolee 10
"$R" "$W/passerelle.conf" jeton site-1 | tee "$W/jeton.txt"
grep -E '^[0-9]+-[A-Z2-7]{26}$' "$W/jeton.txt" > "$W/agent/jeton"
attendre attente_validation 20
[ ! -e "$W/agent/jeton" ] || echec "jeton non consommé"
EMPREINTE=$(sed -n 's/.*"empreinte": "\([0-9a-f]\{64\}\)".*/\1/p' "$W/run/etat.json")
[ -n "$EMPREINTE" ] || echec "empreinte non publiée par l'agent"
echo "empreinte affichée par la borne : $EMPREINTE"
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
echo "OK : enrôlement validé, battement supervisé, mode dégradé puis reprise, révocation → refusée (dossier : $W)"
