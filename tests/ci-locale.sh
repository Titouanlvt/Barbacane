#!/bin/bash
# CI locale : mêmes vérifications que .github/workflows/ci.yml, en parallèle, sur une VM du lab
# (bu, Debian 13, cargo, shellcheck). La CI GitHub n'est plus qu'une confirmation.
#   tests/ci-locale.sh [--iso]      → résumé, code 0 si tout passe ; journaux dans $CI_JOURNAUX
# SHELLCHECK : binaire à utiliser (même version que la CI GitHub : 0.11 sur ubuntu-latest au 20/11/2026).
# --iso : construit aussi l'ISO (profil hors-ligne) puis tests/iso/hors-ligne.sh et tests/iso/qemu.sh.
# Sur la VM de lab : clamd (AppArmor) doit pouvoir lire le dossier des sources ; pour /travail sur bu :
#   /etc/apparmor.d/local/usr.sbin.clamd ← « /travail/** r, » et « /travail/tmp/** rwk, ». target/ doit être
#   le dossier de compilation (le test e2e attend target/release) : lab/ci-locale-bu.sh y met un lien.
# GARDE_FOU=1 : lance aussi tests/garde-fou/scripts.sh (sudo ; VM jetable seulement).
set -u
cd "$(dirname "$0")/.." || exit 1
J=${CI_JOURNAUX:-$(mktemp -d "${TMPDIR:-/tmp}/ci-locale-XXXXXX")}; mkdir -p "$J"
CIBLE=${CARGO_TARGET_DIR:-$PWD/target}; export CARGO_TARGET_DIR=$CIBLE
# Binaires usbsas des tests : suivre un dossier de compilation déplacé (.cargo/config.toml : target/release)
export USBSAS_BIN_PATH=${USBSAS_BIN_PATH:-$CIBLE/release}
declare -A PID
lancer() { local n=$1; shift; ( timeout "${DELAI:-90m}" bash -c "$*" ) > "$J/$n.log" 2>&1 & PID[$n]=$!; }

# Rapides, indépendants de la compilation
# shellcheck disable=SC2016  # développé par le bash -c de lancer
lancer shellcheck '${SHELLCHECK:-shellcheck} systeme/*.sh systeme/iso/*.sh tests/*.sh tests/*/*.sh borne/update/barbacane-update-*'
lancer fmt 'cargo fmt --all --check'
lancer audit 'command -v cargo-audit >/dev/null || cargo install -q --locked cargo-audit; cargo audit'
[ "${GARDE_FOU:-0}" = 1 ] && lancer garde-fou 'sudo tests/garde-fou/scripts.sh'
# Chaîne compilée (même target : séquentiel pour ne pas se bloquer sur le verrou cargo)
lancer cargo 'set -e
  tests/phase1-mock.sh
  cargo clippy --no-deps --all-targets -p barbacane-client -p barbacane-analyzer -p barbacane-admind -p barbacane-parcours -- -D warnings
  cargo clippy --no-deps --all-targets --workspace
  cargo test
  cargo build -p barbacane-admind && tests/maj/maj.sh
  cargo build -p barbacane-passerelle -p barbacane-web -p barbacane-audit && tests/iso/serveur-config.sh'
if [ "${1:-}" = --iso ]; then
  lancer iso "set -e; systeme/iso/build-iso.sh --sortie '$J/ci.iso' && bash tests/iso/hors-ligne.sh '$J/ci.iso' && bash tests/iso/qemu.sh '$J/ci.iso' '$J/qemu'"
fi

ko=0
for n in "${!PID[@]}"; do
  if wait "${PID[$n]}"; then echo "OK    $n"; else echo "ÉCHEC $n  ($J/$n.log)"; tail -n 15 "$J/$n.log" | sed 's/^/      /'; ko=1; fi
done
echo "journaux : $J"; exit $ko
