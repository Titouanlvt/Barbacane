#!/bin/bash
# Installe Rust pour CONSTRUIRE Barbacane (poste de construction, jamais la borne), sans exécuter
# de script distant : rustup-init d'une version épinglée, vérifié par une empreinte inscrite ici,
# puis une chaîne d'outils de version fixe. Remplace « curl https://sh.rustup.rs | sh ».
# Mise à jour : changer les valeurs ci-dessous après vérification de l'empreinte publiée
# (https://static.rust-lang.org/rustup/archive/<version>/x86_64-unknown-linux-gnu/rustup-init.sha256).
set -euo pipefail
RUSTUP_VERSION=1.28.2
RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
TOOLCHAIN=${RUST_TOOLCHAIN:-1.100.0}
[ "$(uname -m)" = x86_64 ] || { echo "architecture non prise en charge : $(uname -m)" >&2; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl --proto '=https' --tlsv1.2 -sSf -o "$T/rustup-init" \
    "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init"
echo "$RUSTUP_SHA256  $T/rustup-init" | sha256sum -c --quiet - \
    || { echo "rustup-init : empreinte inattendue, installation refusée" >&2; exit 1; }
chmod +x "$T/rustup-init"
"$T/rustup-init" -y --profile minimal --default-toolchain "$TOOLCHAIN"
