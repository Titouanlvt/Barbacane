#!/bin/bash
# Construit les paquets de production (sans « mock ») : usbsas-server, usbsas-hid, barbacane.
# Sortie : systeme/mkosi/paquets/ (utilisés par install.sh --debs et par mkosi).
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/systeme/mkosi/paquets"
# Outils de compilation installés si absents (ex. conteneur debian:trixie vierge).
# shellcheck disable=SC1091
[ -f "${CARGO_HOME:-$HOME/.cargo}/env" ] && . "${CARGO_HOME:-$HOME/.cargo}/env"
if ! command -v cargo >/dev/null; then
    [ "$(id -u)" = 0 ] || { echo "cargo absent : installer Rust (https://rustup.rs) ou lancer en root" >&2; exit 1; }
    apt-get update -q
    apt-get install -y -q --no-install-recommends pkgconf clang cmake git dpkg-dev curl ca-certificates \
        libssl-dev libkrb5-dev libseccomp-dev libudev-dev libusb-1.0-0-dev protobuf-compiler libdbus-1-dev \
        libwayland-dev libxkbcommon-dev libfuse3-dev build-essential
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi
command -v cargo-deb >/dev/null || cargo install --locked cargo-deb
cd "$REPO"
export USBSAS_BIN_PATH=/usr/libexec
# Répertoire distinct des binaires « mock » des tests.
export CARGO_TARGET_DIR="$REPO/target/production"
# Note « future-incompat » de dépendances tierces (binrw) : sans action possible ici.
export CARGO_FUTURE_INCOMPAT_REPORT_FREQUENCY=never
# Compilation optimisée (LTO complète, une unité par crate) : certaines crates (cranelift,
# wasmtime via yara-x) demandent ~3 Go chacune. Sans limite, cargo lance une tâche par cœur et
# le noyau tue le compilateur faute de mémoire (« signal: 9, SIGKILL »). On limite donc le nombre
# de tâches parallèles à la mémoire disponible (1 tâche par 3 Go), sauf si CARGO_BUILD_JOBS est fixé.
if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
    MEM_GO=$(( $(awk '/^MemAvailable:/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
    SWAP_GO=$(( $(awk '/^SwapFree:/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
    JOBS=$(( (MEM_GO + SWAP_GO / 2) / 3 )); [ "$JOBS" -ge 1 ] || JOBS=1
    [ "$JOBS" -le "$(nproc)" ] || JOBS=$(nproc)
    export CARGO_BUILD_JOBS=$JOBS
    echo "Mémoire disponible : ${MEM_GO} Go (+ ${SWAP_GO} Go d'échange) → ${JOBS} compilation(s) en parallèle"
    if [ $(( MEM_GO + SWAP_GO )) -lt 4 ]; then
        echo "ATTENTION : moins de 4 Go de mémoire disponible ; la compilation risque d'échouer." >&2
        echo "Fermer d'autres programmes ou ajouter un fichier d'échange (voir le guide d'installation)." >&2
    fi
fi
# DEB_REVISION (lab) : révision des paquets (défaut 1). Un correctif livré par mise à jour signée doit
# porter une révision supérieure, sinon apt considère le paquet déjà installé et ne fait rien.
REV_ARGS=(--deb-revision "${DEB_REVISION:-1}")
rm -f "$CARGO_TARGET_DIR"/debian/*.deb
cargo build --release --locked -p usbsas-usbsas -p usbsas-net -p usbsas-cmdexec -p usbsas-dev2scsi \
    -p usbsas-files2fs -p usbsas-files2tar -p usbsas-local2files -p usbsas-fs2dev -p usbsas-identifier \
    -p usbsas-scsi2files -p usbsas-tar2files -p usbsas-usbdev -p usbsas-hid
cargo-deb --no-build "${REV_ARGS[@]}" -p usbsas-usbsas
cargo-deb --no-build "${REV_ARGS[@]}" -p usbsas-hid
cargo build --release --locked -p barbacane-client -p barbacane-analyzer -p barbacane-admind -p barbacane-optique
# Zone de démarrage Ventoy de confiance (clés démarrables reconstruites) : empreinte vérifiée
"$REPO/systeme/ventoy/preparer.sh" "$REPO/systeme/ventoy/dist"
cargo-deb --no-build "${REV_ARGS[@]}" -p barbacane-client
mkdir -p "$OUT"
cp "$CARGO_TARGET_DIR"/debian/usbsas-server_*.deb "$CARGO_TARGET_DIR"/debian/usbsas-hid_*.deb "$CARGO_TARGET_DIR"/debian/barbacane_*.deb "$OUT/"
ls -l "$OUT"
