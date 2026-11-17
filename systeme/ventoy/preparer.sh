#!/bin/bash
# Zone de démarrage Ventoy embarquée dans la borne (clés démarrables reconstruites, écart n° 9).
#
#   systeme/ventoy/preparer.sh DOSSIER_SORTIE
#
# Télécharge l'archive OFFICIELLE de Ventoy (ou la reprend du cache), vérifie son empreinte
# SHA-256 contre systeme/ventoy/ventoy.sha256 (épinglée et relue dans le dépôt : Ventoy ne publie
# pas de signature cryptographique), puis en extrait, décompressés, les seuls fichiers écrits sur
# une clé reconstruite : boot.img, core.img, ventoy.disk.img (+ version, licence).
# Changer de version = modifier ventoy.sha256 (revue de code) ; sur une borne installée, la
# version ne change que par un paquet de mise à jour signé.
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?DOSSIER_SORTIE}"
read -r SHA NOM < "$ICI/ventoy.sha256"
VERSION=${NOM#ventoy-}; VERSION=${VERSION%-linux.tar.gz}
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/barbacane"; mkdir -p "$CACHE" "$OUT"
if ! echo "$SHA  $CACHE/$NOM" | sha256sum -c --quiet >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$CACHE/$NOM.part" "https://github.com/ventoy/Ventoy/releases/download/v$VERSION/$NOM"
    mv "$CACHE/$NOM.part" "$CACHE/$NOM"
fi
echo "$SHA  $CACHE/$NOM" | sha256sum -c --quiet || { echo "empreinte de $NOM incorrecte : refus" >&2; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -xzf "$CACHE/$NOM" -C "$T" "./ventoy-$VERSION/boot" "./ventoy-$VERSION/ventoy/ventoy.disk.img.xz" "./ventoy-$VERSION/ventoy/version"
D="$T/ventoy-$VERSION"
install -m 644 "$D/boot/boot.img" "$OUT/boot.img"
xz -dc "$D/boot/core.img.xz" > "$OUT/core.img"
xz -dc "$D/ventoy/ventoy.disk.img.xz" > "$OUT/ventoy.disk.img"
printf 'Ventoy %s (%s, sha256 %s)\nLicence GPL v3 ; sources : https://github.com/ventoy/Ventoy/tree/v%s\n' \
    "$VERSION" "$NOM" "$SHA" "$VERSION" > "$OUT/VERSION"
(cd "$OUT" && sha256sum boot.img core.img ventoy.disk.img > SHA256SUMS)
echo "Ventoy $VERSION prêt dans $OUT"
