#!/bin/bash
# Génère le Manuel Barbacane (docs/Barbacane-installation.pdf) depuis docs/Barbacane-installation.md.
# Outils (Debian 13) : apt-get install pandoc weasyprint
# Charte v2 : polices embarquées depuis docs/charte/fonts (OFL, aucun téléchargement).
set -euo pipefail
DOCS="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed "s|@POLICES@|file://$DOCS/charte/fonts|g; s|@DOCS@|file://$DOCS|g" "$DOCS/pdf/style.css" > "$T/style.css"
# Couverture : date du jour et version réelle (celle du workspace Cargo, [workspace.package]).
DATE="$(LC_ALL=C date +%d/%m/%Y)"
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([0-9.]*\)"$/\1/p' "$DOCS/../Cargo.toml")"
[ -n "$VERSION" ] || { echo "version du workspace introuvable (Cargo.toml)" >&2; exit 1; }
sed "s|@DOCS@|file://$DOCS|g; s|@DATE@|$DATE|; s|@VERSION@|$VERSION|" "$DOCS/pdf/couverture.html" > "$T/couverture.html"
cd "$DOCS"
pandoc Barbacane-installation.md --standalone --toc --toc-depth=2 \
    --metadata toc-title="Sommaire" --include-before-body "$T/couverture.html" \
    --css "$T/style.css" -o "$T/guide.html"
weasyprint --base-url "$DOCS/" "$T/guide.html" "$DOCS/Barbacane-installation.pdf"
ls -l "$DOCS/Barbacane-installation.pdf"
