#!/bin/bash
# Génère docs/Barbacane-installation.pdf depuis docs/Barbacane-installation.md.
# Outils (Debian 13) : apt-get install pandoc weasyprint
# Polices de la charte embarquées depuis borne/client/ressources/polices (aucun téléchargement).
set -euo pipefail
DOCS="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$DOCS/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed "s|@POLICES@|file://$REPO/borne/client/ressources/polices|g; s|@DOCS@|file://$DOCS|g" "$DOCS/pdf/style.css" > "$T/style.css"
# Couverture : date du jour et version du paquet de la borne
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/Cargo.toml" | head -1)"
DATE="$(LC_ALL=C date +%d/%m/%Y)"
sed "s|@DOCS@|file://$DOCS|g; s|@DATE@|$DATE|; s|@VERSION@|$VERSION|" "$DOCS/pdf/couverture.html" > "$T/couverture.html"
cd "$DOCS"
pandoc Barbacane-installation.md --standalone --toc --toc-depth=2 \
    --metadata toc-title="Sommaire" --include-before-body "$T/couverture.html" \
    --css "$T/style.css" -o "$T/guide.html"
weasyprint --base-url "$DOCS/" "$T/guide.html" "$DOCS/Barbacane-installation.pdf"
ls -l "$DOCS/Barbacane-installation.pdf"
