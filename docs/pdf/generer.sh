#!/bin/bash
# Génère docs/Barbacane-installation.pdf depuis docs/Barbacane-installation.md.
# Outils (Debian 13) : apt-get install pandoc weasyprint
# Polices de la charte embarquées depuis borne/client/ressources/polices (aucun téléchargement).
set -euo pipefail
DOCS="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$DOCS/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed "s|@POLICES@|file://$REPO/borne/client/ressources/polices|g; s|@DOCS@|file://$DOCS|g" "$DOCS/pdf/style.css" > "$T/style.css"
cd "$DOCS"
pandoc Barbacane-installation.md --standalone --toc --toc-depth=2 \
    --metadata toc-title="Sommaire" --css "$T/style.css" -o "$T/guide.html"
weasyprint --base-url "$DOCS/" "$T/guide.html" "$DOCS/Barbacane-installation.pdf"
ls -l "$DOCS/Barbacane-installation.pdf"
