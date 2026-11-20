#!/bin/bash
# Captures PNG des pages de l'interface web d'administration, thèmes Jour et Nuit, 1280 px de large.
#   tests/web/captures.sh [SORTIE]     (défaut : docs/preuves/serveur-web/captures)
# Les pages sont rendues par le VRAI code (exemple cargo « captures », données d'exemple), puis
# photographiées par un Chromium sans tête (chromium-headless-shell ou chromium, Debian 13).
# À lancer sur une VM de dev (bu), jamais sur l'hôte Proxmox.
set -eu
cd "$(dirname "$0")/../.."
SORTIE=${1:-docs/preuves/serveur-web/captures}
case $SORTIE in /*) ;; *) SORTIE=$PWD/$SORTIE ;; esac
NAV=""
for n in chromium-headless-shell chromium; do
	if command -v "$n" >/dev/null; then NAV=$n; break; fi
done
if [ -z "$NAV" ]; then
	echo "Aucun Chromium sans tête : « apt install chromium-headless-shell » sur la VM de dev." >&2
	exit 2
fi
PAGES=$(mktemp -d)
trap 'rm -rf "$PAGES"' EXIT
timeout 30m cargo run -q -p barbacane-web --example captures -- "$PAGES" >/dev/null
mkdir -p "$SORTIE"
for f in "$PAGES"/*.html; do
	nom=$(basename "$f" .html)
	# --virtual-time-budget : polices chargées avant la capture ; aucun accès réseau (file://).
	timeout 2m "$NAV" --headless --no-sandbox --disable-gpu --hide-scrollbars \
		--window-size=1280,800 --virtual-time-budget=3000 \
		--screenshot="$SORTIE/$nom.png" "file://$f" >/dev/null 2>&1
	echo "$SORTIE/$nom.png"
done
