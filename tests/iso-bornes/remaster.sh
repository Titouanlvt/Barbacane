#!/bin/bash
# Remaster de l'ISO de borne en ligne (serveur/iso-bornes/barbacane-iso-borne) :
#   - l'ISO personnalisée ne diffère de la source QUE par /barbacane/en-ligne/parametres.conf
#     (liste des fichiers et SHA-256 de chacun comparés) ; volume et démarrage conservés ;
#   - refus : jeton d'un autre port, jeton mal formé, site invalide, ISO hors ligne (sans
#     agent.toml), ISO déjà personnalisée, sortie existante.
# Usage : tests/iso-bornes/remaster.sh [ISO_EN_LIGNE]   (défaut : petite ISO synthétique ; xorriso requis)
set -euo pipefail
ICI=$(cd "$(dirname "$0")" && pwd)
OUTIL="$ICI/../../serveur/iso-bornes/barbacane-iso-borne"
W=$(mktemp -d -p "${TMPDIR:-/tmp}"); trap 'rm -rf "$W"' EXIT
ko=0
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
ok() { echo "ok : $*"; }
JETON=43117-ABCDEFGHIJKLMNOPQRSTUVWXYZ

if [ $# -ge 1 ]; then
    SRC=$(realpath "$1")
    PE=$("$OUTIL" parametres "$SRC" | sed 's/.*port_enrolement=//')
    JETON="$PE-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
else
    mkdir -p "$W/arbre/barbacane/en-ligne" "$W/arbre/barbacane/debs" "$W/hl/barbacane"
    printf 'adresse = "10.20.0.1"\nport_enrolement = 43117\nport_service = 47686\n' > "$W/arbre/barbacane/en-ligne/agent.toml"
    head -c 300000 /dev/urandom > "$W/arbre/barbacane/debs/x_1_amd64.deb"
    echo preseed > "$W/arbre/barbacane/preseed.cfg"; echo hl > "$W/hl/barbacane/preseed.cfg"
    xorriso -report_about SORRY -outdev "$W/src.iso" -volid BARBACANE -map "$W/arbre" / >/dev/null 2>&1
    xorriso -report_about SORRY -outdev "$W/hl.iso" -volid BARBACANE -map "$W/hl" / >/dev/null 2>&1
    SRC="$W/src.iso"
fi

empreintes() { # ISO → liste « sha256  chemin » triée
    rm -rf "$W/x"; mkdir "$W/x"
    xorriso -osirrox on -indev "$1" -extract / "$W/x" >/dev/null 2>&1
    chmod -R u+rwX "$W/x"
    (cd "$W/x" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
}

echo "$JETON" | "$OUTIL" personnaliser "$SRC" "$W/perso.iso" site-3 > "$W/sortie.txt" || echec "personnalisation refusée"
if [ "$(stat -c %a "$W/perso.iso")" = 600 ]; then ok "ISO personnalisée en 0600"; else echec "droits de l'ISO personnalisée"; fi
empreintes "$SRC" > "$W/a.txt"
empreintes "$W/perso.iso" > "$W/b.txt"
cp "$W/x/barbacane/en-ligne/parametres.conf" "$W/p.conf" 2>/dev/null || true
diff "$W/a.txt" "$W/b.txt" | grep '^[<>]' > "$W/diff.txt" || true
if [ "$(wc -l < "$W/diff.txt")" = 1 ] && grep -q '^> .*  \./barbacane/en-ligne/parametres\.conf$' "$W/diff.txt"; then
    ok "seule différence : parametres.conf ($(wc -l < "$W/a.txt") fichiers identiques)"
else
    echec "différences inattendues :"; cat "$W/diff.txt" >&2
fi
if grep -qx "jeton = $JETON" "$W/p.conf" && grep -qx 'site = site-3' "$W/p.conf"; then ok "paramètres : jeton, adresse, port, site"; else echec "contenu de parametres.conf"; fi
v1=$(xorriso -indev "$SRC" -pvd_info 2>/dev/null | grep '^Volume Id')
v2=$(xorriso -indev "$W/perso.iso" -pvd_info 2>/dev/null | grep '^Volume Id')
if [ "$v1" = "$v2" ]; then ok "volume conservé ($v1)"; else echec "volume : $v1 / $v2"; fi
grep -q "$(echo "$JETON" | cut -d- -f2)" "$W/sortie.txt" && echec "secret du jeton affiché"

refuse() { local nom=$1; shift; if "$@" >/dev/null 2>&1; then echec "accepté : $nom"; else ok "refusé : $nom"; fi; }
refuse "jeton d'un autre port" sh -c "echo 1-ABCDEFGHIJKLMNOPQRSTUVWXYZ | '$OUTIL' personnaliser '$SRC' '$W/r1.iso' site-3"
refuse "jeton mal formé" sh -c "echo '${JETON%?}1' | '$OUTIL' personnaliser '$SRC' '$W/r2.iso' site-3"
refuse "site invalide" sh -c "echo $JETON | '$OUTIL' personnaliser '$SRC' '$W/r3.iso' 'site-1;x'"
refuse "ISO déjà personnalisée" sh -c "echo $JETON | '$OUTIL' personnaliser '$W/perso.iso' '$W/r4.iso' site-3"
refuse "sortie existante" sh -c "echo $JETON | '$OUTIL' personnaliser '$SRC' '$W/perso.iso' site-3"
[ -f "$W/hl.iso" ] && refuse "ISO hors ligne" sh -c "echo $JETON | '$OUTIL' personnaliser '$W/hl.iso' '$W/r5.iso' site-3"
for i in 1 2 3 4 5; do [ ! -e "$W/r$i.iso" ] || echec "r$i.iso produite malgré le refus"; done

[ "$ko" = 0 ] && echo "REMASTER : OK"
exit "$ko"
