#!/bin/bash
# shellcheck disable=SC2015,SC2054 # « test && ok || echec » : ok ne peut pas échouer ; virgules = options QEMU
# Test automatisé de serveur/sauvegarde/barbacane-sauvegarde (conception §3.8 : « restauration
# testée en CI ») : sauvegarde d'une arborescence de serveur factice, DESTRUCTION, restauration,
# comparaison exacte (contenu, types, droits, liens, propriétaires si root) ; puis refus attendus :
# support abîmé, archive modifiée, mauvaise clé, archive forgée par un tiers ; rotation ;
# conservation (v2.3.0) : sauvegardes plus anciennes que la durée purgées, purge inscrite au
# journal d'audit (avec le vrai barbacane-audit s'il est compilé).
# Usage : tests/serveur/sauvegarde.sh   (prérequis : openssl ≥ 3, tar, coreutils)
set -euo pipefail
S="$(cd "$(dirname "$0")/../.." && pwd)/serveur/sauvegarde/barbacane-sauvegarde"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
ko=0
ok() { echo "OK : $*"; }
echec() { echo "ÉCHEC : $*" >&2; ko=1; }
refuse() { # description commande… : la commande doit échouer
    local d=$1; shift
    if "$@" > "$W/sortie" 2>&1; then echec "$d : accepté"; else ok "$d : refusé ($(grep -m1 'ÉCHEC' "$W/sortie" || tail -n1 "$W/sortie"))"; fi
}

# Clés : sauvegarde (hors serveur), signature du serveur, et celles d'un tiers.
bash "$S" cles-destinataire "$W/coffre" --sans-phrase >/dev/null
bash "$S" cles-signature "$W/serveur-cles" >/dev/null
bash "$S" cles-destinataire "$W/autre-coffre" --sans-phrase >/dev/null
bash "$S" cles-signature "$W/tiers" >/dev/null
COMMUN=(--destinataire "$W/coffre/destinataire.pem" --signature-cle "$W/serveur-cles/signature.cle.pem"
        --signature-cert "$W/serveur-cles/signature.pem")
OUVRIR=(--cle-privee "$W/coffre/destinataire.cle.pem" --signataire "$W/serveur-cles/signature.pem")

# Serveur factice : configuration, PKI, données binaires, lien, fichier vide, nom avec espace.
R="$W/racine"
mkdir -p "$R/etc/barbacane-serveur/sauvegarde" "$R/var/lib/barbacane-serveur/svc/pki" \
    "$R/var/lib/barbacane-serveur/svc/.local/share/containers/storage" "$R/var/lib/barbacane-serveur/base"
echo "VERSION='suite-test'" > "$R/etc/barbacane-serveur/serveur.conf"
chmod 600 "$R/etc/barbacane-serveur/serveur.conf"
openssl rand 3000000 > "$R/var/lib/barbacane-serveur/base/donnees.bin"
printf 'cle\n' > "$R/var/lib/barbacane-serveur/svc/pki/cle.pem"; chmod 400 "$R/var/lib/barbacane-serveur/svc/pki/cle.pem"
: > "$R/var/lib/barbacane-serveur/base/vide"
echo "nom avec espace" > "$R/var/lib/barbacane-serveur/base/un fichier"
ln -s ../base/donnees.bin "$R/var/lib/barbacane-serveur/svc/lien"
echo "image (exclue, rechargée depuis l'ISO)" > "$R/var/lib/barbacane-serveur/svc/.local/share/containers/storage/x"
if [ "$(id -u)" = 0 ]; then chown 4321:4321 "$R/var/lib/barbacane-serveur/svc/pki/cle.pem"; fi
printf '# chemins sauvegardés\n/etc/barbacane-serveur\n/var/lib/barbacane-serveur\n' > "$W/liste"
# Comparaison limitée aux chemins sauvegardés (leurs parents, /etc et /var, existent sur un vrai serveur).
etat() { (cd "$R" && find ./etc/barbacane-serveur ./var/lib/barbacane-serveur -path ./var/lib/barbacane-serveur/svc/.local -prune -o -printf '%p %y %m %U %G %s %l\n' | sort
          find ./etc/barbacane-serveur ./var/lib/barbacane-serveur -path ./var/lib/barbacane-serveur/svc/.local -prune -o -type f -print0 | sort -z | xargs -0 sha384sum); }
etat > "$W/avant"

# 1. Sauvegarde
mkdir "$W/support"
bash "$S" creer --destination "$W/support" --racine "$R" --liste "$W/liste" "${COMMUN[@]}"
A=$(find "$W/support" -name '*.cms' | head -1)
[ -f "$A" ] && [ -f "$A.sha384" ] && ok "archive et empreinte sur le support" || echec "archive absente"
if grep -qa 'nom avec espace\|VERSION=' "$A"; then echec "contenu en clair dans l'archive"; else ok "aucun contenu en clair dans l'archive"; fi
openssl cms -cmsout -print -inform DER -in "$A" | grep -q 'aes-256-gcm\|id-aes256-GCM' \
    && ok "chiffrement AES-256-GCM (AuthEnvelopedData)" || echec "algorithme de chiffrement inattendu"

# 2. Destruction puis restauration
rm -rf "${R:?}/etc" "${R:?}/var"
[ -z "$(ls -A "$R")" ] && ok "serveur factice détruit"
bash "$S" restaurer --archive "$A" --racine "$R" "${OUVRIR[@]}"
etat > "$W/apres"
grep -v '\.local' "$W/avant" > "$W/avant.f"; grep -v '\.local' "$W/apres" > "$W/apres.f"
if diff -u "$W/avant.f" "$W/apres.f"; then ok "restauration identique ($(wc -l < "$W/avant.f") lignes comparées : contenu, droits, liens, propriétaires)"
else echec "restauration différente"; fi
[ ! -e "$R/var/lib/barbacane-serveur/svc/.local/share/containers/storage/x" ] && ok "stockage des conteneurs exclu"

# 3. Refus attendus, sans rien écrire
vide="$W/vide"; mkdir "$vide"
cp "$A" "$W/abime.cms"; cp "$A.sha384" "$W/abime.cms.sha384"
sed -i "s|$(basename "$A")|abime.cms|" "$W/abime.cms.sha384"
printf '\xff' | dd of="$W/abime.cms" bs=1 seek=$(( $(stat -c %s "$A") / 2 )) conv=notrunc status=none
refuse "support abîmé (empreinte)" bash "$S" restaurer --archive "$W/abime.cms" --racine "$vide" "${OUVRIR[@]}"
(cd "$W" && sha384sum abime.cms > abime.cms.sha384)
refuse "archive modifiée, empreinte recalculée (GCM)" bash "$S" restaurer --archive "$W/abime.cms" --racine "$vide" "${OUVRIR[@]}"
refuse "mauvaise clé de sauvegarde" bash "$S" verifier --archive "$A" --cle-privee "$W/autre-coffre/destinataire.cle.pem" \
    --signataire "$W/serveur-cles/signature.pem"
mkdir "$W/forge"
bash "$S" creer --destination "$W/forge" --racine "$R" --liste "$W/liste" --destinataire "$W/coffre/destinataire.pem" \
    --signature-cle "$W/tiers/signature.cle.pem" --signature-cert "$W/tiers/signature.pem" >/dev/null
F=$(find "$W/forge" -name '*.cms' | head -1)
refuse "archive forgée par un tiers (signature)" bash "$S" restaurer --archive "$F" --racine "$vide" "${OUVRIR[@]}"
[ -z "$(ls -A "$vide")" ] && ok "rien écrit lors des refus" || echec "fichiers écrits malgré un refus"

# 4. Rotation : --garder 2 ne laisse que les deux plus récentes
for _ in 1 2; do sleep 1.1; bash "$S" creer --destination "$W/support" --racine "$R" --liste "$W/liste" --garder 2 "${COMMUN[@]}" >/dev/null; done
n=$(find "$W/support" -name '*.cms' | wc -l)
[ "$n" = 2 ] && [ ! -e "$A" ] && ok "rotation : 2 archives gardées, la plus ancienne purgée" || echec "rotation : $n archives"

# 5. Conservation : sauvegardes datées de 400, 200 et 10 jours (copies renommées), durée 365 j
B=$(basename "$(find "$W/support" -name '*.cms' | sort | tail -1)")
for j in 400 200 10; do
    n="barbacane-sauvegarde-hote-a-b-$(date -u -d "-$j days" +%Y%m%dT%H%M%SZ).cms"
    cp "$W/support/$B" "$W/support/$n"; (cd "$W/support" && sha384sum "$n" > "$n.sha384")
done
bash "$S" purger --destination "$W/support" --conservation-jours aucune > "$W/p0"
n=$(find "$W/support" -name '*.cms' | wc -l)
[ "$n" = 5 ] && grep -q 'aucune durée en vigueur' "$W/p0" && ok "conservation en préavis (« aucune ») : rien purgé par âge" || echec "préavis : $n archives"
AUDIT_BIN="${CARGO_TARGET_DIR:-$(dirname "$S")/../../target}/debug/barbacane-audit"
JA="$W/audit.jsonl"
if [ -x "$AUDIT_BIN" ]; then export BARBACANE_AUDIT="$AUDIT_BIN" JOURNAL_AUDIT="$JA"; : > "$JA"; fi
bash "$S" purger --destination "$W/support" --conservation-jours 365 > "$W/p1"
n=$(find "$W/support" -name '*.cms' | wc -l)
[ "$n" = 4 ] && ! ls "$W/support"/*"$(date -u -d '-400 days' +%Y%m%d)"* >/dev/null 2>&1 \
    && ok "conservation 365 jours : la sauvegarde de 400 jours (et son empreinte) purgée, celles de 200 et 10 jours gardées" \
    || echec "conservation 365 j : $n archives ($(cat "$W/p1"))"
bash "$S" purger --destination "$W/support" --conservation-jours 180 > "$W/p2"
n=$(find "$W/support" -name '*.cms' | wc -l)
[ "$n" = 3 ] && ok "conservation 180 jours : la sauvegarde de 200 jours purgée ($(grep -c 'purgée (plus' "$W/p2") archive)" || echec "conservation 180 j : $n archives"
refuse "durée de conservation invalide" bash "$S" purger --destination "$W/support" --conservation-jours 'x;y'
if [ -x "$AUDIT_BIN" ]; then
    [ "$(grep -c '"purge":{"objet":"sauvegardes","nombre":1,' "$JA")" = 2 ] \
        && "$AUDIT_BIN" structurer "$JA" srv | grep -q '"type":"purge"' \
        && ok "purges des sauvegardes inscrites au journal d'audit (vrai barbacane-audit) : $(wc -l < "$JA") enregistrements" \
        || echec "purge des sauvegardes absente du journal : $(cat "$JA")"
else
    echo "(barbacane-audit non compilé : inscription au journal non vérifiée ici)"
fi

[ "$ko" = 0 ] && echo "SAUVEGARDE/RESTAURATION : OK"
exit "$ko"
