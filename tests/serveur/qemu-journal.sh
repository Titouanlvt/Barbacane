# shellcheck shell=bash
# shellcheck disable=SC2015 # « test && ok || echec » : ok ne peut pas échouer
# Parcours v2.3.0 du banc QEMU serveur (sourcé par tests/serveur/qemu-serveur.sh, VM démarrée,
# parcours des comptes fait : admin-01 et admin-02 connectés, cookies et jetons CSRF S1/S2) :
#   export Syslog TLS 1.3 + mTLS vers un collecteur de test (tests/serveur/collecteur-syslog.py,
#   joint par la VM en 10.0.3.100 via guestfwd QEMU), double validation (auto-validation refusée),
#   rapports de passage d'une borne de test enrôlée par le protocole réel, collecteur coupé puis
#   rétabli (reprise sans trou, doublons marqués), conservation réduite par double validation,
#   sauvegardes sur un disque « support » ; via la console série (compte d'administration système,
#   sudo) : avance de l'horloge de la VM (+100 puis +250 jours), tâche barbacane-conservation,
#   purge des passages, rotation et purge du journal d'audit, vérification de la chaîne restante,
#   purge des sauvegardes ; horloge rétablie, résultat vu dans la Console ; enfin Syslog en clair.
# Variables : W, PKI, U, A1, A2, S1, S2 (qemu-serveur.sh), MDP_ADMIN (fichier : mot de passe initial
# du compte barbadmin), COMPTE_ADMIN (défaut barbadmin), PA/PB (ports de la passerelle).

DEPOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COL=$W/collecteur
SERIE=$W/serie.sock
NV=0 # numéro de commande sur la console série

# ---------------------------------------------------------------- console série (root par sudo)
serie() { printf '%s\r' "$1" | socat - "UNIX-CONNECT:$SERIE" >/dev/null 2>&1 || true; }
lignes_console() { lisible "$W/demarrage.log" | wc -l; }
attendre_console() { # MOTIF DÉLAI_S LIGNE_DE_DÉPART → 0 si le motif paraît après cette ligne
    local _
    for _ in $(seq "$2"); do
        lisible "$W/demarrage.log" | tail -n +"$(($3 + 1))" | grep -qiE "$1" && return 0
        sleep 1
    done
    return 1
}
connexion_console() {
    local c=${COMPTE_ADMIN:-barbadmin} m n
    m=$(head -n 1 "$MDP_ADMIN" | tr -d '\r\n')
    NOUVEAU="Banc-v230-$(head -c 9 /dev/urandom | base64 | tr -dc a-zA-Z0-9)-Console"
    n=$(lignes_console); serie ""
    attendre_console 'login:' 60 "$n" || { echec "console série : pas d'invite de connexion"; return 1; }
    n=$(lignes_console); serie "$c"
    attendre_console 'password:' 30 "$n" || { echec "console série : pas de demande de mot de passe"; return 1; }
    n=$(lignes_console); serie "$m"
    # Mot de passe initial à changer à la première connexion (chage -d 0).
    if attendre_console 'current password|mot de passe actuel' 30 "$n"; then
        n=$(lignes_console); serie "$m"
        attendre_console 'new password|nouveau mot de passe' 20 "$n" && { n=$(lignes_console); serie "$NOUVEAU"; }
        attendre_console 'retype|retapez|new password' 20 "$n" && { n=$(lignes_console); serie "$NOUVEAU"; }
    else
        NOUVEAU=$m
    fi
    attendre_console '\$ *$' 30 "$n" || { echec "console série : connexion du compte $c refusée"; return 1; }
    n=$(lignes_console); serie "sudo -i"
    attendre_console 'password for|mot de passe de' 20 "$n" && { n=$(lignes_console); serie "$NOUVEAU"; }
    attendre_console '# *$' 30 "$n" || { echec "console série : sudo refusé"; return 1; }
    serie "stty -echo; export TERM=dumb PS1='# '"
    sleep 2
    ok "console série : compte d'administration système $c connecté (mot de passe initial changé), root par sudo"
}
# racine COMMANDE [DÉLAI_S] → sortie dans $W/racine-N.txt (code dans RC)
racine() {
    NV=$((NV + 1)); RC=1
    local n d=${2:-120}
    n=$(lignes_console)
    serie "( $1 ) > /root/banc-$NV.out 2>&1; r=\$?; echo ==DEB""UT-$NV==; cat /root/banc-$NV.out; echo ==F""IN-$NV== \$r"
    if attendre_console "==FIN-$NV== [0-9]+" "$d" "$n"; then
        lisible "$W/demarrage.log" | tail -n +"$((n + 1))" | sed -n "/^==DEBUT-$NV==/,/^==FIN-$NV==/p" | sed '1d;$d' > "$W/racine-$NV.txt"
        RC=$(lisible "$W/demarrage.log" | tail -n +"$((n + 1))" | sed -n "s/.*==FIN-$NV== \([0-9]*\).*/\1/p" | head -1)
    else
        echo "(commande $NV sans réponse en $d s : $1)" > "$W/racine-$NV.txt"
    fi
    SORTIE="$W/racine-$NV.txt"
}

# ---------------------------------------------------------------- collecteur de test (sur l'hôte du banc)
pki_collecteur() {
    mkdir -p "$COL"
    openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1100 -subj "/CN=AC collecteur Syslog de TEST" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$COL/ac.cle" -out "$COL/ac.pem" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=collecteur.barbacane.invalid" \
        -keyout "$COL/serveur.cle" -out "$COL/serveur.csr" 2>/dev/null
    printf 'subjectAltName=DNS:collecteur.barbacane.invalid\nextendedKeyUsage=serverAuth\n' > "$COL/ext"
    openssl x509 -req -in "$COL/serveur.csr" -CA "$COL/ac.pem" -CAkey "$COL/ac.cle" -CAcreateserial -days 1000 \
        -extfile "$COL/ext" -out "$COL/serveur.pem" 2>/dev/null
}
lancer_collecteur() { # tls|clair
    if [ "$1" = tls ]; then
        python3 "$DEPOT/tests/serveur/collecteur-syslog.py" --port 16514 --sortie "$COL/recus-tls.txt" \
            --cert "$COL/serveur.pem" --cle "$COL/serveur.cle" --ac-client "$COL/ac.pem" &
        PID_TLS=$!
    else
        python3 "$DEPOT/tests/serveur/collecteur-syslog.py" --port 15514 --sortie "$COL/recus-clair.txt" &
        PID_CLAIR=$!
    fi
    sleep 1
}
# numeros FICHIER → numéros n reçus (un par ligne, dans l'ordre de réception)
numeros() { sed -n 's/.* n="\([0-9]*\)".*/\1/p' "$1"; }
# contigus FICHIER → « premier dernier » si les numéros reçus couvrent tout l'intervalle, sinon vide
contigus() {
    numeros "$1" | sort -nu | awk 'NR == 1 { p = $1; d = $1 - 1 } $1 != d + 1 { trou = 1 } { d = $1 } END { if (!trou && NR) print p, d }'
}
attendre_fichier() { # FICHIER MOTIF DÉLAI_S
    local _
    for _ in $(seq "$3"); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 1; done
    return 1
}

# ---------------------------------------------------------------- borne de test (protocole réel)
borne_de_test() {
    local B=$W/borne-test jeton port secret csr reponse id emp code pe ps hote=passerelle.barbacane.invalid
    mkdir -p "$B"
    code=$(requete "${A1[@]}" "$B/jeton.html" /enrolement/jeton "csrf=$S1" "site=labo")
    jeton=$(sed -n 's/.*<div class="b-code">\([^<]*\)<.*/\1/p' "$B/jeton.html" | head -1)
    port=${jeton%%-*} secret=${jeton#*-}
    case "$port" in "$PA") pe=47001 ps=47005 ;; "$PB") pe=47005 ps=47001 ;; *) echec "jeton : port inconnu ($jeton, HTTP $code)"; return 1 ;; esac
    openssl ecparam -name prime256v1 -genkey -noout -out "$B/cle.pem"
    openssl req -new -key "$B/cle.pem" -sha256 -subj "/CN=borne de test" -out "$B/csr.pem"
    csr=$(sed ':a;N;$!ba;s/\n/\\n/g' "$B/csr.pem")
    CURL_P=(--silent --max-time 30 --cacert "$PKI/racine/cert.pem")
    reponse=$(curl "${CURL_P[@]}" --resolve "$hote:$pe:127.0.0.1" -H 'Content-Type: application/json' \
        --data "{\"version\":1,\"jeton\":\"$secret\",\"csr_pem\":\"$csr\\n\",\"version_logiciel\":\"2.3.0-banc\"}" \
        "https://$hote:$pe/enrolement/demande" 2>&1 || true)
    id=$(sed -n 's/.*"demande_id":"\([0-9a-f]*\)".*/\1/p' <<<"$reponse")
    emp=$(sed -n 's/.*"empreinte":"\([0-9a-f]*\)".*/\1/p' <<<"$reponse")
    [ -n "$id" ] || { echec "borne de test : demande d'enrôlement refusée : $reponse"; return 1; }
    code=$(requete "${A1[@]}" "$B/valide.html" /enrolement/valider "csrf=$S1" "id=$id" "empreinte=$emp" "nom=borne-banc")
    reponse=$(curl "${CURL_P[@]}" --resolve "$hote:$pe:127.0.0.1" -H 'Content-Type: application/json' \
        --data "{\"version\":1,\"demande_id\":\"$id\"}" "https://$hote:$pe/enrolement/retrait" 2>&1 || true)
    printf '%b' "$(sed -n 's/.*"certificat_pem":"\([^"]*\)".*/\1/p' <<<"$reponse")" > "$B/cert.pem"
    openssl x509 -in "$B/cert.pem" -noout 2>/dev/null \
        && ok "borne de test enrôlée par le protocole réel (jeton de la Console, demande, validation HTTP $code, certificat retiré)" \
        || { echec "borne de test : certificat non obtenu : $reponse"; return 1; }
    # Deux rapports de passage (sain, menace), sans nom de fichier (D2).
    PASSAGES=0
    for v in sain menace; do
        local pid; pid=$(cat /proc/sys/kernel/random/uuid)
        reponse=$(curl "${CURL_P[@]}" --cert "$B/cert.pem" --key "$B/cle.pem" --resolve "$hote:$ps:127.0.0.1" \
            -H 'Content-Type: application/json' \
            --data "{\"version\":1,\"id\":\"$pid\",\"horodatage\":$(date +%s),\"verdict\":\"$v\",\"support\":\"$(printf 'support-banc' | sha256sum | cut -c1-64)\",\"partie\":1,\"parties\":1,\"fichiers\":[{\"taille\":68,\"sha256\":\"$(printf '%064d' 7)\",\"verdict\":\"$v\"}]}" \
            "https://$hote:$ps/rapport/passage" 2>&1 || true)
        grep -q '"deja_recu":false' <<<"$reponse" && PASSAGES=$((PASSAGES + 1))
    done
    [ "$PASSAGES" = 2 ] && ok "2 rapports de passage (sain, menace) reçus par la passerelle (mTLS de la borne de test)" \
        || echec "rapports de passage : $PASSAGES/2 ($reponse)"
}

# ---------------------------------------------------------------- parcours
demande_de() { sed -n 's/.*name="demande" value="\([^"]*\)".*/\1/p' "$1" | head -1; }
valider() { # FICHIER_DEMANDE ADMIN(A1|A2) → code HTTP, page dans $W/val.html
    local d; d=$(demande_de "$1")
    if [ "$2" = A1 ]; then requete "${A1[@]}" "$W/val.html" /validations/valider "csrf=$S1" "demande=$d" "retour=journal"
    else requete "${A2[@]}" "$W/val.html" /validations/valider "csrf=$S2" "demande=$d" "retour=journal"; fi
}

parcours_journal() {
    command -v python3 >/dev/null || { echec "python3 absent : parcours v2.3.0 impossible"; return; }
    T0=$(date +%s)
    pki_collecteur
    lancer_collecteur tls
    # 1. État initial (serveur 2.3.0 neuf : 365 jours, préavis).
    code=$(requete "${A1[@]}" "$W/j0.html" /journal)
    [ "$code" = 200 ] && grep -q '365 jours' "$W/j0.html" && grep -q 'aucune purge avant le' "$W/j0.html" \
        && ok "conservation : 365 jours par défaut, posée au premier démarrage avec préavis (aucune purge immédiate)" \
        || echec "page Conservation et export : HTTP $code"
    # 2. mTLS : clé client tirée par le serveur, demande signée par l'AC du collecteur.
    requete "${A1[@]}" "$W/j-cle.html" /journal/syslog/cle "csrf=$S1" >/dev/null
    sed -n '/-----BEGIN CERTIFICATE REQUEST-----/,/-----END CERTIFICATE REQUEST-----/p' "$W/j-cle.html" \
        | sed 's/.*\(-----BEGIN\)/\1/; s/\(REQUEST-----\).*/\1/' > "$COL/client.csr"
    printf 'extendedKeyUsage=clientAuth\n' > "$COL/ext-client"
    openssl x509 -req -in "$COL/client.csr" -CA "$COL/ac.pem" -CAkey "$COL/ac.cle" -CAcreateserial -days 400 \
        -extfile "$COL/ext-client" -out "$COL/client.pem" 2>/dev/null
    code=$(requete "${A1[@]}" "$W/j-cert.html" /journal/syslog/certificat "csrf=$S1" "certificat@$COL/client.pem")
    [ "$code" = 200 ] && grep -q 'Certificat client déposé' "$W/j-cert.html" \
        && ok "mTLS : clé client tirée par le serveur, demande signée par l'AC du collecteur, certificat déposé (clé assortie vérifiée)" \
        || echec "mTLS : dépôt du certificat client : HTTP $code"
    # 3. Réglage TLS : demande d'admin-01, auto-validation refusée, validation par admin-02.
    code=$(requete "${A1[@]}" "$W/j-tls.html" /journal/syslog "csrf=$S1" "mode=tls" "adresse=10.0.3.100" "port=6514" \
        "nom=collecteur.barbacane.invalid" "ac@$COL/ac.pem" "mtls=oui")
    code2=$(valider "$W/j-tls.html" A1)
    grep -q 'second administrateur' "$W/val.html" && [ "$code" = 200 ] && [ "$code2" = 400 ] \
        && ok "Syslog : demande TLS par admin-01, AUTO-VALIDATION REFUSÉE (400)" || echec "Syslog : demande $code, auto-validation $code2"
    code=$(valider "$W/j-tls.html" A2)
    [ "$code" = 200 ] && grep -q 'Export Syslog TLS' "$W/val.html" \
        && ok "Syslog TLS 1.3 + mTLS vers 10.0.3.100:6514 validé par admin-02 (double validation)" || echec "Syslog : validation par admin-02 : HTTP $code"
    if attendre_fichier "$COL/recus-tls.txt" 'conservation_reglee' 90; then
        r=$(contigus "$COL/recus-tls.txt")
        [ -n "$r" ] && [ "${r%% *}" = 1 ] && grep -q '^<[0-9]*>1 [0-9T:-]*Z ' "$COL/recus-tls.txt" \
            && ok "collecteur TLS (mTLS exigé) : $(wc -l < "$COL/recus-tls.txt") messages RFC 5424, n° $r sans trou, JSON structuré" \
            || echec "collecteur TLS : numéros non contigus ($(numeros "$COL/recus-tls.txt" | tr '\n' ' ' | head -c 200))"
    else echec "collecteur TLS : rien reçu en 90 s ($(cat "$COL/recus-tls.txt.erreurs" 2>/dev/null | tail -2))"; fi
    # 4. Rapports de passage au format structuré (sans nom de fichier, pseudonymes seulement).
    borne_de_test
    attendre_fichier "$COL/recus-tls.txt" '"type":"rapport_passage"' 60 \
        && grep '"type":"rapport_passage"' "$COL/recus-tls.txt" | grep -q '"gravite":"avertissement"' \
        && ok "rapports de passage exportés au format structuré (gravité « avertissement » pour la menace)" \
        || echec "rapports de passage absents du collecteur"
    # 5. Collecteur coupé, événements produits, collecteur rétabli : reprise sans trou.
    kill "$PID_TLS" 2>/dev/null; wait "$PID_TLS" 2>/dev/null || true
    for _ in 1 2 3 4 5; do requete "${A1[@]}" /dev/null /passages >/dev/null; done
    sleep 20
    requete "${A1[@]}" "$W/j-coupe.html" /journal >/dev/null
    grep -q 'injoignable' "$W/j-coupe.html" && ok "collecteur coupé : « injoignable » et événements en attente affichés dans la Console" \
        || echec "collecteur coupé : état non affiché"
    avant=$(numeros "$COL/recus-tls.txt" | sort -n | tail -1)
    lancer_collecteur tls
    sleep 70
    r=$(contigus "$COL/recus-tls.txt")
    doublons=$(numeros "$COL/recus-tls.txt" | sort -n | uniq -d | wc -l)
    silencieux=$(awk '{ n = $0; sub(/.* n="/, "", n); sub(/".*/, "", n); r = ($0 ~ /reprise="1"/); if (vu[n]++ && !r) s++ } END { print s + 0 }' "$COL/recus-tls.txt")
    [ -n "$r" ] && [ "${r##* }" -gt "${avant:-0}" ] && [ "$silencieux" = 0 ] \
        && ok "collecteur rétabli : reprise sans perte (n° $r contigus, dernier avant coupure $avant), $doublons doublon(s), tous marqués reprise=\"1\"" \
        || echec "reprise : intervalle « $r », dernier avant $avant, doublons non marqués $silencieux"
    requete "${A1[@]}" "$W/j-repris.html" /journal >/dev/null
    grep -q 'injoignable' "$W/j-repris.html" && echec "Console : toujours « injoignable » après reprise" || ok "Console : export de nouveau à jour"
    # 6. Conservation réduite à 200 jours (auto-validation refusée, admin-02 valide).
    code=$(requete "${A1[@]}" "$W/j-cons.html" /journal/conservation "csrf=$S1" "jours=200")
    code2=$(valider "$W/j-cons.html" A1)
    code3=$(valider "$W/j-cons.html" A2)
    [ "$code" = 200 ] && [ "$code2" = 400 ] && [ "$code3" = 200 ] && grep -q '200 jours (double validation)' "$W/val.html" \
        && ok "conservation : 200 jours demandés par admin-01, auto-validation refusée, validés par admin-02 (préavis de 7 jours)" \
        || echec "conservation : demande $code, auto-validation $code2, validation $code3"
    # 7. Console série : sauvegarde, horloge avancée, purges.
    connexion_console || return
    J=/var/lib/barbacane-serveur/svc/etat/registre
    PUB=/etc/barbacane-serveur/audit/cle-audit.pub
    racine "mkdir -p /mnt/support && mount /dev/vdb /mnt/support && barbacane-sauvegarde cles-destinataire /root/coffre --sans-phrase >/dev/null && cp /root/coffre/destinataire.pem /etc/barbacane-serveur/sauvegarde/ && barbacane-sauvegarde creer --destination /mnt/support" 180
    [ "$RC" = 0 ] && grep -q 'créée' "$SORTIE" && ok "sauvegarde chiffrée créée sur le disque « support » ($(grep -o 'créée : [^ ]*' "$SORTIE" | head -1))" \
        || echec "sauvegarde : $(tail -n 3 "$SORTIE")"
    racine "nft list set inet barbacane syslog; systemctl is-active barbacane-syslog barbacane-conservation.timer"
    grep -q '10.0.3.100 . tcp . 6514' "$SORTIE" && ok "pare-feu : seule la cible Syslog validée est ouverte ($(grep -o '10.0.3.100 . tcp . 6514' "$SORTIE"))" \
        || echec "pare-feu : ensemble syslog : $(cat "$SORTIE")"
    # +100 jours : rotation, rien de purgé (limite = T0 − 100 j).
    racine "date -u -s @$((T0 + 100 * 86400)) >/dev/null && systemctl start barbacane-conservation.service && journalctl -q -o cat -n 6 -u barbacane-conservation -u barbacane-conservation-registre && /usr/local/sbin/barbacane-registre jeton labo >/dev/null && barbacane-sauvegarde creer --destination /mnt/support >/dev/null && ls $J/audit-segments && /usr/local/lib/barbacane-serveur/barbacane-registre /var/lib/barbacane-serveur/svc/registre.conf conservation-etat" 240
    [ "$RC" = 0 ] && grep -q 'passages : 2' "$SORTIE" && grep -q '^0000000000000000000[0-9]*' "$SORTIE" && grep -q 'Segment n°' "$SORTIE" \
        && ok "horloge +100 j : segment du jour rangé et scellé, 2 passages conservés (200 j pas encore atteints)" \
        || echec "horloge +100 j : $(tr '\n' ' ' < "$SORTIE" | head -c 600)"
    # +250 jours : purge des passages (T0 < limite), du segment de T0 et de la sauvegarde de T0.
    racine "date -u -s @$((T0 + 250 * 86400)) >/dev/null && systemctl start barbacane-conservation.service && journalctl -q -o cat -n 8 -u barbacane-conservation -u barbacane-conservation-registre; barbacane-sauvegarde purger --destination /mnt/support; ls $J/audit-segments; ls /mnt/support | grep -c '\\.cms\$'; /usr/local/lib/barbacane-serveur/barbacane-registre /var/lib/barbacane-serveur/svc/registre.conf conservation-etat; barbacane-audit verifier $J/audit.jsonl $PUB; echo code-verification=\$?; barbacane-audit structurer $J/audit.jsonl | grep -o '\"objet\":\"[a-z]*\"\\|\"type\":\"segment_purge\"' | sort | uniq -c" 300
    cp "$SORTIE" "$W/purge-250j.txt"
    grep -q 'rapport(s) de passage purgé(s)' "$SORTIE" && grep -q 'passages : 0' "$SORTIE" \
        && ok "horloge +250 j : 2 rapports de passage PURGÉS (fichiers et index ; trace « purge » au journal)" || echec "purge des passages : $(grep -i 'passage' "$SORTIE" | head -3)"
    grep -q 'segment(s) purgé(s) n°' "$SORTIE" && grep -q 'code-verification=0' "$SORTIE" && grep -q 'purgés (conservation)' "$SORTIE" \
        && ok "journal d'audit : segment de T0 purgé, CHAÎNE RESTANTE VÉRIFIÉE depuis l'ancre signée ($(grep -o 'Journal intègre[^.]*' "$SORTIE" | head -1))" \
        || echec "rotation/purge du journal : $(grep -E 'segment|intègre|ALTÉRÉ|code-verification' "$SORTIE" | head -4 | tr '\n' ' ')"
    grep -q '1 sauvegarde(s) purgée(s)' "$SORTIE" && grep -qx '1' "$SORTIE" \
        && ok "sauvegardes : celle de T0 (250 j) purgée du support, celle de T0+100 j gardée ; purge inscrite au journal" \
        || echec "purge des sauvegardes : $(grep -i 'sauvegarde' "$SORTIE" | head -3)"
    grep -q '"objet":"sauvegardes"' "$SORTIE" && grep -q '"objet":"passages"' "$SORTIE" \
        && ok "purges tracées au journal d'audit (purge passages, purge sauvegardes, segment_purge)" || echec "traces de purge absentes"
    # Horloge rétablie (heure du banc) ; résultat vu dans la Console.
    racine "date -u -s @$(date +%s) >/dev/null && umount /mnt/support && date -u"
    sleep 5
    code=$(requete "${A1[@]}" "$W/j-passages.html" /passages)
    ! grep -q 'borne-banc' "$W/j-passages.html" && [ "$code" = 200 ] && ok "Console : page Passages vide après la purge" || echec "Console : passages encore affichés (HTTP $code)"
    code=$(requete "${A1[@]}" "$W/j-verif.html" /audit/verification)
    grep -q 'Chaîne intègre' "$W/j-verif.html" && grep -q 'purgés par la conservation' "$W/j-verif.html" \
        && ok "Console : vérification de la chaîne restante OK ($(grep -o 'Chaîne intègre[^<]*' "$W/j-verif.html" | head -1))" \
        || echec "Console : vérification après purge : $(grep -o 'b-avis[^<]*<span>[^<]*' "$W/j-verif.html" | head -2)"
    attendre_fichier "$COL/recus-tls.txt" '"type":"segment_purge"' 90 \
        && ok "collecteur TLS : traces de purge reçues (segment_purge, purge)" || echec "collecteur TLS : traces de purge non reçues"
    # 8. Syslog en clair (TCP), signalé : demande d'admin-02, validation par admin-01.
    lancer_collecteur clair
    code=$(requete "${A2[@]}" "$W/j-clair.html" /journal/syslog "csrf=$S2" "mode=tcp-clair" "adresse=10.0.3.100" "port=5514")
    code2=$(valider "$W/j-clair.html" A2)
    code3=$(valider "$W/j-clair.html" A1)
    [ "$code" = 200 ] && [ "$code2" = 400 ] && [ "$code3" = 200 ] && grep -q 'EN CLAIR' "$W/val.html" \
        && ok "Syslog en clair (TCP) : demande d'admin-02, auto-validation refusée, validé par admin-01, avertissement affiché" \
        || echec "Syslog en clair : demande $code, auto $code2, validation $code3"
    if attendre_fichier "$COL/recus-clair.txt" '"action":"clair"' 90; then
        r=$(contigus "$COL/recus-clair.txt")
        [ -n "$r" ] && ok "collecteur en clair : $(wc -l < "$COL/recus-clair.txt") messages, n° $r sans trou (tout le journal conservé)" \
            || echec "collecteur en clair : numéros non contigus"
    else echec "collecteur en clair : rien reçu"; fi
    requete "${A1[@]}" "$W/j-tab.html" /tableau >/dev/null
    grep -q 'EN CLAIR' "$W/j-tab.html" && ok "tableau de bord : alerte « export Syslog EN CLAIR »" || echec "tableau de bord : pas d'alerte en clair"
    racine "nft list set inet barbacane syslog"
    grep -q '10.0.3.100 . tcp . 5514' "$SORTIE" && ! grep -q '6514' "$SORTIE" && ok "pare-feu : cible remplacée (seul 10.0.3.100:5514 ouvert)" || echec "pare-feu après changement : $(cat "$SORTIE")"
    kill "$PID_TLS" "$PID_CLAIR" 2>/dev/null || true
    cp "$COL"/recus-*.txt "$W/" 2>/dev/null || true
}
