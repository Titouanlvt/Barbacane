# Export Syslog du journal (v2.3.0, 23/11/2026)

Étude E1 (`etude-conformite-e1.md` §2.2 R6, §4, écart bloquant n° 3) : un serveur compromis ne
doit pas pouvoir effacer ses traces avant qu'elles soient sorties. Code :
`serveur/passerelle/src/syslog.rs`, `serveur/passerelle/src/bin/barbacane-syslog.rs`,
`serveur/web/src/journal.rs`, `serveur/iso/fichiers/usr/local/sbin/barbacane-syslog-pare-feu`,
unités `barbacane-syslog*`, pare-feu `nftables.conf.modele`.

## 1. Réglage (Console, double validation)

Page **Journal → Conservation et export**, administrateur : transport, adresse IPv4 du
collecteur, port, et en TLS le nom attendu dans son certificat, l'AC du collecteur (PEM collé) et
l'option mTLS. Toute modification **et la désactivation** passent par la double validation
(opération `syslog` ; auto-validation refusée). Rien n'est appliqué avant la validation.

| Transport | Norme | Garanties |
|---|---|---|
| **TLS 1.3** (recommandé) | RFC 5425, cadrage par longueur | rustls, `TLS_AES_256_GCM_SHA384`/`TLS_AES_128_GCM_SHA256`, P-384/P-256 (D6) ; certificat du collecteur vérifié contre l'AC configurée **et** le nom attendu (DNS ou adresse IP) ; mTLS facultatif ; remise confirmée (§3) |
| TCP en clair | RFC 6587, cadrage par longueur | remise confirmée ; **aucune confidentialité ni intégrité** : avertissement permanent dans la Console et sur le tableau de bord, `syslog {action: clair}` au journal (gravité avertissement) |
| UDP en clair | RFC 5426 | **ni confirmation ni chiffrement** : à éviter ; mêmes avertissements |

Contrôles : adresse IPv4 hors bouclage, diffusion et multidiffusion ; **aucun nom DNS** (le serveur
n'a pas de résolveur) ; AC et certificat client analysés, conservés sous leur empreinte SHA-256
(`ac-<sha256>.pem`, `client-<sha256>.pem`), l'empreinte est dans la demande validée : le validateur
valide exactement ce qu'il voit (sujet et échéance affichés), un fichier modifié ensuite est refusé.

**mTLS** : « Générer une nouvelle clé client » → clé P-256 **tirée par le serveur** (elle ne le
quitte jamais) et sa demande de certificat affichée ; la faire signer par l'AC du collecteur ;
« Déposer le certificat » (refusé s'il ne correspond pas à la clé) ; puis demander un réglage TLS
avec « présenter le certificat client ».

## 2. Pare-feu : la seule cible validée, aucune sortie Internet

À la validation, la Console écrit `<registre>/syslog/pare-feu` (`aucun` ou `tcp|udp ADRESSE PORT`).
`barbacane-syslog-pare-feu.path` déclenche `barbacane-syslog-pare-feu` (root), qui relit cette ligne
**strictement** (64 octets, une ligne, motif fixe), exige une adresse du **réseau
d'administration** du serveur (et pas la sienne), remplit l'ensemble nftables `syslog`
(vide à l'installation) puis relance l'exportateur. Règle de sortie :
`oifname <admin> meta skuid barbacane-svc ip daddr . meta l4proto . th dport @syslog ct state new accept`.
Le serveur n'a toujours aucune route par défaut : rien ne peut sortir vers Internet.

## 3. File d'attente persistante, reprise sans perte ni doublon silencieux

- La file est **le journal d'audit lui-même** (segments compris) : rien n'est recopié (pas de
  seconde copie de données personnelles), rien ne se perd au redémarrage. `curseur.json` retient
  le dernier numéro dont la remise est **confirmée** et le plus grand numéro déjà écrit.
- **Remise confirmée** (TCP, TLS) : un lot (500 messages au plus) par connexion ; le serveur ferme
  son côté (`close_notify` puis FIN) et attend que le collecteur ferme le sien (10 s) : le
  collecteur ne ferme qu'après avoir lu tout ce qui précède notre FIN (rsyslog, syslog-ng ; c'est
  une **exigence** pour le collecteur). Sinon le lot est renvoyé plus tard : les messages déjà écrits
  sont marqués **`reprise="1"`** et portent le même `id` (doublon possible, jamais silencieux).
- **Collecteur injoignable** : nouvelles tentatives de 1 s à 60 s ; `syslog {action: injoignable}`
  au premier échec de l'épisode, `reprise` au retour ; la Console et le tableau de bord affichent
  l'état, le nombre d'événements en attente et la dernière erreur.
- **Débordement** : au-delà de **100 000** événements en attente, alerte « file en débordement »
  (Console, tableau de bord, `syslog {action: debordement}`, gravité erreur), une fois par
  épisode. Les événements restent dans le journal et partent au retour du collecteur : la file est
  bornée par la durée de conservation, pas par une troncature. Un événement **purgé** par la
  conservation avant d'avoir été remis est signalé (`syslog {action: perte, detail: "N1-N2"}`,
  compteur dans la Console).
- **Nouvelle cible** : elle reçoit tout le journal encore conservé, depuis le premier
  enregistrement présent (ce qui a été purgé avant n'est pas une perte pour elle).
- **Exportateur arrêté** : la Console le signale après 5 minutes sans mise à jour de son état.

## 4. Service

`barbacane-syslog.service` : hors conteneur, sous **barbacane-svc** (propriétaire du journal),
écriture limitée au registre, familles d'adresses IPv4 et Unix, aucune capacité, filtre d'appels
système, 256 Mio. Inactif tant qu'aucun réglage n'est validé (passe toutes les secondes, rien à
faire). `barbacane-syslog CONFIG --une-passe` pour un essai à la main.

## 5. Limites

- Un serveur déjà compromis (root) peut couper l'export ; ce qui a été remis avant reste chez le
  collecteur, et la coupure est visible chez lui (fin des messages, `injoignable` manquant). Le
  collecteur séparé, homologué avec le SI, reste à la charge de l'organisme (2.8 : rôles séparés).
- Les conteneurs (même compte barbacane-svc) peuvent joindre la cible validée, et elle seule.
- Clé client mTLS en fichier (0600) : TPM prévu en 2.4 avec les autres clés du serveur.
- SD-ID `barbacane@32473` (numéro réservé à la documentation) : à remplacer par un numéro
  d'entreprise privé du projet si l'utilisateur en obtient un.

## 6. Preuves

`serveur/passerelle/tests/syslog.rs` (collecteurs rustls réels : TLS 1.3 + mTLS, mauvais nom refusé,
coupure puis reprise sans trou, remise non confirmée puis doublons marqués, TCP et UDP en clair,
débordement, nouvelle cible, perte après purge), `serveur/web/tests/journal.rs` (double validation,
cibles refusées, pare-feu, alertes), banc QEMU (`tests/serveur/qemu-journal.sh` : ISO installée,
collecteur de test TLS 1.3 avec mTLS exigé puis en clair, coupure et reprise, pare-feu).
