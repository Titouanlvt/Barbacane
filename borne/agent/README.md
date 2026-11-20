# barbacane-agent (borne en ligne uniquement)

Seul processus réseau de la borne en ligne : connexion **sortante** unique vers le serveur
(TLS 1.3 mutuel, CA serveur épinglée). N'existe que dans `build-iso.sh --profil en-ligne` ;
jamais dans la borne hors ligne (décision D12, garde-fou `tests/iso/hors-ligne.sh`).

Jalon du 20/11/2026 : **enrôlement + battement** du protocole v1 (`docs/suite/protocole-agent.md`).
Aucune donnée ni aucun nom de fichier n'est envoyé (D2) : le battement ne porte que des compteurs
(heure, version, état, âge des signatures, espace libre, taille de la file locale).

## Fonctionnement

| Situation | Ce que fait l'agent | `mode` dans `etat.json` |
|---|---|---|
| Ni certificat ni demande | surveille le fichier `jeton` toutes les 5 s | `non_enrolee` |
| Jeton déposé | vérifie le port (= `port_enrolement` de l'ISO), génère une clé P-256, envoie la demande PKCS#10 ; le jeton n'est supprimé qu'après une réponse **définitive** du serveur | `attente_validation` |
| Demande en attente | publie l'**empreinte** (à comparer par l'administrateur avec `barbacane-registre … demandes`), consulte toutes les 30 s | `attente_validation` |
| Demande validée | contrôle que le certificat porte **sa** clé publique et que le port de service est celui de l'ISO, puis l'installe | — |
| Certificat valide | battement (période donnée par le serveur, 60 s) ; à mi-vie : nouvelle clé, renouvellement sur la liaison authentifiée | `connectee` |
| Serveur injoignable | nouvel essai espacé (5 s, 10 s, 20 s… 300 s au plus) ; **la borne fonctionne comme la v1** (l'agent ne commande rien) | `degradee` |
| Serveur non authentifié (certificat hors CA épinglée) | rien n'est envoyé, nouvel essai, message « serveur NON authentifié » | inchangé / `degradee` |
| Borne refusée (alerte TLS `certificate_revoked`, `borne_refusee`, certificat expiré) | **plus aucune connexion** jusqu'à un nouveau jeton | `refusee` |
| Horloge décalée de plus de 300 s | le signale (`horloge_derivee`) ; ne règle pas l'horloge (aucune capacité, voir « Limites ») | `connectee` |

Fichiers :

- `/etc/barbacane/agent.toml` (écrit par l'ISO en ligne ; exemple : `systeme/etc/agent.toml.exemple`) ;
  `/etc/barbacane/agent/ca-serveur.pem` : CA serveur, dont le SHA-256 du DER est **aussi** dans
  `agent.toml` : un fichier qui ne correspond pas empêche l'agent de démarrer.
- `/var/lib/barbacane-agent/` (0700, compte `barbacane-agent`) : `cle.pem` (0600), `chaine.pem`,
  `attente.json`, `passage-*.json` (file), `jeton` (déposé par l'administrateur), `refusee`.
- `/run/barbacane-agent/etat.json` (0644, aucun secret) : mode, empreinte de la demande, dernière
  liaison, écart d'horloge, fin de validité du certificat, file locale.

## Mises à jour relayées par le serveur (2e jalon, 20/11/2026)

Battement sur `/maj/battement`. Mise à jour proposée → téléchargement mTLS écrit au fil de l'eau
dans `maj/.reception` (taille exacte, SHA-256 annoncé ; sinon supprimé), puis
`maj/barbacane-maj-N.bcu`, `.bcu.minisig` et `annonce.json` (en dernier). L'agent **n'applique
rien** : admind vérifie (clé de la borne) et applique sur décision de l'administrateur local
(écran Administration → Serveur), puis dépose `maj/resultat.json`, que l'agent transmet par
`/maj/rapport` avant de vider `maj/`. Jeton : déposé par admind (op `serveur_jeton`).
Détails : `docs/suite/borne-en-ligne.md`.

## Clé de la borne : fichier au lab, TPM ensuite (D9)

La clé privée est générée **sur la borne** (aléa du noyau, `ring`) et ne la quitte jamais ; seul le
PKCS#10 voyage. À ce jalon elle est stockée dans un **fichier PKCS#8 0600** du dossier d'état (0700,
compte dédié) ; une clé lisible par d'autres est refusée. Limite assumée : un vol du disque donne la
clé (parade : révocation, CRL relue à chaque connexion). L'accès à la clé passe uniquement par le trait
`Coffre` (`src/coffre.rs`) : l'implémentation TPM 2.0 (clé non exportable, signature dans le TPM)
s'y substituera sans autre changement.

## File locale bornée

Fichiers `passage-<horodatage>-<id>-<partie>.json` du dossier d'état, déposés par admind (seul
producteur) : rapports minimaux de passage (protocole §10, aucun nom de fichier). Jamais de perte ;
pleine (`file_max`, 1000 par défaut) → admind refuse le dépôt, l'interface met la borne hors
service et le battement annonce `hors_service`. L'agent revalide chaque élément (schéma strict),
l'envoie sur `/rapport/passage` après le battement et ne le retire qu'après `200` ; un élément
refusé définitivement est renommé `rejet-…` (jamais effacé).

## Limites de ce jalon (suite)

- Saisie du jeton et affichage de l'empreinte **à l'écran** : par admind (écran Administration) à
  venir ; d'ici là, fichier `jeton` et `etat.json`.
- Réglage de l'horloge sur `heure_serveur` : nécessite un service privilégié (admind) ; l'agent, sans
  aucune capacité, ne fait que mesurer et signaler.
- Blocage de la borne après le délai de grâce (conception §3.1) : demande l'intégration au parcours ;
  à ce jalon la borne continue de fonctionner comme la v1 quand le serveur est absent.
- Politique, rapports, journaux, mises à jour : versions suivantes du protocole.

## Tests

`cargo test -p barbacane-agent` : unitaires + `tests/passerelle.rs` (vraie passerelle en cours de
processus, PKI de TEST de `serveur/pki/racine-test.sh`) : enrôlement, validation, battement visible
dans la supervision, renouvellement à mi-vie, mode dégradé puis reprise, révocation, CA non épinglée,
jeton d'un autre port. Bout en bout avec les vrais binaires : `tests/suite/agent-bout-en-bout.sh`.
