# Protocole borne ↔ serveur — version 1 (étape 5 « socle », 20/11/2026)

Protocole entre le futur `barbacane-agent` (borne en ligne) et la passerelle du serveur.
Implémentation de référence des messages : crate `serveur/protocole` (`barbacane-protocole`),
partagée par la passerelle et l'agent. Décisions appliquées : D1 (serveur traité comme un SI DR),
D2 (aucun nom de fichier), D4 (port tiré à l'installation), D6 (cryptographie), D8 (CRL
fail-closed), D9 (clé de la borne dans le TPM). Profils de certificats :
`politique-certification.md`.

## 1. Principes

1. **Tout message de l'autre partie est hostile** (conception §2, principe 7) : taille contrôlée
   avant analyse, JSON strict (`deny_unknown_fields`, champ répété ou absent = refus), chaque
   texte borné en longueur et en jeu de caractères. Les mêmes contrôles s'appliquent dans les
   deux sens (l'agent décode les réponses du serveur avec la même crate).
2. **Versionné** : chaque message porte `"version": 1`. Une autre valeur → `version_non_geree`.
   Toute évolution du schéma (même un champ optionnel ajouté) change de version : un champ
   inconnu est toujours un refus.
3. **Aucun nom de fichier, aucun identifiant d'utilisateur** dans les messages de cette version
   (D2, minimisation). Les rapports (étape 3 de la conception) auront leur propre schéma.
4. **Le serveur ne commande rien** : il répond. La borne décide (conception §2, principe 1).
5. **Codes d'erreur peu bavards** : un jeton inconnu, expiré ou déjà utilisé donne la même
   réponse (`jeton_invalide`) ; le détail n'est que dans le journal du serveur.

## 2. Transport

| Élément | Valeur |
|---|---|
| Chiffrement | TLS 1.3 seul, `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, groupes `secp384r1`, `secp256r1` (D6) — sur les deux écoutes |
| Authentification du serveur | certificat signé par la CA « serveur », dont l'empreinte est **épinglée dans l'ISO** de la borne en ligne (conception §3.5) : aucune confiance au premier usage |
| Requête | HTTP/1.1, **une requête par connexion**, `POST` (ou `GET /sante`), corps JSON UTF-8, `Content-Length` obligatoire et exact, `Transfer-Encoding` refusé |
| En-têtes | 4 Kio au plus (ligne de requête comprise) |
| Corps | borné par message (§4) ; au-delà : `413 trop_gros`, sans lecture du corps |
| Réponse | `Content-Type: application/json`, `Connection: close` ; 16 Kio au plus (l'agent refuse au-delà) |
| Délais | côté serveur : 10 s d'inactivité par lecture ou écriture, et **durée totale** par connexion (poignée de main TLS + requête + réponse) de **20 s** (service) et **10 s** (enrôlement) : un client lent (« slowloris ») ne garde pas une place au-delà |

### 2.1 Deux écoutes distinctes (choix au regard de D1 et D6)

| Écoute | Port | Certificat client | Routes | Connexions |
|---|---|---|---|---|
| **enrôlement** | `port_enrolement` (tiré à l'installation, inscrit dans le jeton, D4) | **aucun** | `POST /enrolement/demande`, `POST /enrolement/retrait` | 8 simultanées |
| **service** | `port` (tiré à l'installation, communiqué à la borne au retrait du certificat) | **obligatoire** (CA bornes, CRL relue à chaque poignée de main) | `GET /sante`, `POST /battement`, `POST /renouvellement` | 256 simultanées |

Pourquoi deux écoutes plutôt qu'un vérificateur de certificat client « optionnel » limité à une
route :

- **Fail-closed par construction** : sur l'écoute de service, une connexion sans certificat valide
  est coupée **pendant la poignée de main TLS**, avant tout code applicatif. Avec un certificat
  optionnel, la protection de chaque route reposerait sur une condition dans le routage : une
  seule erreur exposerait le battement ou le renouvellement à un client anonyme. Ici, aucune
  route de service n'existe sur l'écoute d'enrôlement (réponse `404 introuvable`) et
  inversement.
- **Filtrage et durcissement séparés (D1)** : le pare-feu peut n'ouvrir le port d'enrôlement
  qu'aux sous-réseaux des sites déclarés, voire le fermer hors campagne d'enrôlement, sans
  toucher au service. Limites propres (8 connexions, 10 s par connexion, corps de 4 Kio).
- **Même cryptographie (D6)** : les deux écoutes utilisent la même configuration TLS 1.3 et le
  même certificat serveur ; seule la vérification du client diffère.

Coût : un second port à documenter et à filtrer (réserve de D4 : à faire valider par l'AH).

## 3. Cycle de vie d'une borne

```
          jeton (admin, 1 h, usage unique, lié à un site)
                │
   borne : clé P-256 générée dans le TPM, demande PKCS#10 signée
                │  POST /enrolement/demande  (écoute d'enrôlement, CA serveur épinglée)
                ▼
         demande EN ATTENTE  ──(24 h sans décision)──▶ expirée
                │  l'administrateur compare l'empreinte affichée sur la borne
                │  à celle de `barbacane-registre demandes`, puis :
        ┌───────┴────────┐
   valider ID EMPREINTE   refuser ID
        │                    │
   certificat 90 jours     REFUSÉE (la borne l'apprend au retrait)
   (CA bornes)
        │  POST /enrolement/retrait → certificat + chaîne + port de service + heure
        ▼
     ACTIVE ── battements (mTLS) ── renouvellement à mi-vie ──┐
        │                                                       │ (même identité)
   revoquer UUID MOTIF                                          ▼
        ▼                                                  ACTIVE (nouveau certificat)
     RÉVOQUÉE : numéro de série inscrit dans la CRL republiée ; refus à la connexion suivante
```

### 3.1 Jeton d'enrôlement

- Créé par un administrateur (`barbacane-registre CONFIG jeton SITE`) : 128 bits aléatoires,
  affichés en base32 (26 caractères `A-Z2-7`) précédés du port d'enrôlement :
  `PORT-SECRET`, par exemple `43117-ABCDEFGHIJKLMNOPQRSTUVWXYZ`. Saisie insensible à la casse,
  espaces ignorés.
- Le serveur ne conserve que le **SHA-256 du secret** (un vol du registre ne donne aucun jeton).
- Valable **1 heure**, **usage unique** : il est consommé au dépôt d'une demande bien formée,
  même si cette demande est ensuite refusée par l'administrateur.
- Lié à un site (`site-<n>`) : le certificat émis portera ce site.

### 3.2 Demande (borne → serveur)

`POST /enrolement/demande`, corps ≤ 4 Kio :

```json
{"version":1,"jeton":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n…","version_logiciel":"2.0.0"}
```

| Champ | Contrainte |
|---|---|
| `jeton` | secret seul (sans le port), 26 caractères base32 décodables en 16 octets |
| `csr_pem` | **un seul** bloc PEM `CERTIFICATE REQUEST`, 2 Kio au plus ; signature vérifiée ; clé **ECDSA P-256** (OID `id-ecPublicKey` + `prime256v1`, point non compressé) ; signature `ecdsa-with-SHA256` |
| `version_logiciel` | `[0-9A-Za-z.+~-]`, 1 à 32 caractères |

La clé privée est générée **sur la borne, dans le TPM** (D9) et ne la quitte jamais : seul le
PKCS#10 voyage. Le serveur **ignore le sujet et les extensions demandés** : il fixe lui-même
le nom, le site, l'identifiant et les extensions (§3.4).

Réponse `202` :

```json
{"version":1,"demande_id":"<32 hex>","empreinte":"<64 hex>","heure_serveur":1795000000}
```

- `empreinte` = SHA-256 de la demande DER. La borne l'**affiche** ; l'administrateur la compare.
- `demande_id` (128 bits aléatoires) sert au retrait.
- 64 demandes en attente au plus (`503 surcharge` au-delà).

### 3.3 Retrait (borne → serveur)

`POST /enrolement/retrait`, corps `{"version":1,"demande_id":"…"}` ≤ 1 Kio. La borne
interroge toutes les 30 s au plus. Réponse `200` :

| `decision` | Champs supplémentaires |
|---|---|
| `en_attente` | aucun |
| `refusee` | aucun |
| `validee` | `certificat_pem` (le certificat de la borne), `chaine_pem` (certificat + CA bornes), `port_service` |

Tous portent `heure_serveur`. Le certificat est une donnée publique : le connaître ne permet
rien sans la clé du TPM. Demande inconnue ou expirée : `404 demande_inconnue`.

### 3.4 Validation par un administrateur et certificat émis

`barbacane-registre CONFIG valider DEMANDE_ID EMPREINTE [NOM]` : l'empreinte **doit être
retapée** (ou collée) depuis l'écran de la borne ; elle est comparée à celle de la demande,
sinon refus. C'est la parade au vol du jeton (conception §6). La signature est faite par la
CA « bornes » (clé P-384, ECDSA-SHA384) :

| Élément | Valeur |
|---|---|
| Sujet | `CN=borne <nom>, OU=<site>, O=<O de la CA bornes>` (`<nom>` : `[a-z0-9-]`, 1–32, donné par l'administrateur, sinon dérivé de l'identifiant) |
| SAN | `URI:urn:barbacane:borne:<site>:<uuid>`, `DNS:<uuid>.bornes.barbacane.invalid` (`<uuid>` tiré par le serveur) |
| Extensions | `basicConstraints CA:FALSE` critique, `keyUsage digitalSignature` critique, `extendedKeyUsage clientAuth`, SKI, AKI |
| Validité | 90 jours (début : 1 minute avant l'émission) |
| Numéro de série | 128 bits aléatoires |

L'identité applicative de la borne est l'**uuid** du SAN URI, jamais le CN.

### 3.5 Renouvellement (mTLS)

`POST /renouvellement`, corps `{"version":1,"csr_pem":"…"}` ≤ 4 Kio, sur une connexion
authentifiée par le certificat courant. Mêmes contrôles de la demande qu'au §3.2 (la borne
génère une **nouvelle** clé dans le TPM). Accepté seulement à partir de la **mi-vie** du
certificat présenté (`409 renouvellement_premature` avant) ; pas de nouvelle validation humaine
(politique §4) ; même uuid, même nom, même site. Réponse `200` :
`{"version":1,"certificat_pem":"…","chaine_pem":"…","heure_serveur":…}`.

L'ancien certificat reste accepté **jusqu'à la première connexion avec le nouveau** (la borne
peut perdre la réponse) ; à cette connexion, son numéro de série est inscrit dans la CRL
(motif `superseded`). Un certificat ni courant ni précédent est refusé (`403 borne_refusee`),
même s'il n'est pas encore dans la CRL.

### 3.6 Révocation

`barbacane-registre CONFIG revoquer UUID MOTIF` (motifs : `volee`, `reformee`, `cle-suspecte`,
`changement-site`, `fin-de-vie`). Le registre passe la borne en `revoquee`, inscrit ses numéros
de série (courant et précédent) dans la CRL, qui est **republiée aussitôt** (validité 7 jours,
D8) en conservant les entrées déjà présentes. La passerelle relisant la CRL à chaque poignée de
main, la connexion suivante est refusée au niveau TLS ; le registre la refuse aussi
(`borne_refusee`) si la CRL n'était pas encore relue. `barbacane-registre CONFIG crl`
republie la CRL (à lancer chaque jour, D8).

## 4. Service : battement, supervision, heure

### 4.1 Battement

`POST /battement` toutes les 60 s, corps ≤ 1 Kio :

| Champ | Type | Contenu |
|---|---|---|
| `heure_borne` | entier | heure de la borne, secondes Unix UTC |
| `version_logiciel` | texte | `[0-9A-Za-z.+~-]`, 1–32 |
| `etat` | `en_service` \| `hors_service` \| `maintenance` | état déclaré |
| `age_signatures_s` | entier | âge de la base antivirale |
| `espace_libre_octets` | entier | espace libre de l'espace de travail |
| `rapports_en_attente` | entier 32 bits | file locale non transmise |

Réponse `200` : `{"version":1,"heure_serveur":…,"ecart_s":…,"prochain_battement_s":60}`.

### 4.2 Heure

- **Le serveur est la source de temps du site** (conception §3.11) ; la borne ne prend l'heure
  **que** par ce canal authentifié (CA serveur épinglée) : `heure_serveur` figure dans toutes
  les réponses, erreurs comprises.
- Seuil : **300 secondes** (`ECART_HORLOGE_MAX_S`). À chaque battement, le serveur calcule
  `ecart_s = heure_borne − heure_serveur`. Au-delà du seuil (en valeur absolue), le battement est
  **refusé** : `409 horloge_derivee` (avec `heure_serveur`) ; la borne est marquée en dérive dans
  la supervision (alerte). L'agent se resynchronise sur `heure_serveur` et renvoie un battement ;
  si l'écart persiste, la borne se bloque (conception §3.11).
- Enrôlement : aucune vérification d'écart (une borne neuve peut avoir une horloge fausse) ;
  l'agent règle son horloge sur `heure_serveur` du retrait, avant la première connexion mTLS.

### 4.3 Supervision

`barbacane-registre CONFIG supervision` : pour chaque borne, uuid, nom, site, statut,
version logicielle, état déclaré, dernière vue (heure du serveur), écart d'horloge, fin de
validité du certificat, et les **alertes** :

| Alerte | Condition |
|---|---|
| `silence` | aucun battement accepté depuis 300 s (5 périodes) — ou jamais vue 300 s après l'émission |
| `horloge` | dernier écart mesuré > 300 s |
| `expiration` | certificat expirant dans moins de 30 jours |
| `hors_service` | la borne se déclare hors service |

Code de sortie 0 sans alerte, 3 avec au moins une alerte (utilisable par une sonde).

## 5. Codes d'erreur

Corps de toute erreur : `{"version":1,"code":"<code>","heure_serveur":…}`.

| Code | HTTP | Cause |
|---|---|---|
| `requete_invalide` | 400 | HTTP mal formé, JSON invalide, champ inconnu, répété, absent ou hors bornes |
| `version_non_geree` | 400 | `version` ≠ 1 |
| `demande_invalide` | 400 | PKCS#10 illisible, signature fausse, clé non P-256 |
| `jeton_invalide` | 403 | jeton inconnu, expiré ou déjà utilisé (indistinguables) |
| `borne_refusee` | 403 | borne inconnue du registre, révoquée, ou certificat remplacé |
| `demande_inconnue` | 404 | identifiant de demande inconnu ou expiré |
| `introuvable` | 404 | route absente de cette écoute |
| `methode_refusee` | 405 | méthode autre que celle de la route |
| `horloge_derivee` | 409 | écart d'horloge > 300 s |
| `renouvellement_premature` | 409 | avant la mi-vie du certificat |
| `trop_gros` | 413 | en-têtes > 4 Kio ou corps > maximum du message |
| `interne` | 500 | erreur du serveur |
| `surcharge` | 503 | trop de demandes en attente |

Un refus TLS (pas de certificat, certificat révoqué, CRL expirée, TLS 1.2) coupe la connexion
sans réponse HTTP.

## 6. Registre du serveur (implémentation du socle)

- Fichier JSON unique (`registre.json`, droits 0600) dans le dossier d'état ; chaque opération
  prend un **verrou exclusif** (`flock` sur `registre.verrou`), relit, modifie, écrit un fichier
  temporaire, `fsync`, puis le **renomme** (jamais d'état à moitié écrit). Partagé entre la
  passerelle et la commande d'administration locale.
- Pourquoi pas SQLite : aucune crate SQLite n'est présente dans `Cargo.lock` ; `rusqlite` ajouterait
  `libsqlite3-sys` (environ 250 000 lignes de C compilées dans le serveur, liaison FFI). La base
  cible est PostgreSQL (conception §2 bis) ; pour 100 bornes, le fichier verrouillé suffit et
  n'ajoute **aucune dépendance**. À remplacer au passage à PostgreSQL (interface `Registre`).
- Journal des opérations d'administration : `journal.jsonl` (ajout seul). Le journal d'audit
  **chaîné et signé** (conception §3.9) viendra avec l'étape « rapports et journaux ».
- La clé de la CA bornes est un fichier PEM sur le serveur (lab) ; dans le TPM ensuite
  (politique §6). **Limite du socle** : le processus de la passerelle, exposé au réseau, lit
  cette clé (renouvellement, CRL après remplacement). À séparer dans un service PKI à compte
  dédié, joint par socket local, avant la production.

## 7. Menaces et preuves

| Menace | Parade | Preuve (`serveur/passerelle/tests/enrolement.rs`) |
|---|---|---|
| Jeton rejoué ou volé tardivement | usage unique, 1 h, haché | `jeton_expire_ou_reutilise_refuse` |
| Jeton volé à temps | validation humaine avec comparaison d'empreinte | `demande_non_validee_sans_certificat`, `empreinte_fausse_refusee` |
| Certificat émis hors profil | sujet, SAN, extensions et durée fixés par le serveur | `validee_certificat_utilisable_en_mtls` |
| Clé faible ou exportable | P-256 exigé, demande vérifiée ; clé dans le TPM (agent) | `cle_non_p256_refusee` |
| Accès anonyme aux routes de service | écoute distincte, mTLS obligatoire | `routes_separees_par_ecoute` |
| Borne volée | révocation, CRL republiée, relue à chaque connexion | `revocation_refuse_la_connexion_suivante` |
| Message hostile | taille avant analyse, schéma strict | `message_mal_forme_ou_trop_gros_refuse` |
| Horloge faussée | heure du serveur, refus au-delà de 300 s, alerte | `derive_horloge_signalee` |
| Borne muette | alerte `silence` | `battement_met_a_jour_la_supervision` |
| Client lent occupant les places (slowloris) | durée totale par connexion, plafond de 8 sur l'enrôlement, compteurs séparés par écoute | `client_lent_coupe_sans_bloquer_les_bornes` |
| Certificat remplacé réutilisé | précédent révoqué au premier usage du nouveau | `renouvellement_a_mi_vie` |

## 8. PRÉVU

- `barbacane-agent` : enrôlement, battement, renouvellement et mode dégradé **faits** le 20/11
  (`borne/agent/`, `docs/suite/borne-en-ligne.md`) ; reste : clés dans le TPM ; interface web
  d'administration (D10) à la place de la commande locale ; double validation des révocations
  massives (conception §3.10).
- Plancher signé hors ligne et politique à chaud dans la réponse de retrait (conception §3.7) ;
  rapports et journaux (version 2 du protocole ou routes nouvelles).
- Journal d'audit chaîné ; PostgreSQL ; republication quotidienne automatique de la CRL.

## 9. Ajout : mises à jour centralisées (20/11/2026, version 1 inchangée)

Ajout **compatible** : routes et messages nouveaux (`serveur/protocole/src/maj.rs`), aucun
message existant modifié ; un agent qui n'utilise que `/battement` n'est pas concerné. Conception :
`serveur-maj-audit.md` §2. Les trois routes ne sont servies que par l'écoute **mTLS** (sur
l'écoute d'enrôlement : `404 introuvable`) et passent le même contrôle applicatif que le
battement (borne connue, active, certificat courant).

| Route | Corps (≤ 1 Kio) | Réponse |
|---|---|---|
| `POST /maj/battement` | `Battement` (§4.1), mêmes contrôles et mêmes erreurs | `200 AccuseBattementMaj` |
| `POST /maj/telechargement` | `{"version":1,"version_maj":N}` | `200 application/octet-stream`, `Content-Length` = `taille` ; sinon erreur JSON |
| `POST /maj/rapport` | `{"version":1,"version_maj":N,"resultat":"appliquee"\|"echec"}` | `200 {"version":1,"heure_serveur":…}` |

`AccuseBattementMaj` (≤ 4 Kio) = champs de `AccuseBattement` + `mise_a_jour` **facultatif** (absent
s'il n'y a rien à proposer) :

| Champ | Contrainte |
|---|---|
| `version_maj` | entier (version du manifeste, `AAAAMMJJHHMM`) |
| `sha256` | 64 hexadécimaux minuscules, du `.bcu` |
| `taille` | 1 à 4 Gio |
| `signature_minisign` | contenu du `.bcu.minisig` : ASCII imprimable, ≤ 1 Kio, 4 lignes, commentaire de confiance exactement `barbacane-maj version <version_maj>` |

Règles :

- Proposé tant que la borne n'a pas rapporté `appliquee` ou `echec` pour cette version.
  Téléchargement refusé (`404 introuvable`) pour une version non proposée à cette borne.
- La borne ne fait **aucune confiance** au serveur pour le contenu : elle vérifie la taille, le
  sha256, puis la signature minisign avec SA clé (`/etc/barbacane/maj.pub`) et l'anti-retour du
  manifeste, exactement comme pour un paquet lu sur clé USB.
- Au plus 8 téléchargements simultanés (`503 surcharge`) ; durée totale de la connexion 20 s
  + 1 s par 512 Kio.
- Un rapport ne vaut qu'une fois par version proposée (`404 introuvable` ensuite).
- Aucun nouveau code d'erreur (la liste du §5 est inchangée).

### 9.1 Côté borne (agent et admind, 20/11/2026, 2e jalon de la borne en ligne)

L'agent bat sur `/maj/battement` (et non plus `/battement` : mêmes contrôles côté serveur). Il
télécharge le paquet proposé, contrôle taille et `sha256` annoncés, le dépose pour
`barbacane-admind`, **n'applique jamais rien** ; l'administrateur local décide (écran
Administration → Serveur), admind vérifie avec la clé de la borne par la chaîne existante, puis
l'agent rapporte `appliquee` ou `echec`. Détails : `borne-en-ligne.md` § Mises à jour.

## 10. PRÉVU : rapports minimaux de passage (ajout, D2)

Non fait au 2e jalon de la borne en ligne (priorité : enrôlement par l'écran et mises à jour).
Conception retenue, pour le jalon suivant :

- **Route** `POST /rapport/passage` (écoute mTLS seulement), message nouveau, **sans nom de
  fichier ni chemin** (D2) : `{"version":1,"id":<uuid du passage>,"horodatage":…,"verdict":"sain"|"menace"|"refuse"|"erreur","support":<identifiant de support = SHA-256 de vendorid:productid:numéro de série>,"fichiers":[{"taille":…,"sha256":…,"verdict":…}]}`,
  fichiers bornés (≤ 10 000 par message, sinon découpage `partie`/`parties`), corps ≤ 1 Mio.
- **Production** : par admind (root), qui lit les rapports détaillés de l'analyseur
  (`/var/lib/barbacane/rapports/*.json`) et n'en retient que ces champs ; l'agent (processus
  réseau) ne voit **jamais** un nom de fichier. Dépôt dans la file locale bornée de l'agent
  (`file.json`, jamais de perte, pleine → borne hors service), rejeu après coupure, retrait du
  premier élément seulement après `200` (idempotent : `id` déjà reçu → `200`).
- **Serveur** : réception, stockage (registre, puis PostgreSQL), événement d'audit
  `rapport_passage` (uuid de borne, id, verdict ; ajout au schéma de `barbacane-audit`).
