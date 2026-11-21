# Serveur — utilisateurs et clés USB (étapes 4 et 5, 20/11/2026)

Conception : `conception-barbacane-suite.md` §3.3 (utilisateurs), séquence « utilisation (mode
authentification) », §3.6 (pseudonymisation), §6 (menaces), §8 étapes 4 et 5. Décisions
appliquées : D1 (SI DR), D2 (aucun nom de fichier), D6 (Argon2id), D13 (mode « Aucun » par
défaut, interdit si la quarantaine est active). AIPD : `aipd.md` (mise à jour §1 et §3).

Code : `serveur/protocole/src/utilisateurs.rs` (messages, décision sur une clé USB partagée avec
la borne), `serveur/passerelle/src/utilisateurs.rs` (base, PIN, anti force brute),
`serveur/passerelle/src/lib.rs` (trois routes mTLS), `serveur/audit` (événements),
`serveur/web/src/annuaire.rs` (LDAPS), `serveur/web` (pages).

## 1. Modes (par site)

| Mode | Borne | Serveur | Données personnelles |
|---|---|---|---|
| **Aucun** (défaut, D13) | rien n'est demandé (comme la v1) | toute vérification est refusée **sans rien conserver** (audit : borne + `hors_mode`, utilisateur `inconnu`) | aucune |
| **Identification** | identifiant tapé | identifiant **actif** de l'annuaire → accepté ; inconnu → refusé (conception §3.3) | identifiant (pseudonymisé dans l'audit) |
| **Authentification** | identifiant + **PIN Barbacane** | PIN vérifié (Argon2id) ; réponse identique pour identifiant inconnu, PIN faux, compte verrouillé | identifiant + PIN dérivé |

- Le mode est réglé par site dans l'interface web ; la borne le lit dans la politique de son site
  (§4). Le site est celui du **certificat de la borne** (SAN `urn:barbacane:borne:<site>:<uuid>`),
  jamais une donnée de la requête.
- **Mode Aucun interdit si la quarantaine est activée** (D13) : `Utilisateurs::definir_mode` le
  refuse quand `quarantaine_active()` est vrai. La quarantaine n'existant pas encore (D3, étape 6),
  la fonction renvoie toujours faux ; le refus est prouvé par un test unitaire.
- Mode par borne (conception §1 « par site ou par borne ») : PRÉVU ; le site suffit à 100 bornes.

## 2. Identifiants et annuaire

- **Aucun mot de passe d'annuaire n'est saisi sur une borne** ni ne transite par elle : l'annuaire
  ne fournit que la **liste des identifiants**.
- Identifiant normalisé `[a-z0-9._-]`, 1 à 64 (minuscules ; AD compare sans casse), même fonction
  côté borne et côté import (`normaliser_identifiant`). Non conformes : ignorés et comptés.
- **Synchronisation LDAPS** (`barbacane-web annuaire CONFIG` ou bouton de la page Utilisateurs) :
  - `ldaps://` seulement (ni `ldap://`, ni StartTLS) ; **TLS 1.3 seul** (D6, mêmes suites et
    groupes que la passerelle) — **seule ancre de confiance : la CA de l'annuaire épinglée**
    (fichier PEM de la configuration), nom du serveur vérifié ; aucun magasin du système.
    Limite : un contrôleur de domaine sans TLS 1.3 (Windows Server antérieur à 2022) est refusé ;
    l'ouverture à TLS 1.2 demanderait la fonction `tls12` de rustls (décision à prendre) ;
  - compte de service en **lecture seule** (droits minimaux : lire l'attribut d'identifiant des
    comptes du groupe Barbacane), mot de passe dans un fichier 0600 lisible du seul service
    (TPM : PRÉVU avec les autres secrets du serveur, conception §3.4) ;
  - recherche paginée (500 par page), un seul attribut demandé (`sAMAccountName` ou `uid`) ;
    10 000 identifiants au plus ; délai de 30 s ;
  - **une liste vide est refusée** (filtre erroné : sinon tout le monde serait retiré).
- Évaluation de `ldap3` (20/11/2026) : version 0.12.1, `default-features = false`, fonctions
  `sync` + `tls-rustls-ring` → 95 crates, dont **4 nouvelles** dans `Cargo.lock` (`ldap3`, `lber`,
  `tokio-stream`, `utf_types`), toutes en Rust, aucune bibliothèque C (rustls + ring déjà
  utilisés ; ni OpenSSL, ni aws-lc). `cargo audit` : voir §9. Retenue.
- Import : les présents sont ajoutés ; les **absents sont retirés** : PIN effacé aussitôt,
  sessions fermées, compte inutilisable ; un retour dans l'annuaire réactive l'identifiant sans
  PIN (réinitialisation nécessaire).

## 3. Cycle de vie du PIN (mode Authentification)

```
 import annuaire ──▶ identifiant actif, SANS PIN (refusé en authentification)
        │  administrateur : « Réinitialiser le PIN »
        ▼
 PIN initial de 8 chiffres tiré par le serveur, AFFICHÉ UNE SEULE FOIS, remis à l'utilisateur
        │  borne : identifiant + PIN initial → « pin_a_changer » (aucune session)
        ▼
 borne : POST /utilisateurs/pin (ancien + nouveau, 6 à 12 chiffres, ni suite ni répétition)
        ▼
 PIN choisi par l'utilisateur (l'administrateur ne le connaît plus) ── vérifications
        │  5 échecs consécutifs                      │ retrait de l'annuaire
        ▼                                            ▼
 VERROUILLÉ (bon PIN refusé) ── déverrouillage   PIN effacé ; correspondance gardée 1 an
 ou réinitialisation par un administrateur        puis purgée
```

- Stockage : **Argon2id, 64 Mio, 3 passes, 1 voie** (RFC 9106), sel aléatoire, **poivre** de
  32 octets (`utilisateurs/poivre-pin`, 0600, secret Argon2) : un vol de la base seule ne permet
  pas d'attaque hors ligne des PIN. Le PIN n'est jamais écrit : ni dans la base, ni dans le
  journal d'audit, ni dans les journaux du service ; les messages qui le portent n'ont pas de
  `Debug` en clair. Preuve : `pin_jamais_en_clair` (§8).
- Une seule dérivation Argon2 à la fois dans la passerelle (mémoire bornée à 64 Mio sous
  attaque) ; vérification et enregistrement de l'échec sous le même verrou (pas d'essais
  parallèles qui échapperaient au compteur).
- La borne **ne stocke aucun PIN** : il est envoyé une fois par la connexion mTLS (TLS 1.3,
  CA serveur épinglée), puis oublié.

## 4. Protocole (borne → serveur, écoute mTLS seulement)

Ajout **compatible** à la version 1 (comme `/maj/*`, `protocole-agent.md` §9) : routes et messages
nouveaux, aucun message existant modifié, **aucun nouveau code d'erreur**. Toutes passent d'abord
le contrôle applicatif du battement (borne connue, active, certificat courant) ; sur l'écoute
d'enrôlement : `404 introuvable`. Corps ≤ 1 Kio, réponses ≤ 15 Kio.

| Route | Corps | Réponse `200` |
|---|---|---|
| `POST /utilisateurs/politique` | `{"version":1}` | `PolitiqueSite` |
| `POST /utilisateurs/verification` | `{"version":1,"identifiant":"…"[,"pin":"…"]}` | `ReponseVerification` |
| `POST /utilisateurs/pin` | `{"version":1,"identifiant":"…","pin":"…","nouveau_pin":"…"}` | `ReponseVerification` |

`PolitiqueSite` : `site`, `mode` (`aucun`/`identification`/`authentification`),
`version_politique` (croissante : la borne refuse une politique plus ancienne que celle qu'elle
applique), `entree_non_enrolees` (`autorisee`/`interdite`), `cles` (au plus 100 :
`fabricant`, `serie`, `entree`, `sortie`), `heure_serveur`.

`ReponseVerification` — **minimale** :

| `decision` | Champs | Sens pour la borne |
|---|---|---|
| `acceptee` | `session` (128 bits hex), `duree_session_s` (1800) | utilisateur reconnu ; la session sera jointe aux rapports (étape 3) |
| `refusee` | `attente_s` **seulement** si la borne est bloquée | identifiant inconnu, PIN faux, compte verrouillé, mode incompatible : indistinguables |
| `pin_a_changer` | aucun | PIN initial correct : demander un nouveau PIN puis `/utilisateurs/pin` |

Exemple de refus (octets exacts) : `{"version":1,"decision":"refusee","heure_serveur":1795000000}`.

### Comportement attendu de la borne (à implémenter côté `borne/`)

1. Au démarrage puis à chaque battement (60 s) : `POST /utilisateurs/politique` ; conserver la
   dernière politique valide (`version_politique` non décroissante) ; serveur injoignable : mode
   dégradé déjà prévu (blocage après le délai de grâce).
2. Mode `aucun` : aucun écran d'identification ; ne jamais appeler `/verification`.
3. Mode `identification` : clavier virtuel, `normaliser_identifiant`, `/verification` sans PIN.
4. Mode `authentification` : identifiant + PIN masqué ; contrôle local `pin_valide` ; PIN effacé
   de la mémoire après l'envoi ; `pin_a_changer` → saisie double du nouveau PIN contrôlé par
   `pin_acceptable` ; message unique « Identifiant ou PIN refusé » ; `attente_s` → « Borne
   bloquée, réessayez dans N min ».
5. Clés USB : `PolitiqueSite::autorise(fabricant, serie, Sens)` (même code que le serveur) avant
   l'analyse (entrée) et avant toute écriture (sortie, blanchiment) ; refus affiché et journalisé.

## 5. Anti force brute

| Compteur | Seuil | Effet | Remise à zéro |
|---|---|---|---|
| par **identifiant** | 5 échecs consécutifs (toutes bornes) | compte **verrouillé** : bon PIN refusé (réponse identique), alerte d'audit `utilisateur_verrouille` | déverrouillage ou réinitialisation par un administrateur ; succès avant le seuil |
| par **borne** | 5 refus en 1 h (identifiants inconnus compris) | toutes les vérifications de la borne refusées **15 min, doublées** à chaque blocage dans les 24 h (16 h au plus), alerte `borne_bloquee`, `attente_s` | le temps seulement (un succès ne remet PAS à zéro : un compte valide de l'attaquant ne relance pas ses essais) |

- Un attaquant à la borne a donc au plus 5 essais par identifiant au total, et 5 par heure et par
  borne (puis 15 min, 30 min…) pour répartir ses essais entre identifiants.
- Le verrouillage d'un compte par un tiers (déni de service) exige un accès physique à une
  borne, est limité par le compteur de borne et laisse une alerte ; le déverrouillage est
  immédiat depuis l'interface web.
- Temps constant : une dérivation Argon2 est faite même pour un identifiant inconnu, sans PIN ou
  verrouillé.

## 6. Pseudonymisation, rôles, conservation

- **Pseudonyme** `u-<16 hex>` = HMAC-SHA256(`utilisateurs/cle-pseudonyme`, identifiant), tronqué
  à 64 bits. Le journal d'audit ne contient **que** des pseudonymes (ou `inconnu`), jamais
  d'identifiant en clair ni de PIN. La correspondance n'existe que dans la base.
- Interface web :
  - **auditeur** (lecture seule) : liste des utilisateurs **en clair** avec pseudonymes, et
    résolution d'un pseudonyme vu dans le journal d'audit (consultation auditée) ;
  - **administrateur** : compteurs et pseudonymes seulement ; l'identifiant n'apparaît que pour
    le compte qu'il **saisit** (réinitialisation, déverrouillage), recherche auditée.
- Conservation : PIN dérivé effacé dès le retrait de l'annuaire ; correspondance
  identifiant ↔ pseudonyme conservée **1 an** après le retrait (durée des journaux, conception
  §1) puis **purgée automatiquement** (à chaque transaction, purge auditée). Après purge, les
  pseudonymes des journaux de plus d'un an ne sont plus attribuables. Sessions : 30 min.
  Sauvegardes : la base (`<registre>/utilisateurs/`) est dans le dossier d'état sauvegardé ; la
  rotation des sauvegardes (`serveur-iso.md`, 14 par défaut) borne la durée de vie d'un
  enregistrement purgé.
- Le mode « Aucun » ne crée aucune donnée personnelle : rien n'est écrit dans la base, et
  l'audit ne porte que la borne (preuve `mode_aucun_aucune_donnee_personnelle`).

## 7. Clés USB : enrôlement et politique par site

- Enrôlement par un administrateur : **fabricant** (VID, 4 hexadécimaux) + **numéro de série**
  (ASCII graphique, 1 à 64, normalisé en majuscules), libellé, site (ou tous les sites), usages
  `entrée` et/ou `sortie`. Doublon refusé ; 100 clés au plus par site. Identifiant interne
  `usb-<8 hex>`.
- Politique par site : **entrée** des clés non enrôlées `autorisée` (défaut, comportement v1) ou
  `interdite` ; **sortie seulement vers une clé enrôlée** avec l'usage `sortie` (toujours).
  Une clé enrôlée sans l'usage `entrée` est refusée comme source (clé réservée à la sortie).
- **Les identifiants USB ne prouvent rien** (conception §2, principe 4 : falsifiables) : la
  politique sert à la gestion et à la traçabilité ; l'analyse ClamAV + YARA reste toujours
  obligatoire, quelle que soit la clé.
- Chaque changement (mode, entrée, enrôlement, retrait) incrémente `version_politique` et est
  audité ; la politique servie à une borne est auditée quand sa version change (pas à chaque
  battement).

## 8. Configuration

Interface web : clé facultative `annuaire = /etc/barbacane/annuaire.conf` (fichier `cle = valeur`) :

```
url = ldaps://dc1.exemple.fr:636
ca = /etc/barbacane/annuaire-ca.pem
compte = CN=svc-barbacane,OU=Services,DC=exemple,DC=fr
mot_de_passe_fichier = /etc/barbacane/annuaire.mdp
base = OU=Agents,DC=exemple,DC=fr
filtre = (&(objectClass=user)(memberOf=CN=Barbacane,OU=Groupes,DC=exemple,DC=fr))
attribut = sAMAccountName
```

Base : `<registre>/utilisateurs/` (0700) : `base.json` + `base.verrou` (même approche que le
registre : verrou exclusif, écriture atomique, aucune dépendance ; pas de SQLite, cf.
`protocole-agent.md` §6), `cle-pseudonyme` et `poivre-pin` (32 octets, 0600, créés au premier
démarrage, refusés s'ils sont lisibles par d'autres comptes). Ces deux secrets sont à sauvegarder
avec la base : sans le poivre, aucun PIN ne se vérifie plus (réinitialisation de tous).

## 9. Preuves

| Exigence | Test |
|---|---|
| PIN faux × 5 → verrouillé, bon PIN refusé ensuite | `verrouillage_apres_cinq_echecs` (unitaire), `pin_faux_cinq_fois_verrouille` (mTLS) |
| Borne bloquée, délai croissant | `borne_bloquee_apres_cinq_echecs` |
| PIN jamais en clair (fichiers, audit, sortie du service) | `pin_jamais_en_clair` |
| Mode Aucun → aucune donnée personnelle | `mode_aucun_aucune_donnee_personnelle` |
| Clé non enrôlée refusée selon la politique ; sortie vers clé enrôlée seulement | `decision_des_cles`, `politique_des_cles_par_site`, `politique_telechargee_par_la_borne` |
| Poivre exigé, paramètres Argon2id | `poivre_exige` |
| Import, retrait, purge à 1 an ; liste vide refusée | `import_retrait_et_purge` |
| Routes absentes de l'écoute d'enrôlement | `politique_telechargee_par_la_borne` |
| LDAPS : CA épinglée, mauvaise CA refusée, import paginé | `annuaire_ldaps_de_test` (faux annuaire local en TLS) |
| Auditeur ne peut rien modifier ; CSRF ; échappement | `utilisateurs_auditeur_lecture_seule`, `utilisateurs_csrf_et_echappement` |
| PIN affiché une seule fois | `reinitialisation_pin_affiche_une_fois` |

## 10. État

| Élément | État |
|---|---|
| Modes par site, politique téléchargée par la borne, vérification identifiant / PIN, changement de PIN, sessions | FAIT (serveur) |
| PIN Argon2id poivré, anti force brute par identifiant et par borne, alertes d'audit | FAIT |
| Pseudonymisation dans l'audit, rôles (auditeur en clair), purge à 1 an | FAIT |
| Synchronisation LDAPS (ldap3, CA épinglée, compte de service, lecture seule) | FAIT, prouvée contre un faux annuaire local ; **jamais contre un vrai AD** (aucun au lab) |
| Pages web : utilisateurs, sites et modes, clés USB | FAIT |
| Côté borne : écrans d'identifiant et de PIN, application de la politique USB | FAIT (branche `borne-utilisateurs`, `docs/suite/borne-en-ligne.md` « Utilisateurs et clés USB ») ; QEMU en ligne et captures : PRÉVU |
| Rattachement des rapports à la session utilisateur | PRÉVU (étape 3, rapports) |
| Synchronisation périodique (minuteur systemd) | PRÉVU (ISO serveur) |
| Poivre, clé de pseudonymisation et mot de passe du compte de service dans le TPM | PRÉVU (conception §3.4) |
| Mode par borne ; rôles administrateur de site et opérateur | PRÉVU |
| Badges CCID/PC-SC | HORS PROJET de cette étape (conception §8, étape 7) |
| Quarantaine (le refus du mode Aucun est en place) | HORS PROJET de cette étape (étape 6) |

Choix à signaler : les nouveaux événements d'audit gardent `VERSION_SCHEMA = 1` (aucun serveur
installé, aucun journal existant) ; profil de compilation `dev` : `argon2` et `blake2`
optimisés (`Cargo.toml`) pour que les tests Argon2id à 64 Mio restent rapides.
