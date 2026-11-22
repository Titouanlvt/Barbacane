# Comptes de la Console, double validation, D13 (v2.2.0, 22/11/2026)

Étude E1 (`etude-conformite-e1.md` §2.2, écarts bloquants n° 4) : comptes nominatifs gérés dans la
Console, séparation des rôles, double validation généralisée (conception §3.10). Code :
`serveur/web/src/{comptes,validations,admin_comptes,pages_comptes,pkcs12}.rs`,
`serveur/passerelle/src/{quarantaine,utilisateurs,admin,ca}.rs`. Preuves : §8.

## 1. Comptes

| Donnée | Contenu | Remarque |
|---|---|---|
| Identifiant | `[a-z0-9._-]`, 1 à 32 | nominatif, jamais partagé |
| Numéro | entier unique, jamais réutilisé | distingue un compte recréé sous le même identifiant |
| Rôle | §2 | |
| Actif | oui / non | désactivé : aucune connexion, sessions fermées |
| Certificat | SHA-256 du certificat client, numéro de série, échéance | un seul certificat par compte (mTLS obligatoire avant toute page) |
| Mot de passe | hachage **Argon2id** (19 Mio, 2 passes) | jamais conservé ni journalisé en clair |
| Changement imposé | oui après création ou réinitialisation | seule la page « Mot de passe » (et la déconnexion) est alors servie |
| Créé le, créé par, dernier accès, mot de passe changé le | dates et acteur | liste « dernier accès » de la Console |

Base : `<registre>/administrateurs/comptes.json` (0600, refusée si plus ouverte, verrou exclusif,
écriture atomique, contrôle de cohérence à chaque lecture : identifiants, numéros et certificats
uniques, hachages `$argon2id$`). Chaque requête relit la base : un compte désactivé, supprimé,
dont le rôle ou le certificat change perd sa session immédiatement.

**Politique de mot de passe** (ANSSI, authentification multifacteur et mots de passe) : 12 à 128
caractères ; trois types parmi minuscules, majuscules, chiffres et autres, **ou** une phrase de
passe d'au moins 20 caractères ; au moins 6 caractères distincts ; sans l'identifiant ; différent
de l'actuel. Mot de passe provisoire : 4 groupes de 5 caractères sans ambiguïté (≈ 113 bits),
affiché une fois. Anti force brute inchangé (5 échecs : 15 min, doublé, par compte et par
certificat), aussi sur la page de changement de mot de passe.

## 2. Rôles et matrice des droits

Contrôle par `droit_route` (méthode + chemin) **avant la lecture du corps** ; une route POST
inconnue exige le droit le plus fort (refus par défaut). Les liens de navigation interdits ne
sont pas affichés.

| Droit (routes) | Administrateur | Opérateur | Auditeur | Lecture seule |
|---|:-:|:-:|:-:|:-:|
| Consulter : Parc, Enrôlement, Mises à jour, Sites et modes, Clés Barbacane | ✔ | ✔ | ✔ | ✔ |
| Données personnelles : Utilisateurs, Passages | ✔ | ✔ | ✔ (identifiants en clair) | — |
| Journal d'audit et sa vérification | ✔ | — | ✔ | — |
| Comptes et demandes de double validation (lecture) | ✔ | — | ✔ | — |
| Exploiter : jetons, validation/refus d'enrôlement, révocation d'UNE borne (nom retapé), plancher, dépôt et diffusion des mises à jour, ISO des bornes, PIN, déverrouillage, annuaire, modes de site, clés USB | ✔ | ✔ | — | — |
| Administrer : comptes, double validation, Quarantaine, révocation de toutes les bornes d'un site | ✔ | — | — | — |
| Son propre mot de passe, déconnexion | ✔ | ✔ | ✔ | ✔ |

Comptes de la v2.1.0 : `administrateur` et `auditeur` gardent leurs droits (l'auditeur garde la
lecture du journal et des utilisateurs). Nouveaux rôles : `operateur`, `lecture`.

## 3. Actions sur les comptes

| Action | Qui | Double validation | Garde-fous |
|---|---|:-:|---|
| Créer un compte (tout rôle) | administrateur | **oui** — sauf le **second administrateur** quand un seul administrateur utilisable existe (amorçage, journalisé `creation-sans-double-validation`) | identifiant libre ; certificat émis et mot de passe provisoire remis au **validateur** |
| Supprimer | administrateur | **oui** | jamais le dernier administrateur utilisable ; certificat révoqué (CRL) |
| Passer administrateur (élévation) | administrateur | **oui** | |
| Réactiver | administrateur | **oui** | |
| Nouveau certificat (.p12) | administrateur | **oui** | ancien certificat révoqué (motif « remplacé ») |
| Révoquer le certificat | administrateur | **oui** | jamais celui du dernier administrateur ; compte délié |
| Désactiver | administrateur | non (sens sûr) | jamais le dernier administrateur, ni soi-même sans un second |
| Rétrograder (rôle autre qu'administrateur) | administrateur | non (sens sûr) | idem |
| Réinitialiser le mot de passe d'un autre | administrateur | non | provisoire affiché une fois, changement imposé ; pas sur son propre compte |
| Changer son mot de passe | tout compte | non | ancien mot de passe exigé, politique |

« Administrateur utilisable » : actif, rôle administrateur, certificat lié.

## 4. Certificats et `.p12`

- **CA « administrateurs » sur le serveur** (décision du 22/11, §9) : clé P-384 en fichier 0400
  (`/web/cle-ca-administrateurs.pem`, conteneur en lecture seule ; TPM prévu en 2.4, comme la CA
  bornes). Absente : la Console n'émet rien (création et nouveau certificat refusés avec un
  message), le reste fonctionne.
- Émission : clé **P-256 tirée par le serveur**, certificat 1 an (`clientAuth`, CN
  `administrateur <identifiant>`), puis `.p12` construit en mémoire : clé PKCS#8 chiffrée en
  **PBES2** (PBKDF2-HMAC-SHA256, 210 000 itérations, AES-256-CBC), certificats (compte + CA), MAC
  **HMAC-SHA256** (10 000 itérations). Mot de passe du `.p12` : 24 caractères tirés, **affiché une
  seule fois** ; `.p12` **téléchargeable une seule fois**, 10 min, par l'administrateur qui l'a
  obtenu ; jamais écrit sur disque ; la clé privée n'est conservée nulle part.
- **CRL des administrateurs publiée par la Console** (`<registre>/administrateurs/crl-administrateurs.pem`) :
  initialisée avec les révocations de la CRL de la cérémonie, republiée à chaque révocation et
  quand il lui reste moins de 4 jours (validité 7 jours, D8) : la Console ne s'arrête plus à
  l'échéance de la CRL de la cérémonie. Les CRL d'autres CA d'administrateurs restent lues du
  fichier configuré (fail-closed si expirées).
- Certificat antérieur à la v2.2.0 : numéro de série relevé à la première connexion ; s'il n'a
  jamais été vu, la révocation délie le compte (plus de session possible) sans entrée de CRL.

## 5. Double validation (conception §3.10)

Une action sensible est **demandée** par un administrateur, puis **validée** par un **second**
administrateur utilisable, distinct (identifiant **et** numéro de compte), dans l'**heure** :

- auto-validation refusée et journalisée (`validation-refusee:auto-validation:<id>`), la demande
  reste en attente ; validation par un non-administrateur refusée de même ;
- demande expirée, ou dont le demandeur n'est plus administrateur utilisable (désactivé,
  supprimé, rétrogradé, certificat révoqué) : retirée ;
- les garde-fous sont revérifiés **au moment de l'exécution** (dernier administrateur, compte
  recréé depuis la demande) ; une exécution refusée retire la demande ;
- demande identique déjà en attente : refusée ; 32 demandes au plus ; annulation par tout
  administrateur (journalisée) ;
- audit des deux temps : `demande:<action>:<cible>:<id>` (demandeur) puis
  `validation:<action>:<cible>:<id>` (validateur) et l'effet (`compte-cree`, `certificat-revoque`…).

**Actions couvertes**

| Action | File |
|---|---|
| Création, suppression, élévation au rôle administrateur, réactivation d'un compte | Comptes |
| Émission et révocation d'un certificat d'administrateur | Comptes |
| Révocation **massive** : toutes les bornes actives d'un site (nom du site retapé, une seule CRL) | Comptes |
| Activation de la quarantaine | Quarantaine |
| **Désactivation** de la quarantaine (v2.2.0 ; un seul administrateur auparavant) | Quarantaine |
| Export d'un élément de la quarantaine | Quarantaine |
| Changement de la durée de conservation (décision du 22/11) | **2.3.0**, même mécanisme |

Hors double validation (sens sûr ou réversible, toujours journalisé) : désactivation et
rétrogradation d'un compte, réinitialisation d'un mot de passe, révocation d'**une** borne (nom
retapé), modes de site, PIN, clés USB, mises à jour (les paquets restent signés hors ligne).

## 6. D13 — mode Aucun et quarantaine

`quarantaine_active()` lit désormais l'état réel (fail-closed : état illisible = active).

- Quarantaine active → passer un site en mode **Aucun** est refusé (« mode Aucun interdit : la
  quarantaine est activée (D13) ; désactivez-la d'abord (double validation) »). Le contrôle se fait
  sous le verrou de la quarantaine : une activation validée au même moment ne peut pas s'intercaler.
- Un site en mode Aucun → **demander et valider** l'activation est refusé (« D13 : la quarantaine
  ne peut pas être activée tant qu'un site est en mode Aucun… (sites en mode Aucun : …) »),
  journalisé `activation-refusee-d13`. Sites pris en compte : réglés, des bornes actives, des
  jetons valides, des demandes d'enrôlement en attente et des clés USB (un site jamais réglé est
  en mode Aucun).
- Quarantaine active → un **jeton d'enrôlement** pour un site encore en mode Aucun est refusé
  (une nouvelle borne y arriverait en mode Aucun).

## 7. Migration depuis la v2.1.0

Au premier démarrage de la 2.2.0, si `comptes.json` n'existe pas, le fichier texte de la v2.1.0
(clé `comptes` de `web.conf`, 0600 exigé) est importé **sans perte** : identifiant, rôle,
empreinte du certificat et hachage Argon2id repris tels quels (même mot de passe, pas de
changement imposé), créé par `migration-2.1.0`, journalisé `migration-comptes-2.1.0:<n>`. Le
fichier v2.1.0 n'est ni modifié ni relu ensuite (retour arrière en 2.1.0 possible : la 2.1.0 le
relit, mais ignore les comptes créés en 2.2.0). `--verifier-config` n'écrit rien (il contrôle le
fichier qui serait importé). `barbacane-web compte` produit toujours une ligne v2.1.0 : c'est ainsi
que l'ISO pose le premier compte.

Mise à jour d'un serveur 2.1.0 (pas encore de mise à jour signée du serveur, prévue en 2.7) :
nouvelle image `barbacane-web` 2.2.0, puis, pour l'émission dans la Console, déposer la clé de la
CA des administrateurs (`~barbacane-svc/web/cle-ca-administrateurs.pem`, 0400) et ajouter
`cle_ca_administrateurs = /web/cle-ca-administrateurs.pem` à `web.conf`.

## 8. Preuves

| Test / banc | Ce qui est prouvé |
|---|---|
| `comptes::tests::*` | migration sans perte, politique, matrice des droits, garde-fous (dernier administrateur), base refusée si altérée ou 0644, rien d'écrit sans audit |
| `validations::tests::auto_validation_expiration_et_non_administrateur` | auto-validation, non-administrateur, doublon, expiration à 1 h, exécution unique, demande d'un compte désactivé retirée |
| `pkcs12::tests::der_et_aes` | DER, AES-256-CBC (SP 800-38A F.2.5) |
| `serveur/web/tests/comptes.rs` | migration, CSRF, dernier administrateur, amorçage du 2e administrateur, `.p12` relu par `openssl pkcs12` (et mauvais mot de passe refusé), téléchargement unique, changement imposé, auto-validation refusée, rôles opérateur et lecture seule refusés, révocation d'un certificat (poignée de main refusée), révocation d'un site, suppression, journal sans secret, CRL de la cérémonie reprise, pas de réimportation |
| `serveur/web/tests/quarantaine.rs` | D13 dans les deux sens, jeton refusé, désactivation par double validation |
| `serveur/passerelle/tests/maj.rs` `quarantaine_refusee_par_la_passerelle_si_desactivee` | D13 sur l'état réel, `sites_en_mode_aucun`, jetons |
| `tests/serveur/migration-comptes.sh` | vrais binaires 2.1.0 puis 2.2.0 sur les mêmes fichiers : comptes conservés |
| `tests/serveur/qemu-serveur.sh` | ISO installée : 2e administrateur, `.p12`, double validation, D13, lecture seule refusée |

## 9. Limites

- Le validateur reçoit le certificat et le mot de passe provisoire du compte créé : il doit les
  remettre par deux canaux séparés ; le changement imposé du mot de passe et le journal rendent
  une usurpation visible. Facteur matériel (carte à puce, FIDO2) : P8 de l'étude E1.
- Clé de la CA des administrateurs en fichier (TPM : 2.4) ; elle est lisible par le service web.
- Avec un seul administrateur, aucune action sensible n'est possible (sauf créer le second).
