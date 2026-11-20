# Serveur — interface web d'administration (20/11/2026)

Suite du socle (`serveur-socle.md`), du protocole (`protocole-agent.md`) et du journal d'audit
(`serveur-maj-audit.md`). Conception : §3.4 (deux interfaces réseau), §3.9 (audit), §3.10
(administration), maquette « Rendu attendu de l'interface web ». Décisions appliquées : D1 (SI DR),
D2 (aucun nom de fichier), D6 (cryptographie), D10 (pages sans JavaScript, charte v2).

Crate `serveur/web` (`barbacane-web`) : un binaire qui sert l'interface sur une **écoute
d'administration distincte** de la passerelle, et qui réutilise les bibliothèques de la passerelle
(`registre`, `admin`, `maj`, CA bornes) et du journal d'audit. Aucun code d'enrôlement, de
révocation ou de mise à jour n'est dupliqué : la page appelle les mêmes fonctions que
`barbacane-registre`, avec l'acteur audité `web:<compte>`.

## 1. Pages

| Page | Route | Rôles | Contenu |
|---|---|---|---|
| Connexion | `GET/POST /connexion` | tous | identifiant + mot de passe (le certificat est déjà présenté) |
| Tableau de bord | `GET /tableau` | tous | tuiles (bornes actives, en service, injoignables, horloge, demandes) ; « À traiter » ; tableau des bornes : état, site, version, dernière vue, écart d'horloge, échéance du certificat, alertes |
| Enrôlement | `GET /enrolement` | tous (actions : administrateur) | création d'un jeton (affiché **une seule fois**), demandes en attente |
| Validation d'une demande | `GET /enrolement/demande?id=…`, `POST /enrolement/valider`, `POST /enrolement/refuser` | administrateur | l'empreinte **n'est pas affichée** : l'administrateur **retape** celle qu'affiche la borne ; le serveur compare (`Registre::valider`) et émet le certificat de 90 jours |
| Révocation | `GET /bornes/revoquer?uuid=…`, `POST /bornes/revoquer` | administrateur | page de confirmation qui reprend la borne par son nom, motif obligatoire, nom de la borne à retaper ; CRL republiée dans la même transaction |
| Mises à jour | `GET /maj`, `POST /maj/plancher`, `POST /maj/depot`, `POST /maj/diffuser` | tous (actions : administrateur) | plancher signé, paquets déposés, paquet diffusé, état par borne ; dépôt d'un plancher ou d'un `.bcu` avec leur `.minisig` (vérification complète par `DepotMaj`) |
| Journal d'audit | `GET /audit`, `GET /audit/verification` | tous | derniers enregistrements (pagination) ; vérification de toute la chaîne (forme, numéros, chaînage, points de contrôle signés) avec la clé publique d'audit |
| Déconnexion | `POST /deconnexion` | tous | session détruite |
| Ressources | `GET /statique/…` | tous (session non exigée, certificat exigé) | feuille de style de la charte v2 et polices TTF de `docs/charte/fonts`, embarquées dans le binaire |

## 2. Rôles

| Rôle | Droits |
|---|---|
| `administrateur` | tout : jetons, validation et refus d'enrôlement, révocation, plancher, dépôt, diffusion, consultation |
| `auditeur` | **lecture seule** : tableau de bord, demandes, mises à jour, journal et sa vérification. Tout `POST` autre que la déconnexion → 403, **avant** lecture du corps |

La double validation (§3.10 : révocation massive, baisse de politique, quarantaine) ne concerne
aucune action de cette version (révocation d'une seule borne) : PRÉVU avec ces fonctions.

## 3. Authentification (deux facteurs)

1. **Certificat client d'administrateur** (possession) : TLS 1.3 exige un certificat émis par la
   CA « administrateurs » (seule ancre de l'écoute ; distincte de la CA bornes), EKU `clientAuth`,
   **CRL relue à chaque connexion**, refus si absente ou expirée (fail-closed, comme D8). Sans
   certificat : la poignée de main échoue, aucune page n'est servie.
2. **Mot de passe** (connaissance) : haché **Argon2id** (paramètres par défaut de la crate
   `argon2` : 19 Mio, 2 passes ; même choix que le PIN de la borne), 12 caractères au moins.
3. **Liaison** : chaque compte est lié à l'empreinte SHA-256 de **son** certificat. Le bon mot de
   passe avec le certificat d'un autre compte est refusé ; la session est liée au certificat (un
   cookie volé ne sert à rien sans le certificat et sa clé).

Fichier des comptes (`comptes`, une ligne par compte, refusé s'il est lisible par d'autres
comptes que le service) : `identifiant rôle empreinte-certificat $argon2id$…`. Ligne produite par
`barbacane-web compte IDENTIFIANT RÔLE CERT.pem` (mot de passe lu sur l'entrée standard). Le
fichier est relu à chaque requête : retirer un compte ferme ses sessions aussitôt.

Anti force brute : 5 échecs pour un compte (ou un certificat) → verrouillage 15 min, doublé à
chaque nouvel échec ; message identique quel que soit le motif (compte inconnu, certificat d'un
autre compte, mot de passe faux) ; vérification Argon2 faite même pour un compte inconnu (temps
constant) ; une seule vérification à la fois (mémoire bornée). Chaque connexion, échec et
déconnexion est audité.

La conception (§3.10) vise une clé FIDO2 ou une carte à puce : le certificat client peut résider
sur une carte à puce (PKCS#11 du navigateur) sans changement côté serveur. WebAuthn exigerait du
JavaScript (D10) : écarté.

## 4. Sessions

- Identifiant de 256 bits aléatoires, cookie `__Host-barbacane` : `Secure; HttpOnly;
  SameSite=Strict; Path=/`, sans date (cookie de session).
- Expiration après **15 min d'inactivité** et **8 h** au plus ; nouvel identifiant à la connexion
  (pas de fixation) ; une session par compte (une nouvelle connexion ferme l'ancienne) ; 64
  sessions au plus en mémoire (redémarrage du service = déconnexion de tous).
- Jeton anti-CSRF de 256 bits par session, exigé (comparaison à temps constant) dans **tout**
  `POST`, y compris la connexion (pré-session). `Sec-Fetch-Site` présent et différent de
  `same-origin`/`none` → refus.

## 5. Menaces web traitées

| Menace | Parade | Preuve (`serveur/web/tests/web.rs`) |
|---|---|---|
| Accès sans certificat d'administrateur | mTLS obligatoire, seule ancre = CA administrateurs | `sans_certificat_refus_tls` |
| Certificat volé sans mot de passe | mot de passe Argon2id exigé avant toute session | `certificat_sans_mot_de_passe_pas_de_session` |
| Mot de passe volé avec un autre certificat | compte lié à l'empreinte du certificat | `certificat_sans_mot_de_passe_pas_de_session` |
| Administrateur révoqué | CRL relue à chaque connexion ; pas de reprise de session TLS | `certificat_revoque_refus_tls` |
| Élévation de privilège de l'auditeur | rôle vérifié avant lecture du corps | `auditeur_ne_peut_pas_poster` |
| CSRF | jeton par session + `SameSite=Strict` + `Sec-Fetch-Site` | `post_sans_jeton_csrf_refuse` |
| Injection HTML / XSS | construction des pages par un tampon qui **échappe tout texte** (le texte brut n'accepte que des littéraux `&'static str`) ; CSP sans script ; aucun JavaScript | `nom_de_borne_malveillant_echappe`, tests unitaires d'échappement |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `entetes_de_securite_presents` |
| Fuite par cache ou référent | `Cache-Control: no-store` (pages), `Referrer-Policy: no-referrer` | `entetes_de_securite_presents` |
| Requêtes énormes, client lent | en-têtes ≤ 8 Kio, formulaire ≤ 16 Kio, dépôt ≤ taille d'un `.bcu` ; 32 connexions ; durée totale 30 s par connexion (dépôt : + 1 s par 512 Kio annoncés) ; une requête par connexion | `requete_trop_grosse_refusee` |
| Validation d'enrôlement « à l'aveugle » | empreinte non affichée, à retaper depuis la borne | `validation_d_enrolement_de_bout_en_bout` |
| Paquet piégé déposé | vérification minisign complète par `DepotMaj` (signature, plancher, anti-retour), refus audité ; le serveur ne décompresse rien | tests de la passerelle (`maj.rs`) ; dépôt par la page dans `depot_bcu_par_la_page` |
| Action sans trace | chaque action passe par `Admin` (audit dans la transaction), connexions et consultations auditées | `validation_d_enrolement_de_bout_en_bout` (journal vérifié) |

Ressources : tout est servi par le binaire (CSS, polices). Aucune ressource externe, aucun CDN.

## 6. Configuration et exploitation

Fichier `cle = valeur` : `adresse`, `port` (écoute d'administration, différente des ports de la
passerelle), `chaine_serveur`, `cle_serveur` (certificat TLS de l'interface), `ca_administrateurs`,
`crl_administrateurs`, `comptes`, `passerelle` (configuration de la passerelle : registre, CA
bornes, CRL bornes), `cle_audit_publique` (vérification de la chaîne).

`barbacane-web CONFIG` sert l'interface ; `barbacane-web compte …` produit une ligne de compte.

## 7. Charte v2 (adaptation simple)

Feuille servie `/statique/barbacane.css` = `docs/charte/web/jetons.css` **inclus tel quel à la
compilation** (chemins des polices réécrits vers `/statique/polices/`) + `serveur/web/statique/composants.css` : composants web de `components/bundle.css` (navigation, tuiles, tableau,
formulaire, avis, états, boutons) **sans** transition ni animation ; thème Jour/Nuit par
`prefers-color-scheme` ; polices de `docs/charte/fonts` (OFL). Pas d'attribut `style` (interdit
par la CSP) : les couleurs d'état passent par des classes.

Captures : §9.

## 8. État

| Élément | État |
|---|---|
| Écoute d'administration TLS 1.3 mTLS + CRL, comptes Argon2id liés au certificat, rôles, sessions, CSRF, en-têtes | FAIT |
| Tableau de bord, enrôlement (jeton, validation par empreinte retapée, refus), révocation, mises à jour (plancher, dépôt, diffusion, état), journal d'audit (consultation, vérification) | FAIT |
| CA « administrateurs » dans `serveur/pki/racine-test.sh` et la cérémonie | PRÉVU (générée par les tests en attendant) |
| Clé de l'interface et de la CA administrateurs dans le TPM, service systemd durci, pare-feu de l'interface d'administration | PRÉVU (ISO serveur) |
| Double validation (§3.10), utilisateurs et PIN (étape 4), clés USB, rapports, politique | PRÉVU |
| Comparaison aux exports d'empreintes d'audit depuis la page | PRÉVU (`barbacane-audit verifier` en ligne de commande) |

## 9. Dépendances

Nouvelles pour la crate, **toutes déjà présentes dans `Cargo.lock`** : `argon2` 0.6 (déjà utilisée
par `borne/admind`), `httparse` (analyse des en-têtes HTTP, déjà tirée par `ureq`),
`form_urlencoded` (décodage des formulaires, déjà tirée par `url`), `tempfile` (dossier de dépôt,
déjà utilisée par `borne/admind`). Les autres viennent de la passerelle (`rustls`, `ring`,
`x509-parser`, `serde_json`, `hex`, `anyhow`). Pas de cadriciel web ni de moteur de gabarits :
un fil par connexion suffit à quelques administrateurs et limite la surface.
