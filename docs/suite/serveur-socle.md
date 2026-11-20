# Socle serveur — jalon 1 : PKI de test et passerelle mTLS (étape 5, 20/11/2026)

Premier jalon du serveur de gestion (`docs/conception-barbacane-suite.md`). Décisions appliquées :
D4 (port tiré à l'installation), D6 (cryptographie), D7 (racine hors ligne), D8 (CRL 7 jours,
fail-closed). Profils : `politique-certification.md`.

## 1. Composants

| Composant | Rôle | État |
|---|---|---|
| `serveur/pki/racine-test.sh` | PKI de **TEST** : racine P-384 (10 ans) → CA « bornes » et CA « serveur » P-384 (3 ans, `pathlen:0`, `nameConstraints`) → serveur P-256 (1 an, `serverAuth`) et borne P-256 (90 jours, `clientAuth`, SAN `URI:urn:barbacane:borne:<site>:<uuid>` + `DNS:<uuid>.bornes.barbacane.invalid`) ; CRL de chaque CA intermédiaire (7 jours). `O=Barbacane TEST — NE PAS UTILISER EN PRODUCTION`, « TEST » dans le CN des CA. Refuse une sortie dans un dépôt git ou non vide. `--cas-de-test` : borne révoquée + CRL expirée. | FAIT |
| `serveur/passerelle` (`barbacane-passerelle`) | Serveur HTTPS : TLS 1.3 seul (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256` ; `secp384r1`, `secp256r1`), certificat client **obligatoire** (`WebPkiClientVerifier`, seule ancre : la CA bornes), CRL relue à chaque connexion, route `GET /sante` → `{"etat":"ok","borne":"<CN>"}`. `#![forbid(unsafe_code)]`. | FAIT |
| Tests `serveur/passerelle/tests/mtls.rs` | Génèrent la PKI par le script, prouvent : borne valide acceptée et identifiée ; sans certificat, révoquée, CRL expirée, TLS 1.2 → refus. | FAIT |

Toutes les CA signent en ECDSA-SHA384 (clé P-384 du signataire) ; les clés feuilles sont P-256.

## 2. Flux

```
borne (agent, clé TPM)            passerelle (port D4)
  ClientHello TLS 1.3  ───────────▶  relit ca-bornes/cert.pem + crl.pem
                                     CRL absente / illisible / expirée → connexion coupée
  certificat borne    ───────────▶  chaîne → CA bornes, EKU clientAuth, nameConstraints,
                                     non révoqué (webpki, statut inconnu = refus)
  GET /sante          ───────────▶  200 {"etat":"ok","borne":"borne borne-01"}
```

Configuration : fichier `cle = valeur` passé en argument (`adresse`, `port`, `chaine_serveur`,
`cle_serveur`, `ca_bornes`, `crl_bornes`). Pas de port par défaut ; port 0 refusé. Au démarrage,
la configuration TLS complète est construite une fois : si la CRL est expirée, le service ne
démarre pas.

## 3. Menaces couvertes par ce jalon

| Menace | Parade | Preuve |
|---|---|---|
| Client non enrôlé | certificat client obligatoire | `sans_certificat_refuse` |
| Borne volée / réformée | CRL relue à chaque poignée de main | `borne_revoquee_refusee` |
| Révocation masquée (CRL non republiée, rejouée) | refus si `nextUpdate` dépassé (contrôle explicite + `enforce_revocation_expiration`) | `crl_expiree_refus_fail_closed` |
| Rétrogradation de protocole | TLS 1.3 seul, suites et groupes restreints | `tls12_refuse` |
| Certificat émis par la CA serveur présenté comme borne | seule ancre = CA bornes, EKU `clientAuth` exigé | par construction |
| Épuisement | 256 connexions simultanées, délai 10 s, requête ≤ 8 Kio | non testé |
| Confusion test / production | mention TEST dans les noms ; sortie hors dépôt | revue |

## 4. Dépendances (aucune nouvelle crate dans `Cargo.lock`)

- `rustls` 0.23 (fournisseur `ring`) : déjà utilisé par `borne/analyzer` ; pas d'`aws-lc-rs`.
- `x509-parser` 0.18 : déjà tiré par `rcgen` ; sert à lire le CN et la date `nextUpdate` de la CRL.
- `anyhow` : déjà utilisé par `borne/admind`.
- Tests seulement : `tempfile` (déjà présent) ; `rustls` avec `tls12` pour **tenter** un client
  TLS 1.2 (la passerelle n'active jamais TLS 1.2). Pas de tokio ni de hyper : un fil par
  connexion suffit à 100 bornes et réduit la surface.

## 5. PRÉVU (jalons suivants)

- Clés serveur et CA dans le TPM (politique §6) ; ici fichiers PEM.
- Vérification de l'empreinte de la racine de production (refus des certificats TEST).
- CRL de la racine (révocation d'une CA intermédiaire) ; republication quotidienne automatique.
- Protocole agent ↔ serveur, enrôlement (jeton 1 h), renouvellement à mi-vie, journal d'audit
  chaîné, interface web, service systemd durci / conteneur Podman sans root, règles de pare-feu.
- Exécution du script sur une VM `barbacane-9xx` sans carte réseau pour la racine du lab (D7).
