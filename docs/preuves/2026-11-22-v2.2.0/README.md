# Preuves v2.2.0 — comptes administrateurs, double validation, D13 (22/11/2026)

Code prouvé : commit `5181187` (branche `v220`) ; les commits suivants ne touchent que la
documentation et les preuves. PKI de TEST de `serveur/pki/racine-test.sh`, TPM logiciel (swtpm).

| Preuve | Fichier | Résultat |
|---|---|---|
| CI locale `lab/ci-locale-bu.sh v220` (audit, fmt, clippy, 353 tests dont `serveur/web/tests/comptes.rs`, `tests/maj/maj.sh`, `tests/iso/serveur-config.sh`, shellcheck) | — | **FIN 0** (`5181187`) ; passe précédente avec `--iso` (ISO borne, `hors-ligne.sh`, `qemu.sh`) : FIN 0 |
| Banc QEMU serveur `tests/serveur/qemu-serveur.sh` (ISO installée, parcours étendu) | `qemu-serveur.txt` | **66 OK, 0 ÉCHEC** (53 en 2.1.0 + 13 nouveaux) |
| Mise à jour de la Console 2.1.0 → 2.2.0 (vrais binaires, mêmes fichiers) `tests/serveur/migration-comptes.sh` | `migration-comptes.txt` | **14 OK, 0 ÉCHEC** |
| Banc QEMU borne `tests/iso/qemu.sh` (ISO hors ligne 2.2.0 de la CI, sha256 `d096fad1…c038a`, `lab/qemu-v220-borne.sh`) | — | **3 passages sur 3, code 0** |
| Campagne 950 : mise à jour signée de TEST 2.1.0 → 2.2.0, non-régression + `grandes-iso` | `resultats.txt` | À COMPLÉTER |

## Nouveaux parcours du banc serveur (sur l'ISO installée, Console sur 10.0.3.15:443)

1. `admin-01` (compte de l'ISO, format v2.1.0) importé au premier démarrage (`migration-2.1.0`) ;
2. POST sans jeton anti-CSRF refusé (403) ;
3. `admin-02` créé par le seul administrateur (amorçage journalisé), `.p12` téléchargé **une
   fois** (2e essai : 404) et relu par `openssl pkcs12` ; connexion au mot de passe provisoire,
   changement imposé (redirection vers `/mot-de-passe`), nouveau mot de passe, tableau 200 ;
4. double validation : `admin-02` demande la création de `lect` (lecture seule), son
   auto-validation est refusée (400), `admin-01` valide ; `.p12` au validateur, mot de passe
   provisoire au demandeur (séparation des remises) ;
5. `lect` : comptes, Journal, réglage de site et jeton refusés (403) ;
6. D13 : site `labo` en mode Aucun → activation de la quarantaine refusée (message D13) ; en
   Identification → activation demandée par `admin-01`, validée par `admin-02` ; mode Aucun alors
   refusé ; désactivation par double validation.

Passe précédente du banc (même jour, commit `3cd4a9a`) : 65 OK, 1 ÉCHEC — le banc choisissait pour
`lect` un mot de passe contenant « lect » (« lecture seule »), refusé **à raison** par la politique ;
banc corrigé.
