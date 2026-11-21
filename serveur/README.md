# Serveur Barbacane (suite, v2.0.0)

Serveur de gestion des bornes en ligne. Vue d'ensemble FAIT/PRÉVU : `docs/suite/README.md` ;
conception : `docs/conception-barbacane-suite.md` ; décisions : `docs/suite/decisions.md`.

**Rien ici n'entre dans la borne hors ligne** : `systeme/iso/build-iso.sh` (profil hors-ligne, le
défaut) n'utilise pas ce dossier, et `tests/iso/hors-ligne.sh` le vérifie sur l'ISO produite.

| Dossier | Rôle | Doc | Tests |
|---|---|---|---|
| `pki/racine-test.sh DOSSIER` | PKI de **TEST** seulement (racine, CA bornes/serveur/administrateurs, CRL) ; jamais dans le dépôt | `docs/suite/politique-certification.md` | utilisé par les tests ci-dessous |
| `protocole/` | messages borne ↔ serveur, partagés avec `borne/agent` | `docs/suite/protocole-agent.md` | `cargo test -p barbacane-protocole` |
| `passerelle/` | passerelle mTLS (service et enrôlement), registre, utilisateurs, rapports, quarantaine ; commande `barbacane-registre` | `docs/suite/serveur-socle.md`, `serveur-utilisateurs.md`, `quarantaine.md` | `cargo test -p barbacane-passerelle` (openssl requis) |
| `audit/` | journal d'audit chaîné SHA-384, points de contrôle P-384 | `docs/suite/serveur-maj-audit.md` | `cargo test -p barbacane-audit` |
| `maj/barbacane-plancher-prepare` | plancher de version signé des mises à jour | `docs/suite/serveur-maj-audit.md` | — |
| `web/` | interface web d'administration (mTLS, charte v2, sans JavaScript) | `docs/suite/serveur-web.md` | `cargo test -p barbacane-web` |
| `iso/build-iso-serveur.sh` | ISO du serveur (LUKS2 scellé TPM, nftables, Podman sans root) ; `--help` | `docs/suite/serveur-iso.md` | `tests/serveur/qemu-serveur.sh`, `tests/iso/serveur-config.sh` |
| `iso-bornes/barbacane-iso-borne` | personnalisation des ISO de bornes embarquées (enrôlement sans saisie) | `docs/suite/serveur-iso-bornes.md` | `tests/iso-bornes/` |
| `sauvegarde/barbacane-sauvegarde` | sauvegarde chiffrée et signée, restauration | `docs/suite/serveur-iso.md` | `tests/serveur/sauvegarde.sh` |
