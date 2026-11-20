# Serveur Barbacane (suite, v2)

Serveur de gestion des bornes en ligne : passerelle mTLS, interface web, identité, PKI, conteneurs
Podman sans root, ISO du serveur (`serveur/iso/`). Conception : `docs/conception-barbacane-suite.md` ;
décisions : `docs/suite/decisions.md`.

**Rien ici n'entre dans la borne hors ligne v1** : `systeme/iso/build-iso.sh` (profil hors-ligne, le
défaut) n'utilise pas ce dossier, et `tests/iso/hors-ligne.sh` le vérifie sur l'ISO produite.

## Socle (étape 5)

- `pki/racine-test.sh DOSSIER` : PKI de **TEST** (jamais dans le dépôt).
- `protocole/` : messages borne ↔ serveur v1, partagés avec le futur agent (`docs/suite/protocole-agent.md`).
- `passerelle/` : passerelle (écoutes de service mTLS et d'enrôlement), registre des bornes et
  commande d'administration `barbacane-registre` (`cargo test -p barbacane-passerelle`, openssl requis).
- Conception du jalon : `docs/suite/serveur-socle.md`.
- `iso/build-iso-serveur.sh` : ISO du serveur (Debian 13 durcie, LUKS2 scellé au TPM, Podman sans
  root) ; banc : `tests/serveur/qemu-serveur.sh`. Conception : `docs/suite/serveur-iso.md`.
- `sauvegarde/barbacane-sauvegarde` : sauvegarde chiffrée et signée ; test : `tests/serveur/sauvegarde.sh`.
