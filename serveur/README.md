# Serveur Barbacane (suite, v2)

Serveur de gestion des bornes en ligne : passerelle mTLS, interface web, identité, PKI, conteneurs
Podman sans root, ISO du serveur (`serveur/iso/`). Conception : `docs/conception-barbacane-suite.md` ;
décisions : `docs/suite/decisions.md`.

**Rien ici n'entre dans la borne hors ligne v1** : `systeme/iso/build-iso.sh` (profil hors-ligne, le
défaut) n'utilise pas ce dossier, et `tests/iso/hors-ligne.sh` le vérifie sur l'ISO produite.
