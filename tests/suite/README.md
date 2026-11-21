# Tests de la suite (serveur, agent, bout en bout)

Les tests de la borne hors ligne restent dans `tests/` ; tout passe par `tests/ci-locale.sh`
avant une fusion.

- `agent-bout-en-bout.sh` : vrais binaires `barbacane-passerelle`, `barbacane-registre` et
  `barbacane-agent` sur la boucle locale, PKI de TEST : enrôlement validé, battement dans la
  supervision, mode dégradé puis reprise, révocation (sans VM).
- `cargo test -p barbacane-agent` : mêmes parcours dans le processus de test, plus le
  renouvellement à mi-vie et la CA non épinglée.
- Ailleurs : `tests/serveur/` (ISO serveur sous QEMU + swtpm, sauvegarde, banc du lab),
  `tests/iso/en-ligne.sh`, `qemu-en-ligne.sh`, `serveur-config.sh`, `tests/iso-bornes/`, `tests/web/`.
