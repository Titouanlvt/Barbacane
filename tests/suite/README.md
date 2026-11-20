# Tests de la suite (serveur, agent, bout en bout)

Les tests de la v1 restent dans `tests/` et sont obligatoires avant toute fusion dans `main`.

- `agent-bout-en-bout.sh` : vrais binaires `barbacane-passerelle`, `barbacane-registre` et
  `barbacane-agent` sur la boucle locale, PKI de TEST : enrôlement validé, battement dans la
  supervision, mode dégradé puis reprise, révocation (sans VM).
- `cargo test -p barbacane-agent` : mêmes parcours en cours de processus, plus le renouvellement à
  mi-vie et la CA non épinglée.
