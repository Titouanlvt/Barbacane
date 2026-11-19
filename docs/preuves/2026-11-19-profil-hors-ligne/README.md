# Profil hors ligne : ISO identique à la v1.0 (19/11/2026)

But (étape 3, conception suite §10) : après l'ajout de `build-iso.sh --profil` (hors-ligne par défaut)
et des dossiers `serveur/`, `borne/agent/`, l'ISO construite **sans option** doit rester la borne v1.

| | ISO v1.0 (18/11, 5c20866) | ISO de l'étape 3 (19/11, `integration` 9cd46d5) |
|---|---|---|
| sha256 | `4e2bd821…cbb2` | `96ca923b…8483` |
| Fichiers de l'ISO | `cmp-barbacane-fichiers.txt` | `cmp-etape3-fichiers.txt` — **identiques** (même liste) |
| Paquets installés (`/barbacane/debs`) | `cmp-barbacane-debs.txt` | `cmp-etape3-debs.txt` — **identiques** (272) |
| Empreinte de chaque paquet | `sha-barbacane.txt` | `sha-etape3.txt` — 269 paquets Debian **identiques** ; seuls `barbacane`, `usbsas-server`, `usbsas-hid` diffèrent (recompilés : construction non reproductible octet pour octet) |
| Fichiers du paquet `barbacane` | `fic-barbacane.txt` | `fic-etape3.txt` — **identiques** |
| Garde-fou `tests/iso/hors-ligne.sh` | OK | OK (aucun agent, aucun paquet réseau, sortie bloquée) |

Garde-fou vérifié aussi en négatif : une ISO v1.0 où `openssh-server` est ajouté à `/barbacane/debs`
est refusée (« paquet réseau interdit dans l'ISO hors ligne : openssh-server »).
`build-iso.sh --profil en-ligne` est refusé tant que l'agent n'existe pas.
