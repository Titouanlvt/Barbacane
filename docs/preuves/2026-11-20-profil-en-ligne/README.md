# Profil en ligne : agent, ISO en ligne, ISO hors ligne inchangée (20/11/2026)

Branche `borne-en-ligne`, construite et testée sur bu (Debian 13). PKI de TEST
(`serveur/pki/racine-test.sh`, jamais dans le dépôt). Doc : `docs/suite/borne-en-ligne.md`.

## 1. ISO hors ligne (sans option) identique à la v1.0.0

Construite depuis la branche (`construction.txt`, même `maj.pub`, netinst 13.7.0 vérifiée),
comparée à `barbacane-1.0.0.iso` (`/travail/v100`, même sha256 `5e0c3fba…3fc7` que
`/nvme/contenu/iso-v100/` sur l'hôte) : `comparaison.txt`.

| | v1.0.0 | branche | |
|---|---|---|---|
| sha256 de l'ISO | `5e0c3fba…3fc7` | `a2ea6778…24ae` | diffère (paquets recompilés) |
| Fichiers de l'ISO (1782) | `v100-fichiers.txt` | `branche-fichiers.txt` | **identiques** |
| Paquets `/barbacane/debs` (272) | `v100-debs.txt` | `branche-debs.txt` | **identiques** |
| Empreinte des paquets | `v100-sha.txt` | `branche-sha.txt` | 269 **identiques** ; `barbacane`, `usbsas-server`, `usbsas-hid` recompilés |
| Fichiers des paquets barbacane / usbsas | `*-fic-barbacane.txt`, `*-fic-usbsas.txt` | | **identiques** (noms et droits) |
| Scripts d'installation, preseed (hors hachage root aléatoire), `maj.pub` | `*-scripts.txt` | | **identiques** (sha256) |
| Données initiales (`donnees.tar`) | `*-donnees.txt` | | **identiques** (liste) |
| `tests/iso/hors-ligne.sh` (inchangé) | | | **OK** |

## 2. ISO en ligne (`--profil en-ligne`)

`build-iso.sh --profil en-ligne --ca-serveur pki/ca-serveur/cert.pem --serveur 10.0.2.2
--port-enrolement 43118 --port-service 43117` (DHCP) : `construction.txt`, `iso-en-ligne.txt`.

- 273 paquets = les 272 de la v1 + **`barbacane-agent` seul** (réseau : `systemd-networkd` du
  paquet `systemd`, déjà présent).
- `tests/iso/en-ligne.sh` : **OK** (agent et service durci, aucun autre paquet réseau, entrée
  fermée, sortie vers 10.0.2.2:{43118,43117} pour le seul compte de l'agent, empreinte de la CA).
- Contre-épreuves : `tests/iso/hors-ligne.sh` sur l'ISO en ligne → **ÉCHEC** attendu
  (« paquet réseau interdit : barbacane-agent ») ; `tests/iso/en-ligne.sh` sur l'ISO hors ligne
  ou avec une autre adresse de serveur → **ÉCHEC** attendu.

## 3. Borne en ligne installée dans QEMU face à une passerelle de test (`qemu-en-ligne.txt`)

`tests/iso/qemu-en-ligne.sh` : installation **sans carte réseau**, jeton déposé sur le disque,
démarrage en DHCP (QEMU user, serveur = 10.0.2.2) :

- l'agent dépose sa demande (empreinte `e0e5 6838 …`), validée par `barbacane-registre`, installe
  le certificat ; battement visible dans la supervision (`écart=-1s`), `etat.json` : `connectee` ;
- pare-feu chargé (`nft list ruleset`), service `IPAddressAllow=10.0.2.2/32`, `CapabilityBoundingSet=` vide,
  clé `cle.pem` 0600 ;
- **root lui-même ne sort pas** : 10.0.2.2:22, 10.0.2.2:43117 (port du serveur, mais pas le
  compte de l'agent) et 10.0.2.3:53 (DNS) bloqués ;
- interface v1 inchangée (`ecran-borne-en-ligne.png`), démarrée une fois.

## 4. Agent bout en bout sans VM (`agent-bout-en-bout.txt`)

`tests/suite/agent-bout-en-bout.sh` (vrais binaires, boucle locale) : jeton → empreinte publiée
= empreinte du registre → validation → battement supervisé → passerelle arrêtée : mode
`degradee`, agent vivant → relancée : `connectee` → révocation : alerte TLS `CertificateRevoked`,
mode `refusee`, plus aucune connexion. `cargo test -p barbacane-agent` : 7 unitaires + 5
d'intégration (dont renouvellement à mi-vie et CA non épinglée), OK.
