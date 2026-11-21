<div align="center">
  <img src="docs/charte/logos/barbacane-relief.svg" width="112" alt="">
  <h1>BARBACANE</h1>
  <p><strong>Borne de décontamination pour clés USB et disques optiques, hors ligne ou reliée à un serveur de gestion.</strong></p>
  <p>
    <a href="https://github.com/Titouanlvt/Barbacane/actions/workflows/ci.yml"><img src="https://github.com/Titouanlvt/Barbacane/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Titouanlvt/Barbacane/actions/workflows/iso.yml"><img src="https://github.com/Titouanlvt/Barbacane/actions/workflows/iso.yml/badge.svg" alt="ISO"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-GPLv3-1C1F22" alt="Licence GPLv3"></a>
    <img src="https://img.shields.io/badge/Debian-13-8A6420" alt="Debian 13">
  </p>
</div>

<p align="center">
  <img src="docs/captures/v1/jour/05-resultat.png" width="49%" alt="Résultat de l'analyse : menaces détectées et fichiers refusés">
  <img src="docs/preuves/2026-11-18-optique/lecteur/01-disque-detecte.png" width="49%" alt="Disque optique détecté : copier, graver ou blanchir">
</p>

## Ce que c'est

Deux produits, construits depuis ce dépôt :

- **La borne hors ligne** (v1) : un poste dédié sous Debian 13, **jamais connecté au réseau**.
  Elle lit une clé USB ou un disque inconnu **sans le monter** (pile USB en espace utilisateur issue
  d'usbsas, processus isolés par seccomp et Landlock), analyse chaque fichier, archives comprises
  (ClamAV, YARA, extraction dans bubblewrap), puis **copie** les fichiers sains vers une clé
  effacée, les **grave** sur un disque réinscriptible vérifié, ou **blanchit** le support. Rapport
  `.txt`/`.html` à chaque passage ; en cas de doute, tout est refusé.
- **La suite en ligne** (v2) : un **serveur Barbacane** (ISO durcie, PKI, passerelle TLS 1.3
  mutuel, interface web d'administration, audit chaîné, mises à jour centralisées, utilisateurs,
  ISO des bornes, quarantaine optionnelle) et une **borne en ligne** (même borne + `barbacane-agent`,
  seule connexion sortante, vers le serveur). Aucun nom de fichier ne quitte la borne.

La borne hors ligne de la v2.0.0 est identique à celle de la v1.0.0.

## Versions publiées

| Version | Date | Contenu | Notes |
|---|---|---|---|
| `v1.0.0` | 19/11/2026 | borne hors ligne | [notes](docs/notes-de-version/v1.0.0.md) · [preuves](docs/preuves/2026-11-19-v1.0.0/README.md) |
| `v2.0.0` | 21/11/2026 | + serveur et borne en ligne | [notes](docs/notes-de-version/v2.0.0.md) · [preuves](docs/preuves/2026-11-21-v2.0.0/README.md) |

Suite prévue : **v2.1.0** (liste dans les [notes v2.0.0](docs/notes-de-version/v2.0.0.md#prévu-pour-v210)).

## Construire les ISO

En root sur Debian 13 (ou conteneur `debian:trixie --privileged`), réseau nécessaire pendant la
construction seulement. Les ISO s'installent sans question et sans réseau ; elles **effacent le
disque interne**.

```shell
apt-get install -y git minisign
git clone https://github.com/Titouanlvt/Barbacane.git barbacane && cd barbacane
borne/update/barbacane-update-keygen ~/cles-barbacane        # clé de signature des mises à jour
cp ~/cles-barbacane/barbacane-maj.pub systeme/iso/maj.pub

# Borne hors ligne (défaut : aucun code réseau)
systeme/iso/build-iso.sh --sortie barbacane.iso

# Borne en ligne générique (CA serveur épinglée, adresse et ports de la passerelle)
systeme/iso/build-iso.sh --profil en-ligne --ca-serveur ca-serveur.pem --serveur 10.20.0.5 \
    --port-enrolement 43118 --port-service 43117 --sortie barbacane-en-ligne.iso

# Serveur (TPM 2.0 exigé), avec les ISO des bornes de la même version embarquées
serveur/iso/build-iso-serveur.sh --port 43117 --port-enrolement 43118 \
    --iso-borne-en-ligne barbacane-en-ligne.iso --iso-borne-hors-ligne barbacane.iso \
    --sha256-bornes SHA256SUMS --sortie barbacane-serveur.iso
```

Options complètes : `--help` de chaque script. **[Manuel Barbacane (PDF)](docs/Barbacane-installation.pdf)**
(borne hors ligne, serveur, bornes en ligne ; source [Markdown](docs/Barbacane-installation.md)) ;
pas à pas de la borne : [guide d'installation](docs/guide-installation-poste.md) ;
borne en ligne : [borne-en-ligne.md](docs/suite/borne-en-ligne.md) ; serveur :
[serveur-iso.md](docs/suite/serveur-iso.md). La PKI de production n'est pas encore outillée :
`serveur/pki/racine-test.sh` ne produit qu'une PKI de **TEST**.

> **Jamais sur un hyperviseur.** Les scripts et paquets refusent un hôte Proxmox (`/etc/pve`).

## Organisation du dépôt

| Dossier | Contenu |
|---|---|
| `noyau/` | pile de lecture/écriture USB isolée, issue d'usbsas (CEA), maintenue ici ([écarts](docs/noyau/ecarts.md)) |
| `borne/` | `client` (interface), `analyzer`, `optique`, `admind`, `parcours`, `update`, `agent` (borne en ligne) |
| `serveur/` | `pki`, `protocole`, `passerelle`, `audit`, `maj`, `web`, `iso`, `iso-bornes`, `sauvegarde` ([README](serveur/README.md)) |
| `systeme/` | ISO de la borne (`iso/`), paquets Debian, unités systemd, pare-feu, durcissement, Ventoy, mkosi |
| `tests/` | mock et EICAR, interface sous Xvfb, mises à jour, ISO sous QEMU, serveur, suite, campagnes Proxmox, CI locale |
| `docs/` | documentation, charte, notes de version, preuves, [archives](docs/archives/README.md) |

## Documentation

| | |
|---|---|
| Manuel | [**Manuel Barbacane** (PDF)](docs/Barbacane-installation.pdf) · [source](docs/Barbacane-installation.md) |
| Borne | [utilisation](docs/exploitation.md) · [administration](docs/administration.md) · [installation](docs/installation.md) · [guide poste](docs/guide-installation-poste.md) |
| Conception | [borne](docs/conception.md) · [disques optiques](docs/conception-optique.md) · [supports démarrables](docs/conception-demarrable.md) · [espace de travail](docs/conception-espace-travail.md) · [suite](docs/conception-barbacane-suite.md) |
| Suite v2 | [vue d'ensemble, FAIT/PRÉVU](docs/suite/README.md) · [décisions](docs/suite/decisions.md) |
| Sécurité | [revue de sécurité](docs/revue-securite.md) · [dossier d'homologation](docs/suite/dossier-homologation.md) · [incident Proxmox](docs/incident-proxmox.md) |
| Tests et preuves | [tests](docs/tests.md) · [**preuves**](docs/preuves/README.md) · [performances](docs/performances.md) |
| Noyau | [architecture](docs/noyau/architecture.md) · [écarts avec usbsas](docs/noyau/ecarts.md) |
| Charte | [charte graphique](docs/charte/README.md) (borne en charte v1, interface web du serveur en charte v2) |

## Sécurité

- **Niveau visé : Diffusion Restreinte** pour la suite (serveur traité comme un SI DR) ;
  cryptographie RGS : P-384/P-256, TLS 1.3, AES-256-GCM, Argon2id. Le projet n'homologue pas :
  la décision revient à l'autorité d'homologation de l'organisme.
- **Pas encore fait (v2.1.0)** : clés et secrets du serveur dans le TPM (fichiers 0600 aujourd'hui,
  preuves avec `swtpm` seulement), preuve sur machine physique avec démarrage sécurisé,
  re-scellement TPM, double validation générale, deux facteurs des administrateurs, cérémonie PKI
  de production. Hors projet : chiffreur IP agréé DR, poste d'administration dédié.
- Les mises à jour sont des paquets `.bcu` signés hors ligne (minisign), revérifiés par la borne,
  sans retour à une version antérieure.

## Développement

```shell
tests/phase1-mock.sh                                   # noyau en mode mock + EICAR
cargo test                                             # tout le workspace
cargo build -p barbacane-admind && tests/maj/maj.sh    # mises à jour signées
tests/ci-locale.sh                                     # mêmes vérifications que la CI GitHub
docs/pdf/generer.sh                                    # Manuel Barbacane en PDF (pandoc + weasyprint)
```

Dépendances (Debian 13) : `pkgconf clang cmake libssl-dev libkrb5-dev libseccomp-dev libudev-dev
libusb-1.0-0-dev protobuf-compiler libdbus-1-dev libwayland-dev libxkbcommon-dev libfuse3-dev
clamav-daemon 7zip bubblewrap minisign xorriso dosfstools mtools exfatprogs ntfs-3g`.

## Licence

GPLv3 ([LICENSE](LICENSE)). Le noyau de lecture USB provient d'[usbsas](https://github.com/cea-sec/usbsas)
(CEA, GPLv3) ; Barbacane l'intègre et le maintient de façon autonome, sans suivre le dépôt d'origine.
`noyau/fscommon` est une copie sous licence MIT.
