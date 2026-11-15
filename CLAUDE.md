# Notes pour Claude Code — projet BARBACANE

Borne de décontamination USB hors ligne (Debian 13). Dépôt **autonome**
`Titouanlvt/Barbacane` (plus de dépôt amont ni de dépendance externe au projet), géré
par Claude. Le noyau de lecture USB provient d'usbsas (CEA) et vit dans `noyau/`.

## Règles permanentes (fixées par l'utilisateur)
- Noyau (`noyau/usbsas-*`) : écarts minimaux, chacun documenté dans `docs/noyau/ecarts.md`.
- Rust, sécurité d'abord, petits commits, tests + CI (aucun test désactivé). Interface et docs en français.
- La borne n'est JAMAIS sur le réseau, même à l'installation : seule l'ISO est valable ;
  `systeme/install.sh` = maquette uniquement.
- Design : charte `docs/charte/` (source : artifact Design System de l'utilisateur).
- Travail sur une branche, fusion dans `main` quand la CI est verte.

## Hôte Proxmox : règles absolues (incident du 15/11/2026, `docs/incident-proxmox.md`)
- Rien de Barbacane ni d'usbsas SUR L'HÔTE : uniquement dans une VM `barbacane-9xx` (900–999).
  `install.sh`, `configurer.sh` et les paquets refusent de toute façon un hôte (`/etc/pve`).
- Jamais modifier sur l'hôte : réseau, pare-feu, modprobe, udev, PAM, GRUB, comptes, services
  (une ligne `iface vmbr0 inet dhcp` a bloqué le démarrage de l'ancien hôte).
- Avant toute autre modification de l'hôte (`qm create`, `apt install`…) :
  `zfs snapshot rpool/ROOT/pve-1@avant-<étape>`. Outils de dev (shellcheck, pandoc, cargo) : dans `bu`/`bb`.
- Ne jamais lire `/root/BARBACANE/.env`. L'ancien NVMe (pool importé `ancien`) : lecture seule.
- Jeton GitHub sans droit `workflow` : une modification de `.github/workflows/` ne peut pas être
  poussée par Claude (patch fourni dans `tests/garde-fou/ci-workflows.patch`).

## Organisation
`noyau/` (crates usbsas, chemins relatifs entre elles) · `borne/` (client, analyzer, admind,
parcours, update) · `systeme/` (ISO, deb, systemd, durcissement) · `tests/` · `docs/`.
Un seul workspace Cargo ; `.cargo/config.toml` fait pointer `USBSAS_BIN_PATH` sur
`target/release` (binaires mock des tests). Clippy strict sur les crates de la borne seulement.

## Vérifications locales
- `tests/phase1-mock.sh` (noyau mock + EICAR ; donne à assert_cmd le chemin d'usbsas-analyzer-server)
- `cargo fmt --all --check && cargo clippy --no-deps --all-targets -p barbacane-client -p barbacane-analyzer -p barbacane-admind -p barbacane-parcours -- -D warnings && cargo test`
- `cargo build -p barbacane-admind && tests/maj/maj.sh`
- `shellcheck systeme/*.sh systeme/iso/*.sh tests/*.sh tests/*/*.sh borne/update/barbacane-update-*`
- Interface : `tests/ui/env.sh` (Xvfb **1280×768**, la résolution minimale visée).

## ISO d'installation hors ligne (`systeme/iso/`)
- `build-iso.sh` (root, Debian 13 ou conteneur `debian:trixie --privileged`) : netinst
  officielle + paquets et dépendances + base ClamAV + `maj.pub` (dans `systeme/iso/maj.pub`).
- `preseed.cfg` sans question ; `fin-installation.sh` installe les .deb SANS aucune source apt
  (sinon apt attend la source « cdrom: » et l'installation se fige à 14 %).
- CI : `.github/workflows/iso.yml` (construction + `tests/iso/qemu.sh`), `ci.yml` (le reste).

## Lab Proxmox (preuves sur vraies clés)
- `tests/proxmox/preuve.sh` : VM 910 sans réseau, installation de l'ISO, PIN, enrôlement,
  transfert, blanchiment, journal ; `REPRISE=1` repart de l'instantané « installee ».
- `tests/proxmox/borne.py` : clics via QMP (tablette absolue ; `mouse_move` HMP est relatif)
  et lecture OCR (tesseract fra, captures binarisées en 3 seuils).
- VM 901 = construction (Debian 13). Clés de test Phison très lentes (~4 Mo/s) : effacement
  complet d'une clé de 7 Go ≈ 45 min.

## État au 14/11/2026
- **Preuves faites sur vraies clés** (docs/preuves/README.md, verdict OK) : transfert (EICAR
  détecté et absent en sortie, sains intacts) et blanchiment (empreinte modifiée, EICAR effacé,
  sains réécrits). Clés : SanDisk 16 Go (source) et SanDisk Ultra 64 Go (destination enrôlée).
- Corrigés : blocage d'installation à 14 %, boutons hors écran en 1280×800, CI phase 1,
  délais USB (30 s, écart n°2), progression avec vitesse/temps restant, charte graphique.
- `main` = arborescence refondue (noyau/ borne/ systeme/ tests/ docs/), fusionnée en gardant le
  contenu prouvé : les 100 commits amont usbsas présents sur l'ancien main n'y sont PAS appliqués.

## Reste à faire
1. Rejouer le blanchiment sur clé lente (Phison 13fe:4200) avec les délais de 30 s.
2. Test de la borne à 8 Go de RAM ; reprendre les correctifs amont usbsas un par un (tests + preuve).
3. Charte : thème Nuit (option), animations d'analyse, bandeau d'étapes.
4. Image mkosi jamais construite ; drop-in tmpfs non supprimé à la purge (mineur).
