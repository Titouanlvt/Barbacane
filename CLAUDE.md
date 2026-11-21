# Notes pour Claude Code — projet BARBACANE

Borne autonome de décontamination USB (Debian 13) et suite en ligne (Serveur Barbacane, Borne connectée,
Console, Liaison bornes, Journal, Quarantaine). Versions publiées : v1.0.0 (19/11/2026), v2.0.0 et
v2.0.1 (21/11/2026) ; en cours : v2.0.2, feuille de route dans `AVANCEMENT.md`. Dépôt **autonome**
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
parcours, update, optique, agent) · `serveur/` (PKI, passerelle, audit, web, ISO serveur) · `systeme/` (ISO, deb, systemd, durcissement) · `tests/` · `docs/`.
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

## Lab Proxmox
- VM existantes : **902 bu** (outils de dev, ISO, CI locale : `ssh -F lab/ssh_config bu`) et **950**
  (borne de développement, installée depuis l'ISO de TEST). Les autres numéros (901, 903, 920, 921,
  930, 940…) ont été supprimés ; ils ne survivent que comme valeurs par défaut de `tests/proxmox/*`
  (VM créées par le script) et dans les preuves archivées. Ponts internes `vmbr9`/`vmbr10`.
- `tests/proxmox/preuve.sh` : installation de l'ISO dans une VM sans réseau, PIN, enrôlement,
  transfert, blanchiment, journal ; `REPRISE=1` / `REPRISE=propre`, `PROPRE=1`, `RETOUR=0`.
  Lanceur rapide : `tests/proxmox/campagne-rapide.sh` ; parallèle : `tests/proxmox/parallele.sh`.
- `tests/proxmox/borne.py` : clics via QMP (tablette absolue ; `mouse_move` HMP est relatif) et OCR
  (tesseract fra, 3 seuils). Libellés sur deux lignes : cliquer sur la 1re.
- Correctifs sans ISO sur la 950 : `tests/proxmox/correctif.sh` (`DEB_REVISION`, ~3 min).
- Disques optiques : lecteur passé en scsi-generic UNIQUEMENT (jamais de passthrough PCI : le
  contrôleur SATA porte le disque système de l'hôte) ; tiroir à refermer à la main (prévenir).
- RTX 4000 non passée aux VM (seule carte d'affichage de l'hôte). Clés Phison très lentes (~4 Mo/s).
- Rien de gros dans `rpool` ni `/var/lib/vz` (saturé le 17/11) : pools `nvme` / `essais`
  (`docs/lab/essais.md`, désigner le disque par `/dev/disk/by-id/…20041A804255`).

## Pièges encore utiles
- `pkill -f` dont le motif figure dans la commande tue le shell ; jamais `pgrep -f` pour attendre.
- Un script bash en cours d'exécution relit son fichier : ne jamais le réécrire en place.
- `qm set --args` VM allumée reste « en attente » et revient à chaque restauration d'instantané.
- `build-debs.sh` vide son dossier de sortie et limite `CARGO_BUILD_JOBS` à la mémoire libre.
- Mises à jour avec paquets Debian : apt/dpkg via `systemd-run --wait` (sous admind,
  `ProtectKernelModules` vidait l'initramfs) ; jamais `--no-download` ; le postinst ne redémarre
  JAMAIS admind.
- Borne : charte v1 (y compris Borne connectée) ; charte v2 = Console seulement ; branche
  `borne-charte-v2` gardée, non fusionnée.
- CI publique lisible sans `gh` : `curl api.github.com/repos/Titouanlvt/Barbacane/actions/runs`.

## Travail autonome (règles de l'utilisateur, 17/11/2026)
- Toute commande longue : `timeout`, en arrière-plan avec journal dans `/root/BARBACANE/logs/`,
  attente par `lab/attendre.sh JOURNAL MOTIF ÉCHÉANCE [BLOCAGE]` (jamais `pgrep -f` : se trouve lui-même).
- Rien d'interactif ; ssh en BatchMode (`lab/ssh_config`). VM figée > 15 min : screendump, arrêt, diagnostic.
- 3 échecs sur un même problème : section « Bloquants » de `docs/preuves/README.md`, puis tâche suivante.
- Suivi : `/root/BARBACANE/AVANCEMENT.md` ; commit + push au moins toutes les heures.
- Choix faits sans l'utilisateur : preuve de la liste blanche avec une clé de signature de TEST du lab
  (la phrase de passe de production n'est connue que de l'utilisateur).
- Chantiers en parallèle dans des worktrees `../wt-<chantier>` ; CI locale avant tout push
  (`timeout 3500 lab/ci-locale-bu.sh BRANCHE`, journal `logs/ci-locale-BRANCHE.log` fini par « FIN 0 ») ;
  ne jamais attendre la CI GitHub.

## Reste à faire
Voir `AVANCEMENT.md` (feuille de route) ; historique des états datés : `git log -- CLAUDE.md`.
