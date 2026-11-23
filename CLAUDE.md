# Notes pour Claude Code — projet BARBACANE

Borne autonome de décontamination USB (Debian 13) et suite en ligne (Serveur Barbacane, Borne connectée,
Console, Liaison bornes, Journal, Quarantaine). Versions publiées : v1.0.0 à v2.2.0 (19–22/11/2026) ;
en cours : v2.3.0 (journal structuré, Syslog, conservation), feuille de route dans `AVANCEMENT.md`. Dépôt **autonome**
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
  (VM créées par le script) et dans les preuves archivées. Ponts internes Barbacane : `vmbr11` (bornes) et
  `vmbr10` (administration), sans port physique ni adresse hôte (`/etc/network/interfaces.d/barbacane-labo`).
- `tests/proxmox/preuve.sh` : installation de l'ISO dans une VM sans réseau, PIN, enrôlement,
  transfert, blanchiment, journal ; `REPRISE=1` / `REPRISE=propre`, `PROPRE=1`, `RETOUR=0`.
  Lanceur rapide : `tests/proxmox/campagne-rapide.sh` ; parallèle : `tests/proxmox/parallele.sh`.
- `tests/proxmox/borne.py` : clics via QMP (tablette absolue ; `mouse_move` HMP est relatif) et OCR
  (tesseract fra, 3 seuils). Libellés sur deux lignes : cliquer sur la 1re.
- Correctifs sans ISO sur la 950 : `tests/proxmox/correctif.sh` (`DEB_REVISION`, ~3 min).
- Disques optiques : lecteur passé en scsi-generic UNIQUEMENT (jamais de passthrough PCI : le
  contrôleur SATA porte le disque système de l'hôte) ; tiroir à refermer à la main (prévenir).
- RTX 4000 non passée aux VM (seule carte d'affichage de l'hôte). Clés Phison très lentes (~4 Mo/s).
- Stockage (22/11/2026, `docs/lab/stockage.md`) : pool **`nvme`** = agrégat (sans redondance) de 2 Micron 2650
  (`/dev/disk/by-id/nvme-2650_Micron_256GB_2523509303FF`, `…_252350930419`) : disques de bu et de la 950,
  `/nvme/{contenu,correctifs,virt}`. Rien dans `rpool`/`local-zfs` ni `/var/lib/vz` (système seulement).
- **Hôte partagé avec Clautilde** (Claude Code de l'infra LLC) : son pool PVE `clautilde`, ses stockages
  `clautilde` et `clautilde-iso` (disque WDC …20041A804255), ses ponts `vmbr9` (NAT Internet) et `vmbr20` (isolé).
  Ne jamais toucher à ses VM, volumes, stockages ni ponts ; ne jamais utiliser `vmbr9`/`vmbr20` pour Barbacane.

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
- Journal d'audit (v2.3.0) : schéma chaîné version 2, segments dans `registre/audit-segments/` ;
  lire TOUT le journal avec `Journal::contenus()`/`verifier_tout()`, jamais `lire()` seul (journal actif).
- Banc serveur v2.3.0 : `MDP_ADMIN=…` active `tests/serveur/qemu-journal.sh` (console série en root,
  horloge de la VM avancée, collecteur Syslog de test sur l'hôte du banc via guestfwd 10.0.3.100).

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
