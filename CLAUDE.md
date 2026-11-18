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

## État au 15/11/2026
- Campagne USB finale : 53 OK, 0 échec (docs/preuves/README.md). VMs : 901 bb (construction),
  902 bu (ISO), 903 bz (Debian vierge), 920 borne USB, 921 borne optique.
- **Disques optiques** (`borne/optique`, service `barbacane-optique`, socket
  `/run/barbacane-optique/optique.sock`) : prouvés sur vrai graveur + CD-RW, lecteur passé à la VM
  en scsi-generic UNIQUEMENT (jamais de passthrough PCI : le contrôleur SATA porte le disque système
  de l'hôte). `tests/proxmox/optique.sh` ; le tiroir doit être refermé à la main (prévenir l'utilisateur).
  usbsas : écart n° 5 (analyse d'un dossier local source).
- Pièges : `pkill -f` dont le motif figure dans la commande tue le shell ; libellés de boutons sur
  deux lignes pour l'OCR (cliquer sur la 1re ligne).

## État au 16/11/2026
- Charte : thème Nuit (Administration → Affichage, `preferences.json` dans admind, palette
  runtime `style::c()`), bandeau d'étapes (`view_etapes`), animations (`anim.rs` : clé qui glisse,
  faisceau d'analyse, bouclier, herse ; option « Animations réduites »). Vérifié sous Xvfb 1280×768.
- `build-debs.sh` limite `CARGO_BUILD_JOBS` à la mémoire libre (SIGKILL sur cranelift-codegen).

## État au 17/11/2026
- Espace de travail : dm-crypt éphémère sur fichier creux, clé neuve à chaque démarrage ET à chaque
  fin de session (op `nouvelle_session` d'admind) ; taille 50 % du disque (`/etc/barbacane/travail.conf`) ;
  refus avant copie si 3 × contenu > libre (`parcours::verifier_espace`). `docs/conception-espace-travail.md`.
- Parcours unique : « Analyser » puis Copier vers une clé connue / Graver / Blanchir / Arrêter ici.
- Clés Ventoy : écart n° 9 (fs2dev `WriteRaw`, `RequestInitTransfer.bootable`, `ventoy = ` dans la
  config usbsas) ; Ventoy 1.1.18 embarqué (`systeme/ventoy/`, empreinte épinglée). Rufus/Etcher :
  détectées, avertissement (liste blanche d'images : conçue, pas encore faite).
  `docs/conception-demarrable.md`.
- Corrigés : délai global reqwest 30 s (écart n° 8, vraie cause du « Remote server error »),
  reconnexion usbsas après effacement, ClamAV MaxScanTime 30 min, rapports > 10 Mo, ISO prise pour
  une bombe (plancher 64 Mo), conteneur > 2 Go sain copié intact.
- Tests : `tests/proxmox/parallele.sh` (borne modèle 940 installée depuis une clé émulée, clones
  941+ en parallèle, clés `virt:NOM`, copie figée des scripts). Les VMs de test sur le pool `nvme`.
  Piège : un script bash en cours d'exécution relit son fichier ; ne jamais le réécrire en place
  (sed -i ou écriture + mv seulement). Le lanceur se relance depuis sa copie figée (`FIGE=1`),
  détruit chaque clone fini ; `SCENARIOS="ventoy usb"` pour ne rejouer que certains scénarios.
- Écart n° 10 : étiquette FAT12/16 lue à 0x2B (sinon `VTOYEFI` jamais reconnue). Ventoy prouvé
  jusqu'au démarrage (`docs/preuves/ventoy/`).
- Liste blanche d'images officielles prouvée avec une clé de signature de TEST du lab
  (`~/cles-test` sur bu, ISO `barbacane-TEST-cle-lab.iso`) : `docs/preuves/liste-blanche/`.
- Analyseur : fichiers simples d'un conteneur analysés sur 4 fils ; compteur en direct.
- Écart n° 11 (branche `etcher-image`) : `RewriteImage` relit l'image d'une clé Etcher/Rufus DD,
  empreinte à chaque frontière de 2048 octets, réécriture seulement si elle est dans la liste.
- `rpool` (système de l'hôte + local-zfs, 109 Go) s'est rempli le 17/11 (clés émulées de 12 Go dans
  /var/lib/vz) : bu (disque sur local-zfs) en `io-error` → `qm resume 902` après nettoyage. Clés
  émulées désormais sur `/nvme/virt` ; ne rien mettre de gros dans /var/lib/vz.
- CI publique lisible sans `gh` : `curl api.github.com/repos/Titouanlvt/Barbacane/actions/runs`.

## Travail autonome (règles de l'utilisateur, 17/11/2026)
- Toute commande longue : `timeout`, en arrière-plan avec journal dans `/root/BARBACANE/logs/`,
  attente par `lab/attendre.sh JOURNAL MOTIF ÉCHÉANCE [BLOCAGE]` (jamais `pgrep -f` : se trouve lui-même).
- Rien d'interactif ; ssh en BatchMode (`lab/ssh_config`). VM figée > 15 min : screendump, arrêt, diagnostic.
- 3 échecs sur un même problème : section « Bloquants » de `docs/preuves/README.md`, puis tâche suivante.
- Suivi : `/root/BARBACANE/AVANCEMENT.md` ; commit + push au moins toutes les heures.
- Choix faits sans l'utilisateur : preuve de la liste blanche avec une clé de signature de TEST du lab
  (la phrase de passe de production n'est connue que de l'utilisateur).
- Réécriture d'image Etcher vérifiée : REPORTÉE après la fusion dans main. Plan retenu : requête usbsas
  `RewriteImage{id, taille, sha256}` (lecture scsi2files → files2fs en mode brut avec empreinte calculée
  au vol par usbsas ; comparaison AVANT toute écriture ; puis effacement fs2dev et écriture avec un
  bitvec construit par usbsas) ; liste blanche étendue à « sha256  taille  nom ». En attendant :
  blanchiment classique + avertissement, Ventoy proposé comme alternative démarrable.

## État au 17/11 au soir
- Transfert et blanchiment reprouvés sur l'ISO e888495 : `docs/preuves/2026-11-17-finale/`. Suite : `AVANCEMENT.md`.
- cranelift-codegen : SIGKILL à la compilation (mémoire), corrigé le 16/11 dans `build-debs.sh` ;
  ne concerne pas la borne (rien n'y est compilé).
- Ancien clone `/root/BARBACANE/usbsas` obsolète (choix : captures rapatriées, branche non recréée).

## État au 18/11/2026
- Tests accélérés : instantané « propre » (installée, PIN, clé enrôlée, avec la mémoire) restauré en
  5 à 8 s avant chaque scénario (`PROPRE=1`, `REPRISE=propre`, `RETOUR=0` pour enchaîner ;
  `export`/`journal` ne reviennent jamais à l'instantané). Lanceur : `tests/proxmox/campagne-rapide.sh`.
- Correctifs sans ISO : borne de développement **950** installée depuis l'ISO de TEST (`~/iso-test`
  sur bu, `--cle-publique ~/cles-test/test.pub`) ; `tests/proxmox/correctif.sh` (compilation
  incrémentale, `DEB_REVISION`, ~3 min) puis scénario `correctif` (applique, redémarre, nouvel instantané).
- Mises à jour avec paquets Debian : apt et dpkg passent par `systemd-run --wait` (sous admind,
  `ProtectKernelModules` vidait l'initramfs et la borne ne redémarrait plus) ; jamais `--no-download` ;
  le postinst ne redémarre JAMAIS admind ; redémarrage demandé à l'administrateur.
- Pièges : `qm set --args` VM allumée reste « en attente » et revient à chaque restauration
  d'instantané (d'où le `device_del cvusb0dev` dans `revenir`) ; `build-debs.sh` vide son dossier de
  sortie ; diagnostic d'une VM qui ne démarre plus : disque monté `ro,noload` sur l'hôte ou clone ZFS
  `readonly=on` de l'instantané (snapshot rpool avant, clone détruit après).

## Reste à faire
1. Rejouer le blanchiment sur clé lente (Phison 13fe:4200) avec les délais de 30 s.
2. Test de la borne à 8 Go de RAM ; reprendre les correctifs amont usbsas un par un (tests + preuve).
5. « Tout Rust » : ntfs-3g et FatFs (C, `noyau/usbsas-fsrw`, isolés par seccomp) restent ; les remplacer
   (crates `fatfs`, `ntfs`) ferait perdre l'exFAT et l'écriture NTFS (sortie FAT32 seule, 4 Go/fichier).
   Décision du 15/11 : fiabilité d'abord, chantier à part avec sa propre campagne de preuves.
4. Image mkosi : construite et démarrée le 16/11 (docs/preuves/mkosi/) ; pas de base ClamAV ni
   d'agrandissement de la racine ; campagne sur vraies clés non faite (l'ISO reste la référence).
