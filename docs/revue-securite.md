# Revue de sécurité de Barbacane

Revue du 14/11/2026 : code de la borne (`borne/`), intégration système (`systeme/` : systemd,
nftables, modprobe, udev, PAM, preseed, scripts ISO) et points de contact avec le noyau de
lecture USB (`noyau/`, issu d'usbsas). Les chemins `barbacane/…` de l'énoncé correspondent
à `borne/` et `systeme/` depuis la refonte du dépôt.

Échelle : **critique** (compromission sans accès physique particulier ou fuite de fichiers
dangereux vers la sortie), **élevé** (compromission de la borne avec un geste simple),
**moyen** (contournement d'une politique ou indisponibilité), **faible** (défense en profondeur).

## Synthèse

| N° | Gravité | Constat | État |
|---|---|---|---|
| S-01 | moyen | Menu GRUB sans mot de passe (édition de la ligne du noyau si le menu s'affiche) | **corrigé** (`a9328f2`) |
| S-02 | élevé | Correctifs mémoire amont des lecteurs FAT/NTFS absents du noyau | **corrigé** (`14425be`) |
| S-03 | moyen | Le premier PIN saisi devient le PIN : borne livrée « ouverte » | documenté |
| S-04 | moyen | Noms de sortie issus d'archives non normalisés (contrôle, longueur) | à démontrer (étape 4) |
| S-05 | faible | Enrôlement par n° de série (copiable), contrôlé par l'interface seule | documenté |
| S-06 | faible | Souris acceptée sur tous les ports (`ports_hid` non réglé) | documenté |
| S-07 | faible | API locale de l'analyseur sans authentification | documenté |
| S-08 | faible | Fichiers sains de la dernière session conservés sur disque jusqu'à la suivante | documenté |

Aucun constat critique. Le constat élevé est corrigé (commit et tests) ; S-01, classé élevé au départ puis
ramené à moyen après essai (voir ci-dessous), est corrigé aussi.

## Constats

### S-01 — moyen (élevé à l'analyse, ramené après essai) — GRUB sans mot de passe (corrigé)
- Où : `systeme/grub/barbacane.cfg` (`GRUB_TIMEOUT=0`, aucun mot de passe), `systeme/iso/configurer.sh`.
- Hypothèse initiale : Échap au démarrage ouvre le menu, `e` permet d'ajouter `init=/bin/sh -c "…"`
  (shell root sans PIN, avec le seul clavier du firmware). **Essai sur la borne** : Échap envoyé toutes
  les 30 ms pendant tout le démarrage n'ouvre pas le menu ; avec `GRUB_TIMEOUT=0` GRUB démarre
  directement ([preuves/grub](preuves/grub/)). L'attaque n'est donc pas démontrée.
- Risque résiduel : GRUB affiche son menu ou sa ligne de commande quand le démarrage échoue
  (configuration abîmée, entrée introuvable) ; sans mot de passe, ce menu permet la même attaque.
- Correctif (défense en profondeur) : super-utilisateur GRUB avec mot de passe aléatoire jamais conservé
  (`/etc/grub.d/01_barbacane`), entrées Debian `--unrestricted` (démarrage automatique, édition et ligne de
  commande interdites), `10_linux` dévié par `dpkg-divert` pour résister aux mises à jour de grub.
- Tests : `tests/iso/qemu.sh` (CI) et `tests/proxmox/preuve.sh` (étape journal) vérifient `superusers`,
  `password_pbkdf2` et l'entrée par défaut `--unrestricted` dans le `grub.cfg` installé.
- Conséquence : un PIN perdu impose une réinstallation (doc corrigée ; l'ancienne procédure
  « clavier en mode maintenance » était impossible : root verrouillé, aucun pilote clavier).

### S-02 — élevé — Correctifs amont des lecteurs FAT/NTFS absents (corrigé)
- Où : `noyau/usbsas-fsrw` (lecteur NTFS via `ntfs3g` en C, lecteur FAT `ff`).
- Attaque : clé au système de fichiers NTFS forgé déclenchant la double fermeture d'un inode
  parent, un débordement d'horodatage ou un nom invalide ; corruption mémoire dans le processus
  de lecture (confiné par seccomp, mais c'est la première ligne de défense).
- Cause : la fusion de `main` en conservant le contenu prouvé a écarté 25 commits du CEA sur ces lecteurs.
- Correctif : dossier `usbsas-fsrw` amont repris tel quel + `4005053` (pas de panique sur version
  d'analyseur inattendue) ; écart n°3 de `docs/noyau/ecarts.md`.
- Tests : `nul_in_path`, `malicious_on_disk_timestamp`, `invalid_names`, `failed_mount_releases`,
  `timestamp_clamped`, `concurrent_mkntfs` ; phase 1 et e2e (clés FAT et NTFS) au vert.

### S-03 — moyen — Premier PIN = premier venu
- Où : `borne/admind/src/main.rs:161`.
- Attaque : une borne installée puis laissée sans PIN ; un passant ouvre Administration, choisit le
  PIN, désactive le mode « clés enrôlées » ou enrôle sa clé, exporte les journaux.
- Ce qui reste protégé : les mises à jour exigent une signature (aucun code ne peut être installé).
- Mesure : choisir le PIN immédiatement après l'installation (guide, étape « Premier démarrage »).
  Option possible : PIN fixé à la construction de l'ISO (non retenu : il serait sur le poste connecté).

### S-04 — moyen — Noms de sortie issus d'archives
- Où : `borne/analyzer/src/scan.rs:424` (`{archive}.extrait/{chemin interne}`).
- Attaque : archive contenant un fichier sain dont le nom a des caractères de contrôle ou dépasse
  255 caractères ; l'écriture exFAT peut échouer et faire échouer toute la copie (déni de service),
  sans fuite de fichier dangereux. Démonstration prévue sur la borne (étape 4, `preuves/hostile/`).

### S-05 — faible — Enrôlement par numéro de série
- Où : `borne/client/src/app.rs:245` ; le noyau écrit sur toute destination demandée par l'interface.
- Attaque : copier le n° de série d'une clé enrôlée sur une clé programmable. Le mode limite les
  erreurs et les clés personnelles ; ce n'est pas une authentification (déjà écrit dans
  `docs/administration.md`). Seule l'interface (utilisateur `barbacane-kiosk`) parle au noyau.

### S-06 — faible — Souris sur tous les ports
- Où : `systeme/etc/config.toml:53` (`ports_hid` commenté).
- Attaque : clé BadUSB se déclarant souris : elle peut cliquer comme un utilisateur (pas
  d'administration sans PIN). Mesure : renseigner `ports_hid` avec le port de la souris.
- Clavier : aucune frappe possible. `hid-user` ne transmet que mouvements et boutons (`uinput`
  n'active aucune touche), les pilotes HID et PS/2 du noyau sont bloqués (`noyau/usbsas-hid/assets/hid.conf`).
  Preuve sur la borne : [docs/preuves/hostile](preuves/hostile/).

### S-07 — faible — API locale de l'analyseur
- `127.0.0.1:8042` sans authentification (préparation, armement de l'import). Atteignable seulement
  par un processus local ; les processus de lecture du noyau n'ont pas accès au réseau (seccomp),
  le pare-feu refuse tout hors `lo`.

### S-08 — faible — Restes de session
- `/var/lib/barbacane/sortie` est vidé avant chaque préparation (`borne/analyzer/src/stage.rs`), mais
  les fichiers sains d'une copie restent sur le disque de la borne jusqu'à la suivante.

## Points vérifiés sans constat

| Domaine | Vérification |
|---|---|
| Clavier / BadUSB | souris seule transmise, aucun pilote clavier noyau (S-06) |
| Traversée de chemin, liens | `extract.rs:288` refuse `/`, `\`, `X:`, `..` ; liens et fichiers spéciaux non suivis ni copiés (`scan.rs:455`) ; tests `borne/analyzer/tests/archives.rs` |
| Bombes, archives chiffrées, imbrication | limites de taux, taille, nombre, profondeur ; mot de passe 3 essais / 300 s ; tests `archives.rs` |
| Rapport HTML | échappement `& < > "` (`report.rs:122`) |
| Sortie | seul le dossier de préparation (fichiers sains + 2 rapports) est copié ; destination effacée puis formatée |
| PIN | Argon2id, 6 chiffres minimum, verrouillage croissant après 5 échecs, persistant au redémarrage |
| Mises à jour | signature du fichier entier, version strictement supérieure, empreintes, rotation signée par l'ancienne clé ; `tests/maj/maj.sh` |
| Socket d'administration | `0660`, groupe `barbacane-kiosk` |
| Réseau | nftables : tout refusé hors `lo` ; services réseau masqués ; pas de carte réseau requise |
| Confinement | analyseur sans privilège, sans capacité, filtre d'appels système, extraction dans bubblewrap ; usbsas-server sans capacité ; kiosque sans changement de console |
| Dépendances | `cargo audit` propre (exception justifiée RUSTSEC-2023-0071, `.cargo/audit.toml`) |
