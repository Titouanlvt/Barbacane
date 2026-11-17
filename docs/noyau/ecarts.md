# Écarts du noyau par rapport à usbsas (CEA)

Base : `cea-sec/usbsas`, commit `69ebcf4` (usbsas-usbsas 0.3.4).

Le code usbsas n'est modifié que par les écarts listés ci-dessous (commits dédiés). Le noyau est dans `noyau/`, le code de la borne dans `borne/`.
Ajouts hors code : `docs/`, `.github/workflows/barbacane.yml`.

## Écarts appliqués

### 1. seccomp `files2fs` : comparaison du descripteur sur 64 bits
- Symptôme : `files2fs` est tué (SIGSYS) au formatage ; le transfert clé → clé échoue (« failed to fill whole buffer »).
- Cause : la règle `lseek` compare l'argument 0 sur 64 bits, or les 32 bits hauts du registre ne sont pas garantis nuls
  pour un `int` (ABI x86_64). Observé : `lseek(0x55bb00000003, 0x1fe, SEEK_SET)`. Dépend du compilateur.
- Correctif (`usbsas-sandbox/src/*.rs`) : toutes les comparaisons de l'argument 0 (descripteur) passent en
  `Cmp::MaskedEq` avec masque `0xffffffff` (le noyau ne lit que 32 bits pour un `int`). À proposer au CEA en PR.

### 2. Délais USB alignés sur Linux (`usbsas-mass-storage`, `usbsas-scsi`)
- Symptômes, sur une clé lente (Phison 13fe:4200, ~1 à 4 Mo/s) pendant un blanchiment :
  1. après 27 min d'effacement : « timed out reading CSW, retrying (1/3) … (2/3) » puis
     « usb error during status stage: Operation timed out » ;
  2. après 1 h 46 : « usb error during data-in stage: Operation timed out ».
  Affiché « usbsas : bad request » ; la clé reste effacée sans être réécrite.
- Cause : pendant les longues écritures, les clés bon marché marquent des pauses internes
  (vidage de cache, ramasse-miettes de la mémoire flash) de plus de 5 s ; usbsas n'accordait
  que 5 s par transfert USB (Linux : 30 s par commande).
- Test modifié (à signaler) : `csw_timeouts_are_retried` vérifiait 2 expirations tolérées sur 3 ; il
  vérifie maintenant 1 tolérée sur 2 (même propriété, nouvelle valeur), il n'est pas affaibli.
- Correctif : délai de transfert 5 s → 30 s (`usbsas-mass-storage/src/lib.rs`) et
  `CSW_READ_ATTEMPTS` 3 → 2 (`usbsas-scsi/src/lib.rs`), soit 60 s d'attente du statut.
  Aucune donnée n'est relue ni réécrite : on attend seulement plus longtemps la même commande.

### 3. Reprise des correctifs amont de `usbsas-fsrw` et de `usbsas-usbsas`
- Constat (revue de sécurité du 14/11/2026, docs/revue-securite.md, S-02) : 25 commits du CEA sur
  les lecteurs de systèmes de fichiers manquaient au noyau (fusion `-s ours` de main) ; plusieurs
  corrigent des défauts mémoire atteignables par une clé piégée : double fermeture d'inode NTFS,
  inodes non fermés sur erreur, horodatages qui débordent, noms invalides, chemins contenant NUL (FAT).
- Correctif : `noyau/usbsas-fsrw` remplacé par la version amont (commit `0af6969` du dépôt, dossier
  inchangé jusque-là côté Barbacane) ; commit amont `4005053` appliqué à `usbsas-usbsas/src/states.rs`
  (plus de panique sur une version d'analyseur non prise en charge).
- Tests apportés : `nul_in_path`, `malicious_on_disk_timestamp`, `invalid_names`, `failed_mount_releases`,
  `timestamp_clamped`, `concurrent_mkntfs`… ; phase 1, e2e de la borne (FAT et NTFS) au vert.
- Non repris (hors usage de la borne) : `907301e` (espace disque avant téléchargement réseau ; la borne
  n'utilise pas la source réseau).

### 4. Paquets `usbsas-server` et `usbsas-hid` : refus sur un hôte Proxmox (`preinst`)
- Contexte : incident du 15/11/2026 ([../incident-proxmox.md](../incident-proxmox.md)). Ces paquets
  posent des règles udev et modprobe (`usbsas-hid` : `hid.conf`, `99-usbsas-hid.rules`) qui
  rendraient un hyperviseur inutilisable s'ils y étaient installés par erreur.
- Correctif : `noyau/usbsas-usbsas/debian/preinst` et `noyau/usbsas-hid/debian/preinst` (nouveaux,
  aucun code Rust touché) sortent en erreur si `/etc/pve` existe, avant la copie des fichiers.
- Test : `tests/garde-fou/paquets.sh` (VM de test ; CI : `tests/garde-fou/ci-workflows.patch`). Spécifique à Barbacane, pas à proposer au CEA.

### 5. Analyse des fichiers d'un dossier local source (`usbsas-usbsas/src/states.rs`)
- Constat (campagne optique du 15/11/2026, VM 921) : un disque optique lu par `barbacane-optique` est
  présenté à usbsas comme dossier local (`[[src_local_dirs]]`). En amont, la décision d'analyser
  (`analyze_usb`, `analyze_cmd`…) ne s'applique qu'aux sources USB : les fichiers d'un dossier local
  n'étaient **jamais analysés**. Sur la borne, l'interface l'a refusé (« analyse introuvable ») ;
  aucun fichier n'a été copié.
- Correctif : une source `LocalDir` vers une destination commande (la passe d'analyse de la borne,
  par laquelle passe tout disque) est analysée selon `analyze_cmd`, comme une clé. Les autres
  transferts depuis un dossier local (dossier de préparation, déjà analysé, vers la clé de sortie)
  restent comme en amont (une première version qui les réanalysait cassait le test bout en bout).
- Test : `tests/proxmox/optique.sh`, étape `image` (EICAR caché dans la 1re session du disque bloqué,
  fichiers sains copiés). Spécifique à l'usage de Barbacane ; proposable au CEA (option de configuration).

### 6. Liaisons ntfs-3g générées : avertissement `unsafe_op_in_unsafe_fn` (`usbsas-fsrw/ntfs3g/src/n3g_c.rs`)
- Constat : à chaque construction, deux avertissements E0133 dans `bindings.rs`, code **généré**
  par bindgen (édition 2024), pas écrit à la main ; ils noyaient les messages utiles.
- Correctif : `#![allow(unsafe_op_in_unsafe_fn)]` dans le module qui inclut les liaisons, comme les
  autres `allow` déjà présents pour ce code généré. Aucun changement de comportement.

### 7. ISO hybride copiée sur une clé (Etcher, Rufus « mode DD ») : système ISO 9660 ignoré (`usbsas-dev2scsi/src/lib.rs`)
- Constat (campagne du 16/11/2026, image d'une ISO Debian netinst copiée telle quelle sur une vraie
  clé) : la table de partitions de l'ISO hybride ne déclare qu'une partition EFI (FAT), reconnue ; le
  système ISO 9660 n'était cherché que si **aucune** partition n'était reconnue. Seuls les 3 fichiers
  EFI étaient lus (sur 1 011) ; un blanchiment aurait effacé l'ISO en ne gardant que ces 3 fichiers.
- Correctif : la signature `CD001` (octet 0x8001 ou 0x8801) est toujours cherchée ; si elle est
  présente, la partition qui démarre au secteur 0 (ou une partition ajoutée couvrant le
  périphérique) est déclarée ISO9660. La borne choisit la plus grande partition lisible : l'ISO.
- Test : `tests/proxmox/preuve.sh`, étape `reel` (scénario `etcher`).

### 8. Envoi à l'analyseur coupé au bout de 30 s (`usbsas-net/src/lib.rs`)
- Constat (Dell OptiPlex 7090, puis campagne du 16/11/2026 sur une clé de 4,9 Go) : « Remote server
  error » / « reqwest error: error sending request ». Le client HTTP **bloquant** de reqwest applique
  par défaut un délai global de 30 s à chaque requête ; l'envoi de l'archive de session (plusieurs Go)
  à l'analyseur local dure plus longtemps et était coupé net (l'analyseur journalise « end of file
  before message length reached », alors que l'espace de travail était largement libre).
- Correctif : `timeout(None)` sur le client (le délai de connexion de 30 s est conservé). L'analyseur
  est local (127.0.0.1) ; un arrêt du service ferme la connexion et l'erreur remonte toujours.
- Test : `tests/proxmox/preuve.sh`, étape `volumineux`.

### 9. Clé Ventoy reconstruite : écriture de secteurs bruts après le système de fichiers (`usbsas-fs2dev`, `usbsas-usbsas`, protocoles)
- Besoin (17/11/2026) : blanchir une clé Ventoy **sans la rendre inutilisable**, sans jamais
  recopier sa zone de démarrage (non vérifiable). usbsas ne savait écrire qu'un système de
  fichiers couvrant toute la clé.
- Correctif :
  - `RequestInitTransfer.bootable` ; refusé si la destination n'est pas une clé USB ou si la zone
    de démarrage de confiance n'a pas été chargée ;
  - configuration `ventoy = "<dossier>"` (`boot.img`, `core.img`, `ventoy.disk.img`, décompressés,
    issus de la version de Ventoy embarquée dans la borne), lue **avant** l'application du bac à
    sable de la session ;
  - files2fs crée la partition de données du secteur 2048 jusqu'à la partition `VTOYEFI`
    (fin de clé moins 32 Mio, alignée sur 1 Mio) ;
  - fs2dev : après l'écriture du système de fichiers, nouvel état acceptant `WriteRaw`
    (secteur, données en secteurs entiers, 120 Kio au plus, dans la clé) puis `End` ;
  - usbsas écrit le secteur 0 (code de démarrage de `boot.img`, identifiant aléatoire, table :
    partition 1 active, partition 2 type 0xEF), `core.img` à partir du secteur 1 et
    `ventoy.disk.img` dans `VTOYEFI` — mêmes emplacements que `Ventoy2Disk.sh` en mode MBR.
- Limite : table MBR, donc clés de 2 Tio au plus (`ventoy::part2_start` refuse au-delà).
- Tests : `usbsas-usbsas/src/ventoy.rs` (disposition, découpage) ; `tests/proxmox/preuve.sh`,
  étape `ventoy` (clé reconstruite comparée octet par octet à la version embarquée, puis démarrée
  dans une VM).

### 10. Étiquette des partitions FAT12/FAT16 lue au bon endroit (`usbsas-dev2scsi`)
- Constat (17/11/2026, passages parallèles n° 4 et 5) : une clé Ventoy n'était jamais reconnue,
  si bien que « Blanchir en gardant démarrable » n'était pas proposé. La partition `VTOYEFI` est en
  FAT16 ; usbsas lisait son étiquette aux octets 0x26..0x31 (signature de secteur étendu et numéro de
  série) au lieu de 0x2B..0x36.
- Correctif : lecture aux octets 0x2B..0x36 (même structure que FAT32, décalée de 0x1C).
- Test : `tests/proxmox/preuve.sh`, étape `ventoy` (choix « démarrable » affiché).

### 11. Réécriture d'une image officielle vérifiée (`usbsas-usbsas`, protocole)
- Besoin (17/11/2026) : une clé Etcher ou Rufus « mode DD » porte une image disque complète
  (ISO hybride). Le blanchiment classique la rend non démarrable ; sa zone de démarrage ne peut
  pas être analysée. Si l'image est une image **officielle** déclarée par l'administrateur (liste
  signée, la même que celle de l'analyseur), la remettre à l'identique est sûr.
- Correctif : requête `RewriteImage { id, sha256[], max_size }`, état `RewriteImageState` :
  1. lecture des secteurs de la clé (scsi2files) vers l'image de session (files2fs en mode
     brut, comme `ImgDisk`), avec une empreinte SHA-256 calculée au fil de la lecture et
     comparée à la liste à chaque frontière de 2048 octets (taille d'un bloc ISO 9660) ;
  2. **aucune correspondance** : erreur, rien n'est écrit sur la clé ;
  3. correspondance sur N octets : effacement complet (fs2dev), puis écriture des N premiers
     octets de l'image de session — exactement ceux qui ont été hachés — avec un vecteur de
     bits construit par usbsas.
- Limite : lecture bornée à `max_size` (16 Gio côté borne).
- Tests : `states.rs` (`image_reconnue_a_la_bonne_frontiere`, `bitvec_des_premiers_secteurs`),
  `parcours` (`liste_images_lue`).
