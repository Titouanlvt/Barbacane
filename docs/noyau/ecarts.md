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
- Correctif : la source `LocalDir` suit les mêmes règles qu'une source USB (selon la destination).
- Test : `tests/proxmox/optique.sh`, étape `image` (EICAR caché dans la 1re session du disque bloqué,
  fichiers sains copiés). Spécifique à l'usage de Barbacane ; proposable au CEA (option de configuration).
