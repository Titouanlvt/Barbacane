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
- Correctif : délai de transfert 5 s → 30 s (`usbsas-mass-storage/src/lib.rs`) et
  `CSW_READ_ATTEMPTS` 3 → 2 (`usbsas-scsi/src/lib.rs`), soit 60 s d'attente du statut.
  Aucune donnée n'est relue ni réécrite : on attend seulement plus longtemps la même commande.
