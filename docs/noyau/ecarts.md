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

### 2. `usbsas-scsi` : attente du statut SCSI portée de 15 s à 60 s
- Symptôme : blanchiment d'une clé lente (Phison 13fe:4200, ~4 Mo/s) interrompu après 27 min d'effacement :
  « timed out reading CSW, retrying (1/3) … (2/3) » puis « usb error during status stage: Operation timed out »,
  affiché « usbsas : bad request ». La clé reste effacée sans être réécrite.
- Cause : pendant les longues écritures, les clés bon marché marquent des pauses internes (vidage de cache,
  ramasse-miettes de la mémoire flash) de plus de 15 s ; usbsas n'attendait le CSW que 3 × 5 s
  (Linux attend 30 s par commande avant de réinitialiser).
- Correctif (`usbsas-scsi/src/lib.rs`) : `CSW_READ_ATTEMPTS` 3 → 12 (≈ 60 s). Aucune donnée n'est relue ni
  réécrite : on attend seulement plus longtemps le statut de la même commande.
