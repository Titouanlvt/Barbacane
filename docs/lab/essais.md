# Pool ZFS « essais » (lab, 19/11/2026)

Disque dédié aux tests, ajouté dans le Dell Precision 5820 (hôte Proxmox du lab).

| | |
|---|---|
| Modèle | WDC PC SN730 SDBQNTY-256G-1001 |
| Série | 20041A804255 |
| Taille | 256 060 514 304 octets (256,06 Go) |
| Chemin (seul à utiliser) | `/dev/disk/by-id/nvme-WDC_PC_SN730_SDBQNTY-256G-1001_20041A804255` |

Le nom `/dev/nvmeXnY` peut changer d'un démarrage à l'autre : ne jamais l'utiliser.

## Vérifications faites avant écriture
- modèle, série et taille lus dans `/sys/block/*/device` et `blockdev` : identiques à ci-dessus ;
- table GPT **vide** (aucune partition, `sgdisk -p`), seules signatures `gpt`/`PMBR` (`wipefs -n`) ;
- aucun pool ZFS (`zpool status`, `zpool import`), pas un volume physique LVM (`pvs`), rien de monté.

## Création
Instantané de l'hôte : `rpool/ROOT/pve-1@avant-pool-essais-20261119-1825`.

```shell
zpool create -o ashift=12 -o autotrim=on -O compression=lz4 -O atime=off -O mountpoint=/essais \
    essais /dev/disk/by-id/nvme-WDC_PC_SN730_SDBQNTY-256G-1001_20041A804255
zfs create essais/vm        # disques des VM de test
zfs create essais/fichiers  # ISO, clés émulées, images
pvesm add zfspool essais --pool essais/vm --content images,rootdir --sparse 1
pvesm add dir essais-fichiers --path /essais/fichiers --content iso,import,snippets --is_mountpoint yes
```

## Usage
- Disques des **nouvelles** VM de test : stockage `essais` (`STOCKAGE=essais`).
- ISO, clés émulées, images de contenu : `/essais/fichiers/` (stockage `essais-fichiers`).
- Rien de gros dans `rpool` ni `/var/lib/vz` (incident du 17/11 : rpool plein → pmxcfs en lecture seule).
- Jamais touchés : SSD système (rpool), pool `nvme` existant, ancien NVMe (pool « ancien », lecture seule).

## Retour arrière
`pvesm remove essais-fichiers; pvesm remove essais; zpool destroy essais` (le disque redevient vierge).
