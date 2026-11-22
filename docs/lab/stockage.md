# Stockage du lab Proxmox (22/11/2026)

| Pool | Disques (toujours désignés par `/dev/disk/by-id/…`) | Taille | Usage |
|---|---|---|---|
| `rpool` | disque système de l'hôte | 109 Go | système Proxmox seulement (`local-zfs` vide) |
| `nvme` | `nvme-2650_Micron_256GB_2523509303FF` + `nvme-2650_Micron_256GB_252350930419`, agrégat **sans redondance** | 476 Go | Barbacane : disques de bu (902) et de la borne 950, `/nvme/contenu`, `/nvme/correctifs`, `/nvme/virt` |
| `clautilde` | `nvme-WDC_PC_SN730_SDBQNTY-256G-1001_20041A804255` | 238 Go | Clautilde (infra LLC) : stockages `clautilde` (VM, CT) et `clautilde-iso` (ISO, modèles, sauvegardes) |

- La panne d'un des deux Micron perd tout le pool `nvme` : le code est sur GitHub ; `/travail` (bu) n'est qu'un
  espace de construction et de cache.
- Historique : le pool `essais` (WDC, 19/11) a été retiré le 22/11 ; le disque `/travail` de bu a été déplacé sur
  `nvme` (`qm disk move`), puis le WDC réattribué à Clautilde. Instantanés de l'hôte :
  `@avant-retrait-essais-20261122-1601`, `@avant-disques-20261122-1638`, `@avant-reseau-clautilde-*`.
- La borne 950 n'a plus d'instantanés « installee » : « propre » est refait depuis l'état installé courant.
