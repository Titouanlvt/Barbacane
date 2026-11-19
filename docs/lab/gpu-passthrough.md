# Passthrough de la RTX 4000 — diagnostic (19/11/2026) : NON RÉALISÉ

Exception accordée par l'utilisateur : activer une fois le passthrough de la NVIDIA RTX 4000 de l'hôte,
**sauf** si la carte partage son groupe IOMMU avec un autre périphérique ou si elle est la seule carte
d'affichage de l'hôte. Diagnostic fait **sans rien modifier** (journal brut : `logs/gpu-diagnostic.txt`).

| Point | Constat |
|---|---|
| CPU | Intel Core i7-7820X (VT-x, VT-d présent : tables DMAR, 4 unités de remappage) |
| Démarrage | UEFI, GRUB via `proxmox-boot-tool` ; ligne de commande sans `intel_iommu` |
| Carte | `65:00.0` Quadro RTX 4000 [10de:1eb1], `65:00.1` audio, `65:00.2` USB 3.1, `65:00.3` UCSI USB-C |
| Groupe IOMMU | groupe 2 = les 4 fonctions de la carte, rien d'autre (acceptable) |
| Affichage de l'hôte | **seule carte VGA de la machine**, `boot_vga=1`, pilote `nouveau`, console de l'hôte dessus (`/dev/fb0`, `card0`) |

**Décision : pas de passthrough.** La RTX 4000 est la seule carte d'affichage de l'hôte : la confier à
vfio-pci retirerait toute console locale au Proxmox (dépannage impossible sans réseau), cas exclu par
la consigne. Aucune modification faite (ni ligne de commande du noyau, ni modules, ni vfio) ; pas de
redémarrage.

## Ce qui permettrait de le faire plus tard
- Ajouter une seconde carte graphique (même modeste) pour la console de l'hôte, la déclarer carte de
  démarrage dans le BIOS, puis reprendre la procédure : instantané `avant-gpu`, `intel_iommu=on iommu=pt`,
  modules `vfio vfio_iommu_type1 vfio_pci`, `vfio-pci ids=10de:1eb1,10de:10f8`, un redémarrage,
  contrôles SSH / 8006 / VM, retour arrière par `zfs rollback` de `avant-gpu` en cas de problème.

## Conséquences pour le projet
- Rendus 3D pré-calculés (Blender/Cycles) : en CPU dans une VM de travail (plus lent, même résultat).
- Mesure de l'interface avec un vrai GPU (wgpu) : non faite ; la borne reste en rendu logiciel
  (tiny-skia), qui est la cible. Le GPU reste optionnel et détecté automatiquement côté code.
