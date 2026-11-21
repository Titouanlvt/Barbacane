# Image mkosi : première construction et premier démarrage (16/11/2026)

- Construite sur la VM de construction (Debian 13, mkosi 25.3) : `systeme/build-debs.sh` puis
  `mkosi -f build` dans `systeme/mkosi/` → `barbacane.raw.zst` (462 Mo, disque de 1,7 Go).
- Corrections nécessaires pour aboutir : `reprepro` (outil de mkosi, sur la machine de construction),
  paquet `systemd-boot-efi` dans l'image (stub de l'image noyau unifiée), configuration de la borne
  exécutée DANS l'image (`configurer.chroot`, le script de l'ISO déposé par `ExtraTrees`),
  `Environment` dans `[Build]`.
- Démarrée dans une VM Proxmox UEFI **sans carte réseau** (930, [vm.conf](vm.conf)) : l'interface
  s'affiche ([01-premier-ecran.png](01-premier-ecran.png)).
- Démarrage verrouillé (vérifié dans la partition EFI de l'image) : `loader.conf` = `timeout 0`,
  `editor no`, `auto-entries no`, `auto-firmware no` (pas d'édition de la ligne du noyau, même rôle
  que le mot de passe GRUB de l'ISO).

Limites connues : l'image ne contient pas de base ClamAV (l'écran le signale ; la déposer dans
`mkosi.extra/var/lib/clamav/` ou l'apporter par une mise à jour signée) ; la partition racine
(1,2 Go) n'est pas agrandie au premier démarrage. **L'ISO reste la méthode d'installation
prouvée** ; l'image mkosi n'a pas fait l'objet de la campagne complète sur vraies clés.
