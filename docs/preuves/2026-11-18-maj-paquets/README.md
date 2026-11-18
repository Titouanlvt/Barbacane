# Mise à jour hors ligne contenant des paquets Debian (18/11/2026, VM 950)

Borne de DÉVELOPPEMENT installée depuis l'ISO signée par la clé de TEST du lab
(`~/cles-test` sur bu ; la clé de production n'est connue que de l'utilisateur), clés émulées.
Le paquet `barbacane-maj-202611180840.bcu` contient les trois paquets Barbacane
(révision 2611180939 > 1 installée) et rien d'autre.

`resultats.txt` : **18 OK, 0 échec** — correctif appliqué, rapport « Redémarrage nécessaire »,
**borne redémarrée sur les nouveaux binaires**, nouvel instantané, puis transfert complet OK.

## Ce que cette preuve a permis de trouver (tous corrigés le 18/11)
Avant le 18/11, aucune mise à jour avec paquets Debian n'avait été essayée (les paquets
« valides » des preuves précédentes ne contenaient que des signatures ClamAV).
1. `apt-get --no-download` sur un .deb local plus récent : `E: Internal Error, Pathname to install
   is not absolute` (reproduit sur bu avec un paquet factice).
2. Le `postinst` redémarrait admind, qui exécute apt : apt tué, écran `réponse invalide : EOF`.
3. apt sous le confinement d'admind (`ProtectKernelModules=yes`) : initramfs reconstruit SANS
   pilotes (25 Mo au lieu de 53, 4 modules, ni virtio_scsi ni sd_mod ni ext4) — **la borne ne
   redémarrait plus** (`avant-correction-ecran-noir.png`). Diagnostic sur le disque de la VM monté
   en lecture seule. Correction : apt et dpkg lancés par `systemd-run --wait` dans une unité à part ;
   admind reste confiné.
4. `build-debs.sh` laissait d'anciennes révisions dans l'ISO.
