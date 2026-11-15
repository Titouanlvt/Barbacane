# Test « depuis zéro » du guide (`docs/guide-installation-poste.md`)

15/11/2026, VM 903 (Debian 13 vierge, connectée à Internet, root) : les commandes de l'**étape 1**
du guide ont été exécutées telles quelles ([zero-guide.log](zero-guide.log), la phrase de passe
de test y est masquée) :

| Commande du guide | Résultat |
|---|---|
| `apt-get install -y git minisign` puis `git clone` (branche `main`, commit `3357709`) | OK |
| `borne/update/barbacane-update-keygen` puis copie de `maj.pub` | OK |
| `systeme/iso/build-iso.sh --sortie barbacane.iso` | OK en **8 min 44** ; sha256 `19a8cf2178587b06…` |

L'ISO ainsi produite a ensuite été installée sans aucune intervention dans une VM UEFI
(`tests/iso/qemu.sh`, ISO branchée comme une clé USB) : [qemu.log](qemu.log) — services
`barbacane-analyzer`, `barbacane-admind`, `barbacane-kiosk`, `usbsas-server`, `clamav-daemon` OK,
bac à sable des archives fonctionnel, GRUB verrouillé, interface affichée ([ecran.png](ecran.png)).

Étapes 2 à 5 (copie sur une vraie clé, BIOS, installation, premier PIN) : prouvées par la campagne
du 15/11 sur VM Proxmox démarrée sur la vraie clé ([../installation/](../installation/)). Le BIOS
d'un vrai poste n'a pas pu être testé (lab en VM).
