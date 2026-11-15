# Preuves : ce qui marche, ce qui ne marche pas, ce qui n'a pas pu être testé

Campagne du 15/11/2026, sur une borne installée **depuis une vraie clé USB** avec l'ISO
`3189c66596521a81baaf0edaff1ebeeecdc95d0fed5cc08cedb0306dbd1c4259` (commit `a003c80`),
pilotée uniquement par l'écran (souris QMP + OCR), produite par
[`tests/proxmox/preuve.sh`](../../tests/proxmox/preuve.sh) (commit `43242b3`).
Résultat : **53 vérifications OK, aucun échec** ([resultats.txt](resultats.txt), [contexte](contexte.txt)).

| Élément | Valeur |
|---|---|
| Borne | VM Proxmox 920 « barbacane-borne », UEFI, **8 Go de RAM**, disque 32 Go, **sans carte réseau** |
| Installation | ISO copiée par `dd` sur la clé SanDisk Ultra 64 Go, VM démarrée dessus, aucune question ([installation/](installation/)) |
| Clé à analyser / à blanchir | SanDisk 3.2Gen1 16 Go, n° `03020611111524225725` (vraie clé) |
| Clé de destination enrôlée | SanDisk Ultra 64 Go, n° de 120 caractères (vraie clé) |
| Clé « autre » (non enrôlée, hostiles, mise à jour) | **clé USB émulée** (usb-storage QEMU sur une image de 4 Go) : la troisième vraie clé (Phison) n'était plus disponible |
| Contenu de test | 4 fichiers sains, `eicar.com`, EICAR déguisé en `.jpg`, archives : mixte, imbriquée, chiffrée (mot de passe « secret »), noms piégés (`../`, absolu, contrôle, 300 caractères) |

## Ce qui marche (avec la preuve)

| Fonction | Preuve |
|---|---|
| Installation automatique hors ligne depuis une clé USB, interface affichée | [installation/](installation/) (01-installateur, 02-premier-ecran, `vm.conf` sans réseau) |
| GRUB : Échap tenu n'ouvre pas le menu ; `grub.cfg` verrouillé (superutilisateur, entrée par défaut `--unrestricted`) | [grub/](grub/), [journal/grub-cfg-extrait.txt](journal/) |
| PIN : premier PIN, mauvais PIN refusé avec essais restants, bon PIN accepté | [pin/](pin/) |
| Enrôlement : la clé figure dans la liste, mode « seules ces clés » activé | [enrolement/](enrolement/) |
| Transfert clé → clé : EICAR (et `.jpg` déguisé) bloqués, 4 sains identiques (sha256), témoin de la destination effacé | [transfert/](transfert/) : `source.sha256`, `sortie.sha256`, rapport |
| Archives : mot de passe demandé au clavier virtuel, archive chiffrée copiée, de l'archive mixte seul le sain est extrait, noms piégés jamais écrits | [transfert/02b-mot-de-passe.png](transfert/), `sortie.sha256` |
| Clé non enrôlée refusée en sortie, et **rien n'y est écrit** | [transfert/03-cle-non-enrolee-refusee.png](transfert/), `non-enrolee-avant/apres.sha256` |
| Blanchiment : empreinte de la clé entière modifiée, aucune trace d'EICAR sur les 16 Go, sains réécrits identiques | [blanchiment/](blanchiment/) |
| Export des journaux et rapports (JSON, détections EICAR) | [export/](export/) |
| Mises à jour signées : valide appliquée (version vérifiée au journal), autre clé refusée, version plus ancienne refusée | [maj/](maj/), [journal/](journal/) |
| Clavier USB branché : aucune frappe ni combinaison n'a d'effet | [clavier/](clavier/) |
| Clés hostiles : vide, pleine (17 fichiers), illisible, retirée pendant la lecture : message, aucune copie, borne de nouveau utilisable | [vide/](vide/), [pleine/](pleine/), [illisible/](illisible/), [retrait/](retrait/) |
| 5 mauvais PIN : administration verrouillée, même le bon PIN refusé | [verrouillage/](verrouillage/) |
| Garde-fou Proxmox : scripts et paquets refusent un hôte (`/etc/pve`) | [garde-fou/](garde-fou/) (VM 902) et CI |
| Bac à sable des archives sous systemd (autotest au démarrage) | `tests/iso/qemu.sh` (CI et VM 903) |

## Défauts trouvés et corrigés pendant la campagne
- **Toutes les archives étaient refusées sur la borne installée** (jamais de demande de mot de passe) :
  bubblewrap bloqué par le durcissement systemd (`AF_NETLINK`, `RestrictSUIDSGID`, montage de
  `/proc`). Corrigé (`dd506a8`, `a003c80`), autotest au démarrage contrôlé en CI.
- Faux positifs du **script de test** corrigés, chacun prouvé ensuite : enrôlement jamais vérifié
  (« ACTIVÉ » lu dans « désactivé »), clic sur un mot de titre au lieu du bouton, clé éjectée par la
  borne relue « sans support » par l'hôte, version de mise à jour illisible par OCR (zéros barrés).
  Les « OK [enrolement] » des preuves antérieures (14/11) n'étaient pas fondés.

## Ce qui ne marche pas
- Rien de connu sur les fonctions ci-dessus à la date de la campagne.

## Ce qui n'a pas pu être testé, et pourquoi
| Point | Raison |
|---|---|
| Clé lente Phison 13fe:4200 (blanchiment long) | clé absente du lab le 15/11 |
| Clé « autre » réelle | remplacée par une clé USB émulée (QEMU) : même chemin logiciel côté borne, pas le même matériel |
| Poste physique (BIOS, écran tactile, ports USB réels de la borne) | tests en VM Proxmox ; les clés USB sont de vraies clés passées à la VM |
| Image mkosi | jamais construite (l'ISO est la seule méthode d'installation) |

## Disques optiques
Voir [optique/](optique/) (section complétée en fin de campagne optique).

Archives : [2026-11-14-premiere/](2026-11-14-premiere/) (premières preuves, dont l'enrôlement
non vérifié).
