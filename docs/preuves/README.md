# Preuves sur vraies clés USB

Preuves de bout en bout du 14/11/2026, produites par
[`tests/proxmox/preuve.sh`](../../tests/proxmox/preuve.sh) sur l'ISO de la borne, avec de vraies clés USB.
Verdict du script : **OK**.

| Élément | Valeur |
|---|---|
| Borne | VM Proxmox 910 « barbacane-borne », UEFI (OVMF), 16 Go de RAM, **sans carte réseau**, installée par l'ISO sans intervention |
| Pilotage | souris (tablette QMP) et lecture de l'écran par OCR ; aucun accès au système de la borne |
| Clé à analyser / à blanchir | SanDisk 3.2Gen1 16 Go (0781:5581, n° `03020611111524225725`), port USB 2 |
| Clé de destination enrôlée | SanDisk Ultra 64 Go (0781:5581), port USB 3 |
| Contenu de test | 4 fichiers sains (texte accentué, CSV, binaire aléatoire de 300 ko, sous-dossier avec espace) + `docs/eicar.com` (fichier de test antivirus EICAR) |

## 1. Transfert : clé inconnue → clé enrôlée

PIN choisi, clé de destination enrôlée, mode « clés enrôlées » activé
([capture](03-cle-enrolee.png)), puis transfert.

| Fichier | sha256 source | sha256 destination |
|---|---|---|
| `docs/donnees.csv` | `f6351f5e…c069587a` | **identique** |
| `docs/rapport.txt` | `64726956…0159db9b` | **identique** |
| `docs/sous dossier/note.txt` | `4007edc2…c9736cd2` | **identique** |
| `photos/image.bin` | `15f7a17b…cb400` | **identique** |
| `docs/eicar.com` | `275a021b…f651fd0f` | **absent** |

Listes complètes : [source](transfert/source.sha256), [destination](transfert/sortie.sha256).
Rapport écrit par la borne sur la clé : [texte](transfert/rapport-barbacane-20261114-180119.txt)
(« [REFUSÉ] docs/eicar.com — menace détectée par ClamAV : Eicar-Test-Signature »).

Étapes : [clé détectée](transfert/01-cle-detectee.png) →
[résultat de l'analyse : 1 menace](transfert/02-resultat-analyse.png) →
[clé de destination](transfert/03-cle-sortie.png) → [terminé](transfert/04-termine.png).

## 2. Blanchiment de la clé

| | Avant | Après |
|---|---|---|
| sha256 de la clé entière (15 376 000 000 octets) | `3d36855e…a1de66` | `de25ec12…1e69fc` |
| EICAR sur la clé (64 premiers Mo) | présent à l'octet 16 539 676 | **aucune trace** |
| Secteur 0 | amorce et table de partitions | remis à zéro |
| Fichiers sains | 4 | **4, sha256 identiques** ([avant](blanchiment/avant.sha256), [après](blanchiment/apres.sha256)) |

Extrait hexadécimal **avant** ([complet](blanchiment/cle-avant-eicar.hex)) :

```
00fc5ffc: b17c d9ab 5835 4f21 5025 4041 505b 345c  .|..X5O!P%@AP[4\
00fc600c: 505a 5835 3428 505e 2937 4343 2937 7d24  PZX54(P^)7CC)7}$
00fc601c: 4549 4341 522d 5354 414e 4441 5244 2d41  EICAR-STANDARD-A
```

Après : plus aucune occurrence ([offset](blanchiment/cle-apres-eicar-offset.txt) : « aucune »).
Secteurs 0 : [avant](blanchiment/cle-avant-secteur0.hex), [après](blanchiment/cle-apres-secteur0.hex).
Rapport de la borne : [texte](blanchiment/rapport-barbacane-20261114-180847.txt).

Étapes : [clé détectée](blanchiment/01-cle-detectee.png) →
[analyse](blanchiment/02-resultat-analyse.png) → [confirmation](blanchiment/03-confirmation.png) →
[terminé](blanchiment/04-termine.png). Pendant l'effacement, l'écran affiche la quantité, la
vitesse de la clé (16 Mo/s ici) et le temps restant.

## 3. Journal de la borne

[`borne/journal.log`](borne/journal.log), lu sur le disque de la VM éteinte :

```
18:01:19 clamd: instream(local): Eicar-Test-Signature(44d88612…:68) FOUND   (transfert)
18:08:47 clamd: instream(local): Eicar-Test-Signature(44d88612…:68) FOUND   (blanchiment)
```

## Défauts trouvés et corrigés pendant ces preuves

| Défaut | Correctif |
|---|---|
| Installation figée à 14 % (apt attendait la source « cdrom: ») | `systeme/iso/fin-installation.sh` : installation sans source apt |
| Boutons hors écran en 1280×800 : transfert impossible | écrans resserrés, test d'interface en 1280×768 |
| Blanchiment interrompu sur clé lente (« usbsas : bad request ») | délais USB alignés sur Linux (30 s), écart n°2 du noyau |
| Barre d'effacement presque immobile (45 min sur clé lente) | quantité, vitesse de la clé, temps restant, alerte « clé lente » |
| Numéro de série de 120 caractères débordant à l'écran | affichage abrégé |
| Emoji affichés en carré | icônes SVG de la charte |

Avec des clés bas de gamme (Phison 13fe:4200, 1 à 4 Mo/s), le transfert est passé, mais le
blanchiment a échoué deux fois avant le correctif des délais USB. Ce correctif n'a pas encore
été rejoué sur ces clés : à faire. Il faut compter plus d'une heure pour une clé de 7 Go.

## Rejouer

```shell
ISO=barbacane.iso SERIE_SOURCE=<n° clé à analyser> SERIE_SORTIE=<n° clé de destination> \
    tests/proxmox/preuve.sh        # REPRISE=1 : repart de l'instantané « installee »
```

Le script **efface entièrement** les deux clés. Il refuse tout disque qui n'est pas en USB, et ne touche qu'aux VM « barbacane-borne » d'ID 900 à 999.
