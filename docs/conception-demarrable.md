# Clés démarrables : conception

Demande du 17/11/2026 : analyser une clé démarrable (Ventoy, Rufus, balenaEtcher) puis la
blanchir **sans la rendre inutilisable** : elle doit rester démarrable.

## Principe imposé

On ne fait **jamais** confiance à la partie démarrage d'une clé entrante (MBR, chargeur, partition
EFI, zones hors partitions). Une clé qui reste démarrable est **reconstruite** à partir d'une
source de confiance ; rien de sa zone de démarrage d'origine n'est recopié.

## Menaces

| Menace | Où elle se cache | Réponse |
|---|---|---|
| Bootkit (MBR, VBR, `core.img`) | secteurs 0 à 2047, début des partitions | jamais recopié ; zone réécrite depuis la borne ou effacée |
| Chargeur EFI piégé (`BOOTX64.EFI`, `grubx64.efi`) | partition EFI | partition EFI reconstruite (Ventoy) ou image officielle vérifiée (Rufus/Etcher) |
| Données cachées hors partitions | espace non alloué, fin de clé | effacement complet de la clé avant réécriture |
| ISO piégée | fichiers `.iso/.img/.wim/.vhd` portés par la clé | contenu analysé récursivement (bac à sable 7-Zip existant) ; image refusée si un seul fichier est menaçant |
| Greffon Ventoy malveillant (`ventoy/ventoy.json`, injections, `ventoy_grub.cfg`) | partition de données | dossier `ventoy/` **jamais recopié** (il peut injecter des fichiers dans l'OS démarré) |
| ISO trop grosse pour l'antivirus | fichiers de plus de 2 Go | conteneur ouvert, chaque fichier analysé ; conteneur conservé seulement si tout est sain |
| Image officielle falsifiée | clé Rufus/Etcher | empreinte comparée à une liste blanche signée ; sinon blanchiment classique |

## Détection (lecture seule, avant toute décision)

Faite dans le noyau usbsas (lecture de la table de partitions, `usbsas-dev2scsi`) et rapportée à
l'interface :

- **Ventoy** : 2 partitions, la 2ᵉ (32 Mo, FAT) étiquetée `VTOYEFI`, la 1re (exFAT/NTFS/FAT) porte les
  images ; table MBR ou GPT.
- **Image Rufus « mode DD » / Etcher** : signature ISO 9660 (`CD001` à l'octet 0x8001) au début du
  périphérique (ISO hybride, écart n° 7), ou image disque (GPT avec partition EFI + données).
- **Rufus « mode ISO »** : une partition FAT32/NTFS contenant `efi/boot/` ou `bootmgr`, parfois une
  petite partition `UEFI_NTFS`.
- **Clé classique** : tout le reste.

La zone de démarrage n'est **pas** analysée comme sûre : le rapport indique « partie démarrage :
non vérifiable (elle sera reconstruite ou effacée) ».

## Blanchiment « démarrable »

### Ventoy : reconstruction

1. Analyse habituelle de tous les fichiers ; les images (`.iso .img .wim .vhd(x) .efi`) sont
   ouvertes et analysées récursivement ; une image n'est conservée que si **tout** son contenu
   est sain. Le dossier `ventoy/` (configuration, greffons) n'est jamais conservé.
2. Effacement complet de la clé (comme le blanchiment actuel).
3. La borne compose une **image disque complète** dans son espace de travail chiffré :
   - secteurs 0 à 2047 : code de démarrage de Ventoy (`boot.img`, `core.img`) issu de la version
     **embarquée** ;
   - partition 1 (exFAT, type 0x07, du secteur 2048 à la fin moins 32 Mo) : système de fichiers
     écrit par usbsas (`files2fs`) avec les seules images saines ;
   - partition 2 (`VTOYEFI`, 32 Mo, type 0xEF) : `ventoy.disk.img` de la version embarquée.
4. Cette image est écrite sur la clé par usbsas (`fs2dev`, comme toute écriture).

Ventoy embarqué : archive officielle `ventoy-X.Y.Z-linux.tar.gz`, empreinte SHA-256 **épinglée dans
le dépôt** (relue en revue de code) et vérifiée à la construction de l'ISO ; la borne n'en change
que par un paquet de mise à jour **signé** (minisign, comme les autres mises à jour). Limite
honnête : Ventoy ne publie pas de signature cryptographique de ses archives, seulement des
empreintes ; la confiance repose donc sur l'empreinte épinglée et sur la signature de nos paquets.

### Image Rufus / Etcher : réécriture d'une image officielle vérifiée

1. Lecture brute de la clé (`ImgDisk`, déjà dans usbsas).
2. Comparaison de l'empreinte des N premiers octets à la **liste blanche** (nom, taille N,
   SHA-256), fournie par l'administrateur dans un paquet de mise à jour signé.
3. Correspondance : effacement complet, puis réécriture des N octets lus (ce sont exactement
   les octets de l'image officielle, prouvé par l'empreinte). Les fichiers de l'image sont de
   toute façon analysés et le rapport l'indique.
4. Pas de correspondance : blanchiment classique (la clé n'est plus démarrable), avec
   l'explication « image inconnue : la partie démarrage ne peut pas être vérifiée ».

### Rufus « mode ISO » et autres clés démarrables inconnues

Pas de source de confiance pour leur chargeur : blanchiment classique, fichiers sains recopiés,
explication à l'écran et dans le rapport. Alternative la plus sûre proposée : recréer la clé avec
Ventoy (la borne copie l'ISO saine sur une clé Ventoy reconstruite).

## Écart au noyau usbsas nécessaire

usbsas sait lire une clé secteur par secteur (`ImgDisk`) mais pas écrire une image arbitraire :
nouvelle requête « écrire une image disque » (`fs2dev` sur une image fournie par la borne, avec
les mêmes contrôles : périphérique choisi, taille, progression). Documentée comme écart n° 9.

## Limites

- Démarrage vérifié en VM (OVMF/UEFI et SeaBIOS) ; le Secure Boot de Ventoy (clé MOK à enrôler)
  dépend du poste cible, comme avec un Ventoy installé normalement.
- Taille : l'image composée est creuse ; l'espace de travail doit contenir les images conservées.
- Les clés Ventoy en mode GPT sont reconstruites en MBR (le mode par défaut de Ventoy).
