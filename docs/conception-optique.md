# Conception : disques optiques réinscriptibles (CD-RW, DVD±RW, BD-RE)

Statut : conception du 15/11/2026, implémentation en cours (voir l'état à la fin).

## Objectif
Le lecteur optique de la borne devient une source et une destination comme les clés USB :

| Direction | Déroulement |
|---|---|
| Disque → clé USB | le disque est une source **inconnue** : toutes les sessions sont lues, analysées (ClamAV + YARA, archives), les fichiers sains sont copiés sur une clé de destination (enrôlée si le mode est actif) |
| Clé USB → disque | la clé inconnue est analysée comme aujourd'hui ; les fichiers sains sont gravés sur un disque réinscriptible, puis relus et comparés (sha256) |
| Disque → disque | lecture et analyse du disque, puis « retirez le disque, insérez le disque de destination » (lecteur unique), gravure différée, relecture |
| Blanchiment du disque | lecture et analyse ; effacement **complet** ; relecture prouvant que rien n'est lisible ; gravure des seuls fichiers sains ; relecture |

## Choix principaux
1. **Pas de modification d'usbsas** (aucun écart au noyau). usbsas sait déjà lire un **dossier local**
   déclaré dans `[[src_local_dirs]]` ; c'est ainsi que la borne écrit le dossier de préparation
   sur la clé de destination. Le disque est donc d'abord **extrait** dans un dossier local
   (`/var/lib/barbacane/optique/entree`), puis ce dossier suit exactement le parcours d'une clé
   inconnue : mêmes règles, même analyseur, même rapport. La sortie optique grave le dossier de
   préparation (`/var/lib/barbacane/sortie`), déjà rempli des seuls fichiers sains par l'analyseur.
2. **Service séparé `barbacane-optique`** (Rust, crate `borne/optique`) : utilisateur dédié
   `barbacane-optique` (groupe `cdrom`), socket Unix locale, journal. Il pilote `xorriso`
   (libburn/libisofs), seul outil, pour l'identification, la lecture, l'effacement et la gravure.
3. **Lecture sans le noyau** : jamais de `mount` du disque (le système de fichiers d'un disque
   hostile est analysé par du code du noyau, en root). `xorriso` lit ISO 9660, Joliet, Rock Ridge
   en espace utilisateur, dans un bac à sable ; l'UDF (DVD, BD) est lu par `7z`, déjà employé
   par l'analyseur, dans le même type de bac à sable.
4. **Toutes les sessions** : la table des sessions (`-toc`) est lue, puis **chaque** session est
   extraite dans `entree/session-N/` (`-load sbsector N`). Une session ancienne, masquée par la
   dernière, est donc analysée aussi.
5. **Vitesse sûre** : la plus basse vitesse d'écriture annoncée à la fois par le lecteur et le
   disque (`-list_speeds`, « Write speed L »), jamais la maximale.
6. **Effacement complet** : `-blank all` (tout le disque est réécrit), jamais `-blank fast`
   (qui n'efface que la table des matières : les données restent lisibles). Vérification :
   le disque est annoncé vierge, **et** une lecture brute de secteurs répartis sur toute la
   surface ne renvoie aucune donnée. Pour un DVD+RW / BD-RE (pas d'état « vierge »),
   l'effacement complet est un formatage complet suivi d'un remplissage de zéros vérifié.
7. **Vérification après gravure** : le disque gravé est relu par le même chemin que l'entrée
   (extraction confinée), et chaque fichier est comparé (sha256) au dossier de préparation.

## Menaces et parades
| Menace | Parade |
|---|---|
| Système de fichiers piégé (ISO/UDF malformé) | lecture en espace utilisateur (xorriso, 7z) dans bubblewrap : aucun réseau, système en lecture seule, seul le lecteur visible, limites mémoire/CPU/taille ; jamais de `mount` |
| Données cachées dans une ancienne session | toutes les sessions extraites et analysées |
| Noms piégés (`..`, absolus, contrôle) | extraction dans un dossier vide, refus des chemins sortants ; puis contrôle usbsas habituel |
| Bombe (taille, nombre de fichiers) | limites de l'analyseur ; taille d'extraction bornée (`RLIMIT_FSIZE`) et espace du dossier d'entrée |
| CD audio, disque illisible, disque vide | refus propre avec un message (aucune session de données) |
| Effacement incomplet (fast blank) | jamais proposé ; vérification par relecture |
| Disque non réinscriptible (CD-R, DVD-R, BD-R) | refusé en destination et au blanchiment, message clair |
| Disque retiré, plein, échec d'écriture | erreur affichée, aucune donnée considérée comme écrite ; la vérification par relecture échoue sinon |
| Service compromis | utilisateur dédié, `NoNewPrivileges`, `ProtectSystem=strict`, pas de réseau (`IPAddressDeny=any`), seuls `/dev/sr*` et `/dev/sg*` du lecteur autorisés (`DevicePolicy=closed`) |

## Limites connues
- **CD-RW** : réinscriptible ; effacement complet lent (proportionnel à la capacité).
  **DVD-RW** : effacement complet possible (`blank all`) ; **DVD+RW, BD-RE** : pas d'effacement
  au sens strict, un formatage complet puis une écriture de zéros sur toute la surface en tient lieu.
- Un disque gravé en multisession par la borne n'est jamais produit : chaque gravure part
  d'un disque entièrement effacé, en une seule session fermée.
- Disque → disque avec un seul lecteur : les fichiers sains restent dans le dossier de
  préparation pendant l'échange de disque (effacés à la fin comme aujourd'hui).
- Tests : la lecture est testée sur des images ISO construites par les tests (multisession,
  Joliet, Rock Ridge, EICAR caché dans une ancienne session) ; gravure et effacement ne
  peuvent être prouvés que sur le matériel réel (lecteur MATSHITA UJ8E2Q, CD-RW du lab).

## Lab Proxmox
Le lecteur est sur le contrôleur SATA 0000:00:17.0, **le même que le SSD système** : aucun
passthrough PCI. La VM borne reçoit le lecteur au niveau SCSI (`scsi-generic` sur `/dev/sg1`
derrière un `virtio-scsi`), ce qui laisse passer les commandes de gravure.
