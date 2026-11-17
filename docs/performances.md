# Performances : mesures et cible de 4 To

Mesures du 17/11/2026, lab Proxmox : borne virtuelle (3 cœurs, 8 Go de RAM, disque sur NVMe),
clés USB **réelles** passées à la VM au niveau USB (SanDisk 3.2 Gen1 16 Go en source, SanDisk
Ultra 64 Go en destination). Aucune mesure n'a été faite sur un vrai SSD externe NVMe ni sur
une borne physique : voir « Ce qui n'a pas été testé ».

## Mesures

| Contenu (clé réelle) | Taille | Fichiers (avec archives) | Analyse + écriture |
|---|---|---|---|
| Clé de 5,6 Go (zip, tar, iso, gros textes) | 4,9 Go | 27 | analyse 16 min 30 s ; blanchiment (effacement de 16 Go + écriture) 21 min 30 s |
| Rufus NTFS (ISO Windows/Linux, `install.wim`) | 6,3 Go | ≈ 75 600 | 20 à 23 min |
| Rufus FAT32 (ISO Linux) | 0,9 Go | plusieurs dizaines de milliers | 32 à 37 min |
| Etcher (ISO Linux) | 0,75 Go | idem | 20 à 34 min |
| Bureau (Office, PDF, archives, ISO) | 0,8 Go | quelques centaines | 36 à 38 min |
| Ventoy (ISO Debian + ISO piégée) | 0,77 Go | ≈ 1 500 | 22 min |

Débits déduits :
- effacement complet de la clé source : 16 Go en ≈ 13 min 30 s, soit **≈ 19 Mo/s** (limite de la
  clé, pas de la borne) ;
- écriture des fichiers sains : ≈ 10 Mo/s sur la même clé ;
- analyse de gros fichiers peu nombreux : ≈ 5 Mo/s de bout en bout (lecture USB, archive de session,
  envoi à l'analyseur, ClamAV + YARA), sur 3 cœurs virtuels.

**Ce qui coûte le plus n'est pas la taille, c'est le nombre de fichiers** : une ISO Linux de 0,9 Go
(des dizaines de milliers de petits fichiers ouverts et analysés un par un) prend plus de temps
qu'une clé de 6,3 Go faite de quelques gros fichiers. L'analyse traite aujourd'hui les fichiers
**un par un** ; la paralléliser sur les cœurs de la borne est la prochaine amélioration (à mesurer).

## Cible théorique : SSD interne de 4 To, disque externe NVMe de 2 à 4 To (boîtier USB)

Ce qui est prêt :
- **aucun chargement complet en mémoire** : les fichiers passent par l'espace de travail chiffré
  sur disque (`docs/conception-espace-travail.md`) ; la RAM ne limite plus la taille (5,6 Go
  analysés avec 8 Go de RAM, 6 Go de tmpfs avant le 16/11 échouaient) ;
- **tailles sur 64 bits** partout (usbsas, analyseur, parcours) ; lecture des disques de plus de
  2 Tio par les commandes SCSI READ(16) ;
- **progression et temps restant** affichés pendant la lecture, l'analyse et l'écriture ;
- **refus clair avant de commencer** si 3 × le contenu dépasse l'espace de travail.

Ce qui limite aujourd'hui (et réglages) :
| Limite | Valeur | Effet pour 4 To |
|---|---|---|
| Contenu analysé par session (`limits.max_total_size`, `analyzer.toml`) | 32 Gio | **à relever** pour une telle borne |
| Nombre de fichiers (`limits.max_files`) | 200 000 | à relever pour un disque de sauvegarde |
| Espace de travail | 50 % du disque, 3 × le contenu | SSD 4 To → ≈ 1,9 To d'espace, **≈ 620 Go de contenu par session** |
| Table de partitions écrite (MBR) | 2 Tio | un disque de destination de plus de 2 Tio n'est utilisé que sur 2 Tio |
| Boîtiers « UAS seul » | non pris en charge | usbsas ne parle que le Bulk-Only ; la plupart des boîtiers NVMe l'offrent aussi |

Extrapolation (hypothèses, non mesurées) : un boîtier NVMe en USB 3.2 Gen 2 lit à 800 Mo/s à
1 Go/s ; la chaîne actuelle (lecture, archive de session, copie à l'analyseur, ClamAV) ne
dépassera pas quelques dizaines à une ou deux centaines de Mo/s sur une borne de 4 à 8 cœurs, car
ClamAV et l'écriture de l'archive de session sont séquentielles. Pour 620 Go de gros fichiers à
100 Mo/s : ≈ 1 h 45 d'analyse ; à 20 Mo/s : ≈ 9 h. Pour des millions de petits fichiers, c'est le
nombre de fichiers qui décide (≈ 30 à 50 fichiers par seconde mesurés sur les ISO Linux).

Conclusion : une borne à 4 To peut **lire** un disque de 2 à 4 To, mais l'analyse d'un tel disque
entier en une session est hors de portée aujourd'hui (espace de travail, plafonds, durée). Le
fonctionnement réaliste est de copier par lots de quelques centaines de Go.

## Ce qui n'a pas été testé

- Aucun disque de plus de 64 Go : ni 2 To ni 4 To (pas de matériel dans le lab).
- Aucun boîtier NVMe USB, ni UAS.
- Aucune borne physique pour ces mesures (VM, cœurs partagés avec d'autres tests en parallèle :
  les durées ci-dessus sont pessimistes).
