# Objets3D

Les objets en volume de Barbacane : l'emblème (porte fortifiée), la clé USB, le disque optique, le bouclier. Ils sont **pré-calculés** en bandes d'images PNG (une image carrée de 240 px à la suite de l'autre) : la borne ne fait que copier une image à l'écran, ce qui coûte quelques dixièmes de milliseconde en rendu logiciel, alors qu'un rendu 3D en temps réel est hors de portée sans carte graphique.

| Séquence | Images | Cadence | Usage |
| --- | --- | --- | --- |
| `embleme-pivot` | 24 | 15 i/s, aller-retour | accueil en veille |
| `embleme-construction` | 32 | 15 i/s, une fois | démarrage |
| `embleme-herse` | 16 | 30 i/s | verdict bloqué |
| `cle` | 16 | 30 i/s | insertion de la clé à analyser |
| `cle-destination` | 16 | 30 i/s | insertion de la clé de sortie (laiton) |
| `cle-blanche` | 1 | — | blanchiment (révélée par une fenêtre) |
| `bouclier` | 14 | 30 i/s | verdict sain |
| `disque` | 18 | 30 i/s, boucle | lecture et gravure |

Fichiers : `3d/<séquence>-<jour|nuit>.png` et `3d/sequences.json` (côté, nombre d'images, cadence, poids). Méthode de production, passage à Blender et budget de poids : section **Éléments 3D** (`3d.md`).

Règles :
- Une seule lumière, la même que celle des ombres de l'interface (en haut à gauche) : objets et boutons semblent posés dans la même pièce.
- La herse reste en laiton, même sur une menace : la couleur d'état est portée par le panneau, pas par l'emblème (règle du logo v1).
- La clé de destination est en laiton, la clé à analyser en pierre : on distingue la clé de confiance avant même de lire.
- Pas de rotation continue de l'emblème hors de la veille : l'objet décoratif ne doit pas concurrencer le verdict.
