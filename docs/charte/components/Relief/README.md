# Relief

Cinq niveaux d'élévation, éclairés par une seule lumière (en haut, un peu à gauche). Chaque niveau dit ce qu'on peut faire de l'objet : on écrit dans ce qui est creusé, on lit ce qui est posé, on appuie sur ce qui dépasse.

| Niveau | Nom | Pour | Classe |
| --- | --- | --- | --- |
| −1 | Creusé | champs, piste des barres, listes, fond du clavier | `.b-creuse` |
| 0 | Sol | fond d'écran | `.b-sol` |
| 1 | Dalle | cartes, panneaux, tableaux | `.b-dalle`, `.b-carte` |
| 2 | Bloc | boutons, touches, cartes de choix | `.b-bloc`, `.b-btn`, `.b-touche`, `.b-choix` |
| 3 | Rempart | panneau de verdict, fenêtre de confirmation, emblème | `.b-rempart`, `.b-verdict` |

Recettes exactes (ombres, dégradés, arête de lumière) dans les deux thèmes, traduction iced et coût en rendu logiciel : section **Relief** (`relief.md`).

Règles :
- **La tranche nette (ombre sans flou) est réservée à ce qui s'enfonce** (niveaux 2 et 3). Une carte qui n'est pas cliquable n'en a pas.
- Un niveau 3 par écran au plus.
- En Nuit, l'ombre se voit mal : le niveau se lit surtout par la clarté de la surface et par l'arête de lumière.
