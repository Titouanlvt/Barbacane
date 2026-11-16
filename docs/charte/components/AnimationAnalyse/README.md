# AnimationAnalyse

Animations des quatre moments de l'analyse, toutes tirées du château : la clé avance vers la porte, un faisceau balaie les fichiers, le bouclier apparaît si tout est sain, la herse tombe sur une menace.

| Moment | Animation | Durée | Courbe |
| --- | --- | --- | --- |
| Clé détectée | la clé glisse de 60 px vers la droite | 600 ms, une fois | `cubic-bezier(.5,0,.3,1)` |
| Analyse | faisceau `analyse` qui balaie de haut en bas + jauge | en boucle, 1,6 s aller | `ease-in-out` |
| CD-ROM inséré | le tiroir remonte avec le disque, 40 px | 600 ms, une fois | `cubic-bezier(.5,0,.3,1)` |
| Lecture CD-ROM | le disque tourne (1 tour / 1,2 s) et la tête laser va du bord vers le centre | en boucle | linéaire / `ease-in-out` |
| Sain | bouclier 60 % → 108 % → 100 % | 500 ms, une fois | `ease-out` |
| Menace | herse qui tombe puis léger tremblement | 700 ms, une fois | `cubic-bezier(.7,0,.2,1)` |

Règles :
- Seules les animations d'analyse tournent en boucle. Les verdicts jouent une fois puis restent fixes.
- Une animation ne retarde jamais une information : le titre et le nombre de fichiers s'affichent tout de suite.
- Sur la borne (iced + tiny-skia, rendu logiciel), animez uniquement des translations, des échelles et la rotation du disque de formes pleines, à 30 images/s maximum. Pas de flou ni de transparence animée.
- Avec `prefers-reduced-motion` (ou l'option de la borne « Animations réduites »), on affiche l'état final directement.
