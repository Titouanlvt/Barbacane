# BarreProgression

Barre de progression de l'analyse, de la copie et de l'effacement. Elle bouge **toujours**, même quand le pourcentage reste bloqué sur un gros fichier : l'utilisateur doit voir que la borne travaille et n'est pas figée.

Trois signes de vie, indépendants de l'avancement :

1. **Rayures qui défilent** dans la partie remplie (`analyse` sur `analyse-fond`), un motif par 0,9 s, en continu.
2. **Tête laiton** au bout de la barre, qui pulse toutes les 1,2 s.
3. **Chronomètre** qui avance chaque seconde (« 6 min 02 s »), en mono, à côté du compteur de fichiers.

Le nom du fichier en cours s'affiche dessous et change dès que l'analyse passe au suivant.

## Fichier long

Si le pourcentage n'a pas bougé depuis **30 s**, afficher sous la barre un bandeau `laiton-pale` avec un point qui pulse : « Ce fichier est volumineux (4,2 Go). L'analyse continue, la borne n'est pas bloquée. » Il disparaît dès que la barre avance.

## Durée inconnue

Quand on ne connaît pas encore le total (lecture de la clé, inventaire des fichiers), on utilise la variante **navette** : un bloc de 30 % fait des allers-retours en 1,6 s. Pas de pourcentage, seulement « … » et le chronomètre.

## Sur la borne

- Les rayures se dessinent comme des bandes pleines qu'on décale (translation), sans dégradé : compatible tiny-skia.
- Mettre à jour le pourcentage au plus 4 fois par seconde, et ne jamais le faire reculer.
- L'animation tourne dans le fil de l'interface, séparé de l'analyse : si l'interface se fige, c'est un vrai blocage, et l'administrateur doit le voir.
- Avec « Animations réduites » : pas de rayures ni de pulsation, mais le chronomètre continue d'avancer.
