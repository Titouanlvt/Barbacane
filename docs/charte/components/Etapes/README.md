# Etapes

Bandeau d'étapes en haut de chaque écran du parcours (`view_etapes`), 48 px de haut.

- À venir : creusées (niveau −1), numéro cerclé, `encre-douce`.
- Faites : à plat, coche sur pastille `encre`.
- En cours : la seule qui ressort (bloc `laiton-pale`, tranche `laiton`, texte gras). On voit d'un coup d'œil où l'on est sans lire.
- Non cliquable : la borne impose l'ordre. `aria-current="step"` sur l'étape en cours.
- Passage à l'étape suivante : l'étape en cours « remonte » (tranche 0 → 3 px, 150 ms) pendant que la précédente se pose.
