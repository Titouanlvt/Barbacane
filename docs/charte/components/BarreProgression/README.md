# BarreProgression

Piste creusée (niveau −1), remplissage en relief (dégradé `analyse`, arête claire), rayures `analyse-fonce` qui défilent, tête `laiton` qui pulse. Implémentée en v1 (`borne/client/src/barre.rs`) ; la v2 ajoute la piste creusée et le dégradé du remplissage.

Signes de vie, indépendants de l'avancement : rayures (un motif par 900 ms), tête (1 200 ms), chronomètre à la seconde. Si le pourcentage n'a pas bougé depuis 30 s : avis « Ce fichier est volumineux… la borne n'est pas bloquée ».

Durée inconnue : variante navette (bloc de 30 % en aller-retour, 1 600 ms).

Rendu logiciel : rayures = rectangles pleins décalés (pas de dégradé répété), dans une zone découpée ; seule la barre (≈ 900 × 24 px) est redessinée à chaque image. Animations réduites : ni rayures ni pulsation, le chronomètre continue.
