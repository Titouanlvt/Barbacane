# Tableau

Tableau de l'interface web (bornes, utilisateurs, clés enrôlées, rapports, audit). Dalle (niveau 1) ; en-tête creusé (niveau −1) en `encre-douce` gras ; lignes séparées par `trait` ; chiffres en `tabular-nums`, alignés à droite (`.num`).

- Survol : `laiton-pale` à 45 %. Ligne sélectionnée : `laiton-pale` + liseré `laiton` à gauche, `aria-selected="true"`.
- Identifiants (borne, empreinte, numéro de série) en mono.
- État : composant Etat (couleur + forme + mot). Pas d'icône seule.
- Large : le cadre défile horizontalement (`overflow-x: auto`), la page jamais.
- Tri et filtres : formulaires GET classiques (lien d'en-tête `?tri=etat`), sans JavaScript.
