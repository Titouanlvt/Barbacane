# TableauDeBord

Page d'accueil de l'interface web (supervision). Le résumé d'abord, le détail ensuite.

1. **Tuiles** (niveau 1) : un chiffre en Barlow Condensed 40 px et un état (composant Etat). Le liseré du haut prend la couleur d'état ; une tuile à zéro reste neutre.
2. **Ce qui demande une action** : bornes injoignables, menaces, signatures anciennes, certificats proches de l'échéance, enrôlements en attente de validation.
3. **Tableau des bornes**, puis graphiques.

Graphiques : SVG produits par le serveur (pas de bibliothèque JavaScript), couleurs de la palette, un seul axe, chaque barre annotée par son titre. Rafraîchissement : rechargement de la page (`<meta http-equiv="refresh" content="60">` ou lien « Actualiser ») ; aucune animation, sauf l'état « en cours » qui reste fixe.
