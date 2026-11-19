# Formulaire

Formulaires de l'interface web : une carte (niveau 1), une colonne de 560 px au plus, champs (niveau −1) avec étiquette au-dessus et aide en dessous, actions en bas à droite (principal à droite, Annuler en lien discret à gauche).

- Validation côté serveur : la page revient avec `.b-champ--erreur` et le message ; aucun JavaScript requis.
- Les actions soumises à double validation (révocation massive, baisse de politique, quarantaine) l'annoncent avant l'envoi par un avis `alerte`.
- Les actions destructives utilisent `b-btn--danger` et une page de confirmation qui reprend l'objet par son nom.
