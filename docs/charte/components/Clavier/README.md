# Clavier

Clavier virtuel de la borne (`borne/client/src/keyboard.rs`) : le seul moyen de saisir, la borne n'accepte aucun clavier USB (protection BadUSB).

- Fond creusé (niveau −1), touches en blocs (niveau 2) de 56 px (`touche`) espacées de 8 px : 10 touches = 632 px, le clavier tient à 1280 × 768 sous le champ.
- Appui : la touche descend de 2 px et prend `laiton-pale` pendant 80 ms. C'est le seul retour : pas de son, pas de bulle agrandie (coûteuse à redessiner et inutile à cette taille).
- « Valider » est la seule touche principale (encre, tranche laiton).
- Pavé numérique pour le PIN : 3 colonnes de touches de 72 px, chiffres dans l'ordre du téléphone.
- Animations réduites : la touche change de couleur sans bouger.
