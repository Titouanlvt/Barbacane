# Bouton

Trois variantes, 72 px de haut minimum (`cible-min`), texte en Atkinson Hyperlegible 700 à 24 px, en relief comme le logo : une tranche pleine décalée de 6 px vers le bas à droite.

- **Principal** : fond `encre`, tranche `laiton`. Un seul par écran, en bas à droite.
- **Secondaire** : fond `surface-haute`, contour `encre`, tranche `trait`. « Annuler », « Retour ».
- **Destructif** : fond `menace`, tranche `encre`. Uniquement pour effacer une clé.

Libellé = verbe + objet (« Copier vers la clé de destination »), jamais « OK » ou « Valider ».

## Animations

| État | Mouvement | Durée |
| --- | --- | --- |
| Survol | le bouton se soulève de 2 px, la tranche s'allonge à 8 px | 120 ms |
| Appui | le bouton s'enfonce de 6 px, la tranche disparaît | 60 ms à l'appui, 120 ms au relâché |
| Focus clavier | anneau `laiton` 4 px, décalé de 6 px | immédiat |
| En cours | trois créneaux qui montent tour à tour + « Préparation… » ; le bouton ne répond plus | en boucle, 900 ms |
| Désactivé | à plat, sans tranche, `encre-douce` sur `surface` | — |
| Terminé | fond `sain`, la coche se trace | 500 ms, une fois |
| Maintenir pour confirmer | un voile `encre` remplit le bouton de gauche à droite ; relâcher avant la fin annule | 2 s |

## Règles

- **Le retour d'appui arrive en moins de 100 ms**, même si l'action prend du temps : le bouton s'enfonce tout de suite, puis passe en « En cours ». L'utilisateur ne doit jamais cliquer deux fois.
- **Un clic passe en « En cours » si l'action dure plus de 300 ms.** Sinon, l'écran suivant arrive directement.
- **Effacer une clé** se fait par « Maintenir pour effacer » (2 s), pas par un double écran de confirmation : plus rapide, et impossible à déclencher par erreur avec la souris.
- **Pas de survol sur écran tactile** : l'appui suffit.
- **Sur la borne** (iced) : le relief est un second rectangle plein décalé, l'appui est une translation du bouton. Pas d'ombre floue.
- **Animations réduites** : changements de couleur sans déplacement ; le maintien de 2 s reste, avec un compte à rebours en texte (« 2… 1… »).
