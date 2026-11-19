# AnimationBorne

> **v1, implémentée** dans `borne/client/src/anim.rs` et `dessin.rs` (formes SVG plates). La v2 garde ses courbes et ses durées ; voir les composants Anim* et `animations.md`.

Animations de la vie de la borne en dehors de l'analyse : démarrage, attente, clé de destination, copie, effacement, retrait, mise à jour hors ligne et support illisible. Elles complètent AnimationAnalyse et suivent le même dessin en relief.

| Moment | Ce qui bouge | Durée | Jeu |
| --- | --- | --- | --- |
| Démarrage | les deux tours puis la courtine montent du sol (décalage 150 ms), la herse se lève, « BARBACANE » apparaît | 2,2 s | une fois, pendant le lancement des 5 services |
| En attente | la clé fait un aller-retour de 10 px vers la porte, la flèche laiton s'allume | 2 s | en boucle |
| Clé de destination | la clé laiton glisse depuis la droite, un sceau vert confirme qu'elle est vierge | 900 ms | une fois |
| Copie | les fichiers (carrés `analyse`) traversent la porte à intervalles de 600 ms | 1,8 s par fichier | en boucle tant que la copie dure |
| Effacement | une barre `laiton` descend par paliers et efface le contenu | suit la progression réelle | en boucle par passe |
| Retrait | les deux clés repartent chacune de leur côté, la herse retombe | 1,5 s | une fois, puis accueil |
| Mise à jour hors ligne | le paquet descend, le sceau laiton apparaît après vérification de `maj.pub` | 1,2 s | une fois |
| Support illisible | la clé tremble 3 fois, le triangle `alerte` apparaît | 600 ms | une fois |

## Règles de mouvement

- **Durées** : 150 ms (retour d'un bouton), 300 ms (changement d'écran), 600 à 900 ms (arrivée d'un objet), 2,2 s au plus (démarrage).
- **Courbes** : `cubic-bezier(.5,0,.3,1)` pour ce qui arrive, `cubic-bezier(.7,0,.2,1)` pour la herse (lourde), linéaire pour ce qui tourne ou défile.
- **Couleurs** : le laiton bouge pour l'identité et la confiance (herse, clé de destination, signature) ; `analyse` pour le travail en cours ; les couleurs de verdict n'apparaissent qu'à la fin.
- **Une animation à la fois** au centre de l'écran. La jauge et le texte ne s'animent pas : ils se mettent à jour.
- **Changement d'écran** : l'ancien contenu glisse de 24 px vers la gauche en s'effaçant, le nouveau arrive de la droite, 300 ms. Pas de fondu au noir.
- **Sur la borne** : formes pleines uniquement, translations, échelles et rotation, 30 images/s maximum (iced + tiny-skia en rendu logiciel). Option « Animations réduites » dans l'administration : affiche l'état final.
