# Verdict

Panneau de niveau 3 (rempart) : fond `*-fond` éclairé en haut, bord 2 px et tranche 6 px dans la couleur d'état, pastille en relief avec l'icône. C'est le seul élément de l'écran à ce niveau.

| Verdict | Couleur | Forme de la pastille | Mot |
| --- | --- | --- | --- |
| Sain | `sain` | cercle, bouclier coché | « Clé saine » |
| Bloqué | `menace` | octogone, croix | « N fichiers bloqués » |
| Écarté | `alerte` | cercle, triangle | « N fichiers écartés » |
| En cours | `analyse` | cercle, anneau ouvert | « Analyse en cours » |

Trois signaux redondants (couleur, forme, mot) : le verdict se comprend en daltonisme, en noir et blanc et de loin. Le titre donne un nombre et un fait ; le texte dit ce qui arrive aux fichiers.

Sous le panneau, la liste (niveau −1) montre d'abord les fichiers bloqués, puis les écartés, avec la raison en mono. Les fichiers sains ne sont listés que sur demande.

Animation d'arrivée : voir AnimSain et AnimBloque.
