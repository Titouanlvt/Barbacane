# Verdict

Bandeau d'état en haut de l'écran d'analyse et de résultat : icône 44 px, titre en Barlow Condensed 700, détail en Atkinson 18 px.

Quatre états, chacun avec sa couleur, son fond et une icône de forme différente :

| État | Jetons | Icône |
| --- | --- | --- |
| En cours | `analyse` / `analyse-fond` | cercle ouvert (tourne) |
| Sain | `sain` / `sain-fond` | bouclier coché |
| Écarté | `alerte` / `alerte-fond` | triangle |
| Menace | `menace` / `menace-fond` | octogone barré |

Le titre donne un nombre et un fait. Le détail dit ce qui a été fait des fichiers. Un seul bandeau à la fois : s'il y a menace et fichiers écartés, la menace l'emporte et les écartés apparaissent dans la liste.
