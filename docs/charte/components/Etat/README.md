# Etat

Pastille d'état pour les tableaux et listes (surtout le serveur web). Chaque état a une couleur ET une forme ET un mot :

| État | Couleur | Forme |
| --- | --- | --- |
| En service, sain | `sain` | disque plein |
| En cours, mise à jour | `analyse` | disque plein |
| Alerte (signatures anciennes, certificat proche de l'échéance) | `alerte` | triangle |
| Menace, bloqué | `menace` | losange |
| Injoignable, hors service | `hors-service` | cercle vide |

Le mot est toujours écrit. Pas d'animation (un tableau de 100 bornes qui clignote ne se lit plus).
