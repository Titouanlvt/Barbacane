# Bouton

Bloc de niveau 2 : dégradé du haut vers le bas, arête de lumière de 1 px, tranche nette dessous. On appuie dessus et il s'enfonce.

| Variante | Fond (haut → bas) | Texte | Tranche | Usage |
| --- | --- | --- | --- | --- |
| Principal | `encre-haut` → `encre-bas` | `sur-encre` | `laiton-fonce` | L'action qui fait avancer. Un seul par écran, en bas à droite. |
| Secondaire | `bloc-haut` → `bloc-bas` | `encre` | `trait-fort` | Annuler, Retour, Exporter. |
| Danger | `menace` éclairci → `menace` | `sur-encre` | `menace-fonce` | Blanchir, Révoquer. Toujours suivi d'une confirmation. |
| Discret | transparent | `encre-douce` | aucune | Liens d'action secondaires (web). |

| État | Rendu | Durée |
| --- | --- | --- |
| Survol (web) | luminosité +4 % | 150 ms |
| Appuyé | descend de 3 px, tranche 4 → 1 px, ombre intérieure | 80 ms à l'appui, 150 ms au relâché |
| Désactivé | à plat (`surface-haute`), bord `trait`, texte `encre-douce`, sans tranche ni ombre | — |
| En cours (`aria-busy`) | trois créneaux qui montent tour à tour, clic ignoré | boucle 900 ms |
| Focus | anneau `laiton` 3 px, décalé de 3 px | — |

Tailles : borne 64 px (`cible`), texte 22 px gras ; web 40 px, texte 15 px. Jamais sous 48 px sur la borne (`cible-min`).

Pourquoi : la v1 posait la tranche derrière un aplat ; la v2 ajoute le dégradé et l'arête, qui font lire le bouton comme un objet sans ajouter de couleur. Le désactivé est plat : ce qui ne s'enfonce pas n'a pas de tranche.

Borne (iced) : voir `realisation.md`, recette « Bloc ». Web : `<button class="b-btn b-btn--principal">`.
