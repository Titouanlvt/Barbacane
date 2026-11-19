# Relief

Cinq niveaux d'élévation, une seule lumière. Chaque niveau répond à une question de l'utilisateur : « est-ce que je peux écrire ici ? » (creusé), « est-ce que je peux appuyer ? » (bloc), « qu'est-ce qui est le plus important ? » (rempart).

## La lumière

Une source unique, **en haut, un peu à gauche** (élévation 45°, 30° à gauche de la verticale). Conséquences, pour tout l'écran et pour tous les objets 3D :

- le haut de chaque surface est plus clair que le bas (dégradé vertical de 3 à 6 % de clarté) ;
- l'arête haute reçoit un liseré de lumière de 1 px (`lumiere`) ;
- l'épaisseur d'un objet (sa **tranche**) se voit **en dessous** ;
- les ombres tombent vers le bas, sans décalage horizontal (sur l'écran, un décalage latéral coûte de la place sans rien dire).

Pourquoi pas de lumière de face ou de dessous : de face, le relief disparaît ; de dessous, les boutons paraissent creux et invitent moins à appuyer.

## Les cinq niveaux

| Niveau | Nom | Fond | Bord | Ombres (dans l'ordre) | Pour |
| --- | --- | --- | --- | --- | --- |
| −1 | **Creusé** | `surface-creuse` uni | 1 px `trait-fort` | intérieure haute 0 2 px 3 px `ombre-interne` ; arête basse intérieure 0 −1 px 0 `lumiere` | champs, pistes de barre, listes, fond du clavier, étapes à venir |
| 0 | **Sol** | dégradé `sol-haut` → `sol-bas` | — | — | fond d'écran |
| 1 | **Dalle** | dégradé `dalle-haut` → `dalle-bas` | 1 px `trait` | arête 0 1 px 0 `lumiere` (intérieure) ; contact 0 1 px 0 `ombre-contact` ; diffuse 0 2 px 6 px `ombre-diffuse` | cartes, panneaux, tableaux, tuiles |
| 2 | **Bloc** | dégradé `bloc-haut` → `bloc-bas` (ou celui de la variante) | 1 px `trait-fort` (ou variante) | arête ; **tranche nette 0 4 px 0** (couleur de la variante) ; diffuse 0 6 px 10 px | boutons, touches, cartes de choix, étape en cours |
| 2 enfoncé | | idem | idem | intérieure 0 2 px 3 px `ombre-interne` ; tranche 0 1 px 0 ; **déplacement de 3 px vers le bas** | retour d'appui, 80 ms |
| 3 | **Rempart** | dégradé `dalle-haut` → `dalle-bas` (verdict : `*-fond` éclairci → `*-fond`) | 1 px `trait` (verdict : 2 px couleur d'état) | arête ; **tranche 0 6 px 0** ; diffuse 0 14 px 24 px | panneau de verdict, fenêtre de confirmation, emblème |

Les valeurs exactes par thème sont dans `tokens.json`, famille `shadow` (`relief-creuse`, `relief-dalle`, `relief-bloc`, `relief-appuye`, `relief-rempart`).

### Teintes par thème

| Jeton | Jour | Nuit | Rôle |
| --- | --- | --- | --- |
| `sol-haut` / `sol-bas` | #f3f0ea / #e6e2d9 | #1a1e22 / #111316 | fond |
| `surface-creuse` | #e3dfd5 | #0d0f11 | creusé |
| `dalle-haut` / `dalle-bas` | #fcfbf8 / #f3f0ea | #262b30 / #1d2125 | dalle |
| `bloc-haut` / `bloc-bas` | #fdfcfa / #ebe7df | #30363c / #252a2f | bloc |
| `trait` / `trait-fort` | #cfc9bd / #7d7566 | #343a40 / #6b737b | bords, tranche neutre |
| `lumiere` | blanc 85 % | blanc 12 % | arête |
| `ombre-contact` | brun 28 % | noir 70 % | ombre courte |
| `ombre-diffuse` | brun 14 % | noir 50 % | ombre large |
| `ombre-interne` | brun 18 % | noir 65 % | creux |

Les ombres de Jour sont **brunes** (#2a2216), pas noires : sur un fond pierre, une ombre noire paraît sale. En Nuit, l'ombre se voit peu ; le niveau s'y lit surtout par la clarté (plus haut = plus clair) et par l'arête de lumière.

### Variantes de tranche

| Élément | Tranche |
| --- | --- |
| Bouton principal | `laiton-fonce` |
| Bouton secondaire, touche, carte de choix | `trait-fort` |
| Bouton danger, carte « Blanchir » | `menace-fonce` |
| Panneau sain / bloqué / écarté / en cours | `sain-fonce` / `menace-fonce` / `alerte-fonce` / `analyse-fonce` |
| Étape en cours | `laiton` |

## Règles

- La tranche nette (sans flou) est **réservée à ce qui s'enfonce** et au niveau 3. Une carte d'information n'en a pas : sinon l'utilisateur la touche pour rien.
- **Un seul niveau 3 par écran** (le verdict, ou la confirmation).
- Un élément ne monte pas de plus d'un niveau par rapport à son parent (pas de bloc sur un creusé sans dalle entre les deux), sauf les touches du clavier, posées dans leur bac.
- Le désactivé est **à plat** (aucun niveau) : ce qui ne s'enfonce pas n'a ni tranche ni ombre.
- Aucun relief sur le texte (pas d'ombre de texte) : il deviendrait flou en rendu logiciel et moins lisible.

## En CSS (serveur web, maquettes)

Classes de `components/bundle.css` : `.b-creuse`, `.b-sol`, `.b-dalle`, `.b-bloc`, `.b-rempart`, et les composants qui les reprennent (`.b-btn`, `.b-carte`, `.b-saisie`, `.b-verdict`…). La tranche d'une variante se change par la variable `--tranche`.

## Dans la borne (iced 0.14, rendu tiny-skia)

iced ne dessine qu'**une ombre par conteneur** et **aucune ombre intérieure**. Chaque niveau se compose donc de couches empilées (`stack!`), comme la tranche des boutons v1 (`app::bouton`) :

| Effet | Réalisation iced | Coût (voir realisation.md) |
| --- | --- | --- |
| Dégradé vertical | `Background::Gradient(Gradient::Linear(Linear::new(Radians(PI)).add_stop(0.0, haut).add_stop(1.0, bas)))` | faible |
| Arête de lumière | 1er arrêt du dégradé : `add_stop(0.0, lumiere_sur_haut)`, `add_stop(1.5 / hauteur, haut)` | nul (même dégradé) |
| Tranche nette | conteneur plein de la couleur de tranche, même rayon, décalé de 4 px vers le bas, **derrière** | très faible |
| Ombre diffuse | `Shadow { color, offset: Vector::new(0.0, 6.0), blur_radius: 10.0 }` sur le conteneur de la tranche | moyen (calcul par pixel) : voir les règles de coût |
| Ombre intérieure (creusé) | dégradé de 3 arrêts : `ombre_interne` à 0, `surface_creuse` à `4 / hauteur`, `surface_creuse` à 1 | faible |
| Enfoncé | translation de 3 px du bloc (`padding` haut + 3, bas − 3), tranche réduite à 1 px | nul |

Les couleurs translucides (`lumiere`, ombres) se calculent **une fois** par thème en couleur opaque mélangée sur leur fond (fonction `melange` de `style.rs`) : tiny-skia mélange plus vite une couleur opaque.
