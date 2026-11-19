# Animations

## Principes

1. **Le mouvement raconte un travail réel.** Une clé entre, des fichiers passent sous un faisceau, une porte se ferme. Pas d'animation d'agrément, pas de logo qui tourne pendant un verdict.
2. **L'information n'attend jamais l'animation.** Le titre, le nombre de fichiers et les boutons sont présents dès la première image ; l'animation les accompagne. Un bouton est actif au plus tard à 600 ms.
3. **Une seule animation au centre à la fois.** Les signes de vie (barre, compteur) peuvent tourner à côté.
4. **Ce qui boucle suit un travail en cours ; le reste joue une fois puis s'arrête.** Un verdict ne clignote pas : c'est un fait, pas une alarme.
5. **Chaque animation a sa version réduite** (option « Animations réduites » de la borne, `prefers-reduced-motion` sur le web) : l'état final, sans mouvement. Les compteurs de temps et les barres de progression, qui sont de l'information, continuent d'avancer.
6. **Dessinable par le processeur** : translations, échelles, rotation d'images pré-calculées, changements de couleur par paliers. Ni flou animé, ni fondu en transparence, ni 3D en temps réel (voir realisation.md).

## Durées et courbes

| Jeton | Valeur | Usage |
| --- | --- | --- |
| `duree-appui` | 80 ms | le bouton ou la touche s'enfonce |
| `duree-courte` | 150 ms | relâché, survol, couleur |
| `duree-ecran` | 300 ms | changement d'écran : glissement de 24 px (`anim::arrivee`) |
| `duree-objet` | 600 ms | arrivée d'un objet (clé, bouclier, panneau) |
| `duree-scene` | 900 ms | verdict complet |
| `duree-boucle` | 1 600 ms | un aller du faisceau |
| `duree-demarrage` | 2 200 ms | construction de l'emblème |

| Courbe | Valeur | Sens | Fonction de `anim.rs` |
| --- | --- | --- | --- |
| `courbe-arrivee` | cubic-bezier(.5,0,.3,1) | ce qui arrive et se pose | `ease_bezier` |
| `courbe-sortie` | cubic-bezier(.4,0,1,1) | ce qui s'en va | à ajouter : `p³` (accélération cubique) |
| `courbe-lourde` | cubic-bezier(.7,0,.2,1) | la herse | `herse` |
| `courbe-ressort` | cubic-bezier(.3,1.45,.5,1) | bouclier, sceau : dépasse puis revient | `echelle_bouclier`, `echelle_sceau` |
| `courbe-lineaire` | linear | rotation, défilement | `balayage` (aller-retour) |

Cadence : 30 images/s pendant une animation, 15 images/s pour la veille de l'accueil, 1 image/s au repos (règle déjà en place dans `app.rs`, cadence de rafraîchissement).

## Les huit animations clés

Chaque animation a un aperçu interactif (groupe **Animations**, case « Version réduite ») et la fiche ci-dessous. Les séquences 3D sont décrites dans `3d.md`.

### 1. Insertion d'une clé (AnimInsertion)

| Temps | Ce qui se passe |
| --- | --- |
| 0 – 600 ms | La clé arrive de la gauche (`courbe-arrivee`, 330 px) en pivotant de 62° vers la porte : bande `cle`, 16 images. |
| 600 – 750 ms | Elle s'enfonce de 16 px. |
| 750 ms | Le voyant sous la porte passe de `trait-fort` à `laiton-clair` : la borne a reconnu la clé. |
| 750 – 1 050 ms | « Clé détectée » arrive de 24 px à droite. |

Réduite : clé en place, voyant allumé, texte affiché. Clé de sortie : même scène avec la bande `cle-destination` (laiton). Disque : le tiroir rentre (translation), puis le disque tourne une fois (bande `disque`).

Logiciel : une image de la bande + une translation par trame, zone redessinée ≈ 520 × 200 px.

### 2. Analyse en cours (AnimAnalyse)

| Temps | Ce qui se passe |
| --- | --- |
| boucle 1 600 ms | Le faisceau `analyse` descend puis remonte sur la pile de fichiers (`anim::balayage`). |
| boucle 6 s | Parallaxe : les lignes de fichiers, au plan arrière, défilent vers le haut à 32 px/s. |
| boucle 900 / 1 200 ms | Barre : rayures, tête laiton (BarreProgression). |
| à chaque fichier | Le compteur sains / bloqués / écartés et le nom du fichier changent. |

Réduite : pas de faisceau ni de défilement ; barre et compteurs avancent.

Logiciel : trois couches dans une fenêtre découpée de 300 × 190 px (lignes translatées, faisceau = rectangle), plus la barre. Les lignes sont des rectangles pleins, pas du texte.

### 3. Verdict sain (AnimSain)

| Temps | Ce qui se passe |
| --- | --- |
| 0 – 420 ms | Le bouclier pivote de la tranche vers la face (bande `bouclier`, 14 images) et passe de 60 % à 108 % puis 100 % (`echelle_bouclier`). |
| 430 – 1 220 ms | Deux ondes (anneaux pleins de 6 px) s'élargissent de ×0,7 à ×1,7, la seconde 280 ms après la première, et changent de couleur par paliers `sain` → `sain-fond` → fond. |
| 600 – 900 ms | Le panneau « Clé saine » monte de 24 px et se pose (niveau 3). |

Réduite : bouclier de face, panneau, pas d'onde.

Logiciel : les ondes sont des anneaux SVG pré-tramés à 3 tailles (pas de mise à l'échelle par trame) ; aucun fondu, la couleur change par palier.

### 4. Verdict bloqué (AnimBloque)

| Temps | Ce qui se passe |
| --- | --- |
| 0 – 540 ms | La herse tombe (bande `embleme-herse`, 16 images ; courbe lourde déjà cuite dans les images). |
| 540 – 970 ms | L'emblème tremble : ±4 px amorti, 3 allers-retours (`anim::herse`, 2e valeur). **L'écran ne bouge pas.** |
| 600 – 900 ms | Le panneau « N fichiers bloqués » descend de 24 px (octogone, `menace`, mot). |

Réduite : herse fermée, panneau. Pas de son, pas de clignotement : le rouge, l'octogone et le mot suffisent ; une alarme pousserait l'utilisateur à retirer la clé en pleine écriture.

Logiciel : une image + une translation, ≈ 220 × 220 px pendant 1 s, puis plus rien.

### 5. Blanchiment (AnimBlanchiment)

| Temps | Ce qui se passe |
| --- | --- |
| par sixième du travail | Une lame `laiton` descend d'un palier sur la clé. |
| derrière la lame | La clé blanchie (bande `cle-blanche`) apparaît à travers une fenêtre qui grandit : ce qui est effacé change de matière. |
| en continu | Barre : octets écrits, vitesse, temps restant (`mesure.rs`). |
| fin | La lame disparaît, « Blanchiment terminé », puis réécriture des fichiers sains (AnimAnalyse). |

Réduite : pas de lame ; la fenêtre suit la progression.

Logiciel : deux images fixes et une fenêtre de découpage (`dessin.rs` sait déjà découper un calque) ; redessin seulement au changement de palier. Le blanchiment d'une clé lente dure 45 min : l'animation ne doit rien coûter entre deux paliers.

### 6. Gravure d'un disque (AnimGravure)

| Temps | Ce qui se passe |
| --- | --- |
| boucle 600 ms | Le disque tourne : bande `disque`, 18 images = un demi-tour (reflets symétriques). |
| avancement réel | L'anneau gravé (`analyse-fonce`) s'élargit du centre vers le bord ; la tête laser le suit. |
| fin | Le disque s'arrête, anneau plein, « Gravure terminée. Le tiroir va s'ouvrir. » |

Réduite : disque immobile ; anneau et tête suivent la progression.

Logiciel : une image + deux ellipses pleines + un rectangle, ≈ 240 × 160 px. Remplace le `disque(angle)` v1 qui régénère un SVG à chaque angle.

### 7. Erreur (AnimErreur)

| Temps | Ce qui se passe |
| --- | --- |
| 300 – 660 ms | La clé tremble 3 fois (±6 px amorti) : un « non » de la tête. |
| 600 – 900 ms | Le triangle d'alerte apparaît (0 → 115 % → 100 %, `echelle_sceau`). |
| texte | Ce qui s'est passé, puis quoi faire. Le code d'erreur va dans le journal, pas à l'écran. |

Couleur `alerte`, jamais `menace` : une clé illisible n'est pas une menace. Réduite : clé immobile, triangle affiché.

### 8. Attente du serveur, v2 en ligne (AnimAttenteServeur)

| Temps | Ce qui se passe |
| --- | --- |
| boucle 1 200 ms | Trois créneaux s'allument de bas en haut, un toutes les 400 ms (`analyse`). |
| délai de grâce | Une barre se **vide** (5 min par défaut, plancher signé), temps restant écrit : « la session en cours se termine normalement ». |
| serveur revenu | Créneaux allumés fixes 300 ms, puis accueil (glissement). |
| délai écoulé | Écran « Borne hors service » (maquette EcranHorsService) : herse fermée, fixe, aucune boucle. |

Réduite : créneaux allumés fixes ; le décompte continue.

Logiciel : trois rectangles qui changent de couleur, ≈ 14 × 80 px redessinés : quasi gratuit, ce qui compte pour un état qui peut durer des heures.

## Autres mouvements

- **Démarrage** : bande `embleme-construction` (32 images, 15 i/s, 2,2 s) pendant le lancement des services, puis « Préparation de la borne… ».
- **Accueil en veille** : bande `embleme-pivot` en aller-retour à 15 i/s ; après 2 min sans toucher, l'emblème s'arrête de face (économie de processeur), reprise au premier toucher ou à l'insertion.
- **Changement d'écran** : l'ancien contenu sort de 24 px vers la gauche, le nouveau arrive de 24 px à droite, 300 ms, sans fondu.
- **Boutons, touches** : voir Bouton et Clavier.

## Animations v1 déjà en place

Les composants AnimationAnalyse et AnimationBorne (v1) décrivent ce que `anim.rs` et `dessin.rs` font aujourd'hui (formes SVG plates). La v2 garde leurs courbes et leurs durées et remplace progressivement les calques SVG par les séquences 3D.
