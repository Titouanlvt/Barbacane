# Barbacane

Charte graphique **v2** de Barbacane : la borne de décontamination (v1 hors ligne, v2 en ligne) et l'interface web du serveur de gestion. Une barbacane est l'ouvrage fortifié bâti devant une porte : tout ce qui veut entrer s'y arrête et s'y fait contrôler. La borne joue ce rôle pour les clés USB et les disques.

La v2 prolonge la v1 : même nom, mêmes couleurs, mêmes polices, même sérieux. Elle ajoute ce qui manquait pour un outil qu'on touche : **du relief** (on voit ce qui s'enfonce), **de la profondeur** (on voit ce qui est au-dessus), **des objets en volume** et **des animations qui racontent le travail de la borne**. Tout cela en restant dessinable par le processeur seul, à 30 images/s.

Sections de la charte :

- **Relief** (`relief.md`) : les cinq niveaux, leurs recettes exactes dans les deux thèmes, en CSS et en iced.
- **Animations** (`animations.md`) : principes, durées, courbes, et les huit animations clés avec storyboard, version réduite et réalisation.
- **Éléments 3D** (`3d.md`) : emblème, clé, disque, bouclier ; méthode de production et poids.
- **Réalisation** (`realisation.md`) : note pour les développeurs : ordre de mise en œuvre, coût de chaque effet en rendu logiciel, ce qu'il faut éviter.

## Principes

1. **Lisible à un mètre, au doigt.** Écran tactile, 1280 × 768 au minimum. Corps de texte 22 px, consignes 30 px, boutons de 64 px de haut (`cible`), aucune zone tactile sous 48 px (`cible-min`).
2. **Une seule chose à faire par écran.** Une consigne, une action principale (en bas à droite), au plus deux autres.
3. **L'état d'abord, par trois signaux.** Un verdict se dit par une couleur, une forme et un mot. La couleur n'est jamais seule.
4. **Le relief dit ce qu'on peut faire.** On écrit dans ce qui est creusé, on lit ce qui est posé, on appuie sur ce qui dépasse. Une seule lumière, en haut à gauche, pour toute l'interface et tous les objets.
5. **Le mouvement raconte, il ne décore pas.** Chaque animation montre un travail réel (une clé qui entre, des fichiers qu'on examine, une porte qui se ferme) et a une version immobile.
6. **Rien ne vient du réseau.** Polices, icônes, images et séquences sont embarquées dans le paquet ou servies par le serveur lui-même.

## Ce qui change entre v1 et v2

| Sujet | v1 | v2 | Pourquoi |
| --- | --- | --- | --- |
| Relief | aplats, tranche décalée, aucun dégradé | 5 niveaux : dégradé vertical léger, arête de lumière, tranche nette, ombre diffuse | Sur un écran tactile, il faut voir ce qui s'enfonce sans lire. Le dégradé reste faible (3 à 6 % de clarté) pour ne pas « faire plastique ». |
| Lumière | tranche en haut à droite (logo), en bas à droite (boutons) : incohérent | une seule lumière, en haut à gauche ; épaisseurs visibles en dessous | Les objets et les boutons semblent posés dans la même pièce. |
| Thèmes | « Pierre » et « Nuit » | **Jour** et **Nuit** (mêmes valeurs ; `PIERRE` devient `JOUR`) | Nom compris de tous dans l'écran Affichage. |
| Cibles | 72 px, souris | 64 px pour les actions, 48 px minimum partout | Écran tactile à 1280 × 768 : 72 px ne laissait pas la place au clavier et aux cartes de choix. |
| Objets | dessins plats en SVG | séquences 3D pré-calculées (PNG) | Le volume sans calcul 3D sur la borne. |
| Couleurs | 16 jetons | 40 jetons : surfaces de relief, lumière et ombres, teintes foncées des états, `hors-service` | Le relief a besoin de ses propres teintes ; les états de leur tranche. |
| Serveur web | — | tableaux, formulaires, tableau de bord, CSS seul | Même identité, très peu de JavaScript. |

## Voix et textes

- Vouvoiement, phrases courtes, verbe à l'impératif en tête : « Insérez la clé à analyser. »
- On nomme les objets comme l'utilisateur les voit : **clé à analyser**, **disque à analyser**, **clé de sortie** (clé enrôlée), **support** quand c'est l'un ou l'autre. Jamais « périphérique » ni « device ».
- Verdicts : un nombre et un fait. « 2 fichiers bloqués », pas « Attention ! Danger ! ».
- Erreurs : ce qui s'est passé, puis quoi faire. « Cette clé n'est pas lisible. Retirez-la et essayez une autre clé. »
- Signatures et chemins en mono, en `encre-douce`, sous le nom du fichier.
- Serveur web : mêmes règles ; libellés d'action = verbe + objet (« Enrôler une borne », « Révoquer le certificat »).

## Couleurs

Deux thèmes : **Jour** (par défaut, bureau éclairé) et **Nuit** (salle sombre). Mêmes rôles, mêmes noms ; tous les couples texte / fond déclarés sont vérifiés par `outils/jetons.py` (114 couples, AA dans les deux thèmes).

| Rôle | Jetons | Règle |
| --- | --- | --- |
| Sol (niveau 0) | `sol-haut` → `sol-bas`, `surface` | Fond de tout écran : dégradé vertical léger. `surface` en repli. |
| Creusé (−1) | `surface-creuse`, `ombre-interne` | Champs, pistes, listes. |
| Dalle (1) | `dalle-haut` → `dalle-bas`, `surface-haute`, `trait` | Cartes et panneaux. |
| Bloc (2) | `bloc-haut` → `bloc-bas`, `trait-fort` | Boutons et touches secondaires, tranche. |
| Lumière et ombre | `lumiere`, `ombre-contact`, `ombre-diffuse`, `voile` | Arête claire de 1 px, ombres, fond des confirmations. |
| Texte | `encre`, `encre-douce`, `sur-encre` | `encre` pour ce qui se lit d'abord. |
| Identité | `laiton`, `laiton-clair`, `laiton-fonce`, `laiton-pale` | Herse, focus, étape en cours, tranche du bouton principal. Moins de 5 % de l'écran. Jamais un état. |
| En cours | `analyse`, `analyse-fonce`, `analyse-fond` | Lecture, analyse, copie, gravure, attente du serveur. |
| Sain | `sain`, `sain-fonce`, `sain-fond` | Verdict sain. |
| Écarté | `alerte`, `alerte-fonce`, `alerte-fond` | Non analysable, erreurs récupérables. |
| Bloqué | `menace`, `menace-fonce`, `menace-fond` | Menace détectée, et le bouton d'effacement. Rien d'autre. |
| Hors service | `hors-service` | Serveur : borne injoignable. Toujours avec un cercle vide et un mot. |

Les teintes `*-fonce` servent de tranche et d'ombre aux aplats d'état ; elles ne portent jamais de texte.

## Typographie

| Famille | Usage | Pourquoi |
| --- | --- | --- |
| **Barlow Condensed** 600/700 | titres d'écran (48 px), verdicts (40 px), affiche (64 px), chiffres du tableau de bord | Condensée et droite, elle tient en une ligne à 1280 px et évoque la pierre gravée. |
| **Atkinson Hyperlegible** 400/700 | consignes (30 px), texte (22 px), boutons (22 px gras), web (15 px) | Conçue pour la basse vision : distingue `I l 1` et `O 0`, indispensable pour un PIN et un identifiant. |
| **JetBrains Mono** 400 | fichiers, signatures, empreintes, identifiants de borne | Les caractères ambigus sont distincts ; les colonnes s'alignent. |

Les fichiers TTF (licence OFL) sont dans `fonts/` et dans `borne/client/ressources/polices/`. Le serveur web les sert lui-même (`web/jetons.css` déclare les `@font-face`). Échelles complètes : jetons de type `Borne : écrans`, `Borne : texte`, `Technique`, `Serveur web`.

## Iconographie

- **Petites icônes** : Lucide (licence ISC), trait de 2 px, coins arrondis, grille de 24, embarquées en SVG (`borne/client/ressources/icones/`). Borne : 32 px ; web : 18 px. Ajouts v2 : `server`, `unplug` (serveur injoignable), `key-round` (PIN), `user-round` (identification), `flame` (gravure), `upload` (mise à jour).
- **Pastilles d'état** (borne, 56 à 72 px) : l'icône Lucide en `sur-encre` sur une pastille en relief (dégradé radial, tranche `*-fonce`). Cercle pour sain, écarté et en cours ; **octogone** pour bloqué.
- **Objets en volume** (120 à 300 px) : séquences pré-calculées, voir Éléments 3D.
- Jamais d'icône seule pour un état ou une action : toujours un mot à côté.

## Logo et emblème

- **Symbole plat** (`logos/barbacane-symbole*.svg`) : barre de titre, favicon, documents ; en dessous de 64 px.
- **Emblème en volume** (`3d/embleme-*.png`) : accueil, démarrage, verdict bloqué, hors service. La herse reste en laiton, même sur une menace : la couleur d'état est portée par le panneau, pas par l'emblème.
- Mot « BARBACANE » en Barlow Condensed 600, capitales, interlettrage +6 %.
- Interdits : ajouter une clé USB dans le symbole, recolorer la herse d'une couleur d'état, texture de pierre photographique, reflets « verre ».

## Parcours de la borne

Structure de chaque écran : bandeau (56 px, nom et site), étapes (48 px), contenu, pied (version, état du serveur en v2, Administration). Maquettes : groupes **Maquettes · borne** et **Maquettes · serveur** ; captures Jour et Nuit dans `maquettes/`.

0. **Démarrage** : l'emblème se construit (2,2 s), « Préparation de la borne… ».
1. **Accueil** : emblème en veille, « Insérez la clé ou le disque à analyser. »
2. **Identification** (v2, si le site l'exige) : identifiant au clavier, PIN au pavé.
3. **Analyse** : clé, barre vivante, compteurs sains / bloqués / écartés en direct, « Annuler l'analyse ».
4. **Résultat** : panneau de verdict, liste des fichiers bloqués, puis le choix : Copier vers une clé, Graver un disque, Blanchir cette clé, Arrêter ici.
5. **Sortie** : insertion de la clé de sortie (laiton) ou du disque vierge.
6. **Copie, gravure ou blanchiment**, puis « Retirez la clé ».

Hors parcours : support illisible (alerte), mise à jour hors ligne (administration), attente du serveur et hors service (v2).

## Serveur de gestion (web)

Même charte, densité de bureau : texte 15 px, boutons 40 px, tableaux 14 px. Une barre de navigation latérale en `bandeau` avec un liseré laiton, une page = un titre + une action principale en haut à droite. Charger `web/jetons.css` puis `components/bundle.css` : tous les composants fonctionnent sans JavaScript (tri et filtres par liens, validation côté serveur). Thème : attribut `data-theme="jour|nuit"` sur `<html>`, sinon préférence du système.

## Fichiers

| Chemin | Contenu |
| --- | --- |
| `tokens.json` | **Source unique** des jetons (format Design System). |
| `jetons.toml` | Jetons à plat pour le code Rust (généré). |
| `web/jetons.css` | Variables CSS et polices pour le serveur web (généré). |
| `components/bundle.css` | Relief et composants (borne en maquette, serveur en production). |
| `components/<Comp>/` | Fiche (`README.md`) et aperçu (`preview.html`) de chaque composant, animation et maquette. |
| `3d/` | Séquences PNG Jour et Nuit, `sequences.json`. |
| `logos/`, `fonts/` | Symbole plat et relief v1, polices. |
| `maquettes/` | Captures PNG des maquettes (borne et serveur), Jour et Nuit, 1280 px de large. |
| `outils/` | `jetons.py` (génération + contrastes), `sequences3d.py`, `aper_anims.py`, `aper_ecrans.py`, `captures.py`. |

Après toute modification de `tokens.json` : `python3 docs/charte/outils/jetons.py && python3 docs/charte/outils/sequences3d.py && python3 docs/charte/outils/captures.py`.
