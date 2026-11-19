# Réalisation

Note pour les développeurs de la borne (`borne/client`, iced 0.14 en rendu tiny-skia sous cage/pixman) et de l'interface web du serveur.

## Le budget

- **30 images/s = 33 ms par image**, mais la borne analyse en même temps : ClamAV et YARA occupent jusqu'à 4 fils pendant l'analyse. Visez **20 ms au 95e centile** pour une image d'animation, et moins de **25 % d'un cœur** pour le processus `barbacane-client` pendant une animation qui boucle.
- iced en rendu tiny-skia ne redessine que les **zones qui changent** d'une image à l'autre (suivi des dommages). Une animation coûte donc surtout **sa surface** plus celle de ce qu'elle recouvre. Petite surface = animation bon marché, même si le fond est riche.
- Le coût qui compte est celui d'**une image d'animation**, pas celui d'un écran fixe : un écran fixe est dessiné une fois puis plus rien, sauf à 1 image/s au repos.

Les coûts ci-dessous sont des **ordres de grandeur estimés** pour un processeur de bureau modeste (2 cœurs à 2 GHz) ; ils sont à confirmer par la mesure décrite en fin de note avant d'adopter un effet coûteux.

## Coût de chaque effet

| Effet | Coût par image (zone typique) | Verdict | Remarque |
| --- | --- | --- | --- |
| Aplat de couleur | ≈ 0,5 ms / plein écran | gratuit | |
| Dégradé linéaire (fond, dalle, bouton) | 3 à 4 × un aplat ; ≈ 2 à 4 ms / plein écran | faible | dessiné une fois par écran fixe |
| Arête de lumière | 0 | gratuit | 1er arrêt du dégradé |
| Tranche nette | un aplat de la taille du bloc | gratuit | conteneur décalé derrière |
| Ombre floue (rayon ≤ 10 px) | ≈ 0,2 à 0,4 ms par bouton de 300 × 64 | moyen | calcul par pixel sur la zone d'ombre ; à éviter sur ce qui bouge |
| Ombre floue (rayon 24 px, niveau 3) | ≈ 1 à 2 ms par panneau | moyen | un seul niveau 3 par écran |
| Dégradé radial (pastilles) | ≈ dégradé linéaire | faible | petites surfaces |
| Copie d'une image pré-calculée à sa taille | ≈ 0,05 à 0,1 ms pour 240 × 240 | gratuit | **la base de toute la 3D** |
| Même image mise à l'échelle à chaque trame | 4 à 8 × plus | moyen | utilisez la taille de rendu ou sa moitié |
| SVG ré-analysé à chaque trame (nouvelle poignée) | ≈ 0,3 à 1 ms par calque | **à corriger** | c'est le cas de `dessin.rs` aujourd'hui, voir plus bas |
| Translation d'un calque | coût du calque | gratuit | |
| Changement de couleur par palier | coût de la zone | gratuit | remplace les fondus |
| Fenêtre de découpage (`clip`) | ≈ 0 | gratuit | blanchiment, analyse |
| Texte qui change (compteur) | ≈ 0,1 ms par ligne | faible | glyphes en cache |
| Glissement d'écran (300 ms) | redessin complet × 9 images ≈ 8 à 15 ms/image | moyen, ponctuel | acceptable : 300 ms, hors analyse |
| Transparence animée (fondu) | composition de toute la couche à chaque image | **élevé** | remplacée par glissement ou palier de couleur |
| Flou animé, verre dépoli | rayon × surface à chaque image | **interdit** | voile opaque `voile` |
| 3D en temps réel | hors budget | **interdit** | séquences pré-calculées |

## Effets demandés trop coûteux, et l'alternative retenue

| Souhait | Pourquoi c'est trop cher | Alternative la plus proche |
| --- | --- | --- |
| Emblème qu'on fait tourner au doigt | 3D temps réel | séquence de 24 images en aller-retour (veille) |
| Ombre qui grandit quand un objet se soulève | flou recalculé à chaque image | ombre de contact cuite dans chaque image de la séquence |
| Lueur (halo) autour du bouclier ou de la herse | flou large animé | deux ondes = anneaux pleins par paliers de couleur |
| Fondu entre écrans | transparence plein écran | glissement de 24 px, 300 ms |
| Arrière-plan en verre dépoli sous une confirmation | flou du fond | `voile` opaque à 60 % (une seule fois, pas animé) |
| Parallaxe plein écran | redessin complet à chaque image | parallaxe locale (≤ 300 × 200 px, 2 plans) pendant l'analyse |
| Écran qui tremble sur une menace | redessin complet, mauvais pour l'accessibilité | seul l'emblème tremble (±4 px) |
| Particules (poussière, étincelles de gravure) | nombreux petits dessins, aucun sens | anneau gravé qui s'élargit |
| Texture de pierre | image plein écran, bruit en palette | dégradé à deux teintes |

## Ordre de mise en œuvre

Chaque étape est livrable seule, testée sous Xvfb 1280 × 768 (`tests/ui/env.sh`) dans les deux thèmes et avec « Animations réduites ».

1. **Jetons** (0,5 j). Lire `docs/charte/jetons.toml` (crate `toml`, déjà en dépendance) par `include_str!` dans un `build.rs`, ou générer `style.rs` depuis le TOML ; renommer `PIERRE` en `JOUR` (l'écran Affichage dit « Jour / Nuit »). Les valeurs v1 n'ont pas changé : rien ne bouge à l'écran.
2. **Cache des calques SVG** (0,5 j). `dessin::calque()` crée une `svg::Handle` neuve à chaque appel de `view`, donc iced ré-analyse et re-trame le SVG à chaque image (≈ 0,3 à 1 ms par calque, 3 à 5 calques par scène). Créer les poignées une fois par thème (structure `Calques` reconstruite par `set_nuit`) ; seule la position change par image. Pour `disque(angle)`, pré-calculer 36 angles ou passer à la séquence `disque`. **Gain immédiat**, à faire avant toute nouvelle animation.
3. **Relief niveau 2 et −1** (1,5 j) : boutons (dégradé, arête, tranche, enfoncé de 3 px), champs, piste de la barre, clavier, étapes. Recettes : `relief.md`, section iced. Ombre floue seulement sur les boutons d'action, pas sur les touches du clavier.
4. **Panneaux de verdict et pastilles** (1 j) : niveau 3, octogone pour bloqué.
5. **Séquences 3D** (1,5 j) : fonctionnalité `image` d'iced, chargeur de bandes (`sequences.json`), widget `Sequence { bande, image }` ; puis insertion, verdict sain, verdict bloqué, démarrage, veille.
6. **Blanchiment et gravure** (1 j) : fenêtre + lame ; anneau + tête laser liés à la progression réelle.
7. **v2 en ligne** (1 j, avec l'agent) : identification (champ, pavé), attente du serveur, hors service.
8. **Interface web** (au fil de l'eau) : `web/jetons.css` + `components/bundle.css`, pages générées par le serveur Rust.

## À éviter

- Créer une `svg::Handle` ou une `image::Handle` dans `view` : toujours les créer une fois et les cloner (le clone garde l'identifiant, donc le cache).
- Mettre à l'échelle une image à chaque trame ; animer la taille d'un SVG (re-tramage).
- Superposer plusieurs ombres floues sur une zone qui bouge (barre de progression, faisceau).
- `Color` avec alpha < 1 sur de grandes surfaces animées : mélanger une fois, au changement de thème.
- Animer un conteneur qui porte du texte long (redessin des glyphes) : animer l'image ou la forme, le texte arrive par un seul glissement.
- Deux boucles au centre de l'écran en même temps.
- Une boucle sans travail réel derrière (sauf la veille, à 15 i/s, arrêtée après 2 min).
- Cacher une information pendant une animation ; retarder un bouton au-delà de 600 ms.
- Le rouge pour autre chose qu'une menace ou un effacement ; le laiton pour un état.
- Côté web : JavaScript pour ce que le CSS fait (survol, appui, focus, menus `<details>`), polices ou images chargées depuis l'extérieur, animations en boucle dans les tableaux.

## Interface web

- Charger `web/jetons.css` puis `components/bundle.css` ; `data-theme="jour|nuit"` sur `<html>` (préférence utilisateur), sinon `prefers-color-scheme`.
- `bundle.css` utilise `color-mix()` (navigateurs de 2023 et après) : le poste d'administration dédié le permet ; sinon remplacer ces quelques lignes par les jetons `*-fonce` les plus proches.
- Sans JavaScript : tri et filtres par liens GET, confirmations par une page dédiée, rafraîchissement du tableau de bord par lien ou `<meta http-equiv="refresh">`.
- Le JavaScript, s'il en faut un jour, ne sert qu'au confort (rafraîchissement partiel), jamais à afficher ou valider.

## Mesurer

1. Construire en `release`, lancer sous Xvfb 1280 × 768 (`tests/ui/env.sh`), avec `taskset -c 0` pour simuler un petit processeur.
2. Ajouter un journal facultatif (`BARBACANE_MESURE_IMAGES=1`) qui note l'instant de chaque `Msg::Anim` traité : l'écart entre deux images donne la cadence réelle, ses 95e et 99e centiles la régularité.
3. `pidstat -u -p $(pidof barbacane-client) 1` pendant chaque animation : part de processeur.
4. Rejouer pendant une analyse réelle (fichier EICAR + gros ZIP) pour mesurer avec ClamAV en charge.
5. Seuils : intervalle p95 ≤ 40 ms (pas plus d'une image sautée), processeur ≤ 25 % d'un cœur. Au-delà, retirer d'abord les ombres floues de la zone animée, puis réduire la surface animée.
