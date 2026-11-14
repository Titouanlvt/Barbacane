# Barbacane

Charte graphique de **Barbacane**, borne de décontamination de clés USB hors ligne (Debian 13, cœur usbsas du CEA, analyse ClamAV + YARA). Une barbacane est l'ouvrage avancé qui contrôle l'entrée d'un château : la borne est l'endroit où une clé inconnue s'arrête avant d'atteindre le réseau.

Cette charte vise l'écran de la borne (interface kiosk sous cage, rendu logiciel), puis la documentation et le dépôt GitHub.

## Principes

1. **Lisible à un mètre.** On utilise la borne debout, souris en main. Corps de texte à 22 px minimum, consignes à 30 px, cibles de 72 px de haut (`cible-min`).
2. **Une seule chose à faire par écran.** Chaque écran porte une consigne et, au plus, deux boutons. Le bouton principal est toujours en bas à droite.
3. **L'état d'abord.** Le verdict (sain, écarté, menace) occupe le haut de l'écran, en couleur, avec une icône et un mot. La couleur n'est jamais le seul signal.
4. **De la pierre taillée.** Le relief se fait par des faces en aplats (face avant, flanc sombre, arête claire, décalage de 45° vers le haut à droite), jamais par des dégradés ou des ombres floues. Les animations racontent l'analyse (voir AnimationAnalyse) et ne décorent jamais.
5. **Rien ne vient du réseau.** Polices, icônes et images sont embarquées dans le paquet Debian.

## Voix et textes

- Vouvoiement, phrases courtes, verbe à l'impératif en tête : « Insérez la clé à analyser. »
- On nomme les objets comme l'utilisateur les voit : **clé à analyser** (clé inconnue) et **clé de destination** (clé de confiance). Jamais « périphérique », « device » ou « stockage de masse ».
- Les verdicts sont des faits : « 2 fichiers malveillants retirés », pas « Attention ! Danger ! ».
- Un message d'erreur dit ce qui s'est passé et quoi faire : « La clé n'est pas lisible. Retirez-la et essayez une autre clé. »
- Les noms de menaces (ex. `Win.Test.EICAR_HDB-1`) s'affichent en police mono, en `encre-douce`, sous le nom du fichier.

## Couleurs

Deux thèmes : **Pierre** (clair, par défaut sur la borne, lisible dans un bureau éclairé) et **Nuit** (sombre, pour la documentation et les salles peu éclairées).

| Rôle | Jeton | Règle |
| --- | --- | --- |
| Fond | `surface`, `surface-haute` | Tout l'écran en `surface`, les cartes en `surface-haute` bordées de `trait`. |
| Texte | `encre`, `encre-douce` | `encre` pour tout ce qui se lit en premier. |
| Identité | `laiton`, `laiton-pale` | Logo, focus, étape en cours. Moins de 5 % de l'écran. |
| En cours | `analyse`, `analyse-fond` | Lecture, analyse, copie, effacement. |
| Sain | `sain`, `sain-fond` | Fichier ou clé validés. |
| Écarté | `alerte`, `alerte-fond` | Fichier refusé sans être malveillant (chiffré, format interdit, trop volumineux). |
| Menace | `menace`, `menace-fond` | Détection ClamAV ou YARA. Réservé à ce seul sens. |

Chaque paire texte / fond respecte 4.5:1 dans les deux thèmes. Sain, alerte et menace diffèrent aussi en clarté et sont toujours accompagnés d'une icône différente (bouclier coché, triangle, octogone).

## Typographie

- **Barlow Condensed** (titres d'écran, verdicts) : condensée et robuste, elle tient en une ligne sur 1920 px.
- **Atkinson Hyperlegible** (consignes, boutons, texte) : conçue pour la lisibilité, distingue `I l 1` et `O 0`.
- **JetBrains Mono** (noms de fichiers, empreintes SHA-256, noms de signatures).

Les trois sont sous licence OFL. Sur la borne, embarquez les fichiers TTF dans le binaire (`include_bytes!` puis chargement via iced au démarrage) ou dans `/usr/share/fonts/barbacane/` via le paquet Debian. Ne comptez pas sur une police système.

## Logo

Le symbole est une barbacane vue de face : deux tours crénelées, une porte en arc, une herse en `laiton`. Il est construit sur une grille de 64 unités. Deux versions :

- **Relief** (`barbacane-relief.svg`) : faces avant, flancs extrudés et arêtes éclairées. Pour l'écran d'accueil, la documentation, GitHub. À partir de 64 px.
- **Plat** (`barbacane-symbole.svg`) : pour les petites tailles (barre de titre, favicon), en dessous de 64 px.

- Version courante : symbole en `encre` + mot « BARBACANE » en Barlow Condensed 600, capitales, interlettrage +4 %.
- Taille minimale du symbole : 24 px à l'écran. Zone de protection : la largeur d'une tour tout autour.
- Interdits : ajouter une clé USB dans le dessin, contours, ombres floues, dégradés, texture pierre photo, recolorer la herse dans une couleur d'état.

## Iconographie

Icônes au trait de 2 px, coins arrondis, grille de 24 (jeu conseillé : Lucide, licence ISC, à embarquer en SVG). Affichées à 32 px sur la borne. Une icône par état : `shield-check` (sain), `triangle-alert` (écarté), `octagon-x` (menace), `loader` (en cours), `usb` (clé).

## Parcours de la borne

Chaque écran reprend la même structure : bandeau d'étapes en haut, consigne au centre, actions en bas.

1. **Accueil** : « Insérez la clé à analyser. » Logo, rien d'autre.
2. **Clé détectée** : nom, taille, nombre de fichiers. Choix : « Copier vers une clé de destination » ou « Effacer cette clé ».
3. **Destination** : « Insérez la clé de destination. »
4. **Analyse** : jauge + fichier en cours (mono). Bouton secondaire « Annuler ».
5. **Verdict** : bandeau de couleur, liste des fichiers écartés avec leur raison.
6. **Copie terminée** : « Retirez les deux clés. » Retour automatique à l'accueil après le retrait.
