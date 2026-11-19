# Adaptation de la charte v2 à la borne v1

**Règle** : la logique de la v1 fait foi et ne change pas (écrans, boutons, libellés, ordre des étapes,
parcours unique « Analyser » puis Copier vers une clé connue / Graver / Blanchir / Arrêter ici,
administration, messages, sécurité). De la charte v2, on reprend **uniquement le style** : couleurs,
typographie, relief, élévations, formes des composants, iconographie, animations, objets 3D.
Les maquettes d'écrans de la charte servent de référence de style, jamais de parcours.

Contraintes : rendu logiciel iced + tiny-skia à 30 images/s, 1280 × 768, cibles tactiles ≥ 48 px,
contraste WCAG AA, thèmes Jour et Nuit, option « Animations réduites ».

## Écarts entre la charte et la v1 (choix : toujours la logique v1)

| Écran / élément | Maquette de la charte | v1 (conservé) | Transposition du style |
|---|---|---|---|
| Accueil | « Insérez la clé ou le disque à analyser. », sous-titre, ports USB et lecteur, emblème 3D | même consigne v1 et mêmes éléments (pas de « Port USB, à droite » propre à un modèle de borne) | emblème 3D (séquence `embleme-pivot`) à la place du dessin plat (étape 5) |
| Pied de page | « Barbacane 2.0 · station blanche », « Serveur connecté » | « Barbacane 0.1.0 — station blanche hors ligne », « Mode clés enrôlées », Administration | aucune indication de serveur (la v1 n'a aucun réseau) ; style du pied repris (légende 18 px) |
| Bandeau | identifiant de borne et site (« B-A-01 · Site A ») | « Signatures antivirales : N jour(s) » | même bandeau `bandeau` / `sur-bandeau` ; contenu v1 |
| Étapes | 5 étapes (Clé insérée, Analyse, Résultat, Sortie, Copie), étape en cours en bloc laiton | 6 étapes v1 (Clé, Analyse, Résultat, Clé de destination, Écriture, Terminé) | style de la charte appliqué aux 6 étapes v1 (étape 4) |
| Identification (v2 en ligne) | écran identifiant + PIN | **n'existe pas en v1** | non repris |
| Attente du serveur, hors service | écrans dédiés | **n'existent pas en v1** | non repris |
| Résultat : choix | cartes de choix (CarteChoix) « Copier vers une clé », « Graver un disque », « Blanchir cette clé » + bouton « Arrêter ici » | rangée de boutons v1 : « Arrêter ici », « Copier vers une clé connue », « Graver un disque », « Blanchir la clé » (+ « Blanchir en gardant démarrable » pour Ventoy) | libellés et ordre v1 ; boutons dans les variantes de la charte (Principal pour Copier, Danger pour Blanchir, Secondaire pour le reste) |
| Clé détectée | — | grande carte « Analyser » (seul choix) | bloc Principal (tranche `laiton-fonce`) |
| Bouton désactivé | à plat (`surface-haute`, bord `trait`, sans tranche ni ombre) | « Effacer cette clé et y copier les fichiers » désactivé tant qu'aucune clé enrôlée | **à plat** comme la charte (rouge pâle opaque pour la variante Danger, même encombrement). Note : le 18/11, en v1, un relief avait été validé sur ce bouton désactivé ; la charte v2 (19/11) le remplace par le plat. |
| Bouton appuyé | descend de 3 px, tranche 4 → 1 px | — | **alternative** : face assombrie seulement. iced ne transmet pas l'état « appuyé » du bouton au calque de la tranche posé derrière ; l'enfoncement exigerait un widget dédié (reporté). |
| Cibles | boutons 64 px, minimum 48 px | boutons v1 ≈ 72 px | inchangé (au-dessus du minimum) |
| Thèmes | « Jour » et « Nuit » | « Pierre » et « Nuit » | libellé « Jour (clair) » ; la valeur enregistrée reste `pierre` (préférences des bornes déjà installées) |

## Ce qui est appliqué (état)

| Étape (realisation.md) | État | Réalisation |
|---|---|---|
| 1. Jetons | fait | `borne/client/build.rs` génère la palette depuis `docs/charte/jetons.toml` (source unique) |
| 2. Cache des calques SVG | fait | `dessin::calque` garde une poignée par texte et par thème (test `calques_mis_en_cache_par_theme`) |
| 3. Relief des boutons (niveau 2) | fait | `style::relief` (dégradé, arête de lumière, bord 1 px), `app::en_relief` (tranche nette 4 px dessous, ombre 0 6 10), tranches par variante |
| 3. Dalle (cartes) | fait | `style::carte` : dégradé `dalle-haut` → `dalle-bas`, bord `trait`, ombre 0 2 6 |
| 3. Creusé (champs, piste de barre, clavier) | à faire | |
| 0. Sol (fond d'écran) | fait | `style::fond` : dégradé `sol-haut` → `sol-bas` |
| 4. Panneaux de verdict (niveau 3) | fait | `style::verdict` : `*-fond` éclairci → `*-fond`, bord 2 px d'état, tranche nette 6 px `*-fonce` (ombre sans flou ; l'ombre diffuse 0 14 24 n'est pas cumulable : une ombre par conteneur dans iced) |
| 4. Pastilles, octogone | à faire | |
| 5. Séquences 3D (emblème, clé, bouclier, disque) | à faire | fonctionnalité `image` d'iced, bandes PNG de `docs/charte/3d/` |
| 6. Blanchiment (lame), gravure (anneau) | à faire | |
| 7. v2 en ligne | hors v1 | |

## Preuves

Captures avant / après de chaque écran (Jour et Nuit) : `tests/ui/captures.sh` ; campagne rapide sur
la borne de développement pour montrer que parcours et tests de l'interface sont inchangés.
