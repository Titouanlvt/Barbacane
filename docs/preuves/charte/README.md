# Charte graphique sur l'interface (16/11/2026)

Captures de l'interface réelle (`barbacane-client`) dans l'environnement de test
`tests/ui/env.sh` (Xvfb **1280×768**, noyau usbsas en mode mock, ClamAV avec l'EICAR, admind).

| Écran | Captures |
|---|---|
| Démarrage : le logo se construit, « Préparation de la borne… » | `00-demarrage` |
| Clé détectée (la clé glisse vers la porte), boutons en relief, bandeau d'étapes | `01-choix` |
| Analyse : faisceau sur les fichiers, barre rayée vivante, chronomètre | `02-analyse-b` |
| Résultat : herse sur une menace | `03-resultat` |
| Clé de destination (clé laiton et sceau) | `04-destination` |
| Retrait : les clés repartent, la herse retombe | `10-retrait` |
| Blanchiment : « Maintenir pour effacer » ; appui d'1 s (voile à moitié), relâché (annulé) | `13-confirmation`, `14-maintien-1s`, `15-relache` |
| Terminé : bouclier | `18-fin` |
| Administration : menu, À propos (crédits), Affichage | `21-menu`, `22-apropos`, `23-affichage` |
| Thème Nuit, animations réduites (barre sans rayures, états finaux) | `25` à `28` |

Non visibles ici (pas de lecteur optique dans cet environnement) : tiroir du disque et lecture
du disque qui tourne ; vérifiés sur la borne Proxmox (voir la campagne de la même date).
