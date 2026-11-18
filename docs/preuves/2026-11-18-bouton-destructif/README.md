# Bouton « Effacer cette clé et y copier les fichiers » à la charte (18/11/2026)

Retour utilisateur : le bouton n'avait pas la charte (variante Principale noire). La charte (composant
Bouton) réserve la variante **Destructive** (fond `menace`) à « Effacer cette clé ».

- `actif.png` : clé enrôlée branchée — rouge `menace`, tranche `encre` (relief).
- `desactive.png` : clé non enrôlée — rouge pâle opaque, même relief qu'« Abandonner » (tranche `trait`).
- Même traitement pour « Effacer ce disque et y graver les fichiers » (disques optiques).

Vérifié sur la borne de développement 950 (correctif par mise à jour signée, clé de TEST du lab,
commit 7a14335), puis scénario `transfert` rejoué : `resultats.txt` (21 OK, 0 échec).
