# Preuve : clé Ventoy blanchie en gardant démarrable (17/11/2026)

**Verdict : OK** (passage parallèle n° 6, ISO 36742b4, clé Ventoy 1.1.18 émulée : ISO Debian
saine, ISO piégée EICAR, `ventoy/ventoy.json`). Détail ligne à ligne : `resultats.txt`.

- clé reconnue, « Blanchir en gardant démarrable » proposé (`02-resultat-analyse.png`) ;
- secteur 0, secteurs 1-2047 et partition `VTOYEFI` identiques octet par octet à la version de
  Ventoy **embarquée dans la borne** ; secteur 0 d'origine remplacé ;
- ISO saine et `notes.txt` conservées à l'identique ; ISO piégée, `ventoy.json` et dossier
  `ventoy/` absents ; aucune trace d'EICAR sur la clé ;
- **la clé démarre** : menu Ventoy affiché dans une VM de test (`05-demarrage-ventoy.png`).

Correctif nécessaire trouvé pendant cette preuve : écart n° 10 du noyau (étiquette FAT16).
