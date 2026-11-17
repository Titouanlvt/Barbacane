# Preuve : liste blanche d'images officielles (17/11/2026)

**Verdict : OK.** Borne virtuelle (VM 960) installée depuis une ISO de test
(`barbacane-TEST-cle-lab.iso`, commit bee9892) qui embarque une **clé publique de test du lab** à
la place de la clé de production (dont la phrase de passe n'est connue que de l'administrateur).
Paquets préparés avec `barbacane-update-prepare --images-officielles` et signés par cette clé de test.

| Vérification | Résultat | Pièce |
|---|---|---|
| Paquet signé valide appliqué, « liste d'images officielles : 1 image(s) » | OK | `01-valide.png` |
| Paquet signé par une autre clé refusé | OK | `02-mauvaise-signature.png` |
| Paquet de version plus ancienne refusé | OK | `03-version-ancienne.png` |
| Avant la liste : ISO Windows 11 (8,3 Go, `install.wim` > 1 million de fichiers) refusée, « trop volumineux pour être ouvert » | constat | `avant-*` |
| Après la liste : ISO reconnue « image officielle (liste de l'administrateur) », copiée intacte (sha256 identique), 0 refus, 1392 s | OK | `apres-*` |

Liste utilisée : `6f1e0c6b…7da4d  Win11_26H2_French_x64.iso` (empreinte calculée sur l'ISO
téléchargée chez Microsoft).
Scripts : `lab/preuve-liste-blanche.sh` (hors dépôt), `tests/proxmox/preuve.sh` étapes `maj` et `reel`.
Note : `preuve.sh` exécute `reel` avant `maj` ; l'étape `reel` a donc été rejouée après la mise à jour.
