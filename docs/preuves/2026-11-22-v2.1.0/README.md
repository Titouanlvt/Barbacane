# Preuves v2.1.0 — grandes images ISO (22/11/2026)

**Verdict : OK — 57 vérifications, 0 ÉCHEC** (`resultats.txt`), borne de développement 950
(ISO de TEST), mise à jour signée de TEST vers 2.1.0 (commit `8d86de3`), puis `lab/rapide-v210.sh` :
43 vérifications de non-régression + 14 du scénario `grandes-iso` (`tests/proxmox/preuve.sh`).

Sources : Debian 13.7.0 netinst `a7ef94ac…e355`, identique au `SHA256SUMS` publié par Debian
(`debian-13.7.0-SHA256SUMS`) ; Windows 11 26H2 Business fr-fr `6f1e0c6b…7da4d`, empreinte calculée
sur l'ISO téléchargée chez Microsoft (même valeur que la preuve du 17/11, `../liste-blanche/`).
Liste signée par la clé de TEST du lab : `images-officielles.sha256` (« sha256 taille nom »,
Windows seulement : Debian doit suivre le chemin d'analyse complète).

| Vérification | Résultat |
|---|---|
| Windows 11 (8,9 Go) : empreinte vérifiée avant copie (214 s), « Image officielle reconnue » | OK (refusée en 10 s en 2.0.3) |
| Copie en flux vers exFAT (432 s), sha256 identique | OK |
| FAT32 : refus clair avant écriture, clé de sortie intacte (témoin) | OK |
| Copie en flux vers NTFS (428 s), sha256 identique, système NTFS | OK |
| Debian 13 : estimation affichée, analyse complète (1761 s), copie exFAT, sha256 identique | OK |

Source Windows en ext4 (exFAT impossible à créer sur l'hôte : `mkfs.exfat` absent, rien n'y est installé).
