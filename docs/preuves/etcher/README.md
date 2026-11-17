# Preuve : clé Etcher réécrite depuis son image officielle vérifiée (écart n° 11, 17/11/2026)

**Verdict : OK.** VM 961 installée depuis une ISO de TEST (clé de signature du lab, commit 34530f3),
paquet signé contenant l'empreinte de l'ISO Debian copiée brute sur la clé (comme Etcher).

| Vérification | Résultat |
|---|---|
| Paquet signé appliqué ; autre clé et version ancienne refusées | OK (`resultats-bruts.txt`) |
| « Blanchir en gardant démarrable » proposé pour la clé Etcher | OK (`02-resultat-analyse.png`) |
| Les **792 723 456** premiers octets de la clé = l'image officielle, zone de démarrage comprise (`cmp`) | OK |
| Après l'image : zéros (64 Mio contrôlés) | OK |
| La clé réécrite **démarre** : installateur Debian chargé (`05-demarrage.png`, entrée par défaut après 30 s) | OK |

Notes :
- 1er essai : « Resource busy » (scsi2files gardait la clé) — corrigé (34530f3).
- `resultats-bruts.txt` contient un faux échec du script (taille du **lien** `etcher.img`, 24 octets,
  au lieu de l'image) : la comparaison a été refaite à la main avec la vraie taille (lignes ci-dessus),
  le script est corrigé (a1dea72).
- Le témoin aléatoire « après l'image » était mal placé à cause du même défaut ; l'effacement complet
  repose sur l'effacement fs2dev, prouvé par ailleurs (blanchiment).
