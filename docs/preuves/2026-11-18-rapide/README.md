# Campagne rapide du 18/11/2026 (VM 920, VRAIES clés, sans réinstallation)

- Borne installée depuis l'ISO de production e888495 (sha256 `2e57f2a7…2b91`), instantané
  « installee » ; PIN choisi et clé de sortie enrôlée, puis instantané **« propre »** (mémoire
  comprise) restauré avant chaque scénario : **13 restaurations, 5 à 8 s chacune**
  (`tests/proxmox/campagne-rapide.sh`, `PROPRE=1`).
- Clés réelles passées à la VM au niveau USB, désignées par numéro de série : source SanDisk 16 Go
  (03020611111524225725), sortie SanDisk Ultra 64 Go enrôlée.
- `resultats.txt` : **65 OK, 4 ÉCHEC**.

| Scénario | Résultat | Preuve |
|---|---|---|
| Transfert clé inconnue → clé enrôlée (EICAR bloqué, sains intacts, sha256) | 13 OK | `transfert/` |
| Blanchiment (sha256 de la clé entière et secteur 0 en hexadécimal avant/après, EICAR effacé) | 11 OK | `blanchiment/` |
| Ventoy blanchie en restant démarrable, démarrage | 14 OK | `ventoy/` |
| Mises à jour signées (valide, mauvaise signature, retour arrière) | 3 OK | `maj/` |
| PIN, enrôlement, GRUB verrouillé, clavier, verrouillage | OK | dossiers du même nom |
| Clé vide, pleine, illisible, retirée pendant la lecture | OK | dossiers du même nom |
| **Écran de veille** (10 min, réveil au toucher) — première preuve | 2 OK | `veille/` |
| Export, journal | 4 ÉCHEC | voir ci-dessous |

Les 4 échecs (`rapports absents de l'export`, `rapports exportés sans les détections`,
`journal sans EICAR`, `version 202611151049 absente`) viennent du **banc de test** : le retour à
l'instantané avant `export` et `journal` effaçait les rapports et la mise à jour des scénarios
précédents. Corrigé (ces deux scénarios ne reviennent plus à l'instantané) ; rejoués en
enchaînement continu : `../2026-11-18-export-journal/`.
