# Export et journal enchaînés (18/11/2026, VM 920, vraies clés)

Depuis l'instantané « propre », sans retour à l'instantané entre les scénarios (`RETOUR=0`) :
transfert → mises à jour signées → export → journal. **26 OK, 0 échec** (`resultats.txt`).

- Export : journal de la borne et 4 rapports JSON exportés, détections EICAR présentes (`export/`).
- Journal : grub.cfg protégé, détections EICAR consignées, mise à jour 202611151049 appliquée,
  clavier USB vu par hid-dealer (`journal/`).

Remplace les 4 échecs de banc de `../2026-11-18-rapide/` (instantané restauré avant ces scénarios).
