# Campagne finale du 17/11/2026 (VM 920, vraies clés) : transfert et blanchiment

- ISO de production construite depuis `integration` e888495, sha256
  `2e57f2a75b28c2852b12c5cb01adddbc21fa499ae6b7088d04449e0875a32b91`.
- Clés réelles passées à la VM au niveau USB : source SanDisk 16 Go, sortie SanDisk Ultra 64 Go enrôlée.
- `resultats.txt` : 35 OK, 0 échec (installation, grub, pin, enrôlement, transfert, blanchiment,
  volumineux). Campagne arrêtée à 21 h 30 à la demande de l'utilisateur ; le reste est à rejouer.

## Transfert d'une clé inconnue vers une clé connue (`transfert/`)
Clé non enrôlée refusée en sortie et laissée intacte ; 4 fichiers sains copiés (sha256 identiques) ;
EICAR (dont un .jpg déguisé) absents ; archive chiffrée copiée ; noms piégés non écrits ; rapport.

## Blanchiment (`blanchiment/`)
EICAR présent avant (`cle-avant-eicar-offsets.txt`) ; empreinte de la clé entière modifiée ;
plus aucune trace d'EICAR sur toute la clé ; fichiers sains réécrits intacts.
