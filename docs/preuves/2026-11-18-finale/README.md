# Campagne finale du 18/11/2026 — vraies clés, ISO de production

- ISO de production construite sur bu depuis `integration` **d4a3641**, sha256
  `080f6ff69805adea3c90d5ccaa3f86fa3e0d240596acbcb20375d7d98d7214d1` (clé publique de production embarquée).
- VM 920, 8 Go, UEFI, sans réseau. Vraies clés en USB : SanDisk 16 Go (source, 03020611111524225725),
  SanDisk Ultra 64 Go (installation puis sortie enrôlée). Troisième clé « autre » émulée.
- Lanceur : `lab/campagne-finale-3.sh` (`tests/proxmox/preuve.sh`).

| Passe | Scénarios | Résultat |
|---|---|---|
| [passe1/](passe1/) — retour à l'instantané « propre » entre scénarios | installation, grub, pin, enrôlement, transfert, blanchiment, volumineux, maj, clés démarrables réelles (bureau, Etcher, Rufus FAT32, Rufus NTFS), ventoy, veille, clavier, vide, pleine, illisible, retrait, verrouillage | **95 OK, 0 échec** |
| [passe2-enchainee/](passe2-enchainee/) — enchaînés sans retour, comme une journée d'usage | transfert, maj, export, journal | **26 OK, 0 échec** |

Détail ligne à ligne : `resultats.txt` de chaque passe ; captures d'écran et empreintes dans les sous-dossiers.
