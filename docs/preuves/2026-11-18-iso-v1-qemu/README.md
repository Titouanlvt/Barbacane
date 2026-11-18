# ISO v1.0 : test d'installation de la CI rejoué 3 fois (18/11/2026)

Sur `main`, le job `installation-qemu` du commit v1.0 (5c20866) a échoué une fois sur GitHub alors
qu'il a réussi sur `integration` avec le même code (journal GitHub non lisible sans authentification).
Le même script (`tests/iso/qemu.sh`) a été rejoué 3 fois de suite sur la VM bu avec l'ISO v1.0
(sha256 `4e2bd821…cbb2`) : **3 réussites sur 3** — installation sans intervention, premier démarrage,
5 services actifs, bac à sable des archives fonctionnel, GRUB verrouillé, interface affichée
(`ecran-essai-1.png`). Conclusion : échec ponctuel de l'exécuteur GitHub, pas un défaut de l'ISO.
