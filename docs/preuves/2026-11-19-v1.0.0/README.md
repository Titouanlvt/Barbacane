# Preuves v1.0.0 (19/11/2026)

| Preuve | Résultat |
|---|---|
| ISO de référence, clone propre GitHub de `66ca87e` (`lab/iso-v100.sh`, bu) | sha256 `5e0c3fba…3fc7`, garde-fou hors ligne OK |
| Installation en VM UEFI (`tests/iso/qemu.sh`), 2 essais | 1er : `usbsas-server` arrêté une fois au démarrage puis relancé ; 2e : tout OK (`installation-qemu.txt`) |
| Campagne rapide, borne de dev 950 (ISO de TEST + correctif `66ca87e`, clés émulées) | **39 OK, 0 échec** : transfert, blanchiment, export, clé vide, illisible, retrait, verrouillage, journal (`resultats.txt`) |

Non rejoué ici : vraies clés USB (campagne du 18/11, 121/121, même code hors `wasmtime`).
