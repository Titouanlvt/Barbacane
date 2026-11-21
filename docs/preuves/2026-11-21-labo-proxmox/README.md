# Labo Proxmox du 21/11/2026 — serveur 960, borne 970 (v2.0.1)

Résumé des traces brutes conservées HORS dépôt (`docs-labo/2026-11-21-proxmox/` sur l'hôte de
travail : journaux série, captures, pcap). Aucun mot de passe, PIN, jeton ni clé n'est reproduit ici ;
les empreintes de certificat sont tronquées.

## Montage

- Serveur : VM 960 (OVMF + TPM 2.0), installée sans intervention depuis l'ISO serveur de TEST
  (`0d8aa11b…`), réseau des bornes 10.20.0.1, réseau d'administration 10.99.0.1.
- Poste d'administration : bu (10.99.0.10). Borne en ligne : VM 970 (10.20.0.10).

## Constats

| Point | Résultat |
|---|---|
| Console avec le certificat `admin-01` de TEST | `GET /connexion` → 200 (journal de barbacane-web : `certificat 8d9fd80f… → 200`) |
| Console sans certificat | refusée à la poignée de main ; journal : `refus : unexpected end of file` (le client voit la fermeture ou l'alerte TLS) |
| Connexion par mot de passe (admin-01) | `POST /connexion` → 303 puis tableau de bord → 200 |
| Second administrateur (`admin-02`, autre certificat) | compte ajouté par `barbacane-web compte` (fichier `comptes` 0600, barbacane-svc), pages servies → 200 |
| Liaison bornes | borne 970 servie en mTLS par la passerelle : `POST /maj/battement` → 200, `POST /utilisateurs/politique` → 200 |
| Deux ports de la passerelle | trafic de la borne observé (tcpdump sur `tap970i0`) vers 10.20.0.1:43117 (service) et :43118 (enrôlement) seulement |
| Parc / registre | demande d'enrôlement de la borne 970 vue puis validée dans la Console (pages « Parc », « Valider ») |
| Journal / audit | passages de la borne listés et détaillés dans la Console (pages « Passages ») |
| Rotation du mot de passe système | `passwd` de barbadmin à la première connexion |

## Défauts relevés (hors 2.0.1)

- Une page a répondu 500 une fois (admin-02) ; message de jeton, écran « Clé détectée », noms de
  site libres, doc barbadmin : 2.0.2 (`docs/suite/point-serveur-2026-11-21.md`).
- Le banc QEMU échouait sur la Console alors que le labo la servait : défauts du BANC, corrigés en
  2.0.1 (`docs/notes-de-version/v2.0.1.md`).
