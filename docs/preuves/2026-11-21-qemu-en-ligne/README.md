# Borne en ligne de bout en bout dans QEMU, avec rapport de passage (21/11/2026)

Branche `serveur-correctifs` (base `integration` 8a0e07e + correctifs web/PKI/annuaire du 21/11),
sur bu, VM QEMU imbriquée seulement (aucune VM Proxmox). PKI de TEST hors dépôt
(`serveur/pki/racine-test.sh`), clé de mise à jour de TEST (`~/cles-test/test.pub`).

ISO : `build-iso.sh --profil en-ligne --ca-serveur … --serveur 10.0.2.2 --port-enrolement 43118
--port-service 43117` → 273 paquets, sha256 `d5a90fbf…182f` (`iso.txt`) ; `tests/iso/en-ligne.sh` OK.

`tests/iso/qemu-en-ligne.sh` : **QEMU FIN 0** (`qemu-en-ligne.txt`)

- installation sans carte réseau ; jeton déposé ; DHCP ; demande reçue (empreinte `104f ccd8 …`),
  validée par `barbacane-registre`, certificat installé ; battement supervisé (`écart=-1s`) ;
- **rapport de passage reçu par le serveur** (nouveau) : rapport d'analyse factice (1 EICAR,
  1 sain) placé là où l'analyseur écrit, op `serveur_passage` envoyée à admind comme l'interface
  (`{"ok":true,"parties":1}`) → fichier déposé dans la file de l'agent → « 1 rapport(s) de passage
  transmis » → ligne dans `registre/passages/index.jsonl` (`passages-index.jsonl` : verdict
  `menace`, 2 fichiers, 1 menace, identifiant de support haché). Aucun nom de fichier ni nom de
  menace côté serveur (vérifié par le script) ;
- pare-feu, `IPAddressAllow=10.0.2.2/32`, capacités vides, clé 0600 ; root ne sort ni vers
  10.0.2.2:22, ni vers 10.0.2.2:43117, ni vers le DNS ; interface v1 démarrée une fois
  (`ecran-borne.png`).

Rien n'a cassé sur cet état ; seul ajout : l'étape « rapport de passage » du script.
Limite : l'analyse elle-même est simulée (pas de clé USB passée à la VM) ; l'op d'admind, la file,
l'agent et la passerelle sont les vrais.
