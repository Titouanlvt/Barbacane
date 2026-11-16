# Guide pas à pas : installer un poste Barbacane

Ce guide s'adresse à la personne qui prépare une borne. Durée : environ 30 minutes
(dont 10 minutes d'installation automatique). Détails techniques : [installation.md](installation.md).

## Ce qu'il faut

| Élément | Remarque |
|---|---|
| Un PC x86_64 (HP, Dell…) | 16 Go de RAM recommandés (8 Go testés), disque interne ≥ 32 Go. **Le disque sera entièrement effacé.** |
| Une clé USB ≥ 2 Go | Elle servira de support d'installation (son contenu sera effacé). |
| Un poste administrateur connecté à Internet | Debian 13 (testé), **8 Go de RAM** (4 Go au minimum, voir ci-dessous), ≈ 20 Go libres, droits root. Il fabrique l'ISO et signe les mises à jour. |
| Un écran tactile, ou un écran et une souris | Le clavier n'est utile qu'au réglage du BIOS. |

## Étape 1 — Fabriquer l'ISO (une seule fois pour toutes les bornes)

Sur le poste administrateur, **en root** (`su -` si `sudo` n'est pas installé) :

```sh
apt-get update && apt-get install -y git minisign
git clone https://github.com/Titouanlvt/Barbacane.git barbacane && cd barbacane

# Clé de signature des mises à jour : à faire UNE fois pour tout le parc.
# Choisir une phrase de passe solide ; la clé secrète (.key) ne quitte jamais ce poste
# (ou une clé USB chiffrée rangée au coffre).
borne/update/barbacane-update-keygen ~/cles-barbacane
cp ~/cles-barbacane/barbacane-maj.pub systeme/iso/maj.pub    # ignoré par git

systeme/iso/build-iso.sh --sortie barbacane.iso              # 30 à 40 min (Rust, paquets, ClamAV)
sha256sum barbacane.iso                                      # à noter avec la date
```

**Mémoire** : la compilation optimisée demande environ 3 Go par tâche ; le script règle seul le
nombre de tâches parallèles selon la mémoire libre. Si elle échoue avec
`signal: 9, SIGKILL` (mémoire épuisée), ajouter un fichier d'échange puis relancer la même commande
(la compilation reprend où elle s'est arrêtée) :

```sh
fallocate -l 8G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
systeme/iso/build-iso.sh --sortie barbacane.iso
swapoff /swapfile && rm /swapfile      # une fois l'ISO construite
```

On peut aussi imposer le nombre de tâches : `CARGO_BUILD_JOBS=1 systeme/iso/build-iso.sh …`.

Sans `maj.pub`, l'ISO fonctionne mais **aucune mise à jour ne pourra jamais être appliquée**
aux bornes ainsi installées (signatures antivirales comprises).
Une autre distribution peut utiliser un conteneur (`docker run --rm --privileged -v "$PWD":/src
-w /src debian:trixie systeme/iso/build-iso.sh --sortie barbacane.iso`) : variante non testée.

Résultat : le fichier `barbacane.iso`. Il contient tout ce qu'il faut (Debian, Barbacane,
base antivirale du jour) : **l'installation ne demande aucun réseau**.

> Faute de poste administrateur, une ISO de test est disponible dans l'onglet
> *Actions* de GitHub (workflow « ISO », artefact `barbacane-iso`). Elle n'a pas de
> clé de mise à jour : à réserver aux essais.

## Étape 2 — Copier l'ISO sur la clé USB

- **Linux** : repérer la clé **avant** de copier — une erreur efface un disque du poste :
  ```sh
  lsblk -d -o NAME,SIZE,TRAN,MODEL,SERIAL     # la clé : TRAN = usb, taille et modèle attendus
  dd if=barbacane.iso of=/dev/sdX bs=4M status=progress conv=fsync    # sdX = la clé
  cmp -n "$(stat -c %s barbacane.iso)" barbacane.iso /dev/sdX && echo copie vérifiée
  ```
  Ne jamais viser un disque dont `TRAN` n'est pas `usb`.
- **Windows** : Rufus, en choisissant le mode **« image DD »** quand il le propose.
- **macOS / tous** : balenaEtcher.

## Étape 3 — Préparer le BIOS du poste

Entrer dans le BIOS (F10 sur HP, F2 sur Dell) :
1. Mode de démarrage **UEFI** (le BIOS classique fonctionne aussi).
2. Désactiver temporairement Secure Boot si le poste refuse de démarrer sur la clé.
3. Autoriser le démarrage sur USB, **le temps de l'installation seulement**.

## Étape 4 — Installer

1. Brancher la clé, allumer, choisir la clé dans le menu de démarrage (**F9** HP, **F12** Dell).
2. Le menu « Barbacane » s'affiche ; l'installation démarre seule après 10 secondes.
3. **Ne rien toucher.** Le plus grand disque interne est effacé (jamais un disque USB),
   le système est installé puis le poste redémarre tout seul (≈ 10 min).
4. **Retirer la clé** au redémarrage.

## Étape 5 — Premier démarrage

1. L'écran Barbacane apparaît.
2. Toucher l'accès **administrateur** : l'écran affiche
   « Premier démarrage : choisissez le PIN ». Saisir un PIN d'au moins 6 chiffres.
   **Le noter en lieu sûr** : il protège l'administration de la borne.

## Étape 6 — Verrouiller le BIOS

De retour dans le BIOS :
1. **Désactiver le démarrage sur USB** et laisser uniquement le disque interne.
2. Poser un **mot de passe administrateur BIOS**.
3. Réactiver Secure Boot si possible.
4. **Ne jamais brancher de câble réseau**, ni à l'installation ni ensuite : la borne fonctionne entièrement hors ligne. Mise à jour du BIOS : par clé USB uniquement.

## Étape 7 — Vérifier

Insérer une clé contenant un fichier de test EICAR : la borne doit le signaler comme
menace. Insérer une clé saine : les fichiers doivent pouvoir être copiés vers une clé de sortie.

## En cas de problème

| Symptôme | Que faire |
|---|---|
| Le poste ne démarre pas sur la clé | Vérifier l'étape 3 (démarrage USB, Secure Boot) ; recopier l'ISO en mode « DD ». |
| L'installation s'arrête sur une question | Le poste a plusieurs disques ambigus : débrancher les disques en trop et relancer. |
| Écran noir après installation | La borne n'a pas de pilote clavier (sécurité) : on ne peut pas s'y connecter. Démarrer le poste sur une clé Debian « live », monter le disque interne en lecture seule et lire `journalctl -D /mnt/var/log/journal -u barbacane-kiosk` ; sinon réinstaller. |
| PIN oublié | Réinstaller le poste (étapes 4 à 6). |

Pour les mises à jour et la base antivirale : [administration.md](administration.md).
