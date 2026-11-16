# Administration de Barbacane

## 1. Entrer en mode administrateur

Sur l'écran d'accueil (ou l'écran « Clé détectée »), bouton discret
**Administration** en bas à droite → saisie du PIN au pavé numérique à l'écran.

- Le PIN est vérifié par le service `barbacane-admind` (haché **Argon2id**,
  jamais stocké en clair, jamais vu par l'interface).
- **5 échecs** → verrouillage 15 min, puis 30, 60 min… à chaque nouvel échec.
- La session administrateur expire après **15 min** d'inactivité.

Menu : État de la borne · Mettre à jour · Exporter les journaux · Clés de sortie
enrôlées · Limites d'analyse · Changer le PIN · Redémarrer · Éteindre.

PIN perdu : **réinstaller la borne** avec l'ISO (les clés enrôlées et les réglages sont
perdus, à refaire). Il n'existe volontairement aucune porte dérobée : root est verrouillé,
la borne n'a aucun pilote clavier et le menu de démarrage GRUB est protégé par un mot de
passe aléatoire que personne ne connaît (sinon un clavier branché au démarrage suffirait
à obtenir un shell root).

## 2. Mises à jour hors ligne

### 2.1 <a name="cles"></a>Clés de signature

Sur le poste administrateur (jamais sur une borne), outil `minisign` installé
(`apt-get install minisign`) ; la phrase de passe est demandée deux fois :

```shell
borne/update/barbacane-update-keygen ~/cles-barbacane
```

- `barbacane-maj.key` : clé **secrète**, protégée par phrase de passe. La garder
  hors ligne (clé chiffrée, coffre). Toute personne qui la détient peut faire
  installer n'importe quoi sur les bornes.
- `barbacane-maj.pub` : clé publique, installée sur chaque borne (`/etc/barbacane/maj.pub`).

**Rotation** (clé compromise ou renouvellement) : générer une nouvelle paire,
puis produire un paquet signé avec l'**ancienne** clé contenant la **nouvelle**
clé publique (`--nouvelle-cle`). Une fois ce paquet appliqué, seule la nouvelle
clé est acceptée. En cas de compromission avérée de l'ancienne clé, réinstaller
la clé publique à la main sur chaque borne (mode maintenance).

### 2.2 Préparer un paquet (poste connecté)

1. Sur la borne : **Exporter les journaux** (§3). Le dossier exporté contient
   `dpkg-status`, l'état des paquets Debian de la borne.
2. Sur le poste (Debian 13, `apt-get update` fait, outils : `minisign zstd
   clamav-freshclam git`) :

```shell
borne/update/barbacane-update-prepare \
    --cle ~/cles-barbacane/barbacane-maj.key --sortie ./maj \
    --yara-sources borne/update/yara-sources.exemple \
    --etat-borne /media/export/barbacane-export-*/dpkg-status \
    --debs systeme/mkosi/paquets          # usbsas / Barbacane reconstruits
```

Le script télécharge les signatures ClamAV (freshclam), les règles YARA, les
mises à jour Debian **calculées sur l'état de la borne** (avec leurs
dépendances), écrit un manifeste (versions, sha256, date), compresse
(`.bcu` = tar.zst) et signe (`.bcu.minisig`). La version est un entier croissant
(par défaut `AAAAMMJJHHMM`).

Paquet minimal (signatures seules) : `--cle … --sortie …` sans autre option.

3. Copier `barbacane-maj-<version>.bcu` et `.bcu.minisig` à la racine d'une clé USB.

### 2.3 Appliquer sur la borne

Administration → **Mettre à jour** → brancher la clé sur le port **d'entrée** →
**Lire et appliquer**.

1. La clé est lue **par usbsas** (pile USB en espace utilisateur, jamais de montage noyau).
2. `barbacane-admind` vérifie la **signature** (fichier entier), refuse toute
   version **inférieure ou égale** à la version installée (anti-retour arrière),
   déballe, contrôle chaque **empreinte** du manifeste et refuse tout fichier non listé.
3. Application : signatures ClamAV puis règles YARA (avec sauvegarde : **retour
   arrière automatique** si le redémarrage de clamd ou de l'analyseur échoue),
   puis paquets Debian (`apt-get` sans aucune source réseau).
4. Rapport à l'écran ; redémarrer si des paquets Debian ont été installés.

Âge des signatures : affiché en permanence en haut à droite ; **alerte** au-delà
de 7 jours (`signatures_max_age_days` dans `/etc/barbacane/client.toml`).

## 3. Exporter journaux et rapports

Administration → **Exporter les journaux** → clé sur le port de **sortie** (elle
est effacée et formatée en exFAT). Contenu : `rapports/` (un JSON détaillé par
transfert), `journal.txt` (journald, 90 jours), `etat.json`, `dpkg-status`.

Rapports conservés localement : `/var/lib/barbacane/rapports/` (5 000 derniers,
`max_reports` dans `analyzer.toml`). Journal système : persistant, 1 Go maximum.
Envoi vers un syslog distant : prévu dans `/etc/systemd/journald.conf.d/barbacane.conf`, désactivé.

## 4. Clés de sortie enrôlées

Par défaut, n'importe quelle clé est acceptée en sortie (elle est toujours
effacée et formatée en exFAT). Mode « clés enrôlées » : seules les clés de la
liste (fabricant, produit, numéro de série) sont acceptées ; toute autre clé est
refusée avec un message.

Administration → **Clés de sortie enrôlées** : brancher la clé à enrôler, cliquer
« Enrôler : … » ; « Activer » / « Désactiver » le mode ; « Retirer » une clé.
Une clé sans numéro de série ne peut pas être enrôlée. Le numéro de série USB
n'est pas une authentification forte (il peut être copié) : ce mode limite les
erreurs et les clés personnelles, il ne remplace pas un contrôle d'accès.

## 5. Limites d'analyse

Administration → **Limites d'analyse** : profondeur d'imbrication (défaut 5),
nombre de fichiers extraits (200 000) et taille décompressée (32 Go), comptés **par fichier
racine** (une ISO, une archive) : avant le 16/11/2026, 10 000 fichiers et 4 Go pour toute la clé,
ce qui refusait toute ISO d'installation. Les autres limites (rapport de compression 100:1, durée 300 s
et mémoire 2 Go par extraction, délai de saisie du mot de passe 300 s, 3 essais)
se règlent dans `/etc/barbacane/analyzer.toml`. Dépasser une limite **refuse tout
le conteneur racine**.

## 5 bis. Affichage : thème et animations

**Administration → Affichage** :
- **Thème** : *Pierre* (clair, par défaut, bureau éclairé) ou *Nuit* (sombre, salle peu
  éclairée). Mêmes couleurs d'état et mêmes contrastes (≥ 4,5:1) dans les deux thèmes
  (charte, `docs/charte/tokens.json`).
- **Animations** : *Normales* ou *Réduites*. Réduites, chaque écran s'affiche directement dans son
  état final (aucune information n'est jamais retardée par une animation).

Le choix est enregistré par `barbacane-admind` (`/var/lib/barbacane/admin/preferences.json`) et
conservé après redémarrage ; il s'applique immédiatement.

## 6. Analyseur central (plusieurs bornes)

Désactivé par défaut. Un serveur Barbacane peut analyser pour plusieurs bornes :

- **Serveur** : `barbacane-analyzer` avec `[server]` (TLS, fichier de jetons
  `<jeton> <nom de la borne>`), voir `systeme/etc/analyzer-serveur.toml.exemple`.
  Les analyses de chaque borne sont isolées ; les refus de jeton sont journalisés.
- **Borne** : même binaire en mode `[relay]` (voir `analyzer-relais.toml.exemple`),
  qui écoute toujours sur 127.0.0.1:8042 : usbsas et l'interface sont inchangés.
  Le certificat du serveur est épinglé. Le pare-feu de la borne doit alors
  autoriser la seule connexion sortante vers le serveur (adapter `/etc/nftables.conf`).
- La lecture de la clé admin (mises à jour) reste locale à la borne.

## 7. Identification par badge (prévu)

Les transferts sont anonymes (horodatage + numéro de série des clés dans les
rapports). Un lecteur de badge pourra s'insérer à l'endroit prévu par usbsas :
le processus `identifier`, dont l'identifiant est déjà transmis à l'analyseur et
aux rapports. L'option `badge` de `client.toml` est réservée à cet usage.
