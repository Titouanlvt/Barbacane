# ISO des bornes téléchargées depuis le serveur (20/11/2026)

Conception : `docs/conception-barbacane-suite.md` §9, §10. Suite de `serveur-iso.md`,
`protocole-agent.md` (jeton, enrôlement) et `serveur-web.md`. **La borne v1 hors ligne n'est pas
touchée** : `build-iso.sh` sans option produit les mêmes fichiers ; seul `fin-en-ligne.sh`
(copié uniquement par le profil en ligne) est modifié.

## 1. Trois ISO

| ISO | Contenu | Secret | Usage |
|---|---|---|---|
| **Générique en ligne** | `build-iso.sh --profil en-ligne` avec la CA serveur (empreinte épinglée), l'adresse et les ports du serveur ; **sans jeton** | aucun | enrôlement au premier démarrage par jeton saisi (écran Administration → Serveur) |
| **Personnalisée** | la générique + `/barbacane/en-ligne/parametres.conf` (jeton, adresse, port d'enrôlement, site) | jeton 1 h, usage unique | installation sans saisie ; à préparer au moment de l'installation, détruite après usage |
| **Hors ligne v1** | `build-iso.sh` sans option, inchangée | aucun | signalée « borne sans serveur » |

Les deux ISO génériques sont **construites hors du serveur** (poste de construction, réseau pendant
la construction seulement) avec la **même version**, et leurs SHA-256 sont notés **hors bande**
(note de version imprimée). `build-iso-serveur.sh --iso-borne-en-ligne --iso-borne-hors-ligne
--sha256-bornes SHA256SUMS` refuse une ISO dont l'empreinte ne figure pas dans ce fichier, une ISO
« en ligne » sans `agent.toml`, une ISO « hors ligne » qui a un dossier `en-ligne`, et une ISO
déjà personnalisée. Elles sont embarquées (`/barbacane/iso-bornes/`, `SHA256SUMS`), revérifiées
par `fin-installation-serveur.sh`, puis copiées en lecture seule dans
`/var/lib/barbacane-serveur/iso-bornes/`. Conséquence assumée : l'adresse et les ports de la
passerelle sont figés dans l'ISO générique, donc le serveur doit être construit avec `--port`
fixe : port tiré à la construction et non à l'installation (écart à D4 consigné dans `decisions.md`).

## 2. Remaster sans Internet (`serveur/iso-bornes/barbacane-iso-borne`)

`barbacane-iso-borne personnaliser ISO_SOURCE ISO_SORTIE SITE` (jeton sur l'entrée standard,
jamais en argument) : `xorriso -indev SOURCE -outdev SORTIE -map parametres.conf
/barbacane/en-ligne/parametres.conf -boot_image any replay` : même volume, mêmes images de
démarrage, **aucun paquet reconstruit, aucun accès réseau**. Contrôles : ISO en ligne non
personnalisée, port du jeton = `port_enrolement` de l'ISO, site `site-<n>`, sortie 0600 jamais
écrasée, fichier temporaire détruit (`shred`). Le jeton vient du **registre existant**
(`Admin::creer_jeton` : 1 h, usage unique, haché, audité `JetonCree`).

À l'installation, `fin-en-ligne.sh` (borne en ligne seulement) vérifie que l'adresse et le port du
fichier sont ceux de l'ISO (sinon l'installation **échoue**), contrôle la forme du jeton et du site,
puis écrit le jeton dans `/var/lib/barbacane-agent/jeton` (0600, compte `barbacane-agent`) :
l'agent le lit au premier démarrage par son mécanisme existant (**aucun changement de
`borne/agent`**) et le supprime après la réponse définitive du serveur. La validation par un
administrateur avec empreinte retapée reste obligatoire.

## 3. Page web « ISO des bornes » (administrateur seulement)

Conception retenue : téléchargement de la générique et de la hors ligne (empreintes affichées, avec
le rappel de les comparer à la note imprimée) ; « Préparer une ISO pour un site » : jeton créé,
ISO produite par l'outil, téléchargeable **une seule fois** (POST avec jeton anti-CSRF, flux sans
mise en mémoire, durée de connexion allongée selon la taille), supprimée après le téléchargement
ou à l'expiration du jeton (1 h) ; chaque préparation et chaque téléchargement audités ; auditeur :
403 sur la page et les actions.

## 4. État

| Élément | État |
|---|---|
| Conception (ce document) | FAIT |
| Outil de remaster + `tests/iso-bornes/remaster.sh` (seule différence = `parametres.conf`, refus) | FAIT (bu, ISO synthétique) |
| Lecture du jeton de l'ISO à l'installation (`fin-en-ligne.sh`) | FAIT (shellcheck) ; installation QEMU : PRÉVU |
| ISO serveur : embarquement + empreintes + outil + xorriso | FAIT (refus prouvés sur bu) ; construction complète : PRÉVU |
| Remaster sur la vraie ISO en ligne (1,1 Go) | FAIT (bu : 1296 fichiers identiques, seule différence `parametres.conf`, volume conservé, 5 refus) |
| Page web, test « auditeur interdit », « téléchargement unique » | PRÉVU (cargo impossible : disque de bu plein) |
| QEMU : borne installée depuis l'ISO personnalisée, demande déposée sans saisie | PRÉVU |
