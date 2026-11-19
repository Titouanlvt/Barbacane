# Barbacane suite — gestion centralisée des bornes (conception)

Statut : **conception, aucun code**. Document de départ pour l'implémentation.
Barbacane v1 (borne hors ligne) reste inchangé : la « suite » est un **produit
distinct** (ISO borne en ligne + ISO serveur).

## 1. Décisions prises

| Sujet | Décision |
|---|---|
| Échelle | 10 à 100 bornes. **Un serveur unique** pour commencer ; serveur central de consolidation multi-sites prévu plus tard (§9). |
| Réseau | LAN de gestion **sans Internet**. Sites reliés par VPN site à site + VXLAN (même réseau de niveau 2). |
| Sens des connexions | **La borne appelle le serveur** ; la borne n'écoute aucun port. TLS avec authentification mutuelle (mTLS). |
| Serveur injoignable | La **borne en ligne se bloque** (message à l'écran). Les bornes v1 hors ligne ne sont pas concernées. |
| Passage v1 → en ligne | **Réinstallation obligatoire** : la v1 ne contient aucun code réseau. |
| Livraison du serveur | **ISO dédiée** (Debian durcie, installation automatique hors ligne) qui embarque les images Docker du serveur. |
| Enrôlement des bornes | **Jeton à usage unique** généré dans l'interface web. |
| Fonctions | Supervision, mises à jour centralisées, journaux et rapports, configuration et politique, gestion des clés (fabricant + numéro de série), identification des utilisateurs. |
| Utilisateurs | Deux notions distinctes, **mode choisi par l'administrateur** par site ou par borne (§3.3) : **identification** (savoir qui fait quoi, pour la journalisation) et **authentification** (être sûr que c'est bien cet utilisateur). Pour commencer, **sans lecteur** : l'utilisateur **tape son identifiant** sur le clavier de l'écran tactile ; badge plus tard. |
| Port | **Pas 443** : port TCP non standard tiré au hasard à l'installation du serveur (modifiable), pour ne pas être repéré par un scan rapide. |
| Données envoyées par la borne | Rapports et journaux, **fichiers malveillants et suspects** (quarantaine chiffrée). |
| Rôles web | Administrateur, administrateur de site, opérateur, auditeur (lecture seule). |
| Conservation | Journaux et rapports **1 an**, quarantaine **30 jours**, purge automatique. |
| Cadre | Recommandations **ANSSI** / homologation, **Diffusion Restreinte** (IGI 1300), **RGPD**. |
| Mises à jour | L'administrateur dépose le `.bcu` signé dans l'interface web ; le serveur le diffuse. |
| Analyse | **ClamAV et YARA restent sur la borne** : toute la décision (sain / bloqué) est prise localement, comme en v1. Le serveur ne fait que gérer, superviser et stocker. |

## 2. Principes de sécurité

1. **Un serveur compromis ne compromet pas les bornes.**
   - Le serveur ne détient jamais la clé de signature des mises à jour (elle reste hors ligne).
   - Chaque borne **revérifie elle-même** la signature et l'anti-retour arrière d'un `.bcu`, comme en v1.
   - Le serveur ne peut pas exécuter de commande sur une borne : il **publie** une politique, la borne la **récupère**, la vérifie (schéma, bornes de valeurs) et l'applique.
2. **Surface minimale de la borne** : aucun port en écoute, une seule connexion sortante vers une adresse et un port fixés (pare-feu nftables : tout le reste refusé).
3. **Identité forte de chaque borne** : certificat client propre à la borne, clé privée générée sur la borne et non exportable (TPM 2.0 si présent, sinon fichier protégé).
4. **Les identifiants USB ne prouvent rien** : fabricant (VID/PID) et numéro de série se falsifient. Ils servent à la gestion et à la traçabilité ; la décision de confiance reste l'analyse du contenu. Une clé « connue » au sens du serveur reste soumise à l'analyse.
5. **Pas de contenu sensible en clair** : fichiers en quarantaine chiffrés de bout en bout, de la borne au stockage du serveur.
6. **Traçabilité** : journal d'audit du serveur inaltérable (entrées chaînées par empreinte et signées), y compris pour les actions des administrateurs.
7. **Cœur usbsas inchangé** : l'agent réseau est un composant Barbacane séparé ; usbsas reste sans réseau.

## 3. Architecture

```
┌─────────── LAN de gestion (sans Internet), sites reliés par VPN + VXLAN ───────────┐
│                                                                                     │
│  Borne Barbacane en ligne (ISO distincte de la v1)                                  │
│   usbsas + analyseur + interface (comme v1)                                         │
│   barbacane-agent  ── connexion sortante unique, TLS 1.3, mTLS ──┐                  │
│     • récupère : politique, méthodes d'identification, clés      │                  │
│       enrôlées, mises à jour .bcu                                │                  │
│     • envoie : état, rapports, journaux, quarantaine chiffrée    │                  │
│     • serveur injoignable → borne bloquée                        │                  │
│                                                                  ▼ port aléatoire        │
│  Serveur Barbacane (ISO durcie, Docker embarqué)                                    │
│   ┌ passerelle-bornes (Rust) : seul point d'entrée des bornes, mTLS, quotas         │
│   ├ interface web d'administration : sur une INTERFACE RÉSEAU DISTINCTE (poste      │
│   │   d'administration), TLS, authentification forte, rôles                        │
│   ├ identité : comptes locaux, PIN, connecteur AD/LDAP (lecture seule)              │
│   ├ PKI interne : autorité intermédiaire en ligne ; racine HORS LIGNE               │
│   ├ diffusion des mises à jour : réception du .bcu, vérification, distribution      │
│   ├ base PostgreSQL : bornes, sites, utilisateurs, clés, politiques, rapports       │
│   ├ quarantaine chiffrée + purge à 30 jours                                         │
│   └ journal d'audit chaîné et signé                                                 │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Borne en ligne

- Même base que la v1 (usbsas, analyseur, interface, mises à jour signées).
- Nouveau service `barbacane-agent` (Rust, utilisateur dédié, durci comme les autres) :
  seul processus autorisé à joindre le réseau, et uniquement le serveur.
- L'interface ne parle qu'à l'agent local (socket Unix), jamais au réseau.
- Identification ou authentification de l'utilisateur à l'écran selon le mode reçu (§3.3) ;
  la vérification se fait par le serveur (PIN et mot de passe jamais stockés sur la borne).
- Blocage : sans connexion valide au serveur (délai court, configurable), l'interface
  affiche « Borne hors service : serveur de gestion injoignable » et refuse toute clé.

### 3.2 Port d'écoute

Le serveur n'écoute pas sur 443 : à l'installation, un port TCP est tiré au hasard dans
une plage haute (par exemple 20000–60000, hors ports connus), affiché à l'administrateur
et inscrit dans le jeton d'enrôlement des bornes ; il reste modifiable. Un scan rapide
(les 1 000 ports courants de nmap) ne le voit pas. C'est une mesure de **discrétion**,
pas de sécurité : un scan complet le trouve. La protection reste le mTLS (une connexion
sans certificat de borne valide est coupée avant tout échange applicatif) et le pare-feu
du serveur (seules les adresses des bornes enrôlées sont acceptées).

### 3.3 Utilisateurs : identification et authentification

- **Identification** : savoir *qui* fait quoi, pour la journalisation. L'utilisateur
  se déclare (code d'un badge lu, ou nom choisi) ; rien ne prouve que c'est lui.
- **Authentification** : être *sûr* que c'est cet utilisateur, par un élément qu'il est
  seul à détenir ou connaître.

L'administrateur choisit le mode, par site ou par borne :

| Mode | Ce qui est demandé | Usage |
|---|---|---|
| Aucun | rien (comme la v1) | borne en libre service, journal anonyme |
| Identification | identifiant tapé à l'écran (ou, plus tard, badge simple lu) | traçabilité de qui a fait quoi |
| Authentification | identifiant tapé + PIN personnel ou mot de passe (compte local ou annuaire AD/LDAP) ; plus tard badge + PIN | preuve de l'identité |

Première version : **aucun lecteur**, l'identifiant se tape sur le clavier virtuel de
l'écran tactile (déjà utilisé pour le PIN et les mots de passe d'archives). Le serveur
refuse un identifiant inconnu dans les deux modes. Le badge est une option ultérieure.

Le badge simple (code lu, type Mifare Classic ou 125 kHz) se copie facilement : seul, il
ne vaut qu'**identification**. Combiné à un PIN, il vaut authentification. Lecteur : un
lecteur de badges USB qui se présente comme un clavier envoie le code comme une frappe ;
la borne bloquant les claviers (usbsas-hid), il faut l'autoriser explicitement par son
identifiant USB et n'accepter de lui qu'une suite de chiffres de longueur fixe, sur l'écran
d'identification uniquement. Les cartes à puce avec certificat restent pour plus tard.

### 3.4 Serveur

- ISO Debian durcie, installation automatique comme la borne ; images Docker chargées
  depuis l'ISO (aucun registre externe).
- Deux interfaces réseau : **bornes** (passerelle uniquement) et **administration**
  (interface web uniquement), séparées par le pare-feu.
- Conteneurs non privilégiés, systèmes de fichiers en lecture seule, secrets hors des
  images, journaux vers le journal d'audit.
- L'analyse reste sur la borne. Éventuelle analyse complémentaire des fichiers suspects (bac à sable, autres moteurs) :
  **phase ultérieure**, dans une VM séparée et non un simple conteneur.

## 4. Flux

| Flux | Sens | Contenu | Protection |
|---|---|---|---|
| Enrôlement | borne → serveur | jeton à usage unique + demande de certificat (CSR) | jeton limité dans le temps, lié à un site ; CSR signé par l'autorité intermédiaire |
| Battement | borne → serveur | état, version, âge des signatures, espace disque | mTLS |
| Politique | borne ← serveur (à l'initiative de la borne) | méthodes d'identification, clés enrôlées, règles | signée par le serveur, versionnée, validée par la borne |
| Mise à jour | borne ← serveur | `.bcu` + `.minisig` | signature hors ligne vérifiée par la borne |
| Identification / authentification | borne → serveur | code du badge, plus PIN ou mot de passe selon le mode | mTLS ; aucune conservation sur la borne |
| Rapports, journaux | borne → serveur | JSON, journald | mTLS ; file d'attente locale bornée |
| Quarantaine | borne → serveur | fichiers malveillants ou suspects | chiffrés pour la clé publique de quarantaine du serveur, puis mTLS |

## 5. Conformité

- **ANSSI** : TLS 1.3 (ou 1.2 avec suites recommandées), PKI conforme au RGS, journalisation
  selon les recommandations ANSSI, durcissement Debian (guide de configuration GNU/Linux).
- **Diffusion Restreinte** : la quarantaine peut contenir des données DR. Le serveur
  traite donc des données DR et doit être **homologué à ce niveau** ; la liaison entre
  sites peut exiger un **chiffreur agréé** (à valider avec l'autorité d'homologation,
  le VPN site à site seul peut ne pas suffire). Prévoir une option « quarantaine
  désactivée » pour les sites qui ne peuvent pas l'accepter.
- **RGPD** : registre de traitement, durées de conservation (1 an / 30 jours) appliquées
  par purge automatique, accès aux données selon les rôles, information des utilisateurs.

## 6. Analyse des risques (principales menaces)

| Menace | Mesure |
|---|---|
| Serveur compromis qui pousse du code | Aucun code poussé ; `.bcu` signés hors ligne et vérifiés par la borne. |
| Serveur compromis qui affaiblit la politique | Valeurs minimales codées en dur dans la borne (analyse toujours obligatoire, jamais de désactivation de ClamAV) ; politique signée et journalisée. |
| Usurpation d'une borne | Certificat client par borne, clé non exportable ; révocation dans l'interface web. |
| Badge simple copié | Mode « identification » seulement ; l'administrateur impose badge + PIN là où l'identité doit être prouvée. |
| Faux lecteur de badges (clavier injecté) | Lecteur autorisé par identifiant USB, saisie limitée aux chiffres de longueur fixe et au seul écran d'identification. |
| Vol du jeton d'enrôlement | Usage unique, durée courte, lié à un site, journalisé. |
| Attaque réseau sur la borne | Aucun port en écoute ; une seule destination autorisée. |
| Fausse clé « connue » (VID/PID/SN falsifiés) | Identifiants USB = traçabilité seulement ; analyse toujours obligatoire. |
| Fuite de la quarantaine | Chiffrement de bout en bout, accès réservé, purge à 30 jours. |
| Panne du serveur | Bornes bloquées par conception : procédure de reprise documentée, sauvegarde et restauration testées ; redondance prévue plus tard. |
| Administrateur malveillant | Rôles séparés, journal d'audit inaltérable consultable par l'auditeur. |

## 7. Découpage en étapes

1. **Socle** : ISO serveur (Debian durcie + Docker embarqué), PKI interne, passerelle
   mTLS, enrôlement par jeton, battement et supervision dans l'interface web.
2. **Mises à jour** : dépôt du `.bcu` dans l'interface web, diffusion, suivi par borne.
3. **Rapports et journaux** : collecte, recherche, export, conservation 1 an.
4. **Utilisateurs** : identifiant tapé à l'écran (identification), identifiant + PIN ou
   mot de passe avec comptes locaux (authentification), puis AD/LDAP, puis badges ;
   mode choisi par site ou par borne.
5. **Clés USB** : enrôlement par fabricant + numéro de série, politiques par site.
6. **Quarantaine** chiffrée, purge 30 jours, option de désactivation.
7. **Plus tard** : badges, analyse complémentaire en bac à sable, serveur central de
   consolidation multi-sites, redondance.

Chaque étape : conception détaillée, tests automatisés, preuves, CI verte.

## 8. Questions ouvertes

- Badges plus sûrs (carte à puce avec certificat, DESFire) : plus tard ; prévoir une interface d'identification
  extensible.
- Exigences exactes de l'autorité d'homologation (chiffreur, produits qualifiés).
- Où conserver la racine de la PKI (support hors ligne, coffre) et qui la détient.
- Durée de blocage acceptable : délai de grâce de quelques minutes après une coupure
  réseau courte, ou blocage immédiat ?

## 9. Évolution prévue : serveur central

Plus tard, un serveur central consolidera plusieurs serveurs de site par le VPN
site à site. Rôle à définir (consolidation seule recommandée : chaque site reste maître
de ses bornes). Les choix de l'étape 1 (identifiants uniques de site, PKI hiérarchique)
doivent le permettre sans refonte.

## 9 bis. Téléchargement de l'ISO des bornes depuis le serveur

L'ISO du serveur **embarque l'ISO de la borne en ligne** de la même version (construite
dans la même publication). L'interface web (rôle administrateur) propose :

- **ISO générique** : la même pour toutes les bornes, sans secret ; l'enrôlement se fait
  au premier démarrage avec un jeton (saisi ou sur clé USB). Empreinte sha256 et
  signature affichées pour vérification.
- **ISO personnalisée** (option) : générée à la demande avec un jeton d'enrôlement à
  usage unique, l'adresse, le port et le site déjà inclus ; la borne s'enrôle seule au
  premier démarrage. Cette ISO contient un secret : durée de validité courte (24 h par
  défaut), usage unique, téléchargement journalisé, à détruire après usage.
- Les deux sont produites **sans Internet**, par le serveur lui-même (remaster de l'ISO
  embarquée, comme `build-iso.sh`).
- Une mise à jour du serveur (`.bcu` serveur signé) apporte la nouvelle ISO des bornes ;
  les bornes déjà installées se mettent à jour par les `.bcu` habituels, sans
  réinstallation.
- L'ISO hors ligne (v1) peut aussi être proposée au téléchargement, signalée comme
  « borne sans serveur ».

## 10. Organisation du dépôt (sans casser la v1)

Un seul dépôt `Titouanlvt/Barbacane`. **La v1 hors ligne reste le produit de référence** :
`git clone` puis `systeme/iso/build-iso.sh` doit continuer à produire exactement la
même borne hors ligne, sans aucun code réseau.

```
noyau/            inchangé (lecture USB, issu d'usbsas)
borne/            inchangé (client, analyzer, admind, parcours, update, optique)
borne/agent/      NOUVEAU : barbacane-agent (borne en ligne uniquement)
serveur/          NOUVEAU : passerelle, interface web, identité, PKI, images Docker
serveur/iso/      NOUVEAU : ISO du serveur
systeme/iso/      build-iso.sh --profil hors-ligne (défaut, = v1) | en-ligne
tests/            + tests/suite/ (serveur, agent, bout en bout)
```

Règles :
- Le profil **hors-ligne est le défaut** : sans option, `build-iso.sh` produit la v1.
- Le paquet `barbacane-agent` et toute configuration réseau n'existent **que** dans le
  profil en-ligne. Un test de CI ouvre l'ISO hors ligne et **échoue** si elle contient
  l'agent, un paquet réseau ou une règle de pare-feu autorisant une sortie.
- La CI existante (construction de l'ISO hors ligne + `tests/iso/qemu.sh`) reste
  obligatoire avant toute fusion dans `main` ; les nouveaux jobs (serveur, ISO en ligne)
  s'y ajoutent sans la remplacer.
- La documentation garde un parcours v1 inchangé (`docs/guide-installation-poste.md`) ;
  la suite a ses propres documents (`docs/suite/`).
- Versions : v1.x pour la borne hors ligne ; la suite démarre en v2.0 (borne en ligne +
  serveur). Une étiquette git par version publiée.
