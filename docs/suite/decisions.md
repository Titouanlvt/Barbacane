# Décisions de la suite (journal)

Niveau visé : **Diffusion Restreinte** (DR, II 901 du 28/01/2015 ; l’IGI 1300 ne couvre que Secret et Très Secret). Il n'y a pas d'autorité d'homologation (AH) :
Claude en tient le rôle « au mieux », en appliquant les recommandations ANSSI pour un SI DR. Claude ne
peut **ni homologuer ni fournir de produit agréé** : ce qui l'exige est listé à part dans
`dossier-homologation.md` (§6 et §7). Une décision ne change que par une nouvelle entrée datée.

| N° | Date | Sujet | Décision | Raison | Alternative écartée |
|---|---|---|---|---|---|
| D1 | 19/11/2026 | Statut du serveur | Le serveur est **traité comme un SI DR** : disque chiffré, poste d'administration dédié, authentification à deux facteurs, journalisation et audit renforcés, **aucune interconnexion avec un réseau de niveau inférieur**. | Rapports, journaux et (option) quarantaine peuvent révéler des informations DR ; la borne traite des supports DR. | Serveur « non DR » sans aucune donnée sensible : impose de ne jamais activer la quarantaine et rend fragile toute évolution. |
| D2 | 19/11/2026 | Noms de fichiers | **Jamais transmis en clair** : sha256, extension et taille seulement ; nom complet consultable sur la borne. | Minimisation : un nom de fichier peut être lui-même une information DR. | Noms en clair (confort d'enquête) : expose du DR dans tous les rapports. |
| D3 | 19/11/2026 | Quarantaine | **Implémentée (étape 11), désactivée par défaut.** Fichiers chiffrés sur la borne pour une clé dont la partie privée n'est pas sur le serveur ; accès conforme DR (rôle analyste, double validation, journalisation). *(Verrou retiré le 21/11/2026, voir plus bas.)* À l'origine : activation refusée par le code tant que `dossier-homologation.md` n'indique pas les mesures DR du serveur comme en place (champ machine `mesures_dr_serveur: en place`, §8). | Fonction utile à l'investigation mais la plus risquée ; le verrou évite une activation « par commodité ». | Pas de quarantaine du tout (perte d'investigation) ; quarantaine active par défaut (DR sur le serveur dès l'installation). |
| D4 | 19/11/2026 | Port d'écoute de la passerelle | **Port aléatoire** tiré à l'installation (20000–60000, hors ports connus), inscrit dans le jeton d'enrôlement. | Choix de l'utilisateur ; discrétion. La sécurité repose sur mTLS + CRL + pare-feu. | Port fixe documenté (filtrage et homologation plus simples) : reste possible par réglage. |
| D5 | 19/11/2026 | Liaison entre sites | **Routée (niveau 3) et chiffrée.** Lab : **WireGuard** entre routeurs virtuels. **Production : chiffreur IP agréé DR** (produit à acquérir, §7 du dossier). | Un VPN logiciel non agréé ne suffit pas pour du DR hors d'une zone protégée. | Niveau 2 étendu (VXLAN) : domaine de diffusion partagé ; VPN logiciel en production : non agréé. |
| D6 | 19/11/2026 | Cryptographie | Conforme au **RGS** et au **guide des mécanismes cryptographiques** de l'ANSSI : ECDSA **P-384**/SHA-384 (CA), **P-256**/SHA-256 (bornes, serveur), TLS 1.3 seul (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, groupes `secp384r1`, `secp256r1`), AES-256-GCM pour les données au repos, Argon2id pour les PIN, Ed25519 (minisign) pour les `.bcu` (déjà en v1). | Mécanismes recommandés, disponibles dans rustls, le TPM 2.0 et Debian. | RSA 2048 (taille limite), TLS 1.2 (suites à risque), SHA-1. |
| D7 | 19/11/2026 | Racine PKI | **Hors ligne.** Lab : générée sur une VM `barbacane-9xx` **sans carte réseau**, clé de TEST marquée « TEST — NE PAS UTILISER EN PRODUCTION ». Production : cérémonie documentée (`politique-certification.md` §8). | La racine ne doit jamais toucher un système en réseau ; la clé de test ne doit pas pouvoir être confondue. | Racine sur le serveur (une compromission du serveur emporterait toute la PKI). |
| D8 | 19/11/2026 | Révocation | **CRL** par CA intermédiaire, validité 7 jours, republiée chaque jour ; la passerelle refuse si la CRL est expirée. | Rien n'est joignable hors du LAN ; fail-closed. | OCSP (service supplémentaire exposé, inutile à 100 bornes). |
| D9 | 19/11/2026 | TPM | **Exigé** sur bornes en ligne et serveur. Lab : `swtpm` (TPM logiciel de Proxmox), marqué comme tel dans les preuves. | Clés non exportables, disque scellé. | Clés dans des fichiers (exportables en cas de vol). |
| D10 | 19/11/2026 | Interface web | Pages générées par le serveur Rust, **sans JavaScript** sauf exception justifiée ; charte v2. Joignable uniquement sur l'interface d'administration. | Surface minimale, pas de dépendance navigateur. | Application JavaScript monopage (surface, dépendances). |
| D11 | 19/11/2026 | Conteneurs | **Podman sans root**, images construites hors ligne, chargées depuis l'ISO, racine en lecture seule. | Pas de démon root, pas d'Internet. | Docker (démon root) ; paquets installés directement (pas d'isolation). |
| D12 | 19/11/2026 | Profils de l'ISO borne | `build-iso.sh` sans option = **hors-ligne**, identique à la v1 ; l'agent n'existe que dans `--profil en-ligne` ; `tests/iso/hors-ligne.sh` refuse toute trace réseau. | La v1 reste le produit de référence (conception §10). | Une seule ISO avec l'agent désactivé (code réseau présent sur une borne hors ligne). |
| D13 | 19/11/2026 | Mode utilisateur par défaut | **Aucun** (comme la v1) ; Identification ou Authentification choisies par site. Aucun est **interdit si la quarantaine est activée**. | Comportement d'une borne neuve inchangé ; traçabilité nominative seulement où elle est justifiée (AIPD). | Authentification obligatoire partout (surcoût, données personnelles inutiles). |
| D14 | 19/11/2026 | GPU du lab | Pas de passthrough de la RTX 4000 (seule carte d'affichage de l'hôte) ; rendus 3D en CPU. | Règle de l'exception accordée (`docs/lab/gpu-passthrough.md`). | Passthrough malgré tout (hôte sans console locale). |

**Écart à D4 (20/11/2026, `serveur-iso-bornes.md`), à faire valider par l'utilisateur et l'AH** : quand
le serveur embarque les ISO des bornes, l'ISO générique en ligne porte déjà l'adresse et les ports de
la passerelle (pare-feu et `agent.toml` de la borne). Le port est donc **tiré une fois, à la
construction** (`build-iso-serveur.sh --port N`, valeur aléatoire choisie par le constructeur), et
non à l'installation. Discrétion conservée (port non standard, propre au site) ; sécurité inchangée
(mTLS + CRL + pare-feu).

## 21/11/2026 — décisions de l'utilisateur

- **D4 (écart validé)** : le port de la passerelle est fixé à la construction de l'ISO serveur (`--port` obligatoire avec les ISO de bornes embarquées), plus tiré à l'installation.
- **Annuaire LDAPS** : TLS 1.3 par défaut ; TLS 1.2 accepté **en option**, désactivée par défaut, suites ECDHE-AES-GCM seulement, activation auditée.
- **Dossier d'homologation** : pas installé par l'ISO serveur (la quarantaine reste donc inactivable sur un serveur installé tant que ce choix n'est pas revu ; levé par la décision suivante).
- **Quarantaine** : « La quarantaine est une option que l'administrateur choisit d'activer ou non. » Le verrou `mesures_dr_serveur` est retiré du logiciel (la ligne reste dans le dossier d'homologation, à titre d'information) ; gardés : désactivée par défaut, activation et export par double validation, désactivation par un seul, audit, AES-256-GCM, 30 jours. Avertissement DR affiché avant l'activation et journalisé avec elle (`docs/suite/quarantaine.md`).
- **Blanchiment et politique USB** : le blanchiment reste autorisé sur toute clé, même non enrôlée et même avec une politique de site (il n'écrit aucune donnée sortante) ; seule la sortie de fichiers (copie, gravure) exige une clé enrôlée pour la sortie.
- **Publication** : « Les points PRÉVU seront la v2.1.0. » La **v2.0.0** sort avec ce qui est FAIT ; tous les points PRÉVU (`docs/suite/README.md`, colonne PRÉVU) sont reportés en **v2.1.0**.

## Décisions du 22/11/2026 (suite à l'étude E1, `etude-conformite-e1.md`)
- **Niveaux visés : les trois**, par profil de déploiement :
  - **SI non sensible** : hygiène ANSSI + RGPD/CNIL ;
  - **Diffusion Restreinte (II 901)** : Borne autonome et suite en ligne, sous homologation de l'autorité de l'organisme ;
  - **Classifié (IGI 1300)** : **Borne autonome hors ligne seule**, intégrée à un SI classifié déjà homologué, sur décision de son autorité ; la suite en ligne n'est pas prévue pour ce niveau. Barbacane ne revendique aucune conformité IGI 1300 par lui-même.
  Chaque fonction de la feuille de route indique les profils où elle est permise (ex. Dépôt vers le SI, Contrôle postes : à soumettre à l'analyse d'interconnexion II 901).
- **Conservation des rapports et journaux : configurable par l'administrateur** dans la Console (valeur par défaut 1 an, plafond imposé, changement audité et par double validation), avec purge effective des rapports de passage, rotation du journal d'audit par segments scellés et purge des sauvegardes (version 2.3). L'AIPD est mise à jour en conséquence.
- **CSPN : non** (pas de certification visée pour l'instant).
- **E1-bis (grilles ANSSI ligne à ligne, registre, plan MCS) : non** ; les écarts bloquants de l'étude restent traités dans les versions 2.2 à 2.4.
