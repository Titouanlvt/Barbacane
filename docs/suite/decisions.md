# Décisions de la suite (journal)

L'utilisateur est seul sur le projet : il n'y a pas d'autorité d'homologation (AH) à attendre.
Les points que la conception renvoyait à l'AH sont tranchés ici, toujours dans le sens **le plus
sûr**, avec la raison. Une décision ne change que par une nouvelle entrée datée.

| N° | Date | Sujet | Décision | Raison |
|---|---|---|---|---|
| D1 | 19/11/2026 | Données Diffusion Restreinte sur le serveur | **Aucune.** Pas de quarantaine (non implémentée), noms de fichiers jamais transmis en clair (sha256 + extension + taille), identifiants pseudonymisés hors rôle auditeur. | Le serveur reste un SI non DR : pas d'homologation DR, pas de chiffreur agréé obligatoire, fuite sans gravité DR. |
| D2 | 19/11/2026 | Quarantaine | **Non implémentée** en v2.0 (étape 6 de la conception abandonnée pour l'instant). | Conséquence de D1 ; c'est la fonction la plus risquée (fichiers malveillants hors de la borne). |
| D3 | 19/11/2026 | Port d'écoute de la passerelle | **Port aléatoire** tiré à l'installation (20000–60000, hors ports connus), inscrit dans le jeton. | Choix de l'utilisateur ; la sécurité repose sur mTLS + CRL + pare-feu, le port n'est que discrétion. |
| D4 | 19/11/2026 | Liaison entre sites | **Routée (niveau 3) et chiffrée** (IPsec/WireGuard entre routeurs de site) ; pas de niveau 2 étendu. Le chiffrement entre sites est un prérequis d'exploitation, hors du produit. | Pas de domaine de diffusion partagé ; le mTLS protège déjà chaque flux de bout en bout. |
| D5 | 19/11/2026 | Racine de la PKI | **Hors ligne**, générée sur une VM isolée (sans carte réseau) du lab pour les essais ; clé de TEST marquée « TEST — NE PAS UTILISER EN PRODUCTION » dans son nom distinctif. Procédure de la vraie racine documentée (`politique-certification.md` §8). | La racine ne doit jamais toucher un système en réseau ; la clé de test ne doit pas pouvoir être confondue. |
| D6 | 19/11/2026 | Algorithmes | ECDSA **P-384** / SHA-384 pour les CA, **P-256** / SHA-256 pour bornes et serveur ; TLS 1.3 seul, suites `TLS_AES_256_GCM_SHA384` et `TLS_AES_128_GCM_SHA256`, groupes `secp384r1`, `secp256r1`. | Conformes aux recommandations ANSSI (RGS B1/B2 cryptographie) et pris en charge partout (rustls, TPM 2.0). |
| D7 | 19/11/2026 | Révocation | **CRL** signée par chaque CA intermédiaire, durée 7 jours, republiée chaque jour ; vérifiée par la passerelle à chaque connexion. Pas d'OCSP. | Rien n'est joignable hors du LAN ; une CRL locale suffit à 100 bornes. |
| D8 | 19/11/2026 | TPM des bornes en ligne | **Exigé** ; dans le lab (VM sans TPM matériel), TPM logiciel `swtpm` déclaré par Proxmox, marqué comme tel dans les preuves. | Conception §2.3 ; la preuve de lab ne vaut pas preuve sur matériel. |
| D9 | 19/11/2026 | Interface web | Pages générées par le serveur Rust (axum + gabarits), **sans JavaScript** sauf exception justifiée ; charte v2 (`docs/charte/web/jetons.css`). | Surface minimale ; la charte v2 fournit des composants CSS seuls. |
| D10 | 19/11/2026 | Conteneurs | **Podman sans root**, images construites hors ligne et chargées depuis l'ISO, système de fichiers en lecture seule. | Pas de démon root ; pas d'Internet. |
| D11 | 19/11/2026 | Mode utilisateur par défaut | **Aucun** (comme la v1) tant que l'administrateur n'a rien choisi ; Identification et Authentification activables par site. | Ne change pas le comportement attendu d'une borne neuve ; Aucun n'est plus interdit puisque la quarantaine n'existe pas (D2). |
| D12 | 19/11/2026 | Profil de l'ISO borne | `build-iso.sh` sans option = **hors-ligne**, identique à la v1 ; l'agent n'existe que dans `--profil en-ligne` ; un test de CI refuse toute trace réseau dans l'ISO hors ligne. | La v1 reste le produit de référence (conception §10). |
| D13 | 19/11/2026 | GPU du lab | Pas de passthrough de la RTX 4000 (seule carte d'affichage de l'hôte) ; rendus 3D en CPU. | Règle de l'exception accordée (`docs/lab/gpu-passthrough.md`). |
