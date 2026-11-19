# Revue de sécurité et de conformité — conception Barbacane suite (19/11/2026)

Relecture faite sans contexte préalable (agent relecteur indépendant), sur la version
du document antérieure à la révision du 19/11. Chaque constat renvoie à la section de
`docs/conception-barbacane-suite.md` qui le traite désormais.

| N° | Gravité | Constat | Traitement |
|---|---|---|---|
| C1 | Critique | Quarantaine dite « de bout en bout » mais chiffrée pour une clé détenue par le serveur | Quarantaine désactivée par défaut ; clé privée hors serveur, VM d'analyse (§3.6) |
| C2 | Critique | Le serveur devient un SI DR sans que l'architecture en tire les conséquences | Pas de DR sur le serveur par défaut ; variante DR homologuée à part ; AH avant l'étape 1 (§5, §8) |
| C3 | Critique | Politique signée par le serveur : inutile face à un serveur compromis | Plancher signé hors ligne, politique bornée, version monotone (§3.7) |
| C4 | Critique | Mots de passe d'annuaire saisis sur la borne ; pas d'anti force brute | PIN Barbacane, aucun mot de passe d'annuaire sur la borne, verrouillage, LDAPS (§3.3) |
| E1 | Élevé | Énumération des identifiants | Réponse identique en mode authentification (§3.3) |
| E2 | Élevé | Jeton / ISO personnalisée volés ; pare-feu incompatible avec l'enrôlement ; pas d'authentification du serveur au premier contact | Validation par un administrateur, jeton 1 h, CA serveur épinglée dans l'ISO, pare-feu par sous-réseau (§3.5, §9) |
| E3 | Élevé | Mode « Aucun » incompatible avec la quarantaine | Interdit si la quarantaine est activée (§3.3) |
| E4 | Élevé | PKI incomplète (révocation, durée, renouvellement, CA séparées) | CRL locale, certificats 90 jours renouvelés, deux CA, politique de certification (§3.5, §3.1) |
| E5 | Élevé | Clé de borne exportable sans TPM | TPM 2.0 exigé, disque scellé (§2.3) |
| E6 | Élevé | Borne compromise absente de l'analyse (flood, faux rapports, XSS) | Schéma strict, quotas, échappement (§2.7, §6) |
| E7 | Élevé | Blocage total = point unique de défaillance ; sauvegarde non conçue | Délai de grâce borné, file locale, sauvegarde/restauration testée (§3.1, §3.8) |
| E8 | Élevé | Heure absente | Heure du serveur par le canal authentifié (§3.11) |
| E9 | Élevé | Audit réécrit par root | Empreintes exportées hors du serveur, séparation des rôles (§3.9) |
| E10 | Élevé | Secrets du serveur non décrits | TPM / fichiers chiffrés, disque chiffré, rotation (§3.4) |
| M1 | Moyen | Port aléatoire : gain faible, complique l'homologation | **Maintenu (choix de l'utilisateur)**, réserve AH notée (§3.2) |
| M2 | Moyen | VXLAN de niveau 2 entre sites | Liaison routée de niveau 3, chiffrée (§1, §5) |
| M3 | Moyen | Docker : démon root | Podman sans root (§3.4) |
| M4 | Moyen | Administration web peu précisée | Poste dédié, 2 facteurs, double validation (§3.10) |
| M5 | Moyen | RGPD incomplet | AIPD, information, pseudonymisation, purges des sauvegardes (§5) |
| M6 | Moyen | Lecteur de badges émulant un clavier | Pas de lecteur en v2.0 ; CCID plus tard (§3.3) |
| M7 | Moyen | Clé de signature du `.bcu` serveur non précisée | Clé distincte, étiquette d'usage, anti-retour (§9) |
| M8 | Moyen | Empreinte de l'ISO vérifiée par la source elle-même | Vérification hors bande (§9) |
| F1–F4 | Faible | Numérotation, TLS 1.2, file pleine, purge vs sauvegardes | Corrigés (§1, §3.1, §3.8) |

Points jugés bons et conservés : borne sans port en écoute ; clé des mises à jour hors
ligne et revérifiée ; décision d'analyse locale ; identifiants USB = traçabilité seulement ;
distinction identification / authentification ; interfaces réseau séparées ; ISO serveur
construite hors ligne ; profil hors ligne par défaut protégé par la CI ; racine PKI hors
ligne ; bac à sable en VM.

Reste à faire valider par l'autorité d'homologation : périmètre DR, port aléatoire,
liaison entre sites. Références ANSSI et IGI 1300 non vérifiées mot à mot.
