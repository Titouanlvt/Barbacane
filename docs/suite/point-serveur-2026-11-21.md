# Point serveur — notes (21/11/2026)

Source : labo Proxmox (serveur 960, borne 970) et retours de l'utilisateur.

## Déjà relevé (labo)

1. Borne en ligne : le message « Jeton enregistré : la demande va être envoyée » reste affiché après l'enrôlement réussi.
2. Borne : après « Arrêter ici », l'écran reste sur « Clé détectée » jusqu'au retrait de la clé (à comparer avec la v1).
3. Serveur : un nom de site doit être `site-<n>` ; un nom libre (« labo ») est refusé.
4. Serveur : le certificat HTTPS de l'interface ne se valide pas contre la racine de TEST (chaîne à vérifier) → avertissement du navigateur.
5. Serveur : `barbadmin` doit changer son mot de passe à la première connexion (voulu) — à documenter dans le manuel.
6. Serveur : aucun moyen dans l'interface web de créer un 2e administrateur (fait à la main sur la console série) ; or la quarantaine et les exports exigent 2 administrateurs.
7. Banc QEMU : l'accès HTTPS à l'interface d'administration échoue sur le banc (réseau « na »), alors que le vrai réseau fonctionne.
8. Version : le projet affiche encore 0.1.0 (pied de page de la borne, Cargo.toml) au lieu de 2.0.x.
9. Quarantaine : la borne n'envoie pas encore les fichiers bloqués (v2.1.0).
10. Règle D13 (mode « Aucun » interdit si quarantaine active) non appliquée (v2.1.0).

## Retours de l'utilisateur

11. Interface web : configurer l'annuaire LDAP et l'envoi Syslog depuis l'interface (aujourd'hui fichiers de configuration).
12. Statistiques de supervision des bornes : courbes, graphiques (activité, disponibilité…).
13. Listes déroulantes dans l'interface (au lieu de champs à saisir, ex. sites).
14. Gestion des utilisateurs : créer, supprimer, modifier ; mode local complet, LDAP, et liaison d'un compte local à un compte LDAP existant.
15. PIN à 6 chiffres pour entrer dans l'administration de la borne, lié à un compte administrateur (traçabilité : qui fait quoi sur quelle borne).
16. Chiffrement du disque des bornes (vol de la borne).
17. À réfléchir — clés USB enrôlées : mode avec certificat géré par l'utilisateur qui authentifie la clé en plus de l'enrôlement, et rend la clé lisible sur les postes Windows/Linux via un agent (.msi / .deb) ; type « contrôle des périphériques » (device control, comme Ivanti Device Control) pour les supports de stockage de masse.
18. Statistiques des passages : ex. un même fichier vu plusieurs fois, vu plusieurs fois en menace (par empreinte SHA-256).
19. Liste de fichiers déjà autorisés à ne pas re-analyser (ex. .iso officielles).

## Décisions (21/11, questions)

- Utilisateurs (14) : mode HYBRIDE — comptes locaux créés/modifiés/supprimés dans l'interface web + LDAP si configuré ; liaison d'un compte local à un compte LDAP existant ; les comptes locaux fonctionnent si l'annuaire est indisponible.
- PIN borne (15) : un PIN à 6 chiffres par administrateur, géré sur le serveur ; la borne garde un cache haché, utilisable hors connexion pendant une durée limitée (ex. 7 jours) ; actions journalisées au nom de l'administrateur et remontées au retour du réseau.
- Chiffrement des bornes (16) : LUKS2 scellé TPM, démarrage automatique (comme le serveur) ; clé de secours TÉLÉCHARGEABLE depuis le serveur, dans la gestion des bornes. À sécuriser : stockée chiffrée sur le serveur, accès administrateur seulement (double validation à étudier), chaque téléchargement audité.
- Liste blanche (19) : par empreinte SHA-256 exacte seulement, gérée sur le serveur et diffusée aux bornes.
- Device control (17) : ÉTUDE d'abord — conception écrite (chiffrement de la clé, certificat par utilisateur/clé, agents .msi/.deb, révocation, PKI), décision ensuite.
- Statistiques (12, 18) : graphiques intégrés dessinés par le serveur en SVG, sans JavaScript ; export CSV.
- Syslog (11) : RFC 5424, au choix TLS (RFC 5425, CA du collecteur épinglée) ou UDP/TCP en clair avec avertissement affiché.
- Découpage :
  - v2.0.1 = correctifs seulement (détection USB ppoll, ISO serveur complète, petits défauts du labo 1-8).
  - v2.1.0 = sécurité d'abord : TPM serveur, PKI de production, chiffrement des bornes (16), PIN par administrateur (15), gestion des utilisateurs hybride (14), LDAP et Syslog dans l'interface (11), liste blanche SHA-256 (19), quarantaine envoyée par la borne (9), D13 (10).
  - v2.2 = statistiques (12, 18), listes déroulantes (13), device control (17, après étude).

## Découpage fin (demande utilisateur : « le moins de debug possible »)

Règle : une version = une seule famille de fonctions, dans l'ordre des dépendances ; chaque version a ses tests, la non-régression 950 si la borne change, la preuve labo Proxmox (960/970), puis publication avant de commencer la suivante.

| Version | Contenu | Dépend de |
|---|---|---|
| 2.0.1 | Correctifs : détection USB (ppoll), ISO serveur complète (web, registre, audit), banc QEMU admin, numéro de version 2.0.x, chaîne du certificat HTTPS | — |
| 2.0.2 | Petits défauts du labo : message de jeton, écran « Clé détectée », noms de site libres, doc barbadmin | 2.0.1 |
| 2.1.0 | Comptes administrateurs dans l'interface web (créer, supprimer, certificat .p12, rôles) + règle D13 | 2.0.x |
| 2.2.0 | PIN à 6 chiffres par administrateur sur la borne (cache haché limité, journal au nom de l'admin) | 2.1.0 |
| 2.3.0 | Chiffrement des bornes (LUKS2 + TPM) et clé de secours téléchargeable (chiffrée, auditée) | 2.1.0 |
| 2.4.0 | Utilisateurs hybride : comptes locaux CRUD, LDAP configurable dans l'interface, liaison local ↔ LDAP | 2.1.0 |
| 2.5.0 | Syslog configurable dans l'interface (TLS ou clair avec avertissement) | 2.1.0 |
| 2.6.0 | Liste blanche par SHA-256 (serveur → bornes) | 2.0.x |
| 2.7.0 | Quarantaine envoyée par la borne | 2.3.0 |
| 2.8.0 | TPM du serveur pour ses secrets + PKI de production et cérémonie | 2.1.0 |
| 2.9.0 | Ergonomie : listes déroulantes + statistiques SVG (bornes, passages, fichiers vus plusieurs fois) + export CSV | 2.4.0 |
| 3.0.0 | Device control (clés à certificat, agents .msi/.deb) — après étude écrite | 2.8.0 |

## 3.0.0 — Device control : décisions (21/11)

- Protection : la borne écrit les fichiers sains dans un VOLUME CHIFFRÉ sur la clé ; illisible sans l'agent et un certificat autorisé.
- Identité : certificat lié à l'UTILISATEUR (ou carte à puce), éventuellement aussi à un groupe.
- Agent poste (.msi Windows / .deb Linux) : vrai device control — tout stockage USB non passé par une borne est bloqué ; seules les clés Barbacane valides sont montées.
- Politiques gérées depuis le serveur, par poste / groupe de postes / utilisateur : actions autorisées (ex. postes d'administration), volume sortant limité (Go par jour…), etc.
- Écriture depuis un poste : CHOIX PAR POLITIQUE (lecture seule ; écriture puis re-analyse obligatoire ; écriture libre pour des postes désignés).

### Architecture proposée (à valider, document de conception à écrire)

1. Serveur de politiques = le serveur Barbacane (nouveau service « postes »), même PKI : CA « postes » et CA « utilisateurs » séparées de la CA des bornes.
2. Clé USB : volume chiffré AES-256-XTS ; clé de volume aléatoire, enveloppée pour chaque certificat utilisateur autorisé (et un séquestre serveur pour la récupération, accès double validation) ; en-tête signé par la borne (identité de la clé, passage, politique, date) → toute modification hors politique invalide la signature.
3. Agent poste : service système minimal (Windows : pilote filtre / politique de périphériques ; Linux : règles udev + polkit + démon), mTLS vers le serveur avec certificat machine, cache de politique signé et durée de validité (fonctionne hors réseau jusqu'à expiration), journal des événements remonté (montage, refus, octets lus/écrits) vers l'audit du serveur.
4. Contrôles : identité utilisateur (session + certificat/carte), quota sortant comptabilisé par l'agent et consolidé par le serveur, révocations (clé, utilisateur, poste) diffusées comme une CRL.
5. Écriture : selon politique ; si « re-analyse obligatoire », l'agent marque la clé comme modifiée (en-tête) → les autres agents la refusent et la borne la ré-analyse avant de la re-signer.
6. Risques à traiter dans la conception : contournement admin local du poste, démarrage sur autre OS, clés non-USB (SD, MTP, Thunderbolt), performances, mises à jour signées des agents.

## Conformité (à concevoir) — RGPD, CNIL, ANSSI, IGI 1300 (21/11)

- Demande : réfléchir l'architecture des serveurs de gestion (bornes, clés) pour être conforme RGPD / CNIL / ANSSI / IGI 1300. Référentiels ANSSI à couvrir : hygiène informatique, configuration GNU/Linux (BP-028), administration sécurisée (PA-022), journalisation (PA-012), TLS, cloisonnement, PKI.
- Remarque à valider : IGI 1300 = secret de la défense nationale (informations classifiées) ; le niveau DR relève de l'II 901 (déjà visé). Si des informations classifiées doivent passer, l'architecture change d'échelle (homologation, matériels agréés, réseaux séparés).

## Nouvelle fonction — dépôt vers le dossier personnel (21/11)

- Un utilisateur présente une clé USB (connue ou inconnue), la borne l'analyse, puis il peut envoyer les fichiers sains DIRECTEMENT dans son dossier personnel (home) du SI, sans clé de sortie.
- Implique : utilisateur authentifié sur la borne (mode Authentification), chemin réseau borne → SI à concevoir sans casser l'isolement.

### Décisions (21/11)

- Niveau (DR II 901 vs classifié IGI 1300) : l'utilisateur ne sait pas encore → rédiger une ANALYSE comparative (exigences, impacts sur l'architecture, coût) pour décider ensuite.
- Dépôt : deux destinations au choix — vers le dossier personnel (homedir) de l'utilisateur, OU mise à disposition par un lien web de téléchargement (zone tampon sur le serveur). Les fichiers passent par le serveur Barbacane (la borne ne parle qu'au serveur).
- Protocole d'écriture vers le homedir : SMB3 (+Kerberos), NFSv4 (krb5p) et SFTP, configurables par l'administrateur dans l'interface web.
- Garde-fous retenus (tous) : utilisateur authentifié (PIN), quota par jour, sous-dossier dédié « Barbacane/<date> » sans écrasement, fichiers sains seulement (douteux → refus ou quarantaine).
- Lien web : à concevoir — accès authentifié (même compte que la borne), lien à usage limité et durée courte, téléchargement journalisé, purge automatique.
- Place dans la feuille de route : après 2.4.0 (utilisateurs hybride, nécessaire) → proposer 2.10.0 « Dépôt vers le SI ».
