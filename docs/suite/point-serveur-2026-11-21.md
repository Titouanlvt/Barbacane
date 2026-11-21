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

## Installation modulaire et mises à jour (21/11, ajouté au point)

- Demande : un administrateur qui installe Barbacane doit pouvoir déployer du MINIMUM au MAXIMUM selon son infrastructure, mettre à jour le serveur, ses services et les bornes, et AJOUTER plus tard les fonctions qu'il n'avait pas installées.
- Proposition :
  - Modules : socle obligatoire (passerelle, registre, audit, interface web) + modules optionnels (utilisateurs/LDAP, Syslog, quarantaine, liste blanche, dépôt vers le SI, statistiques, device control). Choix à l'installation, puis ajout ou retrait depuis l'interface web (double validation, audité), sans réinstaller.
  - Profils d'installation : « minimal » (borne hors ligne seule, sans serveur), « socle » (serveur + bornes en ligne), « complet », ou sur mesure.
  - Mises à jour signées : serveur (système + services), modules et bornes, sur la même chaîne de signature que les mises à jour des bornes ; support hors ligne (clé ou ISO de mise à jour), vérification de l'empreinte, sauvegarde avant mise à jour et retour arrière.
- Version : nouvelle 2.2.0 « Installation modulaire et mises à jour » juste après les comptes administrateurs (2.1.0) ; les versions suivantes sont décalées d'un cran (PIN 2.3, chiffrement des bornes 2.4, utilisateurs 2.5, Syslog 2.6, liste blanche 2.7, quarantaine par la borne 2.8, TPM + PKI 2.9, ergonomie 2.10, dépôt vers le SI 2.11, device control 3.0).

## Répartition des rôles (21/11, ajouté au point)

- Risque relevé par l'utilisateur : tout gérer avec un seul serveur concentre le risque (compromission = bornes + comptes + écriture dans le SI + postes) et la panne.
- Décision : en 2.2.0, chaque rôle est déployable sur sa propre machine (même logiciel). Rôles : gestion des bornes (passerelle + cœur + administration) ; relais de dépôt vers le SI (seul à écrire dans le SI) ; contrôle des postes (3.0) ; AC émettrice (TPM/HSM) ; collecteur de journaux (toujours à part) ; signature des mises à jour, modules et agents (toujours hors ligne, jamais sur un serveur).
- Profils : petit site = une machine durcie, sans dépôt SI ni contrôle des postes ; site DR = au moins relais de dépôt et contrôle des postes séparés + poste d'administration dédié ; classifié = une machine par rôle.
- L'étude E1 fixe le découpage minimal exigé par niveau.

## Politique des agents .msi / .deb (3.0, à détailler dans l'étude)

- Rédaction des politiques : rôle « administrateur des postes », distinct des administrateurs des bornes (séparation des tâches), sur le serveur « contrôle des postes ».
- Politiques signées (clé du rôle dans TPM/HSM), vérifiées par l'agent avant application ; récupérées en mTLS (certificat machine) ; cache avec date d'expiration.
- Paquets des agents signés hors ligne (Authenticode pour le .msi, dépôt APT signé GPG pour le .deb) ; déploiement par les outils du SI (GPO, Intune/SCCM, Ansible, dépôt APT interne).
- Protection de l'agent : service non arrêtable par un utilisateur, alerte au serveur si l'agent disparaît ou ne remonte plus ; limite connue : un administrateur local du poste peut le contourner → droits d'administration locale encadrés par le SI.

## Noms des services et systèmes (21/11, choix « mixte »)

Règle (précisée par l'utilisateur) : nom fonctionnel ET sous-titre, dans les interfaces comme dans la doc, selon la situation, pour ne pas perdre les utilisateurs. Par défaut : titres de pages, menus, en-têtes de chapitres → « Console · Chemin de ronde » ; messages, boutons, journaux, commandes, identifiants d'événements → nom fonctionnel seul (court, stable). Les deux noms restent toujours associés de la même façon partout.

| Nom fonctionnel | Sous-titre (doc) | Ce que c'est | Nom technique actuel |
|---|---|---|---|
| Borne autonome | — | borne hors ligne (v1) | profil hors ligne |
| Borne connectée | — | borne en ligne, rattachée au serveur | profil en ligne + barbacane-agent |
| Clé Barbacane | « Sauf-conduit » | clé de sortie (chiffrée en 3.0) | clé enrôlée |
| Agent Poste | « Sentinelle » | agent .msi / .deb des postes (3.0) | — |
| Serveur Barbacane | — | l'ensemble des services ci-dessous | serveur |
| Console | « Chemin de ronde » | interface web d'administration | barbacane-web |
| Liaison bornes | « Herse » | point d'entrée mTLS des bornes | barbacane-passerelle |
| Parc | « Donjon » | registre des bornes, supervision, politiques, utilisateurs | registre, barbacane-registre |
| Journal | « Chronique » | journal d'audit chaîné et signé | barbacane-audit |
| Quarantaine | « Oubliette » | fichiers bloqués, chiffrés | quarantaine |
| Dépôt | « Poterne » | envoi des fichiers sains vers le SI ou lien web (2.11) | — |
| Contrôle postes | « Guet » | politiques des Agents Poste (3.0) | — |
| Autorité | « Trésor » | racine PKI hors ligne et AC émettrice | PKI |
| Atelier signature | « Sceau » | poste hors ligne qui signe mises à jour, modules et agents | clé de signature des mises à jour |

À appliquer progressivement : libellés de l'interface et du manuel en 2.0.2 (sans renommer les binaires ni les chemins, pour ne rien casser) ; renommage technique éventuel des paquets/services à décider en 2.2.0 (installation modulaire).

## Évolution future vers un SOC / SIEM (21/11)

Barbacane pourra évoluer vers un SOC/SIEM : tout ce qui est construit doit le préparer, sans l'implémenter maintenant.
- Événements structurés : format JSON stable et documenté, identifiants d'événements fixes (catégorie.action, ex. `borne.enrolement.valide`), horodatage UTC, identifiant de corrélation par passage / session, source (rôle + machine), gravité.
- Noms stables : le nom fonctionnel du service sert d'identifiant de source dans les événements (ne pas le renommer ensuite).
- Export : Syslog RFC 5424 (2.6) avec champs structurés ; prévoir un mapping vers un schéma standard (ECS ou OCSF, à choisir dans l'étude E1) et une API de lecture en lecture seule.
- Données utiles à la détection déjà collectées : passages (empreintes, verdicts), enrôlements, révocations, connexions admin, refus mTLS, écarts d'horloge, file d'envoi pleine.
- Sans fuite : jamais de nom de fichier, de PIN ni de contenu dans les événements (D2, RGPD) ; pseudonymes pour les utilisateurs.
- À intégrer : contraintes dans E1 (conformité) et dans 2.6 (Syslog) ; un éventuel module « SOC » viendrait après 3.0.

## Découpage refait — sécurité d'abord, fonctionnement fiable à chaque version (21/11, remplace les découpages précédents)

Porte de sortie OBLIGATOIRE de chaque version : revue de sécurité (modèle de menaces mis à jour), CI locale et GitHub vertes, banc QEMU, non-régression borne 950, preuve labo Proxmox (serveur + borne), mise à jour depuis la version précédente sans perte de données, retour arrière testé, documentation et notes de version à jour. La version suivante ne commence qu'après publication.

| Version | Nature | Contenu | Dépend de |
|---|---|---|---|
| 2.0.1 | Correctif | Fiabilité : détection USB (ppoll), ISO serveur complète, banc QEMU, chaîne du certificat HTTPS, numéro de version | — |
| 2.0.2 | Correctif | Défauts du labo + noms fonctionnels/sous-titres dans la Console et le manuel | 2.0.1 |
| E1 | Étude | Conformité ANSSI / RGPD-CNIL / II 901 / IGI 1300, découpage des rôles par niveau, schéma d'événements SOC ; en parallèle, terminée avant 2.3 | — |
| 2.1.0 | Sécurité | Comptes administrateurs dans la Console, double validation généralisée, D13 | 2.0.x |
| 2.2.0 | Sécurité | Journal : événements structurés + export Syslog (TLS ou clair) | 2.1.0 |
| 2.3.0 | Sécurité | Autorité : secrets serveur dans le TPM, AC émettrice hors Liaison bornes, racine hors ligne, PKI de production + cérémonie | 2.1.0, E1 |
| 2.4.0 | Sécurité | Chiffrement des bornes + clé de secours chiffrée, auditée, double validation | 2.3.0 |
| 2.5.0 | Sécurité | PIN par administrateur sur la borne | 2.1.0 |
| 2.6.0 | Fiabilité | Mises à jour signées du serveur et des services, sauvegarde avant, retour arrière | 2.3.0 |
| 2.7.0 | Fondation | Installation modulaire + rôles sur machines séparées | 2.6.0 |
| 2.8.0 | Fonction | Utilisateurs hybride (local + LDAP) | 2.1.0 |
| 2.9.0 | Fonction | Liste blanche SHA-256 | 2.2.0 |
| 2.10.0 | Fonction | Quarantaine envoyée par la borne | 2.4.0 |
| 2.11.0 | Fonction | Dépôt vers le SI (relais sur sa propre machine) | 2.7.0, 2.8.0 |
| 2.12.0 | Ergonomie | Listes déroulantes, statistiques, export CSV | 2.8.0 |
| 3.0.0 | Étude puis produit | Contrôle postes (Agent Poste, Clés Barbacane chiffrées) | 2.3.0, 2.7.0 |
| après 3.0 | Évolution | Module SOC / SIEM | 2.2.0 |
