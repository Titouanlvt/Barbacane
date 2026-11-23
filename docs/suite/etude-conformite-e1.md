# Étude de conformité E1 — ANSSI, RGPD/CNIL, II 901, IGI 1300

Version 0.1 du 22/11/2026, étude **documentaire** (aucun code modifié), sur `main` au commit
`37f3770`. Elle ne décide rien : les décisions restent dans [decisions.md](decisions.md) et le niveau de
conformité visé n'est **pas encore fixé** par l'utilisateur (§7). Elle **ne vaut ni homologation, ni
qualification, ni avis de DPO**.

Conventions :
- **Obligatoire** : exigence d'un texte opposable (RGPD, loi, II 901 pour un SI DR, IGI 1300 pour un
  SI classifié). **Recommandé** : guide ANSSI, recommandation CNIL (non contraignante en soi, mais
  référence de la CNIL et des autorités d'homologation).
- État : **FAIT** (code + test ou preuve citée), **PARTIEL**, **ABSENT**, **HORS PROJET** (relève de
  l'organisme : locaux, personnel, produits agréés, décision).
- Versions de la feuille de route : celles d'`AVANCEMENT.md` (2.2 comptes admin … 3.0 contrôle postes).
  « **NOUVEAU** » = élément absent de la feuille de route, proposé au §6.
- Quand un point n'a pu être vérifié dans le texte officiel, il est marqué *(à vérifier dans le texte)*.

## 1. Références

| Réf. | Texte | Date / version | Nature |
|---|---|---|---|
| R1 | ANSSI, *Guide d'hygiène informatique* (42 mesures) | v2.0, 2017 | recommandé |
| R2 | ANSSI, *Profil de fonctionnalités et de sécurité — Sas et station blanche (réseaux non classifiés)*, SSI-P-G-076 | v1.0, 01/07/2020 | recommandé |
| R3 | ANSSI, *Recommandations pour les architectures des SI sensibles ou Diffusion Restreinte* (§5.7 supports amovibles) | v1.2, 2020 (publié 09/2021) | recommandé (déclinaison de l'II 901) |
| R4 | ANSSI, *Recommandations de configuration d'un système GNU/Linux* (BP-028) | v2.0, 2022 *(à vérifier)* | recommandé |
| R5 | ANSSI, *Recommandations relatives à l'administration sécurisée des SI* (PA-022) | v3.0, 2021 *(à vérifier)* | recommandé (fortement attendu pour DR) |
| R6 | ANSSI, *Recommandations de sécurité pour la mise en œuvre d'un système de journalisation* (PA-012) | *(version à vérifier)* | recommandé |
| R7 | ANSSI, *Recommandations de sécurité relatives à TLS* et *Guide des mécanismes cryptographiques* (RGS annexe B) | 2020 / 2021 *(à vérifier)* | recommandé ; RGS obligatoire pour les autorités administratives (ordonnance 2005-1516) |
| R8 | ANSSI, CSPN (certification de sécurité de premier niveau) et qualification / visa de sécurité | — | volontaire (démarche de l'éditeur) ; peut être **exigé** par l'AH ou un marché |
| R9 | Règlement (UE) 2016/679 (RGPD), art. 5, 6, 13-14, 15-22, 25, 30, 32, 35 | 27/04/2016 | obligatoire |
| R10 | Loi n° 78-17 « Informatique et libertés » modifiée | 06/01/1978 | obligatoire |
| R11 | CNIL, délibération n° 2021-122 du 14/10/2021, recommandation relative à la journalisation (JO 30/10/2021) | 14/10/2021 | recommandé |
| R12 | CNIL, méthode et outil PIA ; guide de la sécurité des données personnelles | — | recommandé |
| R13 | II n° 901/SGDSN/ANSSI du 28/01/2015 (protection des SI sensibles, Diffusion Restreinte) | 28/01/2015 | obligatoire dans son champ (administrations et organismes soumis, SI DR) |
| R14 | IGI n° 1300/SGDSN/PSE/PSD, approuvée par arrêté du 09/08/2021 (JO 11/08/2021), en vigueur au 01/07/2021 ; décret n° 2019-1271 du 02/12/2019 | 09/08/2021 | obligatoire pour les informations classifiées (Secret, Très Secret) |
| R15 | ANSSI, référentiel PDIS (prestataires de détection des incidents de sécurité) | — | **non pertinent** pour un produit : vise des prestataires ; utile seulement si le futur module SOC/SIEM est exploité par un prestataire qualifié |

Sources en ligne consultées le 22/11/2026 : [R2](https://cyber.gouv.fr/sites/default/files/2020/08/anssi-profil_de_fonctionnalites_et_de_securite-sas_et_station_blanche_reseaux_non_classifies-v1.0.pdf),
[R3](https://cyber.gouv.fr/sites/default/files/2021/09/anssi-guide-recommandations_architectures_systemes_information_sensibles_ou_diffusion_restreinte-v1.2.pdf),
[R11](https://www.cnil.fr/sites/cnil/files/atoms/files/recommandation_-_journalisation.pdf),
[R13](https://cyber.gouv.fr/instruction-interministerielle-n901),
[R14](https://cyber.gouv.fr/instruction-generale-interministerielle-n1300).
Limite : le contenu détaillé de R2 n'a pas pu être relu exigence par exigence ; les lignes « R2 » ci-dessous
reprennent les fonctions générales d'un sas / station blanche et doivent être confrontées au texte
(**action E1-bis**, §6).

**Rappel de champ (corrige une confusion possible)** : depuis la réforme de 2021, la *Diffusion
Restreinte* est une **mention de protection** relevant de l'**II 901**, pas un niveau de classification de
l'IGI 1300. L'IGI 1300 ne concerne que *Secret* et *Très Secret*. `decisions.md` écrit « DR, IGI 1300 » :
à corriger (§6, P1).

## 2. ANSSI

### 2.1 Station blanche / sas de décontamination (R2, R3 §5.7, R1 mesure sur les supports amovibles)

| Exigence (nature) | État Barbacane (preuve) | Écart | Traité par |
|---|---|---|---|
| Analyse des supports avant tout usage sur le SI (recommandé R1, R3) | FAIT : borne v1, ClamAV + YARA, 121/121 sur vraies clés (`docs/preuves/2026-11-19-v1.0.0/README.md`, `tests/phase1-mock.sh`) | antivirus unique (ClamAV) : le multi-moteurs souvent attendu d'une station blanche n'est pas fourni | NOUVEAU (option multi-moteurs ou justification) |
| Isolement de la station vis-à-vis du réseau opérationnel (R2 définition) | FAIT hors ligne (D12, `tests/iso/hors-ligne.sh`) ; borne en ligne : mTLS vers le seul serveur, nftables | la borne en ligne n'est plus « isolée » au sens strict : à justifier dans le dossier | 2.12 (dépôt SI) aggrave ; analyse dans le dossier d'homologation |
| Isolement des composants d'analyse (recommandé) | FAIT : processus usbsas sous seccomp, bubblewrap des archives (`noyau/`, `docs/noyau/ecarts.md`) | — | — |
| Mises à jour de signatures intègres (recommandé) | FAIT : `.bcu` Ed25519 hors ligne, anti-retour (`docs/preuves/2026-11-18-maj-paquets/`, `tests/maj/maj.sh`) | fraîcheur des signatures non alertée côté serveur *(à vérifier)* | 2.13 (statistiques) ou NOUVEAU |
| Traçabilité des passages (recommandé) | FAIT : rapports sans nom de fichier (`serveur/passerelle/tests/passages.rs`) | rapport non signé par la borne ; analyse en échec non remontée | 2.3 / 2.4 |
| Liste blanche de fichiers connus (recommandé selon R2 *(à vérifier)*) | ABSENT | — | 2.10 |
| Filtrage des périphériques HID (recommandé) | FAIT (v1) ; S-06 souris sur tous les ports (`docs/revue-securite.md`) | S-06 ouvert | NOUVEAU (faible) |
| Effacement des données résiduelles (recommandé) | PARTIEL : espace chiffré éphémère ; S-08 fichiers sains gardés jusqu'à la session suivante | S-08 | 2.5 (chiffrement borne) |
| Produit évalué (CSPN / qualification) | ABSENT : aucune évaluation ; usbsas (CEA) non plus *(à vérifier)* | **écart majeur si un marché ou l'AH exige un produit certifié** | NOUVEAU : décision CSPN (§6, P4) |

### 2.2 Hygiène, durcissement, administration, journalisation, cryptographie (R1, R4–R7)

| Exigence (nature) | État (preuve) | Écart | Traité par |
|---|---|---|---|
| Comptes nominatifs des administrateurs, pas de compte partagé (R1, R5, recommandé) | **FAIT (v2.2.0)** : comptes nominatifs gérés dans la Console (création, désactivation, suppression, rôle, mot de passe, certificat `.p12`, dernier accès), liés à un certificat + mot de passe Argon2id, politique de robustesse (`comptes-administrateurs.md`, `serveur/web/tests/comptes.rs`) | — | 2.2 |
| Authentification forte des administrateurs (R5) | PARTIEL : certificat client mTLS + mot de passe ; certificats en fichiers, pas de carte à puce/FIDO2 | support matériel du facteur | 2.4 (TPM) + NOUVEAU FIDO2/carte (HORS PROJET pour le matériel) |
| Poste et réseau d'administration dédiés (R5) | interface d'administration distincte (`serveur/iso/configurer-serveur.sh`) ; poste dédié : HORS PROJET | pare-feu d'administration à compléter | 2.2 / organisme |
| Séparation des rôles, double validation (R5) | **FAIT (v2.2.0)** : 4 rôles (administrateur, opérateur, auditeur, lecture seule), double validation généralisée (comptes, certificats, révocation d'un site, quarantaine), auto-validation refusée, expiration 1 h (`comptes-administrateurs.md` §2, §5) | conservation (2.3) sur le même mécanisme | 2.2 |
| Durcissement GNU/Linux (R4) | borne FAIT (systemd confiné, nftables, GRUB verrouillé S-01) ; serveur PARTIEL (sysctl, auditd, journald : `serveur/iso/fichiers/etc/`) | pas d'auto-évaluation BP-028 ligne à ligne ; faillock, AIDE absents ; services web non durcis (systemd) | NOUVEAU : grille BP-028 (niveau visé à fixer) ; AIDE/faillock en 2.7 ou 2.8 |
| Journalisation centralisée, horodatée, protégée (R6) | **FAIT (v2.3.0)** pour le format et l'export : audit chaîné SHA-384 + points ECDSA P-384, **scellement quotidien automatique**, segments scellés ; **format structuré** (JSON par ligne, RFC 3339 UTC, identifiant, gravité RFC 5424, `journal-structure.md`) ; **export Syslog** RFC 5424 en TLS 1.3 (RFC 5425, mTLS possible) ou en clair signalé, double validation, file persistante, remise confirmée, alertes (`journal-syslog.md`, `serveur/passerelle/tests/syslog.rs`, banc QEMU) | collecteur séparé et homologué (organisme), `chattr +a` absent | collecteur séparé 2.8 |
| TLS 1.3, suites et courbes RGS (R7) | FAIT : `serveur/passerelle/tests/mtls.rs` ; LDAPS TLS 1.2 optionnel audité (`serveur/web/tests/annuaire.rs`) | — | — |
| Clés non exportables (R7, recommandé) | ABSENT : clés serveur en fichiers 0600 ; TPM seulement pour LUKS (swtpm au labo) | **écart important** | 2.4 |
| Racine PKI hors ligne, politique de certification (R7) | document FAIT (`politique-certification.md`) ; racine de TEST seulement (`serveur/pki/racine-test.sh`) | PKI de production, cérémonie, refus des certificats TEST | 2.4 |
| Mises à jour maîtrisées (R1) | bornes FAIT (`.bcu`) ; serveur : paquets de l'ISO, pas de mise à jour signée du serveur | — | 2.7 |
| Sauvegarde testée (R1) | FAIT manuel (`tests/serveur/sauvegarde.sh`, désormais en CI locale) ; purge par âge (v2.3.0) ; non planifiée | sauvegarde planifiée, hors site | NOUVEAU (petit, à rattacher à 2.7) |
| Veille et correction des vulnérabilités (R1) | PARTIEL : reprise des correctifs usbsas (v2.0.3), dependabot | pas de processus de veille écrit (CVE Debian, ClamAV) | NOUVEAU (document MCS, §4.5) |

## 3. RGPD et CNIL

Responsable de traitement : **l'organisme qui déploie**, pas le projet. Le projet doit fournir un produit
qui **permet** la conformité (art. 25, protection dès la conception).

| Exigence (nature) | État (preuve) | Écart | Traité par |
|---|---|---|---|
| Base légale (art. 6, obligatoire) | trame : 6.1.e ou 6.1.f (`aipd.md` §1) | à choisir par l'organisme | HORS PROJET |
| Registre des traitements (art. 30, obligatoire) | ABSENT : aucune fiche de registre fournie | modèle de fiche à fournir | NOUVEAU (document, E1-bis) |
| AIPD (art. 35, obligatoire si risque élevé ; surveillance de l'activité des salariés = cas listé par la CNIL *(à vérifier)*) | PARTIEL : trame v0.1 non validée (`aipd.md` §4 vide) ; ne couvre pas les administrateurs en détail, ni Syslog, dépôt SI, contrôle postes | AIPD à réviser à chaque version qui ajoute des données (2.3, 2.9, 2.11, 2.12, 3.0) | règle NOUVELLE dans la porte de sortie |
| Minimisation (art. 5.1.c, obligatoire) | FAIT : pas de nom de fichier (D2), pseudonyme HMAC (`serveur/passerelle/src/utilisateurs.rs`, `serveur/passerelle/tests/utilisateurs.rs`), mode Aucun sans donnée | numéro de série du support = donnée indirectement identifiante, à justifier ; contenu quarantaine | AIPD ; 2.11 |
| Limitation de la conservation (art. 5.1.e, obligatoire) ; durée des journaux 6 mois à 1 an sauf justification (R11, recommandé) | **FAIT (v2.3.0)** : durée réglée dans la Console par double validation (défaut 365 j, 180–730 j, préavis de 7 j), purge quotidienne tracée des rapports de passage, du journal d'audit (segments), des correspondances et des sauvegardes du support monté (`journal-conservation.md`, `serveur/audit/tests/segments.rs`, `passages::tests`, `tests/serveur/sauvegarde.sh`, banc QEMU avec horloge avancée) ; quarantaine 30 j | supports de sauvegarde au coffre purgés à leur montage seulement (procédure) | — |
| Contradiction purge / journal chaîné | **FAIT (v2.3.0)** : rotation quotidienne en segments scellés, ancre signée en tête de chaque segment, purge des plus anciens seulement, chaîne restante vérifiée (outil, Console) | — | — |
| Information des personnes (art. 13, obligatoire) | PARTIEL : message prévu sur la borne (`aipd.md` §2) ; modèle de note d'information absent | modèle de mention | NOUVEAU (document) |
| Droits d'accès, rectification, limitation (art. 15-18, obligatoire) | PARTIEL : export par identifiant par l'auditeur annoncé dans l'AIPD *(non retrouvé comme test dédié)* | procédure et fonction testée | 2.13 (export CSV) ou NOUVEAU |
| Données des administrateurs (journaux d'actions, art. 5, 13) | **FAIT (v2.3.0)** pour la durée : journal nominatif des administrateurs = durée du journal d'audit (réglée, défaut 1 an) ; journald 1 an (`aipd.md` §1) | information des administrateurs (note interne) | organisme |
| Sécurité (art. 32, obligatoire) ; journalisation des accès aux données (R11) | **FAIT (v2.3.0)** : consultations journalisées (liste et détail des passages avec le rapport consulté, fiche utilisateur par pseudonyme, journal, export structuré), `serveur/web/tests/journal.rs` | — | — |
| Consultation des représentants du personnel (Code du travail L.2312-38, obligatoire pour un employeur privé avec CSE ; équivalent public) | HORS PROJET, rappelée dans `aipd.md` | — | organisme |
| Pas de transfert hors UE, pas de sous-traitant | FAIT par conception (serveur sur site sans Internet) | — | — |

## 4. II 901 — Diffusion Restreinte

L'II 901 impose aux SI DR dans son champ une **homologation** préalable et des mesures minimales.
Barbacane traite des **supports** pouvant contenir du DR : la borne et le serveur (rapports, quarantaine)
relèvent du périmètre du SI DR qui les héberge (D1).

| Exigence (nature) | État (preuve) | Écart | Traité par |
|---|---|---|---|
| Homologation par l'AH avant mise en service (obligatoire) | dossier préparé (`dossier-homologation.md`, EBIOS RM simplifié), `mesures_dr_serveur: non` | décision de l'AH ; Claude ne peut pas homologuer | HORS PROJET |
| Produits de sécurité agréés / qualifiés DR pour les fonctions de sécurité (obligatoire selon l'II 901 pour certaines fonctions, notamment le chiffrement hors zone protégée *(périmètre exact à vérifier dans le texte)*) | ABSENT : logiciels libres non qualifiés | à accepter par l'AH ou à compenser ; chiffreur IP agréé entre sites | HORS PROJET (achat) ; NOUVEAU : liste des fonctions concernées |
| Cloisonnement, aucune interconnexion avec un SI de niveau inférieur sans passerelle adaptée (obligatoire) | PARTIEL : serveur sans route par défaut, nftables liste blanche (`serveur/iso/configurer-serveur.sh`, `tests/serveur/qemu-serveur.sh`) | **2.12 (dépôt vers le SI) et 3.0 créent des flux vers d'autres SI** : à analyser avant conception | 2.8 (rôles séparés) ; analyse NOUVELLE avant 2.12 |
| Chiffrement des données DR au repos sur les supports mobiles et serveurs hors zone protégée (obligatoire en pratique, par produit agréé) | serveur : LUKS2 + TPM (PCR 7), non qualifié ; borne : non chiffrée au repos hors espace éphémère | — | 2.5 (bornes) ; produit agréé HORS PROJET |
| Chiffrement des flux DR hors zone protégée (obligatoire) | sur site : TLS 1.3 (non agréé) ; entre sites : WireGuard au labo seulement | chiffreur IP agréé | HORS PROJET |
| Journalisation et conservation des traces (obligatoire au titre de la sécurité ; modalités R6) | voir §2.2 ; **export Syslog et conservation : FAIT (v2.3.0)** | collecteur séparé | 2.8 |
| Administration depuis des postes dédiés (exigé pour DR selon R3/R5) | voir §2.2 | — | 2.2 + organisme |
| Maintien en condition de sécurité (obligatoire : correctifs, veille, revue périodique de l'homologation) | PARTIEL : mises à jour bornes signées ; serveur sans mise à jour signée ; pas de plan MCS écrit ; pas de durée de support annoncée | plan MCS (veille CVE, délais, fin de vie Debian 13) | 2.7 + NOUVEAU (document MCS) |
| Gestion des supports amovibles (obligatoire : maîtrise des supports) | FAIT pour la décontamination ; enrôlement des clés (`serveur/passerelle/tests/utilisateurs.rs`) ; S-05 n° de série copiable | identification forte des supports | 3.0 (Clés Barbacane chiffrées) |
| Personnel, locaux, besoin d'en connaître | HORS PROJET | — | organisme |

## 5. IGI 1300 — informations classifiées

| Point | Constat |
|---|---|
| Applicabilité | Seulement si des supports **Secret** ou **Très Secret** passent sur une borne ou si le serveur en reçoit (quarantaine). |
| Ce qu'exige l'IGI 1300 (obligatoire) | homologation propre par l'AH avec l'ANSSI membre de droit de la commission ; produits **agréés** au niveau ; zones protégées ; personnes habilitées ; SI classifiés cloisonnés (pas de flux vers un SI de niveau inférieur sauf dispositif agréé) ; gestion des articles contrôlés de la SSI (II 910). |
| Ce que Barbacane **NE peut PAS** revendiquer | aucun agrément ; aucun composant (ClamAV, rustls, LUKS, usbsas, Debian) n'est agréé pour du classifié à notre connaissance ; la borne en ligne, le dépôt vers le SI, Syslog, le contrôle des postes et la quarantaine centralisée sont **incompatibles en l'état** avec un SI classifié relié à un SI de niveau inférieur ; Claude ne peut ni homologuer ni fournir de produit agréé. |
| Usage éventuel | au mieux une **borne hors ligne v1** dédiée, intégrée à l'intérieur d'un SI classifié homologué, comme outil complémentaire, avec décision explicite de l'AH ; serveur et borne connectée à réserver à un réseau du même niveau, une machine par rôle (point du 21/11). |
| Conclusion | le dossier et les documents ne doivent jamais écrire « conforme IGI 1300 ». |

## 6. Synthèse

### 6.1 Écarts bloquants avant 2.4

1. ~~**Purge non implémentée** des rapports de passage, du journal d'audit et des sauvegardes~~ —
   **traité en v2.3.0** (`journal-conservation.md`).
2. **Secrets du serveur en fichiers** (clés de la passerelle, de l'audit, poivre des PIN, CA émettrice
   sur la passerelle) — objet même de 2.4 ; pré-requis : décision sur le TPM matériel cible.
3. ~~**Pas d'export de journal hors serveur**~~ (R6, II 901) — **traité en v2.3.0** (export Syslog
   TLS 1.3, `journal-syslog.md`) ; reste le collecteur séparé (2.8, organisme).
4. ~~**Double validation et comptes administrateurs incomplets** (R5)~~ — **traité en v2.2.0**
   (`comptes-administrateurs.md`) ; reste le facteur matériel (P8).
5. **Niveau de conformité non décidé** : la PKI de production (2.4) ne doit pas être figée avant de savoir
   si une AH exige des supports/produits agréés (carte à puce, HSM).
6. Confusion DR / IGI 1300 dans `decisions.md` et `README.md` à corriger (documentaire).

### 6.2 Propositions de changements de la feuille de route

- **P1** (doc, immédiat) : corriger « DR, IGI 1300 » en « DR, II 901 » ; ajouter la phrase
  « Barbacane ne revendique aucune conformité IGI 1300 ».
- ~~**P2**~~ (**fait en v2.3.0**) : ajouter **rétention et purge** (passages, audit par segments scellés, sauvegardes),
  journalisation des consultations de données personnelles, durée des journaux des administrateurs.
- **P3** (porte de sortie de chaque version ; **appliquée en v2.3.0** : `aipd.md` révisée) : **revue de l'AIPD et du registre** dès qu'une version
  ajoute une donnée ou un flux (2.3, 2.9, 2.11, 2.12, 3.0).
- **P4** (décision) : viser ou non une **CSPN** de la borne hors ligne (cible de sécurité à rédiger) ; si
  oui, geler le périmètre de la borne v1 et prévoir une version « candidate CSPN ».
- **P5** (nouveau document, avant 2.4) : grille d'auto-évaluation **BP-028 / PA-022 / R2** ligne à ligne
  (E1-bis), après lecture complète des guides.
- **P6** (nouveau document, avec 2.7) : **plan de MCS** (veille CVE Debian/ClamAV/Rust, délais de
  correction, fin de vie Debian 13, revue annuelle de l'homologation) et sauvegarde planifiée.
- **P7** (avant 2.12) : **analyse d'interconnexion** du dépôt vers le SI au regard de l'II 901 ; la
  fonction peut être interdite par l'AH pour un SI DR relié à un niveau inférieur.
- **P8** (2.2 ou 2.4) : facteur matériel des administrateurs (FIDO2 / carte à puce) explicitement inscrit.
- **P9** (option) : multi-moteurs d'analyse ou justification écrite de l'antivirus unique.
- **P10** (documents) : modèles de fiche de registre (art. 30) et de mention d'information (art. 13).

## 7. Questions à poser à l'utilisateur

1. Quel **niveau** visez-vous : (a) SI non sensible (hygiène + RGPD), (b) SI DR soumis à l'II 901,
   (c) usage dans un SI classifié (IGI 1300, borne hors ligne seule) ?
2. Y aura-t-il une **autorité d'homologation** réelle chez un organisme pilote, ou le dossier reste-t-il
   un modèle ?
3. Souhaitez-vous engager une **CSPN** (borne hors ligne) ? Budget et calendrier (centre d'évaluation
   agréé, plusieurs mois) ?
4. Validez-vous la **durée de conservation** de 1 an (rapports, audit, administrateurs) et la purge des
   sauvegardes, avec rotation par segments de l'audit chaîné ?
5. Le **numéro de série des supports** doit-il rester dans les rapports (donnée indirectement
   identifiante) ?
6. TPM **matériel** et éventuel **HSM** : quel matériel cible pour 2.4 ? Cartes à puce ou FIDO2 pour les
   administrateurs ?
7. Le **dépôt vers le SI** (2.12) et le **contrôle des postes** (3.0) restent-ils prioritaires s'ils
   rendent l'homologation DR plus difficile ?
8. Acceptez-vous l'ajout d'une version ou d'une étape **E1-bis** (grilles BP-028/PA-022/R2 détaillées,
   registre, MCS) avant 2.4 ?
9. Quel schéma d'événements pour le futur SOC : **ECS** ou **OCSF** (à trancher avant 2.3) ?
