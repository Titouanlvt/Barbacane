# Dossier d'homologation — Barbacane suite (niveau visé : Diffusion Restreinte)

Version 0.1 du 19/11/2026. Rédigé par Claude, qui tient « au mieux » le rôle d'autorité
d'homologation (AH) faute d'AH réelle. **Ce document ne vaut pas homologation** : seule une AH
désignée par l'organisme peut prononcer la décision d'homologation, et certains éléments exigent
des produits agréés que le projet ne peut pas fournir. Chaque mesure est donc marquée :

- **FAIT** : réalisé dans le dépôt et prouvé (lien vers la preuve) ;
- **PRÉVU** : conçu, à réaliser dans une étape du plan (numéro) ;
- **HORS PROJET** : exige un produit agréé, une décision officielle ou une organisation que le
  logiciel ne peut pas fournir.

Références (non vérifiées mot à mot) : IGI 1300 (protection du secret, mentions DR), II 901
(protection des SI sensibles et DR), guide ANSSI « Homologation de sécurité en neuf étapes »,
EBIOS Risk Manager, RGS et guide des mécanismes cryptographiques, guide d'hygiène informatique,
recommandations relatives à l'administration sécurisée des SI, recommandations de configuration
d'un système GNU/Linux, recommandations pour TLS.

## 1. Périmètre

| Élément | Dans le périmètre | Remarque |
|---|---|---|
| Serveur Barbacane (ISO durcie, conteneurs, base, PKI intermédiaire) | oui | **traité comme un SI DR** (D1) |
| Bornes en ligne (ISO `--profil en-ligne`, agent) | oui | traitent des supports DR |
| Poste d'administration dédié | oui (exigences) | matériel et système fournis par l'organisme |
| LAN de gestion de chaque site, liaison entre sites | oui (exigences) | chiffreur agréé DR entre sites (HORS PROJET) |
| Racine PKI hors ligne et sa cérémonie | oui | procédure : `politique-certification.md` §8 |
| Bornes v1 hors ligne | non | produit distinct, aucun lien réseau |
| Annuaire AD/LDAP de l'organisme | interface seulement | LDAPS, compte de service en lecture seule |
| Réseaux de niveau inférieur, Internet | **exclus** | aucune interconnexion (D1) |

Informations traitées : métadonnées de décontamination (verdicts, empreintes, tailles, identifiants
d'agents et de supports), journaux ; **contenu de fichiers DR uniquement si la quarantaine est
activée** (désactivée par défaut, verrouillée, D3).

## 2. Valeurs métier et biens supports (EBIOS RM, atelier 1)

| Valeur métier | Besoin (D/I/C/T) | Biens supports |
|---|---|---|
| Décision d'analyse (sain / bloqué) | D 2, **I 4**, C 2, T 3 | borne (analyseur, signatures), `.bcu` |
| Traçabilité des passages | D 2, **I 4**, C 3, **T 4** | agent, passerelle, base, journal d'audit |
| Disponibilité du service de décontamination | **D 3**, I 3, C 1, T 2 | serveur, réseau, bornes |
| Fichiers en quarantaine (option) | D 1, I 3, **C 4 (DR)**, T 4 | borne, stockage chiffré du serveur, VM d'analyse |
| Identités (PIN, certificats) | D 2, I 4, **C 4**, T 3 | TPM, PKI, base (Argon2id) |

Échelle 1 (faible) à 4 (critique). Événements redoutés principaux : ER1 un fichier malveillant
déclaré sain atteint le SI ; ER2 une information DR quitte le périmètre ; ER3 la traçabilité est
falsifiée ou effacée ; ER4 les bornes sont toutes hors service ; ER5 l'identité d'un agent est usurpée.

## 3. Socle de sécurité (atelier 1)

Écarts au guide d'hygiène et aux recommandations ANSSI : voir §5. Le socle repose sur : profil
hors ligne inchangé de la v1, durcissement Debian (ANSSI niveau renforcé visé), pare-feu en
liste blanche, TLS 1.3 mutuel, journalisation centralisée et chaînée, administration sur poste dédié.

## 4. Sources de risque, scénarios et mesures (ateliers 2 à 5, simplifiés)

| Source de risque | Objectif visé | Scénario stratégique | Scénarios opérationnels | Mesures | État |
|---|---|---|---|---|---|
| Attaquant étatique (via support piégé) | ER1, ER2 | support piégé → borne → SI | maliciel inconnu des signatures ; exploitation d'un analyseur | décision locale ClamAV + YARA, noyau usbsas en processus isolés (seccomp), bac à sable bubblewrap des archives, espace de travail chiffré éphémère | **FAIT** (v1, `docs/preuves/`) |
| Attaquant ayant pris le serveur | ER1, ER3 | serveur → bornes | pousser du code ; abaisser la politique ; falsifier l'audit | `.bcu` signés hors ligne et revérifiés ; plancher signé hors ligne ; politique bornée, version monotone ; audit chaîné exporté hors serveur | `.bcu` **FAIT** (v1) ; reste **PRÉVU** (étapes 5–7) |
| Attaquant sur le LAN | ER2, ER5 | interception, usurpation de serveur ou de borne | écoute, homme du milieu, rejeu, borne clonée | mTLS 1.3, CA serveur épinglée dans l'ISO, CRL, clés dans le TPM, jeton 1 h + validation humaine | **PRÉVU** (étape 5) |
| Attaquant entre sites | ER2 | interception de la liaison inter-sites | écoute du lien opérateur | chiffreur IP **agréé DR** | **HORS PROJET** (lab : WireGuard) |
| Utilisateur malveillant | ER3, ER5 | usurpation, force brute de PIN, faux clavier | PIN d'un collègue, clavier HID injecteur | PIN Argon2id, verrouillage 5 échecs, filtrage HID (v1), pas de mot de passe d'annuaire sur la borne | HID **FAIT** (v1) ; PIN **PRÉVU** (étape 8) |
| Administrateur malveillant | ER2, ER3 | abus de droits | export de quarantaine, effacement d'audit | rôles séparés, double validation, audit exporté, 2 facteurs | **PRÉVU** (étapes 5, 7, 11) |
| Défaillance (panne, coupure) | ER4 | serveur indisponible | perte du serveur, certificat expiré | délai de grâce borné, file locale, sauvegarde/restauration testée, alertes d'expiration | **PRÉVU** (étapes 5–6) |

## 5. Mesures appliquées et écarts au niveau DR

| Domaine | Exigence DR (II 901 / guides ANSSI) | Mesure Barbacane | État |
|---|---|---|---|
| Chiffrement au repos | disque du SI DR chiffré par un produit adapté | LUKS2 (AES-XTS-512) scellé au TPM du serveur | **PRÉVU** (étape 5) ; **produit non qualifié** : un chiffrement de disque **qualifié/agréé** peut être exigé par l'AH — HORS PROJET |
| Chiffrement en transit (site) | flux protégés | TLS 1.3 mutuel, suites RGS | **PRÉVU** (étape 5) |
| Chiffrement entre sites | chiffreur agréé DR | lab : WireGuard | **HORS PROJET** en production |
| Administration | poste dédié, réseau d'administration séparé, 2 facteurs | interface web sur interface réseau distincte, FIDO2 / carte à puce | **PRÉVU** (étape 5) ; poste dédié et ses moyens d'authentification : fournis par l'organisme (HORS PROJET) |
| Cloisonnement | aucune interconnexion avec un niveau inférieur | serveur sans route par défaut, pare-feu liste blanche, ISO hors ligne | **PRÉVU** (étape 5) ; topologie réseau : organisme |
| Journalisation | journaux protégés, conservés, analysés | journal chaîné et signé, empreintes exportées chaque jour hors serveur | **PRÉVU** (étape 7) |
| Mise à jour | maîtrisée, intègre | `.bcu` signés hors ligne (Ed25519), anti-retour | **FAIT** (v1, `docs/preuves/2026-11-18-maj-paquets/`) |
| Supports amovibles | décontamination avant usage | la borne elle-même | **FAIT** (v1, 121/121 sur vraies clés) |
| Durcissement OS | guide ANSSI GNU/Linux | v1 : nftables tout bloqué, services confinés (systemd), GRUB verrouillé ; serveur : même base | borne **FAIT** ; serveur **PRÉVU** |
| PKI | politique de certification, racine hors ligne | `politique-certification.md`, cérémonie | document **FAIT** ; réalisation **PRÉVU** (étape 5) |
| Produits | produits **qualifiés/agréés** pour les fonctions de sécurité DR | logiciels libres non qualifiés (Debian, rustls, ClamAV) | **ÉCART** : à accepter explicitement par l'AH ou à compenser |
| Personnel | habilitation / besoin d'en connaître | — | **HORS PROJET** |
| Locaux | zone protégée pour serveur et bornes | — | **HORS PROJET** |

## 6. Plan pour combler les écarts

| Écart | Action | Porteur | Échéance |
|---|---|---|---|
| Liaison inter-sites non agréée | acquérir et déployer un chiffreur IP agréé DR à chaque site | organisme | avant mise en service multi-sites |
| Disque du serveur non qualifié | choisir un produit de chiffrement de disque agréé, ou faire accepter LUKS par l'AH avec mesures compensatoires (local en zone protégée, TPM, arrêt hors service) | organisme / AH | avant mise en service |
| Produits non qualifiés | analyse de risque résiduel signée par l'AH ; veille de vulnérabilités ; mises à jour signées | AH | décision d'homologation |
| Poste d'administration | poste dédié durci, clé FIDO2 ou carte à puce, réseau d'administration séparé | organisme | avant étape 5 en production |
| Mesures du serveur (étapes 5–7) | implémentation et preuves de lab | projet | plan de la mission |
| Homologation | décision formelle (et commission) | AH de l'organisme | après les points ci-dessus |

## 7. Produits agréés à acquérir (HORS PROJET)

| Besoin | Type de produit | Remarque |
|---|---|---|
| Liaison entre sites | **chiffreur IP agréé DR** (un par site) | remplace WireGuard du lab |
| Chiffrement du disque du serveur (si exigé) | produit de chiffrement de disque agréé DR | à défaut, acceptation de LUKS2 + TPM par l'AH |
| Authentification forte des administrateurs | cartes à puce / clés FIDO2 et leur gestion | moyen agréé si l'AH l'exige |
| Poste d'administration | poste durci de l'organisme (éventuellement solution agréée) | — |
| Supports de la racine PKI | supports chiffrés agréés + coffre | cérémonie (`politique-certification.md` §8) |

## 8. État des mesures DR du serveur (lu par le logiciel)

La quarantaine (étape 11) ne peut être activée que si la ligne ci-dessous vaut exactement
`mesures_dr_serveur: en place`. Ce champ ne doit être changé qu'après réalisation et preuve de
toutes les mesures du §5 marquées serveur, et décision de l'AH (§6).

mesures_dr_serveur: non

## 9. Décision

| | |
|---|---|
| Décision d'homologation | **non prononcée** (pas d'AH) |
| Recommandation de Claude (rôle AH « au mieux ») | ne pas mettre en service avec des données DR tant que les écarts §6 ne sont pas levés ; usage de lab et de qualification seulement |
