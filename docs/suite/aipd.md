# Analyse d'impact relative à la protection des données (AIPD) — trame

Barbacane suite, v0.1 du 19/11/2026, révisée le 22/11/2026 (v2.2.0 : comptes de la Console). Trame à compléter par le responsable de traitement de
l'organisme qui déploie (nom, DPO, instances consultées). Méthode : celle de la CNIL (PIA).
Décisions prises par défaut : `decisions.md`.

## 1. Description du traitement

| Rubrique | Contenu |
|---|---|
| Finalité | Traçabilité de la décontamination des supports amovibles (qui a présenté quel support, quand, sur quelle borne, avec quel verdict) pour l'investigation des incidents de sécurité. |
| Base légale | Mission d'intérêt public / intérêt légitime de l'organisme à la sécurité de son SI (art. 6.1.e ou 6.1.f RGPD), selon la nature de l'organisme. |
| Personnes concernées | Agents et prestataires utilisant les bornes ; titulaires des comptes de la Console (administrateurs, opérateurs, auditeurs, lecture seule). |
| Données | Identifiant de l'agent (mode Identification ou Authentification), importé de l'annuaire (identifiant seul, LDAPS en lecture seule) ; pseudonyme dérivé (HMAC-SHA256 à clé du serveur), seul nom porté par le journal d'audit ; PIN Barbacane **dérivé** (Argon2id poivré, jamais en clair) ; compteur d'échecs et état de verrouillage ; horodatage ; borne et site ; verdict ; nombre, empreintes SHA-256, extensions et tailles des fichiers (**pas les noms**) ; identifiant du support (fabricant, modèle, n° de série). **Comptes de la Console** (v2.2.0, `comptes-administrateurs.md` §1) : identifiant nominatif, rôle, état, empreinte, numéro de série et échéance du certificat, hachage Argon2id du mot de passe, dates de création, de dernier accès et de changement du mot de passe, compte créateur ; journal d'audit nominatif de leurs actions (connexions, consultations, demandes et validations). La clé privée et le mot de passe du `.p12` ne sont conservés nulle part. |
| Données exclues | Noms de fichiers (D2) ; mots de passe d'annuaire (jamais saisis sur une borne). Contenu des fichiers : seulement si la quarantaine est activée (désactivée par défaut, D3) — l'AIPD doit alors être revue (contenu potentiellement personnel et DR). |
| Destinataires | Administrateurs de site (leur périmètre), auditeurs (lecture seule, identifiants en clair), équipe sécurité lors d'un incident. Aucun transfert hors UE ; aucun sous-traitant (serveur sur site, sans Internet). |
| Durée de conservation (comptes de la Console) | Compte : jusqu'à sa suppression (son certificat est alors révoqué) ; « dernier accès » remplacé à chaque connexion ; actions des comptes dans le journal d'audit : même durée que le journal (1 an, configurable en 2.3 par double validation). |
| Durée de conservation | 1 an pour les rapports et journaux, sauvegardes comprises (purge automatique). Départ de l'agent (absent de l'annuaire à la synchronisation) : PIN dérivé effacé **aussitôt**, compte inutilisable ; correspondance identifiant ↔ pseudonyme conservée **1 an** (pour exploiter les journaux de la même durée) puis purgée automatiquement (`serveur-utilisateurs.md` §6). *Révision du 20/11/2026 : remplace « comptes supprimés 1 mois après le départ », incompatible avec l'exploitation d'un an de journaux.* |
| Mode « Aucun » | Aucune donnée personnelle (journal anonyme) : hors champ de l'AIPD. |

## 2. Nécessité et proportionnalité

- Minimisation : pas de nom de fichier, pas de contenu ; identifiant pseudonymisé hors rôle auditeur
  (journal d'audit : pseudonyme seulement ; administrateur : pseudonymes, sauf le compte qu'il saisit) ;
  de l'annuaire, seul l'attribut d'identifiant est lu ; mode Aucun : rien n'est conservé même si une
  borne envoie un identifiant.
- Le mode est choisi par l'administrateur par site : Identification seulement là où la traçabilité
  nominative est justifiée.
- Information des personnes : affichage sur la borne (« Vos actions sur cette borne sont
  enregistrées… ») et note d'information interne ; consultation des instances représentatives du
  personnel avant mise en service (contrôle de l'activité des agents).
- Droits : accès et rectification auprès du responsable de traitement ; export des entrées d'un
  identifiant depuis l'interface web (rôle auditeur) ; pas de droit d'opposition au-delà de ce que
  permet la finalité de sécurité (à préciser par le DPO).

## 3. Risques

| Risque | Origine | Gravité / vraisemblance (avant) | Mesures | Résiduel |
|---|---|---|---|---|
| Accès illégitime aux journaux | administrateur, attaquant sur le serveur | importante / significative | rôles séparés, 2 facteurs, poste d'administration dédié, audit chaîné exporté, disque chiffré | limitée / limitée |
| Détournement de finalité (surveillance des agents) | hiérarchie | importante / limitée | finalité écrite, accès restreint aux auditeurs, consultations journalisées, information des IRP | limitée / négligeable |
| Fuite des PIN | serveur compromis | importante / limitée | Argon2id (64 Mio) poivré par une clé du serveur, aucun PIN sur la borne, PIN initial à changer au premier usage, verrouillage après 5 échecs | négligeable / négligeable |
| Fuite du compte de service de l'annuaire | serveur compromis | limitée / limitée | compte en lecture seule, droits minimaux, mot de passe 0600 (TPM prévu), LDAPS avec CA épinglée | négligeable / limitée |
| Verrouillage malveillant de comptes (déni de service) | personne présente à une borne | limitée / limitée | blocage de la borne après 5 refus en 1 h (délai croissant), alertes d'audit, déverrouillage immédiat par l'administrateur | négligeable / limitée |
| Usurpation d'un compte de la Console | administrateur malveillant, vol du `.p12` | importante / limitée | deux facteurs (certificat + mot de passe), double validation des créations et élévations, changement imposé du mot de passe provisoire, `.p12` téléchargeable une fois, journal nominatif des deux administrateurs | limitée / négligeable |
| Conservation excessive | défaut de purge | limitée / significative | purge automatique testée, y compris sauvegardes | négligeable / limitée |
| Révélation d'informations sensibles par les noms de fichiers | transmission en clair | importante / significative | noms jamais transmis (D2) | négligeable |
| Exposition de fichiers en quarantaine | serveur, analyste | importante / limitée | quarantaine désactivée par défaut, chiffrée pour une clé hors serveur, activation par double validation, jamais avec un site en mode Aucun (D13, v2.2.0) | limitée / négligeable |

## 4. Validation

| Rôle | Nom | Avis | Date |
|---|---|---|---|
| Responsable de traitement | | | |
| DPO | | | |
| RSSI | | | |
| Instances représentatives | | | |
