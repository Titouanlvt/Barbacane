# Analyse d'impact relative à la protection des données (AIPD) — trame

Barbacane suite, v0.1 du 19/11/2026. Trame à compléter par le responsable de traitement de
l'organisme qui déploie (nom, DPO, instances consultées). Méthode : celle de la CNIL (PIA).
Décisions prises par défaut : `decisions.md`.

## 1. Description du traitement

| Rubrique | Contenu |
|---|---|
| Finalité | Traçabilité de la décontamination des supports amovibles (qui a présenté quel support, quand, sur quelle borne, avec quel verdict) pour l'investigation des incidents de sécurité. |
| Base légale | Mission d'intérêt public / intérêt légitime de l'organisme à la sécurité de son SI (art. 6.1.e ou 6.1.f RGPD), selon la nature de l'organisme. |
| Personnes concernées | Agents et prestataires utilisant les bornes ; administrateurs de l'interface web. |
| Données | Identifiant de l'agent (mode Identification ou Authentification) ; PIN Barbacane **dérivé** (Argon2id, jamais en clair) ; horodatage ; borne et site ; verdict ; nombre, empreintes SHA-256, extensions et tailles des fichiers (**pas les noms**) ; identifiant du support (fabricant, modèle, n° de série). Comptes d'administration et journal d'audit. |
| Données exclues | Contenu des fichiers ; noms de fichiers ; quarantaine (non implémentée, D2) ; mots de passe d'annuaire (jamais saisis sur une borne). |
| Destinataires | Administrateurs de site (leur périmètre), auditeurs (lecture seule, identifiants en clair), équipe sécurité lors d'un incident. Aucun transfert hors UE ; aucun sous-traitant (serveur sur site, sans Internet). |
| Durée de conservation | 1 an pour les rapports et journaux, sauvegardes comprises (purge automatique) ; comptes supprimés 1 mois après le départ de l'agent. |
| Mode « Aucun » | Aucune donnée personnelle (journal anonyme) : hors champ de l'AIPD. |

## 2. Nécessité et proportionnalité

- Minimisation : pas de nom de fichier, pas de contenu ; identifiant pseudonymisé hors rôle auditeur.
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
| Fuite des PIN | serveur compromis | importante / limitée | Argon2id, aucun PIN sur la borne, verrouillage après 5 échecs | négligeable / négligeable |
| Conservation excessive | défaut de purge | limitée / significative | purge automatique testée, y compris sauvegardes | négligeable / limitée |
| Révélation d'informations sensibles par les noms de fichiers | transmission en clair | importante / significative | noms jamais transmis (D1) | négligeable |

## 4. Validation

| Rôle | Nom | Avis | Date |
|---|---|---|---|
| Responsable de traitement | | | |
| DPO | | | |
| RSSI | | | |
| Instances représentatives | | | |
