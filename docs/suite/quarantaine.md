# Quarantaine côté serveur (étape 11, 20/11/2026)

Conception : `docs/conception-barbacane-suite.md` §3.6, §3.10 ; homologation :
`docs/suite/dossier-homologation.md` (§1, §2, §8). **Implémentée mais DÉSACTIVÉE par défaut**
(niveau Diffusion Restreinte). **Décision du 21/11/2026** : la quarantaine est une option que
l'administrateur choisit d'activer ou non ; le champ `mesures_dr_serveur` du dossier
d'homologation (toujours `non`) n'est plus un verrou logiciel. Aucun changement côté borne (v1 hors ligne et charte v1
intactes).

## FAIT

| Sujet | Mesure | Code / preuve |
|---|---|---|
| Option des administrateurs | désactivée par défaut ; rien n'est reçu ni exporté tant qu'elle n'est pas activée ; activation = seul choix des administrateurs (plus de `quarantaine.conf` ni de lecture du dossier d'homologation) | `desactivee_par_defaut`, `reception_refusee_si_desactivee` |
| Avertissement DR | page `/quarantaine` désactivée : « Les fichiers conservés en quarantaine peuvent être de niveau Diffusion Restreinte (DR) : n'activez qu'avec un stockage et des accès conformes. » (`AVERTISSEMENT_DR`) ; l'activation validée journalise aussi `avertissement-dr` avec l'identifiant `fichiers-conserves-peuvent-etre-DR:activer-seulement-avec-stockage-et-acces-conformes` | `serveur/web/tests/quarantaine.rs`, `activation_par_deux_administrateurs` |
| Activation | demande par un administrateur, validation par un SECOND administrateur distinct (1 h) ; refus explicite et audité (`validation-refusee`) ; désactivation par un seul (sens sûr) | `activation_par_deux_administrateurs` |
| Stockage chiffré | AES-256-GCM (`ring`, déjà audité) ; clé neuve de 32 octets par fichier, enveloppée AES-256-GCM par la clé de quarantaine (`<registre>/quarantaine/cle-quarantaine`, 0600, refusée si droits plus larges) derrière le trait `CleQuarantaine` (TPM prévu) | `chiffrement_dechiffrement_et_cle_0600` |
| Métadonnées minimales | identifiant aléatoire, uuid de borne, dates, SHA-256, taille ; jamais de nom de fichier | `Element` |
| Intégrité | métadonnées liées au chiffré (données associées) ; clé enveloppée liée à l'identifiant ; SHA-256 revérifié ; altération auditée (`alteration-detectee`) | `alteration_detectee` (octet du chiffré, prolongation de la date) |
| Conservation | 30 jours, purge à chaque réception, consultation et listage, sur min(date inscrite, réception + 30 j) ; purge auditée | `purge_a_echeance` |
| Réception | route mTLS `POST /quarantaine/depot` (`DepotQuarantaine`, 4 Mio max, base64, empreinte et taille revérifiées) ; désactivée → `403 quarantaine_desactivee` **avant la lecture du corps**, audité (`reception-refusee`, uuid de la borne) | `serveur/passerelle/tests/maj.rs` `quarantaine_refusee_par_la_passerelle_si_desactivee` |
| Accès | page `/quarantaine` (charte v2, sans JS) : état « Désactivée » et raison ; administrateur seul, auditeur 403 (page et actions) ; chaque consultation auditée ; export par double validation, restitué en pièce jointe neutralisée `quarantaine-<id>.bin` (`application/octet-stream`, jamais d'aperçu) | `serveur/web/tests/quarantaine.rs` |
| Audit | événement `quarantaine {action, element}` (version de schéma 1 gardée : ajout avant toute installation) | `serveur/audit/src/lib.rs` |

## PRÉVU

- Clé de quarantaine dans le TPM du serveur (implémentation de `CleQuarantaine`).
- Variante de la conception §3.6 : chiffrement **sur la borne** pour une clé d'analyste hors
  serveur (carte à puce), déchiffrement dans une VM d'analyse isolée seulement ; restitution en
  archive protégée.
- Envoi par la borne en ligne (agent) — aucun code côté borne dans ce chantier.
- Fichiers > 4 Mio (dépôt en flux), purge des sauvegardes.
- Deux facteurs hors ligne pour les administrateurs (§3.10), comme le reste de l'interface.
