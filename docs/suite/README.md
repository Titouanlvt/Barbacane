# Barbacane v2 — la suite (serveur + borne en ligne)

État au 21/11/2026, branche `integration`. Ce document est la porte d'entrée : il ne décide rien
(les décisions sont dans [decisions.md](decisions.md)) et ne fait que reprendre les sections
FAIT / PRÉVU des documents ci-dessous et de [AVANCEMENT.md](../../AVANCEMENT.md).

## À retenir

- **Version** : la **v2.0.0** contient ce qui est FAIT ; **tous les points PRÉVU sont reportés en
  v2.1.0** (décision du 21/11, [notes v2.0.0](../notes-de-version/v2.0.0.md)).
- **La borne hors ligne v1 est inchangée** : `build-iso.sh` sans option produit la même ISO que
  la v1.0.0 (D12, [preuve](../preuves/2026-11-20-profil-en-ligne/README.md)) ; l'agent réseau
  n'existe que dans `--profil en-ligne`. Non-régression sur la borne 950 sans agent : 43 OK
  ([preuve](../preuves/2026-11-21-borne-utilisateurs/campagne-v1-950.txt)).
- **Charte v1 sur la borne** (en ligne comprise) ; **charte v2 seulement pour l'interface web du
  serveur** (adaptation simple, sans JavaScript, D10). L'adaptation v2 de la borne est suspendue.
- **Quarantaine optionnelle, désactivée par défaut** : depuis la décision du 21/11, c'est un choix
  des administrateurs (double validation, avertissement DR affiché et journalisé) ; le verrou
  `mesures_dr_serveur` n'est plus dans le logiciel ([quarantaine.md](quarantaine.md)).
- **Niveau visé : Diffusion Restreinte** (IGI 1300). Le projet n'homologue pas : la décision
  revient à l'autorité d'homologation de l'organisme ([dossier-homologation.md](dossier-homologation.md)).
  Manque encore, notamment : clés et secrets du serveur dans le **TPM** (aujourd'hui fichiers
  0600 ; preuves faites avec `swtpm` seulement), preuve sur machine physique avec TPM matériel et
  démarrage sécurisé, re-scellement TPM, double validation générale, deux facteurs des
  administrateurs, cérémonie PKI de production ; hors projet : chiffreur IP agréé DR entre sites,
  éventuel chiffrement de disque agréé, poste d'administration dédié. `mesures_dr_serveur: non`.

## Architecture en bref

```
 site A                                   LAN d'administration
 ┌──────────────┐  mTLS 1.3 (P-256)       ┌────────────────────────────────────┐
 │ borne en     │ ──────────────────────► │ serveur Barbacane (ISO durcie,      │
 │ ligne        │  enrôlement / battement │ LUKS2 + TPM, nftables, sans route   │
 │ barbacane-   │  /maj/* /rapport/passage│ par défaut, chrony local)           │
 │ agent        │  /utilisateurs/*        │  passerelle (rustls) · registre     │
 └──────────────┘                         │  audit chaîné P-384 · web (mTLS     │
 ┌──────────────┐                         │  admin, charte v2) · quarantaine    │
 │ borne hors   │  aucun réseau (v1)      │  (option) · ISO des bornes          │
 │ ligne v1     │                         └────────────────────────────────────┘
 └──────────────┘       PKI : racine hors ligne → CA bornes / serveur / administrateurs
```

Les bornes ne transmettent jamais de nom de fichier (D2 : sha256, extension, taille). Les mises à
jour restent des `.bcu` signés hors ligne et revérifiés par la borne.

## Index des documents

| Document | Contenu |
|---|---|
| [../conception-barbacane-suite.md](../conception-barbacane-suite.md) | Conception d'ensemble de la suite et plan par étapes (§8). |
| [decisions.md](decisions.md) | Journal des décisions D1–D14 et décisions de l'utilisateur du 21/11. |
| [revue-conception-2026-11-19.md](revue-conception-2026-11-19.md) | Revue de sécurité et de conformité de la conception (19/11). |
| [dossier-homologation.md](dossier-homologation.md) | Dossier d'homologation DR (EBIOS RM simplifié), mesures, écarts, produits agréés à acquérir. |
| [aipd.md](aipd.md) | Trame d'analyse d'impact relative à la protection des données. |
| [politique-certification.md](politique-certification.md) | Politique de certification de la PKI (racine hors ligne, CA, CRL, cérémonie). |
| [serveur-socle.md](serveur-socle.md) | Jalon 1 du socle : PKI de test et passerelle mTLS. |
| [protocole-agent.md](protocole-agent.md) | Protocole borne ↔ serveur v1 : enrôlement, battement, ajouts mises à jour, rapports, utilisateurs. |
| [serveur-iso.md](serveur-iso.md) | ISO du serveur : LUKS2 + TPM, pare-feu, heure, sauvegarde/restauration. |
| [serveur-maj-audit.md](serveur-maj-audit.md) | Journal d'audit chaîné et mises à jour centralisées. |
| [serveur-web.md](serveur-web.md) | Interface web d'administration (mTLS, Argon2id, CSRF, charte v2). |
| [serveur-utilisateurs.md](serveur-utilisateurs.md) | Utilisateurs (identifiant/PIN, LDAPS), sites et modes, clés USB. |
| [serveur-iso-bornes.md](serveur-iso-bornes.md) | ISO des bornes personnalisées et téléchargées depuis le serveur. |
| [borne-en-ligne.md](borne-en-ligne.md) | Profil `en-ligne` de l'ISO borne, `barbacane-agent`, écrans identifiant/PIN. |
| [quarantaine.md](quarantaine.md) | Quarantaine côté serveur, optionnelle, désactivée par défaut. |

## Ordre de lecture

- **Exploitant** : ce README → [borne-en-ligne.md](borne-en-ligne.md) → [serveur-iso.md](serveur-iso.md)
  (installation, sauvegarde) → [serveur-web.md](serveur-web.md) → [serveur-utilisateurs.md](serveur-utilisateurs.md)
  → [serveur-iso-bornes.md](serveur-iso-bornes.md) → [quarantaine.md](quarantaine.md).
- **Homologation** : [decisions.md](decisions.md) → [dossier-homologation.md](dossier-homologation.md)
  → [revue-conception-2026-11-19.md](revue-conception-2026-11-19.md) → [aipd.md](aipd.md)
  → [politique-certification.md](politique-certification.md) → tableau ci-dessous et preuves.
- **Développeur** : [../conception-barbacane-suite.md](../conception-barbacane-suite.md) →
  [protocole-agent.md](protocole-agent.md) → [serveur-socle.md](serveur-socle.md) →
  [serveur-maj-audit.md](serveur-maj-audit.md) → [serveur-web.md](serveur-web.md) → les autres.

## FAIT / PRÉVU par composant

« FAIT » = livré en v2.0.0, fusionné dans `integration` avec CI locale verte ; la colonne preuve renvoie à
`docs/preuves/` quand une preuve de lab existe (sinon : tests automatiques du dépôt). « PRÉVU » = reporté en **v2.1.0**.

| Composant | FAIT (v2.0.0) | Preuve | PRÉVU (v2.1.0) |
|---|---|---|---|
| PKI et passerelle mTLS ([serveur-socle.md](serveur-socle.md)) | PKI de TEST (racine/CA P-384, feuilles P-256), TLS 1.3 seul, certificat client obligatoire, CRL relue à chaque connexion, fail-closed ; CA administrateurs de test | tests `mtls.rs`, `enrolement.rs` | clés dans le TPM, refus des certificats TEST en production, CRL de la racine et republication quotidienne automatique, service PKI séparé, racine du lab sur VM sans réseau |
| Enrôlement, battement, heure ([protocole-agent.md](protocole-agent.md)) | jeton 1 h à usage unique, validation par empreinte, certificat 90 jours, renouvellement à mi-vie, mode dégradé | [QEMU en ligne](../preuves/2026-11-21-qemu-en-ligne/README.md) | double validation des révocations massives, PostgreSQL |
| ISO serveur ([serveur-iso.md](serveur-iso.md)) | ISO durcie, LUKS2 scellé TPM (PCR 7), aucune route par défaut, seul le port tiré ouvert, Podman sans root, sauvegarde/restauration (QEMU + swtpm 42/42) | [2026-11-20-serveur-iso](../preuves/2026-11-20-serveur-iso/qemu-serveur.txt) | machine physique avec TPM matériel et démarrage sécurisé, re-scellement (shim, `systemd-pcrlock`), faillock, AIDE, GNSS/radio, sauvegarde planifiée et PostgreSQL |
| Audit et mises à jour ([serveur-maj-audit.md](serveur-maj-audit.md)) | audit chaîné SHA-384 + points de contrôle ECDSA P-384, `.bcu` vérifiés, plancher signé, routes `/maj/*` | tests du dépôt | minuteries de scellement/export, clé d'audit dans le TPM, `chattr +a`, clé distincte pour le `.bcu` serveur, plancher étendu, diffusion par lot avec double validation |
| Interface web ([serveur-web.md](serveur-web.md)) | mTLS admin + Argon2id, rôles, CSRF, CSP, sans JS ; enrôlement, révocation, mises à jour, audit, Passages ; Supervision corrigée à 1280 px | [captures Jour/Nuit](../preuves/serveur-web/captures/audit-jour.png) | TPM, service systemd durci, pare-feu d'administration, double validation, comparaison aux exports d'audit, lecture de la fin du journal |
| Utilisateurs et clés USB ([serveur-utilisateurs.md](serveur-utilisateurs.md)) | modes par site, PIN Argon2id poivré, anti force brute, pseudonymisation, LDAPS (TLS 1.2 en option auditée), pages web ; côté borne : écrans identifiant/PIN (charte v1), politique USB | [950 : 43 OK](../preuves/2026-11-21-borne-utilisateurs/campagne-v1-950.txt) (non-régression) | rattachement aux rapports, synchronisation périodique, secrets dans le TPM, mode par borne, rôles de site ; LDAPS prouvé sur faux annuaire seulement |
| Borne en ligne ([borne-en-ligne.md](borne-en-ligne.md)) | profil `en-ligne`, `barbacane-agent`, pare-feu, page Serveur (charte v1), mises à jour depuis le serveur ; ISO hors ligne identique à v1.0 | [profil en ligne](../preuves/2026-11-20-profil-en-ligne/README.md), [borne en ligne 2](../preuves/2026-11-20-borne-en-ligne-2/README.md), [QEMU en ligne](../preuves/2026-11-21-qemu-en-ligne/README.md) | clés dans le TPM, session jointe aux rapports, captures des nouveaux écrans |
| Rapports de passage ([protocole-agent.md](protocole-agent.md) §10) | route `/rapport/passage` sans nom de fichier, file et rejeu de l'agent, page Passages | [QEMU en ligne](../preuves/2026-11-21-qemu-en-ligne/README.md) (analyse simulée), [950 : 43 OK](../preuves/2026-11-20-rapports-passage/campagne-v1-950.txt) | PostgreSQL, rapport d'analyse en échec, signature par la borne, rétention/purge, analyse réelle de bout en bout |
| ISO des bornes ([serveur-iso-bornes.md](serveur-iso-bornes.md)) | remaster sur la vraie ISO en ligne (seule différence `parametres.conf`), page web, enrôlement sans saisie en QEMU (AVANCEMENT) | tests du dépôt | construction complète de l'ISO serveur avec ISO embarquées |
| Quarantaine ([quarantaine.md](quarantaine.md)) | option désactivée par défaut, double validation, AES-256-GCM, 30 jours, avertissement DR | tests du dépôt | clé dans le TPM, chiffrement sur la borne pour une clé d'analyste hors serveur, envoi par l'agent, fichiers > 4 Mio |
| Homologation ([dossier-homologation.md](dossier-homologation.md)) | dossier, AIPD, politique de certification, décisions | — | décision de l'AH, produits agréés (chiffreur IP, disque, FIDO2/carte à puce, poste d'administration), cérémonie de la racine |
