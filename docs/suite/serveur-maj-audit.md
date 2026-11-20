# Serveur — journal d'audit chaîné et mises à jour centralisées (étapes 2 et 3, 20/11/2026)

Suite du socle (`serveur-socle.md`, `protocole-agent.md`). Conception : §3.7 (plancher signé hors
ligne), §3.9 (journal d'audit), §8 étapes 2 et 3, §9 (`.bcu` du serveur). Décisions appliquées :
D1 (serveur traité comme un SI DR), D2 (aucun nom de fichier), D6 (cryptographie).

## 1. Journal d'audit chaîné (`serveur/audit`, crate `barbacane-audit`)

| Propriété | Mise en œuvre |
|---|---|
| Schéma strict | une ligne JSON par enregistrement `{"v":1,"n":…,"le":…,"acteur":…,"evenement":{…},"prec":…}` ; la ligne doit être **exactement** la sérialisation canonique de son contenu (champ inconnu, répété, réordonné, espace ajouté → refus) ; textes bornés (`[A-Za-z0-9._:+~=-]`, 128) ; 2 Kio par ligne ; aucun nom de fichier ni d'utilisateur (D2) |
| Événements | `jeton_cree`, `enrolement_demande` / `_valide` / `_refuse`, `revocation`, `crl_publiee`, `certificat_renouvele`, `battement_anormal` (horloge dérivée, hors service, borne refusée — au **changement d'état**), `plancher_installe`, `maj_deposee`, `maj_refusee` (motif), `maj_diffusee`, `maj_proposee`, `maj_telechargee`, `maj_rapportee`, `rapport_passage` (protocole §10, sans nom de fichier), `administration` (consultations), `point_de_controle` |
| Chaînage | `prec` = **SHA-384** de la ligne précédente (96 zéros pour la première), `n` croissant de 1 en 1 |
| Ajout seul | `O_APPEND`, jamais de réécriture (compatible `chattr +a`), verrou `flock` entre écrivains ; une dernière ligne incomplète bloque tout ajout (fail-closed) |
| Points de contrôle | `barbacane-audit sceller JOURNAL CLE` : vérifie **toute** la chaîne puis ajoute un enregistrement signé **ECDSA P-384 / SHA-384** (D6) sur `contexte ‖ n ‖ empreinte du dernier`. Clé d'audit **distincte**, refusée si lisible par d'autres comptes |
| Vérification | `barbacane-audit verifier JOURNAL CLE.pub [EXPORT…]` : code 0 intègre, **2 altéré** (modification, suppression, réordonnancement, point de contrôle faux, désaccord avec un export) |
| Export quotidien | `barbacane-audit exporter JOURNAL CLE.pub DOSSIER` → `empreintes-audit-AAAAMMJJHHMMSS.txt` (SHA-384 de chaque point de contrôle), **à sortir du serveur** (support non réinscriptible ou serveur de journaux distinct) ; refusé si la chaîne est altérée |
| Horodatage | heure de réception du serveur (référence du site, §3.11) |

Ordre d'écriture : l'enregistrement d'audit est écrit **dans** la transaction du registre, juste
avant l'écriture du registre ; si l'audit échoue, l'opération est annulée (aucune action sans
trace). Une erreur d'écriture du registre après l'audit laisse une trace d'une tentative, jamais
l'inverse.

Séparation des rôles (§3.9) : la passerelle et `barbacane-registre` écrivent `audit.jsonl` dans le
dossier du registre **sans** clé ; seul le compte d'audit (minuterie horaire `sceller`, export
quotidien) détient la clé privée. Une compromission de la passerelle ne permet pas de forger un
point de contrôle.

### Ce que la chaîne détecte, et ce qu'elle ne détecte pas

| Altération | Détectée par | Preuve (`serveur/audit/tests/chaine.rs`) |
|---|---|---|
| Modification d'une ligne | chaînage de la suivante, ou signature du point | `modification_detectee` |
| Suppression d'une ligne | numéro d'ordre | `suppression_detectee` |
| Réordonnancement | numéro d'ordre | `reordonnancement_detecte` |
| Suppression puis rechaînage complet sans la clé | signature du point de contrôle | `rechainage_sans_cle_detecte` |
| Troncature, réécriture complète re-signée avec la clé volée | export conservé hors du serveur | `troncature_et_reecriture_detectees_par_export` |
| Écriture interrompue | dernière ligne incomplète ; ajout et scellement refusés | `ecriture_interrompue_bloque_l_ajout_et_le_scellement` |
| **Troncature des enregistrements postérieurs au dernier point** | **non détectable** : fenêtre = période de scellement (1 h). Le bilan l'affiche (« postérieurs au dernier point ») | — |

## 2. Mises à jour centralisées (côté serveur)

Le serveur **ne signe jamais** un `.bcu` : il le **relaie**. La borne revérifie tout (signature
minisign, anti-retour sur la version du manifeste, empreintes) comme pour une clé USB.

### 2.1 Fichiers (dossier `<registre>/maj/`, 0700)

| Fichier | Rôle |
|---|---|
| `cle-bornes.pub` | clé publique minisign **des bornes** (la même que `/etc/barbacane/maj.pub`), posée à l'installation ; absente → tout dépôt refusé. Au lab : `~/cles-test/test.pub` (clé de TEST), **jamais** la clé de production |
| `plancher.json` + `.minisig` | plancher signé hors ligne |
| `paquets/barbacane-maj-N.bcu` + `.minisig` | paquets acceptés |
| `etat.json` (+ `etat.verrou`) | paquets, plancher, paquet diffusé, suivi par borne |

### 2.2 Plancher signé hors ligne (§3.7, partie « versions »)

`serveur/maj/barbacane-plancher-prepare --cle CLE --version-min N --sortie DOSSIER` (poste hors
ligne, même clé que les `.bcu`) produit `plancher.json` =
`{"format":1,"usage":"barbacane-plancher-maj","version_min":N}` et sa signature. Le serveur vérifie
la signature avec `cle-bornes.pub`, le schéma strict, l'usage, et refuse un plancher **en recul**
(N inférieur au plancher installé : rejeu d'un ancien plancher). Sans plancher, aucun dépôt.

### 2.3 Dépôt (`barbacane-registre CONFIG maj-deposer FICHIER.bcu`)

Contrôles, dans l'ordre, sur une **copie** faite par le serveur (la vérification porte sur les
octets conservés, pas sur le fichier de l'administrateur qui pourrait changer entre-temps) :
clé des bornes présente, `.minisig` présent, taille ≤ 4 Gio, signature minisign du fichier entier
(Ed25519, D6), commentaire de confiance (signé) exactement `barbacane-maj version N`, plancher
installé et N ≥ plancher, N > toute version déjà déposée (anti-retour). Tout refus est audité
avec son motif. Le serveur **ne décompresse pas** le paquet (surface minimale : la version est
lue dans le commentaire signé, la borne contrôle le manifeste).

`maj-diffuser N` : N déposé, ≥ plancher, ≥ paquet déjà diffusé. `maj-etat` : paquets, plancher,
suivi par borne.

### 2.4 Diffusion (protocole, ajouts compatibles : `protocole-agent.md` §9)

- `POST /maj/battement` (mTLS) : même corps et mêmes contrôles que `/battement`, réponse
  `AccuseBattementMaj` = accusé + `mise_a_jour` facultative `{version_maj, sha256, taille,
  signature_minisign}` (si un paquet est diffusé et que la borne ne l'a ni appliqué ni rapporté en
  échec). `/battement` reste inchangé.
- `POST /maj/telechargement` (mTLS) `{"version":1,"version_maj":N}` → `200
  application/octet-stream` : seulement pour une borne active à qui N est proposé. 8
  téléchargements simultanés, durée totale 20 s + 1 s par 512 Kio.
- `POST /maj/rapport` (mTLS) `{"version":1,"version_maj":N,"resultat":"appliquee"|"echec"}`.
- Suivi par borne : `proposee` → `telechargee` (dernier octet envoyé) → `appliquee` | `echec`.

## 3. État

| Élément | État |
|---|---|
| Crate `barbacane-audit` (chaîne, points signés P-384, vérification, export, commande) | FAIT |
| Appels d'audit dans la passerelle et `barbacane-registre` | FAIT |
| Dépôt vérifié, plancher signé, diffusion, téléchargement mTLS, suivi | FAIT |
| Tests : chaîne altérée, `.bcu` refusés, proposition/téléchargement/suivi | FAIT |
| Minuterie systemd du scellement (horaire) et de l'export (quotidien), compte d'audit dédié | PRÉVU (ISO serveur) |
| Clé d'audit dans le TPM ; `chattr +a` posé à l'installation | PRÉVU |
| `.bcu` du serveur signé par une **clé distincte** (§9) et apportant l'ISO des bornes | PRÉVU |
| Plancher étendu au reste du §3.7 (CA, sites, paramètres non négociables), politique à chaud | PRÉVU |
| Diffusion par site ou par lot, double validation (§3.10), interface web (D10) | PRÉVU |
| Agent de la borne utilisant `/maj/*` | PRÉVU (chantier borne en ligne) |
| Journal distant temps réel (syslog TLS) en plus de l'export | HORS PROJET (choix du client) |
| Agrément d'un produit de journalisation | HORS PROJET (`dossier-homologation.md` §7) |

## 4. Dépendances

Aucune crate nouvelle dans `Cargo.lock` : `ring` (SHA-384, ECDSA P-384), `minisign-verify` (déjà
utilisé par `borne/admind`), `serde`, `serde_json`, `hex`, `data-encoding`, `anyhow`.

## 5. Preuves

Tests (`cargo test -p barbacane-audit -p barbacane-passerelle`) :
`serveur/audit/tests/chaine.rs` (8, tableau du §1) et `serveur/passerelle/tests/maj.rs` :

| Test | Prouve |
|---|---|
| `bcu_non_signe_mal_signe_ou_sous_le_plancher_refuse` | refus sans clé des bornes, sans plancher, plancher d'une autre clé, `.bcu` non signé, signé par une autre clé, altéré après signature, sous le plancher, version déjà déposée ou plus ancienne, plancher en recul ; rien de refusé n'est conservé ; chaque motif audité |
| `bcu_valide_propose_au_battement_telecharge_en_mtls_et_suivi` | proposition au battement (version, sha256, taille, signature) ; `/battement` inchangé ; téléchargement refusé sur l'écoute d'enrôlement, sans certificat, pour une borne non proposée ou une autre version, après révocation ; octets identiques ; états `proposee` → `telechargee` → `appliquee` / `echec` ; rapport unique ; journal intègre et complet, une seule proposition auditée par borne et version |
| `anomalies_de_battement_auditees_au_changement` | trois battements en dérive → une seule entrée `battement_anormal` |

Lab (VM bu, 20/11/2026, clé de **TEST** `~/cles-test/test.pub`, paquets de test de
`tests/maj/maj.sh`) : plancher 202611170000 signé avec `~/cles-test/test.key` et installé ;
`mauvaise-signature/…1500.bcu` → « signature invalide pour la clé des bornes » (code 1) ;
`ancienne/…-1.bcu` → « version sous le plancher signé » (code 1) ; `paquet/…1453.bcu` accepté
(352 octets, sha256 `3ee0fcec…9dea`) puis diffusé ; scellement, export et `verifier` → code 0 ;
une version modifiée dans le journal → « ligne 6 : chaînage rompu », code 2.
