# Avancement — Barbacane (état au 23/11/2026, v2.3.0 publiée)

## Versions publiées
- **v1.0.0** (19/11/2026) : borne hors ligne — [notes](docs/notes-de-version/v1.0.0.md),
  [preuves](docs/preuves/2026-11-19-v1.0.0/README.md) (39/39).
- **v2.0.0** (21/11/2026, étiquette `v2.0.0` sur 82910cd) : serveur + borne en ligne —
  [notes](docs/notes-de-version/v2.0.0.md), [preuves](docs/preuves/2026-11-21-v2.0.0/README.md).
- **v2.0.1** (21/11/2026, étiquette `v2.0.1` sur 455c385) : ISO serveur complète (Console,
  registre, audit), seccomp `ppoll` d'usbsas-usbdev (test ISO intermittent), certificat de la
  Console — [notes](docs/notes-de-version/v2.0.1.md), [labo Proxmox](docs/preuves/2026-11-21-labo-proxmox/README.md).
  Vue d'ensemble FAIT/PRÉVU : [docs/suite/README.md](docs/suite/README.md).

## Chantiers clos
Socle serveur et PKI de test, Liaison bornes (mTLS, enrôlement, battement), ISO serveur (LUKS2/TPM,
nftables, Podman), Borne connectée, Journal d'audit chaîné et mises à jour centralisées, Console
(charte v2, sans JS), utilisateurs et clés USB, ISO des bornes depuis le serveur, rapports de
passage, Quarantaine optionnelle, CI locale (`lab/ci-locale-bu.sh BRANCHE`). Détail : notes de version.

## Chantier suspendu
- **Charte v2 sur la borne** (`borne-charte-v2`, non fusionnée) : suspendue le 20/11 par
  l'utilisateur, priorité au serveur. La borne reste en charte v1 ; la charte v2 ne sert qu'à
  l'interface web du serveur. Reste sur la branche : captures Nuit, creusé, pastilles, herse,
  campagne ; OCR PPM corrigé à reporter dans `integration`.

## Feuille de route (décidée le 21/11/2026)

Une version = une seule famille de fonctions ; tests + non-régression 950 si la borne change + preuve labo Proxmox, publication, puis la suivante. Détail, décisions et architecture cible : [docs/suite/point-serveur-2026-11-21.md](docs/suite/point-serveur-2026-11-21.md).

Sécurité d'abord ; porte de sortie de chaque version : revue de sécurité, CI, QEMU, 950, labo Proxmox, mise à jour depuis la précédente, retour arrière, doc. 2.0.1 fiabilité (USB ppoll, ISO serveur complète, banc QEMU, HTTPS, version) · 2.0.2 défauts du labo + noms · E1 étude de conformité (en parallèle, avant 2.4) · 2.1.0 grandes images ISO (Debian 13, Windows 11 : liste officielle ou analyse complète, sortie FAT32/exFAT/NTFS au choix) · 2.2.0 comptes administrateurs + D13 · 2.3.0 journal structuré + Syslog · 2.4.0 TPM serveur, AC hors passerelle, PKI de production · 2.5.0 chiffrement des bornes · 2.6.0 PIN par administrateur · 2.7.0 mises à jour signées du serveur + retour arrière · 2.8.0 installation modulaire + rôles séparés · 2.9.0 utilisateurs hybride · 2.10.0 liste blanche · 2.11.0 quarantaine par la borne · 2.12.0 dépôt vers le SI · 2.13.0 ergonomie et statistiques · 3.0.0 contrôle postes · ensuite module SOC/SIEM.

## E1 — étude de conformité (branche `etude-e1`, documentaire)
[docs/suite/etude-conformite-e1.md](docs/suite/etude-conformite-e1.md) : tableaux exigence → état → écart → version ; bloquants avant 2.4 (purge non implémentée, secrets en fichiers, export du journal) ; questions sur le niveau visé.

## v2.0.2 (publiée le 21/11/2026)
Défauts du labo du 21/11 : page 500 ponctuelle (admin-02), message de jeton, écran « Clé détectée »,
noms de site libres, doc barbadmin, noms fonctionnels ([labo](docs/preuves/2026-11-21-labo-proxmox/README.md)).

## v2.0.3 (branche `v203`, preuves faites, non fusionnée) : reprise des correctifs usbsas du CEA
Fait : base `c75c7eb`, écarts 1/3/8/10 retirés, 12 et 13 ajoutés, jiff 1.0, nix 0.32 ([notes](docs/notes-de-version/v2.0.3.md)).
151 commits amont depuis notre base `69ebcf4`, surtout du durcissement : `fsrw/ntfs3g` et `ff`
(fermetures, noms, NUL), `dev2scsi` (lectures hors périphérique, isolement, secteurs 4K, ISO9660),
`comm`/seccomp, `net` (TLS 1.3, limites). Reprise commit par commit, chaque reprise dans
`docs/noyau/ecarts.md`, même porte de sortie que les autres versions. Contributions envoyées au CEA
(fork `Titouanlvt/usbsas`) : `usbdev-allow-ppoll`, `usb-transfer-timeouts`. Avec : dépendances
`nix` 0.32 et `jiff` 1.0 (dependabot).

## v2.1.0 (branche `v210`, preuves faites, non fusionnée) : grandes images ISO
Image officielle vérifiée puis copiée en flux (écart 14), analyse complète avec plafond et
estimation, format de sortie au choix ([notes](docs/notes-de-version/v2.1.0.md)).

## v2.2.0 (branche `v220`, preuves faites, non fusionnée) : comptes administrateurs + D13
Comptes gérés dans la Console (4 rôles, `.p12`, politique, dernier accès), double validation
généralisée (comptes, certificats, révocation d'un site, activation et export de la quarantaine ; sa désactivation reste à un seul administrateur),
séparation des remises, D13 raccordée, migration des comptes 2.1.0
([notes](docs/notes-de-version/v2.2.0.md), [référence](docs/suite/comptes-administrateurs.md)).
Preuves ([dossier](docs/preuves/2026-11-22-v2.2.0/README.md)) : CI locale FIN 0, banc serveur
66 OK, banc borne 3/3, migration 2.1.0 → 2.2.0 14 OK, campagne 950 57 OK.
Choix à valider par l'utilisateur : `docs/suite/decisions.md` (22/11, v2.2.0).

## v2.3.0 (publiée le 23/11/2026) : journal structuré, Syslog, conservation
Format structuré (JSON par ligne, RFC 3339 UTC, identifiant, gravité RFC 5424), export Syslog
RFC 5424 en TLS 1.3 (mTLS possible) ou en clair signalé, file persistante (le journal) avec remise
confirmée, alertes ; durée de conservation réglée par double validation (365 j, 180–730 j, préavis
7 j), purge quotidienne des passages, rotation du journal d'audit en segments scellés (ancre
signée) et purge, purge des sauvegardes ; consultations journalisées ; migration 2.2.0 avec préavis
([notes](docs/notes-de-version/v2.3.0.md), références `docs/suite/journal-*.md`). Écarts E1 n° 1 et
n° 3 traités. Choix à valider : `docs/suite/decisions.md` (23/11, v2.3.0).

## Reporté après 2.0.2 (reprend les [notes v2.0.0](docs/notes-de-version/v2.0.0.md))
- **PKI et passerelle** : clés dans le TPM, refus des certificats TEST en production, CRL de la
  racine et republication quotidienne, service PKI séparé, racine du lab sur VM sans réseau ;
  cérémonie de production.
- **Enrôlement** : PostgreSQL (double validation des révocations massives : faite en 2.2.0).
- **ISO serveur** : machine physique avec TPM matériel et démarrage sécurisé, re-scellement (shim,
  `systemd-pcrlock`), faillock, AIDE, GNSS/radio, sauvegarde planifiée.
- **Audit et mises à jour** : export automatique des empreintes (le scellement quotidien est fait en 2.3.0), clé d'audit dans le TPM, `chattr +a`,
  clé distincte pour le `.bcu` serveur, plancher étendu, diffusion par lot avec double validation.
- **Interface web** : TPM, service systemd durci, pare-feu d'administration, facteur matériel
  des administrateurs, comparaison aux exports d'audit, fin du journal.
- **Utilisateurs et clés USB** : rattachement aux rapports, synchronisation de l'annuaire, secrets
  dans le TPM, mode par borne, rôles de site ; LDAPS sur un vrai annuaire (D13 raccordée en 2.2.0).
- **Borne en ligne** : clés dans le TPM, session jointe aux rapports, captures des nouveaux écrans.
- **Rapports de passage** : analyse en échec, signature par la borne, analyse
  réelle de bout en bout.
- **Quarantaine** : clé dans le TPM, chiffrement sur la borne pour une clé d'analyste hors serveur,
  envoi par l'agent, fichiers > 4 Mio.
- **Homologation** (hors logiciel) : décision de l'AH, produits agréés, cérémonie de la racine.

## Ouvert, à la décision de l'utilisateur
- Écran de confirmation avant l'effacement de la clé de destination (demandé par la charte).
- PR Dependabot ouvertes (nix 0.32, actix-web, jiff) : non fusionnées.
- `.github/workflows/iso.yml` garde `curl | sh` (décision du 18/11) ; jeton sans droit `workflow`.
- Signature d'une vraie mise à jour avec la clé de production (phrase de passe de l'utilisateur seul).

## Limites connues de la borne (v1, toujours valables)
- Analyse parallèle sur 4 fils : aucun gain mesuré (`docs/performances.md`) ; cible 4 To extrapolée.
- DVD, Blu-ray, poste physique : non testés ([bilan des preuves](docs/preuves/README.md)).

L'historique détaillé (journal du 14 au 21/11) est dans `git log -- AVANCEMENT.md`.
