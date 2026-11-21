# Avancement — Barbacane (état au 21/11/2026, après v2.0.0)

## Versions publiées
- **v1.0.0** (19/11/2026) : borne hors ligne — [notes](docs/notes-de-version/v1.0.0.md),
  [preuves](docs/preuves/2026-11-19-v1.0.0/README.md) (39/39).
- **v2.0.0** (21/11/2026, étiquette `v2.0.0` sur 82910cd) : serveur + borne en ligne —
  [notes](docs/notes-de-version/v2.0.0.md), [preuves](docs/preuves/2026-11-21-v2.0.0/README.md).
  Vue d'ensemble FAIT/PRÉVU : [docs/suite/README.md](docs/suite/README.md).

## Chantiers clos (tous fusionnés dans `integration`, CI locale « FIN 0 »)
| Chantier | Résultat |
|---|---|
| CI locale | `tests/ci-locale.sh`, `lab/ci-locale-bu.sh BRANCHE` (VM bu) |
| Socle serveur (PKI de test, passerelle mTLS) | TLS 1.3 seul, CRL relue à chaque connexion, fail-closed |
| Enrôlement, protocole agent, battement, heure | jeton 1 h, validation par empreinte, renouvellement à mi-vie |
| ISO serveur | LUKS2 scellé TPM (PCR 7), nftables sans route par défaut, Podman sans root, sauvegarde ; QEMU + swtpm |
| Borne en ligne (`--profil en-ligne`, `barbacane-agent`, page Serveur) | ISO hors ligne identique à v1.0.0 |
| Audit chaîné et mises à jour centralisées | SHA-384 + points signés P-384, routes `/maj/*` |
| Interface web d'administration (charte v2, sans JS) | mTLS admin, Argon2id, CSRF, CSP ; captures Jour/Nuit |
| Utilisateurs et clés USB (serveur et borne) | modes par site, PIN, LDAPS (TLS 1.2 en option auditée) |
| ISO des bornes depuis le serveur | remaster, enrôlement sans saisie (QEMU) |
| Rapports de passage | sans nom de fichier, file et rejeu |
| Quarantaine | option désactivée par défaut, double validation ; verrou `mesures_dr_serveur` retiré le 21/11 |
| Correctifs serveur, publication v2.0.0 | `passerelle.conf` complète, deux ports, `tests/iso/serveur-config.sh` |

## Chantier suspendu
- **Charte v2 sur la borne** (`borne-charte-v2`, non fusionnée) : suspendue le 20/11 par
  l'utilisateur, priorité au serveur. La borne reste en charte v1 ; la charte v2 ne sert qu'à
  l'interface web du serveur. Reste sur la branche : captures Nuit, creusé, pastilles, herse,
  campagne ; OCR PPM corrigé à reporter dans `integration`.

## v2.1.0 à faire (reprend les [notes v2.0.0](docs/notes-de-version/v2.0.0.md))
- **PKI et passerelle** : clés dans le TPM, refus des certificats TEST en production, CRL de la
- **Priorité 1 — test ISO intermittent** : `installation-qemu` (`tests/iso/qemu.sh`) échoue de façon aléatoire sur GitHub (même commit 82910cd : 2 succès, 1 échec ; échecs ensuite sur des commits sans code). Cause probable : plantage intermittent de usbsas-server au démarrage (déjà noté en v1.0.0). Reproduire sur bu (boucle de N démarrages), corriger, puis CI ISO stable.
  racine et republication quotidienne, service PKI séparé, racine du lab sur VM sans réseau ;
  cérémonie de production.
- **Enrôlement** : double validation des révocations massives ; PostgreSQL.
- **ISO serveur** : machine physique avec TPM matériel et démarrage sécurisé, re-scellement (shim,
  `systemd-pcrlock`), faillock, AIDE, GNSS/radio, sauvegarde planifiée.
- **Audit et mises à jour** : minuteries de scellement/export, clé d'audit dans le TPM, `chattr +a`,
  clé distincte pour le `.bcu` serveur, plancher étendu, diffusion par lot avec double validation.
- **Interface web** : TPM, service systemd durci, pare-feu d'administration, double validation
  générale (§3.10), deux facteurs des administrateurs, comparaison aux exports d'audit, fin du journal.
- **Utilisateurs et clés USB** : rattachement aux rapports, synchronisation de l'annuaire, secrets
  dans le TPM, mode par borne, rôles de site ; LDAPS sur un vrai annuaire ; raccorder
  `quarantaine_active()` (renvoie encore toujours faux, D13).
- **Borne en ligne** : clés dans le TPM, session jointe aux rapports, captures des nouveaux écrans.
- **Rapports de passage** : analyse en échec, signature par la borne, rétention/purge, analyse
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
