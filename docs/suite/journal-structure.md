# Journal structuré (v2.3.0, 23/11/2026)

Étude E1 (`etude-conformite-e1.md` §2.2, R6 « journalisation centralisée, horodatée, protégée ») :
format structuré des événements d'audit et de passage. Code : `serveur/audit/src/structure.rs`
(format), `serveur/audit/src/lib.rs` (schéma strict du journal chaîné). Le format est produit à
partir du journal chaîné, qui reste la référence ; il est envoyé au collecteur Syslog
(`journal-syslog.md`) et téléchargeable dans la Console (« Conservation et export », lien
« exporter tout le journal conservé », consultation journalisée) ou par
`sudo barbacane-audit structurer /var/lib/barbacane-serveur/svc/etat/registre/audit.jsonl`.

## 1. Une ligne JSON par événement

```json
{"acteur":"passerelle","categorie":"passages","donnees":{"borne":"0b6f…","fichiers":2,"partie":1,"passage":"1c6f…","verdict":"menace"},"empreinte":"<SHA-384>","gravite":"avertissement","gravite_code":4,"horodatage":"2026-11-18T11:06:40Z","id":"<32 hex>","n":7,"prec":"<SHA-384>","schema":"barbacane.journal/1","serveur":"barbacane-serveur","type":"rapport_passage"}
```

| Champ | Contenu | Stabilité |
|---|---|---|
| `schema` | `barbacane.journal/1` | change seulement si un champ change de sens ou disparaît |
| `serveur` | nom du serveur (`/etc/hostname`, `[A-Za-z0-9.-]`) | — |
| `id` | 32 premiers caractères hexadécimaux de l'empreinte de la ligne : **identifiant unique et stable** (un renvoi après coupure porte le même `id`) | stable |
| `n` | numéro d'ordre dans la chaîne (continu d'un segment à l'autre) | stable |
| `horodatage` | heure de réception par le serveur, **RFC 3339, UTC**, à la seconde (`…Z`) | stable |
| `gravite`, `gravite_code` | gravité RFC 5424 : `erreur` 3, `avertissement` 4, `avis` 5, `info` 6 (§3) | stable |
| `categorie` | `bornes`, `mises_a_jour`, `utilisateurs`, `passages`, `administration`, `quarantaine`, `journal` | stable |
| `type` | nom de l'événement du journal chaîné (§2) | stable ; de nouveaux types peuvent s'ajouter |
| `acteur` | `passerelle`, `web:<compte>`, `admin:uid-<n>`, `audit`, `conservation`, `syslog`, `sauvegarde`… | stable |
| `donnees` | champs de l'événement, exactement ceux du journal chaîné | stable par type |
| `empreinte`, `prec` | SHA-384 de la ligne chaînée et de la précédente : la chaîne reste vérifiable chez le collecteur | stable |

Les clés sont émises dans l'ordre alphabétique (sérialisation déterministe) ; un consommateur ne
doit pas dépendre de l'ordre.

**Données personnelles** : le schéma strict du journal chaîné **interdit tout nom de fichier**
(D2 : empreinte, taille, verdict seulement) et ne porte, pour les utilisateurs des bornes, que le
**pseudonyme** `u-<16 hex>` (HMAC-SHA256 à clé du serveur) ; les comptes de la Console sont
nominatifs (`web:<compte>`), par conception (journal nominatif des administrateurs, AIPD).

## 2. Types

Ceux du journal chaîné (`Evenement`, `serveur/audit/src/lib.rs`) : `jeton_cree`,
`enrolement_demande`, `enrolement_valide`, `enrolement_refuse`, `revocation`, `crl_publiee`,
`certificat_renouvele`, `battement_anormal`, `plancher_installe`, `maj_deposee`, `maj_refusee`,
`maj_diffusee`, `maj_proposee`, `maj_telechargee`, `maj_rapportee`, `utilisateurs_importes`,
`utilisateur_verifie`, `utilisateur_verrouille`, `borne_bloquee`, `pin_reinitialise`, `pin_change`,
`utilisateur_deverrouille`, `utilisateurs_purges`, `mode_site`, `politique_usb_site`,
`cle_usb_enrolee`, `cle_usb_retiree`, `politique_servie`, `rapport_passage`, `administration`,
`quarantaine`, `point_de_controle`, et depuis la v2.3.0 (schéma chaîné version 2) :
`segment_ouvert`, `segment_purge`, `purge` (`objet` : `passages` ou `sauvegardes`),
`conservation_reglee`, `syslog` (`action` : `configuration`, `clair`, `injoignable`, `reprise`,
`debordement`, `perte`).

`administration.action` : `connexion`, `connexion-refusee`, `consultation-passages`,
`consultation-passage:<borne>:<passage>:<partie>`, `consultation-utilisateurs`,
`consultation-utilisateur:<pseudonyme>`, `consultation-audit`, `consultation-conservation-export`,
`export-journal-structure`, `demande:<action>:<cible>:<id>`, `validation:…`,
`validation-refusee:<raison>:<id>`, `refus:<route>:<cible>`… (liste ouverte, toujours sans secret).

## 3. Gravité

| Gravité | Événements |
|---|---|
| 3 erreur | `utilisateur_verrouille`, `borne_bloquee` (alertes de force brute), `syslog` `debordement` et `perte` |
| 4 avertissement | `revocation`, `battement_anormal`, `maj_refusee`, `maj_rapportee` en échec, `utilisateur_verifie` refusé, `rapport_passage` menace/refusé/erreur, `administration` contenant `refus` ou `verrouill`, `quarantaine` refusée, `syslog` `clair` et `injoignable` |
| 5 avis | changements de configuration et d'état (enrôlement validé/refusé, plancher, modes et politiques de site, clés USB, PIN réinitialisé, purges, `segment_purge`, `conservation_reglee`, autres actions d'administration, quarantaine, `syslog` `configuration` et `reprise`) |
| 6 info | le reste (consultations, connexions, passages sains, points de contrôle, ouvertures de segment…) |

## 4. Enveloppe Syslog (RFC 5424)

`<PRI>1 HORODATAGE SERVEUR barbacane - TYPE [barbacane@32473 n="N" id="ID" reprise="0|1"] BOM JSON`

- `PRI` = 13 × 8 + gravité (facilité 13, « log audit ») ;
- `MSGID` = `type` ; données structurées : numéro, identifiant, **`reprise="1"`** pour un message
  renvoyé après une coupure (doublon possible, reconnaissable à son `id`) ;
- SD-ID `barbacane@32473` : 32473 est le numéro d'entreprise réservé à la documentation (RFC 5612),
  à remplacer si le projet obtient le sien (choix à valider, `decisions.md`) ;
- message : marque d'ordre des octets UTF-8 puis la ligne JSON du §1.

## 5. Preuves

`structure::tests::structure_et_syslog` (champs, RFC 3339, gravité, PRI, ligne altérée refusée),
`serveur/audit/tests/segments.rs` `commande_conservation` (commande `structurer`),
`serveur/web/tests/journal.rs` (export de la Console, journalisé), `serveur/passerelle/tests/syslog.rs`
et le banc QEMU (`tests/serveur/qemu-journal.sh` : messages reçus par un collecteur).
