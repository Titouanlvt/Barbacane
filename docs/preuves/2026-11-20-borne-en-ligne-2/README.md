# Borne en ligne, 2e jalon : écran Serveur, mises à jour relayées (20/11/2026)

Branche `borne-en-ligne-2`, vérifiée sur bu (Debian 13). Doc : `docs/suite/borne-en-ligne.md`.

## 1. Bout en bout sans VM (`agent-bout-en-bout.txt`)

`tests/suite/agent-bout-en-bout.sh` (vrais binaires : passerelle, barbacane-registre, agent,
barbacane-admind en `dry_run`) : **OK**.

- jeton d'un autre port refusé par admind ; jeton en minuscules accepté (op `serveur_jeton`) ;
  empreinte publiée par l'agent = empreinte relayée par admind = empreinte du registre ;
- mise à jour 200 déposée et diffusée → téléchargée par l'agent (octets identiques, suivi serveur
  `telechargee`) → **non appliquée** sans décision (`update_version` = 0) → op
  `serveur_appliquer_maj` : appliquée → serveur `appliquee` → dossier de l'agent vidé ;
- paquet 300 signé par une autre clé : refusé au dépôt par le serveur ; placé directement dans
  le dossier de l'agent (serveur compromis simulé) : **refusé par la borne** (« signature
  invalide »), `echec` rendu à l'agent, version installée inchangée (200) ;
- mode dégradé puis reprise, révocation → `refusee` : inchangés.

## 2. ISO hors ligne (sans option) identique à la v1.0.0 (`iso-hors-ligne.txt`)

Construite depuis la branche (commit 5098fbd, même `maj.pub` que la v1.0.0, sha256 `f3ba30ba…`),
comparée à `/travail/v100/barbacane-1.0.0.iso` (sha256 `5e0c3fba…3fc7`) par la méthode de
`../2026-11-20-profil-en-ligne/` :

| | |
|---|---|
| Fichiers de l'ISO (1782), paquets (272), fichiers des paquets barbacane et usbsas (53 + 53), scripts et preseed, données initiales | **identiques** (`branche-*.txt` ; les listes v1.0.0 sont celles de `../2026-11-20-profil-en-ligne/v100-*.txt`) |
| Empreintes des paquets | 269 identiques ; `barbacane`, `usbsas-server`, `usbsas-hid` recompilés (le code nouveau, inactif sans `agent.toml`, est dans `barbacane`) |
| `tests/iso/hors-ligne.sh` | **OK** (272 paquets, aucun agent, aucun paquet réseau) |

Premier essai écarté : la copie de travail ne contenait pas `systeme/iso/maj.pub` (fichier ignoré
par git) → ISO sans clé, signalée par la comparaison ; reconstruite avec la clé de la v1.0.0.

## 3. Tests Rust

`cargo test -p barbacane-agent` (9 unitaires + 7 d'intégration, dont
`mise_a_jour_telechargee_deposee_rapportee_jamais_appliquee`, `paquet_altere_sur_le_serveur_ecarte`),
`-p barbacane-admind` (dont `hors_ligne_aucune_fonction_serveur`,
`jeton_valide_strictement_et_depose`, `maj_du_serveur_verifiee_par_la_borne`),
`-p barbacane-client` (dont `hors_ligne_sans_page_serveur`) : OK ; clippy `-D warnings` OK.

## Non fait à ce jalon

- QEMU profil en ligne avec l'écran Serveur (`tests/iso/qemu-en-ligne.sh` non rejoué) ; pas de
  capture de la page Serveur (Xvfb absent de bu).
- Rapports minimaux de passage : PRÉVU (`docs/suite/protocole-agent.md` §10).
