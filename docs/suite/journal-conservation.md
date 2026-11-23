# Conservation, purge et segments scellés du journal (v2.3.0, 23/11/2026)

Décision de l'utilisateur du 22/11/2026 (`decisions.md`) et étude E1 (`etude-conformite-e1.md`
§3, écart bloquant n° 1, P2) : **durée de conservation configurable par l'administrateur** dans la
Console, défaut 1 an, plafond imposé, changement audité et par **double validation** ; **purge
effective** des rapports de passage, **rotation du journal d'audit par segments scellés** (la
chaîne reste vérifiable), **purge des sauvegardes**. Code : `serveur/audit/src/{conservation,
segments}.rs`, `serveur/passerelle/src/conservation.rs`, `serveur/passerelle/src/passages.rs`
(`purger`), `serveur/web/src/journal.rs`, `serveur/sauvegarde/barbacane-sauvegarde`, unités
`barbacane-conservation*`.

## 1. Durée

| Valeur | Jours | Justification |
|---|---|---|
| Défaut | **365** | CNIL, recommandation journalisation (délibération 2021-122) : 6 mois à 1 an |
| Minimum | **180** | bas de la fourchette de la CNIL ; en deçà, un incident découvert tardivement ne pourrait plus être instruit |
| Plafond | **730** | au-delà d'1 an la CNIL demande une justification, que l'organisme consigne dans son AIPD (rappel affiché dans la Console) ; au-delà de 2 ans, aucune finalité de sécurité courante ne le justifie pour ces données (*choix de Claude à valider*) |
| Préavis | **7 jours** | toute **réduction** (et la valeur posée au premier démarrage) ne prend effet qu'après 7 jours, date d'effet affichée ; une augmentation est immédiate |

La même durée s'applique : aux **rapports de passage** (date de réception), au **journal d'audit**
(dont les actions des comptes de la Console : c'est la durée des journaux des administrateurs),
aux **correspondances identifiant ↔ pseudonyme** des utilisateurs retirés de l'annuaire (1 an
tant que le réglage n'est pas en vigueur) et aux **sauvegardes**. Restent à part : la
quarantaine (30 jours, `quarantaine.md`), le journal système journald (1 an, `MaxRetentionSec`,
dont `sudo` : journaux d'administration du système, pas de la Console).

Réglage : `<registre>/conservation.json` (0600, schéma strict, bornes revérifiées à chaque
lecture : un fichier hors bornes arrête la purge, jamais l'inverse).

## 2. Changement (Console, double validation)

Page **Journal → Conservation et export** (administrateur ; l'auditeur la consulte) : durée,
date d'effet, durée appliquée aujourd'hui, nombre de rapports conservés, segments du journal et
plus ancien enregistrement. « Demander le changement » → un **second administrateur** valide
(1 h, auto-validation refusée et journalisée), mécanisme de la v2.2.0 (`comptes-administrateurs.md`
§5, opération `conservation`). Journal : `demande:conservation:<n>j:<id>`,
`validation:conservation:<n>j:<id>`, puis `conservation_reglee {jours, effective_le}` (acteur :
le validateur ; `par` du réglage : `web:<demandeur>+<validateur>`).

## 3. Tâche planifiée

`barbacane-conservation.timer` : chaque nuit à 03:15 (± 10 min), 3 minutes après chaque
démarrage, rattrapage d'un passage manqué (`Persistent=true`) :

1. `barbacane-conservation-registre.service` (sous **barbacane-svc**, sans réseau) :
   `barbacane-registre … conservation` → pose le réglage s'il manque, purge des **rapports de
   passage** reçus avant la limite (fichiers et index réécrit atomiquement ; trace
   `purge {objet: passages, nombre, avant}` écrite **avant** la suppression ; un rapport
   illisible arrête la purge sans rien supprimer) ;
2. `barbacane-conservation.service` (**root**, seul compte qui lit la clé d'audit ; sans réseau,
   écriture limitée au registre) : `barbacane-audit conservation` → **rotation** du journal d'audit,
   **purge des segments** hors durée, **scellement** quotidien (un point de contrôle signé par jour au
   moins : la minuterie de scellement reportée depuis la v2.0.0 est ainsi faite).

## 4. Segments scellés du journal d'audit

- **Rotation** (une fois par jour UTC, si le journal actif contient des enregistrements d'un jour
  antérieur) : **toute** la chaîne est vérifiée, le journal actif est scellé (point de contrôle),
  rangé dans `audit-segments/<premier n sur 20 chiffres>.jsonl`, et le nouveau journal actif
  s'ouvre par `segment_ouvert {precedent, empreinte, cle, signature}` : signature ECDSA P-384 de la
  clé d'audit sur le numéro et l'empreinte de la dernière ligne rangée (contexte
  `barbacane-audit-v2 ouverture-de-segment`). La numérotation continue (`n`) d'un fichier à l'autre.
- **Purge** : les segments les plus **anciens** dont la dernière donnée (hors point de fermeture)
  est antérieure à la limite sont supprimés, du plus ancien au plus récent ; jamais un segment du
  milieu, jamais le journal actif ; seulement si **toute** la chaîne est intègre (sinon : aucune
  purge, aucune rotation, aucun scellement — l'altération reste visible). Chaque suppression est
  d'abord inscrite : `segment_purge {premier, dernier, empreinte}`.
- **Vérification** (`barbacane-audit verifier`, Console « Vérifier la chaîne », état du serveur) :
  segments puis journal actif ; le premier fichier présent part du tout premier enregistrement ou
  de **son ancre signée** (partie purgée : « enregistrements 1 à N purgés ») ; chaque fichier
  suivant doit s'ouvrir par une ancre qui prolonge exactement le précédent. Détectés (tests) :
  segment du milieu supprimé, segment renommé, ligne modifiée, ancre déplacée, début de journal
  remplacé par une chaîne fabriquée avec une autre clé. Un export d'empreintes antérieur à la purge
  reste accepté pour la partie présente ; ses points purgés sont comptés comme « non
  revérifiables », pas comme une altération.
- **Interruption** : nouveau journal écrit à part (`audit.jsonl.nouveau`), segment rangé, nouveau
  journal mis en place ; un journal actif absent est repris depuis `.nouveau`, ou refusé s'il reste
  des segments (jamais recréé vide : la chaîne repartirait de 1).
- **Propriétaire** : l'outil tourne en root dans le dossier de barbacane-svc ; chaque fichier créé
  reçoit le propriétaire du dossier (les services continuent d'écrire). Bac à sable systemd :
  écriture dans le registre seulement.

## 5. Sauvegardes

`barbacane-sauvegarde creer` (après sa rotation `--garder N`) et `barbacane-sauvegarde purger
--destination SUPPORT` suppriment du **support monté** les sauvegardes plus anciennes que la durée
(date UTC du nom de fichier ; `--conservation-jours N|aucune`, sinon la valeur en vigueur lue par
`barbacane-audit conservation-jours`) ; chaque purge est inscrite au journal d'audit
(`purge {objet: sauvegardes}`, acteur `sauvegarde`). Limites : un support rangé au coffre n'est
purgé qu'à son prochain montage (procédure : le monter au moins une fois par mois, `purger`) ; une
sauvegarde contient des données jusqu'à la durée de conservation à sa date : après une
**restauration**, la tâche de conservation (au démarrage, puis chaque nuit) purge aussitôt ce qui
a dépassé la durée.

## 6. Migration depuis la 2.2.0 et premier passage

Au premier démarrage de la Console 2.3.0 (ou au premier passage de la tâche), le réglage
**365 jours** est posé avec **préavis de 7 jours** (`conservation_reglee`, acteur
`premier-demarrage-2.3.0`) : **aucune purge pendant 7 jours**, même pour des données de plus d'un
an ; la Console affiche « aucune purge avant le … ». À la date d'effet, la première passe purge
d'un coup tout ce qui dépasse 365 jours, en le traçant (`purge`, `segment_purge`) ; les
administrateurs ont 7 jours pour allonger la durée (immédiat) ou pour exporter le journal
structuré. Le journal 2.2.0 (schéma 1) est relu tel quel puis rangé à la première rotation ; ses
lignes restent vérifiables. Retour arrière vers la 2.2.0 : non pris en charge une fois des
événements de schéma 2 écrits (la 2.2.0 signale le journal comme illisible, elle ne le lit jamais
en silence).

## 7. Limites

- `conservation.json` appartient à barbacane-svc (comme le journal et le registre) : un attaquant
  qui exécute du code sous ce compte (conteneur compromis) peut le réécrire et contourner la double
  validation et le préavis (dans les bornes 180–730 jours, revérifiées par root). Les purges restent
  tracées avant suppression et parties au collecteur Syslog ; séparation des comptes : 2.8.
- Un rapport de passage purgé puis renvoyé par une borne (qui ne l'aurait jamais vu accusé) serait
  de nouveau conservé, avec sa nouvelle date de réception.
- La purge suit la date de réception par le serveur ; une horloge du serveur faussée (aucune source
  NTP par défaut) décale d'autant les purges (`chrony`, §3.11 de la conception).

## 8. Preuves

| Test / banc | Ce qui est prouvé |
|---|---|
| `conservation::tests::preavis_et_bornes` | bornes, préavis des réductions et de la migration, augmentation immédiate |
| `serveur/audit/tests/segments.rs` | rotation et ancre, purge puis chaîne restante vérifiée (avec export antérieur), altérations détectées, purge refusée sur chaîne altérée, rotation interrompue, schémas 1 et 2, commande `conservation` (sans réglage, préavis, purge) |
| `passages::tests::purge_des_rapports_anciens` | purge des fichiers et de l'index, dossiers vidés, trace, rapport altéré : rien supprimé |
| `serveur/web/tests/journal.rs` | double validation (auto-validation refusée, auditeur refusé, bornes, CSRF), préavis |
| `tests/serveur/sauvegarde.sh` §5 | purge des sauvegardes par âge, préavis, inscription au journal par le vrai `barbacane-audit` |
| `tests/serveur/migration-v230.sh` | serveur 2.2.0 → 2.3.0 : données conservées, préavis respecté même pour des données de 400 jours, purge ensuite, retour arrière signalé |
| `tests/serveur/qemu-serveur.sh` + `qemu-journal.sh` | ISO installée : réduction par double validation, horloge +100 j puis +250 j, purge des passages, rotation et purge du journal, chaîne restante vérifiée (outil et Console), purge des sauvegardes |
