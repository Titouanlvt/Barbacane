# Borne en ligne : profil `en-ligne` de l'ISO (20/11/2026)

Étape « borne en ligne » de la suite (conception §3.1, §3.5, §3.11, §10 ; décisions D2, D6, D9,
D12). La borne **hors ligne reste la v1** : `build-iso.sh` sans option produit la même ISO
(preuve : `docs/preuves/2026-11-20-profil-en-ligne/`). Agent : `borne/agent/README.md`.

## Construire l'ISO en ligne

```
systeme/iso/build-iso.sh --profil en-ligne \
    --ca-serveur ca-serveur.pem --serveur 10.20.0.5 \
    --port-enrolement 43118 --port-service 43117 \
    [--nom-serveur passerelle.barbacane.invalid] [--reseau dhcp | 10.30.0.21/24 --routeur 10.30.0.1]
```

- `--ca-serveur` : certificat de la CA « serveur » (un seul certificat, `CA:TRUE`, aucune clé).
  Son empreinte SHA-256 (DER) est inscrite dans `/etc/barbacane/agent.toml` : c'est la **seule**
  ancre de confiance de l'agent (aucune confiance au premier usage).
- `--serveur` : adresse **IPv4** (la borne n'a pas de résolveur DNS) ; ports de la passerelle
  (D4). Les options réseau sont **refusées** avec le profil hors-ligne.
- Paquets ajoutés à l'ISO : **`barbacane-agent` seulement**. Le réseau utilise
  `systemd-networkd`, déjà présent dans le paquet `systemd` de Debian 13 : aucun paquet réseau
  supplémentaire (ni client DHCP, ni NTP, ni DNS, ni accès distant).

## Ce que l'installation pose (fin-en-ligne.sh, après la fin d'installation commune)

| Élément | Contenu |
|---|---|
| Installation | **toujours sans réseau** (`netcfg/enable false`), comme la v1 |
| `/etc/barbacane/agent.toml`, `/etc/barbacane/agent/ca-serveur.pem` | adresse, ports, nom, CA et empreinte |
| `/etc/nftables.conf` | entrée : **rien** sauf les réponses du serveur à une connexion ouverte par la borne (`ct state established`, adresse et ports du serveur) ; sortie : adresse:ports du serveur pour le **seul compte `barbacane-agent`** (`meta skuid`) ; IPv6 et transfert bloqués ; DHCP (sortie 68→67 du compte `systemd-network`) seulement avec `--reseau dhcp` |
| `/etc/systemd/network/10-barbacane.network` | IPv4 statique ou DHCP ; ni IPv6, ni LLDP, ni mDNS/LLMNR ; DHCP sans DNS, NTP ni nom d'hôte |
| `barbacane-agent.service.d/serveur.conf` | `IPAddressAllow=SERVEUR/32` (le service porte `IPAddressDeny=any`) |
| Services | `systemd-networkd` démasqué ; `systemd-resolved`, `timesyncd`, ssh… restent masqués |

Défense en profondeur : même si une règle nftables était retirée, le service de l'agent ne peut
joindre que le serveur (filtre BPF de systemd) ; même si l'agent était compromis, il n'a aucune
capacité, ne peut écrire que dans son dossier d'état, et le pare-feu n'accepte aucune connexion
entrante. Un autre processus de la borne (même root) ne peut pas sortir.

### Statique ou DHCP

- **DHCP** (défaut) : une seule ISO pour tout un site. Exception unique du pare-feu : DHCP par
  `systemd-network`. Recommandé : bail réservé par adresse MAC et sous-réseau dédié aux bornes.
- **Statique** : aucune exception, mais une ISO par borne (adresse inscrite dans l'ISO).

## Enrôlement d'une borne (2e jalon : écran Administration → Serveur)

1. Sur le serveur : `barbacane-registre CONFIG jeton site-1` → `43118-XXXXXXXX…` (1 h, usage unique).
2. Sur la borne : Administration (PIN) → **Serveur** → « Saisir un jeton » (clavier virtuel
   existant, minuscules acceptées). L'interface n'écrit rien : elle appelle l'op `serveur_jeton`
   d'admind, qui valide le format et le port (= port d'enrôlement de l'ISO) puis dépose
   atomiquement `/var/lib/barbacane-agent/jeton` (0600, compte de l'agent ; le secret n'est jamais
   journalisé). L'agent dépose sa demande ; la page Serveur affiche l'**empreinte** en groupes de 4.
3. Sur le serveur : `barbacane-registre CONFIG demandes`, **retaper l'empreinte** lue sur la borne,
   `valider ID EMPREINTE NOM`. L'agent installe le certificat et commence ses battements.

Page Serveur : adresse du serveur, état (non enrôlée, en attente de validation, enrôlée, dégradée,
refusée, agent arrêté), empreinte, dernière synchronisation, écart d'horloge, rapports en attente,
dernier message de l'agent, mise à jour reçue. Données lues par admind dans `etat.json` (champs
connus seulement, 64 Kio au plus) et relayées dans son op `status`.

## Mises à jour reçues du serveur

1. L'agent bat sur `/maj/battement` ; si une mise à jour est proposée, il la télécharge (mTLS,
   corps écrit au fil de l'eau, taille exacte, SHA-256 annoncé) dans `/var/lib/barbacane-agent/maj/`
   puis écrit `annonce.json` en dernier. Il ne l'applique **jamais** ; un paquet dont l'empreinte
   diffère est supprimé (nouvel essai au battement suivant).
2. Page Serveur : « Mise à jour N reçue du serveur » → **Vérifier et appliquer** (décision de
   l'administrateur local). Op `serveur_appliquer_maj` d'admind : copie du paquet dans son dossier
   privé (lien refusé, taille et empreinte annoncées contrôlées sur la copie : l'agent ne peut plus
   la modifier), puis la **chaîne existante inchangée** (`update::apply_from`, la même que pour une
   clé USB) : signature minisign avec `/etc/barbacane/maj.pub` (la signature reste la seule
   autorité), anti-retour, manifeste ; en plus, version du manifeste signé = version annoncée.
3. admind rend `resultat.json` (`appliquee` ou `echec`) ; l'agent le transmet par `/maj/rapport`
   au battement suivant, puis vide le dossier.

## Interface de la borne

Charte v1, mêmes widgets. **Profil hors ligne : strictement inchangée** — sans
`/etc/barbacane/agent.toml` (posé seulement par l'ISO en ligne), admind ne publie aucun bloc
`serveur`, refuse les ops `serveur_*`, le menu n'a pas de bouton « Serveur » et le pied de page dit
« station blanche hors ligne » (tests `hors_ligne_aucune_fonction_serveur`,
`hors_ligne_sans_page_serveur`). Profil en ligne : bouton « Serveur » dans le menu ; pied de page
« station blanche en ligne » dès que l'agent publie son état.

## Tests et preuves

- `cargo test -p barbacane-agent -p barbacane-admind -p barbacane-client` ;
  `tests/suite/agent-bout-en-bout.sh` (vrais binaires, sans VM : jeton par admind, mise à jour
  reçue, appliquée sur décision, rapportée ; paquet d'une autre clé refusé par la borne).
- `tests/iso/en-ligne.sh ISO SERVEUR PE PS` : contenu de l'ISO en ligne (agent, service durci,
  pare-feu, empreinte, preseed). `tests/iso/hors-ligne.sh` inchangé, appliqué à l'ISO hors ligne.
- `tests/iso/qemu-en-ligne.sh` : installation QEMU, enrôlement réel face à une passerelle de test,
  sorties de root bloquées.

## Bloquants

Aucun à ce jour.

## Rapports de passage (20/11/2026, `protocole-agent.md` §10)

Après chaque analyse, admind dépose pour l'agent un rapport minimal (tailles, SHA-256, verdicts,
identifiant de support ; **aucun nom de fichier**), l'agent l'envoie sur `/rapport/passage` et
ne le retire qu'après `200`. File pleine (`file_max`) → la borne refuse toute nouvelle analyse
(« Borne hors service », écran d'erreur existant de la charte v1). Rien de tout cela sans
`/etc/barbacane/agent.toml`.

## Utilisateurs et clés USB (21/11/2026, `serveur-utilisateurs.md` §4)

| Élément | Où | État |
|---|---|---|
| Politique du site téléchargée après chaque battement, version jamais décroissante, gardée dans `<etat agent>/politique.json` (0600, survit au redémarrage) | agent `utilisateurs.rs` | FAIT |
| Relais admind → agent → serveur sur `/run/barbacane-agent/relais.sock` (0600 : agent et root seulement) pour `/utilisateurs/verification` et `/utilisateurs/pin` | agent, admind ops `utilisateur_verifier`, `utilisateur_pin` (sans PIN administrateur) | FAIT |
| PIN : en mémoire seulement (tampons effacés par `zeroize` dans client, admind, agent), jamais écrit ni journalisé ; journal d'admind : la décision seule | — | FAIT (tests : aucun fichier ne contient le PIN) |
| Écran « Identification » (charte v1 : mêmes titre, champ en carte, clavier virtuel, message d'alerte, boutons Annuler / Valider que le PIN administrateur) : identifiant, PIN, PIN initial → nouveau PIN saisi deux fois (`pin_acceptable`) ; « Identifiant ou PIN refusé. » ; « Borne bloquée … réessayez dans N min. » ; serveur injoignable → identification impossible | client `utilisateur.rs`, `app.rs` | FAIT |
| Mode Aucun : aucun écran, aucun appel | client, admind | FAIT |
| Clé source refusée par la politique (non enrôlée, entrée interdite) : écran d'erreur existant, journalisé, clé ignorée jusqu'à son retrait ; sortie (copie, blanchiment) seulement vers une clé enrôlée `sortie` dès qu'une politique existe ; gravure alors refusée | client | FAIT |
| Session utilisateur jointe aux rapports de passage | — | PRÉVU (étape 3) |
| Rejeu QEMU en ligne, captures des nouveaux écrans | — | PRÉVU |

**Hors ligne (sans `agent.toml`) : rien ne change** — admind refuse les ops `utilisateur_*`, l'état
n'a pas de bloc `serveur`, le client ne voit aucune politique et suit exactement le parcours v1
(tests `hors_ligne_aucune_fonction_serveur`, `hors_ligne_comportement_v1`). En ligne sans politique
reçue : comportement v1 aussi.

## Reste à faire

- Clé de la borne dans le **TPM** (D9) : trait `Coffre` prêt, implémentation fichier au lab.
- Réglage de l'horloge sur l'heure du serveur par un service privilégié ; blocage après le délai
  de grâce (conception §3.1) ; politique, rapports, journaux, mises à jour (protocole v2).
