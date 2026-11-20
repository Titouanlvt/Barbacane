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

## Enrôlement d'une borne (lab, en attendant l'écran d'administration)

1. Sur le serveur : `barbacane-registre CONFIG jeton site-1` → `43118-XXXXXXXX…` (1 h, usage unique).
2. Sur la borne : déposer le jeton dans `/var/lib/barbacane-agent/jeton` (l'écran d'admind est à
   venir) ; l'agent dépose sa demande et publie l'empreinte dans `/run/barbacane-agent/etat.json`.
3. Sur le serveur : `barbacane-registre CONFIG demandes`, **comparer l'empreinte**, puis
   `valider ID EMPREINTE NOM`. L'agent installe le certificat et commence ses battements.

## Interface de la borne

Inchangée (charte v1, même parcours ; le pied de page dit toujours « station blanche hors ligne »). Aucun indicateur n'est ajouté à ce jalon ; l'état de liaison
est disponible dans `etat.json` pour un indicateur discret ultérieur (profil en-ligne seulement).

## Tests et preuves

- `cargo test -p barbacane-agent` ; `tests/suite/agent-bout-en-bout.sh` (vrais binaires, sans VM).
- `tests/iso/en-ligne.sh ISO SERVEUR PE PS` : contenu de l'ISO en ligne (agent, service durci,
  pare-feu, empreinte, preseed). `tests/iso/hors-ligne.sh` inchangé, appliqué à l'ISO hors ligne.
- `tests/iso/qemu-en-ligne.sh` : installation QEMU, enrôlement réel face à une passerelle de test,
  sorties de root bloquées.

## Bloquants

Aucun à ce jour.

## Reste à faire

- Clé de la borne dans le **TPM** (D9) : trait `Coffre` prêt, implémentation fichier au lab.
- Écran d'administration (admind) : saisie du jeton, affichage de l'empreinte ; indicateur discret.
- Réglage de l'horloge sur l'heure du serveur par un service privilégié ; blocage après le délai
  de grâce (conception §3.1) ; politique, rapports, journaux, mises à jour (protocole v2).
