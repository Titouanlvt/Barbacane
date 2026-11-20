# Socle serveur — ISO du serveur (étape « socle », 20/11/2026)

Conception de l'ISO d'installation du **serveur** Barbacane (suite, v2) : Debian 13 durcie,
installée sans question et sans réseau, disque chiffré LUKS2 scellé au TPM, pare-feu en liste
blanche, heure locale de référence, services en conteneurs Podman **sans root**, journal persistant,
sauvegarde chiffrée et restauration testée. Références : `docs/conception-barbacane-suite.md`
§2, §3.4, §3.8, §3.10, §3.11, §8, §10 ; décisions D1 (SI DR), D4 (port aléatoire), D6
(cryptographie), D9 (TPM), D11 (Podman sans root) ; `dossier-homologation.md` §5.

**La borne v1 n'est pas touchée** : `systeme/iso/build-iso.sh` n'est ni appelé ni modifié ;
`serveur/iso/build-iso-serveur.sh` ne fait que **lire** `systeme/iso/choisir-disque.sh`.

## 1. Fichiers

| Fichier | Rôle |
|---|---|
| `serveur/iso/build-iso-serveur.sh` | construit l'ISO : netinst Debian 13 (empreinte vérifiée) + paquets du serveur et dépendances (résolus dans un Debian 13 minimal) + image de la passerelle + fichiers du serveur |
| `serveur/iso/paquets-serveur.txt` | paquets ajoutés au système de base (aucun ne vient d'Internet à l'installation) |
| `serveur/iso/preseed-serveur.cfg` | installation sans question : réseau coupé, partitionnement chiffré, aucun tasksel |
| `serveur/iso/fin-installation-serveur.sh` | `late_command` : paquets **sans source apt** (technique de la borne v1), fichiers, puis `configurer-serveur.sh` |
| `serveur/iso/configurer-serveur.sh` | dans le système installé : TPM, crypttab + dracut, réseau, nftables, chrony, durcissement, comptes, Podman |
| `serveur/iso/fichiers/` | arborescence copiée telle quelle (sysctl, modprobe, journald, audit, modèles nftables/chrony/quadlet, `barbacane-serveur-etat`, liste des paquets interdits, liste de sauvegarde) |
| `serveur/sauvegarde/barbacane-sauvegarde` | sauvegarde, vérification, restauration, génération des clés (§7) |
| `tests/serveur/sauvegarde.sh` | sauvegarde → destruction → restauration → comparaison, et refus attendus |
| `tests/serveur/qemu-serveur.sh` | installation dans QEMU avec swtpm et vérifications (§9) |

Paramètres fixés à la construction (options de `build-iso-serveur.sh`, consignés dans
`/etc/barbacane-serveur/serveur.conf`) : interfaces et adresses « bornes » et « administration »,
port de l'interface web, port fixe éventuel de la passerelle, source d'heure interne éventuelle,
compte d'administration et empreinte de son mot de passe initial, PKI de **test** éventuelle.
Chaque valeur est contrôlée (format strict) car elle entre dans des fichiers shell, nftables et systemd.

## 2. Partitionnement

Disque interne choisi par `choisir-disque.sh` (jamais un périphérique USB), entièrement effacé, GPT :

| Partition / volume | Taille (min–max) | Montage | Options |
|---|---|---|---|
| EFI | 538 Mo–1 Go | `/boot/efi` | — |
| `/boot` (ext4, **en clair**) | 1 Go | `/boot` | `nodev,nosuid,noexec` |
| LUKS2 → LVM `barbacane` : | reste du disque | | |
| `racine` | 4–8 Go | `/` | — |
| `var` | 2–8 Go | `/var` | `nodev,nosuid` |
| `journaux` | 1–4 Go | `/var/log` | `nodev,nosuid,noexec` |
| `audit` | 0,5–2 Go | `/var/log/audit` | `nodev,nosuid,noexec` |
| `home` | 0,2–1 Go | `/home` | `nodev,nosuid,noexec` |
| `donnees` | 2 Go–reste | `/var/lib/barbacane-serveur` (données, PKI, conteneurs) | `nodev,nosuid` |

Pas d'échange (swap). `/tmp` est un tmpfs (défaut de Debian 13). Le volume `donnees` doit permettre
l'exécution (images des conteneurs sans root) ; il reste `nodev,nosuid`.

## 3. Chiffrement du disque et TPM (D6, D9)

- `partman-crypto` formate le volume en **LUKS2** (`cryptsetup luksFormat`, type par défaut),
  **aes-xts-plain64, clé de 512 bits** (AES-256 en XTS), dérivation Argon2id. La phrase de passe
  de l'installateur est **temporaire** : tirée au hasard à chaque construction d'ISO.
- En fin d'installation (`configurer-serveur.sh`, TPM visible dans l'installateur car le noyau
  Debian intègre `tpm_crb`/`tpm_tis`) :
  1. `systemd-cryptenroll --recovery-key` : **clé de secours** (emplacement dédié, jeton
     `systemd-recovery`), écrite dans `/root/cle-de-secours-luks.txt` (0400, sur le disque chiffré) ;
  2. `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7` : clé **scellée au TPM**, liée au PCR 7
     (état du démarrage sécurisé : PK/KEK/db/dbx et autorités de signature) ;
  3. `systemd-cryptenroll --wipe-slot=password` : la phrase temporaire est **effacée** (elle est
     dans l'ISO et commune à toutes ses installations ; le test vérifie qu'elle n'ouvre plus rien).
- `/etc/crypttab` : `luks,tpm2-device=auto` (sans `discard`, qui révélerait l'occupation).
  L'initramfs est produit par **dracut** (modules `systemd`, `crypt`, `systemd-cryptsetup`,
  `tpm2-tss`, `lvm`) : celui de Debian (`cryptsetup-initramfs`) ne sait pas utiliser un jeton TPM2.
  dracut remplace `initramfs-tools` à l'installation (paquets de l'ISO).
- Sans TPM, l'installation **s'arrête** (D9 : TPM exigé). Au démarrage sans TPM (ou TPM effacé,
  PCR 7 modifié), le système demande la clé : seule la clé de secours l'ouvre.
- `barbacane-serveur-etat` rappelle à chaque démarrage que la clé de secours est encore sur le
  disque : l'administrateur la transcrit (coffre, comme les supports de la racine PKI) puis
  `shred -u /root/cle-de-secours-luks.txt`.

Limites (assumées, à présenter à l'AH) :
- **PCR 7 seul** : un autre système signé par la même autorité (par exemple une clé Debian
  démarrable) produit le même PCR 7. Parades : mot de passe du micrologiciel, ordre de démarrage
  verrouillé, démarrage USB désactivé, local en zone protégée. PRÉVU : politique `systemd-pcrlock`
  (PCR 0, 2, 4, 7) ou noyau unifié signé (UKI) avec politique PCR 11 signée ; option TPM + PIN.
- Démarrage sécurisé : utilisé s'il est actif dans le micrologiciel (shim et GRUB signés Debian) ;
  non activé dans le banc QEMU (OVMF sans clés), d'où un PCR 7 « démarrage sécurisé désactivé ».
- LUKS n'est pas un produit qualifié : `dossier-homologation.md` §5 et §6 (HORS PROJET si l'AH
  exige un produit agréé).

## 4. Durcissement (guide ANSSI GNU/Linux, niveau renforcé visé) et pare-feu

| Mesure | Mise en œuvre |
|---|---|
| Surface minimale | aucun tasksel ; liste blanche de paquets (`paquets-serveur.txt`) ; liste de **paquets interdits** (SSH, accès distant, découverte, partage, DHCP, NTP autre que chrony, MTA, serveurs web, VPN, Docker) refusée à la construction et retirée à l'installation si présente |
| Noyau (sysctl) | `90-barbacane-serveur.conf` : `dmesg_restrict`, `kptr_restrict=2`, `ptrace_scope=2`, `perf_event_paranoid=3`, BPF non privilégié interdit, `kexec_load_disabled`, `sysrq=0`, `protected_*`, `suid_dumpable=0`, pas de routage ni de redirections ICMP, `rp_filter`, IPv6 désactivé |
| Noyau (démarrage) | `slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off lockdown=integrity module.sig_enforce=1 iommu=force ipv6.disable=1 audit=1` |
| Modules | `modprobe.d` : protocoles et systèmes de fichiers inutiles interdits (dccp, sctp, rds, tipc, bluetooth, firewire, thunderbolt, cramfs, hfs, udf, cifs, nfs…) ; `usb-storage` conservé (sauvegarde) |
| Démarrage | GRUB verrouillé comme la borne v1 : entrée par défaut sans mot de passe, édition interdite |
| Comptes | root verrouillé ; un compte d'administration système (`barbadmin`, groupes `sudo`, `adm`, `systemd-journal`), mot de passe initial **expiré** (changé à la 1re connexion), console seulement ; `sudo` journalisé (`/var/log/sudo.log`, `use_pty`) ; `umask 027` ; un compte système `barbacane-svc` (sans shell) pour les conteneurs |
| Audit | `auditd`, règles `90-barbacane-serveur.rules` (comptes, sudoers, configuration du serveur, pare-feu, crypttab, heure, PKI, modules, montages, exécutions root par un administrateur), figées (`-e 2`) |
| Services réseau | `networking`, `NetworkManager`, `wpa_supplicant`, `ssh`, `systemd-resolved`, `systemd-timesyncd` masqués ; tâches apt périodiques masquées |

**Écart assumé** : les espaces de noms utilisateur restent autorisés (le guide recommande de les
restreindre) car Podman sans root en a besoin (D11). Compensation : un seul compte les utilise
(`barbacane-svc`, plages subuid dédiées), conteneurs sans capacité ni privilège.

**Réseau** (systemd-networkd) : deux interfaces à adresse fixe, **aucune passerelle**, donc **aucune
route par défaut** (D1 : aucune interconnexion) ; ni DHCP, ni RA IPv6, ni LLMNR/mDNS.

**nftables** (`/etc/nftables.conf`, généré depuis `nftables.conf.modele`), politique `drop` partout :

| Chaîne | Accepté | Tout le reste |
|---|---|---|
| entrée | boucle locale ; connexions établies ; **port de la passerelle** sur l'interface **bornes** et l'adresse bornes seulement ; **port de l'interface web** sur l'interface **administration** seulement | refusé, journalisé (6/min) |
| transit | rien (aucun routage entre les deux réseaux) | refusé, journalisé |
| sortie | boucle locale ; réponses aux connexions établies ; NTP vers la source **interne** si elle est configurée (interface administration) | refusé, journalisé |

Port de la passerelle : **tiré au hasard à l'installation** entre 20000 et 60000, hors ports
connus (`/etc/services`) (D4) ; consigné dans `/etc/barbacane-serveur/port-passerelle` (il entre
dans le jeton d'enrôlement). `--port N` fixe un port documenté si l'AH le préfère.

## 5. Heure (§3.11)

chrony, **sans aucune source Internet** (ni `pool`, ni serveur public) : `local stratum 10`
(l'horloge du serveur fait référence), `port 0` (aucun service NTP réseau : les bornes prennent
l'heure par le canal mTLS), `cmdport 0` (commande par socket locale seulement). Option
`--source-heure IP` : un serveur NTP **interne** du réseau d'administration (et la règle de sortie
correspondante). La mise à l'heure initiale de l'horloge matérielle se fait à la mise en service
(procédure §8) ; PRÉVU : récepteur GNSS/radio (`refclock`).

## 6. Services : Podman sans root (D11) et journal

- Compte `barbacane-svc` (système, sans shell, maison `/var/lib/barbacane-serveur/svc`), plages
  subuid/subgid 200000–265535, session systemd permanente (`/var/lib/systemd/linger`).
- Image `localhost/barbacane-passerelle:<version>` : racine minimale (binaire
  `barbacane-passerelle` et ses seules bibliothèques, ni shell ni gestionnaire de paquets),
  construite avec l'ISO, chargée au démarrage par `barbacane-images.service` (`podman import`,
  aucun registre).
- Conteneur décrit par un **quadlet** (`~/.config/containers/systemd/barbacane-passerelle.container`) :
  racine en **lecture seule**, `NoNewPrivileges`, **aucune capacité**, PKI montée en lecture seule,
  réseau `pasta`, port publié **sur l'adresse bornes seulement**, limites de processus et de mémoire.
  `ConditionPathExists` : sans PKI (production avant la cérémonie), la passerelle ne démarre pas
  et ce n'est pas un échec. Une ISO de **TEST** (`--pki-test`) embarque une PKI de test (certificat
  serveur et sa clé, CA bornes, CRL ; **aucune clé de CA**), nom de volume `BARBACANE_SERVEUR_TEST`.
- Journal : `journald` **persistant** (`/var/log/journal`, volume chiffré séparé), compressé,
  2 Go au plus, **1 an** de conservation, jamais transmis.
- `barbacane-serveur-etat` (service au démarrage, sortie sur la console et dans le journal) :
  faits bruts (disque, routes, pare-feu, écoute, heure, services, conteneurs, paquets, journal,
  clé de secours) ; aucune donnée secrète. Lu par le test QEMU.

## 7. Sauvegarde et restauration (§3.8)

`barbacane-sauvegarde` produit un fichier **CMS** :

1. `tar` des chemins de `/etc/barbacane-serveur/sauvegarde/liste` (configuration, données,
   PKI ; le stockage des images est exclu, il se recharge depuis l'ISO), propriétaires numériques,
   ACL, attributs étendus ;
2. **manifeste SHA-384** de chaque fichier + métadonnées (date, hôte, version) ;
3. **signature** ECDSA P-384/SHA-384 par la clé du serveur (`signature.cle.pem`, créée à
   l'installation ; l'empreinte de son certificat est à consigner hors du serveur) ;
4. **chiffrement** AES-256-GCM (AuthEnvelopedData) pour le **certificat de la clé de sauvegarde**
   (ECDH P-384) : la clé privée est créée sur le poste hors ligne (`cles-destinataire`, protégée par
   une phrase) et reste au coffre ; **le serveur ne peut pas relire ses propres sauvegardes** ;
5. empreinte SHA-384 du fichier chiffré à côté (`.sha384`, détecte un support abîmé sans clé).

Destination : un **support amovible** monté (refus si le dossier est sur le disque système) ;
rotation `--garder N` (14 par défaut : les purges s'appliquent aussi aux sauvegardes).
Restauration : empreinte, déchiffrement (GCM authentifié), signature (seule ancre : le certificat
de signature consigné), métadonnées, puis extraction **en zone de transit** et contrôle du manifeste
**avant toute écriture** dans la cible. Planification quotidienne et vidage de PostgreSQL : PRÉVU
(la base n'existe pas encore).

## 8. Mise en service (procédure)

1. Construire l'ISO sur un poste Debian 13 (réseau pendant la construction seulement), noter
   l'empreinte. 2. Démarrer le serveur sur l'ISO (TPM 2.0 actif, démarrage sécurisé conseillé) :
   installation sans question, arrêt si pas de TPM. 3. À la console : se connecter (`barbadmin`),
   changer le mot de passe, lire `barbacane-serveur-etat`, **transcrire la clé de secours** puis la
   détruire, régler l'heure (`date -s`, `hwclock -w`) si aucune source interne. 4. Déposer
   `destinataire.pem` (clé de sauvegarde) dans `/etc/barbacane-serveur/sauvegarde/`, consigner
   l'empreinte du certificat de signature. 5. Déposer la PKI issue de la cérémonie dans
   `~barbacane-svc/pki/` et démarrer la passerelle.

## 9. Vérification (banc QEMU, `tests/serveur/qemu-serveur.sh`)

ISO de test construite avec `--ip-bornes 10.0.2.15/24 --ip-admin 10.0.3.15/24 --pki-test PKI
--hache-admin FICHIER`. Le banc : machine UEFI (OVMF), **TPM logiciel swtpm** (TPM CRB ; D9 : banc
seulement), deux réseaux QEMU isolés (`restrict=on`), installation par la console série, puis :

- ISO : aucun paquet interdit, réseau coupé à l'installation, chiffrement 512 bits au preseed ;
- démarrage **sans saisie** (TPM) jusqu'à l'état du serveur ; puis démarrage **sans TPM** : arrêt
  sur la demande de clé ;
- en-tête LUKS lu de l'extérieur (sans clé) : LUKS2, aes-xts-plain64, 512 bits, jetons
  `systemd-tpm2` et `systemd-recovery`, 2 emplacements, phrase d'installation refusée, une seule
  partition en clair (`/boot`) ;
- de l'intérieur : volume ouvert en aes-xts 512 bits, aucune route par défaut, trois chaînes en
  `drop` et exactement les règles d'acceptation attendues, ports en écoute, chrony sans source,
  services actifs, passerelle active dans Podman sans root (racine en lecture seule, aucune capacité,
  processus non root), aucun paquet interdit installé, journal persistant ;
- de l'extérieur (redirections QEMU) : borne mTLS servie sur le réseau des bornes, client sans
  certificat refusé, passerelle injoignable depuis le réseau d'administration, 443 et 22 muets.

Résultats : §10.

## 10. État

| Élément | État |
|---|---|
| Conception (ce document) | FAIT |
| `build-iso-serveur.sh`, preseed, fin d'installation, configuration | voir résultats ci-dessous |
| Sauvegarde / restauration + `tests/serveur/sauvegarde.sh` | FAIT (bu, 20/11) |
| `tests/serveur/qemu-serveur.sh` | voir résultats ci-dessous |
| Politique PCR renforcée (pcrlock / UKI signé), TPM + PIN | PRÉVU |
| Clés serveur et CA dans le TPM (politique §6) | PRÉVU (jalon PKI) |
| Interface web (port d'administration ouvert, aucun service encore) | PRÉVU (étape 5, suite) |
| Sauvegarde quotidienne planifiée, vidage PostgreSQL, purges | PRÉVU |
| Récepteur GNSS/radio comme source d'heure | PRÉVU |
| `pam_faillock`, bannière légale, AIDE (intégrité des fichiers) | PRÉVU |
| Chiffrement de disque qualifié/agréé, poste d'administration dédié, locaux | HORS PROJET (organisme / AH) |

## Bloquants

Aucun pour l'instant.
