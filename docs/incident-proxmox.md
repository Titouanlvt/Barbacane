# Incident du 15/11/2026 : hôte Proxmox injoignable (écran gris, plus de SSH ni de port 8006)

## Résumé
L'ancien hôte (Dell 5820, Proxmox VE sur le NVMe, pool `rpool`) ne démarrait plus au-delà de
`networking.service` : pas de console, pas de SSH, pas d'interface web (8006).

**Cause : une modification du réseau de l'hôte faite par Claude le 14/11/2026 à 12 h 20**, pas
l'installation de Barbacane. L'hypothèse de départ (paquets, `install.sh` ou `configurer.sh`
appliqués sur l'hôte) est **écartée** : rien de Barbacane ni d'usbsas n'a été installé sur l'hôte
(preuves plus bas).

La faute est quand même du côté de Claude : la règle « ne jamais modifier le réseau de l'hôte »
n'existait pas encore, mais modifier `/etc/network/interfaces` d'un hyperviseur sans tester un
redémarrage, ni prévenir, ni prendre d'instantané était une erreur.

## La commande exacte
Session Claude Code `7ea3d35d-1353-4d78-a59a-0a98c291a75a`, commande n° 27, horodatage
`2026-11-14T11:20:03Z` (12 h 20 heure de Paris), lancée sur l'hôte :

```sh
cp /etc/network/interfaces /etc/network/interfaces.bak-claude && \
sed -i '/^auto vmbr0$/a iface vmbr0 inet dhcp' /etc/network/interfaces
```

But : l'hôte n'avait que de l'IPv6 et GitHub était injoignable. Juste avant (commande n° 25),
`timeout 40 dhclient -4 -1 -v vmbr0` avait donné une adresse IPv4 **en direct** ; la ligne
ajoutée devait la rendre permanente. Elle n'a jamais été appliquée par `ifreload` : le problème
n'est apparu qu'au redémarrage suivant.

Fichier obtenu (`/etc/network/interfaces` de l'ancien disque, modifié le 14/11 à 12:20:08) :

```
auto vmbr0
iface vmbr0 inet dhcp          <- ligne ajoutée
iface vmbr0 inet6 static
	address 2a01:e0a:b17:34d0:ce96:e5ff:fe09:6539/64
	gateway fe80::3a07:16ff:fecc:8782
	bridge-ports nic0
	...
```

## Mécanisme
1. ifupdown2 fusionne les deux strophes `vmbr0` en un seul objet : méthode `dhcp`, familles
   `inet` **et** `inet6`.
2. Le module `/usr/share/ifupdown2/addons/dhcp.py` (`_up`) lance `dhclient` pour chaque famille :
   `if 'inet6' in ifaceobj.addr_family:` → `dhclient -6 … vmbr0` au premier plan (sans `-nw`).
   L'IPv4 arrive en 4 s, mais le réseau local n'a **aucun serveur DHCPv6** : `dhclient -6`
   attend indéfiniment.
3. `networking.service` a `TimeoutStartUSec=infinity` : il ne finit jamais.
4. `ssh.service` et `systemd-user-sessions.service` sont ordonnés `After=network.target` ;
   les `getty` attendent `systemd-user-sessions`. Donc : pas de SSH, pas d'invite de connexion
   (écran gris de la console), et pas de `pveproxy` (port 8006).

## Chronologie (journal de l'ancien disque, heure de Paris)
| Démarrage | Début | Fin | Ce qui se passe |
|---|---|---|---|
| -4 | 14/11 11:56 | 14/11 20:11 | Démarrage normal (`Finished networking.service` en 2 s), AVANT la modification. La ligne est ajoutée à 12:20 ; l'hôte marche toute la journée. Arrêt volontaire à 20:09 (`shutdown`, dernière commande de la session). |
| -3 | 15/11 10:30 | 10:32 | `dhclient -6` bloqué ; appui sur le bouton d'alimentation à 10:32:55. |
| -2 | 15/11 10:33 | 10:34 | Même blocage ; bouton d'alimentation à 10:34:30. |
| -1 | 15/11 10:36 | 10:40 | Même blocage pendant 4 min ; redémarrage. |
| 0 | 15/11 10:41 | 10:51 | Même blocage pendant 10 min ; redémarrage. |

À chaque fois : `networking.service: Main process exited, code=killed, status=15/TERM` et
`dhclient -6 … failed: returned -15` (tué à l'arrêt), jamais de `Started ssh.service`.

Sources : `journalctl -D /ancien/var/log/journal/f4235a54…` (`--list-boots`, `-b -3` à `-b 0`),
`/ancien/var/log/ifupdown2/network_config_ifupdown2_17_Nov-15-2026_10:41:23*/ifupdown2.debug.log`.

## Ce qui a été vérifié et écarté
- **Aucun paquet Barbacane ni usbsas sur l'hôte** : ni `/ancien/var/log/dpkg.log` ni
  `/ancien/var/log/apt/history.log` n'en contiennent ; aucun fichier `barbacane`/`usbsas` dans
  `/ancien/etc` hors le service ci-dessous ; aucun `modprobe.d`, `udev`, `pam.d`, `grub` modifié.
- **Aucune exécution d'`install.sh`, de `configurer.sh` ou de `dpkg -i`** sur l'hôte dans les
  575 commandes de la session (les lancements trouvés se font dans les VM 901/902 par `ssh bb`
  / `ssh bu`, ou sont du texte de documentation).
- Fichiers de `/ancien/etc` modifiés après l'installation de Proxmox : `network/interfaces`
  (la cause), `network/interfaces.bak-claude`, `systemd/system/barbacane-claude.service`,
  plus `issue`, `resolv.conf`, `ld.so.cache`, `shells` (normaux).

## Autres modifications de l'hôte faites par Claude le 14/11 (non causes, mais contraires aux règles actuelles)
- Paquets d'outillage : `shellcheck`, `tesseract-ocr`, `tesseract-ocr-fra`, `socat`, `xxd`,
  `parted`, `exfatprogs`, `zip` (`git`, `tmux`, `xorriso`… ont été installés par l'utilisateur).
- Service `barbacane-claude.service` + `/usr/local/bin/barbacane-reprise.sh` (relance de Claude
  Code au démarrage). Il est `After=network-online.target` : il n'a donc jamais démarré le 15/11
  et n'a pas contribué au blocage. Il n'est **pas** recréé sur le nouvel hôte.
- Passage des clés USB aux VM (`qm set 9xx -usbN host=…`) : sans effet sur l'hôte.

## Pour réparer l'ancien disque (à faire par l'utilisateur ; Claude ne l'a monté qu'en lecture seule)
Démarrer sur l'ancien NVMe en mode secours (ou l'importer en écriture depuis un autre système), puis :

```sh
cp /etc/network/interfaces.bak-claude /etc/network/interfaces   # retire la ligne « inet dhcp »
systemctl disable barbacane-claude.service
rm /etc/systemd/system/barbacane-claude.service /usr/local/bin/barbacane-reprise.sh
```

Pour une IPv4 fixe, mieux vaut une strophe `iface vmbr0 inet static` (adresse + passerelle),
comme sur le nouvel hôte (`192.168.10.72/24`, passerelle `192.168.10.254`).

## Garde-fous ajoutés
1. **Règles de travail** (CLAUDE.md) : jamais de modification du réseau, du pare-feu, de
   modprobe, udev, PAM, GRUB, des comptes ou des services de l'hôte ; instantané
   `zfs snapshot rpool/ROOT/pve-1@avant-<étape>` avant toute autre modification ; Barbacane et
   usbsas uniquement dans une VM `barbacane-9xx`. C'est ce qui aurait évité cet incident.
2. **Refus sur un hôte Proxmox** (`/etc/pve` présent), en tête de script, avant toute action, sans
   variable pour passer outre :
   - `systeme/install.sh` et `systeme/iso/configurer.sh` ;
   - `preinst` des paquets `barbacane`, `usbsas-server` et `usbsas-hid` (exécuté par dpkg
     **avant** la copie des fichiers modprobe, udev, PAM et GRUB qui rendraient un hôte
     inutilisable : clavier et stockage USB bloqués, réseau masqué…).

   Ce garde-fou n'aurait pas empêché l'incident du 15/11 (une commande à la main), mais il
   ferme la cause soupçonnée au départ.
3. **Tests** (machine jetable uniquement, jamais sur un vrai hôte : ils créent puis retirent `/etc/pve`) :
   - Branchement en CI : `tests/garde-fou/ci-workflows.patch` (jobs `garde-fou-proxmox` dans ci.yml,
     étape après la construction des paquets dans iso.yml). Le jeton de Claude n'a pas le droit
     GitHub `workflow` : appliquer le patch et le pousser soi-même (`git apply` puis commit).
   - Passage vérifié le 15/11 dans la VM 902 (Debian 13) : [preuves/archives/2026-11-15-campagne/garde-fou/](preuves/archives/2026-11-15-campagne/garde-fou/).
   - `tests/garde-fou/scripts.sh` : avec `/etc/pve`, chaque
     script sort en erreur avec le message « REFUS : hôte Proxmox VE détecté » et **aucune** des
     commandes témoins (`apt-get`, `dpkg`, `systemctl`, `install`, `sed`, `passwd`,
     `update-grub`…) n'est appelée ; contrôle sans `/etc/pve` : le garde-fou laisse passer.
   - `tests/garde-fou/paquets.sh` (après la construction des paquets) : avec `/etc/pve`,
     `dpkg -i` de chaque paquet échoue dans le preinst et ne pose aucun fichier.
