# Espace de travail de l'analyse : conception

## Rôle

Tout ce qui est lu sur une clé passe par le disque interne de la borne : archive de session
d'usbsas (`travail/usbsas`), copie reçue par l'analyseur et extraction des archives
(`travail/analyse`). Mesuré le 16/11/2026 : la réception seule occupe **2 fois** le contenu ;
avec l'extraction, on compte **3 fois** (`FACTEUR_ESPACE`).

Avant le 16/11, c'était un tmpfs de 6 Go en RAM : une clé de 5,5 Go faisait échouer l'analyse
(« Remote server error ») sur une borne à 8 Go de RAM.

## Choix : dm-crypt éphémère, clé jetée à chaque session

`systeme/travail/barbacane-travail` : un fichier creux `/var/lib/barbacane-travail.img`, ouvert par
dm-crypt (`plain`, AES-XTS 512 bits) avec une clé lue dans `/dev/urandom` et jamais écrite, puis
formaté en ext4 (`nodev,nosuid,noexec`).

La clé est **renouvelée** :
- à chaque démarrage de la borne ;
- à la fin de chaque session utilisateur : quand l'interface revient à l'accueil après une
  analyse, elle demande au service d'administration l'opération `nouvelle_session`, qui
  redémarre le volume (usbsas et l'analyseur, qui en dépendent, redémarrent avec lui).

Pourquoi pas un effacement garanti (écriture de zéros) ? Effacer des centaines de Go à chaque
session prendrait des dizaines de minutes et userait le SSD ; et sur un SSD, l'effacement logique
ne garantit pas que les anciennes cellules soient vidées. Jeter la clé rend les données
**indéchiffrables** immédiatement, quel que soit le support : c'est l'effacement cryptographique,
recommandé pour les SSD (NIST SP 800-88, « cryptographic erase »).

## Taille calculée au démarrage

Fichier creux : sa taille ne coûte rien tant qu'il n'est pas écrit. Recalculée à chaque
démarrage (`/etc/barbacane/travail.conf`) :

| Réglage | Défaut | Rôle |
|---|---|---|
| `PART` | 50 | part du disque interne, en % |
| `PLANCHER` | 8 | minimum en Gio |
| `PLAFOND` | 0 (aucun) | maximum en Gio |

et jamais plus de 80 % de l'espace libre. Exemples : SSD de 256 Go → environ 115 Go (contenu
analysable ≈ 38 Go) ; NVMe de 2 To → environ 930 Go (≈ 310 Go de contenu).

La demande citait « environ 25 % » comme exemple. La borne étant dédiée à l'analyse, 50 % est
retenu par défaut : à 25 %, un Dell OptiPlex à 256 Go ne pourrait analyser que ≈ 19 Go, soit
moins qu'une ISO d'installation de 20 Go. `PART=25` reste possible.

## Refus avant de commencer

usbsas annonce la taille totale des fichiers dès le début de la lecture. Si
`3 × contenu > espace libre`, le parcours s'arrête aussitôt, avant toute copie :

> contenu trop volumineux pour cette borne : 42,0 Go à analyser, il faut environ 126,0 Go
> d'espace de travail et 115,0 Go sont disponibles. Rien n'a été copié.

## Administration

Administration → État de la borne : « Espace de travail (analyse) : X libres sur Y : contenu
analysable jusqu'à Z environ ».
