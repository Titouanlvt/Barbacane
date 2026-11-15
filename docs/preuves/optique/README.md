# Preuves : disques optiques

Campagne du 15/11/2026 sur la borne VM 921, **installée depuis une vraie clé USB** avec l'ISO de
la campagne 10 (commit `2b7dd9c`, [installation/](installation/)), pilotée uniquement par l'écran.
Le lecteur est un vrai graveur **MATSHITA UJ8E2Q** passé à la VM **au niveau SCSI seulement**
(`virtio-scsi` + `scsi-generic` sur `/dev/sg1`) : aucun passthrough PCI, car le contrôleur SATA
porte aussi le disque système de l'hôte ([lecteur/vm.conf](lecteur/)). Le disque est un vrai
**CD-RW** (CMC Magnetics, 4x à 10x) : [identification.txt](identification.txt). Toute gravure et
tout effacement ont été faits par la borne ; l'hôte n'a fait que lire.

Contrôle final après correction de l'écart n° 5 : [controle-final/](controle-final/) (étape image, 7 OK).

Résultat : **22 vérifications OK, aucun échec** ([resultats.txt](resultats.txt)), plus le
blanchiment ci-dessous (5 OK, ISO précédente).

| Fonction | Preuve |
|---|---|
| Disque inséré → écran « Disque détecté » (type, sessions, taille) | `image/01`, `lecteur/01` |
| Lecture de **toutes les sessions** : disque à 2 sessions, l'EICAR n'est que dans la 1re (masquée par la 2e) ; il est trouvé et refusé | `image/` : rapport (`session-1/cache/eicar.com`), `sortie.sha256` |
| Disque → clé : 4 fichiers sains copiés, sha256 identiques à l'image d'origine | `image/sortie.sha256`, [image-test-contenu.sha256](image-test-contenu.sha256) |
| Clé → disque : effacement complet, gravure à la vitesse la plus basse (706 ko/s, 4x), relecture sha256 par la borne ; EICAR non gravé ; relu par l'hôte à l'identique | `gravure/` (`source.sha256`, `disque.sha256`, `disque.toc.txt`) |
| Disque gravé → clé : sha256 identiques à la clé d'origine | `relecture/sortie.sha256` |
| Blanchiment du disque : analyse, effacement complet vérifié, regravure des seuls sains ; relu par l'hôte : **une seule session « BARBACANE »**, l'ancien volume HP-ESXI introuvable | [blanchiment/](blanchiment/) (ISO de la campagne 7, commit `734769b`) |
| Éjection après gravure ; reprise après fermeture du tiroir | [interventions.txt](interventions.txt) |
| Bac à sable optique actif sous systemd, aucun échec au journal | `journal/journal.log` |

## Durées mesurées (CD-RW de 702 Mo, lecteur portable)
| Opération | Durée |
|---|---|
| Effacement complet (« blank all », jamais rapide), vérifié | **519 s** (8 min 39), 1386 ko/s |
| Gravure de 2,2 Mo à 4x, puis relecture | 37 s de gravure ; opération complète (effacement + gravure + relecture) **588 s** |
| Blanchiment complet (analyse, effacement, regravure de 191 Mo, relecture) | **881 s** |
| Lecture d'un disque (toutes sessions, 8 fichiers) | 13 s |
| Lecture de l'ancien disque HP-ESXI (370 Mo) depuis l'hôte | 2 min 50 |

## Défauts trouvés et corrigés pendant la campagne
- **usbsas n'analysait pas les fichiers d'un dossier local source** : seules les clés USB passaient
  par l'analyseur. Un disque n'aurait jamais été analysé ; la borne a refusé le transfert
  (« analyse introuvable »). Corrigé : [écart n° 5](../../noyau/ecarts.md).
- **Disque qui apparaissait puis disparaissait** : l'écran de choix revenait à l'accueil à chaque
  rafraîchissement de la liste USB, et le disque restait ensuite ignoré ; un disque présent au
  démarrage était ignoré aussi. Corrigé (`541d9c6`), et identifications sérialisées côté service.
- **Bouton « Ignorer ce disque » dessiné vide** à 1280 px (trois cartes trop larges). Corrigé (`2b7dd9c`).
- Script de test : libellés sur deux lignes, `blkid` bloqué sur un CD-RW, xorriso de l'hôte
  « busy » tant que la VM tient le lecteur (relecture par lecture brute de `/dev/sr0`).

## Ce qui n'a pas pu être testé, et pourquoi
| Point | Raison |
|---|---|
| DVD±RW, BD-RE, DVD-RAM | aucun disque de ce type au lab ; le code (remplissage de zéros vérifié) est couvert par tests unitaires seulement |
| Refus d'un disque non réinscriptible (CD-R, DVD-R, CD-ROM pressé) en sortie | aucun disque de ce type au lab ; refus testé par tests unitaires (`non_reinscriptibles_refuses`) et vu à l'écran pour le CD-ROM virtuel (pas de « Blanchir ») |
| CD audio refusé | aucun CD audio ; test unitaire `cd_audio_sans_session_de_donnees` |
| CD → CD avec échange de disque | un seul CD-RW au lab |
| Retrait du disque, disque plein, échec de gravure en cours d'opération | non provoqués (risque pour l'unique disque, lecteur sans fermeture motorisée) |
| Fermeture du tiroir par la borne | lecteur portable : le tiroir doit être refermé à la main (`eject -t` sans effet) |
