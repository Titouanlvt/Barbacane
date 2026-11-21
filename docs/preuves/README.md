# Preuves : ce qui marche, ce qui ne marche pas, ce qui n'a pas pu être testé

## Par version publiée

| Version | Preuves |
|---|---|
| **v2.0.1** (21/11/2026, tag `v2.0.1`) | [2026-11-21-labo-proxmox/](2026-11-21-labo-proxmox/) (Serveur Barbacane et Borne connectée sur Proxmox), notes : [../notes-de-version/v2.0.1.md](../notes-de-version/v2.0.1.md) |
| **v2.0.0** (21/11/2026, tag `v2.0.0`) | [2026-11-21-v2.0.0/](2026-11-21-v2.0.0/) (empreintes des ISO, non-régression v1, QEMU serveur et bornes), [2026-11-21-qemu-en-ligne/](2026-11-21-qemu-en-ligne/), [2026-11-21-borne-utilisateurs/](2026-11-21-borne-utilisateurs/), [2026-11-20-serveur-iso/](2026-11-20-serveur-iso/), [2026-11-20-profil-en-ligne/](2026-11-20-profil-en-ligne/), [2026-11-20-borne-en-ligne-2/](2026-11-20-borne-en-ligne-2/), [2026-11-20-rapports-passage/](2026-11-20-rapports-passage/), [serveur-web/](serveur-web/) |
| **v1.0.0** (19/11/2026, tag `v1.0.0`) | [2026-11-19-v1.0.0/](2026-11-19-v1.0.0/), [2026-11-19-profil-hors-ligne/](2026-11-19-profil-hors-ligne/), campagne sur vraies clés du 18/11 ci-dessous |

Les preuves remplacées par des campagnes plus récentes (14/11, 15/11, 17/11, mkosi, passages
parallèles) sont dans [archives/](archives/README.md).


## Borne autonome v1 : bilan au 18/11/2026

**Version livrée : v1.0** (tag `v1.0` = 5c20866, `main`). ISO de production
`/nvme/contenu/iso-v1/barbacane.iso`, sha256
`4e2bd821466e9ae1c3e3b81f88a86205ce647f332b4436907632ca8cf073cbb2` (clé publique de production
embarquée). Différence avec l'ISO de la campagne finale (d4a3641) : bouton « Effacer » à la charte
(affichage seul, [2026-11-18-bouton-destructif/](2026-11-18-bouton-destructif/)), fscommon recopié dans
le dépôt et Rust épinglé (construction seule) ; CI verte. Installation QEMU : un échec ponctuel sur
GitHub, rejouée 3 fois sur 3 avec succès ([2026-11-18-iso-v1-qemu/](2026-11-18-iso-v1-qemu/)).

Borne installée depuis l'ISO de **production** construite depuis `integration` (d4a3641, sha256
`080f6ff69805adea3c90d5ccaa3f86fa3e0d240596acbcb20375d7d98d7214d1`), VM Proxmox 920 (supprimée depuis) sans réseau,
**vraies clés USB** passées à la VM au niveau USB (SanDisk 16 Go en source, SanDisk Ultra 64 Go
enrôlée en sortie). Campagne finale : [2026-11-18-finale/](2026-11-18-finale/) — **121 OK, 0 échec** (95 en passe 1 avec retour à
l'instantané entre scénarios, 26 en passe 2 enchaînée sans retour : transfert, mise à jour, export, journal).

### Ce qui marche (avec la preuve)
| Fonction | Preuve |
|---|---|
| Transfert d'une clé inconnue vers une clé connue : EICAR (dont .jpg déguisé) bloqué, sains identiques (sha256), clé non enrôlée refusée et intacte | [2026-11-18-finale/](2026-11-18-finale/), [2026-11-18-rapide/transfert/](2026-11-18-rapide/transfert/) |
| Blanchiment : sha256 de la clé entière et secteur 0 en hexadécimal avant/après, EICAR effacé de toute la clé | [2026-11-18-rapide/blanchiment/](2026-11-18-rapide/blanchiment/) (`cle-avant-secteur0.hex`, `cle-apres-secteur0.hex`) |
| Administration : PIN, verrouillage après 5 erreurs, enrôlement, export des journaux et rapports, journal | [2026-11-18-rapide/](2026-11-18-rapide/), [2026-11-18-export-journal/](2026-11-18-export-journal/) |
| Mises à jour signées : valide appliquée, autre clé et version ancienne refusées | [2026-11-18-export-journal/maj/](2026-11-18-export-journal/maj/) |
| Mise à jour contenant des **paquets Debian**, borne redémarrée sur la nouvelle version | [2026-11-18-maj-paquets/](2026-11-18-maj-paquets/) (clé de signature de TEST, VM 950) |
| Clés démarrables : Ventoy blanchie en restant démarrable (et démarre) ; Etcher réécrite depuis son image officielle vérifiée (et démarre) | [2026-11-18-rapide/ventoy/](2026-11-18-rapide/ventoy/), [ventoy/](ventoy/), [etcher/](etcher/) |
| Liste blanche d'images officielles (ISO Windows 11 de 8,3 Go copiée intacte) | [liste-blanche/](liste-blanche/) (clé de signature de TEST) |
| Espace de travail dynamique chiffré, clé de 5,6 Go analysée et blanchie avec 8 Go de RAM | `volumineux` de la campagne finale ; `docs/conception-espace-travail.md` |
| Clés hostiles : vide, pleine, illisible, retirée pendant la lecture ; clavier USB sans effet ; GRUB verrouillé | [2026-11-18-rapide/](2026-11-18-rapide/) |
| Écran de veille (10 min, réveil au toucher) | [2026-11-18-rapide/veille/](2026-11-18-rapide/veille/) |
| Disques optiques : lecture multisession (EICAR caché trouvé), vrai graveur en scsi-generic, vrai CD-RW → clé (18/11) ; gravure et blanchiment de CD-RW (15/11) | [2026-11-18-optique/](2026-11-18-optique/), [optique/](optique/) |
| Guide d'installation (PDF) à jour, ISO hors ligne | [../Barbacane-installation.pdf](../Barbacane-installation.pdf), [installation-doc/](installation-doc/) |
| Bouton « Effacer » à la charte (Destructif, rouge ; pâle avec relief quand indisponible) | [2026-11-18-bouton-destructif/](2026-11-18-bouton-destructif/) |

### Défauts trouvés et corrigés le 18/11
Mise à jour avec paquets Debian jamais essayée avant : `--no-download` (erreur apt), postinst qui
redémarrait admind (apt tué), **initramfs vidé sous le confinement d'admind (borne qui ne
redémarrait plus)**, anciennes révisions embarquées dans l'ISO. Détail :
[2026-11-18-maj-paquets/README.md](2026-11-18-maj-paquets/README.md). Bornes installées avant le
18/11 : réinstaller depuis une ISO récente pour recevoir des paquets (guide, § 7).

### Ce qui ne marche pas
- Aucun échec dans la campagne finale (121/121) sur l'ISO de production d4a3641.
- Charte graphique : « Effacer cette clé et y copier les fichiers » était en variante Principale (noire)
  au lieu de la variante Destructive (rouge `menace`) ; corrigé après la campagne et vérifié sur la 950
  (inclus dans la v1.0).
- Écart à la charte non corrigé : l'effacement de la clé de destination n'est pas suivi d'un écran de
  confirmation (la charte le demande) ; changement de parcours laissé à la décision de l'utilisateur.

### Ce qui n'a pas pu être testé, et pourquoi
| Point | Raison |
|---|---|
| Signature avec la clé de **production** (paquets, liste blanche, Etcher) | phrase de passe connue de l'administrateur seul ; mêmes chemins prouvés avec une clé de TEST du lab |
| Gravure et blanchiment de CD-RW sur le code du 18/11 | la borne éjecte le disque et ce lecteur portable ne referme pas son tiroir : il faut une personne ; preuve du 15/11 |
| Disque de 2 à 4 To, boîtier NVMe USB, UAS | pas de matériel ; limites et extrapolation dans `docs/performances.md` |
| Gain de l'analyse parallèle (4 fils) | non mesurable sur l'hôte partagé ; mesure isolée non faite |
| Borne physique (BIOS, écran tactile, ports réels) | lab en VM ; seules les clés USB sont réelles |
| Clé lente Phison, DVD/BD, CD-R | absents du lab |
| `.github/workflows/iso.yml` avec Rust épinglé | laissé tel quel (décision du 18/11) : jeton sans droit `workflow`. Risque restant limité à l'ISO construite par la CI (`curl \| sh` de rustup.rs) ; constructions locales et installation sur poste passent par `systeme/rust/installer-rust.sh` (sha256 vérifié). Correctif prêt : `tests/garde-fou/ci-rust-epingle.patch` |

---

## Demandes du 17/11/2026 (clés démarrables, tests parallèles, espace de travail, 4 To, parcours)

### Marche (avec la preuve)
| Fonction | Preuve |
|---|---|
| Parcours unique : « Analyser » puis Copier vers une clé connue / Graver / Blanchir / Arrêter ici (4 boutons sur une ligne en 1280 px) | passages parallèles 5 et 6 (`archives/parallele-7/`), captures `ventoy/02-resultat-analyse.png` |
| Clé Ventoy blanchie **en gardant démarrable** : zone de démarrage reconstruite depuis le Ventoy embarqué (octet par octet), ISO piégée et `ventoy/` écartés, **la clé démarre** | [ventoy/](ventoy/) |
| Clé **Etcher** réécrite depuis son image officielle vérifiée (empreinte avant écriture, 792 Mo identiques octet par octet), **elle démarre** | [etcher/](etcher/) (clé de signature de **test** du lab) |
| Liste blanche d'images officielles livrée par paquet signé (autre clé et version ancienne refusées) ; ISO Windows 11 de 8,3 Go copiée intacte | [liste-blanche/](liste-blanche/) (clé de signature de **test** du lab) |
| Clés Rufus (FAT32, NTFS 6,3 Go), Etcher, bureau : sains intacts (sha256), piégés écartés, aucun EICAR | passage parallèle 5 (clés émulées) ; campagne 920 (vraies clés) |
| Espace de travail chiffré éphémère (dm-crypt, clé jetée à chaque session), espace re-mesuré avant la copie, refus clair si trop gros | `docs/conception-espace-travail.md` ; Rufus NTFS 6,3 Go OK après correctif 90e720f |
| Clé de 5,6 Go analysée et blanchie avec 8 Go de RAM (correctif « Remote server error », écart n° 8) | campagne 920 (`volumineux`) |
| Tests en parallèle : borne modèle + clones liés, clés émulées, 3 bornes à la fois | `tests/proxmox/parallele.sh` ; passage 6 : 74 OK en 44 min |
| Mesures de débit et extrapolation 4 To | [../performances.md](../performances.md) |

### Ne marche pas (encore)
| Point | État |
|---|---|
| Clé Rufus « mode ISO », ou Etcher dont l'image n'est pas dans la liste : redevient non démarrable après blanchiment | voulu (zone de démarrage non vérifiable) ; avertissement à l'écran ; alternative sûre : Ventoy |
| ISO Windows sans liste blanche | refusée avec une raison claire (« trop volumineux pour être ouvert ») : 1,8 million de fichiers dans `install.wim` |

### Pas testé, et pourquoi
| Point | Raison |
|---|---|
| Disque de 2 à 4 To, boîtier NVMe USB, UAS | pas de matériel ; limites connues dans `docs/performances.md` |
| Signature avec la clé de **production** | phrase de passe connue de l'administrateur seul ; preuve faite avec une clé de test |
| Borne physique | lab en VM ; clés USB réelles passées à la VM |

### Bloquants
- Résolu (17/11, 19 h 30) : `/etc/pve` en lecture seule après la saturation de `rpool` ;
  `pve-cluster` redémarré par l'administrateur, campagnes relancées.
