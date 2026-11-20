# Avancement — mission « Barbacane suite » (depuis le 19/11/2026, Claude en autonomie)

## Priorité (20/11, utilisateur)
1. **Serveur (Barbacane suite)** d'abord, ordre de `docs/conception-barbacane-suite.md` §8 : socle (ISO serveur,
   PKI, passerelle mTLS, enrôlement validé, heure, supervision, sauvegarde) → borne en ligne (`--profil en-ligne`,
   `barbacane-agent`, charte **v1**) → mises à jour, rapports/journaux, utilisateurs, clés USB, ISO des bornes,
   quarantaine désactivée par défaut.
2. **Charte v2 sur la borne : SUSPENDUE.** La borne reste en charte v1. La charte v2 sert seulement à
   l'interface web du serveur (adaptation simple, sans effets coûteux).

## Chantiers en cours (règle du 20/11 : parallèle, CI locale avant push, jamais attendre la CI)
| Chantier | Branche / worktree | État | Attend |
|---|---|---|---|
| CI locale | `ci-locale` / `wt-ci-locale` | `tests/ci-locale.sh` écrit ; `lab/ci-locale-bu.sh BRANCHE` (bu) | 1er passage sur bu (`logs/ci-locale-ci-locale.log`) |
| Charte v2 borne | `borne-charte-v2` / `wt-charte` | **SUSPENDU le 20/11** (priorité serveur). Branche gardée, non fusionnée : jetons générés, relief, verdict en tranche, séquences 3D découpées image par image, captures Jour (`docs/captures/charte-v2/jour`), OCR PPM corrigé (à reporter dans integration). Reste : captures Nuit, creusé, pastilles, herse, campagne. `main` n'a aucun changement visuel de la borne depuis v1.0 (`git diff v1.0 main -- borne/` vide) | — |
| Socle serveur (étape 5) | `serveur-socle` / `wt-serveur-socle` | fait par sous-agent, relu : PKI de TEST (CA P-384, feuilles P-256), passerelle rustls TLS 1.3 seul, AES-GCM, CRL relue à chaque connexion, fail-closed ; 9 tests | **fusionné dans integration** (CI locale verte) |
| Serveur : enrôlement, protocole agent, battement, heure | `serveur-enrolement` | **fusionné** (01b1b1e, CI locale verte, 35 tests) ; délai total par connexion (20 s / 10 s, 8 places d'enrôlement) fusionné 9eb8df9 | — |
| Serveur : ISO durcie, LUKS2+TPM, nftables, chrony local, sauvegarde | `serveur-iso` / `wt-serveur-iso` (depuis `serveur-socle`) | sous-agent en cours | — |
| Borne en ligne : `barbacane-agent`, `--profil en-ligne` | `borne-en-ligne` | **fusionné** (CI locale verte ; QEMU : enrôlement, battement, pare-feu ; ISO hors ligne identique à v1.0, `docs/preuves/2026-11-20-profil-en-ligne/`). Reste : jeton/empreinte dans admind, pied de page « en ligne », TPM, routes /maj/* côté agent | — |
| Serveur : audit chaîné + mises à jour centralisées | `serveur-maj-audit` | **fusionné** c6ea2a4 (CI locale verte ; audit SHA-384 + points de contrôle ECDSA P-384, .bcu vérifié, plancher signé, routes /maj/*) | — |
| Serveur : interface web d'administration (charte v2 simple, sans JS) | `serveur-web` | **fusionné** cfcf867 (CI locale verte ; mTLS admin + Argon2id, CSRF, CSP, 26 tests). Captures en cours (`lab/web-captures.sh`). PRÉVU : CA administrateurs dans racine-test.sh, double validation, TPM, service systemd | — |
| Borne 950 remise en v1 | — | **fait** : code v1, transfert OK | — |
| Surveillance CI | `lab/ci-surveille.sh BRANCHE` | `logs/ci-<branche>.log` | — |

## Plan et état
| Étape | État |
|---|---|
| Lab 1 : NVMe dédié → pool ZFS `essais` | **fait** (`docs/lab/essais.md`, instantané `avant-pool-essais-20261119-1825`) |
| Lab 2 : passthrough RTX 4000 | **non fait, par règle** : seule carte d'affichage de l'hôte (`docs/lab/gpu-passthrough.md`) |
| Charte v2 dans `docs/charte/` | **fait par l'utilisateur** (branche `charte-v2`, identique à l'Artifact, vérifié) |
| 1. Documentation v1 à jour | **fait** (captures Jour/Nuit `docs/captures/v1/`, guide, PDF, README) |
| 2. Publication v1.0.0 | **fait** : étiquette `v1.0.0` = `main` = 08acd06 ; ISO `/nvme/contenu/iso-v100/` sha256 `5e0c3fba…3fc7` ; `docs/preuves/2026-11-19-v1.0.0/` (39/39) |
| 3. Organisation du dépôt | **fait** (`docs/preuves/2026-11-19-profil-hors-ligne/`) |
| 4. Préalables suite (DR) | **fait** (`docs/suite/`) |
| Adaptation visuelle charte v2 (borne) | `borne-charte-v2` à jour d'integration` (audit OK, clippy, 16 tests) ; vérification sur 950 en cours (`lab/charte-apres.sh`, `logs/charte-apres.log`, captures → `docs/captures/charte-v2/`) ; reste creusé, pastilles, herse |
| 5–10. Barbacane suite | à faire |

## Étape 1 — inventaire (19/11)
| Élément | Problème | Traitement |
|---|---|---|
| `docs/captures/01..10` (12/11) | écrans d'avant la refonte (choix Copier/Blanchir, anciennes couleurs) | remplacés par `docs/captures/v1/{jour,nuit}/` (`tests/ui/captures.sh`, borne 950, 1280×800) |
| `docs/Barbacane-installation.md` (19 images) | captures des 14–16/11 (`preuves/transfert`, `pin`, `enrolement`…) | pointent vers `captures/v1/jour/` ou les preuves du 18/11 (ISO v1.0) |
| — gravure en cours | seule capture du 15/11 (tiroir à refermer à la main) | conservée, signalée |
| `README.md` | capture du résultat d'avant v1.0 | `captures/v1/jour/05-resultat.png` |
| `docs/exploitation.md` | `captures/01-choix.png` (écran supprimé : parcours unique) | `captures/v1/jour/02-cle-detectee.png` |
| `docs/administration.md` | thème « Pierre » | à renommer « Jour » avec l'adaptation de la charte (libellé encore « Pierre » dans la v1.0) |
| Résolution | consigne 1280×768 ; la VM de test affiche 1280×800 | captures en 1280×800 (même mise en page, 32 px de plus en bas) |

## Décisions (19/11)
- Stockages : l'utilisateur autorise tous les stockages Proxmox (19/11, dont `nvme`). ISO v1.0.0 : `/nvme/contenu/iso-v100/` (sha256 `5e0c3fba…3fc7`).
- RTX 4000 : pas de passthrough (seule carte VGA, `boot_vga=1`) → rendus 3D en CPU, mesure wgpu non faite.
- Charte : la branche `charte-v2` de l'utilisateur prime sur ma copie depuis l'Artifact (contenu identique,
  plus complète : outils, maquettes). Ma copie n'est pas poussée.

## Bloquants
- (aucun)

## Historique — v1 (18/11)

### En cours le 18/11
- Rien. **v1.0 livrée** (tag `v1.0` = 5c20866 = `main`, CI verte) ; ISO de production
  `/nvme/contenu/iso-v1/barbacane.iso` (sha256 `4e2bd821…cbb2`, `.sha256` à côté).

## Ouvert, à la décision de l'utilisateur
- Écran de confirmation avant l'effacement de la clé de destination (demandé par la charte).
- PR Dependabot #4 (nix 0.32) : `installation-qemu` en échec sur la PR ; nix 0.31.4 (correctif UB
  `recvfrom`) serait l'alternative compatible. Non fusionnée (on ne touche pas la version livrée).
- `.github/workflows/iso.yml` laissé avec `curl | sh` (décision utilisateur 18/11).
- Signature d'une vraie mise à jour avec la clé de production (phrase de passe de l'utilisateur).

## Fait et prouvé le 18/11 — bouton
- « Effacer cette clé… » en variante Destructive de la charte, vérifié sur la 950 :
  `docs/preuves/2026-11-18-bouton-destructif/` (transfert rejoué : 21 OK).

## Fait et prouvé le 18/11 — campagne finale
- **121 OK, 0 échec** sur vraies clés, ISO de production d4a3641 (sha256 `080f6ff6…14d1`), VM 920 :
  `docs/preuves/2026-11-18-finale/` (passe 1 : 95 OK ; passe 2 enchaînée : 26 OK).
- fscommon recopié dans `noyau/fscommon`, Rust épinglé : fusionnés, CI verte (main 4568f92).

## Fait et prouvé le 18/11 (suite)
- Mise à jour avec paquets Debian, borne redémarrée sur les nouveaux binaires : `docs/preuves/2026-11-18-maj-paquets/`.
- Export et journal enchaînés, vraies clés (26 OK) : `docs/preuves/2026-11-18-export-journal/`.
- Bouton désactivé plat et lisible (retour utilisateur) : `docs/preuves/2026-11-18-bouton-desactive/`.
- Guide et PDF : mises à jour avec paquets (redémarrage, bornes d'avant le 18/11).

## Trouvé et corrigé le 18/11 (grâce à la boucle rapide sur la 950)
Aucune mise à jour contenant des paquets Debian n'avait jamais été testée (les paquets « valides »
des preuves ne contenaient que des signatures ClamAV). Quatre défauts en chaîne :
1. `apt-get --no-download` + .deb local plus récent → `E: Internal Error, Pathname to install is not
   absolute` (reproduit sur bu avec un paquet factice) → option retirée.
2. `build-debs.sh` accumulait les anciennes révisions dans son dossier de sortie (ISO de test avec
   deux admind) → dossier vidé avant copie ; `DEB_REVISION` pour les correctifs du lab.
3. `postinst` redémarrait admind, qui exécute apt → `réponse invalide : EOF` → plus de redémarrage d'admind.
4. apt sous le confinement d'admind (`ProtectKernelModules=yes`) → `update-initramfs` sans
   `/usr/lib/modules` : initramfs 25 Mo au lieu de 53, 4 modules, ni virtio_scsi ni sd_mod ni ext4
   → **la borne ne redémarre plus**. Diagnostic : disque de la 950 monté en lecture seule sur l'hôte
   + clone ZFS lecture seule de l'instantané (détruit ensuite, instantané rpool pris avant).
   Correction : apt et `dpkg --configure -a` dans une unité à part (`systemd-run --wait`).
   Choix : garder admind confiné plutôt que retirer ProtectKernelModules (plus sûr).

## Méthode de test accélérée (18/11)
- Instantané « propre » restauré en 5 à 8 s avant chaque scénario (13 fois) au lieu d'une
  réinstallation (30 min) : `tests/proxmox/campagne-rapide.sh`, `PROPRE=1`, `REPRISE=propre`, `RETOUR=0`.
- Correctifs sans ISO : `tests/proxmox/correctif.sh` (compilation incrémentale sur bu, 3 min) +
  scénario `correctif` (borne de développement signée par la clé de TEST uniquement).
- bu : 24 Go, 8 cœurs, `CARGO_BUILD_JOBS` = cœurs − 2.

## Fait et prouvé — 18/11
- Campagne rapide sur vraies clés : 65 OK dont transfert (13), blanchiment (11, sha256 + hexadécimal),
  Ventoy (14), **écran de veille (première preuve)** — `docs/preuves/2026-11-18-rapide/`.

## Fait et prouvé avant le 18/11 (vraies clés sauf mention)
- Transfert clé inconnue → clé connue, et blanchiment : `docs/preuves/2026-11-17-finale/` (ISO e888495, 35 OK, 0 échec) ;
  avant : `docs/preuves/transfert/`, `docs/preuves/blanchiment/`.
- Installation, GRUB, PIN, enrôlement, export, clavier, clé vide/pleine/illisible, retrait, verrouillage, journal, MAJ :
  `docs/preuves/<étape>/`, bilan `docs/preuves/README.md`.
- Disques optiques : `docs/preuves/optique/`.
- Ventoy blanchie en restant démarrable (écart n° 10) : `docs/preuves/ventoy/`.
- Liste blanche d'images officielles (clé de signature de TEST du lab) : `docs/preuves/liste-blanche/`.
- Réécriture d'image Etcher vérifiée, clé démarrable (écart n° 11) : `docs/preuves/etcher/`.
- Tests parallèles sur clones : `docs/preuves/parallele-7/`. Image mkosi qui démarre : `docs/preuves/mkosi/`.

## Fait, pas prouvé
- Analyse parallèle sur 4 fils : aucun gain mesuré (hôte partagé) — `docs/performances.md`.
- Écart n° 8 borné à 12 h (b9614a5) : testé, pas rejoué sur borne.
- Cible 4 To : extrapolation, aucun disque > 64 Go.

## Ne marche pas
- Aucun échec : campagne finale arrêtée à 21 h 30 sur demande à 42 OK, 0 échec (jusqu’à reel-bureau inclus ; reste ventoy, export, clavier, vide, pleine, illisible, retrait, verrouillage, journal).

## Bloqué
- Signature de production : phrase de passe de `~/cles-barbacane/barbacane-maj.key` connue de l'utilisateur seul.
- `systemctl restart pve-cluster` refusé à Claude (fait par l'utilisateur après rpool plein).
- `.github/workflows/` : jeton sans droit `workflow`.

## 5 prochaines étapes
1. CI : `curl -s 'https://api.github.com/repos/Titouanlvt/Barbacane/actions/runs?branch=integration&per_page=5'` ;
   si verte : `git push origin integration:main` (avance rapide seulement).
2. Campagne finale complète : `cd /root/BARBACANE && nohup bash lab/campagne-finale.sh > logs/campagne-finale-3.log 2>&1 &`
   (~6 h, 920) ; attendre avec `lab/attendre.sh logs/campagne-finale-3.log FIN= 600 30 <PID>`.
3. Écran de veille : `SCENARIOS="limites" tests/proxmox/parallele.sh` (clones depuis 940).
4. Chaîne de construction : remplacer `curl https://sh.rustup.rs | sh` par Rust épinglé (paquets Debian ou
   rustup-init vérifié par sha256) ; recopier `rust-fscommon` dans `noyau/` (accord utilisateur 17/11).
5. Mesurer l'analyse parallèle sur une borne seule et compléter `docs/performances.md`.
