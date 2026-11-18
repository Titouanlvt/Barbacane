# Avancement — 18/11/2026 (mis à jour par Claude, en autonomie)

## En cours
- **Campagne finale** (ISO de production d4a3641, sha256 `080f6ff6…14d1`, vraies clés, VM 920) :
  passe 1 tous les scénarios depuis l'instantané, passe 2 `transfert maj export journal` enchaînés —
  `lab/campagne-finale-3.sh`, `logs/campagne-finale-3.log`.
- Branche `fscommon-local` : rust-fscommon recopié dans `noyau/fscommon` + Rust épinglé
  (`systeme/rust/installer-rust.sh`) ; tests complets sur bu en cours (`logs/vendoring-tests.log`).
  `.github/workflows/iso.yml` garde `curl | sh` (jeton sans droit workflow).
- CI d'integration en file d'attente ; fusion dans main dès qu'elle est verte.

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
