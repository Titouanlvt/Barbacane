# Avancement — 17/11/2026, 21 h (mis à jour par Claude)

Dépôt de travail : `/root/BARBACANE/wt-main`, branche `integration` (GitHub Titouanlvt/Barbacane).
`main` = b9614a5 (CI et ISO vertes ; Etcher 141f78f et la suite attendent leur CI). L'ancien clone `/root/BARBACANE/usbsas` (branche
`claude/affectionate-galileo-w0bjm2`, supprimée du distant) est obsolète : ses captures non suivies
sont dans `docs/preuves/2026-11-14-clone-usbsas/`. Ne plus y travailler.

## Fait et prouvé (vraies clés sauf mention)
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
- Écran de veille (10 min) : étape `veille` écrite, jamais jouée.
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
