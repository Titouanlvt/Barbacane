# Avancement — 18/11/2026 (mis à jour par Claude)

## En cours (18/11)
- 920 (vraies clés) : `tests/proxmox/campagne-rapide.sh` — plus de réinstallation : instantané
  « propre » (PIN, clé enrôlée, mémoire comprise) restauré avant chaque scénario en **5 s**
  (`PROPRE=1`, `REPRISE=propre`). Journal `logs/campagne-rapide.log`.
- Boucle de correctif rapide : borne de développement **950** (ISO signée par la clé de TEST du lab),
  `tests/proxmox/correctif.sh` (compilation incrémentale sur bu : 189 s ; `DEB_REVISION`) puis
  scénario `correctif` (mise à jour signée, redémarrage, nouvel instantané « propre »).
- **Bogue trouvé par cette boucle** : une mise à jour contenant des paquets Debian échoue toujours
  (`apt-get : E: Internal Error, Pathname to install is not absolute 'usbsas-server_0.3.4-…_amd64.deb'`),
  cause `--no-download` (reproduit sur bu avec un paquet factice). Corrigé dans admind (test unitaire).
  Les bornes installées avant ne peuvent pas recevoir ce correctif par mise à jour : ISO de TEST
  reconstruite une fois pour la 950 (`logs/iso-test-2.log`) ; ISO de production à la fin seulement.
- bu : 24 Go de RAM, 8 cœurs (compilation à 6 tâches = cœurs − 2).

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
