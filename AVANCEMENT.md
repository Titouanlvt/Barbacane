# Avancement — mission du 17/11/2026 (mis à jour par Claude)

## En cours
- Passage parallèle 7 (ISO 7de2d18 : ventoy, usb, limites) — `logs/parallele-7.log`.
- Écart n° 11 (réécriture d'image Etcher vérifiée), branche `etcher-image` : code + tests unitaires OK ;
  preuve VM 961 (ISO de test, clé du lab) chaînée après la construction — `logs/preuve-etcher.log`.
- 920 : campagne vraies clés, ISO 20a9e6d (`lab/campagne-integ2.sh`, journal `campagne-integ.log`).
  68 OK à 17 h 30 ; étape ventoy. Seul échec : reel-windows (attendu sans liste blanche).

## Fait (avec preuve)
- **Fusion dans main** : e438f52 (CI et ISO vertes), 17/11 vers 18 h. Dependabot n° 1-3 inclus (d4ebad6).
- Écran de veille (10 min, réveil au toucher) — 3ec44be ; étape de preuve `veille` — e438f52.
- Analyse parallèle des fichiers simples (4 fils) + compteur en direct — 436abd8, d5f301f (tests OK ; mesure à venir).
- Guide d'installation et PDF : clés démarrables, images officielles, espace de travail — 5f0f89a.
- docs/preuves/README.md : bilan des demandes du 17/11 — 95c6cc6.
- Parcours « Analyser » puis Copier / Graver / Blanchir / Arrêter ici — passages parallèles 5 et 6.
- Clé Ventoy blanchie en gardant démarrable, démarre — `docs/preuves/ventoy/` (écart n° 10).
- Liste blanche d'images officielles (paquet signé, clé de test du lab) — `docs/preuves/liste-blanche/`.
- Espace de travail chiffré éphémère, refus avant copie — passages 5/6 (Rufus NTFS 6,3 Go OK).
- Mesures de performance — `docs/performances.md`.
- Correctifs d'interface : boutons sur une ligne, gris opaque + tranche grise, centrage, barre, bandeau.

## Bloquants
- Signature de production : phrase de passe de `barbacane-maj.key` inconnue (choix : clé de test du lab pour les preuves).

## Prochaines étapes
1. Fin de la 920 → ISO finale (integration HEAD) → passage parallèle `limites` + captures d'interface.
2. Mesurer le gain de l'analyse parallèle (ISO suivante).
3. Écart n° 11 : preuve puis fusion de `etcher-image` dans integration.
4. Campagne finale vraies clés (`lab/campagne-finale.sh`, `logs/campagne-finale.log`) puis bilan final dans docs/preuves/README.md.
