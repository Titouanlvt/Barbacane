# Avancement — mission du 17/11/2026 (mis à jour par Claude)

## En cours
- 920 : campagne vraies clés, ISO 20a9e6d (`lab/campagne-integ2.sh`, journal `campagne-integ.log`).
  68 OK à 17 h 30 ; étape ventoy. Seul échec : reel-windows (attendu sans liste blanche).

## Fait (avec preuve)
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
3. Réécriture d'image Etcher vérifiée : reportée (plan dans CLAUDE.md).
4. docs/preuves/README.md, PDF, CLAUDE.md ; merge integration → main (CI verte) ; dependabot.
