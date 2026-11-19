# barbacane-agent (borne en ligne uniquement)

Seul processus réseau de la borne en ligne : connexion sortante unique vers le serveur (TLS 1.3
mutuel, clé dans le TPM), récupère politique, clés enrôlées, mises à jour, heure ; envoie état,
rapports et journaux. N'existe que dans `build-iso.sh --profil en-ligne` ; jamais dans la borne hors
ligne (garde-fou `tests/iso/hors-ligne.sh`).
