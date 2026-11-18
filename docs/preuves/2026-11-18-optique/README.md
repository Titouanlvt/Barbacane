# Disques optiques sur le code du 18/11/2026 (VM 950)

Depuis la preuve complète du 15/11 (`../optique/`), le contenu des disques passe par le volume
chiffré de session (0312b55). Rejoué sur la borne de développement 950 (code d'integration, ISO
de test), clés émulées car les vraies clés servaient à la campagne finale de la 920.

| Étape | Résultat | Preuve |
|---|---|---|
| Image ISO multisession en lecteur virtuel → clé : 4 sains identiques (sha256), EICAR caché dans la 1re session trouvé et refusé | 7 OK | `image/`, `image-resultats.txt` |
| Vrai graveur (MATSHITA UJ8E2Q) passé en **scsi-generic**, aucun passthrough PCI : CD-RW vu par la borne | 2 OK | `lecteur/` |
| Vrai CD-RW (gravé par la borne le 15/11) → clé : 3 fichiers, sha256 identiques à la clé d'origine | 3 OK | `relecture/` |

La vérification finale de l'étape `image` a été refaite à la main avec la même logique que le
script : la copie d'exécution ne contenait pas `docs/` (liste de référence absente) ; corrigé en
lançant depuis une archive complète du dépôt.

**Non rejoué** : gravure et blanchiment de CD-RW. La borne éjecte le disque après gravure et ce
lecteur portable ne referme pas son tiroir : il faut une personne (preuve du 15/11).
