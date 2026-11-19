# Politique de certification — PKI Barbacane suite (v0.1, 19/11/2026)

Document minimal exigé avant l'étape « Socle » (conception §3.5, §8 étape 0). Il fixe ce que la
PKI émet, avec quoi, pour combien de temps, et comment on révoque. Décisions : `decisions.md`
(D6 cryptographie, D7 racine, D8 révocation). Mécanismes conformes au RGS et au guide des
mécanismes cryptographiques de l'ANSSI.

## 1. Hiérarchie

```
Racine Barbacane (HORS LIGNE, jamais sur un système en réseau)
├── CA « bornes »   → certificats clients des bornes (mTLS)
└── CA « serveur »  → certificat TLS de la passerelle (et de l'interface web)
```

Un identifiant de site (`site-<n>`) figure dans chaque certificat de borne : un futur serveur
central (conception §11) pourra chapeauter plusieurs serveurs de site sans réémettre.

## 2. Algorithmes

| Élément | Clé | Signature |
|---|---|---|
| Racine | ECDSA P-384 | ECDSA-SHA384 |
| CA intermédiaires | ECDSA P-384 | ECDSA-SHA384 |
| Borne, serveur | ECDSA P-256 | ECDSA-SHA256 |
| TLS | 1.3 seul ; `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256` ; groupes `secp384r1`, `secp256r1` | — |

Pas de RSA, pas de SHA-1, pas de TLS 1.2 (refusé côté passerelle et côté agent).

## 3. Profils

| Profil | Durée | Extensions |
|---|---|---|
| Racine | 10 ans | `basicConstraints CA:TRUE, pathlen:1` critique ; `keyUsage keyCertSign, cRLSign` critique |
| CA intermédiaire | 3 ans | `basicConstraints CA:TRUE, pathlen:0` critique ; `keyUsage keyCertSign, cRLSign` critique ; `nameConstraints` : la CA bornes n'émet que des noms `*.bornes.barbacane.invalid`, la CA serveur que le nom du serveur |
| Borne | **90 jours**, renouvelé à mi-vie par l'agent | `keyUsage digitalSignature` critique ; `extendedKeyUsage clientAuth` ; SAN `URI:urn:barbacane:borne:<site>:<uuid>` ; clé générée et non exportable dans le TPM |
| Serveur | 1 an | `keyUsage digitalSignature` critique ; `extendedKeyUsage serverAuth` ; SAN DNS/IP du serveur |

Nom distinctif : `CN=<type> <identifiant>, OU=<site>, O=Barbacane`. Les certificats et clés de
**TEST** du lab portent `O=Barbacane TEST — NE PAS UTILISER EN PRODUCTION` : la passerelle de
production les refuse (vérification de l'empreinte de la racine attendue).

## 4. Émission

- **Borne** : uniquement après un enrôlement validé par un administrateur (jeton 1 h à usage
  unique + comparaison de l'empreinte de la demande affichée sur la borne et dans l'interface web).
  Renouvellement : l'agent présente son certificat valide et une nouvelle demande signée dans le
  TPM ; même identité, pas de nouvelle validation humaine.
- **Serveur** : à l'installation, demande générée sur le serveur, signée par la CA serveur.
- **CA intermédiaires** : signées par la racine lors d'une **cérémonie hors ligne** (§8).

## 5. Révocation

- Motifs : borne volée ou réformée, clé suspecte, changement de site, fin de vie.
- CRL par CA intermédiaire, **validité 7 jours**, republiée chaque jour et à chaque révocation ;
  la passerelle refuse toute connexion si sa CRL est expirée (fail-closed).
- Révocation d'une borne : effet à la connexion suivante (la passerelle lit la CRL à chaque
  poignée de main). Révocation massive : double validation (conception §3.10).
- CRL de la racine (révocation d'une CA intermédiaire) : produite lors de la cérémonie, validité
  1 an, importée manuellement sur le serveur.

## 6. Garde des clés

| Clé | Où | Qui |
|---|---|---|
| Racine | support chiffré (LUKS) au coffre, double exemplaire en deux lieux | deux détenteurs nommés, présents ensemble |
| CA intermédiaires | TPM du serveur, ou fichier chiffré déverrouillé par le TPM au démarrage | service PKI du serveur (compte système dédié) |
| Borne | TPM de la borne, non exportable | agent |
| Serveur | TPM du serveur | passerelle |

## 7. Journalisation

Toute émission, renouvellement et révocation entre dans le journal d'audit chaîné (conception
§3.9) : empreinte du certificat, numéro de série, sujet, opérateur, horodatage.

## 8. Cérémonie de la racine (production)

1. Machine dédiée **sans aucune interface réseau** (carte retirée ou désactivée dans le BIOS),
   démarrée sur un support Debian vérifié ; deux détenteurs présents ; procès-verbal.
2. Génération de la racine (P-384) et de son certificat (10 ans) ; empreinte SHA-256 lue à voix
   haute et inscrite au procès-verbal.
3. Signature des demandes des deux CA intermédiaires apportées sur support amovible.
4. Copie chiffrée de la clé racine sur deux supports ; vérification de relecture ; machine éteinte,
   mémoire non conservée.
5. L'empreinte de la racine et celle de la CA serveur sont publiées hors bande (note de version
   imprimée) et embarquées dans l'ISO des bornes.

## 9. Lab (clé de TEST)

La racine de TEST est générée par `serveur/pki/racine-test.sh` (étape 5) sur une VM `barbacane-9xx`
**sans carte réseau**, puis seuls le certificat racine et les CA intermédiaires signées en sortent
(disque de transfert). Son nom porte la mention TEST ; elle n'est jamais embarquée dans une ISO de
production.
