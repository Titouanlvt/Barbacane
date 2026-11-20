//! Journal d'audit chaîné du serveur Barbacane (conception §3.9, `docs/suite/serveur-maj-audit.md`).
//!
//! - **Schéma strict** : chaque ligne est un [`Enregistrement`] JSON dont la forme est
//!   canonique (la ligne doit être exactement la sérialisation de son contenu : champ inconnu,
//!   répété, réordonné ou espace ajouté → refus) ; chaque texte est borné en longueur et en jeu
//!   de caractères ; aucun nom de fichier (D2).
//! - **Chaînage SHA-384** : `prec` = SHA-384 de la ligne précédente (96 zéros pour la première) ;
//!   `n` = numéro d'ordre à partir de 1.
//! - **Ajout seul** : ouverture `O_APPEND`, jamais de réécriture ni de troncature (compatible
//!   avec l'attribut `chattr +a`), verrou exclusif `flock` entre écrivains.
//! - **Points de contrôle signés** (ECDSA P-384 / SHA-384, D6) par une **clé d'audit distincte**,
//!   que le processus exposé au réseau (passerelle) ne lit jamais : `barbacane-audit sceller`,
//!   lancé périodiquement sous un compte dédié, vérifie toute la chaîne puis ajoute un
//!   enregistrement `point_de_controle` qui signe le numéro et l'empreinte du dernier.
//! - **Export** des empreintes des points de contrôle, à sortir du serveur chaque jour :
//!   une réécriture complète du journal (même re-signée avec une clé volée) ou une troncature
//!   devient détectable.
#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};

/// Version du schéma portée par chaque enregistrement.
pub const VERSION_SCHEMA: u16 = 1;
/// Taille maximale d'une ligne (sans le saut de ligne).
pub const TAILLE_ENREGISTREMENT_MAX: usize = 2048;
/// Contexte signé avec chaque point de contrôle (séparation des usages de la clé).
pub const CONTEXTE_SIGNATURE: &str = "barbacane-audit-v1 point-de-controle";
/// En-tête SubjectPublicKeyInfo d'une clé publique ECDSA P-384 (point non compressé).
const SPKI_P384: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

/// Empreinte « précédente » du premier enregistrement.
pub fn empreinte_initiale() -> String {
    "0".repeat(96)
}

/// SHA-384 (hexadécimal minuscule) d'une ligne du journal, sans son saut de ligne.
pub fn empreinte(ligne: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA384, ligne))
}

// ───────────────────────────── Schéma ─────────────────────────────────────────────────────────

/// Battement anormal (journalisé au changement d'état, pas à chaque battement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anomalie {
    HorlogeDerivee,
    HorsService,
    BorneRefusee,
}

/// Motif de refus d'un paquet ou d'un plancher de mise à jour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusMaj {
    CleAbsente,
    NonSigne,
    SignatureInvalide,
    FormatInvalide,
    TropGros,
    PlancherAbsent,
    SousLePlancher,
    VersionNonCroissante,
    PlancherEnRecul,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultatMaj {
    Appliquee,
    Echec,
}

/// Événements audités. Toute évolution change [`VERSION_SCHEMA`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Evenement {
    JetonCree {
        site: String,
        expire_le: u64,
    },
    EnrolementDemande {
        demande: String,
        empreinte: String,
    },
    EnrolementValide {
        demande: String,
        borne: String,
    },
    EnrolementRefuse {
        demande: String,
    },
    Revocation {
        borne: String,
        motif: String,
    },
    CrlPubliee {
        numero: u64,
    },
    CertificatRenouvele {
        borne: String,
    },
    BattementAnormal {
        borne: String,
        anomalie: Anomalie,
        ecart_s: i64,
    },
    PlancherInstalle {
        version_min: u64,
    },
    MajDeposee {
        version_maj: u64,
        sha256: String,
        taille: u64,
    },
    MajRefusee {
        sha256: String,
        refus: RefusMaj,
    },
    MajDiffusee {
        version_maj: u64,
    },
    MajProposee {
        borne: String,
        version_maj: u64,
    },
    MajTelechargee {
        borne: String,
        version_maj: u64,
    },
    MajRapportee {
        borne: String,
        version_maj: u64,
        resultat: ResultatMaj,
    },
    /// Autre action d'administration (consultation, export…) : nom court.
    Administration {
        action: String,
    },
    /// Écrit seulement par [`Journal::sceller`].
    PointDeControle {
        jusqua: u64,
        empreinte: String,
        cle: String,
        signature: String,
    },
}

/// Identifiant ou mot court : `[A-Za-z0-9._:+~=-]`, 1 à 128.
pub fn ident_valide(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:+~=-".contains(&c))
}

fn hex_valide(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

impl Evenement {
    /// Contrôle des champs (longueurs, jeux de caractères).
    pub fn valider(&self) -> bool {
        use Evenement::*;
        match self {
            JetonCree { site, .. } => ident_valide(site),
            EnrolementDemande { demande, empreinte } => {
                ident_valide(demande) && hex_valide(empreinte, 64)
            }
            EnrolementValide { demande, borne } => ident_valide(demande) && ident_valide(borne),
            EnrolementRefuse { demande } => ident_valide(demande),
            Revocation { borne, motif } => ident_valide(borne) && ident_valide(motif),
            CertificatRenouvele { borne }
            | BattementAnormal { borne, .. }
            | MajProposee { borne, .. }
            | MajTelechargee { borne, .. }
            | MajRapportee { borne, .. } => ident_valide(borne),
            MajDeposee { sha256, .. } | MajRefusee { sha256, .. } => hex_valide(sha256, 64),
            Administration { action } => ident_valide(action),
            PointDeControle {
                empreinte,
                cle,
                signature,
                ..
            } => hex_valide(empreinte, 96) && hex_valide(cle, 16) && hex_valide(signature, 192),
            CrlPubliee { .. } | PlancherInstalle { .. } | MajDiffusee { .. } => true,
        }
    }
}

/// Une ligne du journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enregistrement {
    pub v: u16,
    /// Numéro d'ordre (1, 2, 3…).
    pub n: u64,
    /// Heure de réception par le serveur (secondes Unix, UTC).
    pub le: u64,
    /// `passerelle`, `admin:uid-<n>`, `audit`…
    pub acteur: String,
    pub evenement: Evenement,
    /// SHA-384 de la ligne précédente.
    pub prec: String,
}

impl Enregistrement {
    /// Analyse stricte d'une ligne (sans saut de ligne).
    pub fn analyser(ligne: &[u8]) -> Result<Enregistrement, String> {
        if ligne.len() > TAILLE_ENREGISTREMENT_MAX {
            return Err("ligne trop longue".into());
        }
        let e: Enregistrement =
            serde_json::from_slice(ligne).map_err(|e| format!("JSON refusé : {e}"))?;
        if e.v != VERSION_SCHEMA {
            return Err(format!("version de schéma {} non gérée", e.v));
        }
        if !ident_valide(&e.acteur) || !hex_valide(&e.prec, 96) || !e.evenement.valider() {
            return Err("champ hors bornes".into());
        }
        if serde_json::to_vec(&e).map_err(|e| e.to_string())? != ligne {
            return Err("forme non canonique".into());
        }
        Ok(e)
    }

    fn ligne(&self) -> Result<Vec<u8>> {
        if !ident_valide(&self.acteur) || !self.evenement.valider() {
            bail!("enregistrement d'audit hors bornes");
        }
        let o = serde_json::to_vec(self)?;
        if o.len() > TAILLE_ENREGISTREMENT_MAX {
            bail!("enregistrement d'audit trop long");
        }
        Ok(o)
    }
}

// ───────────────────────────── Clés ───────────────────────────────────────────────────────────

fn pem(etiquette: &str, der: &[u8]) -> String {
    let b64 = data_encoding::BASE64.encode(der);
    let mut s = format!("-----BEGIN {etiquette}-----\n");
    for bloc in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(bloc).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {etiquette}-----\n"));
    s
}

fn depem(texte: &str, etiquette: &str) -> Result<Vec<u8>> {
    let debut = format!("-----BEGIN {etiquette}-----");
    let fin = format!("-----END {etiquette}-----");
    let mut lignes = texte.lines().map(str::trim).skip_while(|l| *l != debut);
    if lignes.next().is_none() {
        bail!("bloc PEM « {etiquette} » absent");
    }
    let mut b64 = String::new();
    for l in lignes {
        if l == fin {
            return data_encoding::BASE64
                .decode(b64.as_bytes())
                .context("PEM : base64 invalide");
        }
        b64.push_str(l);
    }
    bail!("bloc PEM « {etiquette} » non terminé")
}

/// Clé publique d'audit (ECDSA P-384).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClePublique {
    point: Vec<u8>,
}

impl ClePublique {
    pub fn depuis_pem(texte: &str) -> Result<ClePublique> {
        let der = depem(texte, "PUBLIC KEY")?;
        let point = der
            .strip_prefix(&SPKI_P384[..])
            .filter(|p| p.len() == 97 && p[0] == 4)
            .context("clé publique d'audit : ECDSA P-384 attendue")?;
        Ok(ClePublique {
            point: point.to_vec(),
        })
    }

    pub fn lire(chemin: &Path) -> Result<ClePublique> {
        ClePublique::depuis_pem(
            &std::fs::read_to_string(chemin)
                .with_context(|| format!("lecture de {}", chemin.display()))?,
        )
    }

    pub fn pem(&self) -> String {
        let mut der = SPKI_P384.to_vec();
        der.extend_from_slice(&self.point);
        pem("PUBLIC KEY", &der)
    }

    /// Identifiant court : 16 premiers caractères du SHA-256 du point.
    pub fn id(&self) -> String {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, &self.point))[..16].to_owned()
    }

    fn verifier(&self, message: &[u8], signature_hex: &str) -> bool {
        let Ok(sig) = hex::decode(signature_hex) else {
            return false;
        };
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &self.point)
            .verify(message, &sig)
            .is_ok()
    }
}

/// Clé privée d'audit (PKCS#8, ECDSA P-384). Jamais lue par la passerelle.
pub struct CleAudit {
    paire: EcdsaKeyPair,
    alea: SystemRandom,
}

impl CleAudit {
    /// Nouvelle clé : PKCS#8 en PEM.
    pub fn generer() -> Result<String> {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("génération de la clé d'audit"))?;
        Ok(pem("PRIVATE KEY", doc.as_ref()))
    }

    pub fn depuis_pem(texte: &str) -> Result<CleAudit> {
        let der = depem(texte, "PRIVATE KEY")?;
        let alea = SystemRandom::new();
        let paire = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &der, &alea)
            .map_err(|_| anyhow::anyhow!("clé d'audit : PKCS#8 ECDSA P-384 attendue"))?;
        Ok(CleAudit { paire, alea })
    }

    /// Lit la clé ; refuse un fichier lisible par le groupe ou les autres (comme ssh).
    pub fn lire(chemin: &Path) -> Result<CleAudit> {
        let mode = std::fs::metadata(chemin)
            .with_context(|| format!("clé d'audit {}", chemin.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "clé d'audit {} lisible par d'autres comptes (mode {:o}) : refusée",
                chemin.display(),
                mode & 0o777
            );
        }
        CleAudit::depuis_pem(&std::fs::read_to_string(chemin)?)
    }

    pub fn publique(&self) -> ClePublique {
        ClePublique {
            point: self.paire.public_key().as_ref().to_vec(),
        }
    }

    fn signer(&self, message: &[u8]) -> Result<String> {
        let s = self
            .paire
            .sign(&self.alea, message)
            .map_err(|_| anyhow::anyhow!("signature du point de contrôle"))?;
        Ok(hex::encode(s.as_ref()))
    }
}

/// Message signé par un point de contrôle.
fn message_point(jusqua: u64, empreinte: &str) -> Vec<u8> {
    format!("{CONTEXTE_SIGNATURE}\n{jusqua}\n{empreinte}\n").into_bytes()
}

// ───────────────────────────── Vérification ───────────────────────────────────────────────────

/// Altération détectée (numéro de ligne = numéro attendu de l'enregistrement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Defaut {
    /// Dernière ligne sans saut de ligne (écriture interrompue ou troncature).
    FinIncomplete,
    Illisible {
        ligne: u64,
        cause: String,
    },
    /// Numéro d'ordre inattendu : suppression ou réordonnancement.
    Numero {
        ligne: u64,
        trouve: u64,
    },
    /// `prec` différent de l'empreinte de la ligne précédente : modification.
    Chainage {
        ligne: u64,
    },
    PointDeControle {
        ligne: u64,
        cause: &'static str,
    },
    /// Désaccord avec une empreinte exportée hors du serveur.
    Export {
        point: u64,
        cause: &'static str,
    },
}

impl std::fmt::Display for Defaut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Defaut::FinIncomplete => write!(f, "dernière ligne incomplète"),
            Defaut::Illisible { ligne, cause } => write!(f, "ligne {ligne} illisible : {cause}"),
            Defaut::Numero { ligne, trouve } => write!(
                f,
                "ligne {ligne} : numéro {trouve} (suppression ou réordonnancement)"
            ),
            Defaut::Chainage { ligne } => write!(
                f,
                "ligne {ligne} : chaînage rompu (ligne précédente modifiée)"
            ),
            Defaut::PointDeControle { ligne, cause } => {
                write!(f, "point de contrôle ligne {ligne} : {cause}")
            }
            Defaut::Export { point, cause } => write!(f, "point exporté n° {point} : {cause}"),
        }
    }
}

impl std::error::Error for Defaut {}

/// Point de contrôle (tel qu'exporté).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointExporte {
    /// Numéro de l'enregistrement `point_de_controle`.
    pub n: u64,
    pub le: u64,
    /// SHA-384 de sa ligne.
    pub empreinte: String,
}

/// Résultat d'une vérification réussie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bilan {
    pub enregistrements: u64,
    pub points: Vec<PointExporte>,
    /// Enregistrements postérieurs au dernier point de contrôle (non encore protégés par une
    /// signature : une troncature de cette fin n'est pas détectable).
    pub non_scelles: u64,
    /// Empreinte de la dernière ligne.
    pub derniere: String,
}

/// Vérifie tout le contenu d'un journal : forme, numéros, chaînage, signatures des points de
/// contrôle, et accord avec les empreintes exportées.
pub fn verifier(
    contenu: &[u8],
    cle: &ClePublique,
    exports: &[PointExporte],
) -> Result<Bilan, Defaut> {
    if !contenu.is_empty() && !contenu.ends_with(b"\n") {
        return Err(Defaut::FinIncomplete);
    }
    let mut prec = empreinte_initiale();
    let mut n = 0u64;
    let mut points = Vec::new();
    let corps = contenu.strip_suffix(b"\n").unwrap_or(contenu);
    if !contenu.is_empty() {
        for ligne in corps.split(|o| *o == b'\n') {
            let attendu = n + 1;
            let e = Enregistrement::analyser(ligne).map_err(|cause| Defaut::Illisible {
                ligne: attendu,
                cause,
            })?;
            if e.n != attendu {
                return Err(Defaut::Numero {
                    ligne: attendu,
                    trouve: e.n,
                });
            }
            if e.prec != prec {
                return Err(Defaut::Chainage { ligne: attendu });
            }
            let h = empreinte(ligne);
            if let Evenement::PointDeControle {
                jusqua,
                empreinte: e_point,
                cle: id,
                signature,
            } = &e.evenement
            {
                let defaut = |cause| Defaut::PointDeControle {
                    ligne: attendu,
                    cause,
                };
                if *jusqua != n || *e_point != prec {
                    return Err(defaut("incohérent avec la chaîne"));
                }
                if *id != cle.id() {
                    return Err(defaut("clé d'audit inconnue"));
                }
                if !cle.verifier(&message_point(*jusqua, e_point), signature) {
                    return Err(defaut("signature invalide"));
                }
                points.push(PointExporte {
                    n: attendu,
                    le: e.le,
                    empreinte: h.clone(),
                });
            }
            prec = h;
            n = attendu;
        }
    }
    for x in exports {
        match points.iter().find(|p| p.n == x.n) {
            Some(p) if p.empreinte == x.empreinte => {}
            Some(_) => {
                return Err(Defaut::Export {
                    point: x.n,
                    cause: "empreinte différente (journal réécrit)",
                });
            }
            None if x.n > n => {
                return Err(Defaut::Export {
                    point: x.n,
                    cause: "absent : journal tronqué",
                });
            }
            None => {
                return Err(Defaut::Export {
                    point: x.n,
                    cause: "n'est plus un point de contrôle (journal réécrit)",
                });
            }
        }
    }
    let dernier_point = points.last().map(|p| p.n).unwrap_or(0);
    Ok(Bilan {
        enregistrements: n,
        points,
        non_scelles: n - dernier_point,
        derniere: prec,
    })
}

// ───────────────────────────── Export ─────────────────────────────────────────────────────────

/// `AAAA-MM-JJ HH:MM:SS UTC` (calendrier grégorien proleptique).
pub fn date_utc(secondes: u64) -> String {
    let jours = (secondes / 86400) as i64;
    let s = secondes % 86400;
    // Algorithme « civil_from_days » (H. Hinnant).
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let jour = doy - (153 * mp + 2) / 5 + 1;
    let mois = if mp < 10 { mp + 3 } else { mp - 9 };
    let annee = yoe + ere * 400 + i64::from(mois <= 2);
    format!(
        "{annee:04}-{mois:02}-{jour:02} {:02}:{:02}:{:02} UTC",
        s / 3600,
        (s / 60) % 60,
        s % 60
    )
}

/// Texte de l'export quotidien (à copier hors du serveur).
pub fn texte_export(bilan: &Bilan, maintenant: u64) -> String {
    let mut s = String::from(
        "# barbacane-audit : empreintes SHA-384 des points de contrôle du journal d'audit\n# À conserver HORS du serveur (support non réinscriptible ou serveur de journaux distinct).\n",
    );
    s.push_str(&format!(
        "# exporté le {} ; {} enregistrements ; dernière empreinte {}\n",
        date_utc(maintenant),
        bilan.enregistrements,
        bilan.derniere
    ));
    for p in &bilan.points {
        s.push_str(&format!("point {} {} {}\n", p.n, p.le, p.empreinte));
    }
    s
}

/// Lit un export (lignes `point N LE EMPREINTE`, commentaires `#`).
pub fn lire_export(texte: &str) -> Result<Vec<PointExporte>> {
    let mut v = Vec::new();
    for (i, l) in texte.lines().enumerate() {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let c: Vec<&str> = l.split(' ').collect();
        match c.as_slice() {
            ["point", n, le, h] if hex_valide(h, 96) => v.push(PointExporte {
                n: n.parse()
                    .with_context(|| format!("export ligne {}", i + 1))?,
                le: le
                    .parse()
                    .with_context(|| format!("export ligne {}", i + 1))?,
                empreinte: (*h).to_owned(),
            }),
            _ => bail!("export ligne {} : « point N LE EMPREINTE » attendu", i + 1),
        }
    }
    Ok(v)
}

// ───────────────────────────── Journal (fichier) ──────────────────────────────────────────────

/// Journal d'audit sur disque : `CHEMIN` (ajout seul) et `CHEMIN.verrou`.
#[derive(Debug, Clone)]
pub struct Journal {
    chemin: PathBuf,
}

impl Journal {
    pub fn new(chemin: impl Into<PathBuf>) -> Journal {
        Journal {
            chemin: chemin.into(),
        }
    }

    pub fn chemin(&self) -> &Path {
        &self.chemin
    }

    fn verrou(&self) -> Result<File> {
        let mut nom = self.chemin.as_os_str().to_owned();
        nom.push(".verrou");
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(PathBuf::from(nom))
            .context("verrou du journal d'audit")?;
        f.lock().context("prise du verrou du journal d'audit")?;
        Ok(f)
    }

    fn ouvrir(&self) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.chemin)
            .with_context(|| format!("journal d'audit {}", self.chemin.display()))
    }

    /// Numéro et empreinte du dernier enregistrement (lecture de la fin seulement).
    fn dernier(f: &mut File) -> Result<(u64, String)> {
        let taille = f.metadata()?.len();
        if taille == 0 {
            return Ok((0, empreinte_initiale()));
        }
        let debut = taille.saturating_sub(2 * TAILLE_ENREGISTREMENT_MAX as u64 + 2);
        f.seek(SeekFrom::Start(debut))?;
        let mut fin = Vec::new();
        f.read_to_end(&mut fin)?;
        let Some(fin) = fin.strip_suffix(b"\n") else {
            bail!("journal d'audit : dernière ligne incomplète (vérification requise)");
        };
        let ligne = match fin.iter().rposition(|o| *o == b'\n') {
            Some(p) => &fin[p + 1..],
            None if debut == 0 => fin,
            None => bail!("journal d'audit : ligne trop longue"),
        };
        let e = Enregistrement::analyser(ligne)
            .map_err(|c| anyhow::anyhow!("journal d'audit : dernière ligne : {c}"))?;
        Ok((e.n, empreinte(ligne)))
    }

    fn ecrire(f: &mut File, le: u64, acteur: &str, evenement: Evenement) -> Result<u64> {
        let (n, prec) = Journal::dernier(f)?;
        let e = Enregistrement {
            v: VERSION_SCHEMA,
            n: n + 1,
            le,
            acteur: acteur.into(),
            evenement,
            prec,
        };
        let mut ligne = e.ligne()?;
        ligne.push(b'\n');
        f.write_all(&ligne)?;
        f.sync_data()?;
        Ok(e.n)
    }

    /// Ajoute un événement (tout sauf un point de contrôle). Renvoie son numéro.
    pub fn ajouter(&self, le: u64, acteur: &str, evenement: Evenement) -> Result<u64> {
        if matches!(evenement, Evenement::PointDeControle { .. }) {
            bail!("un point de contrôle s'écrit par « sceller »");
        }
        let _v = self.verrou()?;
        let mut f = self.ouvrir()?;
        Journal::ecrire(&mut f, le, acteur, evenement)
    }

    /// Contenu complet (vide si le journal n'existe pas encore).
    pub fn lire(&self) -> Result<Vec<u8>> {
        match std::fs::read(&self.chemin) {
            Ok(o) => Ok(o),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).context("lecture du journal d'audit"),
        }
    }

    /// Vérifie TOUTE la chaîne puis ajoute un point de contrôle signé. Une chaîne altérée
    /// n'est jamais scellée.
    pub fn sceller(&self, cle: &CleAudit, le: u64) -> Result<u64> {
        let _v = self.verrou()?;
        let mut f = self.ouvrir()?;
        let mut contenu = Vec::new();
        f.read_to_end(&mut contenu)?;
        let bilan = verifier(&contenu, &cle.publique(), &[])
            .map_err(|d| anyhow::anyhow!("journal d'audit altéré, non scellé : {d}"))?;
        let signature = cle.signer(&message_point(bilan.enregistrements, &bilan.derniere))?;
        Journal::ecrire(
            &mut f,
            le,
            "audit",
            Evenement::PointDeControle {
                jusqua: bilan.enregistrements,
                empreinte: bilan.derniere,
                cle: cle.publique().id(),
                signature,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forme_canonique_exigee() {
        let e = Enregistrement {
            v: 1,
            n: 1,
            le: 5,
            acteur: "passerelle".into(),
            evenement: Evenement::CrlPubliee { numero: 3 },
            prec: empreinte_initiale(),
        };
        let ligne = e.ligne().unwrap();
        assert_eq!(Enregistrement::analyser(&ligne).unwrap(), e);
        let texte = String::from_utf8(ligne).unwrap();
        for variante in [
            texte.replacen("{\"v\"", "{ \"v\"", 1),
            texte.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1),
            texte.replacen("\"numero\":3", "\"numero\":3,\"nom\":\"x.doc\"", 1),
            texte.replacen("passerelle", "passe relle", 1),
        ] {
            assert!(
                Enregistrement::analyser(variante.as_bytes()).is_err(),
                "{variante}"
            );
        }
    }

    #[test]
    fn cle_pem_aller_retour() {
        let cle = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
        let p = cle.publique();
        assert_eq!(ClePublique::depuis_pem(&p.pem()).unwrap(), p);
        let m = message_point(3, &empreinte_initiale());
        let s = cle.signer(&m).unwrap();
        assert!(p.verifier(&m, &s));
        assert!(!p.verifier(&message_point(4, &empreinte_initiale()), &s));
    }

    #[test]
    fn dates() {
        assert_eq!(date_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(date_utc(1_795_000_000), "2026-11-18 11:06:40 UTC");
        assert_eq!(date_utc(951_782_400), "2000-02-29 00:00:00 UTC");
    }
}
