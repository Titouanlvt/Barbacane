//! Mises à jour centralisées côté serveur (`docs/suite/serveur-maj-audit.md` §2).
//!
//! Le serveur **relaie** des `.bcu` signés hors ligne avec la clé des bornes ; il ne signe
//! jamais. Avant toute acceptation : signature minisign du fichier entier (avec la clé publique
//! des bornes), commentaire de confiance `barbacane-maj version N`, plancher signé hors ligne,
//! version strictement croissante. Chaque décision est auditée.
//!
//! Dossier `<registre>/maj/` (0700) : `cle-bornes.pub`, `plancher.json(.minisig)`,
//! `paquets/barbacane-maj-N.bcu(.minisig)`, `etat.json` sous verrou `etat.verrou`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use barbacane_audit::{Evenement, RefusMaj};
use barbacane_protocole::CodeErreur;
use barbacane_protocole::maj::{
    MiseAJourDisponible, ResultatMaj, TAILLE_BCU_MAX, TAILLE_SIGNATURE_MAX, commentaire_maj,
    signature_valide,
};
use serde::{Deserialize, Serialize};

use crate::outils::{aleatoire, ecrire_atomique, maintenant};
use crate::registre::{Refus, Stockage};

/// Valeur du champ `usage` d'un plancher (séparation des usages de la clé de signature).
pub const USAGE_PLANCHER: &str = "barbacane-plancher-maj";
const TAILLE_PLANCHER_MAX: u64 = 1024;

/// Plancher signé hors ligne (`serveur/maj/barbacane-plancher-prepare`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plancher {
    format: u32,
    usage: String,
    version_min: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paquet {
    pub version_maj: u64,
    pub sha256: String,
    pub taille: u64,
    pub depose_le: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtatMajBorne {
    Proposee,
    Telechargee,
    Appliquee,
    Echec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiviBorne {
    pub version_maj: u64,
    pub etat: EtatMajBorne,
    pub le: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtatMaj {
    pub version: u16,
    pub plancher: Option<u64>,
    pub paquets: Vec<Paquet>,
    /// Paquet proposé aux bornes.
    pub diffusee: Option<u64>,
    /// Suivi par uuid de borne.
    pub bornes: BTreeMap<String, SuiviBorne>,
}

impl Default for EtatMaj {
    fn default() -> Self {
        EtatMaj {
            version: 1,
            plancher: None,
            paquets: Vec::new(),
            diffusee: None,
            bornes: BTreeMap::new(),
        }
    }
}

/// Refus d'un dépôt ou d'un plancher (motif audité).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusDepot(pub RefusMaj);

impl std::fmt::Display for RefusDepot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let texte = match self.0 {
            RefusMaj::CleAbsente => "clé publique des bornes absente (maj/cle-bornes.pub)",
            RefusMaj::NonSigne => "signature .minisig absente",
            RefusMaj::SignatureInvalide => "signature invalide pour la clé des bornes",
            RefusMaj::FormatInvalide => "format invalide",
            RefusMaj::TropGros => "paquet trop gros",
            RefusMaj::PlancherAbsent => "aucun plancher signé installé",
            RefusMaj::SousLePlancher => "version sous le plancher signé (anti-retour)",
            RefusMaj::VersionNonCroissante => {
                "version non supérieure aux paquets déjà déposés (anti-retour)"
            }
            RefusMaj::PlancherEnRecul => "plancher inférieur au plancher installé (rejeu)",
        };
        write!(f, "refusé : {texte}")
    }
}
impl std::error::Error for RefusDepot {}

fn refus<T>(m: RefusMaj) -> Result<T> {
    Err(RefusDepot(m).into())
}

/// Fichier temporaire supprimé s'il n'a pas été conservé.
struct Temporaire(PathBuf);
impl Drop for Temporaire {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn signature_de(chemin: &Path) -> PathBuf {
    let mut s = chemin.as_os_str().to_owned();
    s.push(".minisig");
    PathBuf::from(s)
}

/// Lit au plus `max` octets ; au-delà → `None`.
fn lire_borne(chemin: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    let mut o = Vec::new();
    File::open(chemin)
        .with_context(|| format!("lecture de {}", chemin.display()))?
        .take(max + 1)
        .read_to_end(&mut o)?;
    Ok((o.len() as u64 <= max).then_some(o))
}

/// SHA-256 d'un fichier (pour l'audit d'un refus) ; zéros s'il est illisible ou trop gros.
fn sha256_fichier(chemin: &Path) -> String {
    let calcul = || -> Result<String> {
        let mut f = File::open(chemin)?;
        if f.metadata()?.len() > TAILLE_BCU_MAX {
            bail!("trop gros");
        }
        let mut h = ring::digest::Context::new(&ring::digest::SHA256);
        let mut tampon = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            h.update(&tampon[..n]);
        }
        Ok(hex::encode(h.finish()))
    };
    calcul().unwrap_or_else(|_| "0".repeat(64))
}

/// Dépôt des mises à jour.
#[derive(Debug, Clone)]
pub struct DepotMaj {
    dossier: PathBuf,
    stockage: Stockage,
}

impl DepotMaj {
    pub fn ouvrir(stockage: &Stockage) -> Result<DepotMaj> {
        let dossier = stockage.dossier().join("maj");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dossier.join("paquets"))
            .with_context(|| format!("dossier {}", dossier.display()))?;
        Ok(DepotMaj {
            dossier,
            stockage: stockage.clone(),
        })
    }

    /// Clé publique minisign des bornes (posée à l'installation).
    pub fn chemin_cle(&self) -> PathBuf {
        self.dossier.join("cle-bornes.pub")
    }

    fn paquet(&self, n: u64) -> PathBuf {
        self.dossier
            .join("paquets")
            .join(format!("barbacane-maj-{n}.bcu"))
    }

    fn cle(&self) -> Result<minisign_verify::PublicKey> {
        if !self.chemin_cle().is_file() {
            return refus(RefusMaj::CleAbsente);
        }
        minisign_verify::PublicKey::from_file(self.chemin_cle())
            .map_err(|e| anyhow::anyhow!("clé publique des bornes illisible : {e}"))
    }

    fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("etat.verrou"))
            .context("verrou des mises à jour")?;
        f.lock().context("prise du verrou des mises à jour")?;
        Ok(f)
    }

    fn lire_sans_verrou(&self) -> Result<(EtatMaj, Vec<u8>)> {
        match std::fs::read(self.dossier.join("etat.json")) {
            Ok(o) => {
                let e: EtatMaj = serde_json::from_slice(&o).context("maj/etat.json illisible")?;
                if e.version != 1 {
                    bail!("version de maj/etat.json non gérée");
                }
                Ok((e, o))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((EtatMaj::default(), Vec::new()))
            }
            Err(e) => Err(e).context("lecture de maj/etat.json"),
        }
    }

    /// Lecture cohérente (sous verrou).
    pub fn lire(&self) -> Result<EtatMaj> {
        let _v = self.verrou()?;
        Ok(self.lire_sans_verrou()?.0)
    }

    /// Transaction : rien n'est écrit si `f` échoue ; rien n'est réécrit si rien n'a changé.
    fn transaction<T>(&self, f: impl FnOnce(&mut EtatMaj) -> Result<T>) -> Result<T> {
        let _v = self.verrou()?;
        let (mut etat, avant) = self.lire_sans_verrou()?;
        let r = f(&mut etat)?;
        let apres = serde_json::to_vec_pretty(&etat)?;
        if apres != avant {
            ecrire_atomique(&self.dossier.join("etat.json"), &apres)?;
        }
        Ok(r)
    }

    /// Audite un refus de dépôt (le refus lui-même est renvoyé à l'appelant).
    fn auditer_refus<T>(&self, r: Result<T>, fichier: &Path, acteur: &str) -> Result<T> {
        if let Err(e) = &r
            && let Some(RefusDepot(m)) = e.downcast_ref::<RefusDepot>()
        {
            self.stockage.auditer(
                acteur,
                Evenement::MajRefusee {
                    sha256: sha256_fichier(fichier),
                    refus: *m,
                },
            )?;
        }
        r
    }

    /// Installe un plancher signé hors ligne (`FICHIER` et `FICHIER.minisig`). Monotone.
    pub fn installer_plancher(&self, fichier: &Path, acteur: &str) -> Result<u64> {
        let r = self.transaction(|etat| {
            let cle = self.cle()?;
            let (Some(octets), Some(sig)) = (
                lire_borne(fichier, TAILLE_PLANCHER_MAX)?,
                lire_borne(&signature_de(fichier), TAILLE_SIGNATURE_MAX as u64).unwrap_or(None),
            ) else {
                return refus(RefusMaj::NonSigne);
            };
            let sig = std::str::from_utf8(&sig)
                .ok()
                .and_then(|s| minisign_verify::Signature::decode(s).ok());
            let Some(sig) = sig else {
                return refus(RefusMaj::FormatInvalide);
            };
            if cle.verify(&octets, &sig, false).is_err() {
                return refus(RefusMaj::SignatureInvalide);
            }
            let p: Plancher = match serde_json::from_slice(&octets) {
                Ok(p @ Plancher { format: 1, .. }) if p.usage == USAGE_PLANCHER => p,
                _ => return refus(RefusMaj::FormatInvalide),
            };
            if etat.plancher.is_some_and(|actuel| p.version_min < actuel) {
                return refus(RefusMaj::PlancherEnRecul);
            }
            ecrire_atomique(&self.dossier.join("plancher.json"), &octets)?;
            std::fs::copy(
                signature_de(fichier),
                self.dossier.join("plancher.json.minisig"),
            )?;
            self.stockage.auditer(
                acteur,
                Evenement::PlancherInstalle {
                    version_min: p.version_min,
                },
            )?;
            etat.plancher = Some(p.version_min);
            Ok(p.version_min)
        });
        self.auditer_refus(r, fichier, acteur)
    }

    /// Dépose un `.bcu` (et son `.minisig`) après vérification complète.
    pub fn deposer(&self, bcu: &Path, acteur: &str) -> Result<Paquet> {
        let r = self.transaction(|etat| self.deposer_dans(etat, bcu, acteur));
        self.auditer_refus(r, bcu, acteur)
    }

    fn deposer_dans(&self, etat: &mut EtatMaj, bcu: &Path, acteur: &str) -> Result<Paquet> {
        let cle = self.cle()?;
        let chemin_sig = signature_de(bcu);
        if !chemin_sig.is_file() {
            return refus(RefusMaj::NonSigne);
        }
        let Some(texte_sig) = lire_borne(&chemin_sig, TAILLE_SIGNATURE_MAX as u64)?
            .and_then(|o| String::from_utf8(o).ok())
        else {
            return refus(RefusMaj::FormatInvalide);
        };
        let Ok(sig) = minisign_verify::Signature::decode(&texte_sig) else {
            return refus(RefusMaj::FormatInvalide);
        };
        let mut source = File::open(bcu).with_context(|| format!("{}", bcu.display()))?;
        if !source.metadata()?.is_file() {
            return refus(RefusMaj::FormatInvalide);
        }
        if source.metadata()?.len() > TAILLE_BCU_MAX {
            return refus(RefusMaj::TropGros);
        }
        // Copie, empreinte et vérification en une passe : on vérifie les octets CONSERVÉS.
        let tmp = Temporaire(
            self.dossier
                .join("paquets")
                .join(format!(".depot-{}.tmp", hex::encode(aleatoire::<8>()))),
        );
        let mut copie = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp.0)?;
        let Ok(mut verif) = cle.verify_stream(&sig) else {
            return refus(RefusMaj::SignatureInvalide);
        };
        let mut h = ring::digest::Context::new(&ring::digest::SHA256);
        let mut taille = 0u64;
        let mut tampon = vec![0u8; 1 << 16];
        loop {
            let n = source.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            taille += n as u64;
            if taille > TAILLE_BCU_MAX {
                return refus(RefusMaj::TropGros);
            }
            verif.update(&tampon[..n]);
            h.update(&tampon[..n]);
            copie.write_all(&tampon[..n])?;
        }
        copie.sync_all()?;
        drop(copie);
        if verif.finalize().is_err() {
            return refus(RefusMaj::SignatureInvalide);
        }
        // Version : commentaire de confiance (couvert par la signature globale).
        let Some(n) = sig
            .trusted_comment()
            .strip_prefix("barbacane-maj version ")
            .filter(|v| !v.is_empty() && v.len() <= 19 && v.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|v| v.parse::<u64>().ok())
        else {
            return refus(RefusMaj::FormatInvalide);
        };
        if sig.trusted_comment() != commentaire_maj(n) || !signature_valide(&texte_sig, n) {
            return refus(RefusMaj::FormatInvalide);
        }
        match etat.plancher {
            None => return refus(RefusMaj::PlancherAbsent),
            Some(p) if n < p => return refus(RefusMaj::SousLePlancher),
            Some(_) => {}
        }
        if etat.paquets.iter().any(|p| p.version_maj >= n) {
            return refus(RefusMaj::VersionNonCroissante);
        }
        let paquet = Paquet {
            version_maj: n,
            sha256: hex::encode(h.finish()),
            taille,
            depose_le: maintenant(),
        };
        let destination = self.paquet(n);
        if destination.exists() {
            bail!("{} existe déjà", destination.display());
        }
        ecrire_atomique(&signature_de(&destination), texte_sig.as_bytes())?;
        std::fs::rename(&tmp.0, &destination)?;
        self.stockage.auditer(
            acteur,
            Evenement::MajDeposee {
                version_maj: n,
                sha256: paquet.sha256.clone(),
                taille,
            },
        )?;
        etat.paquets.push(paquet.clone());
        Ok(paquet)
    }

    /// Choisit le paquet proposé aux bornes (jamais en recul, jamais sous le plancher).
    pub fn diffuser(&self, n: u64, acteur: &str) -> Result<()> {
        self.transaction(|etat| {
            if !etat.paquets.iter().any(|p| p.version_maj == n) {
                bail!("paquet {n} non déposé");
            }
            if etat.plancher.is_none_or(|p| n < p) {
                bail!("paquet {n} sous le plancher signé");
            }
            if etat.diffusee.is_some_and(|d| n < d) {
                bail!("diffusion en recul refusée (paquet {n} plus ancien que le paquet diffusé)");
            }
            self.stockage
                .auditer(acteur, Evenement::MajDiffusee { version_maj: n })?;
            etat.diffusee = Some(n);
            Ok(())
        })
    }

    /// Mise à jour à annoncer à une borne (déjà authentifiée) en réponse à son battement.
    pub fn offre(&self, uuid: &str) -> Result<Option<MiseAJourDisponible>> {
        let offre = self.transaction(|etat| {
            let Some(d) = etat
                .diffusee
                .filter(|d| etat.plancher.is_some_and(|p| *d >= p))
            else {
                return Ok(None);
            };
            let Some(p) = etat.paquets.iter().find(|p| p.version_maj == d).cloned() else {
                return Ok(None);
            };
            match etat.bornes.get(uuid) {
                Some(s) if s.version_maj > d => return Ok(None),
                Some(s)
                    if s.version_maj == d
                        && matches!(s.etat, EtatMajBorne::Appliquee | EtatMajBorne::Echec) =>
                {
                    return Ok(None);
                }
                Some(s) if s.version_maj == d => {}
                _ => {
                    self.stockage.auditer(
                        "passerelle",
                        Evenement::MajProposee {
                            borne: uuid.into(),
                            version_maj: d,
                        },
                    )?;
                    etat.bornes.insert(
                        uuid.into(),
                        SuiviBorne {
                            version_maj: d,
                            etat: EtatMajBorne::Proposee,
                            le: maintenant(),
                        },
                    );
                }
            }
            Ok(Some(p))
        })?;
        let Some(p) = offre else {
            return Ok(None);
        };
        let signature = std::fs::read_to_string(signature_de(&self.paquet(p.version_maj)))
            .context("signature du paquet diffusé")?;
        Ok(Some(MiseAJourDisponible {
            version_maj: p.version_maj,
            sha256: p.sha256,
            taille: p.taille,
            signature_minisign: signature,
        }))
    }

    /// Fichier à envoyer : seulement le paquet diffusé, à une borne à qui il est proposé.
    pub fn fichier_propose(&self, uuid: &str, n: u64) -> Result<(File, u64)> {
        let etat = self.lire()?;
        let proposee = etat.diffusee == Some(n)
            && etat.bornes.get(uuid).is_some_and(|s| {
                s.version_maj == n
                    && matches!(s.etat, EtatMajBorne::Proposee | EtatMajBorne::Telechargee)
            });
        let Some(p) = etat
            .paquets
            .iter()
            .find(|p| p.version_maj == n)
            .filter(|_| proposee)
        else {
            return Err(Refus(CodeErreur::Introuvable).into());
        };
        let f = File::open(self.paquet(n)).context("paquet diffusé")?;
        if f.metadata()?.len() != p.taille {
            bail!("paquet {n} : taille différente de celle du dépôt");
        }
        Ok((f, p.taille))
    }

    /// Dernier octet envoyé : `proposee` → `telechargee`.
    pub fn marquer_telechargee(&self, uuid: &str, n: u64) -> Result<()> {
        self.transaction(|etat| {
            if let Some(s) = etat.bornes.get_mut(uuid)
                && s.version_maj == n
                && s.etat == EtatMajBorne::Proposee
            {
                self.stockage.auditer(
                    "passerelle",
                    Evenement::MajTelechargee {
                        borne: uuid.into(),
                        version_maj: n,
                    },
                )?;
                s.etat = EtatMajBorne::Telechargee;
                s.le = maintenant();
            }
            Ok(())
        })
    }

    /// Résultat rapporté par la borne (une seule fois par version proposée).
    pub fn rapport(&self, uuid: &str, n: u64, resultat: ResultatMaj) -> Result<()> {
        self.transaction(|etat| {
            let Some(s) = etat.bornes.get_mut(uuid).filter(|s| {
                s.version_maj == n
                    && matches!(s.etat, EtatMajBorne::Proposee | EtatMajBorne::Telechargee)
            }) else {
                return Err(Refus(CodeErreur::Introuvable).into());
            };
            self.stockage.auditer(
                "passerelle",
                Evenement::MajRapportee {
                    borne: uuid.into(),
                    version_maj: n,
                    resultat: match resultat {
                        ResultatMaj::Appliquee => barbacane_audit::ResultatMaj::Appliquee,
                        ResultatMaj::Echec => barbacane_audit::ResultatMaj::Echec,
                    },
                },
            )?;
            s.etat = match resultat {
                ResultatMaj::Appliquee => EtatMajBorne::Appliquee,
                ResultatMaj::Echec => EtatMajBorne::Echec,
            };
            s.le = maintenant();
            Ok(())
        })
    }
}
