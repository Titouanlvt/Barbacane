//! Rapports minimaux de passage reçus des bornes (`docs/suite/protocole-agent.md` §10, D2).
//!
//! Dossier `<registre>/passages/` (0700) :
//! - `<uuid de borne>/<id>-<partie>.json` : rapport reçu (taille, SHA-256 et verdict de chaque
//!   fichier ; **jamais** de nom de fichier ni de chemin, le schéma strict du protocole
//!   l'interdit) ;
//! - `index.jsonl` : une ligne de résumé par partie reçue (ajout seul), lue par l'interface web ;
//! - `passages.verrou` : verrou exclusif des écrivains.
//!
//! Idempotent : un `(borne, id, partie)` déjà stocké n'est ni réécrit, ni réaudité.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result};
use barbacane_audit::{Evenement, ObjetPurge, VerdictPassage};
use barbacane_protocole::passage::{RapportPassage, TAILLE_RAPPORT_MAX, Verdict, uuid_valide};
use serde::{Deserialize, Serialize};

use crate::outils::ecrire_atomique;
use crate::registre::Stockage;

/// Octets lus au plus à la fin de l'index pour l'affichage.
const FIN_INDEX_MAX: u64 = 512 * 1024;

/// Résumé d'une partie reçue (une ligne de `index.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    pub borne: String,
    pub id: String,
    pub partie: u32,
    pub parties: u32,
    pub verdict: Verdict,
    pub support: String,
    pub horodatage: u64,
    pub recu_le: u64,
    pub fichiers: u64,
    pub menaces: u64,
    pub refuses: u64,
}

/// Rapport stocké : le message reçu et l'heure de réception.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stocke {
    pub recu_le: u64,
    pub rapport: RapportPassage,
}

fn verdict_audit(v: Verdict) -> VerdictPassage {
    match v {
        Verdict::Sain => VerdictPassage::Sain,
        Verdict::Menace => VerdictPassage::Menace,
        Verdict::Refuse => VerdictPassage::Refuse,
        Verdict::Erreur => VerdictPassage::Erreur,
    }
}

#[derive(Debug, Clone)]
pub struct Passages {
    dossier: PathBuf,
    stockage: Stockage,
}

impl Passages {
    pub fn ouvrir(stockage: &Stockage) -> Result<Passages> {
        let dossier = stockage.dossier().join("passages");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dossier)
            .with_context(|| format!("dossier {}", dossier.display()))?;
        Ok(Passages {
            dossier,
            stockage: stockage.clone(),
        })
    }

    fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("passages.verrou"))
            .context("verrou des passages")?;
        f.lock().context("prise du verrou des passages")?;
        Ok(f)
    }

    /// Chemin d'un rapport ; `None` si un identifiant n'a pas la forme attendue (aucun chemin
    /// construit à partir d'une donnée non contrôlée).
    fn chemin(&self, borne: &str, id: &str, partie: u32) -> Option<PathBuf> {
        (uuid_valide(borne) && uuid_valide(id))
            .then(|| self.dossier.join(borne).join(format!("{id}-{partie}.json")))
    }

    /// Reçoit un rapport (déjà décodé et contrôlé) d'une borne authentifiée. Renvoie `true` si
    /// cette partie avait déjà été reçue (rien n'est alors écrit).
    pub fn recevoir(&self, borne: &str, r: &RapportPassage, acteur: &str, t: u64) -> Result<bool> {
        let chemin = self
            .chemin(borne, &r.id, r.partie)
            .context("identifiant de borne ou de passage invalide")?;
        let _v = self.verrou()?;
        if chemin.exists() {
            return Ok(true);
        }
        let compter = |v: Verdict| r.fichiers.iter().filter(|f| f.verdict == v).count() as u64;
        // Trace d'abord : aucune réception sans audit.
        self.stockage.auditer(
            acteur,
            Evenement::RapportPassage {
                borne: borne.into(),
                passage: r.id.clone(),
                partie: r.partie,
                verdict: verdict_audit(r.verdict),
                fichiers: r.fichiers.len() as u64,
            },
        )?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(chemin.parent().context("chemin")?)?;
        ecrire_atomique(
            &chemin,
            &serde_json::to_vec(&Stocke {
                recu_le: t,
                rapport: r.clone(),
            })?,
        )?;
        let resume = Resume {
            borne: borne.into(),
            id: r.id.clone(),
            partie: r.partie,
            parties: r.parties,
            verdict: r.verdict,
            support: r.support.clone(),
            horodatage: r.horodatage,
            recu_le: t,
            fichiers: r.fichiers.len() as u64,
            menaces: compter(Verdict::Menace),
            refuses: compter(Verdict::Refuse),
        };
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dossier.join("index.jsonl"))
            .context("index des passages")?;
        writeln!(f, "{}", serde_json::to_string(&resume)?)?;
        f.sync_all()?;
        Ok(false)
    }

    /// Derniers résumés reçus, du plus récent au plus ancien (`max` au plus).
    pub fn derniers(&self, max: usize) -> Result<Vec<Resume>> {
        let mut f = match File::open(self.dossier.join("index.jsonl")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("index des passages"),
        };
        let taille = f.metadata()?.len();
        let debut = taille.saturating_sub(FIN_INDEX_MAX);
        f.seek(SeekFrom::Start(debut))?;
        let mut o = Vec::new();
        f.take(FIN_INDEX_MAX).read_to_end(&mut o)?;
        let mut lignes: Vec<&[u8]> = o.split(|c| *c == b'\n').collect();
        if debut > 0 && !lignes.is_empty() {
            lignes.remove(0); // ligne tronquée par la lecture de la fin seulement
        }
        Ok(lignes
            .into_iter()
            .rev()
            .filter_map(|l| serde_json::from_slice::<Resume>(l).ok())
            .take(max)
            .collect())
    }

    /// Nombre de parties indexées (affichage).
    pub fn nombre(&self) -> Result<u64> {
        match std::fs::read(self.dossier.join("index.jsonl")) {
            Ok(o) => Ok(o.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count() as u64),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e).context("index des passages"),
        }
    }

    /// Purge (conservation, v2.3.0) : supprime les rapports REÇUS avant `avant` (fichiers et
    /// lignes de l'index, réécrit atomiquement) et les dossiers de bornes vidés. La purge est
    /// inscrite au journal d'audit AVANT toute suppression. Renvoie le nombre de rapports
    /// supprimés. Un rapport illisible est gardé (et compté dans l'erreur affichée), jamais
    /// supprimé à l'aveugle.
    pub fn purger(&self, avant: u64, acteur: &str) -> Result<u64> {
        let _v = self.verrou()?;
        let mut fichiers = Vec::new();
        for borne in std::fs::read_dir(&self.dossier).context("dossier des passages")? {
            let borne = borne?;
            let nom = borne.file_name().to_string_lossy().into_owned();
            if !borne.file_type()?.is_dir() || !uuid_valide(&nom) {
                continue;
            }
            for r in std::fs::read_dir(borne.path())? {
                let r = r?;
                if !r.file_type()?.is_file() || !r.file_name().to_string_lossy().ends_with(".json")
                {
                    continue;
                }
                let mut o = Vec::new();
                File::open(r.path())?
                    .take(2 * TAILLE_RAPPORT_MAX as u64)
                    .read_to_end(&mut o)?;
                let s: Stocke = serde_json::from_slice(&o).with_context(|| {
                    format!("rapport de passage illisible : {}", r.path().display())
                })?;
                if s.recu_le < avant {
                    fichiers.push(r.path());
                }
            }
        }
        let index = match std::fs::read(self.dossier.join("index.jsonl")) {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("index des passages"),
        };
        let mut garde = Vec::new();
        let mut retirees = 0u64;
        for l in index.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
            match serde_json::from_slice::<Resume>(l) {
                Ok(r) if r.recu_le < avant => retirees += 1,
                _ => {
                    garde.extend_from_slice(l);
                    garde.push(b'\n');
                }
            }
        }
        if fichiers.is_empty() && retirees == 0 {
            return Ok(0);
        }
        // Trace d'abord : aucune suppression sans audit.
        self.stockage.auditer(
            acteur,
            Evenement::Purge {
                objet: ObjetPurge::Passages,
                nombre: fichiers.len() as u64,
                avant,
            },
        )?;
        ecrire_atomique(&self.dossier.join("index.jsonl"), &garde)?;
        for f in &fichiers {
            std::fs::remove_file(f).with_context(|| format!("suppression de {}", f.display()))?;
            if let Some(d) = f.parent() {
                // Dossier de la borne vidé : retiré (échoue sans dommage s'il reste un rapport).
                let _ = std::fs::remove_dir(d);
            }
        }
        Ok(fichiers.len() as u64)
    }

    /// Rapport complet d'une partie (`None` s'il est inconnu).
    pub fn detail(&self, borne: &str, id: &str, partie: u32) -> Result<Option<Stocke>> {
        let Some(chemin) = self.chemin(borne, id, partie) else {
            return Ok(None);
        };
        match File::open(&chemin) {
            Ok(f) => {
                let mut o = Vec::new();
                f.take(2 * TAILLE_RAPPORT_MAX as u64).read_to_end(&mut o)?;
                Ok(Some(
                    serde_json::from_slice(&o).context("rapport de passage illisible")?,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("rapport de passage"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbacane_protocole::VERSION;
    use barbacane_protocole::passage::FichierPassage;

    const BORNE: &str = "0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";

    fn rapport() -> RapportPassage {
        RapportPassage {
            version: VERSION,
            id: "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            horodatage: 5,
            verdict: Verdict::Menace,
            support: "c".repeat(64),
            partie: 1,
            parties: 1,
            fichiers: vec![
                FichierPassage {
                    taille: 68,
                    sha256: "a".repeat(64),
                    verdict: Verdict::Menace,
                },
                FichierPassage {
                    taille: 3,
                    sha256: "b".repeat(64),
                    verdict: Verdict::Sain,
                },
            ],
        }
    }

    #[test]
    fn idempotent_et_indexe() {
        let d = tempfile::tempdir().unwrap();
        let s = Stockage::ouvrir(&d.path().join("etat")).unwrap();
        let p = Passages::ouvrir(&s).unwrap();
        assert!(!p.recevoir(BORNE, &rapport(), "passerelle", 10).unwrap());
        assert!(p.recevoir(BORNE, &rapport(), "passerelle", 11).unwrap());
        let l = p.derniers(10).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].menaces, l[0].fichiers, l[0].recu_le), (1, 2, 10));
        let det = p.detail(BORNE, &rapport().id, 1).unwrap().unwrap();
        assert_eq!(det.rapport, rapport());
        assert!(p.detail(BORNE, "../x", 1).unwrap().is_none());
        assert!(p.recevoir("../../x", &rapport(), "passerelle", 1).is_err());
        let audit = String::from_utf8(s.journal_audit().lire().unwrap()).unwrap();
        assert_eq!(audit.matches("rapport_passage").count(), 1, "{audit}");
    }

    #[test]
    fn purge_des_rapports_anciens() {
        let d = tempfile::tempdir().unwrap();
        let s = Stockage::ouvrir(&d.path().join("etat")).unwrap();
        let p = Passages::ouvrir(&s).unwrap();
        let mut r2 = rapport();
        r2.id = "2c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into();
        let autre = "3b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";
        p.recevoir(BORNE, &rapport(), "passerelle", 100).unwrap();
        p.recevoir(BORNE, &r2, "passerelle", 300).unwrap();
        p.recevoir(autre, &rapport(), "passerelle", 150).unwrap();
        assert_eq!(p.nombre().unwrap(), 3);
        // Rien avant 100 : rien à purger, rien n'est audité.
        assert_eq!(p.purger(100, "conservation").unwrap(), 0);
        assert_eq!(p.purger(200, "conservation").unwrap(), 2);
        assert_eq!(p.nombre().unwrap(), 1);
        assert!(p.detail(BORNE, &rapport().id, 1).unwrap().is_none());
        assert!(p.detail(BORNE, &r2.id, 1).unwrap().is_some());
        assert!(
            !d.path().join("etat/passages").join(autre).exists(),
            "dossier vidé retiré"
        );
        let l = p.derniers(10).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].id, r2.id);
        let audit = String::from_utf8(s.journal_audit().lire().unwrap()).unwrap();
        assert!(
            audit.contains("\"purge\":{\"objet\":\"passages\",\"nombre\":2,\"avant\":200}"),
            "{audit}"
        );
        // Rapport altéré : purge refusée, rien supprimé.
        std::fs::write(
            d.path().join("etat/passages").join(BORNE).join("x.json"),
            b"{",
        )
        .unwrap();
        assert!(p.purger(1000, "conservation").is_err());
        assert_eq!(p.nombre().unwrap(), 1);
    }
}
