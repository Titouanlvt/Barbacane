//! File locale bornée des rapports de passage à transmettre au serveur (conception §3.1,
//! protocole §10).
//!
//! Éléments = fichiers `passage-<horodatage>-<id>-<partie>.json` du dossier d'état, déposés
//! atomiquement par admind (root), seul producteur ; l'agent, seul consommateur, les envoie
//! dans l'ordre des noms et ne retire un élément qu'après l'accusé `200` du serveur (rejeu
//! après coupure ; le serveur est idempotent). Règle : **jamais de perte** : quand la file est
//! pleine, admind refuse tout nouveau dépôt et la borne est mise hors service (aucun passage
//! sans rapport). Un élément que le serveur ne pourra jamais accepter (schéma refusé) est mis
//! de côté (`rejet-…`), jamais effacé. Aucun nom de fichier analysé n'y figure (D2) : admind
//! n'y écrit que tailles, empreintes et verdicts, et l'agent revalide chaque élément avec le
//! schéma strict du protocole avant l'envoi.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use barbacane_protocole::passage::TAILLE_RAPPORT_MAX;

use crate::coffre::ecrire_atomique;

/// Préfixe des éléments (le même qu'admind).
pub const PREFIXE: &str = "passage-";
/// Préfixe d'un élément mis de côté.
pub const PREFIXE_REJET: &str = "rejet-";

pub struct FileLocale {
    dossier: PathBuf,
    max: usize,
}

/// Nom d'élément bien formé : préfixe, `[0-9a-f-]`, `.json`, court.
fn nom_valide(nom: &str) -> bool {
    nom.len() <= 96
        && nom
            .strip_prefix(PREFIXE)
            .and_then(|n| n.strip_suffix(".json"))
            .is_some_and(|n| {
                !n.is_empty()
                    && n.bytes()
                        .all(|c| c.is_ascii_digit() || b"abcdef-".contains(&c))
            })
}

impl FileLocale {
    /// File du dossier d'état `dossier`, de capacité `max`.
    pub fn ouvrir(dossier: &Path, max: usize) -> Result<FileLocale> {
        let f = FileLocale {
            dossier: dossier.to_owned(),
            max,
        };
        f.noms()?;
        Ok(f)
    }

    /// Noms des éléments, du plus ancien au plus récent.
    fn noms(&self) -> Result<Vec<String>> {
        let mut n: Vec<String> = std::fs::read_dir(&self.dossier)
            .context("file locale")?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(PREFIXE))
            .collect();
        n.sort();
        Ok(n)
    }

    /// Nombre d'éléments ; illisible → la capacité (sûreté : la file est alors « pleine »).
    pub fn len(&self) -> usize {
        self.noms().map(|n| n.len()).unwrap_or(self.max)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn pleine(&self) -> bool {
        self.len() >= self.max
    }

    /// Premier élément : (nom, contenu). Un élément mal nommé, qui n'est pas un fichier
    /// ordinaire ou trop gros est mis de côté.
    pub fn premier(&self) -> Result<Option<(String, Vec<u8>)>> {
        for nom in self.noms()? {
            if !nom_valide(&nom) {
                self.ecarter(&nom)?;
                continue;
            }
            let lu = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(self.dossier.join(&nom))
                .and_then(|f| {
                    let m = f.metadata()?;
                    let mut o = Vec::new();
                    if m.file_type().is_file() && m.len() <= TAILLE_RAPPORT_MAX as u64 {
                        f.take(TAILLE_RAPPORT_MAX as u64 + 1).read_to_end(&mut o)?;
                    }
                    Ok(o)
                });
            match lu {
                Ok(o) if !o.is_empty() && o.len() <= TAILLE_RAPPORT_MAX => {
                    return Ok(Some((nom, o)));
                }
                _ => self.ecarter(&nom)?,
            }
        }
        Ok(None)
    }

    /// Retire un élément, une fois sa transmission confirmée par le serveur.
    pub fn retirer(&self, nom: &str) -> Result<()> {
        match std::fs::remove_file(self.dossier.join(nom)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("retrait d'un élément de la file"),
        }?;
        File::open(&self.dossier)?.sync_all()?;
        Ok(())
    }

    /// Met un élément de côté (jamais effacé) : il ne compte plus dans la file.
    pub fn ecarter(&self, nom: &str) -> Result<()> {
        eprintln!("agent : élément de file {nom:?} refusé : mis de côté");
        let reste = nom.strip_prefix(PREFIXE).unwrap_or(nom);
        std::fs::rename(
            self.dossier.join(nom),
            self.dossier.join(format!("{PREFIXE_REJET}{reste}")),
        )
        .context("mise de côté d'un élément de la file")
    }

    /// Ajout (tests ; en service, seul admind dépose). File pleine : `false`, rien n'est écrit.
    pub fn ajouter(&self, nom: &str, contenu: &[u8]) -> Result<bool> {
        if self.pleine() {
            return Ok(false);
        }
        ecrire_atomique(
            &self.dossier.join(format!("{PREFIXE}{nom}.json")),
            contenu,
            0o600,
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bornee_ordonnee_sans_perte() {
        let d = tempfile::tempdir().unwrap();
        let f = FileLocale::ouvrir(d.path(), 2).unwrap();
        assert!(f.is_empty());
        assert!(f.ajouter("0002-b", b"b").unwrap());
        assert!(f.ajouter("0001-a", b"a").unwrap());
        assert!(!f.ajouter("0003-c", b"c").unwrap(), "pleine : refus");
        assert!(f.pleine());
        let (nom, o) = f.premier().unwrap().unwrap();
        assert_eq!(
            (nom.as_str(), o.as_slice()),
            ("passage-0001-a.json", &b"a"[..])
        );
        f.retirer(&nom).unwrap();
        assert_eq!(f.premier().unwrap().unwrap().1, b"b");
        // Élément mal nommé ou trop gros : mis de côté, pas effacé.
        std::fs::write(d.path().join("passage-0000-Z.json"), b"x").unwrap();
        std::fs::write(
            d.path().join("passage-0000-0.json"),
            vec![b' '; TAILLE_RAPPORT_MAX + 1],
        )
        .unwrap();
        assert_eq!(f.premier().unwrap().unwrap().1, b"b");
        assert!(d.path().join("rejet-0000-Z.json").exists());
        assert!(d.path().join("rejet-0000-0.json").exists());
        assert_eq!(f.len(), 1);
    }
}
