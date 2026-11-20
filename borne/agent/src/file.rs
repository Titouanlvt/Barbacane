//! File locale bornée des éléments à transmettre au serveur (conception §3.1).
//!
//! Règle : **jamais de perte**. Quand la file est pleine, un ajout est REFUSÉ (l'appelant
//! le signale ; la conception prévoit alors le blocage de la borne) ; rien n'est écrasé.
//! À ce jalon (protocole v1 : enrôlement et battement seulement), aucun rapport n'y est encore
//! déposé : la file ne sert qu'au compteur `rapports_en_attente` du battement. Les rapports
//! (étape 3 de la suite) y entreront, sans nom de fichier (D2).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::coffre::ecrire_atomique;

/// Taille maximale d'un élément (octets).
pub const ELEMENT_MAX: usize = 16 * 1024;

pub struct FileLocale {
    chemin: PathBuf,
    max: usize,
    elements: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pleine;

impl FileLocale {
    /// Ouvre la file (fichier JSON du dossier d'état) ; absente = vide. Un contenu illisible ou
    /// au-delà de la capacité est une erreur (jamais ignorée silencieusement).
    pub fn ouvrir(dossier: &Path, max: usize) -> Result<FileLocale> {
        let chemin = dossier.join("file.json");
        let elements: Vec<String> = match std::fs::read(&chemin) {
            Ok(o) => {
                if o.len() > max.saturating_mul(ELEMENT_MAX + 8) + 2 {
                    bail!("file locale plus grosse que sa capacité");
                }
                serde_json::from_slice(&o).context("file locale illisible")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("lecture de la file locale"),
        };
        if elements.len() > max || elements.iter().any(|e| e.len() > ELEMENT_MAX) {
            bail!("file locale au-delà de sa capacité");
        }
        Ok(FileLocale {
            chemin,
            max,
            elements,
        })
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn pleine(&self) -> bool {
        self.elements.len() >= self.max
    }

    /// Ajoute un élément (persisté avant de rendre la main). File pleine : refus, rien perdu.
    pub fn ajouter(&mut self, element: String) -> Result<Result<(), Pleine>> {
        if element.len() > ELEMENT_MAX {
            bail!("élément trop gros pour la file locale");
        }
        if self.pleine() {
            return Ok(Err(Pleine));
        }
        self.elements.push(element);
        if let Err(e) = self.sauver() {
            self.elements.pop();
            return Err(e);
        }
        Ok(Ok(()))
    }

    /// Premier élément (le plus ancien), sans le retirer.
    pub fn premier(&self) -> Option<&str> {
        self.elements.first().map(String::as_str)
    }

    /// Retire le premier élément, une fois sa transmission confirmée par le serveur.
    pub fn retirer_premier(&mut self) -> Result<()> {
        if self.elements.is_empty() {
            return Ok(());
        }
        let e = self.elements.remove(0);
        if let Err(err) = self.sauver() {
            self.elements.insert(0, e);
            return Err(err);
        }
        Ok(())
    }

    fn sauver(&self) -> Result<()> {
        ecrire_atomique(&self.chemin, &serde_json::to_vec(&self.elements)?, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bornee_sans_perte_et_persistante() {
        let d = tempfile::tempdir().unwrap();
        let mut f = FileLocale::ouvrir(d.path(), 2).unwrap();
        assert!(f.is_empty());
        assert_eq!(f.ajouter("a".into()).unwrap(), Ok(()));
        assert_eq!(f.ajouter("b".into()).unwrap(), Ok(()));
        assert_eq!(
            f.ajouter("c".into()).unwrap(),
            Err(Pleine),
            "pleine : refus"
        );
        let mut f = FileLocale::ouvrir(d.path(), 2).unwrap();
        assert_eq!((f.len(), f.premier()), (2, Some("a")), "rien n'est perdu");
        f.retirer_premier().unwrap();
        assert_eq!(
            FileLocale::ouvrir(d.path(), 2).unwrap().premier(),
            Some("b")
        );
        assert!(f.ajouter("x".repeat(ELEMENT_MAX + 1)).is_err());
        assert!(
            FileLocale::ouvrir(d.path(), 0).is_err(),
            "capacité réduite sous le contenu"
        );
    }
}
