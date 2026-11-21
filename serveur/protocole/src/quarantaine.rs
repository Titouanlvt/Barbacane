//! Quarantaine des fichiers bloqués (ajout compatible à la version 1,
//! `docs/suite/quarantaine.md`). **Désactivée par défaut** : tant que le serveur ne l'a pas
//! activée (choix des administrateurs, par double validation), la
//! passerelle répond [`crate::CodeErreur::QuarantaineDesactivee`] AVANT de lire le corps.
//! Route servie UNIQUEMENT par l'écoute mTLS. Aucun nom de fichier (D2).

use serde::{Deserialize, Serialize};

use crate::{CodeErreur, Message, controle, hex_valide};

pub mod route {
    /// Dépôt d'un fichier bloqué (corps [`super::DepotQuarantaine`]).
    pub const DEPOT: &str = "/quarantaine/depot";
}

/// Taille maximale d'un fichier déposé (corps entier en mémoire : borné).
pub const TAILLE_FICHIER_MAX: usize = 4 << 20;

/// `POST /quarantaine/depot` : contenu en base64 standard, empreinte et taille annoncées
/// (revérifiées par le serveur).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepotQuarantaine {
    pub version: u16,
    /// SHA-256 du contenu en clair.
    pub sha256: String,
    pub taille: u64,
    pub contenu_b64: String,
}

impl Message for DepotQuarantaine {
    // base64 : 4/3 de la taille, plus l'enveloppe JSON.
    const TAILLE_MAX: usize = TAILLE_FICHIER_MAX / 3 * 4 + 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            hex_valide(&self.sha256, 64)
                && (1..=TAILLE_FICHIER_MAX as u64).contains(&self.taille)
                && self.contenu_b64.len() <= Self::TAILLE_MAX
                && self
                    .contenu_b64
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)),
        )
    }
}

/// Réponse à un dépôt accepté : identifiant de l'élément et date de purge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseQuarantaine {
    pub version: u16,
    pub element: String,
    pub expire_le: u64,
    pub heure_serveur: u64,
}

impl Message for AccuseQuarantaine {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(hex_valide(&self.element, 32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION, decoder, encoder};

    #[test]
    fn depot_controle() {
        let d = DepotQuarantaine {
            version: VERSION,
            sha256: "a".repeat(64),
            taille: 3,
            contenu_b64: "YWJj".into(),
        };
        assert_eq!(
            decoder::<DepotQuarantaine>(&encoder(&d).unwrap()),
            Ok(d.clone())
        );
        let mut m = d.clone();
        m.contenu_b64 = "YW\"Jj".into();
        assert!(encoder(&m).is_err());
        let mut m = d;
        m.taille = TAILLE_FICHIER_MAX as u64 + 1;
        assert!(encoder(&m).is_err());
    }
}
