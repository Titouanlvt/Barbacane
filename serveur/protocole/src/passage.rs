//! Rapports minimaux de passage (ajout compatible à la version 1, `docs/suite/protocole-agent.md`
//! §10, décision D2).
//!
//! Un passage (une analyse sur la borne) est résumé SANS nom de fichier ni chemin : identifiant
//! du passage, verdict, identifiant de support (SHA-256 de `vendorid:productid:série`) et, pour
//! chaque fichier, taille, SHA-256 et verdict. Le schéma strict (`deny_unknown_fields`) rend
//! impossible l'ajout d'un nom : un champ inconnu est refusé. Route servie UNIQUEMENT par
//! l'écoute mTLS. Idempotent : un `(id, partie)` déjà reçu d'une borne est accusé `200`.

use serde::{Deserialize, Serialize};

use crate::{CodeErreur, Message, controle, hex_valide};

pub mod route {
    /// Dépôt d'un rapport de passage (corps [`super::RapportPassage`]).
    pub const PASSAGE: &str = "/rapport/passage";
}

/// Corps maximal d'un rapport (1 Mio).
pub const TAILLE_RAPPORT_MAX: usize = 1 << 20;
/// Fichiers au plus par message ; au-delà, découpage en parties.
pub const FICHIERS_MAX: usize = 10_000;
/// Parties au plus par passage.
pub const PARTIES_MAX: u32 = 1000;
/// Fichiers par partie choisis par la borne : 5 000 × ~130 octets reste sous 1 Mio.
pub const FICHIERS_PAR_PARTIE: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Sain,
    /// Menace détectée (antivirus, règle YARA).
    Menace,
    /// Refusé par la politique (type, archive chiffrée, bombe…).
    Refuse,
    /// Analyse en échec : rien n'a été copié.
    Erreur,
}

impl Verdict {
    pub fn texte(self) -> &'static str {
        match self {
            Verdict::Sain => "sain",
            Verdict::Menace => "menace",
            Verdict::Refuse => "refuse",
            Verdict::Erreur => "erreur",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FichierPassage {
    pub taille: u64,
    pub sha256: String,
    pub verdict: Verdict,
}

/// UUID textuel minuscule `8-4-4-4-12`.
pub fn uuid_valide(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5
        && p.iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(x, n)| hex_valide(x, n))
}

/// `POST /rapport/passage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RapportPassage {
    pub version: u16,
    /// Identifiant du passage (UUID de l'analyse sur la borne).
    pub id: String,
    /// Fin de l'analyse (heure de la borne, secondes Unix).
    pub horodatage: u64,
    pub verdict: Verdict,
    /// SHA-256 (hexadécimal) de `vendorid:productid:numéro de série` du support source.
    pub support: String,
    /// Numéro de partie (1..=parties).
    pub partie: u32,
    pub parties: u32,
    pub fichiers: Vec<FichierPassage>,
}

impl Message for RapportPassage {
    const TAILLE_MAX: usize = TAILLE_RAPPORT_MAX;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            uuid_valide(&self.id)
                && hex_valide(&self.support, 64)
                && (1..=PARTIES_MAX).contains(&self.parties)
                && (1..=self.parties).contains(&self.partie)
                && self.fichiers.len() <= FICHIERS_MAX
                && self.fichiers.iter().all(|f| hex_valide(&f.sha256, 64)),
        )
    }
}

/// Réponse à un rapport accepté (nouveau ou déjà reçu).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseRapportPassage {
    pub version: u16,
    pub heure_serveur: u64,
    /// Vrai si ce `(id, partie)` avait déjà été reçu (rejeu après coupure).
    pub deja_recu: bool,
}

impl Message for AccuseRapportPassage {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

/// Verdict d'un passage à partir de ceux de ses fichiers (l'échec de l'analyse prime).
pub fn verdict_global(erreur: bool, fichiers: &[FichierPassage]) -> Verdict {
    if erreur {
        Verdict::Erreur
    } else if fichiers.iter().any(|f| f.verdict == Verdict::Menace) {
        Verdict::Menace
    } else if fichiers.iter().any(|f| f.verdict != Verdict::Sain) {
        Verdict::Refuse
    } else {
        Verdict::Sain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION, decoder, encoder};

    pub fn rapport(n: usize) -> RapportPassage {
        RapportPassage {
            version: VERSION,
            id: "0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            horodatage: 1_790_000_000,
            verdict: Verdict::Sain,
            support: "c".repeat(64),
            partie: 1,
            parties: 1,
            fichiers: vec![
                FichierPassage {
                    taille: u64::MAX,
                    sha256: "a".repeat(64),
                    verdict: Verdict::Refuse,
                };
                n
            ],
        }
    }

    #[test]
    fn aller_retour_et_bornes() {
        let r = rapport(3);
        assert_eq!(decoder::<RapportPassage>(&encoder(&r).unwrap()), Ok(r));
        // Pire cas d'une partie choisie par la borne : sous la taille maximale.
        assert!(encoder(&rapport(FICHIERS_PAR_PARTIE)).is_ok());
        assert!(encoder(&rapport(FICHIERS_MAX + 1)).is_err());
        let mut r = rapport(0);
        r.partie = 2;
        assert_eq!(encoder(&r), Err(CodeErreur::RequeteInvalide));
        let mut r = rapport(0);
        r.id = "0B6F4B0E-6A43-4C8E-9A51-2F7D0F3C9E11".into();
        assert!(encoder(&r).is_err());
    }

    #[test]
    fn aucun_nom_de_fichier_admis() {
        let mut v = serde_json::to_value(rapport(1)).unwrap();
        v["fichiers"][0]["nom"] = "secret.docx".into();
        let o = serde_json::to_vec(&v).unwrap();
        assert_eq!(
            decoder::<RapportPassage>(&o),
            Err(CodeErreur::RequeteInvalide)
        );
        let mut v = serde_json::to_value(rapport(1)).unwrap();
        v["chemin"] = "/a/b".into();
        let o = serde_json::to_vec(&v).unwrap();
        assert_eq!(
            decoder::<RapportPassage>(&o),
            Err(CodeErreur::RequeteInvalide)
        );
        let o = vec![b' '; TAILLE_RAPPORT_MAX + 1];
        assert_eq!(decoder::<RapportPassage>(&o), Err(CodeErreur::TropGros));
    }

    #[test]
    fn verdicts() {
        let f = |v| FichierPassage {
            taille: 1,
            sha256: "a".repeat(64),
            verdict: v,
        };
        assert_eq!(verdict_global(false, &[]), Verdict::Sain);
        assert_eq!(
            verdict_global(false, &[f(Verdict::Sain), f(Verdict::Refuse)]),
            Verdict::Refuse
        );
        assert_eq!(
            verdict_global(false, &[f(Verdict::Refuse), f(Verdict::Menace)]),
            Verdict::Menace
        );
        assert_eq!(verdict_global(true, &[f(Verdict::Menace)]), Verdict::Erreur);
    }
}
