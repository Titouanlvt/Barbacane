//! Mises à jour centralisées (ajout compatible à la version 1, `docs/suite/protocole-agent.md` §9).
//!
//! Le serveur relaie un `.bcu` signé hors ligne ; il ne signe jamais. La borne revérifie tout
//! (signature minisign, anti-retour, manifeste) comme pour un paquet lu sur clé USB.
//! Routes servies UNIQUEMENT par l'écoute mTLS ; `/battement` reste inchangé.

use serde::{Deserialize, Serialize};

use crate::{CodeErreur, Message, controle, hex_valide};

pub mod route {
    /// Battement (corps [`crate::Battement`]) dont la réponse peut annoncer une mise à jour.
    pub const BATTEMENT: &str = "/maj/battement";
    /// Téléchargement du `.bcu` proposé (réponse `application/octet-stream`).
    pub const TELECHARGEMENT: &str = "/maj/telechargement";
    /// Résultat de l'application rapporté par la borne.
    pub const RAPPORT: &str = "/maj/rapport";
}

/// Taille maximale d'un paquet `.bcu` relayé.
pub const TAILLE_BCU_MAX: u64 = 4 << 30;
/// Taille maximale du fichier `.minisig` (environ 300 octets en pratique).
pub const TAILLE_SIGNATURE_MAX: usize = 1024;

/// Commentaire de confiance (signé) attendu pour la version `n` (`barbacane-update-prepare`).
pub fn commentaire_maj(n: u64) -> String {
    format!("barbacane-maj version {n}")
}

/// Texte d'une signature minisign : ASCII imprimable et sauts de ligne, borné, quatre lignes,
/// commentaire de confiance exactement celui de la version annoncée.
pub fn signature_valide(s: &str, version_maj: u64) -> bool {
    let lignes: Vec<&str> = s.lines().collect();
    s.len() <= TAILLE_SIGNATURE_MAX
        && s.bytes().all(|c| c == b'\n' || (b' '..=b'~').contains(&c))
        && lignes.len() == 4
        && lignes[0].starts_with("untrusted comment: ")
        && lignes[2] == format!("trusted comment: {}", commentaire_maj(version_maj))
}

/// Mise à jour proposée à la borne.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiseAJourDisponible {
    /// Version du paquet (celle de son manifeste, AAAAMMJJHHMM).
    pub version_maj: u64,
    /// SHA-256 du `.bcu`.
    pub sha256: String,
    pub taille: u64,
    /// Contenu du `.bcu.minisig`.
    pub signature_minisign: String,
}

impl MiseAJourDisponible {
    pub fn valide(&self) -> bool {
        hex_valide(&self.sha256, 64)
            && (1..=TAILLE_BCU_MAX).contains(&self.taille)
            && signature_valide(&self.signature_minisign, self.version_maj)
    }
}

/// Réponse à `POST /maj/battement` : l'accusé du battement et, le cas échéant, la mise à jour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseBattementMaj {
    pub version: u16,
    pub heure_serveur: u64,
    pub ecart_s: i64,
    pub prochain_battement_s: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mise_a_jour: Option<MiseAJourDisponible>,
}

impl Message for AccuseBattementMaj {
    const TAILLE_MAX: usize = 4 * 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            (1..=3600).contains(&self.prochain_battement_s)
                && self.mise_a_jour.as_ref().is_none_or(|m| m.valide()),
        )
    }
}

/// `POST /maj/telechargement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandeTelechargement {
    pub version: u16,
    pub version_maj: u64,
}

impl Message for DemandeTelechargement {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultatMaj {
    Appliquee,
    Echec,
}

/// `POST /maj/rapport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RapportMaj {
    pub version: u16,
    pub version_maj: u64,
    pub resultat: ResultatMaj,
}

impl Message for RapportMaj {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

/// Réponse à un rapport accepté.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseRapportMaj {
    pub version: u16,
    pub heure_serveur: u64,
}

impl Message for AccuseRapportMaj {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION, decoder, encoder};

    const SIG: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i5wAAAA==\ntrusted comment: barbacane-maj version 202611200900\nAAAA==\n";

    fn accuse(m: Option<MiseAJourDisponible>) -> AccuseBattementMaj {
        AccuseBattementMaj {
            version: VERSION,
            heure_serveur: 1,
            ecart_s: 0,
            prochain_battement_s: 60,
            mise_a_jour: m,
        }
    }

    fn maj() -> MiseAJourDisponible {
        MiseAJourDisponible {
            version_maj: 202611200900,
            sha256: "a".repeat(64),
            taille: 352,
            signature_minisign: SIG.into(),
        }
    }

    #[test]
    fn aller_retour_et_absence() {
        for a in [accuse(None), accuse(Some(maj()))] {
            assert_eq!(decoder::<AccuseBattementMaj>(&encoder(&a).unwrap()), Ok(a));
        }
        let sans = String::from_utf8(encoder(&accuse(None)).unwrap()).unwrap();
        assert!(!sans.contains("mise_a_jour"));
    }

    #[test]
    fn mise_a_jour_controlee() {
        let mut m = maj();
        m.version_maj += 1; // commentaire signé d'une autre version
        assert!(encoder(&accuse(Some(m))).is_err());
        let mut m = maj();
        m.taille = TAILLE_BCU_MAX + 1;
        assert!(encoder(&accuse(Some(m))).is_err());
        let mut m = maj();
        m.signature_minisign = SIG.replace("AAAA==", "AA\u{1b}A==");
        assert!(encoder(&accuse(Some(m))).is_err());
        let r = br#"{"version":1,"version_maj":5,"resultat":"autre"}"#;
        assert_eq!(decoder::<RapportMaj>(r), Err(CodeErreur::RequeteInvalide));
    }
}
