//! Utilisateurs et clés USB (ajout compatible à la version 1, `docs/suite/serveur-utilisateurs.md`).
//!
//! Trois routes servies UNIQUEMENT par l'écoute mTLS :
//!
//! - `POST /utilisateurs/politique` : la borne télécharge la politique de SON site (mode
//!   utilisateur, clés USB enrôlées) ; la décision sur une clé est prise par la borne avec
//!   [`PolitiqueSite::autorise`] (même code des deux côtés) ;
//! - `POST /utilisateurs/verification` : identifiant (mode Identification) ou identifiant + PIN
//!   (mode Authentification) ; la borne ne stocke JAMAIS de PIN ;
//! - `POST /utilisateurs/pin` : changement du PIN (obligatoire après une réinitialisation).
//!
//! Réponse minimale ([`ReponseVerification`]) : identique pour un identifiant inconnu, un PIN
//! faux ou un compte verrouillé (pas d'énumération, conception §3.3). Les messages portant un
//! PIN n'implémentent pas `Debug` en clair (le PIN est masqué).

use serde::{Deserialize, Serialize};

use crate::{CodeErreur, Message, TAILLE_REPONSE_MAX, controle, hex_valide};

pub mod route {
    pub const POLITIQUE: &str = "/utilisateurs/politique";
    pub const VERIFICATION: &str = "/utilisateurs/verification";
    pub const PIN: &str = "/utilisateurs/pin";
}

/// PIN : chiffres seulement, longueur minimale (conception §3.3 : 6 chiffres minimum).
pub const PIN_MIN: usize = 6;
pub const PIN_MAX: usize = 12;
/// Longueur maximale d'un identifiant d'utilisateur.
pub const IDENTIFIANT_MAX: usize = 64;
/// Clés USB enrôlées au plus par site (la politique tient dans une réponse de 16 Kio).
pub const CLES_PAR_SITE_MAX: usize = 100;
/// Longueur maximale d'un numéro de série USB.
pub const SERIE_MAX: usize = 64;

/// Identifiant d'utilisateur normalisé : `[a-z0-9._-]`, 1 à 64 (minuscules : les annuaires
/// AD/LDAP comparent sans tenir compte de la casse).
pub fn identifiant_valide(s: &str) -> bool {
    (1..=IDENTIFIANT_MAX).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// Normalise une saisie (espaces de tête et de fin retirés, minuscules ASCII) ; `None` si le
/// résultat n'est pas un identifiant valide. Utilisé par la borne avant l'envoi et par
/// l'import de l'annuaire.
pub fn normaliser_identifiant(saisie: &str) -> Option<String> {
    let s = saisie.trim().to_ascii_lowercase();
    identifiant_valide(&s).then_some(s)
}

/// PIN : 6 à 12 chiffres.
pub fn pin_valide(s: &str) -> bool {
    (PIN_MIN..=PIN_MAX).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit())
}

/// PIN choisi par l'utilisateur : valide, ni un seul chiffre répété, ni une suite (123456,
/// 987654).
pub fn pin_acceptable(s: &str) -> bool {
    if !pin_valide(s) {
        return false;
    }
    let o = s.as_bytes();
    let pas: Vec<i16> = o.windows(2).map(|w| w[1] as i16 - w[0] as i16).collect();
    let constant = pas.iter().all(|p| *p == pas[0]);
    !(constant && (-1..=1).contains(&pas[0]))
}

/// Identifiant fabricant USB (VID) : 4 hexadécimaux minuscules.
pub fn fabricant_valide(s: &str) -> bool {
    hex_valide(s, 4)
}

/// Numéro de série USB normalisé : ASCII graphique (sans espace), majuscules, 1 à 64.
pub fn serie_valide(s: &str) -> bool {
    (1..=SERIE_MAX).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_graphic() && !c.is_ascii_lowercase())
}

/// Normalise un numéro de série lu sur la clé ou saisi par l'administrateur.
pub fn normaliser_serie(saisie: &str) -> Option<String> {
    let s = saisie.trim().to_ascii_uppercase();
    serie_valide(&s).then_some(s)
}

/// Normalise un identifiant fabricant (`0781`, `0x0781`, `0781h` refusé).
pub fn normaliser_fabricant(saisie: &str) -> Option<String> {
    let s = saisie.trim().to_ascii_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s).to_owned();
    fabricant_valide(&s).then_some(s)
}

// ───────────────────────────── Politique d'un site ────────────────────────────────────────────

/// Mode utilisateur d'un site (conception §3.3, D13 : « aucun » par défaut).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeUtilisateurs {
    #[default]
    Aucun,
    Identification,
    Authentification,
}

/// Clés USB non enrôlées présentées en entrée (source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntreeNonEnrolees {
    /// Comportement de la v1 : toute clé peut être analysée.
    #[default]
    Autorisee,
    Interdite,
}

/// Sens d'utilisation d'une clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sens {
    /// Clé source (analysée).
    Entree,
    /// Clé de destination (copie des fichiers sains, blanchiment).
    Sortie,
}

/// Clé enrôlée pour le site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleUsbAutorisee {
    pub fabricant: String,
    pub serie: String,
    pub entree: bool,
    pub sortie: bool,
}

/// `POST /utilisateurs/politique` (corps `{"version":1}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandePolitique {
    pub version: u16,
}

impl Message for DemandePolitique {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

/// Politique du site de la borne (site lu dans SON certificat, jamais dans la requête).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolitiqueSite {
    pub version: u16,
    pub site: String,
    pub mode: ModeUtilisateurs,
    /// Croît à chaque changement (mode, politique, clés) : la borne ignore une politique plus
    /// ancienne que celle qu'elle applique (anti-rejeu).
    pub version_politique: u64,
    pub entree_non_enrolees: EntreeNonEnrolees,
    pub cles: Vec<CleUsbAutorisee>,
    pub heure_serveur: u64,
}

impl Message for PolitiqueSite {
    const TAILLE_MAX: usize = TAILLE_REPONSE_MAX - 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            (1..=64).contains(&self.site.len())
                && self
                    .site
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && self.cles.len() <= CLES_PAR_SITE_MAX
                && self
                    .cles
                    .iter()
                    .all(|c| fabricant_valide(&c.fabricant) && serie_valide(&c.serie)),
        )
    }
}

impl PolitiqueSite {
    /// Décision de la borne pour une clé présentée (identifiants lus sur la clé, normalisés).
    ///
    /// - Entrée : clé enrôlée avec `entree` → oui ; enrôlée sans `entree` → non (clé réservée à
    ///   la sortie) ; non enrôlée → selon `entree_non_enrolees`.
    /// - Sortie : **seulement** vers une clé enrôlée avec `sortie`.
    ///
    /// Les identifiants USB sont falsifiables (conception §2, principe 4) : cette décision sert
    /// à la gestion et à la traçabilité ; l'analyse reste toujours obligatoire.
    pub fn autorise(&self, fabricant: &str, serie: &str, sens: Sens) -> bool {
        let (Some(fabricant), Some(serie)) =
            (normaliser_fabricant(fabricant), normaliser_serie(serie))
        else {
            // Identifiants absents ou illisibles : jamais une clé enrôlée.
            return sens == Sens::Entree
                && self.entree_non_enrolees == EntreeNonEnrolees::Autorisee;
        };
        let cle = self
            .cles
            .iter()
            .find(|c| c.fabricant == fabricant && c.serie == serie);
        match (sens, cle) {
            (Sens::Entree, Some(c)) => c.entree,
            (Sens::Entree, None) => self.entree_non_enrolees == EntreeNonEnrolees::Autorisee,
            (Sens::Sortie, Some(c)) => c.sortie,
            (Sens::Sortie, None) => false,
        }
    }
}

// ───────────────────────────── Vérification d'un utilisateur ──────────────────────────────────

/// `POST /utilisateurs/verification`. `pin` absent en mode Identification, exigé en mode
/// Authentification.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandeVerification {
    pub version: u16,
    pub identifiant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

impl std::fmt::Debug for DemandeVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DemandeVerification")
            .field("identifiant", &self.identifiant)
            .field("pin", &self.pin.as_ref().map(|_| "<masqué>"))
            .finish()
    }
}

impl Message for DemandeVerification {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            identifiant_valide(&self.identifiant) && self.pin.as_deref().is_none_or(pin_valide),
        )
    }
}

/// `POST /utilisateurs/pin` : changement du PIN (mode Authentification seulement).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandeChangementPin {
    pub version: u16,
    pub identifiant: String,
    pub pin: String,
    pub nouveau_pin: String,
}

impl std::fmt::Debug for DemandeChangementPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DemandeChangementPin")
            .field("identifiant", &self.identifiant)
            .finish_non_exhaustive()
    }
}

impl Message for DemandeChangementPin {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        // Le nouveau PIN n'est contrôlé (suite, répétition) qu'après vérification de l'ancien :
        // un refus de forme ne doit pas renseigner sur le compte.
        controle(
            identifiant_valide(&self.identifiant)
                && pin_valide(&self.pin)
                && pin_valide(&self.nouveau_pin),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionUtilisateur {
    /// Utilisateur reconnu : `session` fournie.
    Acceptee,
    /// Identifiant inconnu, PIN faux, compte verrouillé, borne bloquée ou mode du site
    /// incompatible : indistinguables (sauf `attente_s` si la BORNE est bloquée).
    Refusee,
    /// PIN correct mais réinitialisé par un administrateur : le changer
    /// (`POST /utilisateurs/pin`) avant toute utilisation ; pas de session.
    PinAChanger,
}

/// Réponse à une vérification ou à un changement de PIN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReponseVerification {
    pub version: u16,
    pub decision: DecisionUtilisateur,
    /// Identifiant de session utilisateur (128 bits, hexadécimal), à joindre aux rapports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duree_session_s: Option<u32>,
    /// Présent seulement si la borne est bloquée (trop d'échecs sur cette borne).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attente_s: Option<u32>,
    pub heure_serveur: u64,
}

impl Message for ReponseVerification {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        let acceptee = self.decision == DecisionUtilisateur::Acceptee;
        controle(
            self.session.is_some() == acceptee
                && self.duree_session_s.is_some() == acceptee
                && self.session.as_deref().is_none_or(|s| hex_valide(s, 32))
                && (self.attente_s.is_none() || self.decision == DecisionUtilisateur::Refusee),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION, decoder, encoder};

    fn politique() -> PolitiqueSite {
        PolitiqueSite {
            version: VERSION,
            site: "site-1".into(),
            mode: ModeUtilisateurs::Authentification,
            version_politique: 3,
            entree_non_enrolees: EntreeNonEnrolees::Interdite,
            cles: vec![
                CleUsbAutorisee {
                    fabricant: "0781".into(),
                    serie: "4C530001".into(),
                    entree: true,
                    sortie: true,
                },
                CleUsbAutorisee {
                    fabricant: "0951".into(),
                    serie: "SORTIE-SEULE".into(),
                    entree: false,
                    sortie: true,
                },
            ],
            heure_serveur: 1,
        }
    }

    #[test]
    fn identifiants_et_pin() {
        assert_eq!(
            normaliser_identifiant("  J.Dupont "),
            Some("j.dupont".into())
        );
        assert_eq!(normaliser_identifiant("j dupont"), None);
        assert_eq!(normaliser_identifiant(""), None);
        assert_eq!(normaliser_identifiant(&"a".repeat(65)), None);
        assert!(pin_valide("123456") && pin_valide("123456789012"));
        assert!(!pin_valide("12345") && !pin_valide("1234567890123") && !pin_valide("12345a"));
        assert!(pin_acceptable("482916"));
        for faible in ["111111", "123456", "987654", "0123456789"] {
            assert!(!pin_acceptable(faible), "{faible}");
        }
        assert_eq!(normaliser_fabricant("0x0781"), Some("0781".into()));
        assert_eq!(normaliser_fabricant("781"), None);
        assert_eq!(normaliser_serie(" 4c53 "), Some("4C53".into()));
        assert_eq!(normaliser_serie("a b"), None);
    }

    #[test]
    fn decision_des_cles() {
        let mut p = politique();
        // Entrée : enrôlée → oui ; réservée à la sortie → non ; inconnue → interdite ici.
        assert!(p.autorise("0781", "4c530001", Sens::Entree));
        assert!(!p.autorise("0951", "SORTIE-SEULE", Sens::Entree));
        assert!(!p.autorise("0781", "AUTRE", Sens::Entree));
        assert!(!p.autorise("", "", Sens::Entree));
        // Sortie : seulement vers une clé enrôlée avec « sortie ».
        assert!(p.autorise("0x0781", "4C530001", Sens::Sortie));
        assert!(p.autorise("0951", "SORTIE-SEULE", Sens::Sortie));
        assert!(!p.autorise("0781", "AUTRE", Sens::Sortie));
        assert!(!p.autorise("", "", Sens::Sortie));
        p.entree_non_enrolees = EntreeNonEnrolees::Autorisee;
        assert!(p.autorise("0781", "AUTRE", Sens::Entree));
        assert!(p.autorise("", "", Sens::Entree));
        assert!(!p.autorise("0781", "AUTRE", Sens::Sortie));
    }

    #[test]
    fn messages_stricts() {
        let p = politique();
        assert_eq!(
            decoder::<PolitiqueSite>(&encoder(&p).unwrap()),
            Ok(p.clone())
        );
        let mut trop = p.clone();
        trop.cles = vec![p.cles[0].clone(); CLES_PAR_SITE_MAX + 1];
        assert!(encoder(&trop).is_err());
        let mut pleine = p;
        pleine.cles = (0..CLES_PAR_SITE_MAX)
            .map(|i| CleUsbAutorisee {
                fabricant: "0781".into(),
                serie: format!("{i:064}"),
                entree: true,
                sortie: true,
            })
            .collect();
        assert!(
            encoder(&pleine).is_ok(),
            "100 clés tiennent dans la réponse"
        );

        let r = br#"{"version":1,"identifiant":"j.dupont","pin":"123456"}"#;
        let d: DemandeVerification = decoder(r).unwrap();
        assert!(!format!("{d:?}").contains("123456"), "PIN masqué");
        let r = br#"{"version":1,"identifiant":"J.Dupont"}"#;
        assert_eq!(
            decoder::<DemandeVerification>(r),
            Err(CodeErreur::RequeteInvalide)
        );
        let r = br#"{"version":1,"identifiant":"a","pin":"12"}"#;
        assert_eq!(
            decoder::<DemandeVerification>(r),
            Err(CodeErreur::RequeteInvalide)
        );
        let c = br#"{"version":1,"identifiant":"a","pin":"482916","nouveau_pin":"739164"}"#;
        let c: DemandeChangementPin = decoder(c).unwrap();
        let texte = format!("{c:?}");
        assert!(!texte.contains("482916") && !texte.contains("739164"));

        let ok = ReponseVerification {
            version: VERSION,
            decision: DecisionUtilisateur::Acceptee,
            session: Some("ab".repeat(16)),
            duree_session_s: Some(1800),
            attente_s: None,
            heure_serveur: 1,
        };
        assert!(encoder(&ok).is_ok());
        let mut sans = ok.clone();
        sans.session = None;
        assert!(encoder(&sans).is_err());
        let refus = ReponseVerification {
            version: VERSION,
            decision: DecisionUtilisateur::Refusee,
            session: None,
            duree_session_s: None,
            attente_s: None,
            heure_serveur: 1,
        };
        let texte = String::from_utf8(encoder(&refus).unwrap()).unwrap();
        assert_eq!(
            texte, r#"{"version":1,"decision":"refusee","heure_serveur":1}"#,
            "réponse minimale"
        );
    }
}
