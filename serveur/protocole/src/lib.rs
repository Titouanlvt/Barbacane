//! Protocole borne ↔ serveur Barbacane, version 1 (`docs/suite/protocole-agent.md`).
//!
//! Crate partagée par la passerelle du serveur et le futur `barbacane-agent` de la borne en
//! ligne. Tout message venant de l'autre partie est **hostile** (conception §2, principe 7) :
//!
//! - schéma strict : `deny_unknown_fields`, champ répété refusé, numéro de version exigé ;
//! - taille bornée AVANT toute analyse ([`Message::TAILLE_MAX`]) ;
//! - chaque champ texte est borné en longueur et en jeu de caractères ([`Message::valider`]) ;
//! - aucun nom de fichier n'existe dans ce protocole (D2).
//!
//! Le transport (HTTP/1.1 minimal sur TLS 1.3) est décrit dans la documentation ; cette crate ne
//! fait aucune entrée-sortie.
#![forbid(unsafe_code)]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Mises à jour centralisées (ajout compatible, protocole §9).
pub mod maj;
/// Quarantaine des fichiers bloqués (ajout compatible, désactivée par défaut,
/// `docs/suite/quarantaine.md`).
pub mod quarantaine;
/// Rapports minimaux de passage (ajout compatible, protocole §10, D2).
pub mod passage;
/// Utilisateurs et clés USB (ajout compatible, `docs/suite/serveur-utilisateurs.md`).
pub mod utilisateurs;

/// Version du protocole portée par chaque message.
pub const VERSION: u16 = 1;

/// Écart d'horloge toléré entre la borne et le serveur (conception §3.11 : 5 minutes).
pub const ECART_HORLOGE_MAX_S: u64 = 300;
/// Période des battements demandée aux bornes.
pub const PERIODE_BATTEMENT_S: u32 = 60;
/// Silence au-delà duquel la supervision signale une borne (5 battements manqués).
pub const SILENCE_ALERTE_S: u64 = 300;
/// Validité d'un jeton d'enrôlement (usage unique).
pub const DUREE_JETON_S: u64 = 3600;
/// Durée pendant laquelle une demande peut être validée par un administrateur.
pub const DUREE_DEMANDE_S: u64 = 24 * 3600;
/// Durée d'un certificat de borne (politique de certification §3).
pub const DUREE_CERTIFICAT_JOURS: u64 = 90;
/// Alerte d'expiration du certificat (conception §3.1).
pub const ALERTE_EXPIRATION_JOURS: u64 = 30;

/// En-têtes HTTP (ligne de requête comprise).
pub const TAILLE_ENTETE_MAX: usize = 4 * 1024;
/// Réponse complète (en-têtes + corps) lue par l'agent.
pub const TAILLE_REPONSE_MAX: usize = 16 * 1024;
/// Demande de certificat PKCS#10 en PEM (P-256 : environ 500 octets).
pub const TAILLE_CSR_MAX: usize = 2 * 1024;
/// Certificat ou chaîne PEM renvoyés à la borne.
pub const TAILLE_CHAINE_MAX: usize = 8 * 1024;

/// Chemins HTTP. Les routes d'enrôlement ne sont servies QUE par l'écoute d'enrôlement, les
/// autres QUE par l'écoute mTLS.
pub mod route {
    pub const DEMANDE: &str = "/enrolement/demande";
    pub const RETRAIT: &str = "/enrolement/retrait";
    pub const SANTE: &str = "/sante";
    pub const BATTEMENT: &str = "/battement";
    pub const RENOUVELLEMENT: &str = "/renouvellement";
}

/// Codes d'erreur : volontairement peu détaillés (pas d'oracle pour un attaquant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeErreur {
    /// JSON invalide, champ inconnu, absent, répété, hors bornes.
    RequeteInvalide,
    /// Corps ou en-têtes au-delà des tailles maximales.
    TropGros,
    /// Champ `version` différent de [`VERSION`].
    VersionNonGeree,
    /// Jeton inconnu, expiré ou déjà utilisé (indistinguables).
    JetonInvalide,
    /// Identifiant de demande inconnu ou demande expirée.
    DemandeInconnue,
    /// Demande de certificat illisible, signature fausse, clé non P-256.
    DemandeInvalide,
    /// Écart d'horloge supérieur à [`ECART_HORLOGE_MAX_S`] : se resynchroniser sur `heure_serveur`.
    HorlogeDerivee,
    /// Borne inconnue du registre, révoquée, ou certificat remplacé.
    BorneRefusee,
    /// Renouvellement avant la mi-vie du certificat.
    RenouvellementPremature,
    /// Route inconnue sur cette écoute.
    Introuvable,
    /// Méthode HTTP non admise.
    MethodeRefusee,
    /// Trop de demandes en attente ou de connexions.
    Surcharge,
    /// Erreur du serveur (détail seulement dans son journal).
    Interne,
    /// Quarantaine non activée sur ce serveur (défaut) : rien n'est reçu ni conservé.
    QuarantaineDesactivee,
}

impl CodeErreur {
    pub fn statut_http(self) -> u16 {
        match self {
            CodeErreur::RequeteInvalide
            | CodeErreur::VersionNonGeree
            | CodeErreur::DemandeInvalide => 400,
            CodeErreur::JetonInvalide
            | CodeErreur::BorneRefusee
            | CodeErreur::QuarantaineDesactivee => 403,
            CodeErreur::DemandeInconnue | CodeErreur::Introuvable => 404,
            CodeErreur::MethodeRefusee => 405,
            CodeErreur::HorlogeDerivee | CodeErreur::RenouvellementPremature => 409,
            CodeErreur::TropGros => 413,
            CodeErreur::Surcharge => 503,
            CodeErreur::Interne => 500,
        }
    }
}

impl std::fmt::Display for CodeErreur {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let texte = serde_json::to_string(self).unwrap_or_default();
        f.write_str(texte.trim_matches('"'))
    }
}

/// Un message du protocole : taille maximale et contrôles de contenu.
pub trait Message: Serialize + DeserializeOwned {
    /// Taille maximale du corps JSON, contrôlée avant l'analyse.
    const TAILLE_MAX: usize;
    /// Version portée par le message.
    fn version(&self) -> u16;
    /// Contrôles des champs (longueurs, jeux de caractères, cohérence).
    fn valider(&self) -> Result<(), CodeErreur>;
}

/// Décode un message reçu : taille, JSON strict, version, contrôles.
pub fn decoder<M: Message>(octets: &[u8]) -> Result<M, CodeErreur> {
    if octets.len() > M::TAILLE_MAX {
        return Err(CodeErreur::TropGros);
    }
    let message: M = serde_json::from_slice(octets).map_err(|_| CodeErreur::RequeteInvalide)?;
    if message.version() != VERSION {
        return Err(CodeErreur::VersionNonGeree);
    }
    message.valider()?;
    Ok(message)
}

/// Encode un message ; refuse (erreur interne) ce qui ne passerait pas le décodage en face.
pub fn encoder<M: Message>(message: &M) -> Result<Vec<u8>, CodeErreur> {
    message.valider()?;
    let octets = serde_json::to_vec(message).map_err(|_| CodeErreur::Interne)?;
    if octets.len() > M::TAILLE_MAX {
        return Err(CodeErreur::TropGros);
    }
    Ok(octets)
}

fn controle(ok: bool) -> Result<(), CodeErreur> {
    if ok {
        Ok(())
    } else {
        Err(CodeErreur::RequeteInvalide)
    }
}

/// Version logicielle : `[0-9A-Za-z.+~-]`, 1 à 32 caractères.
pub fn version_logiciel_valide(v: &str) -> bool {
    (1..=32).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".+~-".contains(&c))
}

/// Chaîne hexadécimale minuscule de longueur exacte.
pub fn hex_valide(v: &str, longueur: usize) -> bool {
    v.len() == longueur && v.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Bloc(s) PEM d'une étiquette donnée : en-tête, base64 strict, pied, taille bornée.
pub fn pem_valide(v: &str, etiquette: &str, blocs_max: usize, taille_max: usize) -> bool {
    if v.is_empty() || v.len() > taille_max {
        return false;
    }
    let debut = format!("-----BEGIN {etiquette}-----");
    let fin = format!("-----END {etiquette}-----");
    let mut blocs = 0;
    let mut dans_bloc = false;
    for ligne in v.lines() {
        if ligne == debut && !dans_bloc {
            dans_bloc = true;
            blocs += 1;
        } else if ligne == fin && dans_bloc {
            dans_bloc = false;
        } else if !dans_bloc
            || ligne.is_empty()
            || ligne.len() > 76
            || !ligne
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c))
        {
            return false;
        }
    }
    !dans_bloc && (1..=blocs_max).contains(&blocs)
}

/// Longueur du secret d'un jeton : 128 bits en base32 sans remplissage.
pub const LONGUEUR_SECRET: usize = 26;

/// Jeton d'enrôlement tel que saisi sur la borne : `PORT-SECRET` (D4 : le port d'enrôlement
/// tiré à l'installation y est inscrit). Seul le secret est envoyé au serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jeton {
    pub port: u16,
    /// 26 caractères base32 (`A-Z2-7`), majuscules.
    pub secret: String,
}

impl Jeton {
    /// Jeton à partir de 16 octets aléatoires.
    pub fn nouveau(port: u16, alea: &[u8; 16]) -> Jeton {
        Jeton {
            port,
            secret: data_encoding::BASE32_NOPAD.encode(alea),
        }
    }

    pub fn formater(&self) -> String {
        format!("{}-{}", self.port, self.secret)
    }

    /// Analyse une saisie : espaces ignorés, minuscules acceptées, port non nul.
    pub fn analyser(saisie: &str) -> Option<Jeton> {
        let propre: String = saisie
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let (port, secret) = propre.split_once('-')?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        secret_valide(secret).then(|| Jeton {
            port,
            secret: secret.to_owned(),
        })
    }
}

/// Secret de jeton bien formé (et décodable en exactement 16 octets).
pub fn secret_valide(s: &str) -> bool {
    s.len() == LONGUEUR_SECRET
        && data_encoding::BASE32_NOPAD
            .decode(s.as_bytes())
            .is_ok_and(|o| o.len() == 16)
}

// ───────────────────────────── Enrôlement (écoute sans certificat client) ─────────────────────

/// `POST /enrolement/demande` : borne → serveur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandeEnrolement {
    pub version: u16,
    /// Secret du jeton (sans le port).
    pub jeton: String,
    /// PKCS#10 PEM, clé ECDSA P-256 générée sur la borne (TPM) ; le serveur ignore le sujet.
    pub csr_pem: String,
    pub version_logiciel: String,
}

impl Message for DemandeEnrolement {
    const TAILLE_MAX: usize = 4 * 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            secret_valide(&self.jeton)
                && pem_valide(&self.csr_pem, "CERTIFICATE REQUEST", 1, TAILLE_CSR_MAX)
                && version_logiciel_valide(&self.version_logiciel),
        )
    }
}

/// Réponse à une demande déposée (HTTP 202).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseDemande {
    pub version: u16,
    /// Identifiant aléatoire (128 bits, hexadécimal) servant au retrait.
    pub demande_id: String,
    /// SHA-256 de la demande DER, à afficher sur la borne et à comparer par l'administrateur.
    pub empreinte: String,
    pub heure_serveur: u64,
}

impl Message for AccuseDemande {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(hex_valide(&self.demande_id, 32) && hex_valide(&self.empreinte, 64))
    }
}

/// `POST /enrolement/retrait` : la borne consulte sa demande.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsultationDemande {
    pub version: u16,
    pub demande_id: String,
}

impl Message for ConsultationDemande {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(hex_valide(&self.demande_id, 32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    EnAttente,
    Refusee,
    Validee,
}

/// État d'une demande. `validee` : certificat, chaîne (certificat + CA bornes) et port de
/// service mTLS ; sinon ces champs sont absents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtatDemande {
    pub version: u16,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificat_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chaine_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_service: Option<u16>,
    pub heure_serveur: u64,
}

impl Message for EtatDemande {
    const TAILLE_MAX: usize = TAILLE_REPONSE_MAX;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        match (
            self.decision,
            &self.certificat_pem,
            &self.chaine_pem,
            self.port_service,
        ) {
            (Decision::Validee, Some(c), Some(ch), Some(p)) => controle(
                p != 0
                    && pem_valide(c, "CERTIFICATE", 1, TAILLE_CHAINE_MAX)
                    && pem_valide(ch, "CERTIFICATE", 4, TAILLE_CHAINE_MAX),
            ),
            (Decision::EnAttente | Decision::Refusee, None, None, None) => Ok(()),
            _ => Err(CodeErreur::RequeteInvalide),
        }
    }
}

// ───────────────────────────── Service (écoute mTLS) ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtatBorne {
    EnService,
    /// Bloquée (serveur injoignable trop longtemps, file pleine, intégrité…).
    HorsService,
    /// Mise à jour ou administration locale en cours.
    Maintenance,
}

/// `POST /battement` : état de la borne, toutes les [`PERIODE_BATTEMENT_S`] secondes.
/// Aucun nom de fichier, aucun identifiant d'utilisateur (D2, minimisation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Battement {
    pub version: u16,
    /// Heure de la borne (secondes Unix, UTC).
    pub heure_borne: u64,
    pub version_logiciel: String,
    pub etat: EtatBorne,
    /// Âge de la base de signatures antivirales, en secondes.
    pub age_signatures_s: u64,
    pub espace_libre_octets: u64,
    /// Rapports en file locale non encore transmis.
    pub rapports_en_attente: u32,
}

impl Message for Battement {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(version_logiciel_valide(&self.version_logiciel))
    }
}

/// Réponse à un battement accepté.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuseBattement {
    pub version: u16,
    /// Heure de référence du site (secondes Unix, UTC).
    pub heure_serveur: u64,
    /// `heure_borne - heure_serveur` mesuré à la réception, en secondes.
    pub ecart_s: i64,
    pub prochain_battement_s: u32,
}

impl Message for AccuseBattement {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle((1..=3600).contains(&self.prochain_battement_s))
    }
}

/// `POST /renouvellement` : nouvelle demande signée par la nouvelle clé (TPM), présentée sur
/// une connexion authentifiée par le certificat courant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemandeRenouvellement {
    pub version: u16,
    pub csr_pem: String,
}

impl Message for DemandeRenouvellement {
    const TAILLE_MAX: usize = 4 * 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(pem_valide(
            &self.csr_pem,
            "CERTIFICATE REQUEST",
            1,
            TAILLE_CSR_MAX,
        ))
    }
}

/// Nouveau certificat (renouvellement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReponseCertificat {
    pub version: u16,
    pub certificat_pem: String,
    pub chaine_pem: String,
    pub heure_serveur: u64,
}

impl Message for ReponseCertificat {
    const TAILLE_MAX: usize = TAILLE_REPONSE_MAX;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(
            pem_valide(&self.certificat_pem, "CERTIFICATE", 1, TAILLE_CHAINE_MAX)
                && pem_valide(&self.chaine_pem, "CERTIFICATE", 4, TAILLE_CHAINE_MAX),
        )
    }
}

/// `GET /sante` (contrôle de la liaison mTLS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sante {
    pub version: u16,
    pub etat: String,
    /// Nom commun du certificat présenté.
    pub borne: String,
    pub heure_serveur: u64,
}

impl Message for Sante {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        controle(self.etat == "ok" && self.borne.len() <= 128)
    }
}

/// Toute réponse d'erreur. `heure_serveur` toujours présente : l'agent s'en sert pour se
/// resynchroniser (le canal est authentifié par la CA serveur épinglée).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReponseErreur {
    pub version: u16,
    pub code: CodeErreur,
    pub heure_serveur: u64,
}

impl Message for ReponseErreur {
    const TAILLE_MAX: usize = 1024;
    fn version(&self) -> u16 {
        self.version
    }
    fn valider(&self) -> Result<(), CodeErreur> {
        Ok(())
    }
}

/// Écart d'horloge `heure_borne - heure_serveur` et verdict (vrai = au-delà du seuil).
pub fn ecart_horloge(heure_borne: u64, heure_serveur: u64) -> (i64, bool) {
    let ecart = (heure_borne as i128 - heure_serveur as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    (ecart, ecart.unsigned_abs() > ECART_HORLOGE_MAX_S)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBAzCBqgIBADAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END CERTIFICATE REQUEST-----\n";

    fn demande() -> DemandeEnrolement {
        DemandeEnrolement {
            version: VERSION,
            jeton: Jeton::nouveau(43117, &[7; 16]).secret,
            csr_pem: CSR.into(),
            version_logiciel: "2.0.0~dev".into(),
        }
    }

    #[test]
    fn aller_retour() {
        let d = demande();
        let octets = encoder(&d).unwrap();
        assert_eq!(decoder::<DemandeEnrolement>(&octets).unwrap(), d);
    }

    #[test]
    fn champ_inconnu_repete_ou_absent_refuse() {
        let texte = String::from_utf8(encoder(&demande()).unwrap()).unwrap();
        let inconnu = texte.replacen('{', "{\"nom_fichier\":\"secret.doc\",", 1);
        assert_eq!(
            decoder::<DemandeEnrolement>(inconnu.as_bytes()),
            Err(CodeErreur::RequeteInvalide)
        );
        let repete = texte.replacen('{', "{\"version\":1,", 1);
        assert_eq!(
            decoder::<DemandeEnrolement>(repete.as_bytes()),
            Err(CodeErreur::RequeteInvalide)
        );
        assert_eq!(
            decoder::<DemandeEnrolement>(b"{\"version\":1}"),
            Err(CodeErreur::RequeteInvalide)
        );
        assert_eq!(
            decoder::<DemandeEnrolement>(b"pas du json"),
            Err(CodeErreur::RequeteInvalide)
        );
    }

    #[test]
    fn version_et_taille() {
        let mut d = demande();
        d.version = 2;
        let octets = serde_json::to_vec(&d).unwrap();
        assert_eq!(
            decoder::<DemandeEnrolement>(&octets),
            Err(CodeErreur::VersionNonGeree)
        );
        let gros = vec![b' '; DemandeEnrolement::TAILLE_MAX + 1];
        assert_eq!(
            decoder::<DemandeEnrolement>(&gros),
            Err(CodeErreur::TropGros)
        );
    }

    #[test]
    fn champs_bornes() {
        let mut d = demande();
        d.version_logiciel = "1.0\u{202e}".into();
        assert!(d.valider().is_err());
        let mut d = demande();
        d.version_logiciel = "x".repeat(33);
        assert!(d.valider().is_err());
        let mut d = demande();
        d.jeton = "B".repeat(26); // bits de remplissage non nuls : refusé
        assert!(d.valider().is_err());
        let mut d = demande();
        d.csr_pem = CSR.replace("BEGIN CERTIFICATE REQUEST", "BEGIN PRIVATE KEY");
        assert!(d.valider().is_err());
        let mut d = demande();
        d.csr_pem = format!("{CSR}{CSR}");
        assert!(d.valider().is_err(), "deux demandes dans un seul champ");
    }

    #[test]
    fn jeton_saisie() {
        let j = Jeton::nouveau(43117, &[0xA5; 16]);
        let texte = j.formater();
        assert_eq!(Jeton::analyser(&texte), Some(j.clone()));
        let saisie = format!(" {} ", texte.to_ascii_lowercase().replace('-', " - "));
        assert_eq!(Jeton::analyser(&saisie), Some(j));
        assert_eq!(Jeton::analyser("0-AAAA"), None);
        assert_eq!(Jeton::analyser("43117"), None);
    }

    #[test]
    fn etat_demande_coherent() {
        let mut e = EtatDemande {
            version: VERSION,
            decision: Decision::EnAttente,
            certificat_pem: None,
            chaine_pem: None,
            port_service: None,
            heure_serveur: 1,
        };
        assert!(e.valider().is_ok());
        e.decision = Decision::Validee;
        assert!(e.valider().is_err(), "validée sans certificat");
        let octets = serde_json::to_vec(&e).unwrap();
        assert!(decoder::<EtatDemande>(&octets).is_err());
    }

    #[test]
    fn horloge() {
        assert_eq!(ecart_horloge(1000, 1000), (0, false));
        assert_eq!(ecart_horloge(1300, 1000), (300, false));
        assert_eq!(ecart_horloge(1301, 1000), (301, true));
        assert_eq!(ecart_horloge(0, 1000), (-1000, true));
        assert!(ecart_horloge(u64::MAX, 0).1);
    }

    #[test]
    fn codes_erreur() {
        assert_eq!(CodeErreur::HorlogeDerivee.to_string(), "horloge_derivee");
        assert_eq!(CodeErreur::TropGros.statut_http(), 413);
    }
}
