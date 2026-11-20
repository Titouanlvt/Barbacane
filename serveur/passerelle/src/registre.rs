//! Registre des bornes : jetons, demandes d'enrôlement, bornes, révocations.
//!
//! Stockage : un fichier JSON (`registre.json`, 0600) sous verrou exclusif (`registre.verrou`),
//! réécrit atomiquement à chaque transaction. Partagé par la passerelle et la commande
//! d'administration locale. Pourquoi pas SQLite : `docs/suite/protocole-agent.md` §6.
//!
//! Toutes les opérations reçoivent l'heure (`maintenant`) en paramètre : testables, et l'heure
//! du serveur est la seule référence (conception §3.11).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use barbacane_protocole::{
    ALERTE_EXPIRATION_JOURS, AccuseBattement, Battement, CodeErreur, DUREE_DEMANDE_S,
    DUREE_JETON_S, Decision, EtatBorne, PERIODE_BATTEMENT_S, SILENCE_ALERTE_S, VERSION,
    ecart_horloge,
};
use serde::{Deserialize, Serialize};

use crate::ca::{CaBornes, EntreeCrl, verifier_csr};
use crate::outils::{ecrire_atomique, sha256_hex};

/// Demandes en attente au plus (protection contre l'épuisement).
pub const DEMANDES_EN_ATTENTE_MAX: usize = 64;
/// Bornes au plus dans un registre de site.
pub const BORNES_MAX: usize = 1000;

/// Refus applicatif portant un code du protocole (les autres erreurs sont internes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refus(pub CodeErreur);

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refus : {}", self.0)
    }
}
impl std::error::Error for Refus {}

/// Code du protocole correspondant à une erreur (interne si ce n'est pas un [`Refus`]).
pub fn code_de(e: &anyhow::Error) -> CodeErreur {
    e.downcast_ref::<Refus>()
        .map(|r| r.0)
        .unwrap_or(CodeErreur::Interne)
}

fn refus<T>(code: CodeErreur) -> Result<T> {
    Err(Refus(code).into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JetonEnregistre {
    /// SHA-256 du secret : le secret lui-même n'est jamais conservé.
    pub empreinte: String,
    pub site: String,
    pub cree_le: u64,
    pub expire_le: u64,
    pub utilise_le: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StatutDemande {
    EnAttente,
    Refusee { le: u64 },
    Validee { le: u64, borne: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Demande {
    pub id: String,
    pub site: String,
    pub csr_pem: String,
    pub empreinte: String,
    pub version_logiciel: String,
    pub deposee_le: u64,
    pub expire_le: u64,
    pub statut: StatutDemande,
}

/// Motifs de révocation (politique §5) ; `remplace` : ancien certificat après renouvellement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Motif {
    Volee,
    Reformee,
    CleSuspecte,
    ChangementSite,
    FinDeVie,
    Remplace,
}

impl Motif {
    pub fn analyser(texte: &str) -> Option<Motif> {
        serde_json::from_value(serde_json::Value::String(texte.into())).ok()
    }
    /// Code RFC 5280 (`CRLReason`).
    pub fn code(self) -> u8 {
        match self {
            Motif::Volee | Motif::CleSuspecte => 1,
            Motif::ChangementSite => 3,
            Motif::Remplace => 4,
            Motif::Reformee | Motif::FinDeVie => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StatutBorne {
    Active,
    Revoquee { le: u64, motif: Motif },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Borne {
    pub uuid: String,
    pub nom: String,
    pub site: String,
    pub statut: StatutBorne,
    pub certificat_pem: String,
    pub serie: String,
    /// Certificat précédent, accepté jusqu'au premier usage du nouveau (protocole §3.5).
    pub serie_precedente: Option<String>,
    pub emis_le: u64,
    pub expire_le: u64,
    pub derniere_vue: Option<u64>,
    pub ecart_horloge_s: Option<i64>,
    pub dernier_battement: Option<Battement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub serie: String,
    pub borne: String,
    pub le: u64,
    pub motif: Motif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registre {
    pub version: u16,
    pub jetons: Vec<JetonEnregistre>,
    pub demandes: Vec<Demande>,
    pub bornes: Vec<Borne>,
    pub revocations: Vec<Revocation>,
    pub numero_crl: u64,
}

impl Default for Registre {
    fn default() -> Self {
        Registre {
            version: 1,
            jetons: Vec::new(),
            demandes: Vec::new(),
            bornes: Vec::new(),
            revocations: Vec::new(),
            numero_crl: 0,
        }
    }
}

/// Site `site-<n>` (politique §1).
pub fn site_valide(site: &str) -> bool {
    site.strip_prefix("site-")
        .is_some_and(|n| (1..=9).contains(&n.len()) && n.bytes().all(|c| c.is_ascii_digit()))
}

/// Nom de borne donné par l'administrateur : `[a-z0-9-]`, 1 à 32.
pub fn nom_valide(nom: &str) -> bool {
    (1..=32).contains(&nom.len())
        && nom
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Identité extraite du certificat client (déjà vérifié par rustls).
#[derive(Debug, Clone)]
pub struct Identite {
    pub uuid: String,
    pub site: String,
    pub serie: String,
}

impl Registre {
    /// Purge des jetons échus depuis plus d'un jour et des demandes refusées ou expirées
    /// depuis plus de 7 jours.
    fn purger(&mut self, maintenant: u64) {
        self.jetons.retain(|j| j.expire_le + 24 * 3600 > maintenant);
        self.demandes.retain(|d| {
            matches!(d.statut, StatutDemande::Validee { .. })
                || d.expire_le + 7 * 24 * 3600 > maintenant
        });
    }

    pub fn creer_jeton(&mut self, site: &str, secret: &str, maintenant: u64) -> Result<()> {
        if !site_valide(site) {
            bail!("site invalide (site-<n>)");
        }
        self.purger(maintenant);
        self.jetons.push(JetonEnregistre {
            empreinte: sha256_hex(secret.as_bytes()),
            site: site.into(),
            cree_le: maintenant,
            expire_le: maintenant + DUREE_JETON_S,
            utilise_le: None,
        });
        Ok(())
    }

    fn en_attente(&self, maintenant: u64) -> usize {
        self.demandes
            .iter()
            .filter(|d| d.statut == StatutDemande::EnAttente && d.expire_le > maintenant)
            .count()
    }

    /// Dépôt d'une demande (CSR déjà vérifiée par l'appelant). Le jeton est consommé.
    pub fn deposer(
        &mut self,
        secret: &str,
        csr_pem: &str,
        empreinte: &str,
        version_logiciel: &str,
        id: &str,
        maintenant: u64,
    ) -> Result<()> {
        let h = sha256_hex(secret.as_bytes());
        let Some(i) = self.jetons.iter().position(|j| j.empreinte == h) else {
            return refus(CodeErreur::JetonInvalide);
        };
        if self.jetons[i].utilise_le.is_some() || self.jetons[i].expire_le <= maintenant {
            return refus(CodeErreur::JetonInvalide);
        }
        if self.en_attente(maintenant) >= DEMANDES_EN_ATTENTE_MAX {
            return refus(CodeErreur::Surcharge);
        }
        self.jetons[i].utilise_le = Some(maintenant);
        let site = self.jetons[i].site.clone();
        self.demandes.push(Demande {
            id: id.into(),
            site,
            csr_pem: csr_pem.into(),
            empreinte: empreinte.into(),
            version_logiciel: version_logiciel.into(),
            deposee_le: maintenant,
            expire_le: maintenant + DUREE_DEMANDE_S,
            statut: StatutDemande::EnAttente,
        });
        Ok(())
    }

    /// État d'une demande pour le retrait : décision et, si validée, certificat PEM.
    pub fn consulter(&self, id: &str, maintenant: u64) -> Result<(Decision, Option<String>)> {
        let Some(d) = self.demandes.iter().find(|d| d.id == id) else {
            return refus(CodeErreur::DemandeInconnue);
        };
        match &d.statut {
            StatutDemande::EnAttente if d.expire_le <= maintenant => {
                refus(CodeErreur::DemandeInconnue)
            }
            StatutDemande::EnAttente => Ok((Decision::EnAttente, None)),
            StatutDemande::Refusee { .. } => Ok((Decision::Refusee, None)),
            StatutDemande::Validee { borne, .. } => {
                let b = self
                    .bornes
                    .iter()
                    .find(|b| &b.uuid == borne)
                    .context("borne d'une demande validée absente")?;
                if b.statut != StatutBorne::Active {
                    return refus(CodeErreur::DemandeInconnue);
                }
                Ok((Decision::Validee, Some(b.certificat_pem.clone())))
            }
        }
    }

    fn demande_en_attente(&mut self, id: &str, maintenant: u64) -> Result<&mut Demande> {
        let d = self
            .demandes
            .iter_mut()
            .find(|d| d.id == id)
            .context("demande inconnue")?;
        if d.statut != StatutDemande::EnAttente {
            bail!("demande déjà traitée");
        }
        if d.expire_le <= maintenant {
            bail!("demande expirée (24 h) : un nouveau jeton est nécessaire");
        }
        Ok(d)
    }

    /// Validation par un administrateur : l'empreinte affichée sur la borne doit être
    /// identique à celle de la demande. Renvoie l'uuid de la nouvelle borne.
    pub fn valider(
        &mut self,
        ca: &CaBornes,
        id: &str,
        empreinte: &str,
        nom: Option<&str>,
        uuid: &str,
        maintenant: u64,
    ) -> Result<String> {
        if self.bornes.len() >= BORNES_MAX {
            bail!("registre plein ({BORNES_MAX} bornes)");
        }
        let saisie: String = empreinte
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();
        let d = self.demande_en_attente(id, maintenant)?;
        if saisie != d.empreinte {
            bail!(
                "empreinte différente de celle de la demande : NE PAS valider, vérifier la borne"
            );
        }
        let nom = match nom {
            Some(n) if nom_valide(n) => n.to_owned(),
            Some(_) => bail!("nom invalide ([a-z0-9-], 1 à 32)"),
            None => format!("b-{}", &uuid[..8]),
        };
        let csr = verifier_csr(&d.csr_pem).map_err(|c| anyhow::anyhow!("demande : {c}"))?;
        let site = d.site.clone();
        let cert = ca.emettre(&csr, &nom, &site, uuid, maintenant)?;
        d.statut = StatutDemande::Validee {
            le: maintenant,
            borne: uuid.into(),
        };
        self.bornes.push(Borne {
            uuid: uuid.into(),
            nom,
            site,
            statut: StatutBorne::Active,
            certificat_pem: cert.pem,
            serie: cert.serie,
            serie_precedente: None,
            emis_le: cert.emis_le,
            expire_le: cert.expire_le,
            derniere_vue: None,
            ecart_horloge_s: None,
            dernier_battement: None,
        });
        Ok(uuid.into())
    }

    pub fn refuser(&mut self, id: &str, maintenant: u64) -> Result<()> {
        let d = self.demande_en_attente(id, maintenant)?;
        d.statut = StatutDemande::Refusee { le: maintenant };
        Ok(())
    }

    /// Révoque une borne (numéros de série courant et précédent). La CRL est à republier.
    pub fn revoquer(&mut self, uuid: &str, motif: Motif, maintenant: u64) -> Result<()> {
        let b = self
            .bornes
            .iter_mut()
            .find(|b| b.uuid == uuid)
            .context("borne inconnue")?;
        if b.statut != StatutBorne::Active {
            bail!("borne déjà révoquée");
        }
        b.statut = StatutBorne::Revoquee {
            le: maintenant,
            motif,
        };
        let series: Vec<String> = std::iter::once(b.serie.clone())
            .chain(b.serie_precedente.take())
            .collect();
        for serie in series {
            self.revocations.push(Revocation {
                serie,
                borne: uuid.into(),
                le: maintenant,
                motif,
            });
        }
        Ok(())
    }

    /// Entrées de CRL de toutes les révocations du registre.
    pub fn entrees_crl(&self) -> Vec<EntreeCrl> {
        self.revocations
            .iter()
            .map(|r| EntreeCrl {
                serie: r.serie.clone(),
                le: r.le,
                motif: r.motif.code(),
            })
            .collect()
    }

    /// Contrôle applicatif d'une connexion mTLS : borne connue, active, du bon site, et
    /// certificat courant (ou précédent tant que le courant n'a pas servi). Renvoie vrai si
    /// le précédent vient d'être révoqué (CRL à republier).
    pub fn authentifier(&mut self, id: &Identite, maintenant: u64) -> Result<bool> {
        let Some(b) = self.bornes.iter_mut().find(|b| b.uuid == id.uuid) else {
            return refus(CodeErreur::BorneRefusee);
        };
        if b.statut != StatutBorne::Active || b.site != id.site {
            return refus(CodeErreur::BorneRefusee);
        }
        if b.serie == id.serie {
            if let Some(ancienne) = b.serie_precedente.take() {
                self.revocations.push(Revocation {
                    serie: ancienne,
                    borne: id.uuid.clone(),
                    le: maintenant,
                    motif: Motif::Remplace,
                });
                return Ok(true);
            }
            return Ok(false);
        }
        if b.serie_precedente.as_deref() == Some(id.serie.as_str()) {
            return Ok(false);
        }
        refus(CodeErreur::BorneRefusee)
    }

    fn borne(&mut self, uuid: &str) -> Result<&mut Borne> {
        self.bornes
            .iter_mut()
            .find(|b| b.uuid == uuid)
            .context("borne absente")
    }

    /// Enregistre un battement (borne déjà authentifiée). La dernière vue et l'écart sont
    /// toujours enregistrés ; au-delà du seuil, le battement est refusé (`horloge_derivee`).
    pub fn battement(
        &mut self,
        uuid: &str,
        b: &Battement,
        maintenant: u64,
    ) -> Result<std::result::Result<AccuseBattement, CodeErreur>> {
        let (ecart, derive) = ecart_horloge(b.heure_borne, maintenant);
        let borne = self.borne(uuid)?;
        borne.derniere_vue = Some(maintenant);
        borne.ecart_horloge_s = Some(ecart);
        if derive {
            return Ok(Err(CodeErreur::HorlogeDerivee));
        }
        borne.dernier_battement = Some(b.clone());
        Ok(Ok(AccuseBattement {
            version: VERSION,
            heure_serveur: maintenant,
            ecart_s: ecart,
            prochain_battement_s: PERIODE_BATTEMENT_S,
        }))
    }

    /// Renouvellement à mi-vie (borne authentifiée par son certificat COURANT).
    pub fn renouveler(
        &mut self,
        ca: &CaBornes,
        id: &Identite,
        csr_pem: &str,
        maintenant: u64,
    ) -> Result<String> {
        let csr = verifier_csr(csr_pem).map_err(Refus)?;
        let borne = self.borne(&id.uuid)?;
        if borne.serie != id.serie {
            return refus(CodeErreur::BorneRefusee);
        }
        if maintenant < borne.emis_le + (borne.expire_le - borne.emis_le) / 2 {
            return refus(CodeErreur::RenouvellementPremature);
        }
        let cert = ca.emettre(&csr, &borne.nom, &borne.site, &borne.uuid, maintenant)?;
        borne.serie_precedente = Some(std::mem::replace(&mut borne.serie, cert.serie));
        borne.certificat_pem = cert.pem.clone();
        borne.emis_le = cert.emis_le;
        borne.expire_le = cert.expire_le;
        Ok(cert.pem)
    }
}

// ───────────────────────────── Supervision ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Alerte {
    Silence,
    Horloge,
    Expiration,
    HorsService,
}

#[derive(Debug, Clone)]
pub struct LigneSupervision {
    pub uuid: String,
    pub nom: String,
    pub site: String,
    pub active: bool,
    pub version_logiciel: Option<String>,
    pub etat: Option<EtatBorne>,
    pub derniere_vue: Option<u64>,
    pub ecart_horloge_s: Option<i64>,
    pub expire_le: u64,
    pub alertes: Vec<Alerte>,
}

impl Registre {
    /// État de supervision de chaque borne et alertes (protocole §4.3). Les bornes révoquées
    /// sont listées sans alerte.
    pub fn supervision(&self, maintenant: u64) -> Vec<LigneSupervision> {
        self.bornes
            .iter()
            .map(|b| {
                let active = b.statut == StatutBorne::Active;
                let mut alertes = Vec::new();
                if active {
                    // Jamais vue : le délai court depuis l'émission du certificat.
                    let reference = b.derniere_vue.unwrap_or(b.emis_le + 60);
                    if maintenant.saturating_sub(reference) > SILENCE_ALERTE_S {
                        alertes.push(Alerte::Silence);
                    }
                    if b.ecart_horloge_s.is_some_and(|e| {
                        e.unsigned_abs() > barbacane_protocole::ECART_HORLOGE_MAX_S
                    }) {
                        alertes.push(Alerte::Horloge);
                    }
                    if b.expire_le.saturating_sub(maintenant) < ALERTE_EXPIRATION_JOURS * 24 * 3600
                    {
                        alertes.push(Alerte::Expiration);
                    }
                    if b.dernier_battement
                        .as_ref()
                        .is_some_and(|d| d.etat == EtatBorne::HorsService)
                    {
                        alertes.push(Alerte::HorsService);
                    }
                }
                LigneSupervision {
                    uuid: b.uuid.clone(),
                    nom: b.nom.clone(),
                    site: b.site.clone(),
                    active,
                    version_logiciel: b
                        .dernier_battement
                        .as_ref()
                        .map(|d| d.version_logiciel.clone()),
                    etat: b.dernier_battement.as_ref().map(|d| d.etat),
                    derniere_vue: b.derniere_vue,
                    ecart_horloge_s: b.ecart_horloge_s,
                    expire_le: b.expire_le,
                    alertes,
                }
            })
            .collect()
    }
}

// ───────────────────────────── Stockage ───────────────────────────────────────────────────────

/// Dossier d'état du registre.
#[derive(Debug, Clone)]
pub struct Stockage {
    dossier: PathBuf,
}

impl Stockage {
    /// Ouvre (et crée en 0700 si besoin) le dossier d'état.
    pub fn ouvrir(dossier: &Path) -> Result<Stockage> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dossier)
            .with_context(|| format!("dossier du registre {}", dossier.display()))?;
        Ok(Stockage {
            dossier: dossier.to_owned(),
        })
    }

    fn fichier(&self) -> PathBuf {
        self.dossier.join("registre.json")
    }

    /// Dossier d'état (registre, journal d'audit, mises à jour).
    pub fn dossier(&self) -> &Path {
        &self.dossier
    }

    /// Journal d'audit chaîné (`audit.jsonl`, ajout seul ; `docs/suite/serveur-maj-audit.md`).
    pub fn journal_audit(&self) -> barbacane_audit::Journal {
        barbacane_audit::Journal::new(self.dossier.join("audit.jsonl"))
    }

    /// Ajoute un événement au journal d'audit, horodaté à la réception. Une erreur doit faire
    /// échouer l'opération (aucune action sans trace) : appeler DANS la transaction.
    pub fn auditer(&self, acteur: &str, evenement: barbacane_audit::Evenement) -> Result<()> {
        self.journal_audit()
            .ajouter(crate::outils::maintenant(), acteur, evenement)
            .map(|_| ())
            .context("journal d'audit")
    }

    fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("registre.verrou"))
            .context("verrou du registre")?;
        f.lock().context("prise du verrou du registre")?;
        Ok(f)
    }

    fn lire_sans_verrou(&self) -> Result<Registre> {
        match std::fs::read(self.fichier()) {
            Ok(octets) => {
                let r: Registre =
                    serde_json::from_slice(&octets).context("registre.json illisible")?;
                if r.version != 1 {
                    bail!("version du registre non gérée");
                }
                Ok(r)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registre::default()),
            Err(e) => Err(e).context("lecture du registre"),
        }
    }

    /// Lecture cohérente (sous verrou).
    pub fn lire(&self) -> Result<Registre> {
        let _verrou = self.verrou()?;
        self.lire_sans_verrou()
    }

    /// Transaction : verrou exclusif, lecture, modification, écriture atomique. Rien n'est
    /// écrit si `f` échoue.
    pub fn transaction<T>(&self, f: impl FnOnce(&mut Registre) -> Result<T>) -> Result<T> {
        let _verrou = self.verrou()?;
        let mut registre = self.lire_sans_verrou()?;
        let resultat = f(&mut registre)?;
        ecrire_atomique(&self.fichier(), &serde_json::to_vec_pretty(&registre)?)?;
        Ok(resultat)
    }

    /// Journal des opérations (ajout seul, une ligne JSON par opération). Le journal d'audit
    /// chaîné viendra à l'étape « rapports et journaux ».
    pub fn journaliser(&self, maintenant: u64, operation: &str, detail: serde_json::Value) {
        let ligne = serde_json::json!({"le": maintenant, "operation": operation, "detail": detail});
        let resultat = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dossier.join("journal.jsonl"))
            .and_then(|mut f| writeln!(f, "{ligne}"));
        if let Err(e) = resultat {
            eprintln!("registre : journal : {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_et_noms() {
        assert!(site_valide("site-1"));
        assert!(!site_valide("site-"));
        assert!(!site_valide("site-1;rm"));
        assert!(nom_valide("borne-07"));
        assert!(!nom_valide("Borne 07"));
        assert!(!nom_valide(&"a".repeat(33)));
    }

    #[test]
    fn motifs() {
        assert_eq!(Motif::analyser("cle-suspecte"), Some(Motif::CleSuspecte));
        assert_eq!(Motif::analyser("autre"), None);
    }

    #[test]
    fn jeton_usage_unique_et_expiration() {
        let mut r = Registre::default();
        r.creer_jeton("site-1", "SECRET", 1000).unwrap();
        let deposer = |r: &mut Registre, t| r.deposer("SECRET", "csr", "e", "1.0", "id", t);
        assert_eq!(
            code_de(&deposer(&mut r, 1000 + DUREE_JETON_S).unwrap_err()),
            CodeErreur::JetonInvalide
        );
        deposer(&mut r, 1001).unwrap();
        assert_eq!(
            code_de(&deposer(&mut r, 1002).unwrap_err()),
            CodeErreur::JetonInvalide
        );
        assert_eq!(
            r.consulter("id", 1003).unwrap(),
            (Decision::EnAttente, None)
        );
        assert_eq!(
            code_de(&r.consulter("id", 1001 + DUREE_DEMANDE_S).unwrap_err()),
            CodeErreur::DemandeInconnue
        );
    }

    #[test]
    fn transaction_atomique() {
        let d = tempfile::tempdir().unwrap();
        let s = Stockage::ouvrir(&d.path().join("etat")).unwrap();
        s.transaction(|r| r.creer_jeton("site-2", "X", 5)).unwrap();
        let echec: Result<()> = s.transaction(|r| {
            r.creer_jeton("site-2", "Y", 5)?;
            bail!("annulé")
        });
        assert!(echec.is_err());
        assert_eq!(s.lire().unwrap().jetons.len(), 1);
    }
}
