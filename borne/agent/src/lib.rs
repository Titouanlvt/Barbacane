//! `barbacane-agent` : seul processus réseau de la borne EN LIGNE (profil `en-ligne` de
//! `build-iso.sh`, décision D12 ; absent de la borne hors ligne).
//!
//! Jalon « enrôlement + battement » du protocole v1 (`docs/suite/protocole-agent.md`) :
//!
//! - **enrôlement** : jeton saisi par l'administrateur (fichier `jeton` du dossier d'état),
//!   clé P-256 générée localement ([`coffre`]), demande PKCS#10, attente de la validation
//!   humaine (empreinte publiée dans `etat.json` pour l'affichage), retrait du certificat ;
//! - **service** : mTLS vers la passerelle, CA serveur **épinglée** (empreinte dans l'ISO),
//!   battement périodique, renouvellement à mi-vie ;
//! - **mode dégradé** : serveur injoignable → nouvel essai espacé ; la borne continue de
//!   fonctionner comme la v1 (l'agent ne commande rien) ; file locale bornée ([`file`]) ;
//! - **borne refusée** (révoquée, certificat expiré) : plus aucune connexion jusqu'à un nouvel
//!   enrôlement décidé par l'administrateur.
//! - **mises à jour** ([`maj`]) : battement `/maj/battement` ; le `.bcu` proposé est téléchargé
//!   (mTLS), son empreinte contrôlée, puis déposé pour admind, qui seul le vérifie (signature)
//!   et l'applique sur décision de l'administrateur local ; résultat rapporté au serveur.
//!
//! Aucune donnée ni nom de fichier n'est envoyé (D2) : le battement ne porte que des compteurs.
#![forbid(unsafe_code)]

pub mod coffre;
pub mod config;
pub mod file;
pub mod maj;
pub mod transport;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use barbacane_protocole::maj::{
    AccuseBattementMaj, AccuseRapportMaj, DemandeTelechargement, MiseAJourDisponible, RapportMaj,
    route as route_maj,
};
use barbacane_protocole::{
    AccuseDemande, Battement, CodeErreur, ConsultationDemande, Decision, DemandeEnrolement,
    DemandeRenouvellement, EtatBorne, EtatDemande, Jeton, Message, ReponseCertificat,
    ReponseErreur, VERSION, decoder, encoder, route,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use crate::coffre::{Coffre, Emplacement, ecrire_atomique};
use crate::config::Config;
use crate::file::FileLocale;
use crate::maj::{DossierMaj, EtatMiseAJour, MARGE_ESPACE};
use crate::transport::{Client, Echec, Identite, Telechargement};

/// Version annoncée au serveur.
pub const VERSION_LOGICIEL: &str = env!("CARGO_PKG_VERSION");
/// Surveillance du fichier de jeton quand il n'y a rien d'autre à faire.
pub const PERIODE_JETON: Duration = Duration::from_secs(5);
/// Taille maximale du fichier de jeton (port + 26 caractères + espaces).
const JETON_MAX: u64 = 256;

/// Mode de l'agent, publié dans `etat.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Aucun certificat, aucune demande : en attente d'un jeton.
    NonEnrolee,
    /// Demande déposée : l'administrateur doit comparer l'empreinte et valider.
    AttenteValidation,
    /// Dernier battement accepté.
    Connectee,
    /// Serveur injoignable (ou non authentifié) : la borne fonctionne comme la v1.
    Degradee,
    /// Le serveur refuse la borne (révoquée, certificat expiré) : nouvel enrôlement requis.
    Refusee,
}

/// État lisible par l'interface et l'administration locale (aucun secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtatPublic {
    pub mode: Mode,
    /// Empreinte de la demande en cours (SHA-256 du DER), à comparer par l'administrateur.
    pub empreinte: Option<String>,
    /// Dernier échange réussi avec le serveur (heure de la borne).
    pub derniere_liaison: Option<u64>,
    /// `heure_borne - heure_serveur` mesuré au dernier échange.
    pub ecart_horloge_s: Option<i64>,
    /// Vrai si le serveur a refusé le dernier battement pour dérive d'horloge (> 300 s).
    pub horloge_derivee: bool,
    pub certificat_expire_le: Option<u64>,
    pub rapports_en_attente: usize,
    pub file_pleine: bool,
    pub message: String,
    /// Mise à jour proposée par le serveur : téléchargée et contrôlée (`prete`), ou résultat de
    /// l'application en attente de transmission. Jamais appliquée par l'agent.
    #[serde(default)]
    pub mise_a_jour: Option<EtatMiseAJour>,
}

impl Default for EtatPublic {
    fn default() -> EtatPublic {
        EtatPublic {
            mode: Mode::NonEnrolee,
            empreinte: None,
            derniere_liaison: None,
            ecart_horloge_s: None,
            horloge_derivee: false,
            certificat_expire_le: None,
            rapports_en_attente: 0,
            file_pleine: false,
            message: String::new(),
            mise_a_jour: None,
        }
    }
}

/// Demande en cours, persistée (survit à un redémarrage).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attente {
    demande_id: String,
    empreinte: String,
}

/// Heure de la borne (secondes Unix, UTC).
pub fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Début et fin de validité du certificat de tête d'une chaîne.
pub fn validite(cert: &CertificateDer<'_>) -> Result<(u64, u64)> {
    let (_, c) = x509_parser::parse_x509_certificate(cert)
        .map_err(|e| anyhow::anyhow!("certificat : {e}"))?;
    let v = c.validity();
    let debut = u64::try_from(v.not_before.timestamp()).unwrap_or(0);
    let fin = u64::try_from(v.not_after.timestamp()).unwrap_or(0);
    Ok((debut, fin))
}

/// Clé publique (SubjectPublicKeyInfo DER) du certificat de tête.
fn cle_publique(cert: &CertificateDer<'_>) -> Result<Vec<u8>> {
    let (_, c) = x509_parser::parse_x509_certificate(cert)
        .map_err(|e| anyhow::anyhow!("certificat : {e}"))?;
    Ok(c.public_key().raw.to_vec())
}

fn lire_chaine(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chaine = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .context("chaîne illisible")?;
    if chaine.is_empty() {
        bail!("chaîne vide");
    }
    Ok(chaine)
}

/// Statut HTTP + corps : message attendu ou code d'erreur du protocole.
enum Reponse<M> {
    Ok(M),
    Erreur(CodeErreur),
}

fn interpreter<M: Message>(statut: u16, attendu: u16, corps: &[u8]) -> Result<Reponse<M>> {
    if statut == attendu {
        return Ok(Reponse::Ok(decoder::<M>(corps).map_err(|c| {
            anyhow::anyhow!("réponse du serveur refusée ({c})")
        })?));
    }
    let e: ReponseErreur =
        decoder(corps).map_err(|c| anyhow::anyhow!("erreur illisible du serveur ({c})"))?;
    Ok(Reponse::Erreur(e.code))
}

pub struct Agent<C: Coffre> {
    pub config: Config,
    coffre: C,
    client: Client,
    file: FileLocale,
    /// Échecs consécutifs de liaison (espacement des essais).
    echecs: u32,
    pub etat: EtatPublic,
    /// Dossier des signatures antivirales (âge annoncé dans le battement).
    pub signatures: PathBuf,
    /// Espace de travail (espace libre annoncé dans le battement).
    pub travail: PathBuf,
}

impl<C: Coffre> Agent<C> {
    /// Contrôles au démarrage : CA épinglée conforme, dossiers, file locale lisible.
    pub fn nouveau(config: Config, coffre: C) -> Result<Agent<C>> {
        let ca = transport::charger_ca(&config.ca_serveur, &config.empreinte_ca_serveur)?;
        let client = Client::nouveau(ca, &config.nom_serveur)?;
        std::fs::create_dir_all(&config.etat)
            .with_context(|| format!("dossier d'état {}", config.etat.display()))?;
        let file = FileLocale::ouvrir(&config.etat, config.file_max)?;
        let mut a = Agent {
            config,
            coffre,
            client,
            file,
            echecs: 0,
            etat: EtatPublic::default(),
            signatures: "/var/lib/clamav".into(),
            travail: "/var/lib/barbacane/travail".into(),
        };
        a.reparer_renouvellement()?;
        Ok(a)
    }

    fn chemin(&self, nom: &str) -> PathBuf {
        self.config.etat.join(nom)
    }

    fn supprimer(&self, nom: &str) -> Result<()> {
        match std::fs::remove_file(self.chemin(nom)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("suppression de {nom}")),
        }
    }

    fn adresse_enrolement(&self) -> SocketAddr {
        SocketAddr::new(self.config.adresse.into(), self.config.port_enrolement)
    }

    fn adresse_service(&self) -> SocketAddr {
        SocketAddr::new(self.config.adresse.into(), self.config.port_service)
    }

    /// Un cycle complet ; renvoie le délai avant le suivant. Ne panique pas, ne s'arrête pas :
    /// toute erreur est publiée dans l'état et l'agent réessaie.
    pub fn cycle(&mut self) -> Duration {
        let attente = match self.etape() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("agent : {e:#}");
                self.etat.message = format!("{e:#}");
                self.reessai()
            }
        };
        self.etat.rapports_en_attente = self.file.len();
        self.etat.file_pleine = self.file.pleine();
        self.etat.mise_a_jour = DossierMaj::nouveau(&self.config.etat).etat();
        if let Err(e) = self.publier_etat() {
            eprintln!("agent : publication de l'état : {e:#}");
        }
        attente
    }

    /// Écrit `etat.json` (dossier d'exécution, lisible par l'interface : aucun secret).
    pub fn publier_etat(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config.execution)?;
        ecrire_atomique(
            &self.config.execution.join("etat.json"),
            &serde_json::to_vec_pretty(&self.etat)?,
            0o644,
        )
    }

    /// Espacement des essais : 5 s, 10 s, 20 s… jusqu'à `reessai_max_s`.
    fn reessai(&mut self) -> Duration {
        self.echecs = self.echecs.saturating_add(1);
        let s = 5u64.saturating_mul(1 << self.echecs.min(16).saturating_sub(1));
        Duration::from_secs(s.min(self.config.reessai_max_s))
    }

    fn etape(&mut self) -> Result<Duration> {
        if let Some(jeton) = self.lire_jeton()? {
            return self.enroler(jeton);
        }
        if self.chemin("refusee").exists() {
            self.etat.mode = Mode::Refusee;
            self.etat.message = std::fs::read_to_string(self.chemin("refusee")).unwrap_or_default();
            return Ok(PERIODE_JETON);
        }
        if self.coffre.existe(Emplacement::Courante) && self.chemin("chaine.pem").exists() {
            return self.service();
        }
        if self.chemin("attente.json").exists() {
            return self.retrait();
        }
        self.etat = EtatPublic {
            message: "borne non enrôlée : en attente d'un jeton d'enrôlement".into(),
            ..EtatPublic::default()
        };
        Ok(PERIODE_JETON)
    }

    /// Jeton déposé par l'administrateur : fichier ordinaire (pas de lien), petit, analysé.
    /// Il n'est supprimé qu'après une réponse définitive du serveur.
    fn lire_jeton(&self) -> Result<Option<Jeton>> {
        let chemin = self.chemin("jeton");
        let meta = match std::fs::symlink_metadata(&chemin) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("fichier de jeton"),
        };
        if !meta.file_type().is_file() || meta.len() > JETON_MAX {
            self.supprimer("jeton")?;
            bail!("fichier de jeton refusé (pas un fichier ordinaire, ou trop gros) : supprimé");
        }
        let texte = std::fs::read_to_string(&chemin).context("lecture du jeton")?;
        match Jeton::analyser(&texte) {
            Some(j) => Ok(Some(j)),
            None => {
                self.supprimer("jeton")?;
                bail!("jeton mal formé (attendu PORT-SECRET) : supprimé");
            }
        }
    }

    /// Dépôt d'une demande avec un nouveau jeton (nouvelle clé ; remplace toute identité).
    fn enroler(&mut self, jeton: Jeton) -> Result<Duration> {
        if jeton.port != self.config.port_enrolement {
            self.supprimer("jeton")?;
            bail!(
                "jeton émis pour le port {} ; la borne est configurée pour le port {} (ISO d'un autre serveur ?) : jeton supprimé",
                jeton.port,
                self.config.port_enrolement
            );
        }
        let (csr, _) = self.coffre.generer(Emplacement::Attente)?;
        let corps = encoder(&DemandeEnrolement {
            version: VERSION,
            jeton: jeton.secret,
            csr_pem: csr,
            version_logiciel: VERSION_LOGICIEL.into(),
        })
        .map_err(|c| anyhow::anyhow!("demande : {c}"))?;
        let (statut, reponse) = match self.client.requete(
            self.adresse_enrolement(),
            None,
            "POST",
            route::DEMANDE,
            &corps,
        ) {
            Ok(r) => r,
            Err(e) => return Ok(self.liaison_perdue(e, Mode::NonEnrolee)),
        };
        self.supprimer("jeton")?;
        match interpreter::<AccuseDemande>(statut, 202, &reponse)? {
            Reponse::Ok(a) => {
                // Nouvel enrôlement : l'ancienne identité (révoquée ou remplacée) disparaît.
                for f in ["refusee", "chaine.pem"] {
                    self.supprimer(f)?;
                }
                self.coffre.supprimer(Emplacement::Courante)?;
                self.coffre.supprimer(Emplacement::Nouvelle)?;
                let attente = Attente {
                    demande_id: a.demande_id,
                    empreinte: a.empreinte.clone(),
                };
                ecrire_atomique(
                    &self.chemin("attente.json"),
                    &serde_json::to_vec(&attente)?,
                    0o600,
                )?;
                eprintln!(
                    "agent : demande déposée ; empreinte à comparer par l'administrateur : {}",
                    a.empreinte
                );
                self.echecs = 0;
                self.etat = EtatPublic {
                    mode: Mode::AttenteValidation,
                    empreinte: Some(a.empreinte),
                    derniere_liaison: Some(maintenant()),
                    ecart_horloge_s: Some(
                        barbacane_protocole::ecart_horloge(maintenant(), a.heure_serveur).0,
                    ),
                    message: "demande déposée : en attente de validation par l'administrateur"
                        .into(),
                    ..EtatPublic::default()
                };
                Ok(Duration::from_secs(self.config.periode_retrait_s))
            }
            Reponse::Erreur(code) => {
                self.coffre.supprimer(Emplacement::Attente)?;
                bail!("demande refusée par le serveur : {code}")
            }
        }
    }

    /// Consultation de la demande en attente.
    fn retrait(&mut self) -> Result<Duration> {
        let attente: Attente = serde_json::from_slice(&std::fs::read(self.chemin("attente.json"))?)
            .context("demande en cours illisible")?;
        self.etat.mode = Mode::AttenteValidation;
        self.etat.empreinte = Some(attente.empreinte.clone());
        let corps = encoder(&ConsultationDemande {
            version: VERSION,
            demande_id: attente.demande_id.clone(),
        })
        .map_err(|c| anyhow::anyhow!("consultation : {c}"))?;
        let (statut, reponse) = match self.client.requete(
            self.adresse_enrolement(),
            None,
            "POST",
            route::RETRAIT,
            &corps,
        ) {
            Ok(r) => r,
            Err(e) => return Ok(self.liaison_perdue(e, Mode::AttenteValidation)),
        };
        self.echecs = 0;
        self.etat.derniere_liaison = Some(maintenant());
        let abandon = |agent: &mut Self, message: &str| -> Result<Duration> {
            agent.supprimer("attente.json")?;
            agent.coffre.supprimer(Emplacement::Attente)?;
            eprintln!("agent : {message}");
            agent.etat = EtatPublic {
                message: message.into(),
                ..EtatPublic::default()
            };
            Ok(PERIODE_JETON)
        };
        let e: EtatDemande = match interpreter(statut, 200, &reponse)? {
            Reponse::Ok(e) => e,
            Reponse::Erreur(CodeErreur::DemandeInconnue) => {
                return abandon(
                    self,
                    "demande inconnue ou expirée : nouveau jeton nécessaire",
                );
            }
            Reponse::Erreur(code) => bail!("consultation refusée : {code}"),
        };
        self.etat.ecart_horloge_s =
            Some(barbacane_protocole::ecart_horloge(maintenant(), e.heure_serveur).0);
        match e.decision {
            Decision::EnAttente => {
                self.etat.message =
                    "demande déposée : en attente de validation par l'administrateur".into();
                Ok(Duration::from_secs(self.config.periode_retrait_s))
            }
            Decision::Refusee => abandon(self, "demande refusée par l'administrateur"),
            Decision::Validee => {
                let (Some(chaine), Some(port)) = (e.chaine_pem, e.port_service) else {
                    bail!("certificat absent de la réponse");
                };
                if port != self.config.port_service {
                    bail!(
                        "le serveur annonce le port de service {port}, la borne est configurée pour {} : certificat non installé",
                        self.config.port_service
                    );
                }
                let certs = lire_chaine(chaine.as_bytes())?;
                if cle_publique(&certs[0])? != self.coffre.publique(Emplacement::Attente)? {
                    bail!("le certificat reçu ne correspond pas à la clé de la borne : refusé");
                }
                ecrire_atomique(&self.chemin("chaine.pem"), chaine.as_bytes(), 0o600)?;
                self.coffre
                    .deplacer(Emplacement::Attente, Emplacement::Courante)?;
                self.supprimer("attente.json")?;
                eprintln!("agent : certificat de la borne installé");
                self.etat.empreinte = None;
                self.etat.message = "certificat installé".into();
                Ok(Duration::ZERO)
            }
        }
    }

    /// Fin de renouvellement interrompue (coupure entre l'écriture de la chaîne et celle de la
    /// clé) : terminée au démarrage si la nouvelle clé correspond à la chaîne.
    fn reparer_renouvellement(&mut self) -> Result<()> {
        if !self.coffre.existe(Emplacement::Nouvelle) {
            return Ok(());
        }
        let Ok(pem) = std::fs::read(self.chemin("chaine.pem")) else {
            return self.coffre.supprimer(Emplacement::Nouvelle);
        };
        let chaine = lire_chaine(&pem)?;
        if cle_publique(&chaine[0])? == self.coffre.publique(Emplacement::Nouvelle)? {
            self.coffre
                .deplacer(Emplacement::Nouvelle, Emplacement::Courante)?;
            eprintln!("agent : renouvellement interrompu terminé");
        } else {
            self.coffre.supprimer(Emplacement::Nouvelle)?;
        }
        Ok(())
    }

    fn identite(&self) -> Result<Identite> {
        Ok(Identite {
            chaine: lire_chaine(&std::fs::read(self.chemin("chaine.pem"))?)?,
            cle: self.coffre.charger(Emplacement::Courante)?,
        })
    }

    /// Le serveur refuse la borne : plus aucune connexion jusqu'à un nouveau jeton.
    fn refuser(&mut self, raison: &str) -> Result<Duration> {
        let message =
            format!("borne refusée par le serveur ({raison}) : nouvel enrôlement nécessaire");
        eprintln!("agent : {message}");
        ecrire_atomique(&self.chemin("refusee"), message.as_bytes(), 0o600)?;
        self.etat.mode = Mode::Refusee;
        self.etat.message = message;
        Ok(PERIODE_JETON)
    }

    /// Serveur injoignable (ou non authentifié) : mode dégradé, essai espacé.
    fn liaison_perdue(&mut self, e: Echec, mode_si_non_enrolee: Mode) -> Duration {
        eprintln!("agent : {e}");
        self.etat.mode = match mode_si_non_enrolee {
            Mode::Connectee => Mode::Degradee,
            m => m,
        };
        self.etat.message = format!("mode dégradé (la borne fonctionne hors ligne) : {e}");
        self.reessai()
    }

    /// Liaison de service : renouvellement si dû, puis battement.
    fn service(&mut self) -> Result<Duration> {
        let identite = self.identite()?;
        let (debut, fin) = validite(&identite.chaine[0])?;
        self.etat.certificat_expire_le = Some(fin);
        let t = maintenant();
        if t >= fin {
            return self.refuser("certificat expiré");
        }
        let identite = if t >= debut + (fin - debut) / 2 {
            match self.renouveler(identite) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("agent : renouvellement : {e:#}");
                    self.identite()?
                }
            }
        } else {
            identite
        };
        let battement = Battement {
            version: VERSION,
            heure_borne: maintenant(),
            version_logiciel: VERSION_LOGICIEL.into(),
            etat: if self.file.pleine() {
                EtatBorne::HorsService
            } else {
                EtatBorne::EnService
            },
            age_signatures_s: self.age_signatures(),
            espace_libre_octets: self.espace_libre(),
            rapports_en_attente: u32::try_from(self.file.len()).unwrap_or(u32::MAX),
        };
        let corps = encoder(&battement).map_err(|c| anyhow::anyhow!("battement : {c}"))?;
        let (statut, reponse) = match self.client.requete(
            self.adresse_service(),
            Some(identite),
            "POST",
            route_maj::BATTEMENT,
            &corps,
        ) {
            Ok(r) => r,
            Err(Echec::Refusee(e)) => return self.refuser(&e),
            Err(e) => return Ok(self.liaison_perdue(e, Mode::Connectee)),
        };
        self.echecs = 0;
        match interpreter::<AccuseBattementMaj>(statut, 200, &reponse)? {
            Reponse::Ok(a) => {
                self.etat.mode = Mode::Connectee;
                self.etat.derniere_liaison = Some(maintenant());
                self.etat.ecart_horloge_s = Some(a.ecart_s);
                self.etat.horloge_derivee = false;
                self.etat.message = "liaison avec le serveur établie".into();
                if let Err(e) = self.suivre_maj(a.mise_a_jour.as_ref()) {
                    eprintln!("agent : mise à jour : {e:#}");
                    self.etat.message = format!("liaison établie ; mise à jour : {e:#}");
                }
                Ok(Duration::from_secs(a.prochain_battement_s.into()))
            }
            Reponse::Erreur(CodeErreur::BorneRefusee) => self.refuser("borne_refusee"),
            Reponse::Erreur(CodeErreur::HorlogeDerivee) => {
                // L'agent n'a pas le droit de régler l'horloge (aucune capacité) : il le signale ;
                // la supervision du serveur lève l'alerte « horloge ».
                let e: ReponseErreur = decoder(&reponse).map_err(|c| anyhow::anyhow!("{c}"))?;
                let ecart = barbacane_protocole::ecart_horloge(maintenant(), e.heure_serveur).0;
                self.etat.mode = Mode::Connectee;
                self.etat.derniere_liaison = Some(maintenant());
                self.etat.ecart_horloge_s = Some(ecart);
                self.etat.horloge_derivee = true;
                self.etat.message = format!(
                    "horloge de la borne décalée de {ecart} s par rapport au serveur : battement refusé"
                );
                eprintln!("agent : {}", self.etat.message);
                Ok(Duration::from_secs(
                    barbacane_protocole::PERIODE_BATTEMENT_S.into(),
                ))
            }
            Reponse::Erreur(code) => bail!("battement refusé : {code}"),
        }
    }

    /// Renouvellement (mi-vie atteinte) : nouvelle clé, demande sur la liaison authentifiée.
    fn renouveler(&mut self, identite: Identite) -> Result<Identite> {
        let (csr, publique) = self.coffre.generer(Emplacement::Nouvelle)?;
        let corps = encoder(&DemandeRenouvellement {
            version: VERSION,
            csr_pem: csr,
        })
        .map_err(|c| anyhow::anyhow!("renouvellement : {c}"))?;
        let (statut, reponse) = self
            .client
            .requete(
                self.adresse_service(),
                Some(identite),
                "POST",
                route::RENOUVELLEMENT,
                &corps,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        match interpreter::<ReponseCertificat>(statut, 200, &reponse)? {
            Reponse::Ok(r) => {
                let certs = lire_chaine(r.chaine_pem.as_bytes())?;
                if cle_publique(&certs[0])? != publique {
                    self.coffre.supprimer(Emplacement::Nouvelle)?;
                    bail!("certificat renouvelé ne correspondant pas à la nouvelle clé : refusé");
                }
                // Ordre : chaîne puis clé ; une coupure entre les deux est réparée au démarrage.
                ecrire_atomique(&self.chemin("chaine.pem"), r.chaine_pem.as_bytes(), 0o600)?;
                self.coffre
                    .deplacer(Emplacement::Nouvelle, Emplacement::Courante)?;
                eprintln!("agent : certificat renouvelé");
                self.identite()
            }
            Reponse::Erreur(code) => {
                self.coffre.supprimer(Emplacement::Nouvelle)?;
                bail!("renouvellement refusé : {code}")
            }
        }
    }

    /// Après un battement accepté : transmet le résultat déposé par admind, puis télécharge
    /// la mise à jour proposée si elle n'est pas déjà prête. N'applique jamais rien.
    fn suivre_maj(&mut self, proposee: Option<&MiseAJourDisponible>) -> Result<()> {
        let dossier = DossierMaj::nouveau(&self.config.etat);
        if let Some(r) = dossier.resultat()? {
            let corps = encoder(&RapportMaj {
                version: VERSION,
                version_maj: r.version_maj,
                resultat: r.resultat,
            })
            .map_err(|c| anyhow::anyhow!("rapport : {c}"))?;
            let (statut, reponse) = self
                .client
                .requete(
                    self.adresse_service(),
                    Some(self.identite()?),
                    "POST",
                    route_maj::RAPPORT,
                    &corps,
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            match interpreter::<AccuseRapportMaj>(statut, 200, &reponse)? {
                // Déjà rapporté ou plus proposé : rien à garder non plus.
                Reponse::Ok(_) | Reponse::Erreur(CodeErreur::Introuvable) => {
                    eprintln!(
                        "agent : résultat de la mise à jour {} transmis ({:?})",
                        r.version_maj, r.resultat
                    );
                    dossier.solder()?;
                }
                Reponse::Erreur(code) => bail!("rapport refusé : {code}"),
            }
        }
        let Some(m) = proposee else {
            return Ok(());
        };
        if !dossier.a_telecharger(m)? {
            return Ok(());
        }
        let libre = espace_libre(&self.config.etat).unwrap_or(0);
        if libre < m.taille.saturating_add(MARGE_ESPACE) {
            bail!(
                "espace insuffisant pour la mise à jour {} ({} octets, {libre} libres)",
                m.version_maj,
                m.taille
            );
        }
        let corps = encoder(&DemandeTelechargement {
            version: VERSION,
            version_maj: m.version_maj,
        })
        .map_err(|c| anyhow::anyhow!("téléchargement : {c}"))?;
        let (chemin, mut fichier) = dossier.ouvrir_reception()?;
        let issue = self.client.telecharger(
            self.adresse_service(),
            self.identite()?,
            route_maj::TELECHARGEMENT,
            &corps,
            m.taille,
            &mut fichier,
        );
        let issue = match issue {
            Ok(i) => i,
            Err(e) => {
                let _ = std::fs::remove_file(&chemin);
                bail!("téléchargement de la mise à jour {} : {e}", m.version_maj);
            }
        };
        match issue {
            Telechargement::Recu { sha256 } => {
                maj::synchroniser(&mut fichier)?;
                drop(fichier);
                dossier.installer(&chemin, m, &sha256)?;
                eprintln!(
                    "agent : mise à jour {} reçue ({} octets, empreinte conforme) : à vérifier et appliquer par l'administrateur",
                    m.version_maj, m.taille
                );
                Ok(())
            }
            Telechargement::Erreur(statut, corps) => {
                let _ = std::fs::remove_file(&chemin);
                let code = decoder::<ReponseErreur>(&corps)
                    .map(|e| e.code.to_string())
                    .unwrap_or_else(|_| format!("HTTP {statut}"));
                bail!(
                    "téléchargement de la mise à jour {} refusé : {code}",
                    m.version_maj
                )
            }
        }
    }

    /// Âge de la base antivirale la plus récente (0 si illisible).
    fn age_signatures(&self) -> u64 {
        let recent = std::fs::read_dir(&self.signatures)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.ends_with(".cvd") || n.ends_with(".cld")
            })
            .filter_map(|e| e.metadata().ok()?.modified().ok())
            .max();
        recent
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Espace libre de l'espace de travail (0 si illisible).
    fn espace_libre(&self) -> u64 {
        espace_libre(&self.travail).unwrap_or(0)
    }

    /// Nombre d'éléments en file locale (rapports non transmis).
    pub fn file(&self) -> &FileLocale {
        &self.file
    }
}

fn espace_libre(chemin: &Path) -> Result<u64> {
    let s = rustix::fs::statvfs(chemin)?;
    Ok(s.f_bavail.saturating_mul(s.f_frsize))
}
