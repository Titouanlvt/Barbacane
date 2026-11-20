//! Passerelle du serveur Barbacane (suite, étape 5 « socle ») — protocole v1
//! (`docs/suite/protocole-agent.md`).
//!
//! - TLS 1.3 seul, suites et groupes de la décision D6 (fournisseur `ring`, déjà utilisé par la
//!   borne) ;
//! - **deux écoutes** : service (certificat client OBLIGATOIRE, CA « bornes », CRL relue à
//!   CHAQUE connexion, refus si elle est absente, illisible ou expirée — D8, fail-closed) et
//!   enrôlement (sans certificat client, deux routes seulement) ;
//! - registre des bornes (`registre`), CA bornes (`ca`) ;
//! - HTTP volontairement minimal : une requête par connexion, tailles bornées avant lecture.
#![forbid(unsafe_code)]

pub mod admin;
pub mod ca;
pub mod maj;
pub mod outils;
pub mod passages;
pub mod registre;
pub mod utilisateurs;

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use barbacane_audit::{Anomalie, Evenement};
use barbacane_protocole::maj::{
    AccuseBattementMaj, AccuseRapportMaj, DemandeTelechargement, RapportMaj, route as route_maj,
};
use barbacane_protocole::passage::{AccuseRapportPassage, RapportPassage, route as route_passage};
use barbacane_protocole::utilisateurs::{
    DemandeChangementPin, DemandePolitique, DemandeVerification, route as route_utilisateurs,
};
use barbacane_protocole::{
    AccuseBattement, AccuseDemande, Battement, CodeErreur, ConsultationDemande, DemandeEnrolement,
    DemandeRenouvellement, ECART_HORLOGE_MAX_S, EtatBorne, EtatDemande, Message, ReponseCertificat,
    ReponseErreur, Sante, TAILLE_ENTETE_MAX, VERSION, decoder, ecart_horloge, encoder, route,
};
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::{cipher_suite, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use crate::ca::{CaBornes, verifier_csr};
use crate::maj::DepotMaj;
use crate::outils::{aleatoire, maintenant, serie_hex};
use crate::registre::{Identite, Refus, Stockage, code_de};

/// Connexions de service traitées simultanément au plus (100 bornes visées).
pub const CONNEXIONS_SERVICE_MAX: usize = 256;
/// Connexions d'enrôlement simultanées au plus (l'enrôlement est rare ; écoute anonyme).
pub const CONNEXIONS_ENROLEMENT_MAX: usize = 8;
/// Délai d'inactivité d'une lecture ou d'une écriture.
const DELAI: Duration = Duration::from_secs(10);
/// Durée TOTALE d'une connexion de service (poignée de main + requête + réponse) : un client
/// lent (« slowloris ») ne garde pas une place au-delà.
pub const DELAI_TOTAL_SERVICE: Duration = Duration::from_secs(20);
/// Téléchargements de `.bcu` simultanés au plus.
pub const TELECHARGEMENTS_MAX: usize = 8;
/// Débit minimal exigé d'un téléchargement : la durée totale admise est
/// [`DELAI_TOTAL_SERVICE`] + 1 s par tranche de ce nombre d'octets.
pub const DEBIT_MIN_TELECHARGEMENT: u64 = 512 * 1024;
/// Durée TOTALE d'une connexion d'enrôlement (écoute sans authentification : plus court).
pub const DELAI_TOTAL_ENROLEMENT: Duration = Duration::from_secs(10);

/// Flux TCP à échéance : chaque lecture ou écriture reçoit comme délai le temps restant
/// (au plus [`DELAI`]) ; échéance passée → `TimedOut`, quel que soit le débit du client.
struct FluxBorne {
    flux: TcpStream,
    fin: Instant,
}

impl FluxBorne {
    fn reste(&self) -> std::io::Result<Duration> {
        let reste = self.fin.saturating_duration_since(Instant::now());
        if reste.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "délai total de la connexion dépassé",
            ));
        }
        Ok(reste.min(DELAI))
    }
}

impl Read for FluxBorne {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        self.flux.set_read_timeout(Some(self.reste()?))?;
        self.flux.read(tampon)
    }
}

impl Write for FluxBorne {
    fn write(&mut self, octets: &[u8]) -> std::io::Result<usize> {
        self.flux.set_write_timeout(Some(self.reste()?))?;
        self.flux.write(octets)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flux.flush()
    }
}

/// Configuration lue dans un fichier `cle = valeur` (lignes `#` ignorées).
#[derive(Debug, Clone)]
pub struct Config {
    pub adresse: IpAddr,
    /// Port de service (mTLS) : tiré à l'installation (D4), jamais de valeur par défaut.
    pub port: u16,
    /// Port d'enrôlement (sans certificat client), inscrit dans les jetons (D4).
    pub port_enrolement: u16,
    /// Certificat serveur suivi de la CA serveur (PEM).
    pub chaine_serveur: PathBuf,
    pub cle_serveur: PathBuf,
    /// Certificat de la CA bornes : seule ancre de confiance des clients.
    pub ca_bornes: PathBuf,
    /// Clé de la CA bornes (signature des certificats de borne et de la CRL).
    pub cle_ca_bornes: PathBuf,
    /// CRL de la CA bornes (PEM), relue à chaque connexion, republiée à chaque révocation.
    pub crl_bornes: PathBuf,
    /// Dossier d'état du registre des bornes.
    pub registre: PathBuf,
}

impl Config {
    pub fn lire(chemin: &Path) -> Result<Config> {
        let texte = std::fs::read_to_string(chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        Config::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<Config> {
        let mut adresse = None;
        let (mut port, mut port_enrolement) = (None, None);
        let (mut chaine, mut cle, mut ca, mut cle_ca, mut crl, mut registre) =
            (None, None, None, None, None, None);
        for (n, ligne) in texte.lines().enumerate() {
            let ligne = ligne.trim();
            if ligne.is_empty() || ligne.starts_with('#') {
                continue;
            }
            let Some((k, v)) = ligne.split_once('=') else {
                bail!("ligne {} : « cle = valeur » attendu", n + 1);
            };
            let v = v.trim();
            let deja = match k.trim() {
                "adresse" => adresse
                    .replace(v.parse::<IpAddr>().context("adresse")?)
                    .is_some(),
                "port" => port.replace(v.parse::<u16>().context("port")?).is_some(),
                "port_enrolement" => port_enrolement
                    .replace(v.parse::<u16>().context("port_enrolement")?)
                    .is_some(),
                "chaine_serveur" => chaine.replace(PathBuf::from(v)).is_some(),
                "cle_serveur" => cle.replace(PathBuf::from(v)).is_some(),
                "ca_bornes" => ca.replace(PathBuf::from(v)).is_some(),
                "cle_ca_bornes" => cle_ca.replace(PathBuf::from(v)).is_some(),
                "crl_bornes" => crl.replace(PathBuf::from(v)).is_some(),
                "registre" => registre.replace(PathBuf::from(v)).is_some(),
                autre => bail!("ligne {} : clé inconnue « {autre} »", n + 1),
            };
            if deja {
                bail!("ligne {} : clé répétée", n + 1);
            }
        }
        let port = port.context("port absent (tiré à l'installation, D4)")?;
        let port_enrolement = port_enrolement.context("port_enrolement absent (D4)")?;
        if port == 0 || port_enrolement == 0 || port == port_enrolement {
            bail!("ports 0 ou identiques refusés (deux écoutes distinctes)");
        }
        Ok(Config {
            adresse: adresse.context("adresse absente")?,
            port,
            port_enrolement,
            chaine_serveur: chaine.context("chaine_serveur absente")?,
            cle_serveur: cle.context("cle_serveur absente")?,
            ca_bornes: ca.context("ca_bornes absente")?,
            cle_ca_bornes: cle_ca.context("cle_ca_bornes absente")?,
            crl_bornes: crl.context("crl_bornes absente")?,
            registre: registre.context("registre absent")?,
        })
    }

    pub fn adresse_ecoute(&self) -> SocketAddr {
        SocketAddr::new(self.adresse, self.port)
    }

    pub fn adresse_enrolement(&self) -> SocketAddr {
        SocketAddr::new(self.adresse, self.port_enrolement)
    }
}

/// Fournisseur `ring` réduit aux mécanismes de D6.
pub fn fournisseur() -> CryptoProvider {
    let mut f = rustls::crypto::ring::default_provider();
    f.cipher_suites = vec![
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    f.kx_groups = vec![kx_group::SECP384R1, kx_group::SECP256R1];
    f
}

/// Lit la CRL et refuse si elle est absente, illisible, sans date de fin ou expirée.
fn lire_crl(chemin: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let crls = CertificateRevocationListDer::pem_file_iter(chemin)
        .with_context(|| format!("CRL {}", chemin.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("CRL illisible")?;
    if crls.is_empty() {
        bail!("aucune CRL dans {}", chemin.display());
    }
    let maintenant = ASN1Time::now();
    for crl in &crls {
        let (_, analyse) =
            CertificateRevocationList::from_der(crl).map_err(|e| anyhow::anyhow!("CRL : {e}"))?;
        match analyse.next_update() {
            Some(fin) if fin > maintenant => {}
            Some(fin) => bail!("CRL expirée depuis {fin} : connexions refusées"),
            None => bail!("CRL sans date de prochaine mise à jour : refusée"),
        }
    }
    Ok(crls)
}

/// Configuration TLS 1.3 commune aux deux écoutes ; seule la vérification du client diffère.
fn construire_tls(
    config: &Config,
    client: Arc<dyn ClientCertVerifier>,
) -> Result<Arc<ServerConfig>> {
    let chaine = CertificateDer::pem_file_iter(&config.chaine_serveur)
        .context("chaîne serveur")?
        .collect::<Result<Vec<_>, _>>()
        .context("chaîne serveur illisible")?;
    let cle = PrivateKeyDer::from_pem_file(&config.cle_serveur).context("clé serveur")?;
    let tls = ServerConfig::builder_with_provider(Arc::new(fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client)
        .with_single_cert(chaine, cle)?;
    Ok(Arc::new(tls))
}

/// Écoute de service : certificat client obligatoire, CRL relue (appelée à chaque connexion).
pub fn config_tls(config: &Config) -> Result<Arc<ServerConfig>> {
    let mut ancres = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&config.ca_bornes).context("CA bornes")? {
        ancres.add(cert.context("CA bornes illisible")?)?;
    }
    if ancres.is_empty() {
        bail!("aucune CA bornes");
    }
    let verificateur =
        WebPkiClientVerifier::builder_with_provider(Arc::new(ancres), Arc::new(fournisseur()))
            .with_crls(lire_crl(&config.crl_bornes)?)
            .enforce_revocation_expiration()
            .build()?;
    construire_tls(config, verificateur)
}

/// Écoute d'enrôlement : aucun certificat client (la borne n'en a pas encore).
pub fn config_tls_enrolement(config: &Config) -> Result<Arc<ServerConfig>> {
    construire_tls(config, WebPkiClientVerifier::no_client_auth())
}

/// Nom commun et identité Barbacane (SAN `urn:barbacane:borne:<site>:<uuid>`, numéro de série)
/// du certificat client déjà vérifié par rustls.
fn identite(conn: &ServerConnection) -> Result<(String, Option<Identite>)> {
    let cert = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .context("aucun certificat client")?;
    let (_, cert) =
        X509Certificate::from_der(cert).map_err(|e| anyhow::anyhow!("certificat : {e}"))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .context("certificat sans CN")?
        .as_str()
        .map_err(|e| anyhow::anyhow!("CN : {e}"))?
        .to_owned();
    let mut id = None;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for nom in &san.value.general_names {
            if let GeneralName::URI(u) = nom
                && let Some((site, uuid)) = u
                    .strip_prefix("urn:barbacane:borne:")
                    .and_then(|r| r.split_once(':'))
            {
                if id.is_some() {
                    bail!("plusieurs identités Barbacane dans le certificat");
                }
                id = Some(Identite {
                    uuid: uuid.to_owned(),
                    site: site.to_owned(),
                    serie: serie_hex(cert.raw_serial()),
                });
            }
        }
    }
    Ok((cn, id))
}

// ───────────────────────────── HTTP minimal ───────────────────────────────────────────────────

/// Requête HTTP lue et bornée.
#[derive(Debug)]
pub struct Requete {
    pub methode: String,
    pub chemin: String,
    pub corps: Vec<u8>,
}

/// Lit une requête : en-têtes ≤ `TAILLE_ENTETE_MAX`, `Content-Length` obligatoire pour POST et
/// ≤ taille admise par la route (`taille_corps`, appelée AVANT de lire le corps),
/// `Transfer-Encoding` refusé, rien après le corps.
pub fn lire_requete(
    flux: &mut impl Read,
    taille_corps: impl Fn(&str, &str) -> Result<usize, CodeErreur>,
) -> Result<Requete, CodeErreur> {
    let invalide = CodeErreur::RequeteInvalide;
    let mut tampon = Vec::new();
    let mut bloc = [0u8; 1024];
    let fin = loop {
        if let Some(p) = tampon.windows(4).position(|f| f == b"\r\n\r\n") {
            break p;
        }
        if tampon.len() > TAILLE_ENTETE_MAX {
            return Err(CodeErreur::TropGros);
        }
        let n = flux.read(&mut bloc).map_err(|_| invalide)?;
        if n == 0 {
            return Err(invalide);
        }
        tampon.extend_from_slice(&bloc[..n]);
    };
    if fin + 4 > TAILLE_ENTETE_MAX {
        return Err(CodeErreur::TropGros);
    }
    let entete = std::str::from_utf8(&tampon[..fin]).map_err(|_| invalide)?;
    let mut lignes = entete.split("\r\n");
    let mut ligne = lignes.next().unwrap_or_default().split(' ');
    let (Some(methode), Some(chemin), Some("HTTP/1.1"), None) =
        (ligne.next(), ligne.next(), ligne.next(), ligne.next())
    else {
        return Err(invalide);
    };
    let mut longueur = None;
    for l in lignes {
        let (k, v) = l.split_once(':').ok_or(invalide)?;
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let v = v.trim();
                if longueur.is_some()
                    || v.is_empty()
                    || v.len() > 9
                    || !v.bytes().all(|c| c.is_ascii_digit())
                {
                    return Err(invalide);
                }
                longueur = Some(v.parse::<usize>().map_err(|_| invalide)?);
            }
            "transfer-encoding" => return Err(invalide),
            _ => {}
        }
    }
    let max = taille_corps(methode, chemin)?;
    let longueur = match (methode, longueur) {
        ("POST", None) => return Err(invalide),
        (_, l) => l.unwrap_or(0),
    };
    if longueur > max {
        return Err(CodeErreur::TropGros);
    }
    let mut corps = tampon[fin + 4..].to_vec();
    while corps.len() < longueur {
        let n = flux.read(&mut bloc).map_err(|_| invalide)?;
        if n == 0 {
            return Err(invalide);
        }
        corps.extend_from_slice(&bloc[..n]);
    }
    if corps.len() != longueur {
        return Err(invalide);
    }
    Ok(Requete {
        methode: methode.into(),
        chemin: chemin.into(),
        corps,
    })
}

fn texte_statut(statut: u16) -> &'static str {
    match statut {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

fn reponse_http(statut: u16, corps: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {statut} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        texte_statut(statut),
        corps.len()
    )
    .into_bytes();
    r.extend_from_slice(corps);
    r
}

/// Réponse d'erreur du protocole (toujours avec l'heure du serveur).
pub fn erreur(code: CodeErreur) -> (u16, Vec<u8>) {
    let corps = serde_json::to_vec(&ReponseErreur {
        version: VERSION,
        code,
        heure_serveur: maintenant(),
    })
    .unwrap_or_default();
    (code.statut_http(), corps)
}

fn json<M: Message>(statut: u16, m: &M) -> Result<(u16, Vec<u8>)> {
    Ok((statut, encoder(m).map_err(Refus)?))
}

/// Taille maximale du corps par route ; route connue, autre méthode → `methode_refusee`.
fn routes(table: &[(&str, &str, usize)], methode: &str, chemin: &str) -> Result<usize, CodeErreur> {
    let mut connue = false;
    for (m, c, t) in table {
        if *c == chemin {
            if *m == methode {
                return Ok(*t);
            }
            connue = true;
        }
    }
    Err(if connue {
        CodeErreur::MethodeRefusee
    } else {
        CodeErreur::Introuvable
    })
}

const ROUTES_ENROLEMENT: &[(&str, &str, usize)] = &[
    ("POST", route::DEMANDE, DemandeEnrolement::TAILLE_MAX),
    ("POST", route::RETRAIT, ConsultationDemande::TAILLE_MAX),
];
const ROUTES_SERVICE: &[(&str, &str, usize)] = &[
    ("GET", route::SANTE, 0),
    ("POST", route::BATTEMENT, Battement::TAILLE_MAX),
    (
        "POST",
        route::RENOUVELLEMENT,
        DemandeRenouvellement::TAILLE_MAX,
    ),
    ("POST", route_maj::BATTEMENT, Battement::TAILLE_MAX),
    (
        "POST",
        route_maj::TELECHARGEMENT,
        DemandeTelechargement::TAILLE_MAX,
    ),
    ("POST", route_maj::RAPPORT, RapportMaj::TAILLE_MAX),
    ("POST", route_passage::PASSAGE, RapportPassage::TAILLE_MAX),
    (
        "POST",
        route_utilisateurs::POLITIQUE,
        DemandePolitique::TAILLE_MAX,
    ),
    (
        "POST",
        route_utilisateurs::VERIFICATION,
        DemandeVerification::TAILLE_MAX,
    ),
    (
        "POST",
        route_utilisateurs::PIN,
        DemandeChangementPin::TAILLE_MAX,
    ),
];

// ───────────────────────────── Passerelle ─────────────────────────────────────────────────────

/// État partagé par les deux écoutes.
pub struct Passerelle {
    pub config: Config,
    pub stockage: Stockage,
    pub ca: CaBornes,
}

/// Téléchargements en cours (tout le processus).
static TELECHARGEMENTS: AtomicUsize = AtomicUsize::new(0);

/// Acteur audité de la passerelle.
const ACTEUR: &str = "passerelle";

/// Place de téléchargement, rendue à la destruction.
struct Place;
impl Drop for Place {
    fn drop(&mut self) {
        TELECHARGEMENTS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Paquet prêt à être envoyé à une borne.
struct Envoi {
    fichier: std::fs::File,
    taille: u64,
    uuid: String,
    version_maj: u64,
    _place: Place,
}

impl Passerelle {
    /// Contrôle au démarrage : configurations TLS (donc CRL valide), CA bornes, registre.
    pub fn nouvelle(config: Config) -> Result<Arc<Passerelle>> {
        config_tls(&config)?;
        config_tls_enrolement(&config)?;
        let ca = CaBornes::charger(&config.ca_bornes, &config.cle_ca_bornes)?;
        let stockage = Stockage::ouvrir(&config.registre)?;
        stockage.lire()?;
        DepotMaj::ouvrir(&stockage)?.lire()?;
        utilisateurs::Utilisateurs::ouvrir(&stockage)?.lire()?;
        passages::Passages::ouvrir(&stockage)?;
        Ok(Arc::new(Passerelle {
            config,
            stockage,
            ca,
        }))
    }

    /// Utilisateurs, sites et clés USB (dossier `utilisateurs/` du registre).
    pub fn utilisateurs(&self) -> Result<utilisateurs::Utilisateurs> {
        utilisateurs::Utilisateurs::ouvrir(&self.stockage)
    }

    /// Dépôt des mises à jour (dossier `maj/` du registre).
    pub fn maj(&self) -> Result<DepotMaj> {
        DepotMaj::ouvrir(&self.stockage)
    }

    /// Route d'enrôlement (aucune authentification du client).
    pub fn enrolement(&self, r: &Requete) -> Result<(u16, Vec<u8>)> {
        let t = maintenant();
        match r.chemin.as_str() {
            route::DEMANDE => {
                let d: DemandeEnrolement = decoder(&r.corps).map_err(Refus)?;
                let csr = verifier_csr(&d.csr_pem).map_err(Refus)?;
                let id = hex::encode(aleatoire::<16>());
                self.stockage.transaction(|reg| {
                    reg.deposer(
                        &d.jeton,
                        &d.csr_pem,
                        &csr.empreinte,
                        &d.version_logiciel,
                        &id,
                        t,
                    )?;
                    self.stockage.auditer(
                        ACTEUR,
                        Evenement::EnrolementDemande {
                            demande: id.clone(),
                            empreinte: csr.empreinte.clone(),
                        },
                    )
                })?;
                self.stockage.journaliser(
                    t,
                    "demande_deposee",
                    serde_json::json!({"demande": id, "empreinte": csr.empreinte}),
                );
                json(
                    202,
                    &AccuseDemande {
                        version: VERSION,
                        demande_id: id,
                        empreinte: csr.empreinte,
                        heure_serveur: t,
                    },
                )
            }
            route::RETRAIT => {
                let c: ConsultationDemande = decoder(&r.corps).map_err(Refus)?;
                let (decision, cert) = self.stockage.lire()?.consulter(&c.demande_id, t)?;
                json(
                    200,
                    &EtatDemande {
                        version: VERSION,
                        decision,
                        chaine_pem: cert.as_deref().map(|c| self.ca.chaine(c)),
                        port_service: cert.as_ref().map(|_| self.config.port),
                        certificat_pem: cert,
                        heure_serveur: t,
                    },
                )
            }
            _ => Err(Refus(CodeErreur::Introuvable).into()),
        }
    }

    /// Republie la CRL depuis une transaction (ancien certificat remplacé).
    fn republier_crl(&self, reg: &mut registre::Registre, t: u64) -> Result<()> {
        admin::publier_crl(&self.ca, &self.config, reg, t)
    }

    /// Battement d'une borne authentifiée. Anomalies auditées au changement d'état : dérive
    /// d'horloge, passage hors service, borne refusée.
    fn battre(&self, id: &Identite, b: &Battement, t: u64) -> Result<AccuseBattement> {
        let resultat = self.stockage.transaction(|reg| {
            if reg.authentifier(id, t)? {
                self.republier_crl(reg, t)?;
            }
            let (avant_derive, avant_hs) = reg
                .bornes
                .iter()
                .find(|x| x.uuid == id.uuid)
                .map(|x| {
                    (
                        x.ecart_horloge_s
                            .is_some_and(|e| e.unsigned_abs() > ECART_HORLOGE_MAX_S),
                        x.dernier_battement
                            .as_ref()
                            .is_some_and(|d| d.etat == EtatBorne::HorsService),
                    )
                })
                .unwrap_or_default();
            let r = reg.battement(&id.uuid, b, t)?;
            let (ecart_s, derive) = ecart_horloge(b.heure_borne, t);
            let anomalie = if derive && !avant_derive {
                Some(Anomalie::HorlogeDerivee)
            } else if !derive && b.etat == EtatBorne::HorsService && !avant_hs {
                Some(Anomalie::HorsService)
            } else {
                None
            };
            if let Some(anomalie) = anomalie {
                self.stockage.auditer(
                    ACTEUR,
                    Evenement::BattementAnormal {
                        borne: id.uuid.clone(),
                        anomalie,
                        ecart_s,
                    },
                )?;
            }
            Ok(r)
        });
        match resultat {
            Ok(Ok(accuse)) => Ok(accuse),
            Ok(Err(code)) => Err(Refus(code).into()),
            Err(e) => {
                if code_de(&e) == CodeErreur::BorneRefusee {
                    self.auditer_refus(id)?;
                }
                Err(e)
            }
        }
    }

    /// Borne présentant un certificat valide mais refusée par le registre.
    fn auditer_refus(&self, id: &Identite) -> Result<()> {
        if barbacane_audit::ident_valide(&id.uuid) {
            self.stockage.auditer(
                ACTEUR,
                Evenement::BattementAnormal {
                    borne: id.uuid.clone(),
                    anomalie: Anomalie::BorneRefusee,
                    ecart_s: 0,
                },
            )?;
        }
        Ok(())
    }

    /// Contrôle applicatif seul (borne connue, active, certificat courant).
    fn authentifier(&self, id: &Identite, t: u64) -> Result<()> {
        let r = self.stockage.transaction(|reg| {
            if reg.authentifier(id, t)? {
                self.republier_crl(reg, t)?;
            }
            Ok(())
        });
        if let Err(e) = &r
            && code_de(e) == CodeErreur::BorneRefusee
        {
            self.auditer_refus(id)?;
        }
        r
    }

    /// `POST /maj/telechargement` : contrôles, place de téléchargement, fichier ouvert.
    fn preparer_envoi(&self, r: &Requete, id: Option<&Identite>) -> Result<Envoi> {
        let id = id.ok_or(Refus(CodeErreur::BorneRefusee))?;
        let d: DemandeTelechargement = decoder(&r.corps).map_err(Refus)?;
        self.authentifier(id, maintenant())?;
        if TELECHARGEMENTS.fetch_add(1, Ordering::SeqCst) >= TELECHARGEMENTS_MAX {
            TELECHARGEMENTS.fetch_sub(1, Ordering::SeqCst);
            return Err(Refus(CodeErreur::Surcharge).into());
        }
        let place = Place;
        let (fichier, taille) = self.maj()?.fichier_propose(&id.uuid, d.version_maj)?;
        Ok(Envoi {
            fichier,
            taille,
            uuid: id.uuid.clone(),
            version_maj: d.version_maj,
            _place: place,
        })
    }

    /// Route de service (borne authentifiée par mTLS).
    pub fn service(&self, r: &Requete, cn: &str, id: Option<&Identite>) -> Result<(u16, Vec<u8>)> {
        let t = maintenant();
        if r.chemin == route::SANTE {
            return json(
                200,
                &Sante {
                    version: VERSION,
                    etat: "ok".into(),
                    borne: cn.chars().take(128).collect(),
                    heure_serveur: t,
                },
            );
        }
        let id = id.ok_or(Refus(CodeErreur::BorneRefusee))?;
        match r.chemin.as_str() {
            route::BATTEMENT => {
                let b: Battement = decoder(&r.corps).map_err(Refus)?;
                json(200, &self.battre(id, &b, t)?)
            }
            route_maj::BATTEMENT => {
                let b: Battement = decoder(&r.corps).map_err(Refus)?;
                let a = self.battre(id, &b, t)?;
                json(
                    200,
                    &AccuseBattementMaj {
                        version: VERSION,
                        heure_serveur: a.heure_serveur,
                        ecart_s: a.ecart_s,
                        prochain_battement_s: a.prochain_battement_s,
                        mise_a_jour: self.maj()?.offre(&id.uuid)?,
                    },
                )
            }
            route_maj::RAPPORT => {
                let m: RapportMaj = decoder(&r.corps).map_err(Refus)?;
                self.authentifier(id, t)?;
                self.maj()?.rapport(&id.uuid, m.version_maj, m.resultat)?;
                json(
                    200,
                    &AccuseRapportMaj {
                        version: VERSION,
                        heure_serveur: t,
                    },
                )
            }
            route_passage::PASSAGE => {
                let m: RapportPassage = decoder(&r.corps).map_err(Refus)?;
                self.authentifier(id, t)?;
                let deja_recu = passages::Passages::ouvrir(&self.stockage)?
                    .recevoir(&id.uuid, &m, ACTEUR, t)?;
                json(
                    200,
                    &AccuseRapportPassage {
                        version: VERSION,
                        heure_serveur: t,
                        deja_recu,
                    },
                )
            }
            route_utilisateurs::POLITIQUE => {
                let _: DemandePolitique = decoder(&r.corps).map_err(Refus)?;
                self.authentifier(id, t)?;
                json(200, &self.utilisateurs()?.politique_pour(id, ACTEUR, t)?)
            }
            route_utilisateurs::VERIFICATION => {
                let d: DemandeVerification = decoder(&r.corps).map_err(Refus)?;
                self.authentifier(id, t)?;
                json(200, &self.utilisateurs()?.verifier(id, &d, ACTEUR, t)?)
            }
            route_utilisateurs::PIN => {
                let d: DemandeChangementPin = decoder(&r.corps).map_err(Refus)?;
                self.authentifier(id, t)?;
                json(200, &self.utilisateurs()?.changer_pin(id, &d, ACTEUR, t)?)
            }
            route::RENOUVELLEMENT => {
                let d: DemandeRenouvellement = decoder(&r.corps).map_err(Refus)?;
                let pem = self.stockage.transaction(|reg| {
                    if reg.authentifier(id, t)? {
                        self.republier_crl(reg, t)?;
                    }
                    let pem = reg.renouveler(&self.ca, id, &d.csr_pem, t)?;
                    self.stockage.auditer(
                        ACTEUR,
                        Evenement::CertificatRenouvele {
                            borne: id.uuid.clone(),
                        },
                    )?;
                    Ok(pem)
                })?;
                self.stockage.journaliser(
                    t,
                    "certificat_renouvele",
                    serde_json::json!({"borne": id.uuid}),
                );
                json(
                    200,
                    &ReponseCertificat {
                        version: VERSION,
                        chaine_pem: self.ca.chaine(&pem),
                        certificat_pem: pem,
                        heure_serveur: t,
                    },
                )
            }
            _ => Err(Refus(CodeErreur::Introuvable).into()),
        }
    }
}

/// Une connexion : poignée de main, une requête, une réponse. Renvoie une description pour le
/// journal.
fn traiter(flux: TcpStream, p: &Passerelle, enrolement: bool) -> Result<String> {
    let total = if enrolement {
        DELAI_TOTAL_ENROLEMENT
    } else {
        DELAI_TOTAL_SERVICE
    };
    let flux = FluxBorne {
        flux,
        fin: Instant::now() + total,
    };
    // Configuration (donc CRL) relue à chaque connexion : une révocation prend effet aussitôt.
    let tls = if enrolement {
        config_tls_enrolement(&p.config)?
    } else {
        config_tls(&p.config)?
    };
    let mut tls = StreamOwned::new(ServerConnection::new(tls)?, flux);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let (cn, id) = if enrolement {
        (String::from("(enrôlement)"), None)
    } else {
        identite(&tls.conn)?
    };
    let table = if enrolement {
        ROUTES_ENROLEMENT
    } else {
        ROUTES_SERVICE
    };
    let (statut, corps, resume) = match lire_requete(&mut tls, |m, c| routes(table, m, c)) {
        Err(code) => {
            let (s, c) = erreur(code);
            (s, c, format!("requête refusée : {code}"))
        }
        Ok(r) if !enrolement && r.chemin == route_maj::TELECHARGEMENT => {
            match p.preparer_envoi(&r, id.as_ref()) {
                Ok(envoi) => return envoyer_paquet(tls, p, envoi, &cn),
                Err(e) => {
                    let code = code_de(&e);
                    let (s, c) = erreur(code);
                    (s, c, format!("{} {} → {code} ({e:#})", r.methode, r.chemin))
                }
            }
        }
        Ok(r) => {
            let resultat = if enrolement {
                p.enrolement(&r)
            } else {
                p.service(&r, &cn, id.as_ref())
            };
            match resultat {
                Ok((s, c)) => (s, c, format!("{} {} → {s}", r.methode, r.chemin)),
                Err(e) => {
                    let code = code_de(&e);
                    let (s, c) = erreur(code);
                    (s, c, format!("{} {} → {code} ({e:#})", r.methode, r.chemin))
                }
            }
        }
    };
    tls.write_all(&reponse_http(statut, &corps))?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(format!("« {cn} » {resume}"))
}

/// Envoie un `.bcu` (application/octet-stream) ; l'échéance de la connexion est allongée selon
/// la taille (débit minimal [`DEBIT_MIN_TELECHARGEMENT`]). État `telechargee` au dernier octet.
fn envoyer_paquet(
    mut tls: StreamOwned<ServerConnection, FluxBorne>,
    p: &Passerelle,
    envoi: Envoi,
    cn: &str,
) -> Result<String> {
    tls.sock.fin = Instant::now()
        + DELAI_TOTAL_SERVICE
        + Duration::from_secs(envoi.taille / DEBIT_MIN_TELECHARGEMENT);
    let entete = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        envoi.taille
    );
    tls.write_all(entete.as_bytes())?;
    let envoye = std::io::copy(&mut (&envoi.fichier).take(envoi.taille), &mut tls)?;
    if envoye != envoi.taille {
        bail!(
            "paquet tronqué à l'envoi ({envoye} / {} octets)",
            envoi.taille
        );
    }
    tls.conn.send_close_notify();
    tls.flush()?;
    p.maj()?
        .marquer_telechargee(&envoi.uuid, envoi.version_maj)?;
    Ok(format!(
        "« {cn} » paquet {} envoyé ({} octets)",
        envoi.version_maj, envoi.taille
    ))
}

fn boucle(ecoute: TcpListener, p: Arc<Passerelle>, enrolement: bool) -> Result<()> {
    let max = if enrolement {
        CONNEXIONS_ENROLEMENT_MAX
    } else {
        CONNEXIONS_SERVICE_MAX
    };
    let nom = if enrolement { "enrôlement" } else { "service" };
    let actives = Arc::new(AtomicUsize::new(0));
    for flux in ecoute.incoming() {
        let flux = match flux {
            Ok(f) => f,
            Err(e) => {
                eprintln!("passerelle ({nom}) : acceptation : {e}");
                continue;
            }
        };
        if actives.fetch_add(1, Ordering::SeqCst) >= max {
            actives.fetch_sub(1, Ordering::SeqCst);
            eprintln!("passerelle ({nom}) : trop de connexions, refus");
            continue;
        }
        let (p, actives) = (p.clone(), actives.clone());
        std::thread::spawn(move || {
            let pair = flux.peer_addr().ok();
            match traiter(flux, &p, enrolement) {
                Ok(r) => eprintln!("passerelle ({nom}) : {pair:?} : {r}"),
                Err(e) => eprintln!("passerelle ({nom}) : {pair:?} : refus : {e:#}"),
            }
            actives.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Écoute de service (mTLS) : un fil par connexion, au plus 256, 20 s chacune.
pub fn servir(ecoute: TcpListener, p: Arc<Passerelle>) -> Result<()> {
    boucle(ecoute, p, false)
}

/// Écoute d'enrôlement (sans certificat client) : au plus 8 connexions de 10 s.
pub fn servir_enrolement(ecoute: TcpListener, p: Arc<Passerelle>) -> Result<()> {
    boucle(ecoute, p, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "# essai\nadresse = 127.0.0.1\nport = 43117\nport_enrolement = 43118\nchaine_serveur = /a\ncle_serveur = /b\nca_bornes = /c\ncle_ca_bornes = /e\ncrl_bornes = /d\nregistre = /f\n";

    #[test]
    fn config_complete() {
        let c = Config::analyser(CONF).unwrap();
        assert_eq!(c.adresse_ecoute().to_string(), "127.0.0.1:43117");
        assert_eq!(c.adresse_enrolement().to_string(), "127.0.0.1:43118");
    }

    #[test]
    fn config_refusee() {
        assert!(Config::analyser(&CONF.replace("43117", "0")).is_err());
        assert!(Config::analyser(&CONF.replace("43118", "43117")).is_err());
        assert!(Config::analyser(&CONF.replace("port = 43117\n", "")).is_err());
        assert!(Config::analyser(&CONF.replace("registre = /f\n", "")).is_err());
        assert!(Config::analyser(&format!("{CONF}port = 1\n")).is_err());
        assert!(Config::analyser(&format!("{CONF}inconnue = 1\n")).is_err());
    }

    fn lire(brut: &str) -> Result<Requete, CodeErreur> {
        lire_requete(&mut brut.as_bytes(), |m, c| routes(ROUTES_SERVICE, m, c))
    }

    #[test]
    fn http_borne() {
        let r = lire("POST /battement HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(
            (r.methode.as_str(), r.corps.as_slice()),
            ("POST", &b"{}"[..])
        );
        assert_eq!(
            lire("GET /sante HTTP/1.1\r\n\r\n").unwrap().chemin,
            "/sante"
        );
        let cas = [
            (
                "POST /battement HTTP/1.1\r\n\r\n",
                CodeErreur::RequeteInvalide,
            ),
            (
                "POST /battement HTTP/1.1\r\nContent-Length: 5000\r\n\r\n",
                CodeErreur::TropGros,
            ),
            (
                "POST /battement HTTP/1.1\r\nContent-Length: +2\r\n\r\n{}",
                CodeErreur::RequeteInvalide,
            ),
            (
                "POST /battement HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                CodeErreur::RequeteInvalide,
            ),
            (
                "POST /battement HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                CodeErreur::RequeteInvalide,
            ),
            (
                "POST /battement HTTP/1.1\r\nContent-Length: 1\r\n\r\n{}",
                CodeErreur::RequeteInvalide,
            ),
            (
                "POST /sante HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                CodeErreur::MethodeRefusee,
            ),
            (
                "GET /enrolement/demande HTTP/1.1\r\n\r\n",
                CodeErreur::Introuvable,
            ),
            ("GET /sante HTTP/1.0\r\n\r\n", CodeErreur::RequeteInvalide),
        ];
        for (brut, code) in cas {
            assert_eq!(lire(brut).unwrap_err(), code, "{brut:?}");
        }
        let gros = format!("GET /sante HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(5000));
        assert_eq!(lire(&gros).unwrap_err(), CodeErreur::TropGros);
    }
}
