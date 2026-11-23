//! Export du journal vers un collecteur Syslog du réseau local (v2.3.0,
//! `docs/suite/journal-syslog.md`).
//!
//! - **Format** : RFC 5424, message = événement structuré ([`barbacane_audit::structure`]) ;
//!   cadrage par longueur (RFC 5425 §4.3 / RFC 6587 §3.4.1) en TLS et en TCP.
//! - **Transport** au choix de l'administrateur : **TLS 1.3** (RFC 5425 ; rustls, suites et
//!   groupes D6, certificat du collecteur vérifié contre l'AC configurée et le nom attendu,
//!   certificat client facultatif : mTLS) **ou en clair** (TCP ou UDP : non recommandé,
//!   signalé dans la Console et audité). Aucune résolution de noms : adresse IPv4 du réseau
//!   local ; le pare-feu du serveur n'ouvre que cette cible (`barbacane-syslog-pare-feu`).
//! - **File d'attente persistante** : le journal d'audit chaîné LUI-MÊME (rien n'est recopié) et
//!   un curseur (`curseur.json`) : numéro du dernier événement dont la remise est CONFIRMÉE.
//!   Collecteur injoignable : rien n'est perdu, l'envoi reprend au curseur. Au-delà de
//!   [`FILE_MAX`] événements en attente : débordement, alerte dans la Console et au journal
//!   (les événements restent dans le journal et partent dès le retour du collecteur) ; un
//!   événement purgé par la conservation avant d'avoir été remis est signalé (`perte`).
//! - **Remise confirmée** (TCP et TLS) : un lot est envoyé sur une connexion, puis le serveur
//!   ferme son côté (`close_notify` TLS puis FIN) et attend la fermeture du collecteur : celui-ci
//!   ne ferme qu'après avoir lu tout ce qui précède notre FIN, la remise du lot est donc
//!   confirmée. Sinon le lot est renvoyé, ses messages marqués `reprise="1"` (même `id`) : un
//!   doublon possible n'est jamais silencieux. En UDP, aucune confirmation n'est possible.
//!
//! Fichiers, dans `<registre>/syslog/` (barbacane-svc, 0600) : `actif.json` (réglage validé
//! par deux administrateurs, écrit par la Console), `pare-feu` (cible lue par root),
//! `ac-<sha256>.pem`, `client.cle.pem`, `client-<sha256>.pem`, `curseur.json`, `etat.json`
//! (écrit par l'exportateur, lu par la Console).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use barbacane_audit::structure::{Structure, message_syslog, structurer};
use barbacane_audit::{Evenement, Journal};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};

use crate::outils::{ecrire_atomique, sha256_hex};
use crate::registre::Stockage;

/// Événements en attente au-delà desquels la file est déclarée en débordement.
pub const FILE_MAX: u64 = 100_000;
/// Messages au plus par lot (une connexion).
pub const LOT_MAX: usize = 500;
/// Taille maximale d'un PEM déposé (AC, certificat client).
pub const PEM_MAX: usize = 8 * 1024;
const DELAI_CONNEXION: Duration = Duration::from_secs(5);
const DELAI_FERMETURE: Duration = Duration::from_secs(10);

/// Transport choisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// RFC 5425, TLS 1.3 (recommandé).
    Tls,
    /// RFC 6587, TCP sans chiffrement (non recommandé).
    TcpClair,
    /// RFC 5426, UDP sans chiffrement ni confirmation (non recommandé).
    UdpClair,
}

impl Mode {
    pub fn nom(self) -> &'static str {
        match self {
            Mode::Tls => "tls",
            Mode::TcpClair => "tcp-clair",
            Mode::UdpClair => "udp-clair",
        }
    }
    pub fn analyser(s: &str) -> Option<Mode> {
        [Mode::Tls, Mode::TcpClair, Mode::UdpClair]
            .into_iter()
            .find(|m| m.nom() == s)
    }
    pub fn libelle(self) -> &'static str {
        match self {
            Mode::Tls => "TLS 1.3 (RFC 5425)",
            Mode::TcpClair => "TCP en clair (non recommandé)",
            Mode::UdpClair => "UDP en clair, sans confirmation (non recommandé)",
        }
    }
    pub fn clair(self) -> bool {
        self != Mode::Tls
    }
}

/// Réglage de l'export (validé par deux administrateurs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSyslog {
    pub mode: Mode,
    pub adresse: Ipv4Addr,
    pub port: u16,
    /// TLS : nom attendu dans le certificat du collecteur (nom DNS ou adresse IP).
    pub nom: Option<String>,
    /// TLS : SHA-256 du PEM de l'AC du collecteur (`ac-<sha256>.pem`).
    pub ac: Option<String>,
    /// TLS facultatif (mTLS) : SHA-256 du certificat client (`client-<sha256>.pem`), clé
    /// `client.cle.pem` tirée par le serveur.
    pub certificat_client: Option<String>,
}

impl ConfigSyslog {
    /// Cible courte (audit) : `tls:10.0.3.100:6514`.
    pub fn cible(&self) -> String {
        format!("{}:{}:{}", self.mode.nom(), self.adresse, self.port)
    }
}

/// Nom attendu : DNS (`[a-z0-9.-]`, 1 à 253) ou adresse IP.
pub fn nom_valide(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && ServerName::try_from(s.to_owned()).is_ok()
}

/// Adresse acceptable pour un collecteur du réseau local.
pub fn adresse_valide(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_broadcast() || a.is_multicast())
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Dossier `syslog/` du registre.
pub fn dossier(stockage: &Stockage) -> Result<PathBuf> {
    let d = stockage.dossier().join("syslog");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&d)
        .with_context(|| format!("dossier {}", d.display()))?;
    Ok(d)
}

fn lire_borne(chemin: &Path, max: usize) -> Result<Option<Vec<u8>>> {
    match std::fs::File::open(chemin) {
        Ok(f) => {
            let mut o = Vec::new();
            f.take(max as u64 + 1).read_to_end(&mut o)?;
            if o.len() > max {
                bail!("{} : trop long", chemin.display());
            }
            Ok(Some(o))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("{}", chemin.display())),
    }
}

/// Certificats PEM (au moins un, tous analysables).
fn certificats(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let v: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<_, _>>()
        .context("PEM de certificat illisible")?;
    if v.is_empty() {
        bail!("aucun certificat dans le PEM");
    }
    for c in &v {
        x509_parser::parse_x509_certificate(c.as_ref())
            .map_err(|e| anyhow::anyhow!("certificat illisible : {e}"))?;
    }
    Ok(v)
}

/// Dépose un PEM (AC ou certificat client) sous son empreinte ; renvoie l'empreinte.
pub fn deposer_pem(stockage: &Stockage, prefixe: &str, pem: &[u8]) -> Result<String> {
    if pem.len() > PEM_MAX {
        bail!("PEM trop long ({PEM_MAX} octets au plus)");
    }
    certificats(pem)?;
    let h = sha256_hex(pem);
    let d = dossier(stockage)?;
    ecrire_atomique(&d.join(format!("{prefixe}-{h}.pem")), pem)?;
    Ok(h)
}

/// Clé client (P-256) tirée par le serveur pour le mTLS, et sa demande de certificat (PEM),
/// à faire signer par l'AC du collecteur. La clé ne quitte jamais le serveur.
pub fn generer_cle_client(stockage: &Stockage, nom_serveur: &str) -> Result<String> {
    let cle = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!(
            "barbacane-syslog {}",
            barbacane_audit::structure::nom_serveur(nom_serveur)
        ),
    );
    let csr = p.serialize_request(&cle)?.pem()?;
    ecrire_atomique(
        &dossier(stockage)?.join("client.cle.pem"),
        cle.serialize_pem().as_bytes(),
    )?;
    Ok(csr)
}

/// Demande de certificat de la clé client en place (pour l'afficher de nouveau).
pub fn csr_client(stockage: &Stockage, nom_serveur: &str) -> Result<Option<String>> {
    let Some(pem) = lire_borne(&dossier(stockage)?.join("client.cle.pem"), PEM_MAX)? else {
        return Ok(None);
    };
    let cle = rcgen::KeyPair::from_pem(std::str::from_utf8(&pem)?)?;
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!(
            "barbacane-syslog {}",
            barbacane_audit::structure::nom_serveur(nom_serveur)
        ),
    );
    Ok(Some(p.serialize_request(&cle)?.pem()?))
}

/// Dépose le certificat client signé par l'AC du collecteur (mTLS) : il doit correspondre à
/// la clé tirée par le serveur. Devient le certificat « actuel » proposé dans la Console.
pub fn deposer_certificat_client(stockage: &Stockage, pem: &[u8]) -> Result<String> {
    let h = deposer_pem(stockage, "client", pem)?;
    verifier_client(&dossier(stockage)?, &h)?;
    ecrire_atomique(&dossier(stockage)?.join("client-actuel"), h.as_bytes())?;
    Ok(h)
}

/// Empreinte du certificat client déposé en dernier (`None` : aucun).
pub fn certificat_client_actuel(stockage: &Stockage) -> Result<Option<String>> {
    Ok(lire_borne(&dossier(stockage)?.join("client-actuel"), 64)?
        .and_then(|o| String::from_utf8(o).ok())
        .filter(|h| hex64(h)))
}

/// Résumé lisible d'un certificat déposé (sujet, échéance) pour l'administrateur validateur.
pub fn resume_pem(stockage: &Stockage, prefixe: &str, h: &str) -> Option<String> {
    if !hex64(h) {
        return None;
    }
    let pem = lire_borne(
        &dossier(stockage).ok()?.join(format!("{prefixe}-{h}.pem")),
        PEM_MAX,
    )
    .ok()??;
    let der = certificats(&pem).ok()?;
    let (_, x) = x509_parser::parse_x509_certificate(der[0].as_ref()).ok()?;
    Some(format!(
        "{} (jusqu'au {})",
        x.subject(),
        crate::outils::date_utc(u64::try_from(x.validity().not_after.timestamp()).unwrap_or(0))
    ))
}

fn verifier_client(d: &Path, h: &str) -> Result<()> {
    let cert = lire_borne(&d.join(format!("client-{h}.pem")), PEM_MAX)?
        .context("mTLS : certificat client absent")?;
    if sha256_hex(&cert) != *h {
        bail!("mTLS : fichier du certificat client modifié");
    }
    let cle = lire_borne(&d.join("client.cle.pem"), PEM_MAX)?
        .context("mTLS : clé client absente (générer la clé)")?;
    let paire = rcgen::KeyPair::from_pem(std::str::from_utf8(&cle)?)?;
    let der = certificats(&cert)?;
    let (_, x) = x509_parser::parse_x509_certificate(der[0].as_ref())
        .map_err(|e| anyhow::anyhow!("certificat client : {e}"))?;
    if x.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(&paire).as_slice() {
        bail!("mTLS : le certificat client ne correspond pas à la clé du serveur");
    }
    Ok(())
}

/// Contrôle d'un réglage DEMANDÉ dans la Console : cible du réseau local, puis
/// [`controler`].
pub fn controler_demande(stockage: &Stockage, c: &ConfigSyslog) -> Result<()> {
    if !adresse_valide(c.adresse) || c.port == 0 {
        bail!("collecteur : adresse IPv4 du réseau local et port 1–65535 attendus");
    }
    controler(stockage, c)
}

/// Contrôle des fichiers d'un réglage (présents et intègres, clé client assortie au
/// certificat) : à la validation et à chaque passe de l'exportateur.
pub fn controler(stockage: &Stockage, c: &ConfigSyslog) -> Result<()> {
    if c.port == 0 {
        bail!("collecteur : port 1–65535 attendu");
    }
    let d = dossier(stockage)?;
    match c.mode {
        Mode::Tls => {
            let nom = c
                .nom
                .as_deref()
                .context("TLS : nom attendu du collecteur requis")?;
            if !nom_valide(nom) {
                bail!("TLS : nom du collecteur invalide (nom DNS en minuscules ou adresse IP)");
            }
            let ac =
                c.ac.as_deref()
                    .filter(|h| hex64(h))
                    .context("TLS : AC du collecteur requise")?;
            let pem = lire_borne(&d.join(format!("ac-{ac}.pem")), PEM_MAX)?
                .context("TLS : AC du collecteur absente")?;
            if sha256_hex(&pem) != ac {
                bail!("TLS : fichier de l'AC du collecteur modifié");
            }
            certificats(&pem)?;
            if let Some(h) = &c.certificat_client {
                if !hex64(h) {
                    bail!("certificat client invalide");
                }
                verifier_client(&d, h)?;
            }
        }
        Mode::TcpClair | Mode::UdpClair => {
            if c.nom.is_some() || c.ac.is_some() || c.certificat_client.is_some() {
                bail!("mode en clair : ni AC, ni nom, ni certificat client");
            }
        }
    }
    Ok(())
}

/// Fichier `actif.json` : réglage en vigueur (`None` : export désactivé).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actif {
    pub version: u16,
    pub config: Option<ConfigSyslog>,
    pub regle_le: u64,
    pub par: String,
}

pub fn lire_actif(stockage: &Stockage) -> Result<Option<Actif>> {
    let Some(o) = lire_borne(&dossier(stockage)?.join("actif.json"), 4096)? else {
        return Ok(None);
    };
    let a: Actif = serde_json::from_slice(&o).context("syslog/actif.json illisible")?;
    if a.version != 1 {
        bail!("syslog/actif.json : version inconnue");
    }
    Ok(Some(a))
}

/// Ligne lue par `barbacane-syslog-pare-feu` (root) : `aucun` ou `tcp|udp ADRESSE PORT`.
pub fn ligne_pare_feu(c: Option<&ConfigSyslog>) -> String {
    match c {
        None => "aucun\n".into(),
        Some(c) => format!(
            "{} {} {}\n",
            if c.mode == Mode::UdpClair {
                "udp"
            } else {
                "tcp"
            },
            c.adresse,
            c.port
        ),
    }
}

/// Applique un réglage validé (deux administrateurs) : audit d'abord, puis `actif.json` et la
/// ligne du pare-feu.
pub fn appliquer(
    stockage: &Stockage,
    c: Option<ConfigSyslog>,
    t: u64,
    acteur: &str,
    par: &str,
) -> Result<()> {
    if let Some(c) = &c {
        controler_demande(stockage, c)?;
    }
    let detail = c
        .as_ref()
        .map(ConfigSyslog::cible)
        .unwrap_or_else(|| "desactive".into());
    stockage.auditer(
        acteur,
        Evenement::Syslog {
            action: "configuration".into(),
            detail: detail.clone(),
        },
    )?;
    if c.as_ref().is_some_and(|c| c.mode.clair()) {
        stockage.auditer(
            acteur,
            Evenement::Syslog {
                action: "clair".into(),
                detail,
            },
        )?;
    }
    let d = dossier(stockage)?;
    ecrire_atomique(&d.join("pare-feu"), ligne_pare_feu(c.as_ref()).as_bytes())?;
    ecrire_atomique(
        &d.join("actif.json"),
        &serde_json::to_vec_pretty(&Actif {
            version: 1,
            config: c,
            regle_le: t,
            par: par.into(),
        })?,
    )?;
    Ok(())
}

// ───────────────────────────── État et curseur ───────────────────────────────────────────────

/// État de l'exportateur (`etat.json`), affiché dans la Console.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Etat {
    /// `desactive`, `ok`, `injoignable`.
    pub etat: String,
    pub cible: Option<String>,
    /// Dernier événement dont la remise est confirmée.
    pub curseur: u64,
    pub dernier: u64,
    pub en_attente: u64,
    pub debordement: bool,
    pub derniere_erreur: Option<String>,
    /// Début de l'état courant.
    pub depuis: u64,
    pub maj_le: u64,
    /// Dernière remise confirmée.
    pub remis_le: Option<u64>,
    /// Événements purgés avant remise (depuis la mise en service).
    pub pertes: u64,
}

pub fn lire_etat(stockage: &Stockage) -> Result<Option<Etat>> {
    match lire_borne(&dossier(stockage)?.join("etat.json"), 8192)? {
        None => Ok(None),
        Some(o) => Ok(Some(
            serde_json::from_slice(&o).context("syslog/etat.json illisible")?,
        )),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Curseur {
    /// Cible du curseur : une nouvelle cible reçoit tout le journal conservé.
    pub cible: String,
    /// Dernier événement dont la remise est confirmée.
    pub remis: u64,
    /// Plus grand numéro déjà écrit vers le collecteur sans confirmation : renvoyé avec
    /// `reprise="1"`.
    pub ecrit: u64,
}

// ───────────────────────────── Lecture du journal (file) ──────────────────────────────────────

/// Lot d'événements à remettre.
#[derive(Debug, Default)]
pub struct Lot {
    /// Événements purgés avant remise (premier, dernier).
    pub perte: Option<(u64, u64)>,
    pub structures: Vec<Structure>,
    /// Dernier numéro du journal.
    pub dernier: u64,
}

/// Lit au plus `max` événements de numéro > `apres` dans tous les fichiers du journal ;
/// signale ceux qui ont été purgés avant d'être remis.
pub fn lire_lot(journal: &Journal, serveur: &str, apres: u64, max: usize) -> Result<Lot> {
    let mut lot = Lot::default();
    let l = journal.lire_depuis(apres, max)?;
    if l.premier > 0 && apres + 1 < l.premier {
        lot.perte = Some((apres + 1, l.premier - 1));
    }
    lot.dernier = l.dernier;
    for ligne in &l.lignes {
        lot.structures.push(structurer(ligne, serveur)?);
    }
    Ok(lot)
}

// ───────────────────────────── Transport ──────────────────────────────────────────────────────

/// Configuration TLS du client (TLS 1.3, suites D6, AC du collecteur, mTLS facultatif).
pub fn config_tls(stockage: &Stockage, c: &ConfigSyslog) -> Result<Arc<rustls::ClientConfig>> {
    controler(stockage, c)?;
    let d = dossier(stockage)?;
    let ac = c.ac.as_deref().context("AC")?;
    let mut racines = rustls::RootCertStore::empty();
    for cert in certificats(&std::fs::read(d.join(format!("ac-{ac}.pem")))?)? {
        racines.add(cert).context("AC du collecteur refusée")?;
    }
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(crate::fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(racines);
    let tls = match &c.certificat_client {
        None => b.with_no_client_auth(),
        Some(h) => {
            let chaine = certificats(&std::fs::read(d.join(format!("client-{h}.pem")))?)?;
            let cle = PrivateKeyDer::from_pem_slice(&std::fs::read(d.join("client.cle.pem"))?)
                .context("clé client illisible")?;
            b.with_client_auth_cert(chaine, cle)?
        }
    };
    Ok(Arc::new(tls))
}

fn trame(m: &[u8]) -> Vec<u8> {
    let mut t = format!("{} ", m.len()).into_bytes();
    t.extend_from_slice(m);
    t
}

/// Attend la fermeture du collecteur après la nôtre (preuve que tout ce qui précède notre FIN
/// a été lu).
fn attendre_fermeture(lecteur: &mut impl Read) -> Result<()> {
    let mut tampon = [0u8; 512];
    loop {
        match lecteur.read(&mut tampon) {
            Ok(0) => return Ok(()),
            Ok(_) => continue, // un collecteur n'envoie rien ; ignoré
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                bail!("remise non confirmée : le collecteur n'a pas fermé la connexion")
            }
            Err(e) => return Err(e).context("fermeture par le collecteur"),
        }
    }
}

/// Envoie un lot ; `Ok(())` seulement si sa remise est confirmée (TCP, TLS) ou s'il est parti
/// (UDP). `ecrit` reçoit le plus grand numéro écrit (même sans confirmation).
pub fn envoyer(
    stockage: &Stockage,
    c: &ConfigSyslog,
    messages: &[(u64, Vec<u8>)],
    ecrit: &mut u64,
) -> Result<()> {
    let cible = SocketAddr::V4(SocketAddrV4::new(c.adresse, c.port));
    match c.mode {
        Mode::UdpClair => {
            let s = UdpSocket::bind("0.0.0.0:0")?;
            for (n, m) in messages {
                s.send_to(m, cible).context("envoi UDP")?;
                *ecrit = (*ecrit).max(*n);
            }
            Ok(())
        }
        Mode::TcpClair => {
            let mut s = TcpStream::connect_timeout(&cible, DELAI_CONNEXION)
                .context("connexion au collecteur")?;
            s.set_write_timeout(Some(DELAI_FERMETURE))?;
            s.set_read_timeout(Some(DELAI_FERMETURE))?;
            for (n, m) in messages {
                s.write_all(&trame(m)).context("envoi au collecteur")?;
                *ecrit = (*ecrit).max(*n);
            }
            s.flush()?;
            s.shutdown(Shutdown::Write)?;
            attendre_fermeture(&mut s)
        }
        Mode::Tls => {
            let tls = config_tls(stockage, c)?;
            let nom =
                ServerName::try_from(c.nom.clone().context("nom")?).context("nom du collecteur")?;
            let tcp = TcpStream::connect_timeout(&cible, DELAI_CONNEXION)
                .context("connexion au collecteur")?;
            tcp.set_write_timeout(Some(DELAI_FERMETURE))?;
            tcp.set_read_timeout(Some(DELAI_FERMETURE))?;
            let conn = rustls::ClientConnection::new(tls, nom)?;
            let mut s = rustls::StreamOwned::new(conn, tcp);
            // Poignée de main complète (certificat du collecteur vérifié) avant tout envoi.
            while s.conn.is_handshaking() {
                s.conn
                    .complete_io(&mut s.sock)
                    .context("poignée de main TLS avec le collecteur")?;
            }
            for (n, m) in messages {
                s.write_all(&trame(m)).context("envoi au collecteur")?;
                *ecrit = (*ecrit).max(*n);
            }
            s.flush()?;
            s.conn.send_close_notify();
            s.flush()?;
            s.sock.shutdown(Shutdown::Write)?;
            attendre_fermeture(&mut s)
        }
    }
}

// ───────────────────────────── Exportateur ────────────────────────────────────────────────────

/// Exportateur : une passe = au plus un lot. Gardé entre deux passes : rien (tout est relu du
/// disque : un redémarrage reprend exactement au curseur).
pub struct Exportateur {
    pub stockage: Stockage,
    pub serveur: String,
    /// Seuil de débordement ([`FILE_MAX`] en service).
    pub file_max: u64,
}

fn ecrire_json<T: Serialize>(chemin: &Path, v: &T) -> Result<()> {
    ecrire_atomique(chemin, &serde_json::to_vec_pretty(v)?)
}

fn lire_curseur(d: &Path) -> Result<Option<Curseur>> {
    match lire_borne(&d.join("curseur.json"), 4096)? {
        None => Ok(None),
        Some(o) => Ok(Some(
            serde_json::from_slice(&o).context("syslog/curseur.json illisible")?,
        )),
    }
}

/// Résultat d'une passe.
#[derive(Debug, PartialEq, Eq)]
pub enum Passe {
    Desactive,
    /// Rien à envoyer.
    AJour,
    /// Lot remis : nombre de messages.
    Remis(usize),
    /// Échec (collecteur injoignable, remise non confirmée…).
    Echec(String),
}

impl Exportateur {
    fn auditer(&self, action: &str, detail: &str) -> Result<()> {
        self.stockage.auditer(
            "syslog",
            Evenement::Syslog {
                action: action.into(),
                detail: detail.into(),
            },
        )
    }

    /// Une passe : lit le réglage, le curseur et au plus un lot, l'envoie, met à jour curseur et
    /// état. Les changements d'état (injoignable, reprise, débordement, perte) sont audités une
    /// fois par épisode.
    pub fn passe(&self, t: u64) -> Result<Passe> {
        let d = dossier(&self.stockage)?;
        let precedent = lire_etat(&self.stockage).ok().flatten().unwrap_or_default();
        let Some(c) = lire_actif(&self.stockage)?.and_then(|a| a.config) else {
            if precedent.etat != "desactive" {
                ecrire_json(
                    &d.join("etat.json"),
                    &Etat {
                        etat: "desactive".into(),
                        depuis: t,
                        maj_le: t,
                        ..Default::default()
                    },
                )?;
            }
            return Ok(Passe::Desactive);
        };
        let cible = c.cible();
        let mut curseur = match lire_curseur(&d)? {
            Some(k) if k.cible == cible => k,
            _ => Curseur {
                cible: cible.clone(),
                remis: 0,
                ecrit: 0,
            },
        };
        let journal = self.stockage.journal_audit();
        let lot = lire_lot(&journal, &self.serveur, curseur.remis, LOT_MAX)?;
        let mut etat = Etat {
            etat: precedent.etat.clone(),
            cible: Some(cible.clone()),
            curseur: curseur.remis,
            dernier: lot.dernier,
            en_attente: lot.dernier.saturating_sub(curseur.remis),
            debordement: precedent.debordement && precedent.cible.as_deref() == Some(&cible),
            derniere_erreur: precedent.derniere_erreur.clone(),
            depuis: if precedent.cible.as_deref() == Some(&cible) {
                precedent.depuis
            } else {
                t
            },
            maj_le: t,
            remis_le: precedent.remis_le,
            pertes: precedent.pertes,
        };
        if let Some((a, b)) = lot.perte {
            self.auditer("perte", &format!("{a}-{b}"))?;
            etat.pertes += b - a + 1;
            curseur.remis = b;
            curseur.ecrit = curseur.ecrit.max(b);
        }
        let debordement = etat.en_attente > self.file_max;
        if debordement && !etat.debordement {
            self.auditer("debordement", &etat.en_attente.to_string())?;
        }
        etat.debordement = debordement;
        if lot.structures.is_empty() {
            if etat.etat != "injoignable" {
                etat.etat = "ok".into();
            }
            ecrire_json(&d.join("curseur.json"), &curseur)?;
            ecrire_json(&d.join("etat.json"), &etat)?;
            return Ok(Passe::AJour);
        }
        let messages: Vec<(u64, Vec<u8>)> = lot
            .structures
            .iter()
            .map(|s| {
                let n = s.enregistrement.n;
                (n, message_syslog(s, &self.serveur, n <= curseur.ecrit))
            })
            .collect();
        let mut ecrit = curseur.ecrit;
        let r = envoyer(&self.stockage, &c, &messages, &mut ecrit);
        curseur.ecrit = ecrit;
        let passe = match r {
            Ok(()) => {
                let dernier = messages.last().map(|m| m.0).unwrap_or(curseur.remis);
                curseur.remis = dernier;
                if etat.etat == "injoignable" {
                    self.auditer("reprise", &format!("{}", dernier))?;
                }
                if etat.etat != "ok" {
                    etat.depuis = t;
                }
                etat.etat = "ok".into();
                etat.derniere_erreur = None;
                etat.remis_le = Some(t);
                Passe::Remis(messages.len())
            }
            Err(e) => {
                let m = format!("{e:#}");
                if etat.etat != "injoignable" {
                    self.auditer("injoignable", &cible)?;
                    etat.depuis = t;
                }
                etat.etat = "injoignable".into();
                etat.derniere_erreur = Some(m.chars().take(300).collect());
                Passe::Echec(m)
            }
        };
        etat.curseur = curseur.remis;
        etat.en_attente = lot.dernier.saturating_sub(curseur.remis);
        ecrire_json(&d.join("curseur.json"), &curseur)?;
        ecrire_json(&d.join("etat.json"), &etat)?;
        Ok(passe)
    }
}
