//! Interface web d'administration du serveur Barbacane (`docs/suite/serveur-web.md`).
//!
//! - Écoute d'**administration** distincte de la passerelle ; TLS 1.3 seul (D6) ; certificat
//!   client d'administrateur **obligatoire** (CA « administrateurs », CRL relue à chaque
//!   connexion, fail-closed), pas de reprise de session TLS ;
//! - second facteur : mot de passe Argon2id du compte **lié à ce certificat** ;
//! - rôles administrateur, opérateur, auditeur, lecture seule (matrice : `comptes::Role::peut`,
//!   contrôlée AVANT la lecture du corps par [`droit_route`]), sessions courtes, jeton anti-CSRF ;
//! - comptes gérés dans la Console (`admin_comptes`), double validation (`validations`) ;
//! - pages sans JavaScript, échappées par construction (`html`), en-têtes de sécurité (`http`) ;
//! - chaque action passe par `barbacane_passerelle::admin::Admin` (journal d'audit chaîné,
//!   acteur `web:<compte>`).
#![forbid(unsafe_code)]

pub mod admin_comptes;
pub mod annuaire;
pub mod comptes;
pub mod html;
pub mod http;
pub mod iso_bornes;
pub mod multipart;
pub mod pages;
pub mod pages_comptes;
pub mod pages_passages;
pub mod pages_utilisateurs;
pub mod pkcs12;
pub mod quarantaine;
pub mod sessions;
pub mod validations;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use barbacane_audit::{ClePublique, Enregistrement, Evenement};
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::fournisseur;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::passages::Passages;
use barbacane_passerelle::registre::{Motif, StatutBorne, StatutDemande};
use barbacane_passerelle::utilisateurs::{BaseUtilisateurs, Utilisateurs, nom_mode};
use barbacane_protocole::DUREE_JETON_S;
use barbacane_protocole::maj::{TAILLE_BCU_MAX, TAILLE_SIGNATURE_MAX};
use barbacane_protocole::utilisateurs::{
    EntreeNonEnrolees, ModeUtilisateurs, normaliser_identifiant,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use x509_parser::prelude::{ASN1Time, FromDer};
use x509_parser::revocation_list::CertificateRevocationList;

use crate::admin_comptes::{CaAdmin, RENOUVELLEMENT_CRL_S, RemiseP12};
use crate::comptes::{
    Comptes, Droit, Role, Verrous, empreinte_certificat, identifiant_valide, lire_comptes,
};
use crate::http::{Refus, Reponse, Requete, lire_entete, lire_formulaire};
use crate::multipart::{Multipart, frontiere};
use crate::pages::{Contexte, JetonAffiche, Rubrique};
use crate::sessions::{COOKIE, Session, Sessions, cookie, cookie_efface, egal};

/// Connexions simultanées au plus (quelques administrateurs).
pub const CONNEXIONS_MAX: usize = 32;
/// Durée TOTALE d'une connexion (poignée de main, requête, réponse).
pub const DELAI_TOTAL: Duration = Duration::from_secs(30);
/// Délai d'inactivité d'une lecture ou d'une écriture.
const DELAI: Duration = Duration::from_secs(10);
/// Débit minimal d'un dépôt : la durée admise croît d'1 s par tranche de ce nombre d'octets.
pub const DEBIT_MIN_DEPOT: u64 = 512 * 1024;
/// Enregistrements d'audit par page.
pub const AUDIT_PAR_PAGE: usize = 50;

// ───────────────────────────── Configuration ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub adresse: IpAddr,
    /// Port de l'écoute d'administration (différent de ceux de la passerelle).
    pub port: u16,
    pub chaine_serveur: PathBuf,
    pub cle_serveur: PathBuf,
    /// CA « administrateurs » : seule ancre des certificats clients.
    pub ca_administrateurs: PathBuf,
    pub crl_administrateurs: PathBuf,
    /// Fichier des comptes (0600).
    pub comptes: PathBuf,
    /// Configuration de la passerelle (registre, CA bornes).
    pub passerelle: PathBuf,
    /// Clé publique d'audit (vérification de la chaîne).
    pub cle_audit_publique: PathBuf,
    /// Configuration de l'annuaire LDAPS (facultative, `annuaire::ConfigAnnuaire`).
    pub annuaire: Option<PathBuf>,
    /// ISO des bornes embarquées (facultatif ; `iso_bornes::DOSSIER_DEFAUT`).
    pub iso_bornes: PathBuf,
    /// Outil de remaster (facultatif ; `iso_bornes::OUTIL_DEFAUT`).
    pub outil_iso_borne: PathBuf,
    /// Clé de la CA « administrateurs » (facultative ; absente ou fichier inexistant : la
    /// Console n'émet aucun certificat). Avec elle, la Console publie la CRL des
    /// administrateurs (`<registre>/administrateurs/crl-administrateurs.pem`).
    pub cle_ca_administrateurs: Option<PathBuf>,
}

impl Config {
    pub fn lire(chemin: &Path) -> Result<Config> {
        let texte = std::fs::read_to_string(chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        Config::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<Config> {
        let mut v: BTreeMap<&str, &str> = BTreeMap::new();
        const CLES: &[&str] = &[
            "adresse",
            "port",
            "chaine_serveur",
            "cle_serveur",
            "ca_administrateurs",
            "crl_administrateurs",
            "comptes",
            "passerelle",
            "cle_audit_publique",
            "annuaire",
            "iso_bornes",
            "outil_iso_borne",
            "cle_ca_administrateurs",
        ];
        for (n, ligne) in texte.lines().enumerate() {
            let ligne = ligne.trim();
            if ligne.is_empty() || ligne.starts_with('#') {
                continue;
            }
            let Some((k, val)) = ligne.split_once('=') else {
                bail!("ligne {} : « cle = valeur » attendu", n + 1);
            };
            let k = k.trim();
            if !CLES.contains(&k) {
                bail!("ligne {} : clé inconnue « {k} »", n + 1);
            }
            if v.insert(k, val.trim()).is_some() {
                bail!("ligne {} : clé répétée", n + 1);
            }
        }
        let obtenir = |k: &str| v.get(k).copied().with_context(|| format!("{k} absent"));
        let chemin = |k: &str| obtenir(k).map(PathBuf::from);
        let port: u16 = obtenir("port")?.parse().context("port")?;
        if port == 0 {
            bail!("port 0 refusé");
        }
        Ok(Config {
            adresse: obtenir("adresse")?.parse().context("adresse")?,
            port,
            chaine_serveur: chemin("chaine_serveur")?,
            cle_serveur: chemin("cle_serveur")?,
            ca_administrateurs: chemin("ca_administrateurs")?,
            crl_administrateurs: chemin("crl_administrateurs")?,
            comptes: chemin("comptes")?,
            passerelle: chemin("passerelle")?,
            cle_audit_publique: chemin("cle_audit_publique")?,
            annuaire: v.get("annuaire").map(PathBuf::from),
            iso_bornes: PathBuf::from(
                v.get("iso_bornes")
                    .copied()
                    .unwrap_or(iso_bornes::DOSSIER_DEFAUT),
            ),
            outil_iso_borne: PathBuf::from(
                v.get("outil_iso_borne")
                    .copied()
                    .unwrap_or(iso_bornes::OUTIL_DEFAUT),
            ),
            cle_ca_administrateurs: v.get("cle_ca_administrateurs").map(PathBuf::from),
        })
    }

    pub fn adresse_ecoute(&self) -> SocketAddr {
        SocketAddr::new(self.adresse, self.port)
    }
}

// ───────────────────────────── TLS ────────────────────────────────────────────────────────────

/// Lit les CRL d'un fichier PEM (au moins une).
fn lire_crls(chemin: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let crls = CertificateRevocationListDer::pem_file_iter(chemin)
        .with_context(|| format!("CRL {}", chemin.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("CRL illisible")?;
    if crls.is_empty() {
        bail!("aucune CRL dans {}", chemin.display());
    }
    Ok(crls)
}

/// Émetteur (DER) et fin de validité d'une CRL.
fn crl_emetteur_fin(crl: &[u8]) -> Result<(Vec<u8>, Option<ASN1Time>)> {
    let (_, a) =
        CertificateRevocationList::from_der(crl).map_err(|e| anyhow::anyhow!("CRL : {e}"))?;
    Ok((a.issuer().as_raw().to_vec(), a.next_update()))
}

/// Refuse si une CRL est sans date de fin ou expirée (fail-closed).
fn controler_crls(crls: &[CertificateRevocationListDer<'static>]) -> Result<()> {
    let t = ASN1Time::now();
    for crl in crls {
        match crl_emetteur_fin(crl)?.1 {
            Some(fin) if fin > t => {}
            Some(fin) => bail!("CRL des administrateurs expirée depuis {fin}"),
            None => bail!("CRL sans date de prochaine mise à jour"),
        }
    }
    Ok(())
}

/// Configuration TLS de l'écoute d'administration avec ces CRL (contrôlées ici).
pub fn config_tls(
    config: &Config,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<Arc<ServerConfig>> {
    controler_crls(&crls)?;
    let mut ancres = RootCertStore::empty();
    for c in
        CertificateDer::pem_file_iter(&config.ca_administrateurs).context("CA administrateurs")?
    {
        ancres.add(c.context("CA administrateurs illisible")?)?;
    }
    if ancres.is_empty() {
        bail!("aucune CA administrateurs");
    }
    let verificateur =
        WebPkiClientVerifier::builder_with_provider(Arc::new(ancres), Arc::new(fournisseur()))
            .with_crls(crls)
            .enforce_revocation_expiration()
            .build()?;
    let chaine = CertificateDer::pem_file_iter(&config.chaine_serveur)
        .context("chaîne serveur")?
        .collect::<Result<Vec<_>, _>>()
        .context("chaîne serveur illisible")?;
    let cle = PrivateKeyDer::from_pem_file(&config.cle_serveur).context("clé serveur")?;
    let mut tls = ServerConfig::builder_with_provider(Arc::new(fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verificateur)
        .with_single_cert(chaine, cle)?;
    // Pas de reprise de session : chaque connexion revérifie le certificat et la CRL.
    tls.session_storage = Arc::new(NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

/// Charge la CA « administrateurs » si sa clé est sur le serveur : le certificat est cherché
/// parmi les ancres de `ca_administrateurs` (celui qui correspond à la clé).
fn charger_ca_admin(config: &Config, registre: &Path) -> Result<Option<CaAdmin>> {
    let Some(cle) = config
        .cle_ca_administrateurs
        .as_ref()
        .filter(|c| c.exists())
    else {
        return Ok(None);
    };
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(cle)?.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} : clé de la CA des administrateurs accessible à d'autres comptes (0400 attendu)",
                cle.display()
            );
        }
    }
    let cle_pem = std::fs::read_to_string(cle)
        .with_context(|| format!("clé de la CA des administrateurs {}", cle.display()))?;
    for c in CertificateDer::pem_file_iter(&config.ca_administrateurs)? {
        let der = c?;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            data_encoding::BASE64.encode(&der)
        );
        if let Ok(ca) = barbacane_passerelle::ca::CaBornes::depuis_pem(&pem, &cle_pem) {
            let (_, x) = x509_parser::prelude::X509Certificate::from_der(&der)
                .map_err(|e| anyhow::anyhow!("CA administrateurs : {e}"))?;
            return Ok(Some(CaAdmin {
                ca,
                sujet: x.subject().as_raw().to_vec(),
                cert_der: der.to_vec(),
                crl: Comptes::ouvrir(registre)?
                    .dossier()
                    .join("crl-administrateurs.pem"),
            }));
        }
    }
    bail!(
        "la clé de la CA des administrateurs ne correspond à aucun certificat de ca_administrateurs"
    )
}

/// Flux TCP à échéance totale.
pub(crate) struct Flux {
    flux: TcpStream,
    fin: Instant,
}

impl Flux {
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

impl Read for Flux {
    fn read(&mut self, t: &mut [u8]) -> std::io::Result<usize> {
        self.flux.set_read_timeout(Some(self.reste()?))?;
        self.flux.read(t)
    }
}

impl Write for Flux {
    fn write(&mut self, o: &[u8]) -> std::io::Result<usize> {
        self.flux.set_write_timeout(Some(self.reste()?))?;
        self.flux.write(o)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flux.flush()
    }
}

// ───────────────────────────── Ressources statiques ───────────────────────────────────────────

/// Feuille de style : jetons de la charte (`docs/charte/web/jetons.css`, polices servies par
/// le binaire) puis composants web.
fn feuille_de_style() -> &'static str {
    static CSS: OnceLock<String> = OnceLock::new();
    CSS.get_or_init(|| {
        let jetons = include_str!("../../../docs/charte/web/jetons.css")
            .replace("../fonts/", "/statique/polices/");
        format!("{jetons}\n{}", include_str!("../statique/composants.css"))
    })
}

/// Ressource statique embarquée (feuille de style, polices, symbole).
pub fn statique(chemin: &str) -> Option<Reponse> {
    let (type_contenu, corps): (&'static str, &'static [u8]) = match chemin {
        "/statique/barbacane.css" => ("text/css; charset=utf-8", feuille_de_style().as_bytes()),
        "/statique/symbole.svg" => (
            "image/svg+xml",
            include_bytes!("../../../docs/charte/logos/barbacane-symbole.svg"),
        ),
        "/statique/polices/AtkinsonHyperlegible-Regular.ttf" => (
            "font/ttf",
            include_bytes!("../../../docs/charte/fonts/AtkinsonHyperlegible-Regular.ttf"),
        ),
        "/statique/polices/AtkinsonHyperlegible-Bold.ttf" => (
            "font/ttf",
            include_bytes!("../../../docs/charte/fonts/AtkinsonHyperlegible-Bold.ttf"),
        ),
        "/statique/polices/BarlowCondensed-SemiBold.ttf" => (
            "font/ttf",
            include_bytes!("../../../docs/charte/fonts/BarlowCondensed-SemiBold.ttf"),
        ),
        "/statique/polices/BarlowCondensed-Bold.ttf" => (
            "font/ttf",
            include_bytes!("../../../docs/charte/fonts/BarlowCondensed-Bold.ttf"),
        ),
        "/statique/polices/JetBrainsMono.ttf" => (
            "font/ttf",
            include_bytes!("../../../docs/charte/fonts/JetBrainsMono.ttf"),
        ),
        _ => return None,
    };
    Some(Reponse {
        statut: 200,
        type_contenu,
        corps: corps.to_vec(),
        entetes: Vec::new(),
        statique: true,
    })
}

// ───────────────────────────── Service ────────────────────────────────────────────────────────

/// Routes de dépôt de fichiers (`multipart/form-data`, durée allongée selon la taille).
const ROUTES_DEPOT: &[&str] = &["/maj/depot", "/maj/plancher"];

pub struct Web {
    pub config: Config,
    pub passerelle: barbacane_passerelle::Config,
    sessions: Sessions,
    pub(crate) verrous: Verrous,
    pub(crate) comptes: Comptes,
    pub(crate) ca_admin: Option<CaAdmin>,
    /// `.p12` en attente de leur téléchargement unique (jamais sur disque).
    pub(crate) remises: Mutex<std::collections::HashMap<String, RemiseP12>>,
    pub(crate) crl_verrou: Mutex<()>,
}

/// Utilisateur authentifié de la requête.
pub(crate) struct Utilisateur {
    id_session: String,
    session: Session,
    pub(crate) compte: String,
    pub(crate) role: Role,
    /// Mot de passe provisoire : seul son changement est permis.
    pub(crate) doit_changer: bool,
}

impl Utilisateur {
    fn contexte(&self, t: u64) -> Contexte<'_> {
        Contexte {
            compte: &self.compte,
            role: self.role,
            csrf: &self.session.csrf,
            maintenant: t,
        }
    }

    pub(crate) fn acteur(&self) -> String {
        format!("web:{}", self.compte)
    }
}

/// Droit exigé par une route (refus par défaut : une route POST inconnue exige
/// [`Droit::Administrer`]). Matrice : `docs/suite/comptes-administrateurs.md` §2.
pub fn droit_route(methode: &str, chemin: &str) -> Droit {
    match (methode, chemin) {
        ("GET", "/utilisateurs" | "/passages" | "/passages/detail") => Droit::ConsulterPersonnel,
        ("GET", "/audit" | "/audit/verification") => Droit::ConsulterJournal,
        ("GET", "/comptes") => Droit::ConsulterComptes,
        ("GET", "/enrolement/demande" | "/bornes/revoquer" | iso_bornes::ROUTE) => Droit::Exploiter,
        ("GET", quarantaine::ROUTE) => Droit::Administrer,
        ("GET", _) => Droit::Consulter,
        ("POST", "/deconnexion" | "/mot-de-passe") => Droit::Consulter,
        (
            "POST",
            "/enrolement/jeton"
            | "/enrolement/valider"
            | "/enrolement/refuser"
            | "/bornes/revoquer"
            | "/maj/diffuser"
            | "/maj/depot"
            | "/maj/plancher"
            | iso_bornes::ROUTE_PREPARER
            | iso_bornes::ROUTE_TELECHARGER,
        ) => Droit::Exploiter,
        ("POST", c)
            if c.starts_with("/utilisateurs/")
                || c.starts_with("/sites/")
                || c.starts_with("/cles-usb/") =>
        {
            Droit::Exploiter
        }
        _ => Droit::Administrer,
    }
}

pub(crate) fn page(statut: u16, html: String) -> Reponse {
    Reponse::html(statut, html)
}

pub(crate) fn refus(statut: u16, message: &str) -> Reponse {
    page(statut, pages::erreur(statut, message))
}

impl Web {
    /// Contrôles au démarrage : TLS (donc CRL valide), comptes (migrés depuis la v2.1.0 au
    /// premier démarrage), passerelle, clé d'audit.
    pub fn nouveau(config: Config) -> Result<Arc<Web>> {
        Web::preparer(config, true)
    }

    /// Mêmes contrôles sans rien écrire (`--verifier-config`) : base des comptes lue si elle
    /// existe, sinon le fichier de la v2.1.0 qui serait importé.
    pub fn verifier(config: Config) -> Result<()> {
        Web::preparer(config, false).map(|_| ())
    }

    fn preparer(config: Config, ecrire: bool) -> Result<Arc<Web>> {
        ClePublique::lire(&config.cle_audit_publique).context("clé publique d'audit")?;
        let passerelle = barbacane_passerelle::Config::lire(&config.passerelle)?;
        if passerelle.port == config.port || passerelle.port_enrolement == config.port {
            bail!(
                "l'écoute de la Console doit être distincte de celles de la Liaison bornes (passerelle)"
            );
        }
        let admin = Admin::ouvrir(passerelle.clone())?;
        Utilisateurs::ouvrir(&admin.stockage)?.lire()?;
        let comptes = Comptes::ouvrir(admin.stockage.dossier())?;
        if !comptes.existe() {
            if ecrire {
                let n = comptes.migrer(&config.comptes, maintenant(), |n| {
                    admin.stockage.auditer(
                        &barbacane_passerelle::admin::acteur_local(),
                        Evenement::Administration {
                            action: format!("migration-comptes-2.1.0:{n}"),
                        },
                    )
                })?;
                if let Some(n) = n {
                    eprintln!(
                        "barbacane-web : {n} compte(s) importé(s) de {} (format v2.1.0) dans {} ; ce fichier n'est plus lu",
                        config.comptes.display(),
                        comptes.fichier().display()
                    );
                }
            } else {
                lire_comptes(&config.comptes)?;
            }
        } else {
            comptes.lire()?;
        }
        let ca_admin = charger_ca_admin(&config, admin.stockage.dossier())?;
        if let Some(a) = &config.annuaire
            && annuaire::ConfigAnnuaire::lire(a)?.tls12
        {
            annuaire::auditer_tls12(
                &admin.stockage,
                &barbacane_passerelle::admin::acteur_local(),
            )?;
        }
        let web = Web {
            config,
            passerelle,
            sessions: Sessions::default(),
            verrous: Verrous::default(),
            comptes,
            ca_admin,
            remises: Mutex::new(Default::default()),
            crl_verrou: Mutex::new(()),
        };
        if ecrire {
            web.tls()?;
        } else {
            web.crls(false).and_then(|c| config_tls(&web.config, c))?;
        }
        Ok(Arc::new(web))
    }

    pub(crate) fn stockage(&self) -> Result<barbacane_passerelle::registre::Stockage> {
        barbacane_passerelle::registre::Stockage::ouvrir(&self.passerelle.registre)
    }

    /// CRL de la poignée de main : celles du fichier configuré, sauf celles de la CA gérée par
    /// la Console, remplacées par la CRL que la Console publie (initialisée depuis la CRL de
    /// la cérémonie, republiée quand il lui reste moins de 4 jours si `renouveler`).
    fn crls(&self, renouveler: bool) -> Result<Vec<CertificateRevocationListDer<'static>>> {
        let mut crls = lire_crls(&self.config.crl_administrateurs)?;
        let Some(ca) = &self.ca_admin else {
            return Ok(crls);
        };
        let (de_la_ca, autres): (Vec<_>, Vec<_>) = crls
            .drain(..)
            .partition(|c| crl_emetteur_fin(c).is_ok_and(|(e, _)| e == ca.sujet));
        let mut crls = autres;
        let _v = self.crl_verrou.lock().unwrap_or_else(|e| e.into_inner());
        // CRL gérée présente mais illisible : refus (fail-closed), jamais de republication qui
        // perdrait ses révocations.
        let actuelle = if ca.crl.exists() {
            let c = CertificateRevocationListDer::pem_file_iter(&ca.crl)
                .context("CRL des administrateurs gérée par la Console")?
                .next()
                .context("CRL des administrateurs gérée par la Console : vide")?
                .context("CRL des administrateurs gérée par la Console : illisible")?;
            crl_emetteur_fin(&c)?;
            Some(c)
        } else {
            None
        };
        let t = maintenant();
        let a_publier = match &actuelle {
            None => true,
            Some(c) => crl_emetteur_fin(c)?
                .1
                .is_none_or(|fin| fin.timestamp() < (t + RENOUVELLEMENT_CRL_S) as i64),
        };
        if a_publier && renouveler {
            if actuelle.is_none()
                && let Some(c) = de_la_ca.first()
            {
                // Reprise des révocations de la cérémonie.
                let pem = format!(
                    "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
                    data_encoding::BASE64.encode(c)
                );
                barbacane_passerelle::outils::ecrire_atomique(&ca.crl, pem.as_bytes())?;
            }
            let n = ca.ca.publier_crl(&ca.crl, &[], 0, t)?;
            self.stockage()?.auditer(
                "web",
                Evenement::Administration {
                    action: format!("crl-administrateurs-publiee:{n}"),
                },
            )?;
        }
        match CertificateRevocationListDer::pem_file_iter(&ca.crl)
            .ok()
            .and_then(|mut i| i.next())
            .and_then(|c| c.ok())
        {
            Some(c) => crls.push(c),
            // Vérification seule, CRL pas encore publiée : celle de la cérémonie.
            None => crls.extend(de_la_ca),
        }
        Ok(crls)
    }

    /// Configuration TLS (relue à chaque connexion : CRL à jour, fail-closed).
    pub fn tls(&self) -> Result<Arc<ServerConfig>> {
        config_tls(&self.config, self.crls(true)?)
    }

    fn admin(&self, u: &Utilisateur) -> Result<Admin> {
        Admin::ouvrir_pour(self.passerelle.clone(), &u.acteur())
    }

    fn auditer(&self, acteur: &str, action: &str) -> Result<()> {
        Admin::ouvrir(self.passerelle.clone())?.stockage.auditer(
            acteur,
            Evenement::Administration {
                action: action.into(),
            },
        )
    }

    /// Session authentifiée et compte toujours valide (fichier relu : retrait immédiat).
    fn utilisateur(&self, r: &Requete, empreinte: &str, t: u64) -> Option<Utilisateur> {
        let id = r.cookies.get(COOKIE)?;
        let session = self.sessions.obtenir(id, empreinte, t)?;
        let (compte, role) = session.compte.clone()?;
        let base = self.comptes.lire().ok()?;
        let k = base.compte(&compte).filter(|c| {
            c.actif && c.role == role && c.empreinte_certificat.as_deref() == Some(empreinte)
        });
        let Some(k) = k else {
            self.sessions.supprimer(id);
            return None;
        };
        Some(Utilisateur {
            id_session: id.clone(),
            session,
            compte,
            role,
            doit_changer: k.changer_mot_de_passe,
        })
    }

    /// Répond à une requête dont les en-têtes sont lus ; le corps est lu ici, après contrôle
    /// de la session et du rôle.
    fn repondre(&self, r: &Requete, flux: &mut impl Read, empreinte: &str, der: &[u8]) -> Reponse {
        let t = maintenant();
        if r.methode == "GET"
            && let Some(rep) = statique(&r.chemin)
        {
            return rep;
        }
        if r.methode == "POST"
            && r.sec_fetch_site
                .as_deref()
                .is_some_and(|s| s != "same-origin" && s != "none")
        {
            return refus(403, "Requête d'une autre origine refusée.");
        }
        match (r.methode.as_str(), r.chemin.as_str()) {
            ("GET", "/connexion") => return self.page_connexion(r, empreinte, t, None),
            ("POST", "/connexion") => {
                return self
                    .connexion(r, flux, empreinte, der, t)
                    .unwrap_or_else(|e| refus(500, &format!("{e:#}")));
            }
            _ => {}
        }
        let Some(u) = self.utilisateur(r, empreinte, t) else {
            return if r.methode == "GET" {
                Reponse::redirection("/connexion")
            } else {
                refus(403, "Session absente ou expirée : reconnectez-vous.")
            };
        };
        // Rôle vérifié AVANT la lecture du corps (matrice `droit_route`).
        if !u.role.peut(droit_route(&r.methode, &r.chemin)) {
            return refus(
                403,
                &format!("Rôle {} : action ou page non autorisée.", u.role.libelle()),
            );
        }
        // Mot de passe provisoire : rien d'autre que son changement (et la déconnexion).
        if u.doit_changer && r.chemin != "/mot-de-passe" && r.chemin != "/deconnexion" {
            return if r.methode == "GET" {
                Reponse::redirection("/mot-de-passe")
            } else {
                refus(403, "Changez d'abord votre mot de passe provisoire.")
            };
        }
        let resultat = match r.methode.as_str() {
            "GET" => self.get(r, &u, t),
            "POST" => {
                if ROUTES_DEPOT.contains(&r.chemin.as_str()) {
                    self.depot(r, flux, &u, t)
                } else {
                    match lire_formulaire(r, flux) {
                        Err(Refus(s)) => return refus(s, "Formulaire refusé."),
                        Ok(f) => {
                            if !f.get("csrf").is_some_and(|j| egal(j, &u.session.csrf)) {
                                return refus(403, "Jeton anti-CSRF absent ou invalide.");
                            }
                            self.post(r, &f, &u, t)
                        }
                    }
                }
            }
            _ => return refus(405, "Méthode refusée."),
        };
        resultat.unwrap_or_else(|e| refus(500, &format!("{e:#}")))
    }

    fn page_connexion(
        &self,
        r: &Requete,
        empreinte: &str,
        t: u64,
        erreur: Option<&str>,
    ) -> Reponse {
        if self.utilisateur(r, empreinte, t).is_some() && erreur.is_none() {
            return Reponse::redirection("/tableau");
        }
        let (id, s) = self.sessions.creer(None, empreinte, t);
        let mut rep = page(
            if erreur.is_some() { 403 } else { 200 },
            pages::connexion(&s.csrf, erreur),
        );
        rep.entetes.push(("Set-Cookie", cookie(&id)));
        rep
    }

    fn connexion(
        &self,
        r: &Requete,
        flux: &mut impl Read,
        empreinte: &str,
        der: &[u8],
        t: u64,
    ) -> Result<Reponse> {
        let pre = r
            .cookies
            .get(COOKIE)
            .and_then(|id| Some((id, self.sessions.obtenir(id, empreinte, t)?)));
        let Some((id_pre, pre)) = pre.filter(|(_, s)| s.compte.is_none()) else {
            return Ok(refus(403, "Page de connexion expirée : rechargez-la."));
        };
        let f = match lire_formulaire(r, flux) {
            Ok(f) => f,
            Err(Refus(s)) => return Ok(refus(s, "Formulaire refusé.")),
        };
        if !f.get("csrf").is_some_and(|j| egal(j, &pre.csrf)) {
            return Ok(refus(403, "Jeton anti-CSRF absent ou invalide."));
        }
        self.sessions.supprimer(id_pre);
        let ident = f.get("identifiant").map(String::as_str).unwrap_or_default();
        let mdp = f
            .get("mot_de_passe")
            .map(String::as_str)
            .unwrap_or_default();
        let ident_sur = if identifiant_valide(ident) {
            ident
        } else {
            "inconnu"
        };
        let acteur = format!("web:{ident_sur}");
        let cles = [format!("compte:{ident_sur}"), format!("cert:{empreinte}")];
        let base = self.comptes.lire()?;
        let compte = base.compte(ident).filter(|c| c.actif);
        let refuse = "Identifiant, mot de passe ou certificat refusé.";
        if self.verrous.verrouille(&cles, t) {
            self.auditer(&acteur, "connexion-verrouillee")?;
            return Ok(self.page_connexion(r, empreinte, t, Some(refuse)));
        }
        let ok = comptes::verifier_mot_de_passe(compte, mdp)
            && compte.is_some_and(|c| {
                c.empreinte_certificat
                    .as_deref()
                    .is_some_and(|e| egal(e, empreinte))
            });
        let Some(compte) = compte.filter(|_| ok) else {
            self.verrous.echec(&cles, t);
            self.auditer(&acteur, "connexion-refusee")?;
            return Ok(self.page_connexion(r, empreinte, t, Some(refuse)));
        };
        self.verrous.succes(&cles);
        self.auditer(&acteur, "connexion")?;
        // Dernier accès ; numéro de série et échéance d'un certificat antérieur à la v2.2.0.
        let (serie, fin) = x509_parser::prelude::X509Certificate::from_der(der)
            .map(|(_, x)| {
                (
                    barbacane_passerelle::outils::serie_hex(x.raw_serial()),
                    u64::try_from(x.validity().not_after.timestamp()).ok(),
                )
            })
            .map_err(|e| anyhow::anyhow!("certificat client : {e}"))?;
        self.comptes.transaction(|b| {
            if let Some(k) = b.compte_mut(&compte.identifiant) {
                k.dernier_acces = Some(t);
                if k.serie_certificat.is_none() {
                    k.serie_certificat = Some(serie);
                    k.certificat_expire_le = fin;
                }
            }
            Ok(())
        })?;
        let (id, _) = self.sessions.creer(
            Some((compte.identifiant.clone(), compte.role)),
            empreinte,
            t,
        );
        let mut rep = Reponse::redirection("/tableau");
        rep.entetes.push(("Set-Cookie", cookie(&id)));
        Ok(rep)
    }

    fn get(&self, r: &Requete, u: &Utilisateur, t: u64) -> Result<Reponse> {
        let ctx = u.contexte(t);
        let admin = self.admin(u)?;
        Ok(match r.chemin.as_str() {
            "/" => Reponse::redirection("/tableau"),
            "/tableau" => {
                let lignes = admin.supervision(t)?;
                let demandes = admin.demandes(t)?.len();
                page(200, pages::tableau(&ctx, &lignes, demandes))
            }
            "/enrolement" => page(
                200,
                pages::enrolement(&ctx, &admin.demandes(t)?, None, None),
            ),
            "/enrolement/demande" => {
                let id = r.parametres.get("id").map(String::as_str).unwrap_or("");
                match admin.demandes(t)?.into_iter().find(|d| d.id == id) {
                    Some(d) => page(200, pages::demande(&ctx, &d, None, "")),
                    None => refus(404, "Demande inconnue, expirée ou déjà traitée."),
                }
            }
            "/bornes/revoquer" => {
                let uuid = r.parametres.get("uuid").map(String::as_str).unwrap_or("");
                let reg = admin.stockage.lire()?;
                match reg
                    .bornes
                    .iter()
                    .find(|b| b.uuid == uuid && b.statut == StatutBorne::Active)
                {
                    Some(b) => page(200, pages::revocation(&ctx, b, None)),
                    None => refus(404, "Borne inconnue ou déjà révoquée."),
                }
            }
            "/maj" => self.page_maj(&admin, &ctx, None)?,
            "/utilisateurs" => {
                admin.stockage.auditer(
                    &u.acteur(),
                    Evenement::Administration {
                        action: "consultation-utilisateurs".into(),
                    },
                )?;
                let base = Utilisateurs::ouvrir(&admin.stockage)?.lire()?;
                let saisie = r.parametres.get("identifiant").map(|s| s.trim());
                let trouve = saisie.and_then(|s| {
                    if u.role == Role::Auditeur && s.starts_with("u-") {
                        base.par_pseudonyme(s)
                    } else {
                        normaliser_identifiant(s).and_then(|i| base.utilisateur(&i))
                    }
                });
                self.page_utilisateurs(&ctx, &base, saisie.map(|s| (s, trouve)), None, None)
            }
            "/sites" => self.page_sites(&admin, &ctx, None)?,
            "/comptes" => {
                self.auditer(&u.acteur(), "consultation-comptes")?;
                self.page_comptes(u, t, None, None)?
            }
            "/mot-de-passe" => self.page_mot_de_passe(u, t, None),
            "/passages" | "/passages/detail" => {
                admin.stockage.auditer(
                    &u.acteur(),
                    Evenement::Administration {
                        action: "consultation-passages".into(),
                    },
                )?;
                let p = Passages::ouvrir(&admin.stockage)?;
                let noms = admin
                    .stockage
                    .lire()?
                    .bornes
                    .into_iter()
                    .map(|b| (b.uuid, b.nom))
                    .collect();
                if r.chemin == "/passages" {
                    let l = p.derniers(pages_passages::PASSAGES_AFFICHES)?;
                    page(200, pages_passages::liste(&ctx, &l, &noms))
                } else {
                    let v = |k: &str| r.parametres.get(k).map(String::as_str).unwrap_or("");
                    let partie = v("partie").parse::<u32>().unwrap_or(0);
                    match p.detail(v("borne"), v("id"), partie)? {
                        Some(s) => page(200, pages_passages::detail(&ctx, v("borne"), &s, &noms)),
                        None => refus(404, "Rapport de passage inconnu."),
                    }
                }
            }
            "/cles-usb" => {
                let base = Utilisateurs::ouvrir(&admin.stockage)?.lire()?;
                page(200, pages_utilisateurs::cles_usb(&ctx, &base, None))
            }
            iso_bornes::ROUTE => self.page_iso(u, t, None)?,
            quarantaine::ROUTE => self.page_quarantaine(u, t, None)?,
            "/audit" => {
                admin.stockage.auditer(
                    &u.acteur(),
                    Evenement::Administration {
                        action: "consultation-audit".into(),
                    },
                )?;
                let contenu = admin.stockage.journal_audit().lire()?;
                let lignes: Vec<&[u8]> = contenu
                    .split(|o| *o == b'\n')
                    .filter(|l| !l.is_empty())
                    .collect();
                let pages_n = lignes.len().div_ceil(AUDIT_PAR_PAGE).max(1);
                let p = r
                    .parametres
                    .get("page")
                    .and_then(|p| p.parse::<usize>().ok())
                    .unwrap_or(1)
                    .clamp(1, pages_n);
                let enr: Vec<_> = lignes
                    .iter()
                    .rev()
                    .skip((p - 1) * AUDIT_PAR_PAGE)
                    .take(AUDIT_PAR_PAGE)
                    .map(|l| Enregistrement::analyser(l))
                    .collect();
                page(200, pages::audit(&ctx, &enr, p, pages_n))
            }
            "/audit/verification" => {
                admin.stockage.auditer(
                    &u.acteur(),
                    Evenement::Administration {
                        action: "verification-audit".into(),
                    },
                )?;
                let cle = ClePublique::lire(&self.config.cle_audit_publique)?;
                let contenu = admin.stockage.journal_audit().lire()?;
                let resultat =
                    barbacane_audit::verifier(&contenu, &cle, &[]).map_err(|d| d.to_string());
                page(200, pages::verification(&ctx, resultat))
            }
            _ => refus(404, "Page introuvable."),
        })
    }

    fn page_utilisateurs(
        &self,
        ctx: &Contexte,
        base: &BaseUtilisateurs,
        recherche: Option<(
            &str,
            Option<&barbacane_passerelle::utilisateurs::Utilisateur>,
        )>,
        pin: Option<(&str, &str)>,
        message: Option<(bool, &str)>,
    ) -> Reponse {
        page(
            if message.is_some_and(|(ok, _)| !ok) {
                400
            } else {
                200
            },
            pages_utilisateurs::utilisateurs(
                ctx,
                &pages_utilisateurs::VueUtilisateurs {
                    base,
                    annuaire_configure: self.config.annuaire.is_some(),
                    recherche,
                    pin,
                    message,
                    maintenant: ctx.maintenant,
                },
            ),
        )
    }

    fn page_sites(
        &self,
        admin: &Admin,
        ctx: &Contexte,
        message: Option<(bool, &str)>,
    ) -> Result<Reponse> {
        let reg = admin.stockage.lire()?;
        let base = Utilisateurs::ouvrir(&admin.stockage)?.lire()?;
        let mut noms: std::collections::BTreeSet<String> = base.sites.keys().cloned().collect();
        noms.extend(reg.bornes.iter().map(|b| b.site.clone()));
        noms.extend(base.cles_usb.iter().filter_map(|c| c.site.clone()));
        let lignes: Vec<pages_utilisateurs::LigneSite> = noms
            .into_iter()
            .map(|site| pages_utilisateurs::LigneSite {
                bornes: reg
                    .bornes
                    .iter()
                    .filter(|b| b.site == site && b.statut == StatutBorne::Active)
                    .count(),
                reglage: base.reglage(&site),
                cles: base.cles_du_site(&site).count(),
                site,
            })
            .collect();
        Ok(page(
            if message.is_some_and(|(ok, _)| !ok) {
                400
            } else {
                200
            },
            pages_utilisateurs::sites(ctx, &lignes, message),
        ))
    }

    /// Actions des pages Utilisateurs, Sites et Clés USB (administrateur ; rôle et CSRF déjà
    /// vérifiés). `None` : route d'une autre rubrique.
    fn post_utilisateurs(
        &self,
        chemin: &str,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        admin: &Admin,
        t: u64,
    ) -> Result<Option<Reponse>> {
        let ctx = u.contexte(t);
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("").trim();
        let ut = Utilisateurs::ouvrir(&admin.stockage)?;
        let acteur = u.acteur();
        let issue = |r: Result<String>| match r {
            Ok(m) => (true, m),
            Err(e) => (false, format!("Refusé : {e:#}")),
        };
        Ok(Some(match chemin {
            "/utilisateurs/synchroniser" => {
                let r = match &self.config.annuaire {
                    None => Err(anyhow::anyhow!("annuaire non configuré")),
                    Some(a) => annuaire::synchroniser(a, &ut, &acteur, t),
                };
                if r.is_err() {
                    admin.stockage.auditer(
                        &acteur,
                        Evenement::Administration {
                            action: "synchronisation-annuaire-refusee".into(),
                        },
                    )?;
                }
                let (ok, m) = issue(r.map(|b| {
                    format!(
                        "Annuaire synchronisé : {} identifiants actifs, {} ajoutés, {} retirés, {} ignorés (forme invalide).",
                        b.actifs, b.ajoutes, b.retires, b.ignores
                    )
                }));
                let base = ut.lire()?;
                self.page_utilisateurs(&ctx, &base, None, None, Some((ok, &m)))
            }
            "/utilisateurs/pin" => {
                let id = normaliser_identifiant(champ("identifiant")).unwrap_or_default();
                match ut.reinitialiser_pin(&id, &acteur, t) {
                    Ok(pin) => {
                        let base = ut.lire()?;
                        let trouve = base.utilisateur(&id);
                        self.page_utilisateurs(
                            &ctx,
                            &base,
                            Some((&id, trouve)),
                            Some((&id, &pin)),
                            None,
                        )
                    }
                    Err(e) => {
                        let base = ut.lire()?;
                        let m = format!("Refusé : {e:#}");
                        self.page_utilisateurs(&ctx, &base, None, None, Some((false, &m)))
                    }
                }
            }
            "/utilisateurs/deverrouiller" => {
                let id = normaliser_identifiant(champ("identifiant")).unwrap_or_default();
                let (ok, m) = issue(
                    ut.deverrouiller(&id, &acteur, t)
                        .map(|_| format!("Compte {id} déverrouillé.")),
                );
                let base = ut.lire()?;
                let trouve = base.utilisateur(&id);
                self.page_utilisateurs(&ctx, &base, Some((&id, trouve)), None, Some((ok, &m)))
            }
            "/sites/mode" => {
                let site = champ("site");
                let mode = match champ("mode") {
                    "aucun" => Some(ModeUtilisateurs::Aucun),
                    "identification" => Some(ModeUtilisateurs::Identification),
                    "authentification" => Some(ModeUtilisateurs::Authentification),
                    _ => None,
                };
                let r = match mode {
                    None => Err(anyhow::anyhow!("mode inconnu")),
                    Some(m) => ut
                        .definir_mode_d13(site, m, &acteur, t)
                        .map(|_| format!("Site {site} : mode {} appliqué.", nom_mode(m))),
                };
                let (ok, m) = issue(r);
                self.page_sites(admin, &ctx, Some((ok, &m)))?
            }
            "/sites/entree" => {
                let site = champ("site");
                let entree = match champ("entree") {
                    "autorisee" => Some(EntreeNonEnrolees::Autorisee),
                    "interdite" => Some(EntreeNonEnrolees::Interdite),
                    _ => None,
                };
                let r = match entree {
                    None => Err(anyhow::anyhow!("choix inconnu")),
                    Some(e) => ut
                        .definir_entree(site, e, &acteur, t)
                        .map(|_| format!("Site {site} : politique d'entrée appliquée.")),
                };
                let (ok, m) = issue(r);
                self.page_sites(admin, &ctx, Some((ok, &m)))?
            }
            "/cles-usb/enroler" => {
                let site = Some(champ("site")).filter(|s| !s.is_empty());
                let (ok, m) = issue(
                    ut.enroler_cle(
                        champ("fabricant"),
                        champ("serie"),
                        champ("libelle"),
                        site,
                        f.contains_key("entree"),
                        f.contains_key("sortie"),
                        &acteur,
                        t,
                    )
                    .map(|id| format!("Clé enrôlée ({id}).")),
                );
                let base = ut.lire()?;
                page(
                    if ok { 200 } else { 400 },
                    pages_utilisateurs::cles_usb(&ctx, &base, Some((ok, &m))),
                )
            }
            "/cles-usb/retirer" => {
                let id = champ("id");
                let (ok, m) = issue(
                    ut.retirer_cle(id, &acteur, t)
                        .map(|_| format!("Clé {id} retirée.")),
                );
                let base = ut.lire()?;
                page(
                    if ok { 200 } else { 400 },
                    pages_utilisateurs::cles_usb(&ctx, &base, Some((ok, &m))),
                )
            }
            _ => return Ok(None),
        }))
    }

    fn page_maj(
        &self,
        admin: &Admin,
        ctx: &Contexte,
        message: Option<(bool, &str)>,
    ) -> Result<Reponse> {
        let etat = admin.maj_etat()?;
        let noms = admin
            .stockage
            .lire()?
            .bornes
            .into_iter()
            .map(|b| (b.uuid, b.nom))
            .collect();
        Ok(page(
            if message.is_some_and(|(ok, _)| !ok) {
                400
            } else {
                200
            },
            pages::maj(ctx, &etat, &noms, message),
        ))
    }

    fn post(
        &self,
        r: &Requete,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Reponse> {
        let ctx = u.contexte(t);
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("");
        if r.chemin == "/deconnexion" {
            self.sessions.supprimer(&u.id_session);
            self.auditer(&u.acteur(), "deconnexion")?;
            let mut rep = Reponse::redirection("/connexion");
            rep.entetes.push(("Set-Cookie", cookie_efface()));
            return Ok(rep);
        }
        if r.chemin == "/mot-de-passe" {
            return self.changer_mot_de_passe(f, u, t);
        }
        let admin = self.admin(u)?;
        if let Some(rep) = self.post_comptes(&r.chemin, f, u, t)? {
            return Ok(rep);
        }
        if let Some(rep) = self.post_quarantaine(&r.chemin, f, u, t)? {
            return Ok(rep);
        }
        if let Some(rep) = self.post_utilisateurs(&r.chemin, f, u, &admin, t)? {
            return Ok(rep);
        }
        Ok(match r.chemin.as_str() {
            "/enrolement/jeton" => {
                let site = champ("site").trim();
                if !barbacane_passerelle::registre::site_valide(site) {
                    return Ok(page(
                        400,
                        pages::enrolement(
                            &ctx,
                            &admin.demandes(t)?,
                            None,
                            Some((
                                site,
                                "Site invalide : 1 à 32 caractères parmi a-z, 0-9 et « - ».",
                            )),
                        ),
                    ));
                }
                let jeton = match admin.creer_jeton(site, t) {
                    Ok(j) => j,
                    Err(e) => {
                        let m = format!("Refusé : {e:#}");
                        return Ok(page(
                            400,
                            pages::enrolement(&ctx, &admin.demandes(t)?, None, Some((site, &m))),
                        ));
                    }
                };
                let texte = jeton.formater();
                page(
                    200,
                    pages::enrolement(
                        &ctx,
                        &admin.demandes(t)?,
                        Some(JetonAffiche {
                            texte: &texte,
                            expire_le: t + DUREE_JETON_S,
                            site,
                        }),
                        None,
                    ),
                )
            }
            "/enrolement/valider" => {
                let id = champ("id");
                let nom = champ("nom").trim();
                let Some(d) = admin.demandes(t)?.into_iter().find(|d| d.id == id) else {
                    return Ok(refus(404, "Demande inconnue, expirée ou déjà traitée."));
                };
                let nom_opt = (!nom.is_empty()).then_some(nom);
                match admin.valider(id, champ("empreinte"), nom_opt, t) {
                    Ok(uuid) => page(
                        200,
                        pages::resultat(
                            &ctx,
                            Rubrique::Enrolement,
                            "Borne enrôlée",
                            true,
                            &format!(
                                "Demande validée : borne {uuid}, certificat de 90 jours émis. La borne le récupère à sa prochaine consultation."
                            ),
                            "/tableau",
                        ),
                    ),
                    Err(e) => {
                        let reg = admin.stockage.lire()?;
                        let toujours = reg
                            .demandes
                            .iter()
                            .any(|x| x.id == id && x.statut == StatutDemande::EnAttente);
                        if !toujours {
                            return Err(e);
                        }
                        page(400, pages::demande(&ctx, &d, Some(&format!("{e:#}")), nom))
                    }
                }
            }
            "/enrolement/refuser" => {
                admin.refuser(champ("id"), t)?;
                page(
                    200,
                    pages::resultat(
                        &ctx,
                        Rubrique::Enrolement,
                        "Demande refusée",
                        true,
                        "Demande refusée : la borne devra obtenir un nouveau jeton.",
                        "/enrolement",
                    ),
                )
            }
            "/bornes/revoquer" => {
                let uuid = champ("uuid");
                let reg = admin.stockage.lire()?;
                let Some(b) = reg
                    .bornes
                    .iter()
                    .find(|b| b.uuid == uuid && b.statut == StatutBorne::Active)
                else {
                    return Ok(refus(404, "Borne inconnue ou déjà révoquée."));
                };
                let motif = Motif::analyser(champ("motif")).filter(|m| *m != Motif::Remplace);
                let Some(motif) = motif else {
                    return Ok(page(
                        400,
                        pages::revocation(&ctx, b, Some("Motif invalide.")),
                    ));
                };
                if champ("confirmation").trim() != b.nom {
                    return Ok(page(
                        400,
                        pages::revocation(
                            &ctx,
                            b,
                            Some(
                                "Le nom retapé ne correspond pas à la borne : rien n'a été révoqué.",
                            ),
                        ),
                    ));
                }
                admin.revoquer(uuid, motif, t)?;
                page(
                    200,
                    pages::resultat(
                        &ctx,
                        Rubrique::Supervision,
                        "Borne révoquée",
                        true,
                        &format!(
                            "Borne {} révoquée ; CRL republiée : elle est refusée dès sa prochaine connexion.",
                            b.nom
                        ),
                        "/tableau",
                    ),
                )
            }
            iso_bornes::ROUTE_PREPARER => self.preparer_iso(f, u, t)?,
            "/maj/diffuser" => {
                let message = match champ("version").parse::<u64>() {
                    Ok(n) => match admin.maj_diffuser(n) {
                        Ok(()) => (
                            true,
                            format!("Paquet {n} proposé aux bornes à leur prochain battement."),
                        ),
                        Err(e) => (false, format!("{e:#}")),
                    },
                    Err(_) => (false, "Version invalide.".into()),
                };
                self.page_maj(&admin, &ctx, Some((message.0, &message.1)))?
            }
            _ => refus(404, "Action introuvable."),
        })
    }

    /// Dépôt d'un `.bcu` ou d'un plancher et de sa signature, lus en flux vers un dossier
    /// temporaire 0700 du registre, puis vérifiés par `DepotMaj`.
    fn depot(&self, r: &Requete, flux: &mut impl Read, u: &Utilisateur, t: u64) -> Result<Reponse> {
        let ctx = u.contexte(t);
        let plancher = r.chemin == "/maj/plancher";
        let Some(f) = r.type_contenu.as_deref().and_then(frontiere) else {
            return Ok(refus(415, "Formulaire de dépôt attendu."));
        };
        let max = if plancher { 1024 } else { TAILLE_BCU_MAX };
        if r.longueur > max + TAILLE_SIGNATURE_MAX as u64 + 64 * 1024 {
            return Ok(refus(413, "Fichier trop gros."));
        }
        let mut m = Multipart::new(http::lecteur_corps(r, flux), &f);
        // Jeton anti-CSRF : premier champ, vérifié avant de recevoir les fichiers.
        let csrf_ok = match m.suivante() {
            Ok(Some(p)) if p.nom == "csrf" && !p.fichier => {
                m.texte(128).is_ok_and(|j| egal(&j, &u.session.csrf))
            }
            _ => false,
        };
        if !csrf_ok {
            return Ok(refus(403, "Jeton anti-CSRF absent ou invalide."));
        }
        let admin = self.admin(u)?;
        let racine = admin.stockage.dossier().join("depots-web");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&racine)?;
        let dossier = tempfile::Builder::new()
            .prefix("depot-")
            .tempdir_in(&racine)?;
        let fichier = dossier.path().join(if plancher {
            "plancher.json"
        } else {
            "paquet.bcu"
        });
        let signature = dossier.path().join(if plancher {
            "plancher.json.minisig"
        } else {
            "paquet.bcu.minisig"
        });
        for (nom, chemin, taille) in [
            ("fichier", &fichier, max),
            ("signature", &signature, TAILLE_SIGNATURE_MAX as u64),
        ] {
            let lu = match m.suivante() {
                Ok(Some(p)) if p.nom == nom && p.fichier => {
                    let mut sortie = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(chemin)?;
                    m.copier(&mut sortie, taille)
                }
                Ok(_) => Err(Refus(400)),
                Err(e) => Err(e),
            };
            if let Err(Refus(s)) = lu {
                return Ok(refus(s, "Dépôt incomplet ou trop gros."));
            }
        }
        if !matches!(m.suivante(), Ok(None)) {
            return Ok(refus(400, "Dépôt mal formé."));
        }
        let message = if plancher {
            admin.maj_plancher(&fichier).map(|n| {
                format!(
                    "Plancher signé installé : aucune version inférieure à {n} ne sera acceptée."
                )
            })
        } else {
            admin.maj_deposer(&fichier).map(|p| {
                format!(
                    "Paquet {} accepté (signature des bornes vérifiée), {} octets. Diffusez-le pour le proposer aux bornes.",
                    p.version_maj, p.taille
                )
            })
        };
        let message = match message {
            Ok(m) => (true, m),
            Err(e) => (false, format!("Refusé : {e:#}")),
        };
        self.page_maj(&admin, &ctx, Some((message.0, &message.1)))
    }
}

/// Traite une connexion : TLS mTLS, une requête, une réponse.
fn traiter(flux: TcpStream, web: &Web) -> Result<String> {
    let flux = Flux {
        flux,
        fin: Instant::now() + DELAI_TOTAL,
    };
    // Configuration (donc CRL des administrateurs) relue à chaque connexion.
    let mut tls = StreamOwned::new(ServerConnection::new(web.tls()?)?, flux);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let der = tls
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .context("aucun certificat client")?;
    let empreinte = empreinte_certificat(der);
    let der = der.to_vec();
    let reponse = match lire_entete(&mut tls) {
        Err(Refus(s)) => refus(s, "Requête invalide."),
        Ok(r) if r.methode == "POST" && r.chemin == iso_bornes::ROUTE_TELECHARGER => {
            // Téléchargement d'une ISO : envoyée en flux (jamais en mémoire), durée allongée.
            match web.telecharger_iso(&r, &mut tls, &empreinte) {
                Ok(None) => {
                    tls.conn.send_close_notify();
                    tls.flush()?;
                    fermer(&tls.sock.flux);
                    return Ok(format!("certificat {}… → 200 (ISO)", &empreinte[..16]));
                }
                Ok(Some(rep)) => rep,
                Err(e) => refus(500, &format!("{e:#}")),
            }
        }
        Ok(r) => {
            if r.methode == "POST" && ROUTES_DEPOT.contains(&r.chemin.as_str()) {
                tls.sock.fin += Duration::from_secs(r.longueur / DEBIT_MIN_DEPOT);
            }
            web.repondre(&r, &mut tls, &empreinte, &der)
        }
    };
    reponse.ecrire(&mut tls)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    fermer(&tls.sock.flux);
    Ok(format!(
        "certificat {}… → {}",
        &empreinte[..16],
        reponse.statut
    ))
}

/// Fermeture « douce » : fin d'écriture, puis lecture et abandon de ce que le client envoie
/// encore (corps refusé non lu), 1 Mio et 2 s au plus. Sans cela, la fermeture d'un socket
/// dont des octets restent à lire émet un RST qui peut faire perdre la réponse au client.
fn fermer(flux: &TcpStream) {
    let _ = flux.shutdown(std::net::Shutdown::Write);
    let fin = Instant::now() + Duration::from_secs(2);
    let mut lu = 0usize;
    let mut tampon = [0u8; 16 * 1024];
    let mut f = flux;
    while lu < 1 << 20 {
        let reste = fin.saturating_duration_since(Instant::now());
        if reste.is_zero() || f.set_read_timeout(Some(reste)).is_err() {
            break;
        }
        match f.read(&mut tampon) {
            Ok(0) | Err(_) => break,
            Ok(n) => lu += n,
        }
    }
}

/// Sert l'interface : un fil par connexion, au plus [`CONNEXIONS_MAX`].
pub fn servir(ecoute: TcpListener, web: Arc<Web>) -> Result<()> {
    let actives = Arc::new(AtomicUsize::new(0));
    for flux in ecoute.incoming() {
        let flux = match flux {
            Ok(f) => f,
            Err(e) => {
                eprintln!("web : acceptation : {e}");
                continue;
            }
        };
        if actives.fetch_add(1, Ordering::SeqCst) >= CONNEXIONS_MAX {
            actives.fetch_sub(1, Ordering::SeqCst);
            eprintln!("web : trop de connexions, refus");
            continue;
        }
        let (web, actives) = (web.clone(), actives.clone());
        std::thread::spawn(move || {
            let pair = flux.peer_addr().ok();
            match traiter(flux, &web) {
                Ok(r) => eprintln!("web : {pair:?} : {r}"),
                Err(e) => eprintln!("web : {pair:?} : refus : {e:#}"),
            }
            actives.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Rouvre l'amorçage (commande locale `barbacane-web reamorcer`, console du serveur) : quand un
/// seul administrateur utilisable reste, il pourra de nouveau créer seul un second
/// administrateur. Refusé s'il y en a plusieurs (rien à réparer). Journalisé.
pub fn reamorcer(config: &Config) -> Result<()> {
    let passerelle = barbacane_passerelle::Config::lire(&config.passerelle)?;
    let admin = Admin::ouvrir(passerelle)?;
    let comptes = Comptes::ouvrir(admin.stockage.dossier())?;
    comptes.transaction(|b| {
        if b.administrateurs_utilisables_sauf("") != 1 {
            bail!("réamorçage refusé : il doit rester exactement un administrateur utilisable");
        }
        b.second_administrateur_cree = false;
        admin.stockage.auditer(
            &barbacane_passerelle::admin::acteur_local(),
            Evenement::Administration {
                action: "reamorcage-local".into(),
            },
        )
    })
}

/// Feuille de style servie (pour les captures de la documentation).
pub fn css() -> &'static str {
    feuille_de_style()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "adresse = 127.0.0.1\nport = 8443\nchaine_serveur = /a\ncle_serveur = /b\nca_administrateurs = /c\ncrl_administrateurs = /d\ncomptes = /e\npasserelle = /f\ncle_audit_publique = /g\n";

    #[test]
    fn configuration() {
        assert_eq!(
            Config::analyser(CONF).unwrap().adresse_ecoute().to_string(),
            "127.0.0.1:8443"
        );
        assert!(Config::analyser(&CONF.replace("8443", "0")).is_err());
        assert!(Config::analyser(&format!("{CONF}port = 1\n")).is_err());
        assert!(Config::analyser(&format!("{CONF}inconnue = 1\n")).is_err());
        assert!(Config::analyser(&CONF.replace("comptes = /e\n", "")).is_err());
    }

    #[test]
    fn feuille_de_style_locale() {
        let css = feuille_de_style();
        assert!(css.contains("/statique/polices/AtkinsonHyperlegible-Regular.ttf"));
        assert!(!css.contains("../fonts/"));
        assert!(
            !css.contains("http:") && !css.contains("https:"),
            "aucune ressource externe"
        );
        assert!(!css.contains("@keyframes") && !css.contains("transition"));
        assert!(css.contains("prefers-color-scheme: dark"));
        for police in [
            "AtkinsonHyperlegible-Regular",
            "AtkinsonHyperlegible-Bold",
            "BarlowCondensed-SemiBold",
            "BarlowCondensed-Bold",
            "JetBrainsMono",
        ] {
            assert!(statique(&format!("/statique/polices/{police}.ttf")).is_some());
        }
        assert!(statique("/statique/../Cargo.toml").is_none());
    }
}
