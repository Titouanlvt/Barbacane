//! Passerelle mTLS du serveur Barbacane (suite, étape 5 « socle »).
//!
//! - TLS 1.3 seul, suites et groupes de la décision D6 (fournisseur `ring`, déjà utilisé par la
//!   borne) ;
//! - authentification client OBLIGATOIRE : certificat émis par la CA « bornes » ;
//! - CRL de la CA bornes relue à CHAQUE connexion ; refus si elle est absente, illisible ou
//!   expirée (D8, fail-closed), contrôlé ici et par webpki (`enforce_revocation_expiration`) ;
//! - route `GET /sante` : renvoie le CN de la borne authentifiée.
//!
//! HTTP volontairement minimal (une requête par connexion, 8 Kio au plus) : pas de serveur HTTP
//! complet tant que le protocole agent ↔ serveur n'est pas fixé.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::{cipher_suite, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

/// Connexions traitées simultanément au plus (100 bornes visées).
const CONNEXIONS_MAX: usize = 256;
/// Taille maximale d'une requête HTTP (ligne + en-têtes).
const REQUETE_MAX: usize = 8 * 1024;
/// Délai d'inactivité d'une connexion.
const DELAI: Duration = Duration::from_secs(10);

/// Configuration lue dans un fichier `cle = valeur` (lignes `#` ignorées).
#[derive(Debug, Clone)]
pub struct Config {
    pub adresse: IpAddr,
    /// Port d'écoute : tiré à l'installation (D4), jamais de valeur par défaut.
    pub port: u16,
    /// Certificat serveur suivi de la CA serveur (PEM).
    pub chaine_serveur: PathBuf,
    pub cle_serveur: PathBuf,
    /// Certificat de la CA bornes : seule ancre de confiance des clients.
    pub ca_bornes: PathBuf,
    /// CRL de la CA bornes (PEM), relue à chaque connexion.
    pub crl_bornes: PathBuf,
}

impl Config {
    pub fn lire(chemin: &Path) -> Result<Config> {
        let texte = std::fs::read_to_string(chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        Config::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<Config> {
        let (mut adresse, mut port, mut chaine, mut cle, mut ca, mut crl) =
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
                "chaine_serveur" => chaine.replace(PathBuf::from(v)).is_some(),
                "cle_serveur" => cle.replace(PathBuf::from(v)).is_some(),
                "ca_bornes" => ca.replace(PathBuf::from(v)).is_some(),
                "crl_bornes" => crl.replace(PathBuf::from(v)).is_some(),
                autre => bail!("ligne {} : clé inconnue « {autre} »", n + 1),
            };
            if deja {
                bail!("ligne {} : clé répétée", n + 1);
            }
        }
        let port = port.context("port absent (tiré à l'installation, D4)")?;
        if port == 0 {
            bail!("port 0 refusé");
        }
        Ok(Config {
            adresse: adresse.context("adresse absente")?,
            port,
            chaine_serveur: chaine.context("chaine_serveur absente")?,
            cle_serveur: cle.context("cle_serveur absente")?,
            ca_bornes: ca.context("ca_bornes absente")?,
            crl_bornes: crl.context("crl_bornes absente")?,
        })
    }

    pub fn adresse_ecoute(&self) -> SocketAddr {
        SocketAddr::new(self.adresse, self.port)
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

/// Construit la configuration TLS à partir des fichiers (appelée à chaque connexion).
pub fn config_tls(config: &Config) -> Result<Arc<ServerConfig>> {
    let fournisseur = Arc::new(fournisseur());
    let mut ancres = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&config.ca_bornes).context("CA bornes")? {
        ancres.add(cert.context("CA bornes illisible")?)?;
    }
    if ancres.is_empty() {
        bail!("aucune CA bornes");
    }
    let verificateur =
        WebPkiClientVerifier::builder_with_provider(Arc::new(ancres), fournisseur.clone())
            .with_crls(lire_crl(&config.crl_bornes)?)
            .enforce_revocation_expiration()
            .build()?;
    let chaine = CertificateDer::pem_file_iter(&config.chaine_serveur)
        .context("chaîne serveur")?
        .collect::<Result<Vec<_>, _>>()
        .context("chaîne serveur illisible")?;
    let cle = PrivateKeyDer::from_pem_file(&config.cle_serveur).context("clé serveur")?;
    let tls = ServerConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verificateur)
        .with_single_cert(chaine, cle)?;
    Ok(Arc::new(tls))
}

/// CN du certificat de la borne (déjà vérifié par rustls).
fn cn_borne(conn: &ServerConnection) -> Result<String> {
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
        .map_err(|e| anyhow::anyhow!("CN : {e}"))?;
    Ok(cn.to_owned())
}

/// Échappement JSON minimal d'une chaîne.
fn json_chaine(s: &str) -> String {
    let mut sortie = String::with_capacity(s.len() + 2);
    sortie.push('"');
    for c in s.chars() {
        match c {
            '"' => sortie.push_str("\\\""),
            '\\' => sortie.push_str("\\\\"),
            c if (c as u32) < 0x20 => sortie.push_str(&format!("\\u{:04x}", c as u32)),
            c => sortie.push(c),
        }
    }
    sortie.push('"');
    sortie
}

/// Réponse HTTP à la première ligne de requête.
fn repondre(ligne: &str, cn: &str) -> String {
    let mut morceaux = ligne.split(' ');
    let (statut, corps) = match (morceaux.next(), morceaux.next()) {
        (Some("GET"), Some("/sante")) => (
            "200 OK",
            format!("{{\"etat\":\"ok\",\"borne\":{}}}", json_chaine(cn)),
        ),
        (Some("GET"), Some(_)) => ("404 Not Found", "{\"erreur\":\"introuvable\"}".into()),
        _ => (
            "405 Method Not Allowed",
            "{\"erreur\":\"méthode refusée\"}".into(),
        ),
    };
    format!(
        "HTTP/1.1 {statut}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
        corps.len()
    )
}

/// Traite une connexion : poignée de main mTLS, une requête, une réponse.
fn traiter(flux: TcpStream, config: &Config) -> Result<String> {
    flux.set_read_timeout(Some(DELAI))?;
    flux.set_write_timeout(Some(DELAI))?;
    // Configuration (donc CRL) relue à chaque connexion : une révocation prend effet aussitôt.
    let conn = ServerConnection::new(config_tls(config)?)?;
    let mut tls = StreamOwned::new(conn, flux);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let cn = cn_borne(&tls.conn)?;
    let mut requete = Vec::new();
    let mut tampon = [0u8; 1024];
    while !requete.windows(4).any(|f| f == b"\r\n\r\n") {
        let n = tls.read(&mut tampon)?;
        if n == 0 {
            bail!("requête incomplète");
        }
        requete.extend_from_slice(&tampon[..n]);
        if requete.len() > REQUETE_MAX {
            bail!("requête trop longue");
        }
    }
    let ligne = String::from_utf8_lossy(&requete);
    let ligne = ligne.lines().next().unwrap_or_default();
    tls.write_all(repondre(ligne, &cn).as_bytes())?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(cn)
}

/// Boucle d'acceptation : un fil par connexion, au plus `CONNEXIONS_MAX`.
pub fn servir(ecoute: TcpListener, config: Config) -> Result<()> {
    let config = Arc::new(config);
    let actives = Arc::new(AtomicUsize::new(0));
    for flux in ecoute.incoming() {
        let flux = match flux {
            Ok(f) => f,
            Err(e) => {
                eprintln!("passerelle : acceptation : {e}");
                continue;
            }
        };
        if actives.fetch_add(1, Ordering::SeqCst) >= CONNEXIONS_MAX {
            actives.fetch_sub(1, Ordering::SeqCst);
            eprintln!("passerelle : trop de connexions, refus");
            continue;
        }
        let (config, actives) = (config.clone(), actives.clone());
        std::thread::spawn(move || {
            let pair = flux.peer_addr().ok();
            match traiter(flux, &config) {
                Ok(cn) => eprintln!("passerelle : {pair:?} : borne « {cn} » servie"),
                Err(e) => eprintln!("passerelle : {pair:?} : refus : {e:#}"),
            }
            actives.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "# essai\nadresse = 127.0.0.1\nport = 43117\nchaine_serveur = /a\ncle_serveur = /b\nca_bornes = /c\ncrl_bornes = /d\n";

    #[test]
    fn config_complete() {
        let c = Config::analyser(CONF).unwrap();
        assert_eq!(c.adresse_ecoute().to_string(), "127.0.0.1:43117");
    }

    #[test]
    fn config_refusee() {
        assert!(Config::analyser(&CONF.replace("43117", "0")).is_err());
        assert!(Config::analyser(&CONF.replace("port = 43117\n", "")).is_err());
        assert!(Config::analyser(&format!("{CONF}port = 1\n")).is_err());
        assert!(Config::analyser(&format!("{CONF}inconnue = 1\n")).is_err());
    }

    #[test]
    fn json_echappe() {
        assert_eq!(json_chaine("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }

    #[test]
    fn routes() {
        assert!(repondre("GET /sante HTTP/1.1", "borne x").starts_with("HTTP/1.1 200"));
        assert!(repondre("GET /autre HTTP/1.1", "x").starts_with("HTTP/1.1 404"));
        assert!(repondre("POST /sante HTTP/1.1", "x").starts_with("HTTP/1.1 405"));
    }
}
