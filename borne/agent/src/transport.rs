//! Transport vers la passerelle : TLS 1.3 seul (D6), CA « serveur » épinglée comme UNIQUE
//! ancre de confiance, HTTP/1.1 minimal (une requête par connexion, tailles bornées).
//!
//! Les erreurs sont classées pour décider du mode de l'agent : serveur injoignable (mode
//! dégradé, nouvel essai), borne refusée par le serveur (révoquée), serveur non authentifié
//! (alerte : jamais de repli sans vérification).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use barbacane_protocole::TAILLE_REPONSE_MAX;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::{cipher_suite, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{AlertDescription, ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Délai de connexion, de lecture et d'écriture.
pub const DELAI: Duration = Duration::from_secs(10);

/// Échec d'un échange avec le serveur.
#[derive(Debug)]
pub enum Echec {
    /// Pas de route, connexion refusée, délai dépassé, coupure : mode dégradé.
    Injoignable(String),
    /// Le serveur a refusé le certificat de la borne pendant la poignée de main (révocation,
    /// certificat inconnu ou expiré) : la borne n'est plus admise.
    Refusee(String),
    /// Le serveur ne s'est pas authentifié (certificat hors de la CA épinglée, nom faux) :
    /// échange abandonné, alerte locale.
    NonAuthentifie(String),
    /// Réponse HTTP mal formée ou trop grosse.
    Protocole(String),
}

impl std::fmt::Display for Echec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Echec::Injoignable(e) => write!(f, "serveur injoignable : {e}"),
            Echec::Refusee(e) => write!(f, "borne refusée par le serveur : {e}"),
            Echec::NonAuthentifie(e) => write!(f, "serveur NON authentifié : {e}"),
            Echec::Protocole(e) => write!(f, "réponse invalide : {e}"),
        }
    }
}

/// Fournisseur `ring` réduit aux mécanismes de D6 (identique à la passerelle).
pub fn fournisseur() -> CryptoProvider {
    let mut f = rustls::crypto::ring::default_provider();
    f.cipher_suites = vec![
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    f.kx_groups = vec![kx_group::SECP384R1, kx_group::SECP256R1];
    f
}

/// Lit la CA serveur et vérifie qu'elle est exactement celle épinglée dans l'ISO
/// (SHA-256 du DER). Un seul certificat admis dans le fichier.
pub fn charger_ca(chemin: &std::path::Path, empreinte: &str) -> Result<CertificateDer<'static>> {
    let certs = CertificateDer::pem_file_iter(chemin)
        .with_context(|| format!("CA serveur {}", chemin.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("CA serveur illisible")?;
    let [ca] = <[_; 1]>::try_from(certs)
        .map_err(|v| anyhow::anyhow!("CA serveur : un certificat attendu, {} lus", v.len()))?;
    let calculee = hex::encode(ring::digest::digest(&ring::digest::SHA256, &ca));
    if calculee != empreinte {
        bail!("CA serveur : empreinte {calculee} différente de l'empreinte épinglée {empreinte}");
    }
    Ok(ca)
}

/// Identité TLS de la borne (chaîne et clé).
pub struct Identite {
    pub chaine: Vec<CertificateDer<'static>>,
    pub cle: PrivateKeyDer<'static>,
}

/// Point d'accès au serveur.
pub struct Client {
    pub ca: CertificateDer<'static>,
    pub nom_serveur: ServerName<'static>,
}

impl Client {
    pub fn nouveau(ca: CertificateDer<'static>, nom: &str) -> Result<Client> {
        Ok(Client {
            ca,
            nom_serveur: ServerName::try_from(nom.to_owned()).context("nom du serveur")?,
        })
    }

    fn config(&self, identite: Option<Identite>) -> Result<Arc<ClientConfig>> {
        let mut ancres = RootCertStore::empty();
        ancres.add(self.ca.clone())?;
        let c = ClientConfig::builder_with_provider(Arc::new(fournisseur()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(ancres);
        Ok(Arc::new(match identite {
            Some(i) => c.with_client_auth_cert(i.chaine, i.cle)?,
            None => c.with_no_client_auth(),
        }))
    }

    /// Une requête, une réponse : (statut HTTP, corps).
    pub fn requete(
        &self,
        adresse: SocketAddr,
        identite: Option<Identite>,
        methode: &str,
        chemin: &str,
        corps: &[u8],
    ) -> Result<(u16, Vec<u8>), Echec> {
        let config = self
            .config(identite)
            .map_err(|e| Echec::Protocole(format!("configuration TLS : {e:#}")))?;
        let conn = ClientConnection::new(config, self.nom_serveur.clone())
            .map_err(|e| Echec::Protocole(e.to_string()))?;
        let flux = TcpStream::connect_timeout(&adresse, DELAI)
            .map_err(|e| Echec::Injoignable(format!("{adresse} : {e}")))?;
        let _ = flux.set_read_timeout(Some(DELAI));
        let _ = flux.set_write_timeout(Some(DELAI));
        let mut tls = StreamOwned::new(conn, flux);
        let mut brut = format!(
            "{methode} {chemin} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.nom_serveur.to_str(),
            corps.len()
        )
        .into_bytes();
        brut.extend_from_slice(corps);
        tls.write_all(&brut).map_err(classer)?;
        tls.flush().map_err(classer)?;
        let mut reponse = Vec::new();
        Read::by_ref(&mut tls)
            .take(TAILLE_REPONSE_MAX as u64 + 1)
            .read_to_end(&mut reponse)
            .map_err(classer)?;
        if reponse.len() > TAILLE_REPONSE_MAX {
            return Err(Echec::Protocole("réponse trop grosse".into()));
        }
        analyser_reponse(&reponse).map_err(|e| Echec::Protocole(format!("{e:#}")))
    }
}

/// Classe une erreur d'entrée-sortie TLS.
fn classer(e: std::io::Error) -> Echec {
    let texte = e.to_string();
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::AlertReceived(
            AlertDescription::CertificateRevoked
            | AlertDescription::BadCertificate
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::AccessDenied
            | AlertDescription::CertificateRequired,
        )) => Echec::Refusee(texte),
        // Autre alerte (serveur mal configuré, CRL expirée côté serveur…) : nouvel essai.
        Some(rustls::Error::AlertReceived(_)) => Echec::Injoignable(texte),
        Some(rustls::Error::InvalidCertificate(_))
        | Some(rustls::Error::NoCertificatesPresented) => Echec::NonAuthentifie(texte),
        Some(_) => Echec::Protocole(texte),
        None => Echec::Injoignable(texte),
    }
}

/// Analyse les en-têtes d'une réponse (sans la ligne vide finale) : statut et `Content-Length`
/// (obligatoire, unique) ; `Transfer-Encoding` refusé.
fn analyser_entete(entete: &[u8]) -> Result<(u16, usize, Option<String>)> {
    let entete = std::str::from_utf8(entete).context("en-têtes non UTF-8")?;
    let mut lignes = entete.split("\r\n");
    let premiere = lignes.next().unwrap_or_default();
    let mut morceaux = premiere.splitn(3, ' ');
    if morceaux.next() != Some("HTTP/1.1") {
        bail!("version HTTP inattendue");
    }
    let statut: u16 = morceaux
        .next()
        .filter(|s| s.len() == 3)
        .and_then(|s| s.parse().ok())
        .context("statut HTTP")?;
    let mut longueur = None;
    let mut type_contenu = None;
    for l in lignes {
        let (k, v) = l.split_once(':').context("en-tête mal formé")?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            if longueur.is_some() {
                bail!("Content-Length répété");
            }
            longueur = Some(v.trim().parse::<usize>().context("Content-Length")?);
        }
        if k.trim().eq_ignore_ascii_case("content-type") {
            type_contenu = Some(v.trim().to_ascii_lowercase());
        }
        if k.trim().eq_ignore_ascii_case("transfer-encoding") {
            bail!("Transfer-Encoding refusé");
        }
    }
    let longueur = longueur.context("Content-Length absent")?;
    Ok((statut, longueur, type_contenu))
}

/// `HTTP/1.1 NNN …`, en-têtes, `Content-Length` obligatoire et exact.
pub fn analyser_reponse(reponse: &[u8]) -> Result<(u16, Vec<u8>)> {
    let fin = reponse
        .windows(4)
        .position(|f| f == b"\r\n\r\n")
        .context("réponse sans fin d'en-têtes")?;
    let (statut, longueur, _) = analyser_entete(&reponse[..fin])?;
    let corps = &reponse[fin + 4..];
    if corps.len() != longueur {
        bail!("Content-Length absent ou inexact");
    }
    Ok((statut, corps.to_vec()))
}

/// Taille maximale des en-têtes d'une réponse.
const ENTETE_MAX: usize = 4096;

/// Issue d'un téléchargement.
#[derive(Debug)]
pub enum Telechargement {
    /// Paquet reçu en entier, de la taille annoncée ; SHA-256 (hexadécimal) des octets écrits.
    Recu { sha256: String },
    /// Réponse d'erreur du serveur (statut, corps JSON borné).
    Erreur(u16, Vec<u8>),
}

impl Client {
    /// `POST` puis réception d'un corps binaire **écrit au fil de l'eau** dans `sortie`
    /// (jamais tout en mémoire), d'exactement `taille` octets : `Content-Length` différent,
    /// type autre que `application/octet-stream`, octets en trop ou en moins → refus.
    pub fn telecharger(
        &self,
        adresse: SocketAddr,
        identite: Identite,
        chemin: &str,
        corps: &[u8],
        taille: u64,
        sortie: &mut impl Write,
    ) -> Result<Telechargement, Echec> {
        let config = self
            .config(Some(identite))
            .map_err(|e| Echec::Protocole(format!("configuration TLS : {e:#}")))?;
        let conn = ClientConnection::new(config, self.nom_serveur.clone())
            .map_err(|e| Echec::Protocole(e.to_string()))?;
        let flux = TcpStream::connect_timeout(&adresse, DELAI)
            .map_err(|e| Echec::Injoignable(format!("{adresse} : {e}")))?;
        let _ = flux.set_read_timeout(Some(DELAI));
        let _ = flux.set_write_timeout(Some(DELAI));
        let mut tls = StreamOwned::new(conn, flux);
        let mut brut = format!(
            "POST {chemin} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.nom_serveur.to_str(),
            corps.len()
        )
        .into_bytes();
        brut.extend_from_slice(corps);
        tls.write_all(&brut).map_err(classer)?;
        tls.flush().map_err(classer)?;
        // En-têtes : lus octet par octet jusqu'à la ligne vide, bornés.
        let mut entete = Vec::with_capacity(512);
        let mut octet = [0u8; 1];
        while !entete.ends_with(b"\r\n\r\n") {
            if entete.len() >= ENTETE_MAX {
                return Err(Echec::Protocole("en-têtes trop longs".into()));
            }
            match tls.read(&mut octet).map_err(classer)? {
                0 => return Err(Echec::Injoignable("connexion coupée (en-têtes)".into())),
                _ => entete.push(octet[0]),
            }
        }
        let (statut, longueur, type_contenu) = analyser_entete(&entete[..entete.len() - 4])
            .map_err(|e| Echec::Protocole(format!("{e:#}")))?;
        if statut != 200 {
            if longueur > TAILLE_REPONSE_MAX {
                return Err(Echec::Protocole("réponse trop grosse".into()));
            }
            let mut c = vec![0u8; longueur];
            tls.read_exact(&mut c).map_err(classer)?;
            return Ok(Telechargement::Erreur(statut, c));
        }
        if type_contenu.as_deref() != Some("application/octet-stream") {
            return Err(Echec::Protocole("type de contenu inattendu".into()));
        }
        if longueur as u64 != taille {
            return Err(Echec::Protocole(format!(
                "taille reçue {longueur} différente de la taille annoncée {taille}"
            )));
        }
        let mut empreinte = ring::digest::Context::new(&ring::digest::SHA256);
        let mut tampon = vec![0u8; 64 * 1024];
        let mut reste = taille;
        while reste > 0 {
            let n = usize::try_from(reste.min(tampon.len() as u64)).unwrap_or(tampon.len());
            let lu = tls.read(&mut tampon[..n]).map_err(classer)?;
            if lu == 0 {
                return Err(Echec::Injoignable(format!(
                    "connexion coupée ({} octets manquants)",
                    reste
                )));
            }
            empreinte.update(&tampon[..lu]);
            sortie
                .write_all(&tampon[..lu])
                .map_err(|e| Echec::Protocole(format!("écriture locale : {e}")))?;
            reste -= lu as u64;
        }
        // Rien après le corps annoncé.
        match tls.read(&mut octet) {
            Ok(0) => {}
            Ok(_) => {
                return Err(Echec::Protocole(
                    "octets au-delà de la taille annoncée".into(),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(classer(e)),
        }
        Ok(Telechargement::Recu {
            sha256: hex::encode(empreinte.finish()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reponse_bornee() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        assert_eq!(analyser_reponse(ok).unwrap(), (200, b"{}".to_vec()));
        for mauvaise in [
            &b"HTTP/1.1 200 OK\r\n\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}",
        ] {
            assert!(
                analyser_reponse(mauvaise).is_err(),
                "{}",
                String::from_utf8_lossy(mauvaise)
            );
        }
    }

    #[test]
    fn ca_non_epinglee_refusee() {
        let d = tempfile::tempdir().unwrap();
        let cle = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["ca".into()])
            .unwrap()
            .self_signed(&cle)
            .unwrap();
        let chemin = d.path().join("ca.pem");
        std::fs::write(&chemin, cert.pem()).unwrap();
        let bonne = hex::encode(ring::digest::digest(&ring::digest::SHA256, cert.der()));
        assert!(charger_ca(&chemin, &bonne).is_ok());
        assert!(charger_ca(&chemin, &"0".repeat(64)).is_err());
        std::fs::write(&chemin, format!("{}{}", cert.pem(), cert.pem())).unwrap();
        assert!(charger_ca(&chemin, &bonne).is_err(), "deux certificats");
    }
}
