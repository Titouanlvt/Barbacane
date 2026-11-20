//! Preuves de la passerelle mTLS avec une PKI de TEST générée à la volée par
//! `serveur/pki/racine-test.sh --cas-de-test` (openssl requis).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_passerelle::{Config, Passerelle, servir};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, SupportedProtocolVersion,
};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";

struct Banc {
    _dossier: tempfile::TempDir,
    pki: PathBuf,
    adresse: SocketAddr,
}

/// Génère la PKI de TEST et démarre une passerelle sur un port libre.
fn banc(crl: &str) -> Banc {
    let dossier = tempfile::tempdir().unwrap();
    let pki = dossier.path().join("pki");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../pki/racine-test.sh");
    let sortie = Command::new(script)
        .arg("--cas-de-test")
        .arg(&pki)
        .output()
        .unwrap();
    assert!(
        sortie.status.success(),
        "racine-test.sh : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    let config = Config {
        adresse: "127.0.0.1".parse().unwrap(),
        port: 1,
        port_enrolement: 2,
        chaine_serveur: pki.join("serveur/chaine.pem"),
        cle_serveur: pki.join("serveur/cle.pem"),
        ca_bornes: pki.join("ca-bornes/cert.pem"),
        cle_ca_bornes: pki.join("ca-bornes/cle.pem"),
        crl_bornes: pki.join(crl),
        registre: dossier.path().join("registre"),
    };
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let adresse = ecoute.local_addr().unwrap();
    // Contrôle au démarrage ignoré ici (CRL expirée volontairement) : la passerelle doit
    // refuser à chaque connexion, ce que prouvent les tests.
    let passerelle = std::sync::Arc::new(Passerelle {
        stockage: barbacane_passerelle::registre::Stockage::ouvrir(&config.registre).unwrap(),
        ca: barbacane_passerelle::ca::CaBornes::charger(&config.ca_bornes, &config.cle_ca_bornes)
            .unwrap(),
        config,
    });
    std::thread::spawn(move || servir(ecoute, passerelle));
    Banc {
        _dossier: dossier,
        pki,
        adresse,
    }
}

/// Requête `GET /sante` ; `borne` = nom du certificat client à présenter.
fn sante(
    banc: &Banc,
    borne: Option<&str>,
    version: &'static SupportedProtocolVersion,
) -> Result<String, String> {
    let mut racines = RootCertStore::empty();
    racines
        .add(CertificateDer::from_pem_file(banc.pki.join("racine/cert.pem")).unwrap())
        .unwrap();
    let constructeur =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(racines);
    let config = match borne {
        Some(b) => {
            let cert = CertificateDer::from_pem_file(banc.pki.join(format!("bornes/{b}.cert.pem")))
                .unwrap();
            let cle =
                PrivateKeyDer::from_pem_file(banc.pki.join(format!("bornes/{b}.cle.pem"))).unwrap();
            constructeur.with_client_auth_cert(vec![cert], cle).unwrap()
        }
        None => constructeur.with_no_client_auth(),
    };
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from(NOM_SERVEUR).unwrap())
        .unwrap();
    let flux = TcpStream::connect(banc.adresse).unwrap();
    flux.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = StreamOwned::new(conn, flux);
    tls.write_all(b"GET /sante HTTP/1.1\r\nHost: passerelle\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut reponse = String::new();
    tls.read_to_string(&mut reponse)
        .map_err(|e| e.to_string())?;
    Ok(reponse)
}

#[test]
fn borne_valide_acceptee_et_identifiee() {
    let b = banc("ca-bornes/crl.pem");
    let r = sante(&b, Some("borne-01"), &rustls::version::TLS13).expect("connexion refusée");
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    let corps = r.split("\r\n\r\n").nth(1).unwrap();
    let sante: barbacane_protocole::Sante = barbacane_protocole::decoder(corps.as_bytes()).unwrap();
    assert_eq!(sante.borne, "borne borne-01", "{r}");
}

#[test]
fn sans_certificat_refuse() {
    let b = banc("ca-bornes/crl.pem");
    let e = sante(&b, None, &rustls::version::TLS13).expect_err("acceptée sans certificat");
    eprintln!("refus attendu : {e}");
}

#[test]
fn borne_revoquee_refusee() {
    let b = banc("ca-bornes/crl.pem");
    let e = sante(&b, Some("borne-revoquee"), &rustls::version::TLS13)
        .expect_err("borne révoquée acceptée");
    eprintln!("refus attendu : {e}");
    // La même passerelle sert toujours une borne valide.
    assert!(sante(&b, Some("borne-01"), &rustls::version::TLS13).is_ok());
}

#[test]
fn crl_expiree_refus_fail_closed() {
    let b = banc("ca-bornes/crl-expiree.pem");
    let e = sante(&b, Some("borne-01"), &rustls::version::TLS13)
        .expect_err("acceptée avec une CRL expirée");
    eprintln!("refus attendu : {e}");
}

#[test]
fn tls12_refuse() {
    let b = banc("ca-bornes/crl.pem");
    let e = sante(&b, Some("borne-01"), &rustls::version::TLS12).expect_err("TLS 1.2 accepté");
    eprintln!("refus attendu : {e}");
}
