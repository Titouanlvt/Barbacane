//! Preuves de l'enrôlement validé, du battement, de l'heure et de la supervision
//! (`docs/suite/protocole-agent.md` §7), avec une PKI de TEST générée à la volée par
//! `serveur/pki/racine-test.sh --cas-de-test` (openssl requis) et une vraie passerelle sur
//! deux écoutes locales.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::registre::{Alerte, Motif};
use barbacane_passerelle::{
    CONNEXIONS_ENROLEMENT_MAX, Config, DELAI_TOTAL_ENROLEMENT, Passerelle, fournisseur, servir,
    servir_enrolement,
};
use barbacane_protocole::{
    AccuseBattement, AccuseDemande, Battement, CodeErreur, Decision, EtatBorne, EtatDemande, Jeton,
    ReponseCertificat, ReponseErreur, Sante, VERSION, decoder, route,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";
const JOUR: u64 = 24 * 3600;

struct Banc {
    _dossier: tempfile::TempDir,
    pki: PathBuf,
    config: Config,
    admin: Admin,
    service: SocketAddr,
    enrolement: SocketAddr,
}

/// PKI de TEST, registre vide, passerelle sur deux ports libres.
fn banc() -> Banc {
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
    let ecoute_service = TcpListener::bind("127.0.0.1:0").unwrap();
    let ecoute_enrolement = TcpListener::bind("127.0.0.1:0").unwrap();
    let service = ecoute_service.local_addr().unwrap();
    let enrolement = ecoute_enrolement.local_addr().unwrap();
    let config = Config {
        adresse: "127.0.0.1".parse().unwrap(),
        port: service.port(),
        port_enrolement: enrolement.port(),
        chaine_serveur: pki.join("serveur/chaine.pem"),
        cle_serveur: pki.join("serveur/cle.pem"),
        ca_bornes: pki.join("ca-bornes/cert.pem"),
        cle_ca_bornes: pki.join("ca-bornes/cle.pem"),
        crl_bornes: pki.join("ca-bornes/crl.pem"),
        registre: dossier.path().join("etat"),
    };
    let p = Passerelle::nouvelle(config.clone()).unwrap();
    let p2 = p.clone();
    std::thread::spawn(move || servir(ecoute_service, p));
    std::thread::spawn(move || servir_enrolement(ecoute_enrolement, p2));
    Banc {
        admin: Admin::ouvrir(config.clone()).unwrap(),
        _dossier: dossier,
        pki,
        config,
        service,
        enrolement,
    }
}

/// Identité TLS d'une borne : chaîne et clé (PKCS#8).
#[derive(Clone)]
struct Cle {
    chaine: Vec<CertificateDer<'static>>,
    cle: Vec<u8>,
}

/// Réponse brute : statut HTTP et corps.
type Reponse = (u16, Vec<u8>);

/// Envoie des octets bruts. La borne épingle la CA serveur (seule ancre), comme l'agent.
fn envoyer(
    banc: &Banc,
    adresse: SocketAddr,
    cle: Option<&Cle>,
    brut: &[u8],
) -> Result<Reponse, String> {
    let mut ancres = RootCertStore::empty();
    ancres
        .add(CertificateDer::from_pem_file(banc.pki.join("ca-serveur/cert.pem")).unwrap())
        .unwrap();
    let constructeur = ClientConfig::builder_with_provider(Arc::new(fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(ancres);
    let config = match cle {
        Some(c) => constructeur
            .with_client_auth_cert(
                c.chaine.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.cle.clone())),
            )
            .unwrap(),
        None => constructeur.with_no_client_auth(),
    };
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from(NOM_SERVEUR).unwrap())
        .unwrap();
    let flux = TcpStream::connect(adresse).unwrap();
    flux.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = StreamOwned::new(conn, flux);
    tls.write_all(brut).map_err(|e| e.to_string())?;
    let mut reponse = Vec::new();
    tls.read_to_end(&mut reponse).map_err(|e| e.to_string())?;
    let texte = String::from_utf8_lossy(&reponse);
    let (entete, _) = texte
        .split_once("\r\n\r\n")
        .ok_or("réponse sans en-têtes")?;
    let statut: u16 = entete
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("statut")?;
    let debut = entete.len() + 4;
    Ok((statut, reponse[debut..].to_vec()))
}

fn post(
    banc: &Banc,
    adresse: SocketAddr,
    cle: Option<&Cle>,
    chemin: &str,
    corps: &str,
) -> Result<Reponse, String> {
    let brut = format!(
        "POST {chemin} HTTP/1.1\r\nHost: passerelle\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{corps}",
        corps.len()
    );
    envoyer(banc, adresse, cle, brut.as_bytes())
}

fn code(r: &Reponse) -> CodeErreur {
    decoder::<ReponseErreur>(&r.1)
        .unwrap_or_else(|e| {
            panic!(
                "réponse d'erreur illisible ({e}) : {}",
                String::from_utf8_lossy(&r.1)
            )
        })
        .code
}

/// Clé et demande PKCS#10 générées « sur la borne ».
fn nouvelle_cle(alg: &'static rcgen::SignatureAlgorithm) -> (KeyPair, String) {
    let cle = KeyPair::generate_for(alg).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&cle)
        .unwrap();
    (cle, csr.pem().unwrap())
}

fn corps_demande(secret: &str, csr: &str) -> String {
    serde_json::json!({"version": VERSION, "jeton": secret, "csr_pem": csr, "version_logiciel": "2.0.0"})
        .to_string()
}

fn deposer(banc: &Banc, secret: &str, csr: &str) -> Result<AccuseDemande, CodeErreur> {
    let r = post(
        banc,
        banc.enrolement,
        None,
        route::DEMANDE,
        &corps_demande(secret, csr),
    )
    .unwrap();
    if r.0 == 202 {
        Ok(decoder(&r.1).unwrap())
    } else {
        Err(code(&r))
    }
}

fn retrait(banc: &Banc, id: &str) -> EtatDemande {
    let corps = serde_json::json!({"version": VERSION, "demande_id": id}).to_string();
    let r = post(banc, banc.enrolement, None, route::RETRAIT, &corps).unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    decoder(&r.1).unwrap()
}

fn jeton(banc: &Banc) -> Jeton {
    let j = banc.admin.creer_jeton("site-1", maintenant()).unwrap();
    assert_eq!(
        j.port, banc.config.port_enrolement,
        "port d'enrôlement inscrit dans le jeton (D4)"
    );
    j
}

/// Parcours complet : jeton, demande, validation (à l'heure `validation`), retrait.
fn enroler_a(banc: &Banc, validation: u64) -> (String, Cle) {
    let (cle, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let accuse = deposer(banc, &jeton(banc).secret, &csr).unwrap();
    let uuid = banc
        .admin
        .valider(
            &accuse.demande_id,
            &accuse.empreinte,
            Some("borne-essai"),
            validation,
        )
        .unwrap();
    let etat = retrait(banc, &accuse.demande_id);
    assert_eq!(etat.decision, Decision::Validee);
    assert_eq!(etat.port_service, Some(banc.config.port));
    let chaine = CertificateDer::pem_slice_iter(etat.chaine_pem.unwrap().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    (
        uuid,
        Cle {
            chaine,
            cle: cle.serialize_der(),
        },
    )
}

fn enroler(banc: &Banc) -> (String, Cle) {
    enroler_a(banc, maintenant())
}

fn battement(heure_borne: u64, etat: EtatBorne) -> String {
    serde_json::to_string(&Battement {
        version: VERSION,
        heure_borne,
        version_logiciel: "2.2.0".into(),
        etat,
        age_signatures_s: 3600,
        espace_libre_octets: 10_000_000_000,
        rapports_en_attente: 0,
    })
    .unwrap()
}

fn battre(banc: &Banc, cle: &Cle, heure_borne: u64) -> Result<Reponse, String> {
    post(
        banc,
        banc.service,
        Some(cle),
        route::BATTEMENT,
        &battement(heure_borne, EtatBorne::EnService),
    )
}

#[test]
fn jeton_expire_ou_reutilise_refuse() {
    let b = banc();
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    // Expiré : créé il y a 2 h (validité 1 h).
    let ancien = b
        .admin
        .creer_jeton("site-1", maintenant() - 2 * 3600)
        .unwrap();
    assert_eq!(
        deposer(&b, &ancien.secret, &csr),
        Err(CodeErreur::JetonInvalide)
    );
    // Inconnu.
    let inconnu = Jeton::nouveau(1, &[9; 16]);
    assert_eq!(
        deposer(&b, &inconnu.secret, &csr),
        Err(CodeErreur::JetonInvalide)
    );
    // Valide une fois, puis réutilisé.
    let j = jeton(&b);
    assert!(deposer(&b, &j.secret, &csr).is_ok());
    assert_eq!(deposer(&b, &j.secret, &csr), Err(CodeErreur::JetonInvalide));
    // Le secret n'est pas conservé en clair dans le registre.
    let registre = std::fs::read_to_string(b.config.registre.join("registre.json")).unwrap();
    assert!(!registre.contains(&j.secret));
}

#[test]
fn demande_non_validee_sans_certificat() {
    let b = banc();
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let accuse = deposer(&b, &jeton(&b).secret, &csr).unwrap();
    let etat = retrait(&b, &accuse.demande_id);
    assert_eq!(etat.decision, Decision::EnAttente);
    assert!(etat.certificat_pem.is_none() && etat.chaine_pem.is_none());
    assert_eq!(b.admin.demandes(maintenant()).unwrap().len(), 1);
    // Sans certificat, l'écoute de service coupe la poignée de main.
    assert!(post(&b, b.service, None, route::BATTEMENT, "{}").is_err());
    // Refusée : jamais de certificat, plus de validation possible.
    b.admin.refuser(&accuse.demande_id, maintenant()).unwrap();
    assert_eq!(retrait(&b, &accuse.demande_id).decision, Decision::Refusee);
    assert!(
        b.admin
            .valider(&accuse.demande_id, &accuse.empreinte, None, maintenant())
            .is_err()
    );
    // Identifiant inconnu.
    let corps = serde_json::json!({"version": VERSION, "demande_id": "0".repeat(32)}).to_string();
    let r = post(&b, b.enrolement, None, route::RETRAIT, &corps).unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::DemandeInconnue));
}

#[test]
fn empreinte_fausse_refusee() {
    let b = banc();
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let accuse = deposer(&b, &jeton(&b).secret, &csr).unwrap();
    let fausse = format!("{}0", &accuse.empreinte[..63]);
    let fausse = if fausse == accuse.empreinte {
        format!("{}1", &accuse.empreinte[..63])
    } else {
        fausse
    };
    assert!(
        b.admin
            .valider(&accuse.demande_id, &fausse, None, maintenant())
            .is_err()
    );
    assert_eq!(
        retrait(&b, &accuse.demande_id).decision,
        Decision::EnAttente
    );
    // Saisie avec espaces et majuscules (affichage groupé par 4) : acceptée.
    let groupee = accuse
        .empreinte
        .to_ascii_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    b.admin
        .valider(&accuse.demande_id, &groupee, None, maintenant())
        .unwrap();
}

#[test]
fn cle_non_p256_refusee() {
    let b = banc();
    let j = jeton(&b);
    let (_, csr384) = nouvelle_cle(&PKCS_ECDSA_P384_SHA384);
    assert_eq!(
        deposer(&b, &j.secret, &csr384),
        Err(CodeErreur::DemandeInvalide)
    );
    // Demande falsifiée (signature cassée) : refusée.
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let mut der = rustls::pki_types::CertificateSigningRequestDer::from_pem_slice(csr.as_bytes())
        .unwrap()
        .as_ref()
        .to_vec();
    let n = der.len();
    der[n - 3] ^= 1;
    let falsifiee = pem_de("CERTIFICATE REQUEST", &der);
    assert_eq!(
        deposer(&b, &j.secret, &falsifiee),
        Err(CodeErreur::DemandeInvalide)
    );
    // Le jeton n'a pas été consommé par ces demandes invalides.
    assert!(deposer(&b, &j.secret, &csr).is_ok());
}

fn pem_de(etiquette: &str, der: &[u8]) -> String {
    use data_encoding::BASE64;
    let b64 = BASE64.encode(der);
    let lignes: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {etiquette}-----\n{}\n-----END {etiquette}-----\n",
        lignes.join("\n")
    )
}

#[test]
fn validee_certificat_utilisable_en_mtls() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    // Profil du certificat émis (politique de certification §3).
    let (_, cert) = x509_parser::parse_x509_certificate(cle.chaine[0].as_ref()).unwrap();
    let duree = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    assert_eq!(duree as u64, 90 * JOUR + 60);
    let san = cert.subject_alternative_name().unwrap().unwrap();
    let noms: Vec<String> = san
        .value
        .general_names
        .iter()
        .map(|n| n.to_string())
        .collect();
    assert!(
        noms.iter()
            .any(|n| n.contains(&format!("urn:barbacane:borne:site-1:{uuid}"))),
        "{noms:?}"
    );
    assert!(
        noms.iter()
            .any(|n| n.contains(&format!("{uuid}.bornes.barbacane.invalid"))),
        "{noms:?}"
    );
    assert!(
        cert.subject().to_string().contains("TEST"),
        "{}",
        cert.subject()
    );
    // Utilisable en mTLS.
    let r = envoyer(
        &b,
        b.service,
        Some(&cle),
        b"GET /sante HTTP/1.1\r\nHost: p\r\n\r\n",
    )
    .unwrap();
    assert_eq!(r.0, 200);
    let sante: Sante = decoder(&r.1).unwrap();
    assert_eq!(sante.borne, "borne borne-essai");
    let r = battre(&b, &cle, maintenant()).unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    let accuse: AccuseBattement = decoder(&r.1).unwrap();
    assert!(accuse.ecart_s.abs() <= 2);
    // Une borne de la PKI de test inconnue du registre passe TLS mais pas le registre.
    let cle01 = Cle {
        chaine: vec![
            CertificateDer::from_pem_file(b.pki.join("bornes/borne-01.cert.pem")).unwrap(),
        ],
        cle: PrivateKeyDer::from_pem_file(b.pki.join("bornes/borne-01.cle.pem"))
            .unwrap()
            .secret_der()
            .to_vec(),
    };
    let r = battre(&b, &cle01, maintenant()).unwrap();
    assert_eq!((r.0, code(&r)), (403, CodeErreur::BorneRefusee));
}

#[test]
fn revocation_refuse_la_connexion_suivante() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let (_, autre) = enroler(&b);
    assert_eq!(battre(&b, &cle, maintenant()).unwrap().0, 200);
    b.admin.revoquer(&uuid, Motif::Volee, maintenant()).unwrap();
    let e = battre(&b, &cle, maintenant()).expect_err("borne révoquée acceptée");
    eprintln!("refus attendu : {e}");
    // Les autres bornes continuent ; la révocation antérieure de la CRL est conservée.
    assert_eq!(battre(&b, &autre, maintenant()).unwrap().0, 200);
    let revoquee = Cle {
        chaine: vec![
            CertificateDer::from_pem_file(b.pki.join("bornes/borne-revoquee.cert.pem")).unwrap(),
        ],
        cle: PrivateKeyDer::from_pem_file(b.pki.join("bornes/borne-revoquee.cle.pem"))
            .unwrap()
            .secret_der()
            .to_vec(),
    };
    assert!(
        envoyer(
            &b,
            b.service,
            Some(&revoquee),
            b"GET /sante HTTP/1.1\r\n\r\n"
        )
        .is_err()
    );
    // La CRL republiée se vérifie avec openssl (signature de la CA bornes, 7 jours).
    let sortie = Command::new("openssl")
        .args(["crl", "-noout", "-text", "-CAfile"])
        .arg(b.pki.join("ca-bornes/cert.pem"))
        .arg("-in")
        .arg(&b.config.crl_bornes)
        .output()
        .unwrap();
    let texte = String::from_utf8_lossy(&sortie.stderr).to_string()
        + &String::from_utf8_lossy(&sortie.stdout);
    assert!(
        sortie.status.success() && texte.contains("verify OK"),
        "{texte}"
    );
    assert!(texte.contains("Key Compromise"), "{texte}");
}

#[test]
fn battement_met_a_jour_la_supervision() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let ligne = |t| {
        b.admin
            .supervision(t)
            .unwrap()
            .into_iter()
            .find(|l| l.uuid == uuid)
            .unwrap()
    };
    // Jamais vue : silence signalé passé 300 s.
    assert!(ligne(maintenant()).alertes.is_empty());
    assert_eq!(ligne(maintenant() + 400).alertes, vec![Alerte::Silence]);
    let r = post(
        &b,
        b.service,
        Some(&cle),
        route::BATTEMENT,
        &battement(maintenant(), EtatBorne::Maintenance),
    )
    .unwrap();
    assert_eq!(r.0, 200);
    let l = ligne(maintenant());
    assert_eq!(l.version_logiciel.as_deref(), Some("2.2.0"));
    assert_eq!(l.etat, Some(EtatBorne::Maintenance));
    assert!(l.derniere_vue.unwrap() + 5 > maintenant());
    assert!(l.alertes.is_empty(), "{:?}", l.alertes);
    // Silence, expiration proche, borne hors service.
    assert_eq!(ligne(maintenant() + 1000).alertes, vec![Alerte::Silence]);
    let l = ligne(maintenant() + 70 * JOUR);
    assert!(l.alertes.contains(&Alerte::Expiration), "{:?}", l.alertes);
    post(
        &b,
        b.service,
        Some(&cle),
        route::BATTEMENT,
        &battement(maintenant(), EtatBorne::HorsService),
    )
    .unwrap();
    assert_eq!(ligne(maintenant()).alertes, vec![Alerte::HorsService]);
    // La commande d'administration renvoie 3 quand une alerte existe.
    let conf = b.pki.join("passerelle.conf");
    std::fs::write(&conf, config_texte(&b.config)).unwrap();
    let sortie = Command::new(env!("CARGO_BIN_EXE_barbacane-registre"))
        .arg(&conf)
        .arg("supervision")
        .output()
        .unwrap();
    let texte = String::from_utf8_lossy(&sortie.stdout);
    assert_eq!(sortie.status.code(), Some(3), "{texte}");
    assert!(
        texte.contains(&uuid) && texte.contains("hors_service"),
        "{texte}"
    );
}

fn config_texte(c: &Config) -> String {
    format!(
        "adresse = {}\nport = {}\nport_enrolement = {}\nchaine_serveur = {}\ncle_serveur = {}\nca_bornes = {}\ncle_ca_bornes = {}\ncrl_bornes = {}\nregistre = {}\n",
        c.adresse,
        c.port,
        c.port_enrolement,
        c.chaine_serveur.display(),
        c.cle_serveur.display(),
        c.ca_bornes.display(),
        c.cle_ca_bornes.display(),
        c.crl_bornes.display(),
        c.registre.display()
    )
}

#[test]
fn commande_jeton() {
    let b = banc();
    let conf = b.pki.join("passerelle.conf");
    std::fs::write(&conf, config_texte(&b.config)).unwrap();
    let sortie = Command::new(env!("CARGO_BIN_EXE_barbacane-registre"))
        .arg(&conf)
        .args(["jeton", "site-1"])
        .output()
        .unwrap();
    assert!(sortie.status.success());
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let j = Jeton::analyser(texte.lines().last().unwrap()).unwrap();
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    assert!(deposer(&b, &j.secret, &csr).is_ok());
    // Site invalide : refus.
    let sortie = Command::new(env!("CARGO_BIN_EXE_barbacane-registre"))
        .arg(&conf)
        .args(["jeton", "site-1;x"])
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(1));
}

#[test]
fn message_mal_forme_ou_trop_gros_refuse() {
    let b = banc();
    let j = jeton(&b);
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let e = b.enrolement;
    let essai = |corps: &str| {
        let r = post(&b, e, None, route::DEMANDE, corps).unwrap();
        (r.0, code(&r))
    };
    assert_eq!(essai("pas du json"), (400, CodeErreur::RequeteInvalide));
    let inconnu =
        corps_demande(&j.secret, &csr).replacen('{', "{\"nom_fichier\":\"rapport.doc\",", 1);
    assert_eq!(essai(&inconnu), (400, CodeErreur::RequeteInvalide));
    let v2 = corps_demande(&j.secret, &csr).replace("\"version\":1", "\"version\":2");
    assert_eq!(essai(&v2), (400, CodeErreur::VersionNonGeree));
    let gros = format!("{{\"x\":\"{}\"}}", "a".repeat(5000));
    assert_eq!(essai(&gros), (413, CodeErreur::TropGros));
    // Annonce d'un corps énorme : refusée avant lecture.
    let r = envoyer(
        &b,
        e,
        None,
        b"POST /enrolement/demande HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n",
    )
    .unwrap();
    assert_eq!((r.0, code(&r)), (413, CodeErreur::TropGros));
    let entete = format!(
        "POST /enrolement/demande HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(5000)
    );
    let r = envoyer(&b, e, None, entete.as_bytes()).unwrap();
    assert_eq!((r.0, code(&r)), (413, CodeErreur::TropGros));
    let r = envoyer(&b, e, None, b"POST /enrolement/demande HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!((r.0, code(&r)), (400, CodeErreur::RequeteInvalide));
    let r = envoyer(&b, e, None, b"GET /enrolement/demande HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!((r.0, code(&r)), (405, CodeErreur::MethodeRefusee));
    // Le jeton a résisté à tout cela.
    assert!(deposer(&b, &j.secret, &csr).is_ok());
    // Côté service : battement avec un champ de trop, ou texte hostile.
    let (_, cle) = enroler(&b);
    let hostile = battement(maintenant(), EtatBorne::EnService).replace("2.2.0", "<script>");
    let r = post(&b, b.service, Some(&cle), route::BATTEMENT, &hostile).unwrap();
    assert_eq!((r.0, code(&r)), (400, CodeErreur::RequeteInvalide));
    let plus = battement(maintenant(), EtatBorne::EnService).replacen('{', "{\"fichiers\":[],", 1);
    let r = post(&b, b.service, Some(&cle), route::BATTEMENT, &plus).unwrap();
    assert_eq!((r.0, code(&r)), (400, CodeErreur::RequeteInvalide));
}

#[test]
fn routes_separees_par_ecoute() {
    let b = banc();
    let (_, cle) = enroler(&b);
    // Aucune route de service sur l'écoute d'enrôlement…
    let r = post(
        &b,
        b.enrolement,
        None,
        route::BATTEMENT,
        &battement(maintenant(), EtatBorne::EnService),
    )
    .unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    let r = envoyer(&b, b.enrolement, None, b"GET /sante HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    // …ni d'enrôlement sur l'écoute de service, même authentifié.
    let corps = serde_json::json!({"version": VERSION, "demande_id": "0".repeat(32)}).to_string();
    let r = post(&b, b.service, Some(&cle), route::RETRAIT, &corps).unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
}

#[test]
fn derive_horloge_signalee() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    // 299 s d'avance : accepté.
    let r = battre(&b, &cle, maintenant() + 290).unwrap();
    assert_eq!(r.0, 200);
    // 10 minutes d'avance : refusé, heure du serveur fournie pour resynchroniser.
    let avant = maintenant();
    let r = battre(&b, &cle, avant + 600).unwrap();
    assert_eq!((r.0, code(&r)), (409, CodeErreur::HorlogeDerivee));
    let e: ReponseErreur = decoder(&r.1).unwrap();
    assert!(e.heure_serveur >= avant && e.heure_serveur <= maintenant());
    let l = b
        .admin
        .supervision(maintenant())
        .unwrap()
        .into_iter()
        .find(|l| l.uuid == uuid)
        .unwrap();
    assert!(l.alertes.contains(&Alerte::Horloge), "{:?}", l.alertes);
    assert!(l.ecart_horloge_s.unwrap() >= 590);
    // En retard aussi ; puis resynchronisée : l'alerte disparaît.
    let r = battre(&b, &cle, maintenant() - 3600).unwrap();
    assert_eq!(code(&r), CodeErreur::HorlogeDerivee);
    assert_eq!(
        battre(&b, &cle, e.heure_serveur.max(maintenant()))
            .unwrap()
            .0,
        200
    );
    let l = b
        .admin
        .supervision(maintenant())
        .unwrap()
        .into_iter()
        .find(|l| l.uuid == uuid)
        .unwrap();
    assert!(l.alertes.is_empty(), "{:?}", l.alertes);
}

#[test]
fn renouvellement_a_mi_vie() {
    let b = banc();
    // Borne récente : renouvellement prématuré.
    let (_, recente) = enroler(&b);
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let corps = serde_json::json!({"version": VERSION, "csr_pem": csr}).to_string();
    let r = post(&b, b.service, Some(&recente), route::RENOUVELLEMENT, &corps).unwrap();
    assert_eq!((r.0, code(&r)), (409, CodeErreur::RenouvellementPremature));
    // Borne validée il y a 50 jours (au-delà de la mi-vie) : nouveau certificat, même identité.
    let (uuid, ancienne) = enroler_a(&b, maintenant() - 50 * JOUR);
    let (nouvelle_cle_borne, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    let corps = serde_json::json!({"version": VERSION, "csr_pem": csr}).to_string();
    let r = post(
        &b,
        b.service,
        Some(&ancienne),
        route::RENOUVELLEMENT,
        &corps,
    )
    .unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    let rep: ReponseCertificat = decoder(&r.1).unwrap();
    let nouvelle = Cle {
        chaine: CertificateDer::pem_slice_iter(rep.chaine_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        cle: nouvelle_cle_borne.serialize_der(),
    };
    let (_, cert) = x509_parser::parse_x509_certificate(nouvelle.chaine[0].as_ref()).unwrap();
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert!(
        san.value
            .general_names
            .iter()
            .any(|n| n.to_string().contains(&uuid))
    );
    // L'ancien certificat reste accepté tant que le nouveau n'a pas servi…
    assert_eq!(battre(&b, &ancienne, maintenant()).unwrap().0, 200);
    assert_eq!(battre(&b, &nouvelle, maintenant()).unwrap().0, 200);
    // …puis il est révoqué (CRL, motif « superseded ») et refusé.
    assert!(battre(&b, &ancienne, maintenant()).is_err());
    assert_eq!(battre(&b, &nouvelle, maintenant()).unwrap().0, 200);
}

/// Client lent : envoie un octet par seconde ; renvoie le temps écoulé (depuis la connexion)
/// jusqu'à ce que le serveur coupe. `tls` : poignée de main faite, lenteur sur la requête ;
/// sinon lenteur pendant la poignée de main elle-même.
fn client_lent(banc: &Banc, adresse: SocketAddr, tls: bool) -> std::thread::JoinHandle<Duration> {
    let ca_serveur = CertificateDer::from_pem_file(banc.pki.join("ca-serveur/cert.pem")).unwrap();
    std::thread::spawn(move || {
        let debut = Instant::now();
        let mut flux = TcpStream::connect(adresse).unwrap();
        let mut conn = None;
        if tls {
            let mut ancres = RootCertStore::empty();
            ancres.add(ca_serveur).unwrap();
            let config = ClientConfig::builder_with_provider(Arc::new(fournisseur()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(ancres)
                .with_no_client_auth();
            let mut c =
                ClientConnection::new(Arc::new(config), ServerName::try_from(NOM_SERVEUR).unwrap())
                    .unwrap();
            while c.is_handshaking() {
                c.complete_io(&mut flux).unwrap();
            }
            conn = Some(c);
        } else {
            // En-tête d'enregistrement TLS « handshake » annonçant 512 octets jamais complétés.
            flux.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00]).unwrap();
        }
        let mut lecteur = flux.try_clone().unwrap();
        lecteur
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        std::thread::spawn(move || {
            let requete = b"POST /enrolement/demande HTTP/1.1\r\nContent-Length: 100\r\n";
            for i in 0..60 {
                let ok = match conn.as_mut() {
                    // Écriture manuelle (jamais de lecture) : un octet de requête par seconde.
                    Some(c) => {
                        c.writer()
                            .write_all(&requete[i % requete.len()..][..1])
                            .is_ok()
                            && c.write_tls(&mut flux).is_ok()
                    }
                    None => flux.write_all(&[0]).is_ok(),
                };
                if !ok {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        let mut poubelle = [0u8; 4096];
        while let Ok(n) = lecteur.read(&mut poubelle) {
            if n == 0 {
                break;
            }
        }
        debut.elapsed()
    })
}

#[test]
fn client_lent_coupe_sans_bloquer_les_bornes() {
    let b = banc();
    let (_, cle) = enroler(&b);
    let debut = Instant::now();
    // Toutes les places de l'écoute d'enrôlement prises par des clients lents (un pendant la
    // requête, les autres pendant la poignée de main).
    let mut lents = vec![client_lent(&b, b.enrolement, true)];
    for _ in 1..CONNEXIONS_ENROLEMENT_MAX {
        lents.push(client_lent(&b, b.enrolement, false));
    }
    // Pendant ce temps, une borne légitime est servie sur l'écoute de service.
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(battre(&b, &cle, maintenant()).unwrap().0, 200);
    assert!(
        debut.elapsed() < DELAI_TOTAL_ENROLEMENT,
        "clients lents déjà coupés : test non probant"
    );
    // Chaque client lent est coupé avant le délai total + 3 s de marge.
    for l in lents {
        let duree = l.join().unwrap();
        eprintln!("client lent coupé après {duree:?}");
        assert!(
            duree >= DELAI_TOTAL_ENROLEMENT - Duration::from_secs(1),
            "coupé trop tôt : {duree:?}"
        );
        assert!(
            duree <= DELAI_TOTAL_ENROLEMENT + Duration::from_secs(3),
            "coupé trop tard : {duree:?}"
        );
    }
    // Les places sont libérées : l'enrôlement fonctionne de nouveau.
    std::thread::sleep(Duration::from_millis(200));
    let (_, csr) = nouvelle_cle(&PKCS_ECDSA_P256_SHA256);
    assert!(deposer(&b, &jeton(&b).secret, &csr).is_ok());
}
