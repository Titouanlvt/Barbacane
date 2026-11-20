//! Preuves des utilisateurs et clés USB côté passerelle (`docs/suite/serveur-utilisateurs.md`
//! §8) : vraie écoute mTLS, borne enrôlée par le vrai parcours (PKI de TEST, openssl requis).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::utilisateurs::Utilisateurs;
use barbacane_passerelle::{Config, Passerelle, fournisseur, servir, servir_enrolement};
use barbacane_protocole::utilisateurs::{
    DecisionUtilisateur, EntreeNonEnrolees, ModeUtilisateurs, PolitiqueSite, ReponseVerification,
    Sens, route as route_u,
};
use barbacane_protocole::{
    AccuseDemande, CodeErreur, EtatDemande, ReponseErreur, VERSION, decoder, route,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";

struct Banc {
    _dossier: tempfile::TempDir,
    pki: PathBuf,
    config: Config,
    admin: Admin,
    service: SocketAddr,
    enrolement: SocketAddr,
}

fn racine() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executer(c: &mut Command) {
    let s = c.output().unwrap();
    assert!(
        s.status.success(),
        "{c:?} : {}{}",
        String::from_utf8_lossy(&s.stdout),
        String::from_utf8_lossy(&s.stderr)
    );
}

fn banc() -> Banc {
    let dossier = tempfile::tempdir().unwrap();
    let pki = dossier.path().join("pki");
    executer(
        Command::new(racine().join("serveur/pki/racine-test.sh"))
            .arg("--cas-de-test")
            .arg(&pki),
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

#[derive(Clone)]
struct Cle {
    chaine: Vec<CertificateDer<'static>>,
    cle: Vec<u8>,
}

type Reponse = (u16, Vec<u8>);

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
    let fin = reponse
        .windows(4)
        .position(|f| f == b"\r\n\r\n")
        .ok_or("réponse sans en-têtes")?;
    let entete = String::from_utf8_lossy(&reponse[..fin]).into_owned();
    let statut: u16 = entete
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("statut")?;
    Ok((statut, reponse[fin + 4..].to_vec()))
}

fn post(
    banc: &Banc,
    adresse: SocketAddr,
    cle: Option<&Cle>,
    chemin: &str,
    corps: &str,
) -> Result<Reponse, String> {
    let brut = format!(
        "POST {chemin} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{corps}",
        corps.len()
    );
    envoyer(banc, adresse, cle, brut.as_bytes())
}

fn code(r: &Reponse) -> CodeErreur {
    decoder::<ReponseErreur>(&r.1).unwrap().code
}

fn enroler(banc: &Banc) -> (String, Cle) {
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&cle)
        .unwrap()
        .pem()
        .unwrap();
    let jeton = banc.admin.creer_jeton("site-1", maintenant()).unwrap();
    let corps = serde_json::json!({"version": VERSION, "jeton": jeton.secret, "csr_pem": csr, "version_logiciel": "2.0.0"}).to_string();
    let r = post(banc, banc.enrolement, None, route::DEMANDE, &corps).unwrap();
    assert_eq!(r.0, 202);
    let a: AccuseDemande = decoder(&r.1).unwrap();
    let uuid = banc
        .admin
        .valider(&a.demande_id, &a.empreinte, None, maintenant())
        .unwrap();
    let corps = serde_json::json!({"version": VERSION, "demande_id": a.demande_id}).to_string();
    let r = post(banc, banc.enrolement, None, route::RETRAIT, &corps).unwrap();
    let e: EtatDemande = decoder(&r.1).unwrap();
    let chaine = CertificateDer::pem_slice_iter(e.chaine_pem.unwrap().as_bytes())
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

fn utilisateurs(b: &Banc) -> Utilisateurs {
    Utilisateurs::ouvrir(&b.admin.stockage).unwrap()
}

fn verifier(b: &Banc, cle: &Cle, identifiant: &str, pin: Option<&str>) -> ReponseVerification {
    let mut corps = serde_json::json!({"version": VERSION, "identifiant": identifiant});
    if let Some(p) = pin {
        corps["pin"] = p.into();
    }
    let r = post(
        b,
        b.service,
        Some(cle),
        route_u::VERIFICATION,
        &corps.to_string(),
    )
    .unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    decoder(&r.1).unwrap()
}

fn changer(
    b: &Banc,
    cle: &Cle,
    identifiant: &str,
    pin: &str,
    nouveau: &str,
) -> ReponseVerification {
    let corps = serde_json::json!({"version": VERSION, "identifiant": identifiant, "pin": pin, "nouveau_pin": nouveau});
    let r = post(b, b.service, Some(cle), route_u::PIN, &corps.to_string()).unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    decoder(&r.1).unwrap()
}

fn politique(b: &Banc, cle: &Cle) -> PolitiqueSite {
    let r = post(
        b,
        b.service,
        Some(cle),
        route_u::POLITIQUE,
        r#"{"version":1}"#,
    )
    .unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    decoder(&r.1).unwrap()
}

/// Tous les fichiers du dossier d'état, concaténés.
fn tout_l_etat(d: &Path) -> Vec<u8> {
    let mut o = Vec::new();
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            o.extend(tout_l_etat(&p));
        } else {
            o.extend(std::fs::read(&p).unwrap());
        }
    }
    o
}

fn contient(foin: &[u8], aiguille: &str) -> bool {
    foin.windows(aiguille.len())
        .any(|f| f == aiguille.as_bytes())
}

fn audit(b: &Banc) -> String {
    String::from_utf8(b.admin.stockage.journal_audit().lire().unwrap()).unwrap()
}

#[test]
fn politique_telechargee_par_la_borne() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let u = utilisateurs(&b);
    let t = maintenant();
    let p = politique(&b, &cle);
    assert_eq!(
        (p.site.as_str(), p.mode),
        ("site-1", ModeUtilisateurs::Aucun),
        "défaut D13"
    );
    assert_eq!(p.entree_non_enrolees, EntreeNonEnrolees::Autorisee);
    u.definir_mode(
        "site-1",
        ModeUtilisateurs::Authentification,
        false,
        "web:alice",
        t,
    )
    .unwrap();
    u.definir_entree("site-1", EntreeNonEnrolees::Interdite, "web:alice", t)
        .unwrap();
    u.enroler_cle(
        "0781",
        "4C530001",
        "SOC",
        Some("site-1"),
        false,
        true,
        "web:alice",
        t,
    )
    .unwrap();
    u.enroler_cle(
        "0951",
        "AUTRE-SITE",
        "",
        Some("site-2"),
        true,
        true,
        "web:alice",
        t,
    )
    .unwrap();
    let p2 = politique(&b, &cle);
    assert!(p2.version_politique > p.version_politique);
    assert_eq!(p2.mode, ModeUtilisateurs::Authentification);
    assert_eq!(p2.cles.len(), 1, "seulement les clés du site de la borne");
    // Clé non enrôlée refusée en entrée (politique « interdite »), sortie vers l'enrôlée seule.
    assert!(!p2.autorise("1234", "INCONNUE", Sens::Entree));
    assert!(!p2.autorise("0951", "AUTRE-SITE", Sens::Sortie));
    assert!(p2.autorise("0781", "4c530001", Sens::Sortie));
    assert!(
        !p2.autorise("0781", "4c530001", Sens::Entree),
        "réservée à la sortie"
    );
    politique(&b, &cle);
    let a = audit(&b);
    assert_eq!(
        a.matches(&format!("\"politique_servie\":{{\"borne\":\"{uuid}\""))
            .count(),
        2,
        "auditée au changement de version seulement"
    );
    // Routes absentes de l'écoute d'enrôlement, refusées sans certificat.
    let r = post(
        &b,
        b.enrolement,
        None,
        route_u::POLITIQUE,
        r#"{"version":1}"#,
    )
    .unwrap();
    assert_eq!(code(&r), CodeErreur::Introuvable);
    assert!(post(&b, b.service, None, route_u::POLITIQUE, r#"{"version":1}"#).is_err());
}

#[test]
fn pin_faux_cinq_fois_verrouille() {
    let b = banc();
    let (_, cle) = enroler(&b);
    let u = utilisateurs(&b);
    let t = maintenant();
    u.importer(&["j.dupont".into()], "annuaire", "web:alice", t)
        .unwrap();
    u.definir_mode(
        "site-1",
        ModeUtilisateurs::Authentification,
        false,
        "web:alice",
        t,
    )
    .unwrap();
    let pin = u.reinitialiser_pin("j.dupont", "web:alice", t).unwrap();
    assert_eq!(
        verifier(&b, &cle, "j.dupont", Some(&pin)).decision,
        DecisionUtilisateur::PinAChanger
    );
    let nouveau = "48291637";
    let r = changer(&b, &cle, "j.dupont", &pin, nouveau);
    assert_eq!(r.decision, DecisionUtilisateur::Acceptee);
    assert_eq!(
        verifier(&b, &cle, "j.dupont", Some(nouveau)).decision,
        DecisionUtilisateur::Acceptee
    );
    // Identifiant inconnu et PIN faux : réponses identiques (octet pour octet hors heure).
    let inconnu = verifier(&b, &cle, "personne", Some("11223344"));
    let faux = verifier(&b, &cle, "j.dupont", Some("11223344"));
    assert_eq!(
        (inconnu.decision, inconnu.session, inconnu.attente_s),
        (faux.decision, faux.session, faux.attente_s)
    );
    // La borne serait bloquée à 5 refus : on remet son compteur pour isoler celui du compte.
    u.transaction(t, |base| {
        base.bornes.clear();
        Ok(())
    })
    .unwrap();
    for _ in 0..4 {
        let r = verifier(&b, &cle, "j.dupont", Some("11223344"));
        assert_eq!(r.decision, DecisionUtilisateur::Refusee);
    }
    let r = verifier(&b, &cle, "j.dupont", Some(nouveau));
    assert_eq!(
        r.decision,
        DecisionUtilisateur::Refusee,
        "5 échecs : bon PIN refusé"
    );
    assert!(
        u.lire()
            .unwrap()
            .utilisateur("j.dupont")
            .unwrap()
            .verrouille_le
            .is_some()
    );
    let a = audit(&b);
    assert!(a.contains("\"utilisateur_verrouille\""));
    assert!(
        a.contains("\"borne_bloquee\""),
        "le 5e refus sur la borne la bloque aussi"
    );
    assert!(
        !a.contains("j.dupont"),
        "aucun identifiant en clair dans l'audit"
    );
    u.deverrouiller("j.dupont", "web:alice", t).unwrap();
    // Borne toujours bloquée (le temps seul la débloque) : attente annoncée.
    let r = verifier(&b, &cle, "j.dupont", Some(nouveau));
    assert_eq!(r.decision, DecisionUtilisateur::Refusee);
    assert!(r.attente_s.is_some_and(|s| s > 0));
}

#[test]
fn pin_jamais_en_clair() {
    let b = banc();
    let (_, cle) = enroler(&b);
    let u = utilisateurs(&b);
    let t = maintenant();
    u.importer(&["a.martin".into()], "annuaire", "web:alice", t)
        .unwrap();
    u.definir_mode(
        "site-1",
        ModeUtilisateurs::Authentification,
        false,
        "web:alice",
        t,
    )
    .unwrap();
    let pin = u.reinitialiser_pin("a.martin", "web:alice", t).unwrap();
    let nouveau = "73916482";
    assert_eq!(
        changer(&b, &cle, "a.martin", &pin, nouveau).decision,
        DecisionUtilisateur::Acceptee
    );
    assert_eq!(
        verifier(&b, &cle, "a.martin", Some(nouveau)).decision,
        DecisionUtilisateur::Acceptee
    );
    verifier(&b, &cle, "a.martin", Some("55667788"));
    let etat = tout_l_etat(&b.config.registre);
    for secret in [pin.as_str(), nouveau, "55667788"] {
        assert!(
            !contient(&etat, secret),
            "PIN {secret} trouvé dans le dossier d'état"
        );
    }
    let base = std::fs::read_to_string(u.dossier().join("base.json")).unwrap();
    assert!(base.contains("$argon2id$v=19$m=65536,t=3,p=1$"));
}

#[test]
fn mode_aucun_aucune_donnee_personnelle() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let temoin = "zz.temoin-personnel";
    for pin in [None, Some("48291637")] {
        let r = verifier(&b, &cle, temoin, pin);
        assert_eq!(r.decision, DecisionUtilisateur::Refusee);
        assert_eq!(r.attente_s, None);
    }
    let etat = tout_l_etat(&b.config.registre);
    assert!(
        !contient(&etat, temoin),
        "identifiant conservé en mode Aucun"
    );
    assert!(!contient(&etat, "48291637"));
    let a = audit(&b);
    assert!(a.contains(&format!(
        "{{\"utilisateur_verifie\":{{\"borne\":\"{uuid}\",\"utilisateur\":\"inconnu\",\"resultat\":\"hors_mode\"}}}}"
    )));
    let base = utilisateurs(&b).lire().unwrap();
    assert!(base.utilisateurs.is_empty() && base.sessions.is_empty() && base.bornes.is_empty());
    // Mode Identification : un PIN superflu est refusé de même, sans rien conserver.
    let t = maintenant();
    let u = utilisateurs(&b);
    u.importer(&["j.dupont".into()], "annuaire", "web:alice", t)
        .unwrap();
    u.definir_mode(
        "site-1",
        ModeUtilisateurs::Identification,
        false,
        "web:alice",
        t,
    )
    .unwrap();
    assert_eq!(
        verifier(&b, &cle, "j.dupont", None).decision,
        DecisionUtilisateur::Acceptee
    );
    assert_eq!(
        verifier(&b, &cle, "j.dupont", Some("48291637")).decision,
        DecisionUtilisateur::Refusee
    );
    assert_eq!(
        verifier(&b, &cle, "inconnu.x", None).decision,
        DecisionUtilisateur::Refusee
    );
}
