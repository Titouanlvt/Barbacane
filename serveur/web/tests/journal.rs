//! Preuves de la page « Conservation et export » (v2.3.0) : vraie écoute TLS, vrai registre.
//! Durée de conservation et export Syslog changés par double validation (auto-validation
//! refusée, auditeur refusé), bornes, pare-feu, alertes, export structuré journalisé.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_audit::CleAudit;
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::fournisseur;
use barbacane_passerelle::outils::maintenant;
use barbacane_web::comptes::{Role, ligne_compte};
use barbacane_web::{Config, Web, servir};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const MDP_ALICE: &str = "phrase de passe de TEST, premier compte";
const MDP_CAROLE: &str = "phrase de passe de TEST, troisième compte";
const MDP_BOB: &str = "phrase de passe de TEST, deuxième compte";

struct Ident {
    chaine: Vec<CertificateDer<'static>>,
    cle: PrivateKeyDer<'static>,
}

struct Banc {
    _dossier: tempfile::TempDir,
    pki: PathBuf,
    web: SocketAddr,
    passerelle: barbacane_passerelle::Config,
    alice: Ident,
    bob: Ident,
    carole: Ident,
}

fn racine() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executer(c: &mut Command) -> Vec<u8> {
    let s = c.output().unwrap();
    assert!(
        s.status.success(),
        "{c:?} : {}",
        String::from_utf8_lossy(&s.stderr)
    );
    s.stdout
}

fn temps(s: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::seconds(s)
}

fn administrateur(issuer: &Issuer<'_, KeyPair>, nom: &str, serie: u8) -> Ident {
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name
        .push(DnType::CommonName, format!("admin {nom} TEST"));
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p.serial_number = Some(SerialNumber::from_slice(&[0x40, serie]));
    p.not_before = temps(-3600);
    p.not_after = temps(30 * 86400);
    let cert = p.signed_by(&cle, issuer).unwrap();
    Ident {
        chaine: vec![cert.der().clone()],
        cle: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cle.serialize_der())),
    }
}

fn banc() -> Banc {
    let dossier = tempfile::tempdir().unwrap();
    let d = dossier.path().to_path_buf();
    let pki = d.join("pki");
    executer(
        Command::new(racine().join("serveur/pki/racine-test.sh"))
            .arg("--cas-de-test")
            .arg(&pki),
    );
    let ca_cle = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name
        .push(DnType::CommonName, "Barbacane TEST CA administrateurs");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = temps(-3600);
    p.not_after = temps(365 * 86400);
    let ca = p.self_signed(&ca_cle).unwrap();
    std::fs::write(d.join("ca-admin.pem"), ca.pem()).unwrap();
    let issuer = Issuer::from_ca_cert_der(ca.der(), ca_cle).unwrap();
    let alice = administrateur(&issuer, "alice", 1);
    let bob = administrateur(&issuer, "bob", 2);
    let carole = administrateur(&issuer, "carole", 3);
    let crl = CertificateRevocationListParams {
        this_update: temps(-60),
        next_update: temps(7 * 86400),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap();
    std::fs::write(d.join("crl-admin.pem"), crl.pem().unwrap()).unwrap();
    let comptes = [
        ligne_compte("alice", Role::Administrateur, &alice.chaine[0], MDP_ALICE).unwrap(),
        ligne_compte("bob", Role::Auditeur, &bob.chaine[0], MDP_BOB).unwrap(),
        ligne_compte(
            "carole",
            Role::Administrateur,
            &carole.chaine[0],
            MDP_CAROLE,
        )
        .unwrap(),
    ]
    .join("\n");
    std::fs::write(d.join("comptes"), comptes).unwrap();
    std::fs::set_permissions(d.join("comptes"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        d.join("audit.pub"),
        CleAudit::depuis_pem(&CleAudit::generer().unwrap())
            .unwrap()
            .publique()
            .pem(),
    )
    .unwrap();
    let conf_passerelle = format!(
        "adresse = 127.0.0.1\nport = 41001\nport_enrolement = 41002\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_bornes = {p}/ca-bornes/cert.pem\ncle_ca_bornes = {p}/ca-bornes/cle.pem\ncrl_bornes = {p}/ca-bornes/crl.pem\nregistre = {}\n",
        d.join("etat").display(),
        p = pki.display()
    );
    std::fs::write(d.join("passerelle.conf"), &conf_passerelle).unwrap();
    let passerelle = barbacane_passerelle::Config::analyser(&conf_passerelle).unwrap();
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let web = ecoute.local_addr().unwrap();
    let config = Config::analyser(&format!(
        "adresse = 127.0.0.1\nport = {}\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_administrateurs = {d}/ca-admin.pem\ncrl_administrateurs = {d}/crl-admin.pem\ncomptes = {d}/comptes\npasserelle = {d}/passerelle.conf\ncle_audit_publique = {d}/audit.pub\n",
        web.port(),
        p = pki.display(),
        d = d.display(),
    ))
    .unwrap();
    let w = Web::nouveau(config).unwrap();
    std::thread::spawn(move || servir(ecoute, w));
    Banc {
        _dossier: dossier,
        pki,
        web,
        passerelle,
        alice,
        bob,
        carole,
    }
}

struct Rep {
    statut: u16,
    entetes: String,
    corps: Vec<u8>,
}

impl Rep {
    fn texte(&self) -> String {
        String::from_utf8_lossy(&self.corps).into_owned()
    }
    fn cookie(&self) -> Option<String> {
        let i = self.entetes.find("__Host-barbacane=")? + 17;
        let id = self.entetes[i..].split(';').next()?;
        (!id.is_empty()).then(|| id.to_owned())
    }
    fn csrf(&self) -> String {
        let t = self.texte();
        let i = t.find("name=\"csrf\" value=\"").expect("csrf") + 19;
        t[i..].split('"').next().unwrap().to_owned()
    }
}

fn envoyer(b: &Banc, id: &Ident, brut: &[u8]) -> Rep {
    let mut ancres = RootCertStore::empty();
    ancres
        .add(CertificateDer::from_pem_file(b.pki.join("ca-serveur/cert.pem")).unwrap())
        .unwrap();
    let c = ClientConfig::builder_with_provider(Arc::new(fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(ancres)
        .with_client_auth_cert(id.chaine.clone(), id.cle.clone_key())
        .unwrap();
    let conn = ClientConnection::new(
        Arc::new(c),
        ServerName::try_from("passerelle.barbacane.invalid").unwrap(),
    )
    .unwrap();
    let flux = TcpStream::connect(b.web).unwrap();
    flux.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut tls = StreamOwned::new(conn, flux);
    tls.write_all(brut).unwrap();
    let mut o = Vec::new();
    let _ = tls.read_to_end(&mut o);
    let fin = o
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("en-têtes");
    let entetes = String::from_utf8_lossy(&o[..fin]).into_owned();
    let statut = entetes.split(' ').nth(1).unwrap().parse().unwrap();
    Rep {
        statut,
        entetes,
        corps: o[fin + 4..].to_vec(),
    }
}

fn get(b: &Banc, id: &Ident, chemin: &str, cookie: Option<&str>) -> Rep {
    let c = cookie
        .map(|c| format!("Cookie: __Host-barbacane={c}\r\n"))
        .unwrap_or_default();
    envoyer(
        b,
        id,
        format!("GET {chemin} HTTP/1.1\r\nHost: admin\r\n{c}\r\n").as_bytes(),
    )
}

fn post(b: &Banc, id: &Ident, chemin: &str, cookie: &str, champs: &[(&str, &str)]) -> Rep {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in champs {
        s.append_pair(k, v);
    }
    let corps = s.finish();
    envoyer(
        b,
        id,
        format!(
            "POST {chemin} HTTP/1.1\r\nHost: admin\r\nCookie: __Host-barbacane={cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{corps}",
            corps.len()
        )
        .as_bytes(),
    )
}

fn connecter(b: &Banc, id: &Ident, ident: &str, mdp: &str) -> (String, String) {
    let page = get(b, id, "/connexion", None);
    let pre = page.cookie().unwrap();
    let r = post(
        b,
        id,
        "/connexion",
        &pre,
        &[
            ("csrf", &page.csrf()),
            ("identifiant", ident),
            ("mot_de_passe", mdp),
        ],
    );
    assert_eq!(r.statut, 303, "{}", r.texte());
    let c = r.cookie().unwrap();
    let t = get(b, id, "/tableau", Some(&c));
    (c.clone(), t.csrf())
}

fn demande(page: &str) -> String {
    let i = page.find("name=\"demande\" value=\"").expect("demande") + 22;
    page[i..].split('"').next().unwrap().to_owned()
}

fn actions(b: &Banc) -> Vec<String> {
    let s = Admin::ouvrir(b.passerelle.clone()).unwrap().stockage;
    s.journal_audit()
        .lire()
        .unwrap()
        .split(|o| *o == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let e = barbacane_audit::Enregistrement::analyser(l).ok()?;
            Some(serde_json::to_string(&e.evenement).unwrap())
        })
        .collect()
}

#[test]
fn conservation_et_syslog_par_double_validation() {
    let b = banc();
    let (ca, sa) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let (cc, sc) = connecter(&b, &b.carole, "carole", MDP_CAROLE);
    let (cb, sb) = connecter(&b, &b.bob, "bob", MDP_BOB);
    let registre = b.passerelle.registre.clone();
    // Réglage posé au premier démarrage : 365 jours, préavis (aucune purge immédiate).
    let r = get(&b, &b.alice, "/journal", Some(&ca));
    assert_eq!(r.statut, 200);
    assert!(r.texte().contains("365 jours"), "{}", r.texte());
    assert!(r.texte().contains("aucune purge avant le"));
    assert!(
        actions(&b)
            .iter()
            .any(|a| a.contains("conservation_reglee"))
    );
    // Bornes.
    for j in ["100", "731", "abc", "365"] {
        let r = post(
            &b,
            &b.alice,
            "/journal/conservation",
            &ca,
            &[("csrf", &sa), ("jours", j)],
        );
        assert_eq!(r.statut, 400, "{j} : {}", r.texte());
    }
    // Sans jeton anti-CSRF : refus.
    let r = post(
        &b,
        &b.alice,
        "/journal/conservation",
        &ca,
        &[("jours", "200")],
    );
    assert_eq!(r.statut, 403);
    let r = post(
        &b,
        &b.alice,
        "/journal/conservation",
        &ca,
        &[("csrf", &sa), ("jours", "200")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let d = demande(&r.texte());
    // Auto-validation refusée, auditeur refusé.
    let r = post(
        &b,
        &b.alice,
        "/validations/valider",
        &ca,
        &[("csrf", &sa), ("demande", &d), ("retour", "journal")],
    );
    assert_eq!(r.statut, 400);
    assert!(r.texte().contains("second administrateur"), "{}", r.texte());
    let r = post(
        &b,
        &b.bob,
        "/validations/valider",
        &cb,
        &[("csrf", &sb), ("demande", &d)],
    );
    assert_eq!(r.statut, 403);
    let r = post(
        &b,
        &b.bob,
        "/journal/conservation",
        &cb,
        &[("csrf", &sb), ("jours", "300")],
    );
    assert_eq!(r.statut, 403);
    assert!(
        barbacane_audit::conservation::Reglage::lire(&registre)
            .unwrap()
            .unwrap()
            .jours
            == 365
    );
    let r = post(
        &b,
        &b.carole,
        "/validations/valider",
        &cc,
        &[("csrf", &sc), ("demande", &d), ("retour", "journal")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(
        r.texte().contains("200 jours (double validation)"),
        "{}",
        r.texte()
    );
    let reglage = barbacane_audit::conservation::Reglage::lire(&registre)
        .unwrap()
        .unwrap();
    assert_eq!(reglage.jours, 200);
    assert_eq!(reglage.par, "web:alice+carole");
    assert!(
        reglage.effective_le > maintenant() + 6 * 86400,
        "réduction : préavis"
    );
    let a = actions(&b).join("\n");
    assert!(a.contains("validation-refusee:auto-validation"), "{a}");
    assert!(a.contains("validation:conservation:200j"), "{a}");
    // Syslog : cible du réseau local seulement, AC exigée en TLS.
    let r = post(
        &b,
        &b.alice,
        "/journal/syslog",
        &ca,
        &[
            ("csrf", &sa),
            ("mode", "tcp-clair"),
            ("adresse", "127.0.0.1"),
            ("port", "514"),
        ],
    );
    assert_eq!(r.statut, 400, "bouclage refusé");
    let r = post(
        &b,
        &b.alice,
        "/journal/syslog",
        &ca,
        &[
            ("csrf", &sa),
            ("mode", "tls"),
            ("adresse", "10.0.3.100"),
            ("port", "6514"),
            ("nom", "collecteur.test"),
        ],
    );
    assert_eq!(r.statut, 400);
    assert!(
        r.texte().contains("AC du collecteur requise"),
        "{}",
        r.texte()
    );
    let ac = std::fs::read_to_string(b.pki.join("ca-serveur/cert.pem")).unwrap();
    let r = post(
        &b,
        &b.alice,
        "/journal/syslog",
        &ca,
        &[
            ("csrf", &sa),
            ("mode", "tls"),
            ("adresse", "10.0.3.100"),
            ("port", "6514"),
            ("nom", "collecteur.test"),
            ("ac", &ac),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let d = demande(&r.texte());
    assert!(
        !registre.join("syslog/actif.json").exists(),
        "rien d'appliqué avant la validation"
    );
    let r = post(
        &b,
        &b.carole,
        "/validations/valider",
        &cc,
        &[("csrf", &sc), ("demande", &d), ("retour", "journal")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert_eq!(
        std::fs::read_to_string(registre.join("syslog/pare-feu")).unwrap(),
        "tcp 10.0.3.100 6514\n"
    );
    assert!(r.texte().contains("TLS 1.3"));
    // En clair : avertissement visible et audité.
    let r = post(
        &b,
        &b.carole,
        "/journal/syslog",
        &cc,
        &[
            ("csrf", &sc),
            ("mode", "udp-clair"),
            ("adresse", "10.0.3.100"),
            ("port", "514"),
        ],
    );
    let d = demande(&r.texte());
    let r = post(
        &b,
        &b.alice,
        "/validations/valider",
        &ca,
        &[("csrf", &sa), ("demande", &d), ("retour", "journal")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert_eq!(
        std::fs::read_to_string(registre.join("syslog/pare-feu")).unwrap(),
        "udp 10.0.3.100 514\n"
    );
    let t = get(&b, &b.alice, "/tableau", Some(&ca)).texte();
    assert!(t.contains("EN CLAIR"), "alerte sur le tableau de bord");
    let a = actions(&b).join("\n");
    assert!(
        a.contains("\"syslog\":{\"action\":\"clair\",\"detail\":\"udp-clair:10.0.3.100:514\"}"),
        "{a}"
    );
    // Désactivation : double validation aussi.
    let r = post(
        &b,
        &b.alice,
        "/journal/syslog",
        &ca,
        &[("csrf", &sa), ("mode", "desactive")],
    );
    let d = demande(&r.texte());
    post(
        &b,
        &b.carole,
        "/validations/valider",
        &cc,
        &[("csrf", &sc), ("demande", &d), ("retour", "journal")],
    );
    assert_eq!(
        std::fs::read_to_string(registre.join("syslog/pare-feu")).unwrap(),
        "aucun\n"
    );
    // Export structuré (auditeur) : JSON par ligne, journalisé.
    let r = get(&b, &b.bob, "/journal/export", Some(&cb));
    assert_eq!(r.statut, 200);
    assert!(r.entetes.contains("application/x-ndjson"));
    let texte = r.texte();
    for l in texte.lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["schema"], "barbacane.journal/1");
        assert!(v["horodatage"].as_str().unwrap().ends_with('Z'));
    }
    assert!(texte.contains("\"type\":\"conservation_reglee\""));
    // Consultations de données personnelles journalisées.
    get(
        &b,
        &b.bob,
        "/passages/detail?borne=0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11&id=1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11&partie=1",
        Some(&cb),
    );
    let a = actions(&b).join("\n");
    assert!(a.contains("export-journal-structure"), "{a}");
    assert!(a.contains("consultation-passage:0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11:1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11:1"), "{a}");
    // Lecture seule de la page pour l'auditeur (aucun formulaire d'action).
    let r = get(&b, &b.bob, "/journal", Some(&cb));
    assert_eq!(r.statut, 200);
    assert!(!r.texte().contains("action=\"/journal/conservation\""));
}
