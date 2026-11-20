//! Preuves de la page « Quarantaine » (`docs/suite/quarantaine.md`) : vraie écoute TLS, vrai
//! registre. Désactivée par défaut ; verrou d'homologation levé par un fichier de TEST
//! seulement ; double validation ; auditeur refusé.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_audit::{CleAudit, Evenement};
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

const MDP_ALICE: &str = "alice : phrase de passe de TEST";
const MDP_CAROLE: &str = "carole : phrase de passe de TEST";
const MDP_BOB: &str = "bob : phrase de passe de TEST";

struct Ident {
    chaine: Vec<CertificateDer<'static>>,
    cle: PrivateKeyDer<'static>,
}

struct Banc {
    _dossier: tempfile::TempDir,
    d: PathBuf,
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
        "adresse = 127.0.0.1\nport = 41001\nport_enrolement = 41002\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_bornes = {p}/ca-bornes/cert.pem\ncle_ca_bornes = {p}/ca-bornes/cle.pem\ncrl_bornes = {p}/ca-bornes/crl.pem\nregistre = {}\ndossier_homologation = {}\n",
        d.join("etat").display(),
        d.join("dossier-homologation.md").display(),
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
    std::fs::write(
        d.join("dossier-homologation.md"),
        "# TEST\n\nmesures_dr_serveur: non\n",
    )
    .unwrap();
    let w = Web::nouveau(config).unwrap();
    std::thread::spawn(move || servir(ecoute, w));
    Banc {
        _dossier: dossier,
        d,
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

fn quarantaine(b: &Banc) -> Vec<String> {
    let contenu = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .journal_audit()
        .lire()
        .unwrap();
    contenu
        .split(|o| *o == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(
            |l| match barbacane_audit::Enregistrement::analyser(l).ok()?.evenement {
                Evenement::Quarantaine { action, .. } => Some(action),
                _ => None,
            },
        )
        .collect()
}

fn demande(page: &str) -> String {
    let i = page.find("name=\"demande\" value=\"").expect("demande") + 22;
    page[i..].split('"').next().unwrap().to_owned()
}

#[test]
fn quarantaine_desactivee_double_validation_auditeur_refuse() {
    let b = banc();
    let (ca, csrf_a) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let (cc, csrf_c) = connecter(&b, &b.carole, "carole", MDP_CAROLE);
    let (cb, csrf_b) = connecter(&b, &b.bob, "bob", MDP_BOB);
    // Auditeur : 403 partout.
    assert_eq!(get(&b, &b.bob, "/quarantaine", Some(&cb)).statut, 403);
    for route in [
        "/quarantaine/activer",
        "/quarantaine/valider",
        "/quarantaine/exporter",
    ] {
        assert_eq!(
            post(&b, &b.bob, route, &cb, &[("csrf", &csrf_b)]).statut,
            403
        );
    }
    // Désactivée, raison affichée ; activation refusée avec « non » (auditée).
    let p = get(&b, &b.alice, "/quarantaine", Some(&ca));
    assert_eq!(p.statut, 200);
    assert!(p.texte().contains("Désactivée") && p.texte().contains("mesures_dr_serveur: non"));
    let r = post(
        &b,
        &b.alice,
        "/quarantaine/activer",
        &ca,
        &[("csrf", &csrf_a)],
    );
    assert_eq!(r.statut, 400);
    assert!(r.texte().contains("activation refusée"), "{}", r.texte());
    assert!(quarantaine(&b).contains(&"activation-refusee".to_owned()));
    // Fichier de TEST à « en place » : demande par alice, refus si alice valide, OK par carole.
    std::fs::write(
        b.d.join("dossier-homologation.md"),
        "mesures_dr_serveur: en place\n",
    )
    .unwrap();
    let r = post(
        &b,
        &b.alice,
        "/quarantaine/activer",
        &ca,
        &[("csrf", &csrf_a)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let id = demande(&r.texte());
    let r = post(
        &b,
        &b.alice,
        "/quarantaine/valider",
        &ca,
        &[("csrf", &csrf_a), ("demande", &id)],
    );
    assert_eq!(r.statut, 400);
    assert!(r.texte().contains("second administrateur"));
    let r = post(
        &b,
        &b.carole,
        "/quarantaine/valider",
        &cc,
        &[("csrf", &csrf_c), ("demande", &id)],
    );
    assert_eq!(r.statut, 200);
    assert!(r.texte().contains("Active"));
    // Un élément déposé (comme par la passerelle), export par double validation.
    let admin = Admin::ouvrir(b.passerelle.clone()).unwrap();
    let q = barbacane_passerelle::quarantaine::Quarantaine::ouvrir(
        &admin.stockage,
        &b.passerelle.dossier_homologation,
    )
    .unwrap();
    let contenu = b"fichier bloque de TEST";
    let e = q
        .recevoir(
            "borne-1",
            &barbacane_protocole::quarantaine::DepotQuarantaine {
                version: barbacane_protocole::VERSION,
                sha256: barbacane_passerelle::outils::sha256_hex(contenu),
                taille: contenu.len() as u64,
                contenu_b64: data_encoding::BASE64.encode(contenu),
            },
            "passerelle",
            maintenant(),
        )
        .unwrap();
    let r = post(
        &b,
        &b.alice,
        "/quarantaine/exporter",
        &ca,
        &[("csrf", &csrf_a), ("element", &e.id)],
    );
    assert_eq!(r.statut, 200);
    let id = demande(&r.texte());
    // Export simple refusé.
    let r = post(
        &b,
        &b.alice,
        "/quarantaine/valider",
        &ca,
        &[("csrf", &csrf_a), ("demande", &id)],
    );
    assert_eq!(r.statut, 400);
    let r = post(
        &b,
        &b.carole,
        "/quarantaine/valider",
        &cc,
        &[("csrf", &csrf_c), ("demande", &id)],
    );
    assert_eq!(r.statut, 200);
    assert!(r.entetes.contains("application/octet-stream"));
    assert!(r.entetes.contains(&format!("quarantaine-{}.bin", e.id)));
    assert_eq!(r.corps, contenu);
    let a = quarantaine(&b);
    for x in [
        "activation-validee",
        "reception",
        "export-demande",
        "validation-refusee",
        "export-valide",
    ] {
        assert!(a.contains(&x.to_owned()), "{x} : {a:?}");
    }
}
