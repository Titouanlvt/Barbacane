//! Preuves de la page « ISO des bornes » (`docs/suite/serveur-iso-bornes.md`) : vraie écoute
//! TLS, vrai outil de remaster (`serveur/iso-bornes/barbacane-iso-borne`, xorriso requis) sur de
//! petites ISO synthétiques, vrai registre (jeton 1 h, usage unique).

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

const MDP_ALICE: &str = "phrase de passe de TEST, premier compte";
const MDP_BOB: &str = "phrase de passe de TEST, deuxième compte";

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

/// Petite ISO : arborescence `arbre` mappée à la racine.
fn iso(arbre: &Path, sortie: &Path) {
    executer(
        Command::new("xorriso")
            .args(["-report_about", "SORRY", "-outdev"])
            .arg(sortie)
            .args(["-volid", "BARBACANE", "-map"])
            .arg(arbre)
            .arg("/"),
    );
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
    // ISO embarquées : générique en ligne (port d'enrôlement de la passerelle) et hors ligne.
    let isos = d.join("iso-bornes");
    let el = d.join("el/barbacane/en-ligne");
    std::fs::create_dir_all(&el).unwrap();
    std::fs::write(
        el.join("agent.toml"),
        "adresse = \"127.0.0.1\"\nport_enrolement = 41002\nport_service = 41001\n",
    )
    .unwrap();
    std::fs::write(d.join("el/barbacane/paquet.deb"), vec![7u8; 200_000]).unwrap();
    std::fs::create_dir_all(d.join("hl/barbacane")).unwrap();
    std::fs::write(d.join("hl/barbacane/preseed.cfg"), "hors ligne").unwrap();
    std::fs::create_dir_all(&isos).unwrap();
    iso(&d.join("el"), &isos.join("barbacane-borne-en-ligne.iso"));
    iso(&d.join("hl"), &isos.join("barbacane-borne-hors-ligne.iso"));
    let sums = executer(
        Command::new("sh")
            .arg("-c")
            .arg(format!("cd {} && sha256sum ./*.iso", isos.display())),
    );
    std::fs::write(isos.join("SHA256SUMS"), sums).unwrap();
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let web = ecoute.local_addr().unwrap();
    let config = Config::analyser(&format!(
        "adresse = 127.0.0.1\nport = {}\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_administrateurs = {d}/ca-admin.pem\ncrl_administrateurs = {d}/crl-admin.pem\ncomptes = {d}/comptes\npasserelle = {d}/passerelle.conf\ncle_audit_publique = {d}/audit.pub\niso_bornes = {i}\noutil_iso_borne = {o}\n",
        web.port(),
        p = pki.display(),
        d = d.display(),
        i = isos.display(),
        o = racine().join("serveur/iso-bornes/barbacane-iso-borne").display()
    ))
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

fn actions(b: &Banc) -> Vec<String> {
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
                Evenement::Administration { action } => Some(action),
                _ => None,
            },
        )
        .collect()
}

#[test]
fn page_iso_bornes_de_bout_en_bout() {
    let b = banc();
    // Auditeur : page et actions interdites.
    let (cb, csrf_b) = connecter(&b, &b.bob, "bob", MDP_BOB);
    assert_eq!(get(&b, &b.bob, "/iso-bornes", Some(&cb)).statut, 403);
    for (route, champs) in [
        (
            "/iso-bornes/preparer",
            vec![("csrf", csrf_b.as_str()), ("site", "site-3")],
        ),
        (
            "/iso-bornes/telecharger",
            vec![("csrf", csrf_b.as_str()), ("fichier", "generique")],
        ),
    ] {
        assert_eq!(post(&b, &b.bob, route, &cb, &champs).statut, 403, "{route}");
    }
    assert!(
        !b.d.join("etat/iso-personnalisees")
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    );

    // Administrateur : empreintes affichées, téléchargements.
    let (ca, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let page = get(&b, &b.alice, "/iso-bornes", Some(&ca));
    assert_eq!(page.statut, 200);
    let sums = std::fs::read_to_string(b.d.join("iso-bornes/SHA256SUMS")).unwrap();
    let e_el = sums.lines().find(|l| l.contains("en-ligne")).unwrap()[..64].to_owned();
    let groupe = barbacane_web::pages::grouper(&e_el);
    assert!(page.texte().contains(&groupe), "empreinte affichée");
    assert!(!page.texte().contains("<script"));
    let g = post(
        &b,
        &b.alice,
        "/iso-bornes/telecharger",
        &ca,
        &[("csrf", &csrf), ("fichier", "generique")],
    );
    assert_eq!(g.statut, 200);
    assert!(
        g.entetes
            .contains("attachment; filename=\"barbacane-borne-en-ligne.iso\"")
    );
    assert_eq!(
        g.corps,
        std::fs::read(b.d.join("iso-bornes/barbacane-borne-en-ligne.iso")).unwrap()
    );
    assert_eq!(
        post(
            &b,
            &b.alice,
            "/iso-bornes/telecharger",
            &ca,
            &[("csrf", "faux"), ("fichier", "generique")]
        )
        .statut,
        403
    );

    // ISO personnalisée.
    let r = post(
        &b,
        &b.alice,
        "/iso-bornes/preparer",
        &ca,
        &[("csrf", &csrf), ("site", "site-3")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let t = r.texte();
    let i = t.rfind("name=\"fichier\" value=\"").unwrap() + 22;
    let id = t[i..i + 32].to_owned();
    assert!(id.bytes().all(|c| c.is_ascii_hexdigit()));
    let p = post(
        &b,
        &b.alice,
        "/iso-bornes/telecharger",
        &ca,
        &[("csrf", &csrf), ("fichier", &id)],
    );
    assert_eq!(p.statut, 200);
    assert!(p.entetes.contains("barbacane-borne-site-3.iso"));
    let deuxieme = post(
        &b,
        &b.alice,
        "/iso-bornes/telecharger",
        &ca,
        &[("csrf", &csrf), ("fichier", &id)],
    );
    assert_eq!(deuxieme.statut, 404, "téléchargement unique");
    assert!(
        !b.d.join("etat/iso-personnalisees").join(&id).exists(),
        "ISO supprimée après usage"
    );
    // Le jeton n'apparaît que dans l'ISO.
    let tele = b.d.join("perso.iso");
    std::fs::write(&tele, &p.corps).unwrap();
    executer(
        Command::new("xorriso")
            .args(["-osirrox", "on", "-indev"])
            .arg(&tele)
            .args(["-extract", "/barbacane/en-ligne/parametres.conf"])
            .arg(b.d.join("p.conf")),
    );
    let params = std::fs::read_to_string(b.d.join("p.conf")).unwrap();
    let jeton = params
        .lines()
        .find_map(|l| l.strip_prefix("jeton = "))
        .unwrap()
        .to_owned();
    assert!(
        params.contains("site = site-3")
            && params.contains("adresse = 127.0.0.1")
            && params.contains("port_enrolement = 41002")
    );
    assert!(jeton.starts_with("41002-"));
    assert!(!t.contains(&jeton[6..]), "jeton jamais affiché");

    // Jeton de l'ISO : expiré refusé, valable une fois, puis refusé.
    let secret = &jeton[6..];
    let admin = Admin::ouvrir(b.passerelle.clone()).unwrap();
    let t0 = maintenant();
    let deposer = |t: u64, n: &str| {
        admin
            .stockage
            .transaction(|r| r.deposer(secret, "csr", &"a".repeat(64), "2.0.0", n, t))
    };
    assert!(deposer(t0 + 3601, "d1").is_err(), "jeton expiré refusé");
    assert!(deposer(t0, "d2").is_ok(), "jeton de l'ISO accepté une fois");
    assert!(deposer(t0, "d3").is_err(), "jeton utilisé refusé");

    // ISO expirée (jeton périmé) : plus téléchargeable, supprimée.
    let r = post(
        &b,
        &b.alice,
        "/iso-bornes/preparer",
        &ca,
        &[("csrf", &csrf), ("site", "site-4")],
    );
    let t = r.texte();
    let i = t.rfind("name=\"fichier\" value=\"").unwrap() + 22;
    let id2 = t[i..i + 32].to_owned();
    std::fs::write(
        b.d.join("etat/iso-personnalisees")
            .join(&id2)
            .join("expire"),
        "1",
    )
    .unwrap();
    assert_eq!(
        post(
            &b,
            &b.alice,
            "/iso-bornes/telecharger",
            &ca,
            &[("csrf", &csrf), ("fichier", &id2)]
        )
        .statut,
        404
    );
    assert!(!b.d.join("etat/iso-personnalisees").join(&id2).exists());

    // Site invalide refusé, rien produit.
    assert_eq!(
        post(
            &b,
            &b.alice,
            "/iso-bornes/preparer",
            &ca,
            &[("csrf", &csrf), ("site", "site-1;x")]
        )
        .statut,
        400
    );

    let a = actions(&b);
    for x in [
        "iso-borne-telechargee:generique",
        "iso-borne-preparee:site-3",
        "iso-borne-telechargee:site-3",
        "iso-borne-preparee:site-4",
    ] {
        assert!(a.iter().any(|y| y == x), "audit {x} : {a:?}");
    }
}
