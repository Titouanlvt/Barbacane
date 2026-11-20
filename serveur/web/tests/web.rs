//! Preuves de l'interface web d'administration (`docs/suite/serveur-web.md` §5) : vraie écoute
//! TLS 1.3 sur un port local, PKI des bornes de TEST (`serveur/pki/racine-test.sh`, openssl
//! requis), CA « administrateurs » de TEST générée ici (rcgen), vraie passerelle pour
//! l'enrôlement de bout en bout, `.bcu` préparé par le vrai script (minisign, zstd, python3).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_audit::{CleAudit, ClePublique, Enregistrement, Evenement, verifier};
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::registre::{Borne, StatutBorne};
use barbacane_passerelle::{Passerelle, fournisseur, servir_enrolement};
use barbacane_protocole::{AccuseDemande, Decision, EtatDemande, VERSION, decoder, route};
use barbacane_web::comptes::{Role, ligne_compte};
use barbacane_web::{Config, Web, servir};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";
const MDP_ALICE: &str = "alice : phrase de passe de TEST";
const MDP_BOB: &str = "bob : phrase de passe de TEST";

/// Identité TLS d'un administrateur.
struct Ident {
    chaine: Vec<CertificateDer<'static>>,
    cle: PrivateKeyDer<'static>,
}

struct Banc {
    dossier: tempfile::TempDir,
    pki: PathBuf,
    web: SocketAddr,
    enrolement: SocketAddr,
    passerelle: barbacane_passerelle::Config,
    cle_audit_pub: PathBuf,
    /// Administrateur, auditeur, administrateur révoqué, certificat sans compte.
    alice: Ident,
    bob: Ident,
    eve: Ident,
    carol: Ident,
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

fn temps(decalage_s: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::seconds(decalage_s)
}

/// Certificat d'administrateur (P-256, clientAuth) signé par la CA de test.
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

fn ecrire_0600(chemin: &Path, contenu: &str) {
    std::fs::write(chemin, contenu).unwrap();
    std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn banc() -> Banc {
    let dossier = tempfile::tempdir().unwrap();
    let d = dossier.path();
    let pki = d.join("pki");
    executer(
        Command::new(racine().join("serveur/pki/racine-test.sh"))
            .arg("--cas-de-test")
            .arg(&pki),
    );
    // CA « administrateurs » de TEST (P-384), certificats et CRL (eve révoquée).
    let ca_cle = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(
        DnType::CommonName,
        "Barbacane TEST CA administrateurs — NE PAS UTILISER EN PRODUCTION",
    );
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = temps(-3600);
    p.not_after = temps(365 * 86400);
    let ca = p.self_signed(&ca_cle).unwrap();
    std::fs::write(d.join("ca-admin.pem"), ca.pem()).unwrap();
    let issuer = Issuer::from_ca_cert_der(ca.der(), ca_cle).unwrap();
    let alice = administrateur(&issuer, "alice", 1);
    let bob = administrateur(&issuer, "bob", 2);
    let eve = administrateur(&issuer, "eve", 3);
    let carol = administrateur(&issuer, "carol", 4);
    let crl = CertificateRevocationListParams {
        this_update: temps(-60),
        next_update: temps(7 * 86400),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from_slice(&[0x40, 3]),
            revocation_time: temps(-60),
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap();
    std::fs::write(d.join("crl-admin.pem"), crl.pem().unwrap()).unwrap();
    // Comptes (mots de passe de TEST) ; carol a un certificat valide mais aucun compte.
    let comptes = [
        ligne_compte("alice", Role::Administrateur, &alice.chaine[0], MDP_ALICE).unwrap(),
        ligne_compte("bob", Role::Auditeur, &bob.chaine[0], MDP_BOB).unwrap(),
        ligne_compte("eve", Role::Administrateur, &eve.chaine[0], MDP_ALICE).unwrap(),
    ]
    .join("\n");
    ecrire_0600(&d.join("comptes"), &comptes);
    let cle_audit = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    let cle_audit_pub = d.join("audit.pub");
    std::fs::write(&cle_audit_pub, cle_audit.publique().pem()).unwrap();
    // Passerelle : écoute d'enrôlement réelle (le service n'est pas nécessaire ici).
    let ecoute_enrolement = TcpListener::bind("127.0.0.1:0").unwrap();
    let enrolement = ecoute_enrolement.local_addr().unwrap();
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let conf_passerelle = format!(
        "adresse = 127.0.0.1\nport = {}\nport_enrolement = {}\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_bornes = {p}/ca-bornes/cert.pem\ncle_ca_bornes = {p}/ca-bornes/cle.pem\ncrl_bornes = {p}/ca-bornes/crl.pem\nregistre = {}\n",
        service.local_addr().unwrap().port(),
        enrolement.port(),
        d.join("etat").display(),
        p = pki.display()
    );
    std::fs::write(d.join("passerelle.conf"), &conf_passerelle).unwrap();
    let passerelle = barbacane_passerelle::Config::analyser(&conf_passerelle).unwrap();
    let gw = Passerelle::nouvelle(passerelle.clone()).unwrap();
    std::thread::spawn(move || servir_enrolement(ecoute_enrolement, gw));
    // Interface web.
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let web = ecoute.local_addr().unwrap();
    let config = Config::analyser(&format!(
        "adresse = 127.0.0.1\nport = {}\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_administrateurs = {d}/ca-admin.pem\ncrl_administrateurs = {d}/crl-admin.pem\ncomptes = {d}/comptes\npasserelle = {d}/passerelle.conf\ncle_audit_publique = {d}/audit.pub\n",
        web.port(),
        p = pki.display(),
        d = d.display()
    ))
    .unwrap();
    let w = Web::nouveau(config).unwrap();
    std::thread::spawn(move || servir(ecoute, w));
    Banc {
        dossier,
        pki,
        web,
        enrolement,
        passerelle,
        cle_audit_pub,
        alice,
        bob,
        eve,
        carol,
    }
}

/// Réponse HTTP analysée.
#[derive(Debug)]
struct Rep {
    statut: u16,
    entetes: Vec<(String, String)>,
    corps: String,
}

impl Rep {
    fn entete(&self, nom: &str) -> Option<&str> {
        self.entetes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nom))
            .map(|(_, v)| v.as_str())
    }

    /// Identifiant de session posé par `Set-Cookie`.
    fn cookie(&self) -> Option<String> {
        let v = self.entete("Set-Cookie")?;
        let id = v.strip_prefix("__Host-barbacane=")?.split(';').next()?;
        (!id.is_empty()).then(|| id.to_owned())
    }

    /// Jeton anti-CSRF du premier formulaire de la page.
    fn csrf(&self) -> String {
        let debut = self
            .corps
            .find("name=\"csrf\" value=\"")
            .unwrap_or_else(|| panic!("pas de jeton CSRF : {}", self.corps))
            + 19;
        self.corps[debut..].split('"').next().unwrap().to_owned()
    }
}

/// Envoie des octets bruts sur une connexion TLS (le client épingle la CA serveur de test).
fn envoyer(
    adresse: SocketAddr,
    pki: &Path,
    id: Option<&Ident>,
    brut: &[u8],
) -> Result<Rep, String> {
    let mut ancres = RootCertStore::empty();
    ancres
        .add(CertificateDer::from_pem_file(pki.join("ca-serveur/cert.pem")).unwrap())
        .unwrap();
    let c = ClientConfig::builder_with_provider(Arc::new(fournisseur()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(ancres);
    let config = match id {
        Some(i) => c
            .with_client_auth_cert(i.chaine.clone(), i.cle.clone_key())
            .unwrap(),
        None => c.with_no_client_auth(),
    };
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from(NOM_SERVEUR).unwrap())
        .unwrap();
    let flux = TcpStream::connect(adresse).unwrap();
    flux.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut tls = StreamOwned::new(conn, flux);
    tls.write_all(brut).map_err(|e| e.to_string())?;
    let mut o = Vec::new();
    tls.read_to_end(&mut o).map_err(|e| e.to_string())?;
    let texte = String::from_utf8_lossy(&o).into_owned();
    let (entete, corps) = texte
        .split_once("\r\n\r\n")
        .ok_or("réponse sans en-têtes")?;
    let mut lignes = entete.split("\r\n");
    let statut = lignes
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("statut")?;
    let entetes = lignes
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    Ok(Rep {
        statut,
        entetes,
        corps: corps.to_owned(),
    })
}

fn get(b: &Banc, id: &Ident, chemin: &str, cookie: Option<&str>) -> Rep {
    let c = cookie
        .map(|c| format!("Cookie: __Host-barbacane={c}\r\n"))
        .unwrap_or_default();
    envoyer(
        b.web,
        &b.pki,
        Some(id),
        format!("GET {chemin} HTTP/1.1\r\nHost: admin\r\n{c}\r\n").as_bytes(),
    )
    .unwrap()
}

fn post_brut(b: &Banc, id: &Ident, chemin: &str, cookie: &str, extra: &str, corps: &str) -> Rep {
    envoyer(
        b.web,
        &b.pki,
        Some(id),
        format!(
            "POST {chemin} HTTP/1.1\r\nHost: admin\r\nCookie: __Host-barbacane={cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{extra}\r\n{corps}",
            corps.len()
        )
        .as_bytes(),
    )
    .unwrap()
}

fn formulaire(champs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in champs {
        s.append_pair(k, v);
    }
    s.finish()
}

fn post(b: &Banc, id: &Ident, chemin: &str, cookie: &str, champs: &[(&str, &str)]) -> Rep {
    post_brut(b, id, chemin, cookie, "", &formulaire(champs))
}

/// Tentative de connexion : (réponse du POST, cookie de session éventuel).
fn tenter(b: &Banc, id: &Ident, identifiant: &str, mdp: &str) -> (Rep, Option<String>) {
    let page = get(b, id, "/connexion", None);
    assert_eq!(page.statut, 200, "{}", page.corps);
    let pre = page.cookie().expect("pré-session");
    let r = post(
        b,
        id,
        "/connexion",
        &pre,
        &[
            ("csrf", &page.csrf()),
            ("identifiant", identifiant),
            ("mot_de_passe", mdp),
        ],
    );
    let c = r.cookie();
    (r, c)
}

/// Session ouverte : (cookie, jeton CSRF de la session).
fn connecter(b: &Banc, id: &Ident, identifiant: &str, mdp: &str) -> (String, String) {
    let (r, c) = tenter(b, id, identifiant, mdp);
    assert_eq!(r.statut, 303, "{}", r.corps);
    assert_eq!(r.entete("Location"), Some("/tableau"));
    let c = c.expect("cookie de session");
    let t = get(b, id, "/tableau", Some(&c));
    assert_eq!(t.statut, 200, "{}", t.corps);
    let csrf = t.csrf();
    (c, csrf)
}

fn journal(b: &Banc) -> Vec<Enregistrement> {
    let contenu = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .journal_audit()
        .lire()
        .unwrap();
    let cle = ClePublique::lire(&b.cle_audit_pub).unwrap();
    verifier(&contenu, &cle, &[]).expect("journal d'audit intègre");
    contenu
        .split(|o| *o == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| Enregistrement::analyser(l).unwrap())
        .collect()
}

fn administration(e: &Enregistrement, acteur: &str, action: &str) -> bool {
    e.acteur == acteur
        && e.evenement
            == Evenement::Administration {
                action: action.into(),
            }
}

// ───────────────────────────── Preuves ────────────────────────────────────────────────────────

#[test]
fn sans_certificat_refus_tls() {
    let b = banc();
    let e = envoyer(b.web, &b.pki, None, b"GET /connexion HTTP/1.1\r\n\r\n").unwrap_err();
    assert!(!e.is_empty());
    // Même une ressource statique exige le certificat.
    assert!(
        envoyer(
            b.web,
            &b.pki,
            None,
            b"GET /statique/barbacane.css HTTP/1.1\r\n\r\n"
        )
        .is_err()
    );
    // Un certificat de BORNE (autre CA) n'ouvre pas l'interface d'administration.
    let borne = Ident {
        chaine: vec![
            CertificateDer::from_pem_file(b.pki.join("bornes/borne-01.cert.pem")).unwrap(),
        ],
        cle: PrivateKeyDer::from_pem_file(b.pki.join("bornes/borne-01.cle.pem")).unwrap(),
    };
    assert!(
        envoyer(
            b.web,
            &b.pki,
            Some(&borne),
            b"GET /connexion HTTP/1.1\r\n\r\n"
        )
        .is_err()
    );
}

#[test]
fn certificat_revoque_refus_tls() {
    let b = banc();
    assert!(
        envoyer(
            b.web,
            &b.pki,
            Some(&b.eve),
            b"GET /connexion HTTP/1.1\r\n\r\n"
        )
        .is_err()
    );
    assert_eq!(get(&b, &b.alice, "/connexion", None).statut, 200);
}

#[test]
fn certificat_sans_mot_de_passe_pas_de_session() {
    let b = banc();
    // Certificat valide, aucune session : redirection vers la connexion, rien n'est servi.
    let r = get(&b, &b.alice, "/tableau", None);
    assert_eq!((r.statut, r.entete("Location")), (303, Some("/connexion")));
    assert!(!r.corps.contains("Bornes"));
    // Cookie inventé.
    let r = get(&b, &b.alice, "/tableau", Some(&"ab".repeat(32)));
    assert_eq!(r.statut, 303);
    // Mauvais mot de passe, compte inconnu, certificat sans compte, mot de passe de bob avec le
    // certificat d'alice : tous refusés avec le même message, aucune session.
    for (id, ident, mdp) in [
        (&b.alice, "alice", "mauvais mot de passe !"),
        (&b.alice, "mallory", MDP_ALICE),
        (&b.carol, "alice", MDP_ALICE),
        (&b.alice, "bob", MDP_BOB),
    ] {
        let (r, c) = tenter(&b, id, ident, mdp);
        assert_eq!(r.statut, 403, "{ident}");
        assert!(
            r.corps
                .contains("Identifiant, mot de passe ou certificat refusé.")
        );
        // Le seul cookie posé est une nouvelle pré-session : elle n'ouvre rien.
        let r = get(&b, id, "/tableau", c.as_deref());
        assert_eq!(r.statut, 303, "{ident}");
    }
    // Session d'alice inutilisable avec un autre certificat (cookie volé).
    let (c, _) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    assert_eq!(get(&b, &b.carol, "/tableau", Some(&c)).statut, 303);
    assert_eq!(
        get(&b, &b.alice, "/tableau", Some(&c)).statut,
        303,
        "session détruite"
    );
    // Anti force brute : 5 échecs → même le bon mot de passe est refusé.
    for _ in 0..5 {
        assert_eq!(
            tenter(&b, &b.bob, "bob", "mauvais mot de passe !").0.statut,
            403
        );
    }
    assert_eq!(tenter(&b, &b.bob, "bob", MDP_BOB).0.statut, 403);
    let j = journal(&b);
    assert!(
        j.iter()
            .any(|e| administration(e, "web:alice", "connexion"))
    );
    assert!(
        j.iter()
            .any(|e| administration(e, "web:alice", "connexion-refusee"))
    );
    assert!(
        j.iter()
            .any(|e| administration(e, "web:bob", "connexion-verrouillee"))
    );
}

#[test]
fn auditeur_ne_peut_pas_poster() {
    let b = banc();
    let (c, csrf) = connecter(&b, &b.bob, "bob", MDP_BOB);
    for page in [
        "/tableau",
        "/enrolement",
        "/maj",
        "/audit",
        "/audit/verification",
    ] {
        let r = get(&b, &b.bob, page, Some(&c));
        assert_eq!(r.statut, 200, "{page}");
        assert!(!r.corps.contains("action=\"/enrolement/jeton\""));
        assert!(!r.corps.contains("action=\"/maj/depot\""));
    }
    for chemin in [
        "/enrolement/jeton",
        "/enrolement/valider",
        "/bornes/revoquer",
        "/maj/diffuser",
    ] {
        let r = post(
            &b,
            &b.bob,
            chemin,
            &c,
            &[("csrf", &csrf), ("site", "site-1")],
        );
        assert_eq!(r.statut, 403, "{chemin}");
    }
    assert_eq!(
        get(&b, &b.bob, "/enrolement/demande?id=x", Some(&c)).statut,
        404
    );
    let reg = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .lire()
        .unwrap();
    assert!(reg.jetons.is_empty(), "aucun jeton créé par l'auditeur");
    // La déconnexion reste permise.
    let r = post(&b, &b.bob, "/deconnexion", &c, &[("csrf", &csrf)]);
    assert_eq!(r.statut, 303);
    assert_eq!(get(&b, &b.bob, "/tableau", Some(&c)).statut, 303);
}

#[test]
fn post_sans_jeton_csrf_refuse() {
    let b = banc();
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let site = [("site", "site-1")];
    assert_eq!(
        post(&b, &b.alice, "/enrolement/jeton", &c, &site).statut,
        403
    );
    let r = post(
        &b,
        &b.alice,
        "/enrolement/jeton",
        &c,
        &[("csrf", "00"), ("site", "site-1")],
    );
    assert_eq!(r.statut, 403);
    // Bon jeton mais requête d'une autre origine.
    let corps = formulaire(&[("csrf", &csrf), ("site", "site-1")]);
    let r = post_brut(
        &b,
        &b.alice,
        "/enrolement/jeton",
        &c,
        "Sec-Fetch-Site: cross-site\r\n",
        &corps,
    );
    assert_eq!(r.statut, 403);
    let reg = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .lire()
        .unwrap();
    assert!(reg.jetons.is_empty());
    // Connexion sans jeton de pré-session : refusée.
    let page = get(&b, &b.alice, "/connexion", None);
    let r = post(
        &b,
        &b.alice,
        "/connexion",
        &page.cookie().unwrap(),
        &[("identifiant", "alice"), ("mot_de_passe", MDP_ALICE)],
    );
    assert_eq!((r.statut, r.cookie()), (403, None));
    // Avec le jeton : accepté.
    let r = post_brut(
        &b,
        &b.alice,
        "/enrolement/jeton",
        &c,
        "Sec-Fetch-Site: same-origin\r\n",
        &corps,
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(r.corps.contains("class=\"b-code\""));
}

#[test]
fn nom_de_borne_malveillant_echappe() {
    let b = banc();
    let admin = Admin::ouvrir(b.passerelle.clone()).unwrap();
    let t = maintenant();
    admin
        .stockage
        .transaction(|r| {
            r.bornes.push(Borne {
                uuid: "11111111-2222-4333-8444-555555555555".into(),
                nom: "<script>alert(1)</script>".into(),
                site: "site-1\"><img src=x onerror=alert(2)>".into(),
                statut: StatutBorne::Active,
                certificat_pem: String::new(),
                serie: "41".into(),
                serie_precedente: None,
                emis_le: t,
                expire_le: t + 90 * 86400,
                derniere_vue: Some(t),
                ecart_horloge_s: Some(0),
                dernier_battement: None,
            });
            Ok(())
        })
        .unwrap();
    let (c, _) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    for page in [
        "/tableau",
        "/bornes/revoquer?uuid=11111111-2222-4333-8444-555555555555",
    ] {
        let r = get(&b, &b.alice, page, Some(&c));
        assert_eq!(r.statut, 200, "{page}");
        assert!(!r.corps.contains("<script"), "{page}");
        assert!(!r.corps.contains("<img"), "{page}");
        assert!(
            r.corps.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{page}"
        );
    }
}

const CSP: &str = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[test]
fn entetes_de_securite_presents() {
    let b = banc();
    let connexion = get(&b, &b.alice, "/connexion", None);
    let cookie = connexion.entete("Set-Cookie").unwrap().to_owned();
    for attendu in [
        "__Host-barbacane=",
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
    ] {
        assert!(cookie.contains(attendu), "{cookie}");
    }
    let (c, _) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    for (page, cache) in [
        ("/connexion", "no-store"),
        ("/tableau", "no-store"),
        ("/audit", "no-store"),
        ("/page-inconnue", "no-store"),
        ("/statique/barbacane.css", "private, max-age=86400"),
    ] {
        let r = get(&b, &b.alice, page, Some(&c));
        assert_eq!(r.entete("Content-Security-Policy"), Some(CSP), "{page}");
        assert_eq!(r.entete("X-Frame-Options"), Some("DENY"));
        assert_eq!(r.entete("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(r.entete("Referrer-Policy"), Some("no-referrer"));
        assert_eq!(r.entete("Cross-Origin-Opener-Policy"), Some("same-origin"));
        assert!(r.entete("Strict-Transport-Security").is_some());
        assert_eq!(r.entete("Cache-Control"), Some(cache), "{page}");
        assert!(!r.corps.contains("<script"), "aucun JavaScript : {page}");
        assert!(
            !r.corps.contains(" style="),
            "aucun style en ligne : {page}"
        );
    }
    let police = get(&b, &b.alice, "/statique/polices/JetBrainsMono.ttf", None);
    assert_eq!(
        (police.statut, police.entete("Content-Type")),
        (200, Some("font/ttf"))
    );
}

#[test]
fn requete_trop_grosse_refusee() {
    let b = banc();
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let gros = format!("GET /tableau HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(10_000));
    assert_eq!(
        envoyer(b.web, &b.pki, Some(&b.alice), gros.as_bytes())
            .unwrap()
            .statut,
        431
    );
    let corps = formulaire(&[("csrf", &csrf), ("site", &"1".repeat(20_000))]);
    assert_eq!(
        post_brut(&b, &b.alice, "/enrolement/jeton", &c, "", &corps).statut,
        413
    );
    let r = envoyer(
        b.web,
        &b.pki,
        Some(&b.alice),
        format!("POST /enrolement/jeton HTTP/1.1\r\nCookie: __Host-barbacane={c}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes(),
    )
    .unwrap();
    assert_eq!(r.statut, 400);
}

/// Dépose une demande d'enrôlement comme le ferait une borne (vraie écoute d'enrôlement).
fn demande_borne(b: &Banc, jeton: &str) -> (AccuseDemande, KeyPair) {
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&cle)
        .unwrap()
        .pem()
        .unwrap();
    let secret = jeton.split_once('-').unwrap().1;
    let corps = serde_json::json!({"version": VERSION, "jeton": secret, "csr_pem": csr, "version_logiciel": "2.0.0"}).to_string();
    let r = envoyer(
        b.enrolement,
        &b.pki,
        None,
        format!(
            "POST {} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{corps}",
            route::DEMANDE,
            corps.len()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(r.statut, 202, "{}", r.corps);
    (decoder(r.corps.as_bytes()).unwrap(), cle)
}

fn retrait(b: &Banc, id: &str) -> EtatDemande {
    let corps = serde_json::json!({"version": VERSION, "demande_id": id}).to_string();
    let r = envoyer(
        b.enrolement,
        &b.pki,
        None,
        format!(
            "POST {} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{corps}",
            route::RETRAIT,
            corps.len()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(r.statut, 200, "{}", r.corps);
    decoder(r.corps.as_bytes()).unwrap()
}

#[test]
fn validation_d_enrolement_de_bout_en_bout() {
    let b = banc();
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    // 1. Jeton créé par la page, affiché une fois.
    let r = post(
        &b,
        &b.alice,
        "/enrolement/jeton",
        &c,
        &[("csrf", &csrf), ("site", "site-1")],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    let debut = r.corps.find("<div class=\"b-code\">").unwrap() + 20;
    let jeton = r.corps[debut..].split('<').next().unwrap().to_owned();
    assert!(
        !get(&b, &b.alice, "/enrolement", Some(&c))
            .corps
            .contains(&jeton)
    );
    // 2. La borne dépose sa demande et affiche son empreinte.
    let (accuse, _cle) = demande_borne(&b, &jeton);
    let empreinte = accuse.empreinte.clone();
    // 3. La page d'examen n'affiche PAS l'empreinte.
    let url = format!("/enrolement/demande?id={}", accuse.demande_id);
    let page = get(&b, &b.alice, &url, Some(&c));
    assert_eq!(page.statut, 200);
    assert!(!page.corps.contains(&empreinte));
    assert!(!page.corps.contains(&empreinte[..8]));
    // 4. Empreinte mal retapée : refus, rien n'est émis.
    let mut fausse = empreinte.clone();
    fausse.replace_range(..1, if fausse.starts_with('0') { "1" } else { "0" });
    let r = post(
        &b,
        &b.alice,
        "/enrolement/valider",
        &c,
        &[
            ("csrf", &csrf),
            ("id", &accuse.demande_id),
            ("empreinte", &fausse),
            ("nom", "borne-07"),
        ],
    );
    assert_eq!(r.statut, 400, "{}", r.corps);
    assert!(r.corps.contains("empreinte différente"));
    assert_eq!(
        retrait(&b, &accuse.demande_id).decision,
        Decision::EnAttente
    );
    // 5. Empreinte retapée (majuscules, groupes de 4) : certificat émis.
    let saisie = empreinte
        .to_uppercase()
        .as_bytes()
        .chunks(4)
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let r = post(
        &b,
        &b.alice,
        "/enrolement/valider",
        &c,
        &[
            ("csrf", &csrf),
            ("id", &accuse.demande_id),
            ("empreinte", &saisie),
            ("nom", "borne-07"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(r.corps.contains("Demande validée"));
    let etat = retrait(&b, &accuse.demande_id);
    assert_eq!(etat.decision, Decision::Validee);
    let pem = etat.certificat_pem.expect("certificat émis");
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let uuid = cert
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .find_map(|n| match n {
            x509_parser::extensions::GeneralName::URI(u) => u
                .strip_prefix("urn:barbacane:borne:site-1:")
                .map(str::to_owned),
            _ => None,
        })
        .expect("identité Barbacane");
    let tableau = get(&b, &b.alice, "/tableau", Some(&c));
    assert!(tableau.corps.contains("borne-07"));
    // 6. Révocation par la page : confirmation par le nom exigée.
    let page = get(
        &b,
        &b.alice,
        &format!("/bornes/revoquer?uuid={uuid}"),
        Some(&c),
    );
    assert_eq!(page.statut, 200);
    let r = post(
        &b,
        &b.alice,
        "/bornes/revoquer",
        &c,
        &[
            ("csrf", &csrf),
            ("uuid", &uuid),
            ("motif", "volee"),
            ("confirmation", "borne-08"),
        ],
    );
    assert_eq!(r.statut, 400);
    let r = post(
        &b,
        &b.alice,
        "/bornes/revoquer",
        &c,
        &[
            ("csrf", &csrf),
            ("uuid", &uuid),
            ("motif", "volee"),
            ("confirmation", "borne-07"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    let reg = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .lire()
        .unwrap();
    assert!(matches!(reg.bornes[0].statut, StatutBorne::Revoquee { .. }));
    // 7. Journal : chaîne intègre, chaque action attribuée à web:alice.
    let j = journal(&b);
    let acteur = |ev: &dyn Fn(&Evenement) -> bool| {
        j.iter()
            .any(|e| e.acteur == "web:alice" && ev(&e.evenement))
    };
    assert!(acteur(
        &|e| matches!(e, Evenement::JetonCree { site, .. } if site == "site-1")
    ));
    assert!(acteur(
        &|e| matches!(e, Evenement::EnrolementValide { borne, .. } if *borne == uuid)
    ));
    assert!(acteur(
        &|e| matches!(e, Evenement::Revocation { motif, .. } if motif == "volee")
    ));
    assert!(
        j.iter()
            .any(|e| administration(e, "web:alice", "consultation-supervision"))
    );
    // 8. Vérification de la chaîne depuis la page.
    let v = get(&b, &b.alice, "/audit/verification", Some(&c));
    assert!(v.corps.contains("Chaîne intègre"), "{}", v.corps);
    let a = get(&b, &b.alice, "/audit", Some(&c));
    assert!(a.corps.contains("Enrôlement validé"));
}

/// Paire minisign jetable sans phrase de passe.
fn cle_minisign(d: &Path) -> PathBuf {
    executer(
        Command::new("minisign")
            .args(["-G", "-W", "-p"])
            .arg(d.join("maj.pub"))
            .arg("-s")
            .arg(d.join("maj.key")),
    );
    d.join("maj.key")
}

/// Corps multipart : csrf, fichier, signature.
fn multipart(csrf: &str, fichier: &[u8], signature: &[u8]) -> (String, Vec<u8>) {
    let f = "----barbacaneTEST7d1";
    let mut c = Vec::new();
    c.extend_from_slice(
        format!("--{f}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n--{f}\r\nContent-Disposition: form-data; name=\"fichier\"; filename=\"x\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    c.extend_from_slice(fichier);
    c.extend_from_slice(
        format!("\r\n--{f}\r\nContent-Disposition: form-data; name=\"signature\"; filename=\"x.minisig\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    c.extend_from_slice(signature);
    c.extend_from_slice(format!("\r\n--{f}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={f}"), c)
}

fn deposer(b: &Banc, c: &str, chemin: &str, csrf: &str, fichier: &Path) -> Rep {
    let mut sig = fichier.as_os_str().to_owned();
    sig.push(".minisig");
    let (type_contenu, corps) = multipart(
        csrf,
        &std::fs::read(fichier).unwrap(),
        &std::fs::read(PathBuf::from(sig)).unwrap(),
    );
    let mut brut = format!(
        "POST {chemin} HTTP/1.1\r\nCookie: __Host-barbacane={c}\r\nContent-Type: {type_contenu}\r\nContent-Length: {}\r\n\r\n",
        corps.len()
    )
    .into_bytes();
    brut.extend_from_slice(&corps);
    envoyer(b.web, &b.pki, Some(&b.alice), &brut).unwrap()
}

#[test]
fn depot_bcu_par_la_page() {
    let b = banc();
    let d = b.dossier.path().join("maj");
    std::fs::create_dir_all(&d).unwrap();
    let cle = cle_minisign(&d);
    let admin = Admin::ouvrir(b.passerelle.clone()).unwrap();
    std::fs::copy(d.join("maj.pub"), admin.maj.chemin_cle()).unwrap();
    // Plancher et paquet préparés par les vrais scripts.
    executer(
        Command::new(racine().join("serveur/maj/barbacane-plancher-prepare"))
            .arg("--cle")
            .arg(&cle)
            .args(["--version-min", "100", "--sortie"])
            .arg(d.join("plancher")),
    );
    std::fs::write(
        d.join("images.sha256"),
        format!("{}  essai.iso\n", "ab".repeat(32)),
    )
    .unwrap();
    executer(
        Command::new(racine().join("borne/update/barbacane-update-prepare"))
            .arg("--cle")
            .arg(&cle)
            .arg("--sortie")
            .arg(d.join("sortie"))
            .args(["--version", "150", "--sans-clamav", "--images-officielles"])
            .arg(d.join("images.sha256")),
    );
    let bcu = d.join("sortie/barbacane-maj-150.bcu");
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    // Sans jeton anti-CSRF : refusé avant réception des fichiers.
    let r = deposer(
        &b,
        &c,
        "/maj/plancher",
        "faux",
        &d.join("plancher/plancher.json"),
    );
    assert_eq!(r.statut, 403);
    // Paquet avant le plancher : refusé (motif affiché, audité).
    let r = deposer(&b, &c, "/maj/depot", &csrf, &bcu);
    assert_eq!(r.statut, 400, "{}", r.corps);
    assert!(r.corps.contains("Refusé"));
    let r = deposer(
        &b,
        &c,
        "/maj/plancher",
        &csrf,
        &d.join("plancher/plancher.json"),
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    // Paquet altéré : signature invalide.
    let altere = d.join("altere.bcu");
    let mut octets = std::fs::read(&bcu).unwrap();
    let dernier = octets.len() - 1;
    octets[dernier] ^= 1;
    std::fs::write(&altere, octets).unwrap();
    std::fs::copy(
        d.join("sortie/barbacane-maj-150.bcu.minisig"),
        d.join("altere.bcu.minisig"),
    )
    .unwrap();
    let r = deposer(&b, &c, "/maj/depot", &csrf, &altere);
    assert_eq!(r.statut, 400);
    // Paquet valide : accepté, puis diffusé.
    let r = deposer(&b, &c, "/maj/depot", &csrf, &bcu);
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(r.corps.contains("Paquet 150 accepté"));
    let r = post(
        &b,
        &b.alice,
        "/maj/diffuser",
        &c,
        &[("csrf", &csrf), ("version", "150")],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    let etat = admin.maj.lire().unwrap();
    assert_eq!((etat.plancher, etat.diffusee), (Some(100), Some(150)));
    let j = journal(&b);
    assert!(j.iter().any(|e| e.acteur == "web:alice"
        && matches!(
            e.evenement,
            Evenement::MajRefusee {
                refus: barbacane_audit::RefusMaj::PlancherAbsent,
                ..
            }
        )));
    assert!(j.iter().any(|e| e.acteur == "web:alice"
        && matches!(
            e.evenement,
            Evenement::MajRefusee {
                refus: barbacane_audit::RefusMaj::SignatureInvalide,
                ..
            }
        )));
    assert!(j.iter().any(|e| e.acteur == "web:alice"
        && matches!(e.evenement, Evenement::MajDiffusee { version_maj: 150 })));
    // Aucun reste de dépôt temporaire.
    let restes = std::fs::read_dir(b.passerelle.registre.join("depots-web"))
        .unwrap()
        .count();
    assert_eq!(restes, 0);
}

// ───────────── Utilisateurs, sites, clés USB (docs/suite/serveur-utilisateurs.md) ─────────────

fn base_utilisateurs(b: &Banc) -> barbacane_passerelle::utilisateurs::Utilisateurs {
    let admin = Admin::ouvrir(b.passerelle.clone()).unwrap();
    barbacane_passerelle::utilisateurs::Utilisateurs::ouvrir(&admin.stockage).unwrap()
}

fn importer(b: &Banc) {
    base_utilisateurs(b)
        .importer(
            &["j.dupont".into(), "a.martin".into()],
            "annuaire",
            "web:alice",
            maintenant(),
        )
        .unwrap();
}

/// Contenus de tous les fichiers sous `d`.
fn fichiers(d: &Path) -> Vec<u8> {
    let mut o = Vec::new();
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            o.extend(fichiers(&p));
        } else {
            o.extend(std::fs::read(&p).unwrap());
        }
    }
    o
}

const ROUTES_UTILISATEURS: &[&str] = &[
    "/utilisateurs/synchroniser",
    "/utilisateurs/pin",
    "/utilisateurs/deverrouiller",
    "/sites/mode",
    "/sites/entree",
    "/cles-usb/enroler",
    "/cles-usb/retirer",
];

#[test]
fn utilisateurs_auditeur_lecture_seule() {
    let b = banc();
    importer(&b);
    let (c, csrf) = connecter(&b, &b.bob, "bob", MDP_BOB);
    for page in ["/utilisateurs", "/sites", "/cles-usb"] {
        let r = get(&b, &b.bob, page, Some(&c));
        assert_eq!(r.statut, 200, "{page}");
        for action in ROUTES_UTILISATEURS {
            assert!(
                !r.corps.contains(&format!("action=\"{action}\"")),
                "{page} : {action}"
            );
        }
    }
    // L'auditeur voit les identifiants en clair et résout un pseudonyme.
    let r = get(&b, &b.bob, "/utilisateurs", Some(&c));
    assert!(r.corps.contains("j.dupont") && r.corps.contains("a.martin"));
    let ps = base_utilisateurs(&b).pseudonyme("j.dupont");
    let r = get(
        &b,
        &b.bob,
        &format!("/utilisateurs?identifiant={ps}"),
        Some(&c),
    );
    assert!(r.corps.contains("<dd class=\"b-mono\">j.dupont</dd>"));
    for chemin in ROUTES_UTILISATEURS {
        let r = post(
            &b,
            &b.bob,
            chemin,
            &c,
            &[
                ("csrf", &csrf),
                ("identifiant", "j.dupont"),
                ("site", "site-1"),
                ("mode", "authentification"),
                ("entree", "interdite"),
                ("fabricant", "0781"),
                ("serie", "4C53"),
            ],
        );
        assert_eq!(r.statut, 403, "{chemin}");
    }
    let base = base_utilisateurs(&b).lire().unwrap();
    assert!(base.utilisateurs.iter().all(|u| u.pin.is_none()));
    assert!(
        base.sites.is_empty() && base.cles_usb.is_empty(),
        "rien modifié"
    );
    // L'administrateur ne voit que les pseudonymes, sauf le compte qu'il saisit.
    let (ca, _) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let r = get(&b, &b.alice, "/utilisateurs", Some(&ca));
    assert!(!r.corps.contains("j.dupont") && r.corps.contains(&ps));
    let r = get(
        &b,
        &b.alice,
        "/utilisateurs?identifiant=J.Dupont",
        Some(&ca),
    );
    assert!(r.corps.contains("j.dupont") && r.corps.contains("action=\"/utilisateurs/pin\""));
    assert!(!r.corps.contains("a.martin"));
    let j = journal(&b);
    assert!(
        j.iter()
            .any(|e| administration(e, "web:bob", "consultation-utilisateurs"))
    );
}

#[test]
fn reinitialisation_pin_affiche_une_fois() {
    let b = banc();
    importer(&b);
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let r = post(
        &b,
        &b.alice,
        "/utilisateurs/pin",
        &c,
        &[("csrf", &csrf), ("identifiant", "j.dupont")],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    let debut = r.corps.find("<div class=\"b-code\">").expect("PIN affiché") + 20;
    let pin = r.corps[debut..].split('<').next().unwrap().to_owned();
    assert!(
        pin.len() == 8 && pin.bytes().all(|o| o.is_ascii_digit()),
        "{pin}"
    );
    assert!(r.corps.contains("Affiché une seule fois"));
    assert_eq!(r.entete("Cache-Control"), Some("no-store"));
    let r = get(&b, &b.alice, "/utilisateurs?identifiant=j.dupont", Some(&c));
    assert!(!r.corps.contains(&pin), "PIN réaffiché");
    assert!(r.corps.contains("PIN à changer"));
    let etat = fichiers(b.dossier.path());
    assert!(
        !etat.windows(8).any(|f| f == pin.as_bytes()),
        "PIN en clair dans un fichier"
    );
    let ps = base_utilisateurs(&b).pseudonyme("j.dupont");
    let j = journal(&b);
    assert!(j.iter().any(|e| e.acteur == "web:alice"
        && e.evenement
            == Evenement::PinReinitialise {
                utilisateur: ps.clone()
            }));
    // Déverrouillage et mode du site par les pages.
    let u = base_utilisateurs(&b);
    u.transaction(maintenant(), |base| {
        let x = base
            .utilisateurs
            .iter_mut()
            .find(|x| x.identifiant == "j.dupont")
            .unwrap();
        x.verrouille_le = Some(1);
        x.echecs = 5;
        Ok(())
    })
    .unwrap();
    let r = post(
        &b,
        &b.alice,
        "/utilisateurs/deverrouiller",
        &c,
        &[("csrf", &csrf), ("identifiant", "j.dupont")],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(
        u.lire()
            .unwrap()
            .utilisateur("j.dupont")
            .unwrap()
            .verrouille_le
            .is_none()
    );
    let r = post(
        &b,
        &b.alice,
        "/sites/mode",
        &c,
        &[
            ("csrf", &csrf),
            ("site", "site-3"),
            ("mode", "authentification"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(r.corps.contains("site-3"));
    assert_eq!(
        u.lire().unwrap().reglage("site-3").mode,
        barbacane_protocole::utilisateurs::ModeUtilisateurs::Authentification
    );
    let r = post(
        &b,
        &b.alice,
        "/utilisateurs/synchroniser",
        &c,
        &[("csrf", &csrf)],
    );
    assert_eq!(r.statut, 400, "annuaire non configuré dans ce banc");
}

#[test]
fn utilisateurs_csrf_et_echappement() {
    let b = banc();
    importer(&b);
    let (c, csrf) = connecter(&b, &b.alice, "alice", MDP_ALICE);
    let champs = |jeton: &'static str| {
        vec![
            ("csrf", jeton),
            ("identifiant", "j.dupont"),
            ("site", "site-1"),
            ("mode", "authentification"),
            ("entree", "interdite"),
            ("fabricant", "0781"),
            ("serie", "4C53"),
            ("sortie", "1"),
        ]
    };
    for chemin in ROUTES_UTILISATEURS {
        let r = post(&b, &b.alice, chemin, &c, &champs("faux")[1..]);
        assert_eq!(r.statut, 403, "{chemin} sans jeton");
        let r = post(&b, &b.alice, chemin, &c, &champs("faux"));
        assert_eq!(r.statut, 403, "{chemin} faux jeton");
        let corps = formulaire(&[("csrf", csrf.as_str()), ("site", "site-1")]);
        let r = post_brut(
            &b,
            &b.alice,
            chemin,
            &c,
            "Sec-Fetch-Site: cross-site\r\n",
            &corps,
        );
        assert_eq!(r.statut, 403, "{chemin} autre origine");
    }
    let base = base_utilisateurs(&b).lire().unwrap();
    assert!(base.sites.is_empty() && base.cles_usb.is_empty());
    assert!(base.utilisateurs.iter().all(|u| u.pin.is_none()));
    // Libellé malveillant : échappé partout ; série invalide : refus échappé.
    let r = post(
        &b,
        &b.alice,
        "/cles-usb/enroler",
        &c,
        &[
            ("csrf", &csrf),
            ("fabricant", "0x0781"),
            ("serie", "4c530001"),
            ("libelle", "<script>alert(1)</script>"),
            ("site", ""),
            ("entree", "1"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    let r = get(&b, &b.alice, "/cles-usb", Some(&c));
    assert!(r.corps.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!r.corps.contains("<script") && !r.corps.contains("style="));
    assert!(r.corps.contains("4C530001"), "série normalisée");
    let r = post(
        &b,
        &b.alice,
        "/cles-usb/enroler",
        &c,
        &[
            ("csrf", &csrf),
            ("fabricant", "\"><img src=x onerror=1>"),
            ("serie", "A"),
            ("entree", "1"),
        ],
    );
    assert_eq!(r.statut, 400);
    assert!(!r.corps.contains("<img"));
    let r = get(
        &b,
        &b.alice,
        "/utilisateurs?identifiant=%22%3E%3Cimg%20src%3Dx%3E",
        Some(&c),
    );
    assert_eq!(r.statut, 200);
    assert!(!r.corps.contains("<img") && r.corps.contains("&quot;&gt;&lt;img"));
    // Retrait par la page.
    let id = base_utilisateurs(&b).lire().unwrap().cles_usb[0].id.clone();
    let r = post(
        &b,
        &b.alice,
        "/cles-usb/retirer",
        &c,
        &[("csrf", &csrf), ("id", &id)],
    );
    assert_eq!(r.statut, 200, "{}", r.corps);
    assert!(base_utilisateurs(&b).lire().unwrap().cles_usb.is_empty());
}
