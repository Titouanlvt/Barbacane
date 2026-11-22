//! Preuves des comptes de la Console et de la double validation (v2.2.0,
//! `docs/suite/comptes-administrateurs.md`) : vraie écoute TLS, PKI de TEST de
//! `serveur/pki/racine-test.sh` (CA « administrateurs » dont la CLÉ est donnée à la Console),
//! `.p12` relu par le vrai `openssl pkcs12`, fichier des comptes au format v2.1.0 migré.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_audit::{CleAudit, ClePublique, Enregistrement, Evenement, verifier};
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::fournisseur;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::registre::{Borne, StatutBorne};
use barbacane_web::comptes::{Comptes, Role, ligne_compte};
use barbacane_web::{Config, Web, servir};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const MDP_ADMIN: &str = "phrase de passe de TEST du premier compte";

struct Ident {
    chaine: Vec<CertificateDer<'static>>,
    cle: PrivateKeyDer<'static>,
}

struct Banc {
    dossier: tempfile::TempDir,
    pki: PathBuf,
    web: SocketAddr,
    passerelle: barbacane_passerelle::Config,
    cle_audit_pub: PathBuf,
    admin01: Ident,
}

fn racine() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executer(c: &mut Command) -> Vec<u8> {
    let s = c.output().unwrap();
    assert!(
        s.status.success(),
        "{c:?} : {}{}",
        String::from_utf8_lossy(&s.stdout),
        String::from_utf8_lossy(&s.stderr)
    );
    s.stdout
}

fn ident_pem(cert: &Path, cle: &Path) -> Ident {
    Ident {
        chaine: vec![CertificateDer::from_pem_file(cert).unwrap()],
        cle: PrivateKeyDer::from_pem_file(cle).unwrap(),
    }
}

/// Démarre une Console sur le dossier `d` (déjà préparé) ; renvoie son adresse.
fn demarrer(d: &Path, pki: &Path) -> SocketAddr {
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let web = ecoute.local_addr().unwrap();
    let texte = format!(
        "adresse = 127.0.0.1\nport = {}\nchaine_serveur = {p}/serveur/chaine.pem\ncle_serveur = {p}/serveur/cle.pem\nca_administrateurs = {p}/ca-administrateurs/cert.pem\ncrl_administrateurs = {p}/ca-administrateurs/crl.pem\ncle_ca_administrateurs = {p}/ca-administrateurs/cle.pem\ncomptes = {d}/comptes\npasserelle = {d}/passerelle.conf\ncle_audit_publique = {d}/audit.pub\n",
        web.port(),
        p = pki.display(),
        d = d.display(),
    );
    std::fs::write(d.join("web.conf"), &texte).unwrap();
    let w = Web::nouveau(Config::analyser(&texte).unwrap()).unwrap();
    std::thread::spawn(move || servir(ecoute, w));
    web
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
    let admin01 = ident_pem(
        &pki.join("administrateurs/admin-01.cert.pem"),
        &pki.join("administrateurs/admin-01.cle.pem"),
    );
    // Fichier des comptes au format v2.1.0 (produit par « barbacane-web compte »).
    let l = ligne_compte(
        "admin-01",
        Role::Administrateur,
        &admin01.chaine[0],
        MDP_ADMIN,
    )
    .unwrap();
    std::fs::write(d.join("comptes"), format!("{l}\n")).unwrap();
    std::fs::set_permissions(d.join("comptes"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let cle_audit_pub = d.join("audit.pub");
    std::fs::write(
        &cle_audit_pub,
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
    std::fs::set_permissions(
        pki.join("ca-administrateurs/cle.pem"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let web = demarrer(&d, &pki);
    Banc {
        dossier,
        pki,
        web,
        passerelle,
        cle_audit_pub,
        admin01,
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
    fn champ(&self, nom: &str) -> String {
        let t = self.texte();
        let m = format!("name=\"{nom}\" value=\"");
        let i = t.find(&m).unwrap_or_else(|| panic!("{nom} absent : {t}")) + m.len();
        t[i..].split('"').next().unwrap().to_owned()
    }
    /// Identifiant de la demande dont le libellé est `libelle`.
    fn demande(&self, libelle: &str) -> String {
        let t = self.texte();
        let i = t
            .find(libelle)
            .unwrap_or_else(|| panic!("« {libelle} » absent : {t}"));
        let m = "name=\"demande\" value=\"";
        let j = t[i..].find(m).unwrap() + i + m.len();
        t[j..].split('"').next().unwrap().to_owned()
    }
    /// Valeur du champ caché `nom` qui suit `avant`.
    fn champ_apres(&self, avant: &str, nom: &str) -> String {
        let t = self.texte();
        let i = t
            .find(avant)
            .unwrap_or_else(|| panic!("« {avant} » absent : {t}"));
        let m = format!("name=\"{nom}\" value=\"");
        let j = t[i..].find(&m).unwrap() + i + m.len();
        t[j..].split('"').next().unwrap().to_owned()
    }
    /// Texte en gras qui suit `avant` (secrets affichés une fois).
    fn gras_apres(&self, avant: &str) -> String {
        let t = self.texte();
        let i = t
            .find(avant)
            .unwrap_or_else(|| panic!("« {avant} » absent : {t}"));
        let j = t[i..].find("<b class=\"b-mono\">").unwrap() + i + 18;
        t[j..].split('<').next().unwrap().to_owned()
    }
}

fn envoyer(b: &Banc, id: &Ident, brut: &[u8]) -> Result<Rep, String> {
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
    tls.write_all(brut).map_err(|e| e.to_string())?;
    let mut o = Vec::new();
    tls.read_to_end(&mut o).map_err(|e| e.to_string())?;
    let fin = o
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("réponse sans en-têtes")?;
    let entetes = String::from_utf8_lossy(&o[..fin]).into_owned();
    let statut = entetes.split(' ').nth(1).unwrap().parse().unwrap();
    Ok(Rep {
        statut,
        entetes,
        corps: o[fin + 4..].to_vec(),
    })
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
    .unwrap()
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
    .unwrap()
}

/// Connexion : (réponse du POST, cookie).
fn tenter(b: &Banc, id: &Ident, ident: &str, mdp: &str) -> (Rep, Option<String>) {
    let page = get(b, id, "/connexion", None);
    let pre = page.cookie().unwrap();
    let r = post(
        b,
        id,
        "/connexion",
        &pre,
        &[
            ("csrf", &page.champ("csrf")),
            ("identifiant", ident),
            ("mot_de_passe", mdp),
        ],
    );
    let c = r.cookie();
    (r, c)
}

/// Session : (cookie, jeton CSRF), page d'arrivée `arrivee` (tableau ou mot de passe).
fn connecter(b: &Banc, id: &Ident, ident: &str, mdp: &str, arrivee: &str) -> (String, String) {
    let (r, c) = tenter(b, id, ident, mdp);
    assert_eq!(r.statut, 303, "{}", r.texte());
    let c = c.unwrap();
    let t = get(b, id, arrivee, Some(&c));
    assert_eq!(t.statut, 200, "{arrivee} : {}", t.texte());
    let csrf = t.champ("csrf");
    (c, csrf)
}

/// Relit un `.p12` avec `openssl pkcs12` (MAC et déchiffrement vérifiés) : identité TLS.
fn ouvrir_p12(d: &Path, nom: &str, octets: &[u8], mdp: &str) -> Ident {
    let f = d.join(format!("{nom}.p12"));
    std::fs::write(&f, octets).unwrap();
    let pass = format!("pass:{mdp}");
    let cert = executer(
        Command::new("openssl")
            .args(["pkcs12", "-in"])
            .arg(&f)
            .args(["-passin", &pass, "-clcerts", "-nokeys"]),
    );
    let cle = executer(
        Command::new("openssl")
            .args(["pkcs12", "-in"])
            .arg(&f)
            .args(["-passin", &pass, "-nocerts", "-nodes"]),
    );
    let info = executer(
        Command::new("openssl")
            .args(["pkcs12", "-in"])
            .arg(&f)
            .args(["-passin", &pass, "-info", "-noout"]),
    );
    let _ = info;
    // Mauvais mot de passe : refusé par openssl (MAC).
    let s = Command::new("openssl")
        .args(["pkcs12", "-in"])
        .arg(&f)
        .args(["-passin", "pass:mauvais-mot-de-passe", "-nokeys"])
        .output()
        .unwrap();
    assert!(!s.status.success(), "mauvais mot de passe accepté");
    Ident {
        chaine: vec![CertificateDer::from_pem_slice(&cert).unwrap()],
        cle: PrivateKeyDer::from_pem_slice(&cle).unwrap(),
    }
}

/// Secrets d'une remise : (mot de passe provisoire, identité TLS du .p12). `demandeur` : le
/// mot de passe provisoire lui est remis (séparation des remises), pas au validateur `par`.
fn remise(
    b: &Banc,
    par: &Ident,
    c: &str,
    csrf: &str,
    r: &Rep,
    nom: &str,
    demandeur: Option<(&Ident, &str, &str)>,
) -> (String, Ident) {
    let provisoire = match demandeur {
        None => r.gras_apres("Mot de passe provisoire"),
        Some((id, cd, sd)) => {
            assert!(
                !r.texte().contains("Mot de passe provisoire ("),
                "le validateur ne voit pas le mot de passe provisoire"
            );
            let l = get(b, id, "/comptes", Some(cd));
            let jeton = l.champ_apres("action=\"/comptes/remise\"", "jeton");
            let p = post(
                b,
                id,
                "/comptes/remise",
                cd,
                &[("csrf", sd), ("jeton", &jeton)],
            );
            assert_eq!(p.statut, 200, "{}", p.texte());
            let deux = post(
                b,
                id,
                "/comptes/remise",
                cd,
                &[("csrf", sd), ("jeton", &jeton)],
            );
            assert_eq!(deux.statut, 404, "remise unique");
            let autre = post(
                b,
                par,
                "/comptes/remise",
                c,
                &[("csrf", csrf), ("jeton", &jeton)],
            );
            assert_eq!(autre.statut, 404);
            p.gras_apres("Mot de passe provisoire")
        }
    };
    let mdp_p12 = r.gras_apres("Mot de passe du fichier .p12");
    let jeton = r.champ("jeton");
    let p = post(
        b,
        par,
        "/comptes/p12",
        c,
        &[("csrf", csrf), ("jeton", &jeton)],
    );
    assert_eq!(p.statut, 200, "{}", p.texte());
    assert!(p.entetes.contains("application/x-pkcs12"));
    assert!(p.entetes.contains(&format!("barbacane-{nom}.p12")));
    let deux = post(
        b,
        par,
        "/comptes/p12",
        c,
        &[("csrf", csrf), ("jeton", &jeton)],
    );
    assert_eq!(deux.statut, 404, "téléchargement unique");
    let id = ouvrir_p12(b.dossier.path(), nom, &p.corps, &mdp_p12);
    (provisoire, id)
}

fn journal(b: &Banc) -> (Vec<u8>, Vec<String>) {
    let contenu = Admin::ouvrir(b.passerelle.clone())
        .unwrap()
        .stockage
        .journal_audit()
        .lire()
        .unwrap();
    verifier(&contenu, &ClePublique::lire(&b.cle_audit_pub).unwrap(), &[])
        .expect("journal d'audit intègre");
    let actions = contenu
        .split(|o| *o == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| match Enregistrement::analyser(l).ok()?.evenement {
            Evenement::Administration { action } => Some(action),
            _ => None,
        })
        .collect();
    (contenu, actions)
}

fn premier_mdp(b: &Banc, id: &Ident, ident: &str, provisoire: &str) -> (String, String) {
    let (c, csrf) = connecter(b, id, ident, provisoire, "/mot-de-passe");
    // Tout le reste est refusé tant que le mot de passe provisoire n'est pas changé.
    let t = get(b, id, "/tableau", Some(&c));
    assert_eq!(t.statut, 303);
    assert!(t.entetes.contains("Location: /mot-de-passe"));
    let r = post(
        b,
        id,
        "/enrolement/jeton",
        &c,
        &[("csrf", &csrf), ("site", "site-1")],
    );
    assert_eq!(r.statut, 403);
    let nouveau = "Nouvelle phrase de passe 2026, choisie";
    let faible = post(
        b,
        id,
        "/mot-de-passe",
        &c,
        &[
            ("csrf", &csrf),
            ("actuel", provisoire),
            ("nouveau", "abcdefgh"),
            ("confirmation", "abcdefgh"),
        ],
    );
    assert_eq!(faible.statut, 400);
    assert!(faible.texte().contains("trop court"));
    let r = post(
        b,
        id,
        "/mot-de-passe",
        &c,
        &[
            ("csrf", &csrf),
            ("actuel", provisoire),
            ("nouveau", nouveau),
            ("confirmation", nouveau),
        ],
    );
    assert_eq!(r.statut, 303, "{}", r.texte());
    let t = get(b, id, "/tableau", Some(&c));
    assert_eq!(t.statut, 200);
    (c, t.champ("csrf"))
}

#[test]
fn comptes_double_validation_roles_et_certificats() {
    let b = banc();
    let d = b.dossier.path();
    // Migration v2.1.0 : base créée, compte repris (même mot de passe, même certificat).
    let base = Comptes::ouvrir(&d.join("etat")).unwrap();
    assert!(base.existe());
    let (c1, s1) = connecter(&b, &b.admin01, "admin-01", MDP_ADMIN, "/tableau");
    let (_, a) = journal(&b);
    assert!(a.contains(&"migration-comptes-2.1.0:1".to_owned()), "{a:?}");
    let l = get(&b, &b.admin01, "/comptes", Some(&c1));
    assert_eq!(l.statut, 200);
    assert!(l.texte().contains("migration-2.1.0"));
    // CSRF absent ou faux : refusé.
    for jeton in ["", "0000"] {
        let r = post(
            &b,
            &b.admin01,
            "/comptes/creer",
            &c1,
            &[("csrf", jeton), ("identifiant", "x"), ("role", "lecture")],
        );
        assert_eq!(r.statut, 403);
    }
    // Dernier administrateur : ni désactivation, ni rétrogradation, ni révocation.
    for (route, champs) in [
        ("/comptes/desactiver", vec![]),
        ("/comptes/role", vec![("role", "lecture")]),
        ("/comptes/revoquer", vec![]),
        ("/comptes/supprimer", vec![]),
    ] {
        let mut f = vec![("csrf", s1.as_str()), ("identifiant", "admin-01")];
        f.extend(champs);
        let r = post(&b, &b.admin01, route, &c1, &f);
        assert_eq!(r.statut, 400, "{route}");
        assert!(
            r.texte().contains("dernier administrateur"),
            "{route} : {}",
            r.texte()
        );
    }
    // Seul administrateur : un opérateur ne peut pas être créé sans second administrateur…
    let r = post(
        &b,
        &b.admin01,
        "/comptes/creer",
        &c1,
        &[("csrf", &s1), ("identifiant", "ope"), ("role", "operateur")],
    );
    assert_eq!(r.statut, 200);
    let id_ope = r.demande("Créer le compte ope");
    let r = post(
        &b,
        &b.admin01,
        "/validations/valider",
        &c1,
        &[("csrf", &s1), ("demande", &id_ope)],
    );
    assert_eq!(r.statut, 400, "auto-validation");
    assert!(r.texte().contains("second administrateur"));
    // … mais il crée seul le SECOND administrateur (amorçage, journalisé).
    let r = post(
        &b,
        &b.admin01,
        "/comptes/creer",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "admin-02"),
            ("role", "administrateur"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(r.texte().contains("sans second administrateur"));
    let (prov2, id2) = remise(&b, &b.admin01, &c1, &s1, &r, "admin-02", None);
    let (c2, s2) = premier_mdp(&b, &id2, "admin-02", &prov2);
    // Deux administrateurs : plus d'amorçage.
    let r = post(
        &b,
        &b.admin01,
        "/comptes/creer",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "admin-03"),
            ("role", "administrateur"),
        ],
    );
    assert!(
        r.texte().contains("SECOND administrateur doit la valider"),
        "{}",
        r.texte()
    );
    let r = post(
        &b,
        &b.admin01,
        "/validations/annuler",
        &c1,
        &[
            ("csrf", &s1),
            ("demande", &r.demande("Créer le compte admin-03")),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    // admin-02 valide la création de l'opérateur (demandée par admin-01).
    let r = post(
        &b,
        &id2,
        "/validations/valider",
        &c2,
        &[("csrf", &s2), ("demande", &id_ope)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let (prov_ope, id_ope_tls) =
        remise(&b, &id2, &c2, &s2, &r, "ope", Some((&b.admin01, &c1, &s1)));
    let (co, so) = premier_mdp(&b, &id_ope_tls, "ope", &prov_ope);
    // Opérateur : exploitation oui, comptes / quarantaine / journal non.
    assert_eq!(get(&b, &id_ope_tls, "/comptes", Some(&co)).statut, 403);
    assert_eq!(get(&b, &id_ope_tls, "/quarantaine", Some(&co)).statut, 403);
    assert_eq!(get(&b, &id_ope_tls, "/audit", Some(&co)).statut, 403);
    assert_eq!(get(&b, &id_ope_tls, "/utilisateurs", Some(&co)).statut, 200);
    let r = post(
        &b,
        &id_ope_tls,
        "/comptes/creer",
        &co,
        &[
            ("csrf", &so),
            ("identifiant", "pirate"),
            ("role", "administrateur"),
        ],
    );
    assert_eq!(r.statut, 403, "opérateur : pas de gestion des comptes");
    let r = post(
        &b,
        &id_ope_tls,
        "/enrolement/jeton",
        &co,
        &[("csrf", &so), ("site", "site-1")],
    );
    assert_eq!(r.statut, 200, "opérateur : enrôlement permis");
    // Compte en lecture seule : créé par admin-02, validé par admin-01.
    let r = post(
        &b,
        &id2,
        "/comptes/creer",
        &c2,
        &[("csrf", &s2), ("identifiant", "lect"), ("role", "lecture")],
    );
    let dem = r.demande("Créer le compte lect");
    let r = post(
        &b,
        &b.admin01,
        "/validations/valider",
        &c1,
        &[("csrf", &s1), ("demande", &dem)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let (prov_l, id_l) = remise(&b, &b.admin01, &c1, &s1, &r, "lect", Some((&id2, &c2, &s2)));
    let (cl, sl) = premier_mdp(&b, &id_l, "lect", &prov_l);
    for page in [
        "/utilisateurs",
        "/passages",
        "/audit",
        "/comptes",
        "/quarantaine",
        "/iso-bornes",
    ] {
        assert_eq!(
            get(&b, &id_l, page, Some(&cl)).statut,
            403,
            "lecture : {page}"
        );
    }
    for page in ["/tableau", "/enrolement", "/sites", "/maj"] {
        let r = get(&b, &id_l, page, Some(&cl));
        assert_eq!(r.statut, 200, "lecture : {page}");
        assert!(!r.texte().contains("href=\"/comptes\""), "lien masqué");
    }
    for (route, champs) in [
        ("/sites/mode", vec![("site", "site-1"), ("mode", "aucun")]),
        ("/enrolement/jeton", vec![("site", "site-1")]),
        ("/validations/valider", vec![("demande", "x")]),
    ] {
        let mut f = vec![("csrf", sl.as_str())];
        f.extend(champs);
        assert_eq!(
            post(&b, &id_l, route, &cl, &f).statut,
            403,
            "lecture : {route}"
        );
    }
    // Élévation de « lect » : double validation ; rétrogradation : immédiate.
    let r = post(
        &b,
        &b.admin01,
        "/comptes/role",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "lect"),
            ("role", "administrateur"),
        ],
    );
    let dem = r.demande("Passer lect administrateur");
    let r = post(
        &b,
        &b.admin01,
        "/validations/valider",
        &c1,
        &[("csrf", &s1), ("demande", &dem)],
    );
    assert_eq!(r.statut, 400, "auto-validation de l'élévation");
    let r = post(
        &b,
        &b.admin01,
        "/validations/annuler",
        &c1,
        &[("csrf", &s1), ("demande", &dem)],
    );
    assert_eq!(r.statut, 200);
    // Séparation des remises : admin-02 a reçu le .p12 de « ope » → il ne peut pas réinitialiser
    // son mot de passe ; admin-01 le peut, mais ne peut alors plus recevoir son certificat.
    let r = post(
        &b,
        &id2,
        "/comptes/reinitialiser",
        &c2,
        &[("csrf", &s2), ("identifiant", "ope")],
    );
    assert_eq!(r.statut, 400);
    assert!(
        r.texte().contains("séparation des remises"),
        "{}",
        r.texte()
    );
    let r = post(
        &b,
        &b.admin01,
        "/comptes/reinitialiser",
        &c1,
        &[("csrf", &s1), ("identifiant", "ope")],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(!r.gras_apres("Mot de passe provisoire").is_empty());
    let r = post(
        &b,
        &id2,
        "/comptes/emettre",
        &c2,
        &[("csrf", &s2), ("identifiant", "ope")],
    );
    let dem = r.demande("Émettre un nouveau certificat pour ope");
    let r = post(
        &b,
        &b.admin01,
        "/validations/valider",
        &c1,
        &[("csrf", &s1), ("demande", &dem)],
    );
    assert_eq!(r.statut, 400);
    assert!(
        r.texte().contains("séparation des remises"),
        "{}",
        r.texte()
    );
    assert_eq!(
        get(&b, &id_ope_tls, "/tableau", Some(&co)).statut,
        303,
        "mot de passe réinitialisé : changement imposé"
    );
    // Révocation du certificat de l'opérateur : validée par admin-02, CRL republiée,
    // connexion TLS refusée ensuite.
    let r = post(
        &b,
        &b.admin01,
        "/comptes/revoquer",
        &c1,
        &[("csrf", &s1), ("identifiant", "ope")],
    );
    let dem = r.demande("Révoquer le certificat de ope");
    let r = post(
        &b,
        &id2,
        "/validations/valider",
        &c2,
        &[("csrf", &s2), ("demande", &dem)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(r.texte().contains("CRL republiée"));
    assert!(
        envoyer(&b, &id_ope_tls, b"GET /connexion HTTP/1.1\r\n\r\n").is_err(),
        "certificat révoqué : refus à la poignée de main"
    );
    // Révocation massive d'un site : deux bornes actives, double validation.
    let adm = Admin::ouvrir(b.passerelle.clone()).unwrap();
    let t = maintenant();
    adm.stockage
        .transaction(|r| {
            for (i, uuid) in [
                "11111111-2222-4333-8444-555555555551",
                "11111111-2222-4333-8444-555555555552",
            ]
            .iter()
            .enumerate()
            {
                r.bornes.push(Borne {
                    uuid: (*uuid).into(),
                    nom: format!("borne-{i}"),
                    site: "site-r".into(),
                    statut: StatutBorne::Active,
                    certificat_pem: String::new(),
                    serie: format!("4{i}"),
                    serie_precedente: None,
                    emis_le: t,
                    expire_le: t + 90 * 86400,
                    derniere_vue: Some(t),
                    ecart_horloge_s: Some(0),
                    dernier_battement: None,
                });
            }
            Ok(())
        })
        .unwrap();
    let r = post(
        &b,
        &id2,
        "/bornes/revoquer-site",
        &c2,
        &[
            ("csrf", &s2),
            ("site", "site-r"),
            ("motif", "volee"),
            ("confirmation", "site-x"),
        ],
    );
    assert_eq!(r.statut, 400, "nom du site mal retapé");
    let r = post(
        &b,
        &id2,
        "/bornes/revoquer-site",
        &c2,
        &[
            ("csrf", &s2),
            ("site", "site-r"),
            ("motif", "volee"),
            ("confirmation", "site-r"),
        ],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    let dem = r.demande("Révoquer toutes les bornes du site site-r");
    assert!(
        adm.stockage
            .lire()
            .unwrap()
            .bornes
            .iter()
            .all(|b| b.statut == StatutBorne::Active)
    );
    let r = post(
        &b,
        &b.admin01,
        "/validations/valider",
        &c1,
        &[("csrf", &s1), ("demande", &dem)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(r.texte().contains("2 borne(s)"));
    assert!(
        adm.stockage
            .lire()
            .unwrap()
            .bornes
            .iter()
            .all(|b| b.statut != StatutBorne::Active)
    );
    // Suppression de admin-02 demandée par admin-01, validée par admin-02 lui-même (il reste
    // admin-01) ; ensuite admin-01 est de nouveau le dernier administrateur.
    let r = post(
        &b,
        &b.admin01,
        "/comptes/supprimer",
        &c1,
        &[("csrf", &s1), ("identifiant", "admin-02")],
    );
    let dem = r.demande("Supprimer le compte admin-02");
    let r = post(
        &b,
        &id2,
        "/validations/valider",
        &c2,
        &[("csrf", &s2), ("demande", &dem)],
    );
    assert_eq!(r.statut, 200, "{}", r.texte());
    assert!(
        envoyer(&b, &id2, b"GET /tableau HTTP/1.1\r\n\r\n").is_err(),
        "compte supprimé : son certificat est révoqué"
    );
    let r = post(
        &b,
        &b.admin01,
        "/comptes/desactiver",
        &c1,
        &[("csrf", &s1), ("identifiant", "admin-01")],
    );
    assert!(r.texte().contains("dernier administrateur"));
    // Amorçage unique : seul de nouveau, admin-01 ne peut PAS créer seul un administrateur
    // (sinon : rétrograder l'autre puis créer un complice) ; « reamorcer » (console locale) le rouvre.
    let r = post(
        &b,
        &b.admin01,
        "/comptes/creer",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "admin-04"),
            ("role", "administrateur"),
        ],
    );
    assert!(
        r.texte().contains("SECOND administrateur doit la valider"),
        "{}",
        r.texte()
    );
    let r = post(
        &b,
        &b.admin01,
        "/validations/annuler",
        &c1,
        &[
            ("csrf", &s1),
            ("demande", &r.demande("Créer le compte admin-04")),
        ],
    );
    assert_eq!(r.statut, 200);
    barbacane_web::reamorcer(&Config::lire(&d.join("web.conf")).unwrap()).unwrap();
    let r = post(
        &b,
        &b.admin01,
        "/comptes/creer",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "admin-04"),
            ("role", "administrateur"),
        ],
    );
    assert!(
        r.texte().contains("sans second administrateur"),
        "{}",
        r.texte()
    );
    // Journal : demandes, validations, refus ; aucun secret.
    let (brut, a) = journal(&b);
    let brut = String::from_utf8_lossy(&brut);
    for x in [
        "creation-sans-double-validation:admin-02:seul-administrateur",
        "validation-refusee:auto-validation",
        "compte-cree:ope:operateur",
        "p12-telecharge:ope",
        "mot-de-passe-change",
        "compte-supprime:admin-02",
        "annulation:elevation-compte",
        "refus:comptes-reinitialiser:ope",
        "mot-de-passe-remis:ope",
        "reamorcage-local",
    ] {
        assert!(a.iter().any(|y| y.starts_with(x)), "{x} : {a:?}");
    }
    assert!(
        a.iter()
            .any(|y| y.starts_with("demande:creation-compte:ope:"))
    );
    assert!(
        a.iter()
            .any(|y| y.starts_with("validation:creation-compte:ope:"))
    );
    assert!(
        a.iter()
            .any(|y| y.starts_with("validation:revocation-site:site-r:"))
    );
    for secret in [
        prov2.as_str(),
        prov_ope.as_str(),
        prov_l.as_str(),
        MDP_ADMIN,
    ] {
        assert!(!brut.contains(secret), "secret dans le journal");
    }
    let base =
        std::fs::read_to_string(Comptes::ouvrir(&d.join("etat")).unwrap().fichier()).unwrap();
    assert!(!base.contains(&prov_l), "seul le hachage est conservé");
}

#[test]
fn migration_conservee_au_redemarrage_et_certificats_de_la_ceremonie() {
    let b = banc();
    let d = b.dossier.path();
    let (c1, s1) = connecter(&b, &b.admin01, "admin-01", MDP_ADMIN, "/tableau");
    // Le certificat révoqué par la cérémonie (CRL de racine-test.sh) reste refusé : la CRL
    // publiée par la Console reprend ses révocations.
    let revoque = ident_pem(
        &b.pki.join("administrateurs/admin-revoque.cert.pem"),
        &b.pki.join("administrateurs/admin-revoque.cle.pem"),
    );
    assert!(envoyer(&b, &revoque, b"GET /connexion HTTP/1.1\r\n\r\n").is_err());
    let r = post(
        &b,
        &b.admin01,
        "/comptes/role",
        &c1,
        &[
            ("csrf", &s1),
            ("identifiant", "admin-01"),
            ("role", "lecture"),
        ],
    );
    assert_eq!(r.statut, 400);
    // Le fichier v2.1.0 n'est plus lu : le modifier ne change rien ; un second démarrage garde
    // la base (pas de nouvelle importation).
    std::fs::write(d.join("comptes"), "").unwrap();
    let web2 = demarrer(d, &b.pki);
    let b2 = Banc {
        dossier: tempfile::tempdir().unwrap(),
        pki: b.pki.clone(),
        web: web2,
        passerelle: b.passerelle.clone(),
        cle_audit_pub: b.cle_audit_pub.clone(),
        admin01: ident_pem(
            &b.pki.join("administrateurs/admin-01.cert.pem"),
            &b.pki.join("administrateurs/admin-01.cle.pem"),
        ),
    };
    connecter(&b2, &b2.admin01, "admin-01", MDP_ADMIN, "/tableau");
    let (_, a) = journal(&b);
    assert_eq!(
        a.iter()
            .filter(|x| x.starts_with("migration-comptes"))
            .count(),
        1
    );
    // Clé de la CA des administrateurs lisible par d'autres comptes : démarrage refusé.
    let cle = b.pki.join("ca-administrateurs/cle.pem");
    std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Web::nouveau(Config::lire(&d.join("web.conf")).unwrap()).is_err());
    std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o400)).unwrap();
    let k = Comptes::ouvrir(&d.join("etat")).unwrap().lire().unwrap();
    let k = k.compte("admin-01").unwrap();
    assert!(k.dernier_acces.is_some());
    assert!(
        k.serie_certificat.is_some(),
        "numéro de série relevé à la connexion"
    );
}
