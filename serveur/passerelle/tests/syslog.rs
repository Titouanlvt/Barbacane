//! Export Syslog (v2.3.0) contre de vrais collecteurs locaux : TLS 1.3 avec vérification du
//! collecteur et mTLS, TCP et UDP en clair, collecteur coupé puis rétabli (reprise sans perte,
//! doublons marqués), remise non confirmée, débordement de la file, perte après purge.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use barbacane_audit::{CleAudit, Evenement};
use barbacane_passerelle::registre::Stockage;
use barbacane_passerelle::syslog::{
    self, ConfigSyslog, Exportateur, FILE_MAX, Mode, Passe, appliquer, deposer_pem,
    generer_cle_client, lire_etat,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

type Recus = Arc<Mutex<Vec<String>>>;

struct Ac {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
}

fn ac() -> Ac {
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(DnType::CommonName, "AC collecteur de TEST");
    let c = p.self_signed(&cle).unwrap();
    Ac {
        pem: c.pem(),
        der: c.der().clone(),
        issuer: Issuer::new(p, cle),
    }
}

fn config_serveur(ac: &Ac, nom: &str, mtls: bool) -> Arc<rustls::ServerConfig> {
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let c = CertificateParams::new(vec![nom.to_owned()])
        .unwrap()
        .signed_by(&cle, &ac.issuer)
        .unwrap();
    let b = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap();
    let b = if mtls {
        let mut r = rustls::RootCertStore::empty();
        r.add(ac.der.clone()).unwrap();
        b.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(r),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap(),
        )
    } else {
        b.with_no_client_auth()
    };
    Arc::new(
        b.with_single_cert(
            vec![c.der().clone()],
            PrivateKeyDer::from_pem_slice(cle.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap(),
    )
}

/// Découpe les trames « LONGUEUR ESPACE MESSAGE ».
fn trames(mut o: &[u8], recus: &Recus) {
    while !o.is_empty() {
        let Some(e) = o.iter().position(|c| *c == b' ') else {
            return;
        };
        let n: usize = std::str::from_utf8(&o[..e]).unwrap().parse().unwrap();
        let m = &o[e + 1..e + 1 + n];
        recus
            .lock()
            .unwrap()
            .push(String::from_utf8(m.to_vec()).unwrap());
        o = &o[e + 1 + n..];
    }
}

/// Collecteur TCP (TLS si `tls`) : lit chaque connexion jusqu'à la fin ; ferme ensuite (comme
/// rsyslog et syslog-ng) sauf si `ne_ferme_pas`.
struct Collecteur {
    port: u16,
    arret: Arc<AtomicBool>,
    fil: Option<std::thread::JoinHandle<()>>,
}

impl Collecteur {
    fn lancer(
        port: u16,
        tls: Option<Arc<rustls::ServerConfig>>,
        ne_ferme_pas: bool,
        recus: Recus,
    ) -> Collecteur {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        let port = l.local_addr().unwrap().port();
        let arret = Arc::new(AtomicBool::new(false));
        let (a, r) = (arret.clone(), recus.clone());
        let fil = std::thread::spawn(move || {
            for c in l.incoming() {
                if a.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut c) = c else { continue };
                c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                let mut o = Vec::new();
                match &tls {
                    None => {
                        let _ = c.read_to_end(&mut o);
                    }
                    Some(t) => {
                        let conn = rustls::ServerConnection::new(t.clone()).unwrap();
                        let mut s = rustls::StreamOwned::new(conn, c.try_clone().unwrap());
                        let _ = s.read_to_end(&mut o);
                    }
                }
                trames(&o, &r);
                if ne_ferme_pas {
                    std::thread::sleep(Duration::from_secs(12));
                }
            }
        });
        Collecteur {
            port,
            arret,
            fil: Some(fil),
        }
    }

    fn arreter(mut self) {
        self.arret.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
        self.fil.take().unwrap().join().unwrap();
    }
}

struct Banc {
    _d: tempfile::TempDir,
    s: Stockage,
    e: Exportateur,
}

fn banc() -> Banc {
    let d = tempfile::tempdir().unwrap();
    let s = Stockage::ouvrir(&d.path().join("etat")).unwrap();
    for i in 0..5 {
        evenement(&s, i);
    }
    Banc {
        e: Exportateur {
            stockage: s.clone(),
            serveur: "srv-test".into(),
            file_max: FILE_MAX,
        },
        s,
        _d: d,
    }
}

fn evenement(s: &Stockage, i: u64) {
    s.auditer(
        "passerelle",
        Evenement::Administration {
            action: format!("essai-{i}"),
        },
    )
    .unwrap();
}

/// (n, reprise) de chaque message reçu, après contrôle de la forme RFC 5424 et du JSON.
fn analyser(recus: &Recus) -> Vec<(u64, bool)> {
    recus
        .lock()
        .unwrap()
        .iter()
        .map(|m| {
            assert!(m.starts_with('<') && m.contains(">1 "), "{m}");
            assert!(m.contains(" srv-test barbacane - "), "{m}");
            let n: u64 = m
                .split(" n=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let reprise = m.split(" reprise=\"").nth(1).unwrap().starts_with('1');
            let json = m.split('\u{feff}').nth(1).unwrap();
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(v["n"], n);
            assert_eq!(v["schema"], "barbacane.journal/1");
            assert!(v["horodatage"].as_str().unwrap().ends_with('Z'));
            (n, reprise)
        })
        .collect()
}

fn passes(e: &Exportateur) -> Passe {
    for _ in 0..50 {
        match e.passe(1_800_000_000).unwrap() {
            Passe::Remis(_) => continue,
            p => return p,
        }
    }
    panic!("toujours des lots à remettre");
}

fn dernier(s: &Stockage) -> u64 {
    s.journal_audit()
        .lire_depuis(0, usize::MAX)
        .unwrap()
        .dernier
}

#[test]
fn tls_avec_mtls_puis_coupure_et_reprise_sans_perte() {
    let b = banc();
    let ac = ac();
    let h_ac = deposer_pem(&b.s, "ac", ac.pem.as_bytes()).unwrap();
    // Clé client tirée par le serveur, demande signée par l'AC du collecteur.
    let csr = generer_cle_client(&b.s, "srv-test").unwrap();
    let cert = CertificateSigningRequestParams::from_pem(&csr)
        .unwrap()
        .signed_by(&ac.issuer)
        .unwrap();
    let h_cli = deposer_pem(&b.s, "client", cert.pem().as_bytes()).unwrap();
    let recus: Recus = Default::default();
    let tls = config_serveur(&ac, "collecteur.barbacane.invalid", true);
    let col = Collecteur::lancer(0, Some(tls.clone()), false, recus.clone());
    let port = col.port;
    let mut c = ConfigSyslog {
        mode: Mode::Tls,
        adresse: Ipv4Addr::LOCALHOST,
        port,
        nom: Some("collecteur.barbacane.invalid".into()),
        ac: Some(h_ac.clone()),
        certificat_client: Some(h_cli),
    };
    // Adresse de bouclage refusée par la Console (réseau local seulement) ; le banc la règle
    // directement pour le test.
    assert!(appliquer(&b.s, Some(c.clone()), 1, "web:a", "web:a+b").is_err());
    ecrire_actif(&b.s, &c);
    assert_eq!(passes(&b.e), Passe::AJour);
    let v = analyser(&recus);
    let attendu: Vec<u64> = (1..=dernier(&b.s)).collect();
    assert!(
        v.iter()
            .map(|x| x.0)
            .collect::<Vec<_>>()
            .starts_with(&attendu[..5])
    );
    assert!(v.iter().all(|x| !x.1), "aucune reprise : {v:?}");
    let e = lire_etat(&b.s).unwrap().unwrap();
    assert_eq!((e.etat.as_str(), e.en_attente), ("ok", 0));
    // Collecteur coupé : événements en attente, état injoignable (audité une fois).
    col.arreter();
    for i in 10..20 {
        evenement(&b.s, i);
    }
    assert!(matches!(b.e.passe(2).unwrap(), Passe::Echec(_)));
    assert!(matches!(b.e.passe(3).unwrap(), Passe::Echec(_)));
    let e = lire_etat(&b.s).unwrap().unwrap();
    assert_eq!(e.etat, "injoignable");
    assert!(e.en_attente >= 10, "{e:?}");
    let audit = String::from_utf8(b.s.journal_audit().lire().unwrap()).unwrap();
    assert_eq!(audit.matches("\"action\":\"injoignable\"").count(), 1);
    // Rétabli : tout arrive, sans trou ; « reprise » auditée.
    let col = Collecteur::lancer(port, Some(tls), false, recus.clone());
    assert_eq!(passes(&b.e), Passe::AJour);
    let v = analyser(&recus);
    let mut vus: BTreeMap<u64, usize> = BTreeMap::new();
    for (n, _) in &v {
        *vus.entry(*n).or_default() += 1;
    }
    let d = dernier(&b.s);
    assert!(
        (1..=d - 1).all(|n| vus.contains_key(&n)),
        "trou dans les numéros reçus : {vus:?} (dernier {d})"
    );
    assert!(
        vus.values().all(|c| *c == 1),
        "aucun doublon ici (aucune écriture sur la connexion coupée)"
    );
    let audit = String::from_utf8(b.s.journal_audit().lire().unwrap()).unwrap();
    assert!(audit.contains("\"action\":\"reprise\""), "{audit}");
    // Mauvais nom attendu : certificat du collecteur refusé.
    c.nom = Some("autre.barbacane.invalid".into());
    ecrire_actif(&b.s, &c);
    evenement(&b.s, 30);
    match b.e.passe(4).unwrap() {
        Passe::Echec(m) => assert!(m.contains("TLS"), "{m}"),
        p => panic!("{p:?}"),
    }
    col.arreter();
}

fn ecrire_actif(s: &Stockage, c: &ConfigSyslog) {
    syslog::controler(s, c).unwrap();
    let d = syslog::dossier(s).unwrap();
    std::fs::write(
        d.join("actif.json"),
        serde_json::to_vec(&syslog::Actif {
            version: 1,
            config: Some(c.clone()),
            regle_le: 1,
            par: "test".into(),
        })
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn tcp_clair_remise_non_confirmee_puis_doublons_marques() {
    let b = banc();
    let recus: Recus = Default::default();
    // Collecteur qui ne ferme pas : remise jamais confirmée.
    let col = Collecteur::lancer(0, None, true, recus.clone());
    let port = col.port;
    let c = ConfigSyslog {
        mode: Mode::TcpClair,
        adresse: Ipv4Addr::LOCALHOST,
        port,
        nom: None,
        ac: None,
        certificat_client: None,
    };
    ecrire_actif(&b.s, &c);
    match b.e.passe(1).unwrap() {
        Passe::Echec(m) => assert!(m.contains("non confirmée"), "{m}"),
        p => panic!("{p:?}"),
    }
    col.arreter();
    let premiers = analyser(&recus);
    assert!(!premiers.is_empty() && premiers.iter().all(|x| !x.1));
    // Collecteur normal : le lot est renvoyé, marqué reprise="1" (doublon visible, même id).
    recus.lock().unwrap().clear();
    let col = Collecteur::lancer(port, None, false, recus.clone());
    assert_eq!(passes(&b.e), Passe::AJour);
    let v = analyser(&recus);
    for (n, r) in &v {
        assert_eq!(
            *r,
            premiers.iter().any(|p| p.0 == *n),
            "n° {n} : reprise={r}"
        );
    }
    col.arreter();
}

#[test]
fn udp_clair() {
    let b = banc();
    let u = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let c = ConfigSyslog {
        mode: Mode::UdpClair,
        adresse: Ipv4Addr::LOCALHOST,
        port: u.local_addr().unwrap().port(),
        nom: None,
        ac: None,
        certificat_client: None,
    };
    ecrire_actif(&b.s, &c);
    assert_eq!(passes(&b.e), Passe::AJour);
    let mut tampon = [0u8; 9000];
    let mut n = 0;
    while let Ok(l) = u.recv(&mut tampon) {
        let m = String::from_utf8_lossy(&tampon[..l]);
        assert!(m.starts_with('<'), "{m}");
        n += 1;
        if n == 5 {
            break;
        }
    }
    assert_eq!(n, 5);
}

#[test]
fn debordement_et_perte_signales() {
    let mut b = banc();
    b.e.file_max = 3;
    let c = ConfigSyslog {
        mode: Mode::TcpClair,
        adresse: Ipv4Addr::LOCALHOST,
        port: 9, // rien n'écoute
        nom: None,
        ac: None,
        certificat_client: None,
    };
    ecrire_actif(&b.s, &c);
    assert!(matches!(b.e.passe(1).unwrap(), Passe::Echec(_)));
    let e = lire_etat(&b.s).unwrap().unwrap();
    assert!(e.debordement, "{e:?}");
    assert!(matches!(b.e.passe(2).unwrap(), Passe::Echec(_)));
    let audit = String::from_utf8(b.s.journal_audit().lire().unwrap()).unwrap();
    assert_eq!(
        audit.matches("\"action\":\"debordement\"").count(),
        1,
        "une fois par épisode"
    );
    // Purge (conservation) d'un segment jamais remis : perte signalée, puis reprise après.
    let cle = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    let j = b.s.journal_audit();
    j.tourner(&cle, 4_000_000_000, true).unwrap().unwrap();
    let p = j
        .purger_segments(&cle.publique(), 4_000_000_000, u64::MAX, "conservation")
        .unwrap();
    assert_eq!(p.len(), 1);
    let recus: Recus = Default::default();
    let col = Collecteur::lancer(0, None, false, recus.clone());
    let mut c = c;
    c.port = col.port;
    ecrire_actif(&b.s, &c);
    assert_eq!(passes(&b.e), Passe::AJour);
    let e = lire_etat(&b.s).unwrap().unwrap();
    assert!(
        e.pertes == 0 && !e.debordement,
        "nouvelle cible : pas de perte ({e:?})"
    );
    let v = analyser(&recus);
    assert_eq!(
        v[0].0,
        p[0].dernier + 1,
        "nouvelle cible : depuis l'ancre du segment restant"
    );
    col.arreter();
    // Même cible, coupée pendant qu'une purge emporte des événements jamais remis : perte.
    for i in 50..55 {
        evenement(&b.s, i);
    }
    assert!(matches!(b.e.passe(5).unwrap(), Passe::Echec(_)));
    j.tourner(&cle, 4_100_000_000, true).unwrap().unwrap();
    let p = j
        .purger_segments(&cle.publique(), 4_100_000_000, u64::MAX, "conservation")
        .unwrap();
    assert_eq!(p.len(), 1);
    assert!(matches!(b.e.passe(6).unwrap(), Passe::Echec(_)));
    let e = lire_etat(&b.s).unwrap().unwrap();
    assert!(e.pertes >= 5, "{e:?}");
    let audit = String::from_utf8(b.s.journal_audit().lire().unwrap()).unwrap();
    assert!(audit.contains("\"action\":\"perte\""), "{audit}");
}
