//! Preuve de la synchronisation LDAPS (`docs/suite/serveur-utilisateurs.md` §2) contre un
//! **faux annuaire local** : TLS 1.3 avec une CA de TEST générée ici (rcgen), réponses LDAP
//! encodées à la main (liaison, recherche paginée). Aucun vrai annuaire au lab.
//!
//! Prouve : la CA épinglée est la seule ancre (une autre CA → refus, rien importé) ; le compte
//! de service et son mot de passe sont présentés ; seul l'attribut demandé est importé ;
//! mauvais mot de passe → refus ; fichier de mot de passe lisible par d'autres → refus.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use barbacane_passerelle::fournisseur;
use barbacane_passerelle::registre::Stockage;
use barbacane_passerelle::utilisateurs::Utilisateurs;
use barbacane_web::annuaire::{ConfigAnnuaire, lire_identifiants, synchroniser};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const COMPTE: &str = "CN=svc-barbacane,OU=Services,DC=exemple,DC=invalid";
const MDP: &str = "mot de passe de TEST du compte de service";
const IDENTIFIANTS: &[&str] = &["J.Dupont", "a.martin", "x y", "b.durand"];

/// Encodage BER : étiquette, longueur (forme courte ou longue), contenu.
fn tlv(etiquette: u8, contenu: &[u8]) -> Vec<u8> {
    let mut o = vec![etiquette];
    let n = contenu.len();
    if n < 128 {
        o.push(n as u8);
    } else {
        let octets: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        o.push(0x80 | octets.len() as u8);
        o.extend(octets);
    }
    o.extend_from_slice(contenu);
    o
}

fn chaine(s: &str) -> Vec<u8> {
    tlv(0x04, s.as_bytes())
}

fn message(id: &[u8], op: Vec<u8>, controles: Option<Vec<u8>>) -> Vec<u8> {
    let mut c = tlv(0x02, id);
    c.extend(op);
    if let Some(k) = controles {
        c.extend(tlv(0xa0, &k));
    }
    tlv(0x30, &c)
}

fn resultat(app: u8, code: u8) -> Vec<u8> {
    let mut c = tlv(0x0a, &[code]);
    c.extend(chaine(""));
    c.extend(chaine(""));
    tlv(app, &c)
}

/// Lit un TLV complet : (étiquette, contenu).
fn lire_tlv(f: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut e = [0u8; 2];
    f.read_exact(&mut e).ok()?;
    let n = if e[1] < 128 {
        e[1] as usize
    } else {
        let mut l = vec![0u8; (e[1] & 0x7f) as usize];
        f.read_exact(&mut l).ok()?;
        l.iter().fold(0usize, |a, b| (a << 8) | *b as usize)
    };
    let mut c = vec![0u8; n];
    f.read_exact(&mut c).ok()?;
    Some((e[0], c))
}

/// Découpe le contenu d'une séquence en TLV.
fn elements(mut c: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut v = Vec::new();
    while !c.is_empty() {
        let Some(x) = lire_tlv(&mut c) else { break };
        v.push(x);
    }
    v
}

/// Ce que le faux annuaire a reçu.
#[derive(Default)]
struct Recu {
    liaisons: Vec<(String, String)>,
    attributs: Vec<String>,
    paginee: bool,
}

/// Faux annuaire : une connexion TLS, liaison simple, une recherche, déconnexion.
fn faux_annuaire(cert: CertificateDer<'static>, cle: Vec<u8>) -> (u16, Arc<Mutex<Recu>>) {
    let tls = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(fournisseur()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cle)),
            )
            .unwrap(),
    );
    let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ecoute.local_addr().unwrap().port();
    let recu = Arc::new(Mutex::new(Recu::default()));
    let r2 = recu.clone();
    std::thread::spawn(move || {
        for flux in ecoute.incoming() {
            let Ok(flux) = flux else { continue };
            let mut s = StreamOwned::new(ServerConnection::new(tls.clone()).unwrap(), flux);
            while let Some((0x30, c)) = lire_tlv(&mut s) {
                let el = elements(&c);
                let id = el[0].1.clone();
                match el[1].0 {
                    0x60 => {
                        let b = elements(&el[1].1);
                        let dn = String::from_utf8_lossy(&b[1].1).into_owned();
                        let mdp = String::from_utf8_lossy(&b[2].1).into_owned();
                        let ok = dn == COMPTE && mdp == MDP;
                        r2.lock().unwrap().liaisons.push((dn, mdp));
                        let rep = message(&id, resultat(0x61, if ok { 0 } else { 49 }), None);
                        if s.write_all(&rep).is_err() {
                            break;
                        }
                    }
                    0x63 => {
                        let req = elements(&el[1].1);
                        let attrs: Vec<String> = elements(&req.last().unwrap().1)
                            .into_iter()
                            .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
                            .collect();
                        let paginee = el.len() > 2;
                        {
                            let mut r = r2.lock().unwrap();
                            r.attributs = attrs;
                            r.paginee = paginee;
                        }
                        for (i, ident) in IDENTIFIANTS.iter().enumerate() {
                            // L'annuaire renvoie aussi un attribut non demandé : ignoré.
                            let mut a = tlv(
                                0x30,
                                &[chaine("sAMAccountName"), tlv(0x31, &chaine(ident))].concat(),
                            );
                            a.extend(tlv(
                                0x30,
                                &[chaine("mail"), tlv(0x31, &chaine("fuite@exemple.invalid"))]
                                    .concat(),
                            ));
                            let entree = tlv(
                                0x64,
                                &[
                                    chaine(&format!("CN=u{i},DC=exemple,DC=invalid")),
                                    tlv(0x30, &a),
                                ]
                                .concat(),
                            );
                            s.write_all(&message(&id, entree, None)).unwrap();
                        }
                        // Fin de recherche avec le contrôle de pagination (cookie vide).
                        let valeur = tlv(0x30, &[tlv(0x02, &[0]), chaine("")].concat());
                        let controle = tlv(
                            0x30,
                            &[chaine("1.2.840.113556.1.4.319"), tlv(0x04, &valeur)].concat(),
                        );
                        s.write_all(&message(&id, resultat(0x65, 0), Some(controle)))
                            .unwrap();
                    }
                    _ => break, // déconnexion (0x42) ou autre
                }
                let _ = s.flush();
            }
        }
    });
    (port, recu)
}

/// CA de TEST et certificat « localhost » signé par elle.
fn pki() -> (String, CertificateDer<'static>, Vec<u8>) {
    let ca_cle = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(
        DnType::CommonName,
        "Barbacane TEST CA annuaire — NE PAS UTILISER",
    );
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let ca = p.self_signed(&ca_cle).unwrap();
    let pem = ca.pem();
    let issuer = Issuer::from_ca_cert_der(ca.der(), ca_cle).unwrap();
    let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&cle, &issuer)
        .unwrap();
    (pem, cert.der().clone(), cle.serialize_der())
}

fn config(d: &Path, port: u16, ca_pem: &str, mdp: &str) -> ConfigAnnuaire {
    std::fs::write(d.join("ca.pem"), ca_pem).unwrap();
    let f = d.join("mdp");
    std::fs::write(&f, format!("{mdp}\n")).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let texte = format!(
        "url = ldaps://localhost:{port}\nca = {d}/ca.pem\ncompte = {COMPTE}\nmot_de_passe_fichier = {d}/mdp\nbase = DC=exemple,DC=invalid\nfiltre = (&(objectClass=user)(memberOf=CN=Barbacane,DC=exemple,DC=invalid))\nattribut = sAMAccountName\n",
        d = d.display()
    );
    std::fs::write(d.join("annuaire.conf"), &texte).unwrap();
    ConfigAnnuaire::analyser(&texte).unwrap()
}

#[test]
fn annuaire_ldaps_de_test() {
    let d = tempfile::tempdir().unwrap();
    let (ca_pem, cert, cle) = pki();
    let (port, recu) = faux_annuaire(cert, cle);
    let c = config(d.path(), port, &ca_pem, MDP);

    // Lecture : identifiants seulement, attribut unique demandé, recherche paginée.
    let ids = lire_identifiants(&c, 100).unwrap();
    assert_eq!(ids, IDENTIFIANTS);
    {
        let r = recu.lock().unwrap();
        assert_eq!(r.liaisons, vec![(COMPTE.to_owned(), MDP.to_owned())]);
        assert_eq!(r.attributs, vec!["sAMAccountName".to_owned()]);
        assert!(r.paginee, "contrôle de pagination envoyé");
    }
    assert!(lire_identifiants(&c, 2).is_err(), "plafond d'identifiants");

    // Import dans la base : normalisés, non conformes ignorés, aucune autre donnée.
    let stockage = Stockage::ouvrir(&d.path().join("etat")).unwrap();
    let u = Utilisateurs::ouvrir(&stockage).unwrap();
    let b = synchroniser(
        &d.path().join("annuaire.conf"),
        &u,
        "web:alice",
        1_800_000_000,
    )
    .unwrap();
    assert_eq!((b.actifs, b.ajoutes, b.ignores), (3, 3, 1));
    let base = std::fs::read_to_string(u.dossier().join("base.json")).unwrap();
    assert!(base.contains("\"j.dupont\"") && !base.contains("fuite@"));
    assert!(!base.contains(MDP));
    let audit = String::from_utf8(stockage.journal_audit().lire().unwrap()).unwrap();
    assert!(audit.contains("\"utilisateurs_importes\"") && !audit.contains("dupont"));

    // Mauvais mot de passe du compte de service : refus.
    let c2 = config(d.path(), port, &ca_pem, "faux");
    assert!(lire_identifiants(&c2, 100).is_err());
    // Fichier de mot de passe lisible par d'autres comptes : refus avant toute connexion.
    std::fs::set_permissions(d.path().join("mdp"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(lire_identifiants(&c2, 100).is_err());

    // Autre CA (le faux annuaire n'est pas celui épinglé) : refus TLS, rien de lu.
    let (autre_ca, _, _) = pki();
    let n = recu.lock().unwrap().liaisons.len();
    let c3 = config(d.path(), port, &autre_ca, MDP);
    let e = lire_identifiants(&c3, 100).unwrap_err();
    assert_eq!(
        recu.lock().unwrap().liaisons.len(),
        n,
        "aucune liaison sans TLS vérifié : {e:#}"
    );
}
