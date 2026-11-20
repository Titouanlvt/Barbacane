//! Preuves des rapports minimaux de passage (`docs/suite/protocole-agent.md` §10, D2) : vraie
//! écoute mTLS, borne enrôlée par le vrai parcours (PKI de TEST, openssl requis).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::passages::Passages;
use barbacane_passerelle::{Config, Passerelle, fournisseur, servir, servir_enrolement};
use barbacane_protocole::passage::{
    AccuseRapportPassage, FichierPassage, RapportPassage, TAILLE_RAPPORT_MAX, Verdict,
    route as route_p,
};
use barbacane_protocole::{
    AccuseDemande, CodeErreur, EtatDemande, ReponseErreur, VERSION, decoder, encoder, route,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";

struct Banc {
    dossier: tempfile::TempDir,
    pki: PathBuf,
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
        dossier,
        pki,
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

const SECRET: &str = "dossier-confidentiel-7f3a.docx";

fn rapport(id: &str, n: usize) -> RapportPassage {
    RapportPassage {
        version: VERSION,
        id: id.into(),
        horodatage: maintenant(),
        verdict: Verdict::Menace,
        support: "c".repeat(64),
        partie: 1,
        parties: 1,
        fichiers: (0..n)
            .map(|i| FichierPassage {
                taille: 68 + i as u64,
                sha256: format!("{i:064x}"),
                verdict: if i == 0 {
                    Verdict::Menace
                } else {
                    Verdict::Sain
                },
            })
            .collect(),
    }
}

fn envoyer_rapport(b: &Banc, cle: Option<&Cle>, corps: &[u8]) -> Result<Reponse, String> {
    let mut brut = format!(
        "POST {} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        route_p::PASSAGE,
        corps.len()
    )
    .into_bytes();
    brut.extend_from_slice(corps);
    envoyer(b, b.service, cle, &brut)
}

const ID: &str = "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";

#[test]
fn rapport_accepte_puis_doublon_idempotent() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let corps = encoder(&rapport(ID, 5_000)).unwrap();
    assert!(corps.len() <= TAILLE_RAPPORT_MAX);
    let r = envoyer_rapport(&b, Some(&cle), &corps).unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    assert!(!decoder::<AccuseRapportPassage>(&r.1).unwrap().deja_recu);
    // Rejeu après coupure : 200, rien de réécrit ni de réaudité.
    let r = envoyer_rapport(&b, Some(&cle), &corps).unwrap();
    assert_eq!(r.0, 200);
    assert!(decoder::<AccuseRapportPassage>(&r.1).unwrap().deja_recu);
    let p = Passages::ouvrir(&b.admin.stockage).unwrap();
    let l = p.derniers(10).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(
        (l[0].borne.as_str(), l[0].fichiers, l[0].menaces),
        (uuid.as_str(), 5_000, 1)
    );
    assert_eq!(
        p.detail(&uuid, ID, 1).unwrap().unwrap().rapport,
        rapport_sans_heure(&p, &uuid)
    );
    let a = audit(&b);
    assert_eq!(a.matches("\"rapport_passage\"").count(), 1, "{a}");
    assert!(a.contains(&uuid) && a.contains(ID) && a.contains("\"menace\""));
}

fn rapport_sans_heure(p: &Passages, uuid: &str) -> RapportPassage {
    let mut r = rapport(ID, 5_000);
    r.horodatage = p.detail(uuid, ID, 1).unwrap().unwrap().rapport.horodatage;
    r
}

#[test]
fn trop_gros_ou_mal_forme_refuse() {
    let b = banc();
    let (_, cle) = enroler(&b);
    // Content-Length au-delà de 1 Mio : refus AVANT lecture du corps.
    let brut = format!(
        "POST {} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        route_p::PASSAGE,
        TAILLE_RAPPORT_MAX + 1
    );
    let r = envoyer(&b, b.service, Some(&cle), brut.as_bytes()).unwrap();
    assert_eq!((r.0, code(&r)), (413, CodeErreur::TropGros));
    // Plus de 10 000 fichiers (et donc plus de 1 Mio ici) : refusé.
    let mut gros = rapport(ID, 1);
    gros.fichiers = vec![gros.fichiers[0].clone(); 10_001];
    assert!(
        encoder(&gros).is_err(),
        "la borne ne peut même pas l'encoder"
    );
    let brut = format!(
        "POST {} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        route_p::PASSAGE,
        serde_json::to_vec(&gros).unwrap().len()
    );
    let r = envoyer(&b, b.service, Some(&cle), brut.as_bytes()).unwrap();
    assert_eq!((r.0, code(&r)), (413, CodeErreur::TropGros));
    // Partie hors bornes : refusée.
    let mut r = rapport(ID, 1);
    r.partie = 2;
    let corps = serde_json::to_vec(&r).unwrap();
    let r = envoyer_rapport(&b, Some(&cle), &corps).unwrap();
    assert_eq!((r.0, code(&r)), (400, CodeErreur::RequeteInvalide));
    assert!(
        Passages::ouvrir(&b.admin.stockage)
            .unwrap()
            .derniers(10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sans_certificat_refuse() {
    let b = banc();
    let corps = encoder(&rapport(ID, 1)).unwrap();
    match envoyer_rapport(&b, None, &corps) {
        Err(e) => eprintln!("refus attendu : {e}"),
        Ok(r) => assert_ne!(r.0, 200, "rapport accepté sans certificat"),
    }
    // Écoute d'enrôlement : la route n'y existe pas.
    let mut brut = format!(
        "POST {} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        route_p::PASSAGE,
        corps.len()
    )
    .into_bytes();
    brut.extend_from_slice(&corps);
    let r = envoyer(&b, b.enrolement, None, &brut).unwrap();
    assert_eq!(r.0, 404);
    assert!(
        Passages::ouvrir(&b.admin.stockage)
            .unwrap()
            .derniers(10)
            .unwrap()
            .is_empty()
    );
    assert!(!audit(&b).contains("rapport_passage"));
}

#[test]
fn aucun_nom_de_fichier_stocke_ni_audite() {
    let b = banc();
    let (_, cle) = enroler(&b);
    // Une borne compromise tente d'ajouter un nom ou un chemin : schéma strict, refus.
    for champ in ["nom", "chemin", "path"] {
        let mut v = serde_json::to_value(rapport(ID, 2)).unwrap();
        v["fichiers"][0][champ] = SECRET.into();
        let r = envoyer_rapport(&b, Some(&cle), &serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(
            (r.0, code(&r)),
            (400, CodeErreur::RequeteInvalide),
            "{champ}"
        );
        let mut v = serde_json::to_value(rapport(ID, 2)).unwrap();
        v[champ] = SECRET.into();
        let r = envoyer_rapport(&b, Some(&cle), &serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(r.0, 400, "{champ}");
    }
    // Un nom glissé dans un champ contrôlé (identifiant, support, empreinte) : refusé aussi.
    let mut r = rapport(ID, 1);
    r.id = SECRET.into();
    let corps = serde_json::to_vec(&r).unwrap();
    assert_eq!(envoyer_rapport(&b, Some(&cle), &corps).unwrap().0, 400);
    let mut r = rapport(ID, 1);
    r.fichiers[0].sha256 = SECRET.into();
    let corps = serde_json::to_vec(&r).unwrap();
    assert_eq!(envoyer_rapport(&b, Some(&cle), &corps).unwrap().0, 400);
    // Rapport valide : accepté ; aucun stockage ni l'audit ne contient le nom.
    let corps = encoder(&rapport(ID, 2)).unwrap();
    assert_eq!(envoyer_rapport(&b, Some(&cle), &corps).unwrap().0, 200);
    let tout = tout_l_etat(b.dossier.path());
    assert!(contient(&tout, "rapport_passage"));
    for aiguille in [SECRET, "dossier-confidentiel", ".docx"] {
        assert!(
            !contient(&tout, aiguille),
            "{aiguille} trouvé dans l'état du serveur"
        );
    }
}
