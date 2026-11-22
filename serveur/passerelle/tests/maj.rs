//! Preuves des mises à jour centralisées et du journal d'audit branché
//! (`docs/suite/serveur-maj-audit.md`) : `.bcu` non signé, mal signé, altéré ou sous le
//! plancher refusé ; `.bcu` valide proposé à une borne enrôlée au battement, téléchargeable
//! seulement en mTLS, état suivi ; journal d'audit intègre et complet.
//!
//! Paquets produits par le VRAI `borne/update/barbacane-update-prepare` et plancher par
//! `serveur/maj/barbacane-plancher-prepare`, avec des clés minisign jetables (minisign, zstd,
//! python3 et openssl requis, comme pour `tests/maj/maj.sh`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use barbacane_audit::{CleAudit, RefusMaj, verifier};
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::maj::{EtatMajBorne, RefusDepot};
use barbacane_passerelle::outils::{maintenant, sha256_hex};
use barbacane_passerelle::{Config, Passerelle, fournisseur, servir, servir_enrolement};
use barbacane_protocole::maj::{AccuseBattementMaj, route as route_maj};
use barbacane_protocole::{
    AccuseBattement, AccuseDemande, Battement, CodeErreur, EtatBorne, EtatDemande, ReponseErreur,
    VERSION, decoder, route,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const NOM_SERVEUR: &str = "passerelle.barbacane.invalid";

struct Banc {
    dossier: tempfile::TempDir,
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
        dossier,
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

fn battement() -> String {
    serde_json::to_string(&Battement {
        version: VERSION,
        heure_borne: maintenant(),
        version_logiciel: "2.0.0".into(),
        etat: EtatBorne::EnService,
        age_signatures_s: 0,
        espace_libre_octets: 1 << 30,
        rapports_en_attente: 0,
    })
    .unwrap()
}

fn battre_maj(banc: &Banc, cle: &Cle) -> AccuseBattementMaj {
    let r = post(
        banc,
        banc.service,
        Some(cle),
        route_maj::BATTEMENT,
        &battement(),
    )
    .unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    decoder(&r.1).unwrap()
}

fn telecharger(
    banc: &Banc,
    adresse: SocketAddr,
    cle: Option<&Cle>,
    n: u64,
) -> Result<Reponse, String> {
    post(
        banc,
        adresse,
        cle,
        route_maj::TELECHARGEMENT,
        &format!("{{\"version\":1,\"version_maj\":{n}}}"),
    )
}

fn rapporter(banc: &Banc, cle: &Cle, n: u64, resultat: &str) -> Reponse {
    post(
        banc,
        banc.service,
        Some(cle),
        route_maj::RAPPORT,
        &format!("{{\"version\":1,\"version_maj\":{n},\"resultat\":\"{resultat}\"}}"),
    )
    .unwrap()
}

// ───────────── Clés minisign jetables, paquets et planchers ─────────────

/// Paire minisign sans phrase de passe : `DOSSIER/NOM.key`, `DOSSIER/NOM.pub`.
fn cle_minisign(d: &Path, nom: &str) -> PathBuf {
    std::fs::create_dir_all(d).unwrap();
    executer(
        Command::new("minisign")
            .args(["-G", "-W", "-p"])
            .arg(d.join(format!("{nom}.pub")))
            .arg("-s")
            .arg(d.join(format!("{nom}.key"))),
    );
    d.join(format!("{nom}.key"))
}

/// `.bcu` de version `n` signé par `cle` (vrai script de préparation).
fn paquet(banc: &Banc, cle: &Path, n: u64) -> PathBuf {
    let base = banc.dossier.path().join(format!(
        "paquet-{n}-{}",
        sha256_hex(cle.to_string_lossy().as_bytes())[..8].to_owned()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let liste = base.join("images.sha256");
    std::fs::write(&liste, format!("{}  essai-{n}.iso\n", "ab".repeat(32))).unwrap();
    executer(
        Command::new(racine().join("borne/update/barbacane-update-prepare"))
            .arg("--cle")
            .arg(cle)
            .arg("--sortie")
            .arg(base.join("sortie"))
            .args([
                "--version",
                &n.to_string(),
                "--sans-clamav",
                "--images-officielles",
            ])
            .arg(&liste),
    );
    base.join("sortie").join(format!("barbacane-maj-{n}.bcu"))
}

fn plancher(banc: &Banc, cle: &Path, n: u64) -> PathBuf {
    let sortie = banc.dossier.path().join(format!(
        "plancher-{n}-{}",
        sha256_hex(cle.to_string_lossy().as_bytes())[..8].to_owned()
    ));
    executer(
        Command::new(racine().join("serveur/maj/barbacane-plancher-prepare"))
            .arg("--cle")
            .arg(cle)
            .args(["--version-min", &n.to_string(), "--sortie"])
            .arg(&sortie),
    );
    sortie.join("plancher.json")
}

fn refus(r: anyhow::Result<impl std::fmt::Debug>) -> RefusMaj {
    match r {
        Ok(v) => panic!("accepté à tort : {v:?}"),
        Err(e) => {
            e.downcast_ref::<RefusDepot>()
                .unwrap_or_else(|| panic!("erreur sans motif de refus : {e:#}"))
                .0
        }
    }
}

/// Banc prêt : clé des bornes installée, plancher 100, paquet 200 déposé.
fn banc_maj() -> (Banc, PathBuf) {
    let b = banc();
    let cles = b.dossier.path().join("cles");
    let cle = cle_minisign(&cles, "bornes");
    std::fs::copy(cles.join("bornes.pub"), b.admin.maj.chemin_cle()).unwrap();
    assert_eq!(b.admin.maj_plancher(&plancher(&b, &cle, 100)).unwrap(), 100);
    let p = b.admin.maj_deposer(&paquet(&b, &cle, 200)).unwrap();
    assert_eq!(p.version_maj, 200);
    (b, cle)
}

/// Scelle le journal d'audit avec une clé d'audit distincte et le vérifie ; renvoie son texte.
fn audit_verifie(b: &Banc) -> String {
    let journal = b.admin.stockage.journal_audit();
    let cle = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    journal.sceller(&cle, maintenant()).unwrap();
    let contenu = journal.lire().unwrap();
    let bilan = verifier(&contenu, &cle.publique(), &[]).unwrap();
    assert_eq!(bilan.non_scelles, 0);
    String::from_utf8(contenu).unwrap()
}

#[test]
fn bcu_non_signe_mal_signe_ou_sous_le_plancher_refuse() {
    let b = banc();
    let cles = b.dossier.path().join("cles");
    let cle = cle_minisign(&cles, "bornes");
    let autre = cle_minisign(&cles, "autre");
    let p300 = paquet(&b, &cle, 300);
    // Sans clé des bornes : aucun dépôt.
    assert_eq!(refus(b.admin.maj_deposer(&p300)), RefusMaj::CleAbsente);
    std::fs::copy(cles.join("bornes.pub"), b.admin.maj.chemin_cle()).unwrap();
    // Sans plancher signé : aucun dépôt.
    assert_eq!(refus(b.admin.maj_deposer(&p300)), RefusMaj::PlancherAbsent);
    // Plancher signé par une autre clé : refusé.
    assert_eq!(
        refus(b.admin.maj_plancher(&plancher(&b, &autre, 100))),
        RefusMaj::SignatureInvalide
    );
    b.admin.maj_plancher(&plancher(&b, &cle, 100)).unwrap();
    // Non signé.
    let nu = b.dossier.path().join("nu.bcu");
    std::fs::copy(&p300, &nu).unwrap();
    assert_eq!(refus(b.admin.maj_deposer(&nu)), RefusMaj::NonSigne);
    // Mal signé (clé inconnue des bornes).
    assert_eq!(
        refus(b.admin.maj_deposer(&paquet(&b, &autre, 300))),
        RefusMaj::SignatureInvalide
    );
    // Altéré après signature.
    let altere = b.dossier.path().join("altere.bcu");
    let mut o = std::fs::read(&p300).unwrap();
    let n = o.len();
    o[n / 2] ^= 1;
    std::fs::write(&altere, o).unwrap();
    std::fs::copy(
        format!("{}.minisig", p300.display()),
        format!("{}.minisig", altere.display()),
    )
    .unwrap();
    assert_eq!(
        refus(b.admin.maj_deposer(&altere)),
        RefusMaj::SignatureInvalide
    );
    // Sous le plancher.
    assert_eq!(
        refus(b.admin.maj_deposer(&paquet(&b, &cle, 50))),
        RefusMaj::SousLePlancher
    );
    // Valide, puis même version ou plus ancienne : anti-retour.
    assert_eq!(b.admin.maj_deposer(&p300).unwrap().version_maj, 300);
    assert_eq!(
        refus(b.admin.maj_deposer(&p300)),
        RefusMaj::VersionNonCroissante
    );
    assert_eq!(
        refus(b.admin.maj_deposer(&paquet(&b, &cle, 250))),
        RefusMaj::VersionNonCroissante
    );
    // Plancher rejoué en recul.
    assert_eq!(
        refus(b.admin.maj_plancher(&plancher(&b, &cle, 99))),
        RefusMaj::PlancherEnRecul
    );
    // Rien de refusé n'est conservé ; un seul paquet accepté.
    let e = b.admin.maj_etat().unwrap();
    assert_eq!(e.paquets.len(), 1);
    let fichiers: Vec<_> = std::fs::read_dir(b.config.registre.join("maj/paquets"))
        .unwrap()
        .map(|f| f.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(fichiers.len(), 2, "{fichiers:?}");
    // Chaque refus est audité, avec son motif.
    let audit = audit_verifie(&b);
    for motif in [
        "cle_absente",
        "plancher_absent",
        "non_signe",
        "signature_invalide",
        "sous_le_plancher",
        "version_non_croissante",
        "plancher_en_recul",
    ] {
        assert!(audit.contains(&format!("\"refus\":\"{motif}\"")), "{motif}");
    }
    assert!(audit.contains("\"maj_deposee\":{\"version_maj\":300"));
}

#[test]
fn bcu_valide_propose_au_battement_telecharge_en_mtls_et_suivi() {
    let (b, _cle) = banc_maj();
    let (uuid, cle) = enroler(&b);
    let (uuid2, cle2) = enroler(&b);
    // Rien de diffusé : pas de proposition ; /battement (v1) inchangé.
    assert!(battre_maj(&b, &cle).mise_a_jour.is_none());
    let r = post(&b, b.service, Some(&cle), route::BATTEMENT, &battement()).unwrap();
    decoder::<AccuseBattement>(&r.1).unwrap();
    assert!(b.admin.maj_diffuser(150).is_err(), "paquet non déposé");
    b.admin.maj_diffuser(200).unwrap();
    // Proposé au battement : version, sha256, taille, signature.
    let m = battre_maj(&b, &cle).mise_a_jour.unwrap();
    let source = b.config.registre.join("maj/paquets/barbacane-maj-200.bcu");
    let octets = std::fs::read(&source).unwrap();
    assert_eq!(
        (m.version_maj, m.taille, m.sha256.as_str()),
        (200, octets.len() as u64, sha256_hex(&octets).as_str())
    );
    assert!(
        m.signature_minisign
            .contains("trusted comment: barbacane-maj version 200")
    );
    let etat = |u: &str| b.admin.maj_etat().unwrap().bornes.get(u).map(|s| s.etat);
    assert_eq!(etat(&uuid), Some(EtatMajBorne::Proposee));
    // Téléchargement : jamais sur l'écoute d'enrôlement, jamais sans certificat client.
    let r = telecharger(&b, b.enrolement, None, 200).unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    assert!(telecharger(&b, b.service, None, 200).is_err());
    // Borne enrôlée à qui rien n'a été proposé, ou version non diffusée : refus.
    let r = telecharger(&b, b.service, Some(&cle2), 200).unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    let r = telecharger(&b, b.service, Some(&cle), 199).unwrap();
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    // Borne proposée, en mTLS : octets identiques au paquet déposé.
    let r = telecharger(&b, b.service, Some(&cle), 200).unwrap();
    assert_eq!(r.0, 200);
    assert_eq!(sha256_hex(&r.1), m.sha256);
    assert_eq!(etat(&uuid), Some(EtatMajBorne::Telechargee));
    assert_eq!(etat(&uuid2), None);
    // Rapport : appliquée, plus proposée, rapport unique.
    let r = rapporter(&b, &cle, 200, "appliquee");
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    assert_eq!(etat(&uuid), Some(EtatMajBorne::Appliquee));
    assert!(battre_maj(&b, &cle).mise_a_jour.is_none());
    let r = rapporter(&b, &cle, 200, "echec");
    assert_eq!((r.0, code(&r)), (404, CodeErreur::Introuvable));
    // Seconde borne : proposée puis échec rapporté sans téléchargement.
    assert!(battre_maj(&b, &cle2).mise_a_jour.is_some());
    assert_eq!(rapporter(&b, &cle2, 200, "echec").0, 200);
    assert_eq!(etat(&uuid2), Some(EtatMajBorne::Echec));
    // Borne révoquée : plus aucune proposition ni téléchargement.
    b.admin
        .revoquer(
            &uuid2,
            barbacane_passerelle::registre::Motif::Volee,
            maintenant(),
        )
        .unwrap();
    assert!(telecharger(&b, b.service, Some(&cle2), 200).is_err());
    // Journal d'audit : intègre, toutes les étapes tracées.
    let audit = audit_verifie(&b);
    for attendu in [
        "\"enrolement_demande\"".to_string(),
        "\"enrolement_valide\"".to_string(),
        "\"plancher_installe\":{\"version_min\":100}".to_string(),
        "\"maj_deposee\":{\"version_maj\":200".to_string(),
        "\"maj_diffusee\":{\"version_maj\":200}".to_string(),
        format!("\"maj_proposee\":{{\"borne\":\"{uuid}\""),
        format!("\"maj_telechargee\":{{\"borne\":\"{uuid}\""),
        format!(
            "\"maj_rapportee\":{{\"borne\":\"{uuid}\",\"version_maj\":200,\"resultat\":\"appliquee\"}}"
        ),
        format!("\"revocation\":{{\"borne\":\"{uuid2}\",\"motif\":\"volee\"}}"),
        "\"acteur\":\"admin:uid-".to_string(),
    ] {
        assert!(audit.contains(&attendu), "absent du journal : {attendu}");
    }
    // Une seule proposition auditée par borne et par version (pas une par battement).
    assert_eq!(
        audit
            .matches(&format!("\"maj_proposee\":{{\"borne\":\"{uuid}\""))
            .count(),
        1
    );
}

#[test]
fn anomalies_de_battement_auditees_au_changement() {
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let derive = |decalage: u64| {
        serde_json::to_string(&Battement {
            version: VERSION,
            heure_borne: maintenant() + decalage,
            version_logiciel: "2.0.0".into(),
            etat: EtatBorne::EnService,
            age_signatures_s: 0,
            espace_libre_octets: 1,
            rapports_en_attente: 0,
        })
        .unwrap()
    };
    for _ in 0..3 {
        let r = post(&b, b.service, Some(&cle), route::BATTEMENT, &derive(3600)).unwrap();
        assert_eq!(code(&r), CodeErreur::HorlogeDerivee);
    }
    let audit = audit_verifie(&b);
    let motif =
        format!("\"battement_anormal\":{{\"borne\":\"{uuid}\",\"anomalie\":\"horloge_derivee\"");
    assert_eq!(audit.matches(&motif).count(), 1, "{audit}");
}

/// Quarantaine (étape 11) : désactivée par défaut, le dépôt d'une borne authentifiée est refusé
/// AVANT la lecture du corps et audité ; accepté une fois l'activation validée par deux
/// administrateurs (option choisie par les administrateurs, décision du 21/11/2026).
#[test]
fn quarantaine_refusee_par_la_passerelle_si_desactivee() {
    use barbacane_passerelle::quarantaine::{Quarantaine, Validation};
    let b = banc();
    let (uuid, cle) = enroler(&b);
    let contenu = b"fichier bloque de TEST";
    let corps = serde_json::json!({
        "version": VERSION,
        "sha256": sha256_hex(contenu),
        "taille": contenu.len(),
        "contenu_b64": data_encoding::BASE64.encode(contenu),
    })
    .to_string();
    let chemin = barbacane_protocole::quarantaine::route::DEPOT;
    let r = post(&b, b.service, Some(&cle), chemin, &corps).unwrap();
    assert_eq!(r.0, 403);
    assert_eq!(code(&r), CodeErreur::QuarantaineDesactivee);
    let journal = String::from_utf8(b.admin.stockage.journal_audit().lire().unwrap()).unwrap();
    assert!(
        journal.contains(&format!("\"reception-refusee\",\"element\":\"{uuid}\"")),
        "{journal}"
    );
    // D13 : la borne enrôlée est sur un site en mode Aucun (défaut) → activation refusée.
    let q = Quarantaine::ouvrir(&b.admin.stockage).unwrap();
    let site = b.admin.stockage.lire().unwrap().bornes[0].site.clone();
    let e = q
        .demander_activation("web:alice", maintenant())
        .unwrap_err();
    assert!(
        format!("{e:#}").contains("D13") && format!("{e:#}").contains(&site),
        "{e:#}"
    );
    let u = barbacane_passerelle::utilisateurs::Utilisateurs::ouvrir(&b.admin.stockage).unwrap();
    u.definir_mode_d13(
        &site,
        barbacane_protocole::utilisateurs::ModeUtilisateurs::Identification,
        "web:alice",
        maintenant(),
    )
    .unwrap();
    assert!(
        barbacane_passerelle::utilisateurs::sites_en_mode_aucun(&b.admin.stockage, maintenant())
            .unwrap()
            .is_empty()
    );
    // Double validation : dépôt accepté.
    let d = q.demander_activation("web:alice", maintenant()).unwrap();
    assert!(matches!(
        q.valider(&d, "web:carole", maintenant()).unwrap(),
        Validation::Activee
    ));
    let r = post(&b, b.service, Some(&cle), chemin, &corps).unwrap();
    assert_eq!(r.0, 200, "{}", String::from_utf8_lossy(&r.1));
    assert_eq!(q.elements(maintenant()).unwrap()[0].borne, uuid);
    // D13, état RÉEL : quarantaine active → mode Aucun refusé, jeton d'un site Aucun refusé.
    assert!(barbacane_passerelle::utilisateurs::quarantaine_active(
        &b.admin.stockage
    ));
    let e = u
        .definir_mode_d13(
            &site,
            barbacane_protocole::utilisateurs::ModeUtilisateurs::Aucun,
            "web:alice",
            maintenant(),
        )
        .unwrap_err();
    assert!(format!("{e:#}").contains("D13"));
    assert!(b.admin.creer_jeton("site-neuf", maintenant()).is_err());
    assert!(b.admin.creer_jeton(&site, maintenant()).is_ok());
    // Désactivation par un seul administrateur (sens sûr), puis Aucun de nouveau permis.
    q.desactiver("web:alice").unwrap();
    assert!(!barbacane_passerelle::utilisateurs::quarantaine_active(
        &b.admin.stockage
    ));
    u.definir_mode_d13(
        &site,
        barbacane_protocole::utilisateurs::ModeUtilisateurs::Aucun,
        "web:alice",
        maintenant(),
    )
    .unwrap();
}
