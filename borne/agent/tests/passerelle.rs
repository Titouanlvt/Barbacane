//! Agent contre une VRAIE passerelle (en cours de processus) et une PKI de TEST générée par
//! `serveur/pki/racine-test.sh` (openssl requis) : enrôlement, validation, battement visible
//! dans la supervision, renouvellement à mi-vie, mode dégradé, révocation, CA non épinglée.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use barbacane_agent::coffre::CoffreFichier;
use barbacane_agent::config::Config as ConfigAgent;
use barbacane_agent::{Agent, EtatPublic, Mode, validite};
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::maj::EtatMajBorne;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::registre::Motif;
use barbacane_passerelle::{Config, Passerelle, servir, servir_enrolement};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

const JOUR: u64 = 24 * 3600;

struct Banc {
    dossier: tempfile::TempDir,
    pki: PathBuf,
    config: Config,
    admin: Admin,
}

fn banc() -> Banc {
    let dossier = tempfile::tempdir().unwrap();
    let pki = dossier.path().join("pki");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../serveur/pki/racine-test.sh");
    let sortie = Command::new(script).arg(&pki).output().unwrap();
    assert!(
        sortie.status.success(),
        "racine-test.sh : {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    let ecoute_service = TcpListener::bind("127.0.0.1:0").unwrap();
    let ecoute_enrolement = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = Config {
        adresse: "127.0.0.1".parse().unwrap(),
        port: ecoute_service.local_addr().unwrap().port(),
        port_enrolement: ecoute_enrolement.local_addr().unwrap().port(),
        chaine_serveur: pki.join("serveur/chaine.pem"),
        cle_serveur: pki.join("serveur/cle.pem"),
        ca_bornes: pki.join("ca-bornes/cert.pem"),
        cle_ca_bornes: pki.join("ca-bornes/cle.pem"),
        crl_bornes: pki.join("ca-bornes/crl.pem"),
        registre: dossier.path().join("registre"),
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
    }
}

fn empreinte(chemin: &Path) -> String {
    let ca = CertificateDer::from_pem_file(chemin).unwrap();
    hex::encode(ring::digest::digest(&ring::digest::SHA256, &ca))
}

/// Configuration de l'agent ; `ca` : la CA épinglée dans « l'ISO ».
fn config_agent(b: &Banc, ca: &Path, port_service: u16) -> ConfigAgent {
    let etat = b.dossier.path().join("agent");
    let texte = format!(
        "adresse = \"127.0.0.1\"\nport_enrolement = {}\nport_service = {port_service}\nca_serveur = \"{}\"\nempreinte_ca_serveur = \"{}\"\netat = \"{}\"\nexecution = \"{}\"\n",
        b.config.port_enrolement,
        ca.display(),
        empreinte(ca),
        etat.display(),
        b.dossier.path().join("run").display(),
    );
    ConfigAgent::analyser(&texte).unwrap()
}

fn agent(b: &Banc) -> Agent<CoffreFichier> {
    let c = config_agent(b, &b.pki.join("ca-serveur/cert.pem"), b.config.port);
    let coffre = CoffreFichier::nouveau(&c.etat);
    Agent::nouveau(c, coffre).unwrap()
}

fn deposer_jeton(b: &Banc, a: &Agent<CoffreFichier>) {
    let j = b.admin.creer_jeton("site-1", maintenant()).unwrap();
    std::fs::write(a.config.etat.join("jeton"), format!("{}\n", j.formater())).unwrap();
}

fn etat_publie(a: &Agent<CoffreFichier>) -> EtatPublic {
    serde_json::from_slice(&std::fs::read(a.config.execution.join("etat.json")).unwrap()).unwrap()
}

/// Jeton, demande, validation (à l'heure `t`, empreinte retapée), installation. Renvoie l'uuid.
fn enroler(b: &Banc, a: &mut Agent<CoffreFichier>, t: u64) -> String {
    deposer_jeton(b, a);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::AttenteValidation, "{}", a.etat.message);
    assert!(
        !a.config.etat.join("jeton").exists(),
        "jeton consommé après le dépôt"
    );
    let empreinte = a.etat.empreinte.clone().unwrap();
    assert_eq!(
        etat_publie(a).empreinte.as_deref(),
        Some(empreinte.as_str())
    );
    // Pas de certificat tant que l'administrateur n'a pas validé.
    a.cycle();
    assert_eq!(a.etat.mode, Mode::AttenteValidation);
    let demandes = b.admin.demandes(maintenant()).unwrap();
    let d = demandes.iter().find(|d| d.empreinte == empreinte).unwrap();
    let uuid = b
        .admin
        .valider(&d.id, &empreinte, Some("borne-agent"), t)
        .unwrap();
    assert_eq!(a.cycle(), Duration::ZERO, "{}", a.etat.message);
    uuid
}

#[test]
fn enrolement_battement_supervision_revocation() {
    let b = banc();
    let mut a = agent(&b);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::NonEnrolee);
    let uuid = enroler(&b, &mut a, maintenant());
    let mode = std::fs::metadata(a.config.etat.join("cle.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "clé privée 0600");
    assert!(!a.config.etat.join("cle-attente.pem").exists());

    // Battement accepté et visible dans la supervision.
    let attente = a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    assert_eq!(attente, Duration::from_secs(60));
    assert_eq!(etat_publie(&a).mode, Mode::Connectee);
    let l = b.admin.supervision(maintenant()).unwrap();
    let l = l.iter().find(|l| l.uuid == uuid).unwrap();
    assert!(l.active && l.derniere_vue.is_some(), "battement enregistré");
    assert_eq!(
        l.version_logiciel.as_deref(),
        Some(barbacane_agent::VERSION_LOGICIEL)
    );
    assert!(l.alertes.is_empty(), "{:?}", l.alertes);

    // Révocation : l'agent passe en « refusée » proprement, ne panique pas, ne reboucle pas.
    b.admin.revoquer(&uuid, Motif::Volee, maintenant()).unwrap();
    assert_eq!(a.cycle(), barbacane_agent::PERIODE_JETON);
    assert_eq!(a.etat.mode, Mode::Refusee, "{}", a.etat.message);
    a.cycle();
    assert_eq!(etat_publie(&a).mode, Mode::Refusee);
    // Agent redémarré : reste refusé.
    let mut a = agent(&b);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Refusee);

    // Nouvel enrôlement décidé par l'administrateur : nouvelle clé, nouvelle identité.
    let uuid2 = enroler(&b, &mut a, maintenant());
    assert_ne!(uuid, uuid2);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
}

#[test]
fn renouvellement_a_mi_vie() {
    let b = banc();
    let mut a = agent(&b);
    // Validée il y a 50 jours : au-delà de la mi-vie d'un certificat de 90 jours.
    enroler(&b, &mut a, maintenant() - 50 * JOUR);
    let lire_fin = |a: &Agent<CoffreFichier>| {
        let pem = std::fs::read(a.config.etat.join("chaine.pem")).unwrap();
        let c = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap();
        validite(&c).unwrap().1
    };
    let avant = lire_fin(&a);
    assert!(avant < maintenant() + 41 * JOUR);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    let apres = lire_fin(&a);
    assert!(
        apres > maintenant() + 89 * JOUR,
        "nouveau certificat de 90 jours"
    );
    assert!(!a.config.etat.join("cle-nouvelle.pem").exists());
    // Le nouveau certificat sert ; l'ancien est alors remplacé (CRL) sans gêner l'agent.
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    assert_eq!(lire_fin(&a), apres, "pas de second renouvellement");
}

#[test]
fn serveur_absent_mode_degrade_puis_reprise() {
    let b = banc();
    let mut a = agent(&b);
    enroler(&b, &mut a, maintenant());
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee);
    // Serveur « éteint » : un port où plus rien n'écoute.
    let ferme = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let c = config_agent(&b, &b.pki.join("ca-serveur/cert.pem"), ferme);
    let mut hors = Agent::nouveau(c.clone(), CoffreFichier::nouveau(&c.etat)).unwrap();
    let d1 = hors.cycle();
    assert_eq!(hors.etat.mode, Mode::Degradee, "{}", hors.etat.message);
    let d2 = hors.cycle();
    assert!(d2 > d1, "essais espacés ({d1:?} puis {d2:?})");
    for _ in 0..20 {
        assert!(hors.cycle() <= Duration::from_secs(300));
    }
    assert_eq!(etat_publie(&hors).mode, Mode::Degradee);
    assert!(hors.file().is_empty());
    // Identité intacte : le serveur revient, la liaison reprend.
    let mut a = agent(&b);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
}

#[test]
fn ca_non_epinglee_aucun_echange() {
    let b = banc();
    // « ISO » d'un autre serveur : CA épinglée = CA bornes (le certificat du serveur n'en
    // descend pas). La demande n'est jamais envoyée, le jeton est conservé.
    let c = config_agent(&b, &b.pki.join("ca-bornes/cert.pem"), b.config.port);
    let mut a = Agent::nouveau(c.clone(), CoffreFichier::nouveau(&c.etat)).unwrap();
    deposer_jeton(&b, &a);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::NonEnrolee);
    assert!(
        a.etat.message.contains("NON authentifié"),
        "{}",
        a.etat.message
    );
    assert!(a.config.etat.join("jeton").exists(), "jeton conservé");
    assert!(b.admin.demandes(maintenant()).unwrap().is_empty());
    // Fichier de CA remplacé (empreinte ne correspondant plus) : l'agent refuse de démarrer.
    let mut c2 = c.clone();
    c2.empreinte_ca_serveur = empreinte(&b.pki.join("ca-serveur/cert.pem"));
    assert!(Agent::nouveau(c2.clone(), CoffreFichier::nouveau(&c2.etat)).is_err());
}

#[test]
fn jeton_d_un_autre_port_ou_mal_forme_supprime() {
    let b = banc();
    let mut a = agent(&b);
    let autre = barbacane_protocole::Jeton::nouveau(1, &[7; 16]).formater();
    std::fs::write(a.config.etat.join("jeton"), autre).unwrap();
    a.cycle();
    assert!(!a.config.etat.join("jeton").exists());
    assert!(a.etat.message.contains("port"), "{}", a.etat.message);
    std::fs::write(a.config.etat.join("jeton"), "n'importe quoi").unwrap();
    a.cycle();
    assert!(!a.config.etat.join("jeton").exists());
    assert_eq!(a.etat.mode, Mode::NonEnrolee);
}

// ───────────── Mises à jour relayées par le serveur (§9 du protocole) ─────────────

fn executer(c: &mut Command) {
    let s = c.output().unwrap();
    assert!(
        s.status.success(),
        "{c:?} : {}{}",
        String::from_utf8_lossy(&s.stdout),
        String::from_utf8_lossy(&s.stderr)
    );
}

/// Clé minisign jetable, plancher 100 et paquet `n` déposé puis diffusé (vrais scripts de
/// préparation, comme `serveur/passerelle/tests/maj.rs`). Renvoie le `.bcu` d'origine.
fn diffuser(b: &Banc, n: u64) -> PathBuf {
    let racine = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let d = b.dossier.path().join("maj-prep");
    std::fs::create_dir_all(&d).unwrap();
    executer(
        Command::new("minisign")
            .args(["-G", "-W", "-p"])
            .arg(d.join("bornes.pub"))
            .arg("-s")
            .arg(d.join("bornes.key")),
    );
    std::fs::copy(d.join("bornes.pub"), b.admin.maj.chemin_cle()).unwrap();
    executer(
        Command::new(racine.join("serveur/maj/barbacane-plancher-prepare"))
            .arg("--cle")
            .arg(d.join("bornes.key"))
            .args(["--version-min", "100", "--sortie"])
            .arg(d.join("plancher")),
    );
    b.admin
        .maj_plancher(&d.join("plancher/plancher.json"))
        .unwrap();
    let liste = d.join("images.sha256");
    std::fs::write(&liste, format!("{}  essai.iso\n", "ab".repeat(32))).unwrap();
    executer(
        Command::new(racine.join("borne/update/barbacane-update-prepare"))
            .arg("--cle")
            .arg(d.join("bornes.key"))
            .arg("--sortie")
            .arg(d.join("sortie"))
            .args([
                "--version",
                &n.to_string(),
                "--sans-clamav",
                "--images-officielles",
            ])
            .arg(&liste),
    );
    let bcu = d.join("sortie").join(format!("barbacane-maj-{n}.bcu"));
    b.admin.maj_deposer(&bcu).unwrap();
    b.admin.maj_diffuser(n).unwrap();
    bcu
}

fn suivi(b: &Banc, uuid: &str) -> Option<EtatMajBorne> {
    b.admin.maj_etat().unwrap().bornes.get(uuid).map(|s| s.etat)
}

#[test]
fn mise_a_jour_telechargee_deposee_rapportee_jamais_appliquee() {
    let b = banc();
    let mut a = agent(&b);
    let uuid = enroler(&b, &mut a, maintenant());
    let bcu = diffuser(&b, 200);
    let maj = a.config.etat.join("maj");

    // Battement : proposition, téléchargement mTLS, empreinte conforme, dépôt pour admind.
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    assert_eq!(
        std::fs::read(maj.join("barbacane-maj-200.bcu")).unwrap(),
        std::fs::read(&bcu).unwrap(),
        "paquet reçu identique"
    );
    assert_eq!(
        std::fs::read_to_string(maj.join("barbacane-maj-200.bcu.minisig")).unwrap(),
        std::fs::read_to_string(format!("{}.minisig", bcu.display())).unwrap()
    );
    assert!(maj.join("annonce.json").is_file());
    let e = etat_publie(&a).mise_a_jour.unwrap();
    assert!(e.prete && !e.rapport_en_attente && e.version_maj == 200);
    assert_eq!(suivi(&b, &uuid), Some(EtatMajBorne::Telechargee));
    // Rien d'appliqué par l'agent ; pas de second téléchargement au battement suivant.
    let avant = std::fs::metadata(maj.join("barbacane-maj-200.bcu"))
        .unwrap()
        .modified()
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    a.cycle();
    assert_eq!(
        std::fs::metadata(maj.join("barbacane-maj-200.bcu"))
            .unwrap()
            .modified()
            .unwrap(),
        avant
    );

    // admind rend le résultat (application décidée par l'administrateur) → rapport au serveur.
    std::fs::write(
        maj.join("resultat.json"),
        r#"{"version_maj":200,"resultat":"appliquee"}"#,
    )
    .unwrap();
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    assert_eq!(suivi(&b, &uuid), Some(EtatMajBorne::Appliquee));
    assert_eq!(std::fs::read_dir(&maj).unwrap().count(), 0, "dossier soldé");
    assert_eq!(etat_publie(&a).mise_a_jour, None);
    // Plus proposée : plus rien n'est téléchargé.
    a.cycle();
    assert_eq!(std::fs::read_dir(&maj).unwrap().count(), 0);
}

#[test]
fn paquet_altere_sur_le_serveur_ecarte() {
    let b = banc();
    let mut a = agent(&b);
    let uuid = enroler(&b, &mut a, maintenant());
    diffuser(&b, 200);
    // Paquet modifié sur le serveur après le dépôt (empreinte annoncée = celle du dépôt).
    let stocke = b.config.registre.join("maj/paquets/barbacane-maj-200.bcu");
    let mut o = std::fs::read(&stocke).unwrap();
    let n = o.len();
    o[n / 2] ^= 1;
    std::fs::write(&stocke, o).unwrap();
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee);
    assert!(a.etat.message.contains("empreinte"), "{}", a.etat.message);
    let maj = a.config.etat.join("maj");
    assert!(!maj.join("annonce.json").exists());
    assert!(!maj.join("barbacane-maj-200.bcu").exists());
    assert!(!maj.join(".reception").exists());
    assert_eq!(etat_publie(&a).mise_a_jour, None);
    let _ = uuid;
}

/// Rapport de passage tel qu'admind le dépose (aucun nom de fichier).
fn passage(id: &str) -> Vec<u8> {
    use barbacane_protocole::passage::{FichierPassage, RapportPassage, Verdict};
    barbacane_protocole::encoder(&RapportPassage {
        version: barbacane_protocole::VERSION,
        id: id.into(),
        horodatage: maintenant(),
        verdict: Verdict::Sain,
        support: "d".repeat(64),
        partie: 1,
        parties: 1,
        fichiers: vec![FichierPassage {
            taille: 3,
            sha256: "e".repeat(64),
            verdict: Verdict::Sain,
        }],
    })
    .unwrap()
}

#[test]
fn rapports_de_passage_envoyes_rejoues_retires_apres_200() {
    use barbacane_passerelle::passages::Passages;
    let b = banc();
    let mut a = agent(&b);
    let uuid = enroler(&b, &mut a, maintenant());
    const ID1: &str = "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";
    const ID2: &str = "2c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";
    assert!(
        a.file()
            .ajouter(&format!("0001-{ID1}-0001"), &passage(ID1))
            .unwrap()
    );
    // Coupure : serveur injoignable → rien n'est retiré.
    let ferme = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let c = config_agent(&b, &b.pki.join("ca-serveur/cert.pem"), ferme);
    let mut hors = Agent::nouveau(c.clone(), CoffreFichier::nouveau(&c.etat)).unwrap();
    hors.cycle();
    assert_eq!(hors.etat.mode, Mode::Degradee);
    assert_eq!((hors.file().len(), hors.etat.rapports_en_attente), (1, 1));
    // Retour du serveur : envoyé puis retiré après 200.
    let mut a = agent(&b);
    a.cycle();
    assert_eq!(a.etat.mode, Mode::Connectee, "{}", a.etat.message);
    assert!(a.file().is_empty(), "{}", a.etat.message);
    let p = Passages::ouvrir(&b.admin.stockage).unwrap();
    assert_eq!(p.derniers(10).unwrap().len(), 1);
    assert_eq!(p.derniers(10).unwrap()[0].borne, uuid);
    // Rejeu (accusé perdu avant le retrait) : 200, pas de doublon côté serveur.
    assert!(
        a.file()
            .ajouter(&format!("0002-{ID1}-0001"), &passage(ID1))
            .unwrap()
    );
    // Élément non conforme au schéma (nom ajouté) : mis de côté, jamais envoyé.
    let mut v: serde_json::Value = serde_json::from_slice(&passage(ID2)).unwrap();
    v["fichiers"][0]["nom"] = "secret.docx".into();
    assert!(
        a.file()
            .ajouter(
                &format!("0003-{ID2}-0001"),
                &serde_json::to_vec(&v).unwrap()
            )
            .unwrap()
    );
    assert_eq!(a.transmettre_passages().unwrap(), 1);
    assert!(a.file().is_empty());
    assert_eq!(p.derniers(10).unwrap().len(), 1, "idempotent");
    assert!(
        a.config
            .etat
            .join(format!("rejet-0003-{ID2}-0001.json"))
            .exists()
    );
    let audit = String::from_utf8(b.admin.stockage.journal_audit().lire().unwrap()).unwrap();
    assert_eq!(audit.matches("\"rapport_passage\"").count(), 1);
    assert!(!audit.contains("secret"));
}

#[test]
fn file_pleine_borne_hors_service() {
    let b = banc();
    let mut c = config_agent(&b, &b.pki.join("ca-serveur/cert.pem"), 1);
    c.file_max = 1;
    let a = Agent::nouveau(c.clone(), CoffreFichier::nouveau(&c.etat)).unwrap();
    const ID: &str = "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11";
    assert!(
        a.file()
            .ajouter(&format!("0001-{ID}-0001"), &passage(ID))
            .unwrap()
    );
    assert!(a.file().pleine());
    assert!(
        !a.file()
            .ajouter(&format!("0002-{ID}-0001"), &passage(ID))
            .unwrap()
    );
}
