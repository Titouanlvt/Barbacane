//! Preuves des segments scellés (v2.3.0) : rotation quotidienne, ancre signée, purge des
//! segments hors durée puis vérification de la chaîne restante, altérations détectées,
//! rotation interrompue, purge refusée sur une chaîne altérée, commande `conservation`.

use std::process::Command;

use barbacane_audit::conservation::Reglage;
use barbacane_audit::{
    CleAudit, Defaut, Enregistrement, Evenement, Journal, VERSION_SCHEMA, empreinte_initiale,
    lire_export, texte_export,
};

const JOUR: u64 = 86400;
const T0: u64 = 1_795_000_000; // 18/11/2026

fn ev(i: u64) -> Evenement {
    Evenement::MajProposee {
        borne: format!("borne-{i}"),
        version_maj: 202611200000 + i,
    }
}

struct Banc {
    d: tempfile::TempDir,
    j: Journal,
    cle: CleAudit,
}

fn banc() -> Banc {
    let d = tempfile::tempdir().unwrap();
    let j = Journal::new(d.path().join("audit.jsonl"));
    let cle = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    Banc { d, j, cle }
}

/// 3 jours de 3 événements, rotation chaque matin : segments des jours 0 et 1 rangés, jour 2
/// actif.
fn trois_jours(b: &Banc) {
    for jour in 0..3 {
        let t = T0 + jour * JOUR;
        if jour > 0 {
            assert!(b.j.tourner(&b.cle, t, false).unwrap().is_some());
            // Une seule rotation par jour.
            assert_eq!(b.j.tourner(&b.cle, t + 10, false).unwrap(), None);
        }
        for i in 0..3 {
            b.j.ajouter(t + 100 + i, "passerelle", ev(jour * 10 + i))
                .unwrap();
        }
    }
}

fn defaut(e: anyhow::Error) -> Defaut {
    e.downcast::<Defaut>().expect("défaut de la chaîne attendu")
}

#[test]
fn rotation_ancre_et_verification() {
    let b = banc();
    assert_eq!(
        b.j.tourner(&b.cle, T0, false).unwrap(),
        None,
        "journal vide"
    );
    trois_jours(&b);
    let seg = b.j.segments().unwrap();
    assert_eq!(seg.len(), 2);
    // Jour 0 : 3 événements + point (4) ; jour 1 : ancre (5), 3 événements, point (9) ;
    // actif : ancre (10) + 3 événements.
    assert_eq!(seg.iter().map(|s| s.0).collect::<Vec<_>>(), [1, 5]);
    let actif = b.j.lire().unwrap();
    let premiere = Enregistrement::analyser(actif.split(|o| *o == b'\n').next().unwrap()).unwrap();
    assert_eq!(premiere.n, 10);
    assert_eq!(premiere.v, VERSION_SCHEMA);
    assert!(matches!(
        premiere.evenement,
        Evenement::SegmentOuvert { precedent: 9, .. }
    ));
    let bilan = b.j.verifier_tout(&b.cle.publique(), &[]).unwrap();
    assert_eq!(
        (bilan.premier, bilan.dernier, bilan.enregistrements),
        (1, 13, 13)
    );
    assert_eq!((bilan.segments, bilan.purges), (3, 0));
    assert_eq!(bilan.points.iter().map(|p| p.n).collect::<Vec<_>>(), [4, 9]);
    // Le scellement du journal actif part de la fin du segment précédent.
    assert_eq!(b.j.sceller(&b.cle, T0 + 2 * JOUR + 500).unwrap(), 14);
    assert_eq!(
        b.j.verifier_tout(&b.cle.publique(), &[])
            .unwrap()
            .non_scelles,
        0
    );
    // Une ouverture de segment ne s'écrit jamais par « ajouter ».
    assert!(
        b.j.ajouter(
            T0,
            "passerelle",
            Evenement::SegmentPurge {
                premier: 1,
                dernier: 4,
                empreinte: "0".repeat(96)
            }
        )
        .is_err()
    );
}

#[test]
fn purge_puis_chaine_restante_verifiee() {
    let b = banc();
    trois_jours(&b);
    let pub_ = b.cle.publique();
    let export = lire_export(&texte_export(&b.j.verifier_tout(&pub_, &[]).unwrap(), T0)).unwrap();
    // Limite entre le jour 0 et le jour 1 : seul le segment du jour 0 est purgé.
    let t = T0 + 2 * JOUR + 1000;
    let p =
        b.j.purger_segments(&pub_, t, T0 + JOUR, "conservation")
            .unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].premier, p[0].dernier), (1, 4));
    assert_eq!(b.j.segments().unwrap().len(), 1);
    let bilan = b.j.verifier_tout(&pub_, &export).unwrap();
    assert_eq!(
        bilan.premier, 5,
        "vérification depuis l'ancre du segment n° 5"
    );
    assert_eq!(bilan.purges, 4);
    assert_eq!(
        bilan.exports_purges, 1,
        "point n° 4 exporté puis purgé : compté, pas refusé"
    );
    // La purge est tracée dans la chaîne (avant la suppression).
    let actif = String::from_utf8(b.j.lire().unwrap()).unwrap();
    assert!(
        actif.contains("\"segment_purge\":{\"premier\":1,\"dernier\":4"),
        "{actif}"
    );
    assert!(actif.contains("\"acteur\":\"conservation\""));
    // Rien de plus à purger avec la même limite ; le journal actif n'est jamais purgé.
    assert!(
        b.j.purger_segments(&pub_, t, T0 + JOUR, "conservation")
            .unwrap()
            .is_empty()
    );
    let p =
        b.j.purger_segments(&pub_, t, t + 10 * JOUR, "conservation")
            .unwrap();
    assert_eq!(p.len(), 1, "segment du jour 1 seulement");
    assert!(b.j.lire().unwrap().len() > 100);
    let bilan = b.j.verifier_tout(&pub_, &[]).unwrap();
    assert_eq!((bilan.premier, bilan.segments), (10, 1));
}

#[test]
fn alterations_des_segments_detectees() {
    // Suppression d'un segment du MILIEU (seuls les plus anciens se purgent).
    let b = banc();
    trois_jours(&b);
    std::fs::remove_file(&b.j.segments().unwrap()[1].1).unwrap();
    assert!(matches!(
        defaut(b.j.verifier_tout(&b.cle.publique(), &[]).unwrap_err()),
        Defaut::Ancre { ligne: 10, .. }
    ));
    // Segment renommé (premier numéro ne correspondant plus au contenu).
    let b = banc();
    trois_jours(&b);
    let s = b.j.segments().unwrap();
    std::fs::rename(&s[1].1, s[1].1.with_file_name("00000000000000000006.jsonl")).unwrap();
    assert!(matches!(
        defaut(b.j.verifier_tout(&b.cle.publique(), &[]).unwrap_err()),
        Defaut::Segment { .. }
    ));
    // Modification d'une ligne d'un segment.
    let b = banc();
    trois_jours(&b);
    let s = b.j.segments().unwrap();
    let t = std::fs::read_to_string(&s[1].1).unwrap();
    std::fs::write(&s[1].1, t.replacen("borne-10", "borne-99", 1)).unwrap();
    assert!(b.j.verifier_tout(&b.cle.publique(), &[]).is_err());
    // Effacement du début sans la clé : un attaquant supprime le segment 1 et fabrique une
    // ancre pour le segment 2 avec SA clé → refus (clé d'audit inconnue).
    let b = banc();
    trois_jours(&b);
    let autre = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    let c = banc();
    // Chaîne fabriquée de bout en bout avec une autre clé, même forme.
    trois_jours(&Banc {
        d: tempfile::tempdir().unwrap(),
        j: c.j.clone(),
        cle: autre,
    });
    std::fs::remove_file(&c.j.segments().unwrap()[0].1).unwrap();
    assert!(matches!(
        defaut(c.j.verifier_tout(&b.cle.publique(), &[]).unwrap_err()),
        Defaut::Ancre {
            cause: "clé d'audit inconnue",
            ..
        }
    ));
    drop(c.d);
    // Ancre déplacée au milieu d'un segment : refus.
    let b = banc();
    trois_jours(&b);
    let s = b.j.segments().unwrap();
    let t = std::fs::read_to_string(&s[1].1).unwrap();
    let mut l: Vec<&str> = t.lines().collect();
    l.swap(0, 1);
    std::fs::write(&s[1].1, l.join("\n") + "\n").unwrap();
    assert!(b.j.verifier_tout(&b.cle.publique(), &[]).is_err());
}

#[test]
fn purge_refusee_sur_chaine_alteree() {
    let b = banc();
    trois_jours(&b);
    let s = b.j.segments().unwrap();
    let t = std::fs::read_to_string(&s[1].1).unwrap();
    std::fs::write(&s[1].1, t.replacen("borne-11", "borne-12", 1)).unwrap();
    assert!(
        b.j.purger_segments(
            &b.cle.publique(),
            T0 + 9 * JOUR,
            T0 + 9 * JOUR,
            "conservation"
        )
        .is_err()
    );
    assert_eq!(b.j.segments().unwrap().len(), 2, "rien supprimé");
    assert!(
        b.j.tourner(&b.cle, T0 + 9 * JOUR, false).is_err(),
        "pas de rotation non plus"
    );
}

#[test]
fn rotation_interrompue() {
    let b = banc();
    trois_jours(&b);
    // Interruption entre le rangement du segment et la mise en place du nouveau journal.
    let actif = b.j.chemin().to_owned();
    let nouveau = actif.with_file_name("audit.jsonl.nouveau");
    std::fs::rename(&actif, &nouveau).unwrap();
    b.j.ajouter(T0 + 3 * JOUR, "passerelle", ev(99)).unwrap();
    assert!(!nouveau.exists());
    b.j.verifier_tout(&b.cle.publique(), &[]).unwrap();
    // Journal actif disparu sans « .nouveau » : jamais recréé vide.
    std::fs::remove_file(&actif).unwrap();
    assert!(b.j.ajouter(T0 + 3 * JOUR, "passerelle", ev(98)).is_err());
    assert!(!actif.exists());
    assert!(b.j.verifier_tout(&b.cle.publique(), &[]).is_err());
}

#[test]
fn version_1_lue_version_2_exigee_pour_les_nouveautes() {
    let e = |v, evenement| {
        serde_json::to_vec(&Enregistrement {
            v,
            n: 1,
            le: 5,
            acteur: "conservation".into(),
            evenement,
            prec: empreinte_initiale(),
        })
        .unwrap()
    };
    assert!(
        Enregistrement::analyser(&e(1, ev(1))).is_ok(),
        "journal 2.2.0 relu"
    );
    let purge = Evenement::Purge {
        objet: barbacane_audit::ObjetPurge::Passages,
        nombre: 3,
        avant: 4,
    };
    assert!(Enregistrement::analyser(&e(2, purge.clone())).is_ok());
    assert!(Enregistrement::analyser(&e(1, purge)).is_err());
    assert!(Enregistrement::analyser(&e(3, ev(1))).is_err());
}

#[test]
fn commande_conservation() {
    let exe = env!("CARGO_BIN_EXE_barbacane-audit");
    let b = banc();
    let reg = b.d.path();
    let cle = reg.join("cles");
    assert!(
        Command::new(exe)
            .arg("cle")
            .arg(&cle)
            .status()
            .unwrap()
            .success()
    );
    let cle_audit = CleAudit::lire(&cle.join("cle-audit.pem")).unwrap();
    let journal = b.j.chemin();
    // Journal « ancien » de 400 jours, puis un événement d'aujourd'hui dans un autre segment.
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    b.j.ajouter(maintenant - 400 * JOUR, "passerelle", ev(1))
        .unwrap();
    b.j.tourner(&cle_audit, maintenant - 399 * JOUR, false)
        .unwrap()
        .unwrap();
    b.j.ajouter(maintenant - 10 * JOUR, "passerelle", ev(2))
        .unwrap();
    let lancer = |args: &[&std::ffi::OsStr]| {
        let s = Command::new(exe).args(args).output().unwrap();
        (
            s.status.code(),
            String::from_utf8_lossy(&s.stdout).into_owned() + &String::from_utf8_lossy(&s.stderr),
        )
    };
    let os = |s: &str| std::ffi::OsString::from(s);
    let args = [
        os("conservation"),
        journal.into(),
        cle.join("cle-audit.pem").into(),
        reg.into(),
    ];
    let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
    // Sans réglage : rotation et scellement, aucune purge.
    let (c, o) = lancer(&refs);
    assert_eq!(c, Some(0), "{o}");
    assert!(o.contains("aucune purge"), "{o}");
    assert_eq!(b.j.segments().unwrap().len(), 2);
    // Réglage en préavis (migration) : aucune purge.
    let r = Reglage::initial(maintenant, "migration-2.2.0");
    std::fs::write(
        reg.join("conservation.json"),
        serde_json::to_vec(&r).unwrap(),
    )
    .unwrap();
    let (c, o) = lancer(&refs);
    assert_eq!(c, Some(0), "{o}");
    assert!(o.contains("préavis"), "{o}");
    let (c, o) = lancer(&[os("conservation-jours").as_os_str(), reg.as_os_str()]);
    assert_eq!((c, o.trim()), (Some(0), "aucune"));
    // Préavis écoulé : le segment de plus de 365 jours est purgé, la chaîne reste vérifiable.
    let mut r = r;
    r.effective_le = maintenant - 1;
    std::fs::write(
        reg.join("conservation.json"),
        serde_json::to_vec(&r).unwrap(),
    )
    .unwrap();
    let (c, o) = lancer(&refs);
    assert_eq!(c, Some(0), "{o}");
    assert!(o.contains("1 segment(s) purgé(s)"), "{o}");
    let (c, o) = lancer(&[os("conservation-jours").as_os_str(), reg.as_os_str()]);
    assert_eq!((c, o.trim()), (Some(0), "365"));
    let (c, o) = lancer(&[
        os("verifier").as_os_str(),
        journal.as_os_str(),
        cle.join("cle-audit.pub").as_os_str(),
    ]);
    assert_eq!(c, Some(0), "{o}");
    assert!(o.contains("purgés (conservation)"), "{o}");
    // Format structuré de tout le journal : une ligne JSON par enregistrement.
    let s = Command::new(exe)
        .arg("structurer")
        .arg(journal)
        .arg("srv-test")
        .output()
        .unwrap();
    assert!(s.status.success());
    let texte = String::from_utf8(s.stdout).unwrap();
    for l in texte.lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["serveur"], "srv-test");
    }
    assert!(texte.contains("\"type\":\"segment_purge\""), "{texte}");
    // Réglage altéré (hors bornes) : refus, rien n'est purgé.
    std::fs::write(
        reg.join("conservation.json"),
        br#"{"version":1,"jours":3,"precedent":null,"effective_le":0,"regle_le":0,"par":"x"}"#,
    )
    .unwrap();
    let (c, _) = lancer(&refs);
    assert_eq!(c, Some(1));
    // Altération d'un segment : verifier → code 2.
    let s = b.j.segments().unwrap();
    let t = std::fs::read_to_string(&s[0].1).unwrap();
    std::fs::write(&s[0].1, t.replacen("borne-2", "borne-3", 1)).unwrap();
    let (c, o) = lancer(&[
        os("verifier").as_os_str(),
        journal.as_os_str(),
        cle.join("cle-audit.pub").as_os_str(),
    ]);
    assert_eq!(c, Some(2), "{o}");
}
