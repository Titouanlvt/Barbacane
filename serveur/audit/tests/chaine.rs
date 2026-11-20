//! Preuves du journal d'audit chaîné : modification, suppression, réordonnancement,
//! rechaînage complet sans la clé, troncature (avec export), écriture interrompue.

use std::process::Command;

use barbacane_audit::{
    CleAudit, Defaut, Enregistrement, Evenement, Journal, empreinte, lire_export, texte_export,
    verifier,
};

struct Banc {
    _d: tempfile::TempDir,
    journal: Journal,
    cle: CleAudit,
}

fn ev(i: u64) -> Evenement {
    Evenement::MajProposee {
        borne: format!("borne-{i}"),
        version_maj: 202611200000 + i,
    }
}

/// 4 événements, point (5), 3 événements, point (9), 1 événement non scellé (10).
fn banc() -> Banc {
    let d = tempfile::tempdir().unwrap();
    let journal = Journal::new(d.path().join("audit.jsonl"));
    let cle = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    for i in 1..=4 {
        journal.ajouter(1000 + i, "passerelle", ev(i)).unwrap();
    }
    assert_eq!(journal.sceller(&cle, 1005).unwrap(), 5);
    for i in 6..=8 {
        journal.ajouter(1000 + i, "admin:uid-0", ev(i)).unwrap();
    }
    assert_eq!(journal.sceller(&cle, 1009).unwrap(), 9);
    journal.ajouter(1010, "passerelle", ev(10)).unwrap();
    Banc {
        _d: d,
        journal,
        cle,
    }
}

fn lignes(b: &Banc) -> Vec<Vec<u8>> {
    let c = b.journal.lire().unwrap();
    c.strip_suffix(b"\n")
        .unwrap()
        .split(|o| *o == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn joindre(l: &[Vec<u8>]) -> Vec<u8> {
    let mut v = l.join(&b'\n');
    v.push(b'\n');
    v
}

#[test]
fn journal_intact_verifie() {
    let b = banc();
    let bilan = verifier(&b.journal.lire().unwrap(), &b.cle.publique(), &[]).unwrap();
    assert_eq!(bilan.enregistrements, 10);
    assert_eq!(bilan.points.iter().map(|p| p.n).collect::<Vec<_>>(), [5, 9]);
    assert_eq!(bilan.non_scelles, 1);
    // Un point de contrôle ne s'écrit que par « sceller ».
    assert!(
        b.journal
            .ajouter(
                1,
                "passerelle",
                Evenement::PointDeControle {
                    jusqua: 1,
                    empreinte: "0".repeat(96),
                    cle: "0".repeat(16),
                    signature: "0".repeat(192),
                }
            )
            .is_err()
    );
}

#[test]
fn modification_detectee() {
    let b = banc();
    let mut l = lignes(&b);
    // Ligne 3 : la borne visée est changée (forme valide, chaînage cassé à la ligne 4).
    l[2] = String::from_utf8(l[2].clone())
        .unwrap()
        .replace("borne-3", "borne-9")
        .into_bytes();
    assert_eq!(
        verifier(&joindre(&l), &b.cle.publique(), &[]),
        Err(Defaut::Chainage { ligne: 4 })
    );
    // Dernière ligne avant un point modifiée : c'est le point de contrôle qui la protège.
    let mut l = lignes(&b);
    l[7] = String::from_utf8(l[7].clone())
        .unwrap()
        .replace("borne-8", "borne-7")
        .into_bytes();
    assert_eq!(
        verifier(&joindre(&l), &b.cle.publique(), &[]),
        Err(Defaut::Chainage { ligne: 9 })
    );
}

#[test]
fn suppression_detectee() {
    let b = banc();
    let mut l = lignes(&b);
    l.remove(5);
    assert_eq!(
        verifier(&joindre(&l), &b.cle.publique(), &[]),
        Err(Defaut::Numero {
            ligne: 6,
            trouve: 7
        })
    );
}

#[test]
fn reordonnancement_detecte() {
    let b = banc();
    let mut l = lignes(&b);
    l.swap(1, 2);
    assert_eq!(
        verifier(&joindre(&l), &b.cle.publique(), &[]),
        Err(Defaut::Numero {
            ligne: 2,
            trouve: 3
        })
    );
}

/// Un attaquant sans la clé d'audit supprime la ligne 3 puis recalcule numéros et chaînage :
/// la signature du point de contrôle ne correspond plus.
#[test]
fn rechainage_sans_cle_detecte() {
    let b = banc();
    let mut l = lignes(&b);
    l.remove(2);
    let mut prec = "0".repeat(96);
    let mut refaites = Vec::new();
    for (i, ligne) in l.iter().enumerate() {
        let mut e = Enregistrement::analyser(ligne).unwrap();
        e.n = i as u64 + 1;
        e.prec = prec.clone();
        if let Evenement::PointDeControle {
            jusqua, empreinte, ..
        } = &mut e.evenement
        {
            *jusqua = i as u64;
            *empreinte = prec.clone();
        }
        let o = serde_json::to_vec(&e).unwrap();
        prec = empreinte(&o);
        refaites.push(o);
    }
    assert_eq!(
        verifier(&joindre(&refaites), &b.cle.publique(), &[]),
        Err(Defaut::PointDeControle {
            ligne: 4,
            cause: "signature invalide"
        })
    );
}

/// Troncature : sans export elle n'est pas visible ; avec l'export du jour, elle l'est.
/// Réécriture complète re-signée avec une AUTRE clé : refusée par la clé publique, et l'export
/// la révèle même si l'attaquant a aussi volé la vraie clé.
#[test]
fn troncature_et_reecriture_detectees_par_export() {
    let b = banc();
    let bilan = verifier(&b.journal.lire().unwrap(), &b.cle.publique(), &[]).unwrap();
    let export = lire_export(&texte_export(&bilan, 2000)).unwrap();
    assert_eq!(export.len(), 2);
    let l = lignes(&b);
    let tronque = joindre(&l[..6]);
    assert!(verifier(&tronque, &b.cle.publique(), &[]).is_ok());
    assert_eq!(
        verifier(&tronque, &b.cle.publique(), &export),
        Err(Defaut::Export {
            point: 9,
            cause: "absent : journal tronqué"
        })
    );
    // Réécriture complète avec la vraie clé (volée) : événements différents.
    let d = tempfile::tempdir().unwrap();
    let faux = Journal::new(d.path().join("faux.jsonl"));
    for i in 1..=4 {
        faux.ajouter(1000 + i, "passerelle", ev(i + 100)).unwrap();
    }
    faux.sceller(&b.cle, 1005).unwrap();
    let contenu = faux.lire().unwrap();
    assert!(verifier(&contenu, &b.cle.publique(), &[]).is_ok());
    assert!(matches!(
        verifier(&contenu, &b.cle.publique(), &export[..1]),
        Err(Defaut::Export { point: 5, .. })
    ));
    // Clé d'un autre : refusée.
    let autre = CleAudit::depuis_pem(&CleAudit::generer().unwrap()).unwrap();
    assert!(matches!(
        verifier(&contenu, &autre.publique(), &[]),
        Err(Defaut::PointDeControle {
            cause: "clé d'audit inconnue",
            ..
        })
    ));
}

#[test]
fn ecriture_interrompue_bloque_l_ajout_et_le_scellement() {
    let b = banc();
    let mut c = b.journal.lire().unwrap();
    c.truncate(c.len() - 10);
    std::fs::write(b.journal.chemin(), &c).unwrap();
    assert_eq!(
        verifier(&c, &b.cle.publique(), &[]),
        Err(Defaut::FinIncomplete)
    );
    assert!(b.journal.ajouter(1, "passerelle", ev(1)).is_err());
    assert!(b.journal.sceller(&b.cle, 1).is_err());
}

/// Commande : clé, scellement, export, vérification (code 2 si altéré), clé trop ouverte.
#[test]
fn commande_barbacane_audit() {
    let exe = env!("CARGO_BIN_EXE_barbacane-audit");
    let d = tempfile::tempdir().unwrap();
    let cles = d.path().join("cles");
    let ok = |args: &[&std::ffi::OsStr]| {
        let s = Command::new(exe).args(args).output().unwrap();
        assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
        String::from_utf8(s.stdout).unwrap()
    };
    ok(&["cle".as_ref(), cles.as_os_str()]);
    let journal = d.path().join("audit.jsonl");
    let j = Journal::new(&journal);
    j.ajouter(1, "passerelle", ev(1)).unwrap();
    let pem = cles.join("cle-audit.pem");
    let publique = cles.join("cle-audit.pub");
    ok(&["sceller".as_ref(), journal.as_os_str(), pem.as_os_str()]);
    let sortie = ok(&[
        "exporter".as_ref(),
        journal.as_os_str(),
        publique.as_os_str(),
        d.path().as_os_str(),
    ]);
    assert!(sortie.contains("1 points de contrôle"), "{sortie}");
    let export = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().contains("empreintes-audit-"))
        .unwrap();
    ok(&[
        "verifier".as_ref(),
        journal.as_os_str(),
        publique.as_os_str(),
        export.as_os_str(),
    ]);
    // Altération : code 2.
    let texte = std::fs::read_to_string(&journal)
        .unwrap()
        .replace("borne-1", "borne-2");
    std::fs::write(&journal, texte).unwrap();
    let s = Command::new(exe)
        .args([journal.as_os_str(), publique.as_os_str()])
        .arg("x")
        .output()
        .unwrap();
    assert_eq!(s.status.code(), Some(1), "usage invalide");
    let s = Command::new(exe)
        .arg("verifier")
        .args([
            journal.as_os_str(),
            publique.as_os_str(),
            export.as_os_str(),
        ])
        .output()
        .unwrap();
    assert_eq!(s.status.code(), Some(2));
    // Clé privée lisible par d'autres comptes : refusée.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(CleAudit::lire(&pem).is_err());
}
