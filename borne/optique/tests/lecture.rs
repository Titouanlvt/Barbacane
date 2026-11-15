//! Lecture d'images ISO construites ici (xorriso requis) : multisession avec un fichier EICAR
//! présent dans la seule PREMIÈRE session (supprimé dans la seconde), Joliet et Rock Ridge.

use barbacane_optique::ops;
use barbacane_optique::outil::Outil;
use std::path::Path;
use std::process::Command;

const EICAR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn xorriso_present() -> bool {
    Command::new("xorriso").arg("-version").output().is_ok()
}

fn x(args: &[&str]) {
    let st = Command::new("xorriso").args(args).output().unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
}

/// Image en deux sessions : la 1re contient sain.txt et cache/eicar.com ; la 2e supprime
/// cache/eicar.com et ajoute nouveau.txt (une lecture « normale » ne voit plus l'EICAR).
fn image_multisession(dir: &Path) -> std::path::PathBuf {
    let img = dir.join("multi.iso");
    let s1 = dir.join("s1");
    std::fs::create_dir_all(s1.join("cache")).unwrap();
    std::fs::write(s1.join("sain.txt"), "contenu sain\n").unwrap();
    std::fs::write(s1.join("cache/eicar.com"), EICAR).unwrap();
    std::fs::write(s1.join("Nom long accentué été.txt"), "joliet\n").unwrap();
    let (img_s, s1_s) = (img.to_str().unwrap(), s1.to_str().unwrap());
    x(&[
        "-outdev", img_s, "-joliet", "on", "-volid", "ANCIENNE", "-map", s1_s, "/", "-close",
        "off", "-commit",
    ]);
    let n = dir.join("nouveau.txt");
    std::fs::write(&n, "seconde session\n").unwrap();
    x(&[
        "-dev",
        img_s,
        "-volid",
        "RECENTE",
        "-rm_r",
        "/cache",
        "--",
        "-map",
        n.to_str().unwrap(),
        "/nouveau.txt",
        "-commit",
    ]);
    img
}

fn outil(img: &Path, confine: bool) -> Outil {
    let mut o = Outil::new(img);
    o.xorriso = "xorriso".into();
    if !confine {
        o.bwrap = None;
    } else {
        o.bwrap = Some(
            String::from_utf8(
                Command::new("sh")
                    .args(["-c", "command -v bwrap"])
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
            .trim()
            .into(),
        );
    }
    o
}

fn lecture(confine: bool) {
    if !xorriso_present() {
        eprintln!("xorriso absent : test ignoré");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let img = image_multisession(t.path());
    let o = outil(&img, confine);
    let (m, _) = ops::identifier(&o).unwrap();
    assert_eq!(m.data_sessions().count(), 2, "{m:?}");
    let dest = t.path().join("entree");
    let n = ops::lire(&o, &dest, &mut |_, _| ()).unwrap();
    let h = ops::empreintes(&dest).unwrap();
    // L'EICAR effacé dans la 2e session est retrouvé dans la 1re : il sera analysé.
    assert!(h.contains_key("session-1/cache/eicar.com"), "{h:?}");
    assert!(!h.contains_key("session-2/cache/eicar.com"));
    assert!(h.contains_key("session-2/nouveau.txt"));
    assert!(
        h.contains_key("session-1/Nom long accentué été.txt"),
        "{h:?}"
    );
    assert!(n >= 5);
}

#[test]
fn toutes_les_sessions_sans_bac_a_sable() {
    lecture(false);
}

#[test]
fn toutes_les_sessions_dans_le_bac_a_sable() {
    if Command::new("sh")
        .args(["-c", "command -v bwrap"])
        .output()
        .map(|o| o.stdout.is_empty())
        .unwrap_or(true)
    {
        eprintln!("bwrap absent : test ignoré");
        return;
    }
    lecture(true);
}

#[test]
fn dossier_d_extraction_non_vide_refuse() {
    if !xorriso_present() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let img = image_multisession(t.path());
    let dest = t.path().join("entree");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("reste"), "x").unwrap();
    assert!(ops::lire(&outil(&img, false), &dest, &mut |_, _| ()).is_err());
}

#[test]
fn image_sans_donnees_refusee() {
    if !xorriso_present() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let img = t.path().join("vide.bin");
    std::fs::write(&img, vec![0u8; 4 << 20]).unwrap();
    let e = ops::lire(&outil(&img, false), &t.path().join("e"), &mut |_, _| ()).unwrap_err();
    assert!(
        e.to_string().contains("vierge") || e.to_string().contains("illisible"),
        "{e}"
    );
}

#[test]
fn comparaison_apres_gravure() {
    use std::collections::BTreeMap;
    let a: BTreeMap<_, _> = [("a".to_string(), "1".to_string()), ("b".into(), "2".into())].into();
    assert!(ops::comparer(&a, &a.clone()).is_ok());
    let mut b = a.clone();
    b.insert("b".into(), "3".into());
    assert!(
        ops::comparer(&a, &b)
            .unwrap_err()
            .to_string()
            .contains("b différent")
    );
    let mut c = a.clone();
    c.remove("a");
    c.insert("z".into(), "9".into());
    let e = ops::comparer(&a, &c).unwrap_err().to_string();
    assert!(e.contains("a absent") && e.contains("z inattendu"), "{e}");
}
