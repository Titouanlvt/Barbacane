//! Palette de la charte v2 générée depuis `docs/charte/jetons.toml` (source unique, produite par
//! `docs/charte/outils/jetons.py` depuis `tokens.json`). Aucune dépendance de construction : le
//! fichier n'a que des lignes `nom = "#rrggbb[aa]"` sous `[couleur.jour]` et `[couleur.nuit]`.
use std::fmt::Write as _;
use std::{env, fs, path::Path};

fn main() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/charte/jetons.toml");
    println!("cargo:rerun-if-changed={}", src.display());
    let texte = fs::read_to_string(&src).expect("docs/charte/jetons.toml illisible");
    let mut themes: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut courant: Option<usize> = None;
    for ligne in texte.lines().map(str::trim) {
        if let Some(t) = ligne.strip_prefix("[couleur.").and_then(|l| l.strip_suffix(']')) {
            themes.push((t.to_string(), Vec::new()));
            courant = Some(themes.len() - 1);
        } else if ligne.starts_with('[') {
            courant = None;
        } else if let (Some(i), Some((nom, val))) = (courant, ligne.split_once('=')) {
            let val = val.trim().trim_matches('"');
            assert!(val.starts_with('#') && (val.len() == 7 || val.len() == 9), "couleur invalide : {ligne}");
            themes[i].1.push((nom.trim().to_string(), val.to_string()));
        }
    }
    let noms: Vec<&String> = themes.first().expect("aucun thème").1.iter().map(|(n, _)| n).collect();
    for (t, v) in &themes {
        let n: Vec<&String> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(n, noms, "le thème {t} n'a pas les mêmes jetons que le premier");
    }
    let champ = |n: &str| if n == "trait" { "trait_".to_string() } else { n.to_string() };
    let mut o = String::from("/// Jetons de couleur de la charte v2 (générés depuis docs/charte/jetons.toml).\n");
    o.push_str("#[derive(Debug, Clone, Copy)]\npub struct Palette {\n");
    for n in &noms {
        writeln!(o, "    pub {}: Color,", champ(n)).unwrap();
    }
    o.push_str("}\n");
    for (t, v) in &themes {
        writeln!(o, "pub const {}: Palette = Palette {{", t.to_uppercase()).unwrap();
        for (n, val) in v {
            let h = u32::from_str_radix(&val[1..7], 16).unwrap();
            let a = if val.len() == 9 { u8::from_str_radix(&val[7..9], 16).unwrap() } else { 255 };
            writeln!(o, "    {}: hexa(0x{h:06X}, {a}),", champ(n)).unwrap();
        }
        o.push_str("};\n");
    }
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("jetons.rs"), o).unwrap();
}
