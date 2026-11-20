//! Outil du journal d'audit (compte dédié, jamais celui de la passerelle).
//!
//! ```text
//! barbacane-audit cle DOSSIER                          clé d'audit P-384 (cle-audit.pem 0600, cle-audit.pub)
//! barbacane-audit sceller JOURNAL CLE_PRIVEE           vérifie la chaîne puis ajoute un point de contrôle signé
//! barbacane-audit verifier JOURNAL CLE_PUBLIQUE [EXPORT…]   code 0 intègre, 2 altéré
//! barbacane-audit exporter JOURNAL CLE_PUBLIQUE DOSSIER     empreintes des points (à sortir du serveur)
//! ```
#![forbid(unsafe_code)]

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use barbacane_audit::{
    CleAudit, ClePublique, Journal, date_utc, lire_export, texte_export, verifier,
};

const USAGE: &str = "usage : barbacane-audit (cle DOSSIER | sceller JOURNAL CLE_PRIVEE | verifier JOURNAL CLE_PUBLIQUE [EXPORT…] | exporter JOURNAL CLE_PUBLIQUE DOSSIER)";

fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Création exclusive (jamais d'écrasement).
fn creer(chemin: &Path, mode: u32, contenu: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(chemin)
        .with_context(|| format!("création de {} (existe déjà ?)", chemin.display()))?;
    f.write_all(contenu.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn executer(args: &[String]) -> Result<ExitCode> {
    match args {
        [c, dossier] if c == "cle" => {
            let d = PathBuf::from(dossier);
            std::fs::create_dir_all(&d)?;
            let pem = CleAudit::generer()?;
            let publique = CleAudit::depuis_pem(&pem)?.publique();
            creer(&d.join("cle-audit.pem"), 0o600, &pem)?;
            creer(&d.join("cle-audit.pub"), 0o644, &publique.pem())?;
            println!(
                "Clé d'audit créée (identifiant {}). La clé privée ne doit être lisible que par le compte qui scelle.",
                publique.id()
            );
        }
        [c, journal, cle] if c == "sceller" => {
            let cle = CleAudit::lire(Path::new(cle))?;
            let n = Journal::new(journal).sceller(&cle, maintenant())?;
            println!("Point de contrôle n° {n} ajouté.");
        }
        [c, journal, publique, exports @ ..] if c == "verifier" => {
            let cle = ClePublique::lire(Path::new(publique))?;
            let mut points = Vec::new();
            for e in exports {
                points.extend(lire_export(
                    &std::fs::read_to_string(e).with_context(|| format!("export {e}"))?,
                )?);
            }
            match verifier(&Journal::new(journal).lire()?, &cle, &points) {
                Ok(b) => {
                    println!(
                        "Journal intègre : {} enregistrements, {} points de contrôle, {} postérieurs au dernier point.",
                        b.enregistrements,
                        b.points.len(),
                        b.non_scelles
                    );
                    if exports.is_empty() {
                        println!(
                            "Attention : sans export (empreintes conservées hors du serveur), une réécriture complète ou une troncature n'est pas détectable."
                        );
                    }
                }
                Err(d) => {
                    eprintln!("JOURNAL D'AUDIT ALTÉRÉ : {d}");
                    return Ok(ExitCode::from(2));
                }
            }
        }
        [c, journal, publique, dossier] if c == "exporter" => {
            let cle = ClePublique::lire(Path::new(publique))?;
            let bilan = verifier(&Journal::new(journal).lire()?, &cle, &[])
                .map_err(|d| anyhow::anyhow!("journal d'audit altéré, pas d'export : {d}"))?;
            let t = maintenant();
            let jour: String = date_utc(t).chars().filter(|c| c.is_ascii_digit()).collect();
            let chemin = PathBuf::from(dossier).join(format!("empreintes-audit-{jour}.txt"));
            creer(&chemin, 0o600, &texte_export(&bilan, t))?;
            println!(
                "{} : {} points de contrôle. À copier HORS du serveur.",
                chemin.display(),
                bilan.points.len()
            );
        }
        _ => bail!(USAGE),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("barbacane-audit : {e:#}");
            ExitCode::from(1)
        }
    }
}
