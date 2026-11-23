//! Outil du journal d'audit (compte dédié, jamais celui de la passerelle).
//!
//! ```text
//! barbacane-audit cle DOSSIER                          clé d'audit P-384 (cle-audit.pem 0600, cle-audit.pub)
//! barbacane-audit sceller JOURNAL CLE_PRIVEE           vérifie la chaîne puis ajoute un point de contrôle signé
//! barbacane-audit verifier JOURNAL CLE_PUBLIQUE [EXPORT…]   code 0 intègre, 2 altéré
//! barbacane-audit exporter JOURNAL CLE_PUBLIQUE DOSSIER     empreintes des points (à sortir du serveur)
//! barbacane-audit tourner JOURNAL CLE_PRIVEE [--forcer]     scelle et range le journal actif (une fois par jour)
//! barbacane-audit conservation JOURNAL CLE_PRIVEE REGISTRE  rotation, purge des segments hors durée, scellement
//! barbacane-audit conservation-jours REGISTRE              durée appliquée aujourd'hui (jours) ou « aucune »
//! barbacane-audit consigner-purge-sauvegardes JOURNAL NOMBRE AVANT   trace d'une purge de sauvegardes
//! barbacane-audit structurer JOURNAL [SERVEUR]              journal complet au format structuré (JSON par ligne)
//! ```
//! `verifier` et `exporter` lisent TOUS les fichiers (segments rangés puis journal actif).
#![forbid(unsafe_code)]

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use barbacane_audit::conservation::Reglage;
use barbacane_audit::{
    CleAudit, ClePublique, Defaut, Evenement, Journal, ObjetPurge, date_utc, lire_export,
    structure, texte_export,
};

const USAGE: &str = "usage : barbacane-audit (cle DOSSIER | sceller JOURNAL CLE_PRIVEE | verifier JOURNAL CLE_PUBLIQUE [EXPORT…] | exporter JOURNAL CLE_PUBLIQUE DOSSIER | tourner JOURNAL CLE_PRIVEE [--forcer] | conservation JOURNAL CLE_PRIVEE REGISTRE | conservation-jours REGISTRE | consigner-purge-sauvegardes JOURNAL NOMBRE AVANT | structurer JOURNAL [SERVEUR])";

fn serveur_local() -> String {
    structure::nom_serveur(&std::fs::read_to_string("/etc/hostname").unwrap_or_default())
}

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
            match Journal::new(journal).verifier_tout(&cle, &points) {
                Ok(b) => {
                    println!(
                        "Journal intègre : {} enregistrements (n° {} à {}) dans {} fichier(s), {} points de contrôle, {} postérieurs au dernier point.",
                        b.enregistrements,
                        b.premier,
                        b.dernier,
                        b.segments,
                        b.points.len(),
                        b.non_scelles
                    );
                    if b.purges > 0 {
                        println!(
                            "Enregistrements 1 à {} purgés (conservation) : vérification depuis l'ouverture signée du segment n° {}{}.",
                            b.purges,
                            b.premier,
                            if b.exports_purges > 0 {
                                format!(
                                    " ; {} point(s) exporté(s) antérieur(s), non revérifiables",
                                    b.exports_purges
                                )
                            } else {
                                String::new()
                            }
                        );
                    }
                    if exports.is_empty() {
                        println!(
                            "Attention : sans export (empreintes conservées hors du serveur), une réécriture complète ou une troncature n'est pas détectable."
                        );
                    }
                }
                Err(e) if e.downcast_ref::<Defaut>().is_some() => {
                    eprintln!("JOURNAL D'AUDIT ALTÉRÉ : {e}");
                    return Ok(ExitCode::from(2));
                }
                Err(e) => return Err(e),
            }
        }
        [c, journal, publique, dossier] if c == "exporter" => {
            let cle = ClePublique::lire(Path::new(publique))?;
            let bilan = Journal::new(journal)
                .verifier_tout(&cle, &[])
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
        [c, journal, cle, opts @ ..] if c == "tourner" && opts.len() <= 1 => {
            let forcer = match opts {
                [] => false,
                [o] if o == "--forcer" => true,
                _ => bail!(USAGE),
            };
            let cle = CleAudit::lire(Path::new(cle))?;
            match Journal::new(journal).tourner(&cle, maintenant(), forcer)? {
                Some(n) => println!(
                    "Segment n° {n} scellé et rangé ; nouveau segment ouvert (ancre signée)."
                ),
                None => println!("Pas de rotation (journal du jour ou vide)."),
            }
        }
        [c, journal, cle, registre] if c == "conservation" => {
            let cle = CleAudit::lire(Path::new(cle))?;
            let j = Journal::new(journal);
            let t = maintenant();
            if let Some(n) = j.tourner(&cle, t, false)? {
                println!("Segment n° {n} scellé et rangé.");
            }
            let mut ajoute = false;
            match Reglage::lire(Path::new(registre))? {
                None => {
                    println!("Aucun réglage de conservation (conservation.json) : aucune purge.")
                }
                Some(r) => match r.limite(t) {
                    None => println!(
                        "Durée {} jours, en préavis jusqu'au {} : aucune purge d'ici là.",
                        r.jours,
                        date_utc(r.effective_le)
                    ),
                    Some(avant) => {
                        let p = j.purger_segments(&cle.publique(), t, avant, "conservation")?;
                        println!(
                            "Durée appliquée : {} jours (limite {}) ; {} segment(s) purgé(s){}.",
                            r.effectifs(t).unwrap_or(0),
                            date_utc(avant),
                            p.len(),
                            p.iter()
                                .map(|s| format!(" n° {}–{}", s.premier, s.dernier))
                                .collect::<String>()
                        );
                        ajoute = !p.is_empty();
                    }
                },
            }
            // Scellement quotidien (et des traces de purge).
            let n = j.sceller(&cle, t)?;
            println!(
                "Point de contrôle n° {n} ajouté.{}",
                if ajoute { " (purge scellée)" } else { "" }
            );
        }
        [c, registre] if c == "conservation-jours" => {
            match Reglage::lire(Path::new(registre))?.and_then(|r| r.effectifs(maintenant())) {
                Some(j) => println!("{j}"),
                None => println!("aucune"),
            }
        }
        [c, journal, nombre, avant] if c == "consigner-purge-sauvegardes" => {
            let nombre: u64 = nombre.parse().context("NOMBRE : entier attendu")?;
            let avant: u64 = avant.parse().context("AVANT : secondes Unix attendues")?;
            let n = Journal::new(journal).ajouter(
                maintenant(),
                "sauvegarde",
                Evenement::Purge {
                    objet: ObjetPurge::Sauvegardes,
                    nombre,
                    avant,
                },
            )?;
            println!("Purge de {nombre} sauvegarde(s) consignée (enregistrement n° {n}).");
        }
        [c, journal, serveur @ ..] if c == "structurer" && serveur.len() <= 1 => {
            let nom = serveur.first().cloned().unwrap_or_else(serveur_local);
            let mut sortie = std::io::stdout().lock();
            for contenu in Journal::new(journal).contenus()? {
                for l in contenu.split(|o| *o == b'\n').filter(|l| !l.is_empty()) {
                    writeln!(sortie, "{}", structure::structurer(l, &nom)?.json)?;
                }
            }
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
