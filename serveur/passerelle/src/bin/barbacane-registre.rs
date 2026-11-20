//! Administration locale du registre des bornes (en attendant l'interface web, D10).
//!
//! ```text
//! barbacane-registre CONFIG jeton SITE
//! barbacane-registre CONFIG demandes
//! barbacane-registre CONFIG valider DEMANDE_ID EMPREINTE [NOM]
//! barbacane-registre CONFIG refuser DEMANDE_ID
//! barbacane-registre CONFIG revoquer UUID MOTIF   (volee|reformee|cle-suspecte|changement-site|fin-de-vie)
//! barbacane-registre CONFIG crl
//! barbacane-registre CONFIG supervision           (code 3 si au moins une alerte)
//! ```
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use barbacane_passerelle::Config;
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::{date_utc, maintenant};
use barbacane_passerelle::registre::Motif;

const USAGE: &str = "usage : barbacane-registre CONFIG (jeton SITE | demandes | valider ID EMPREINTE [NOM] | refuser ID | revoquer UUID MOTIF | crl | supervision)";

/// Empreinte lisible : groupes de 4 caractères.
fn grouper(h: &str) -> String {
    h.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn executer(args: &[String]) -> Result<ExitCode> {
    let [config, commande, reste @ ..] = args else {
        bail!(USAGE);
    };
    let admin = Admin::ouvrir(Config::lire(&PathBuf::from(config))?)?;
    let t = maintenant();
    let arg = |i: usize| reste.get(i).map(String::as_str).context(USAGE);
    match commande.as_str() {
        "jeton" => {
            let j = admin.creer_jeton(arg(0)?, t)?;
            println!(
                "Jeton d'enrôlement (usage unique, valable jusqu'à {}) :",
                date_utc(t + barbacane_protocole::DUREE_JETON_S)
            );
            println!("{}", j.formater());
        }
        "demandes" => {
            let d = admin.demandes(t)?;
            if d.is_empty() {
                println!("Aucune demande en attente.");
            }
            for d in d {
                println!("demande  {}", d.id);
                println!("  site       {}", d.site);
                println!("  déposée    {}", date_utc(d.deposee_le));
                println!("  logiciel   {}", d.version_logiciel);
                println!("  empreinte  {}", grouper(&d.empreinte));
            }
            println!("Comparer l'empreinte à celle affichée par la borne AVANT de valider.");
        }
        "valider" => {
            let nom = reste.get(2).map(String::as_str);
            let uuid = admin.valider(arg(0)?, arg(1)?, nom, t)?;
            println!("Demande validée : borne {uuid} (certificat de 90 jours émis).");
        }
        "refuser" => {
            admin.refuser(arg(0)?, t)?;
            println!("Demande refusée.");
        }
        "revoquer" => {
            let motif = Motif::analyser(arg(1)?)
                .filter(|m| *m != Motif::Remplace)
                .context("motif : volee, reformee, cle-suspecte, changement-site ou fin-de-vie")?;
            admin.revoquer(arg(0)?, motif, t)?;
            println!("Borne révoquée ; CRL republiée (refus à la prochaine connexion).");
        }
        "crl" => {
            let n = admin.publier_crl(t)?;
            println!(
                "CRL n° {n} publiée, valable jusqu'à {}.",
                date_utc(t + barbacane_passerelle::ca::VALIDITE_CRL_S)
            );
        }
        "supervision" => {
            let lignes = admin.supervision(t)?;
            let mut alertes = 0;
            println!("Heure du serveur : {}", date_utc(t));
            for l in &lignes {
                let vue = l
                    .derniere_vue
                    .map(date_utc)
                    .unwrap_or_else(|| "jamais".into());
                println!(
                    "{}  {:<12} {:<8} {:<9} version={} état={} vue={} écart={} expire={}{}",
                    l.uuid,
                    l.nom,
                    l.site,
                    if l.active { "active" } else { "révoquée" },
                    l.version_logiciel.as_deref().unwrap_or("-"),
                    l.etat
                        .map(|e| format!("{e:?}"))
                        .unwrap_or_else(|| "-".into()),
                    vue,
                    l.ecart_horloge_s
                        .map(|e| format!("{e}s"))
                        .unwrap_or_else(|| "-".into()),
                    date_utc(l.expire_le),
                    if l.alertes.is_empty() {
                        String::new()
                    } else {
                        format!("  ALERTE {}", serde_json::to_string(&l.alertes)?)
                    }
                );
                alertes += l.alertes.len();
            }
            if lignes.is_empty() {
                println!("Aucune borne enrôlée.");
            }
            if alertes > 0 {
                return Ok(ExitCode::from(3));
            }
        }
        _ => bail!(USAGE),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("barbacane-registre : {e:#}");
            ExitCode::from(1)
        }
    }
}
