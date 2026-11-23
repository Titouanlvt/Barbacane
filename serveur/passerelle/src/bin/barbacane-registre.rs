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
//! barbacane-registre CONFIG maj-plancher FICHIER   (plancher signé hors ligne + FICHIER.minisig)
//! barbacane-registre CONFIG maj-deposer FICHIER.bcu (+ FICHIER.bcu.minisig, clé des bornes)
//! barbacane-registre CONFIG maj-diffuser VERSION
//! barbacane-registre CONFIG maj-etat
//! barbacane-registre CONFIG conservation          passe quotidienne : réglage posé si absent, purge des passages
//! barbacane-registre CONFIG conservation-etat     durée, date d'effet, passages conservés
//! ```
//! Chaque opération est inscrite au journal d'audit chaîné (`audit.jsonl` du registre).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use barbacane_passerelle::Config;
use barbacane_passerelle::admin::Admin;
use barbacane_passerelle::outils::{date_utc, maintenant};
use barbacane_passerelle::registre::Motif;

const USAGE: &str = "usage : barbacane-registre CONFIG (jeton SITE | demandes | valider ID EMPREINTE [NOM] | refuser ID | revoquer UUID MOTIF | crl | supervision | maj-plancher FICHIER | maj-deposer FICHIER.bcu | maj-diffuser VERSION | maj-etat | conservation | conservation-etat)";

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
        "maj-plancher" => {
            let n = admin.maj_plancher(Path::new(arg(0)?))?;
            println!("Plancher signé installé : aucune version inférieure à {n} ne sera acceptée.");
        }
        "maj-deposer" => {
            let p = admin.maj_deposer(Path::new(arg(0)?))?;
            println!(
                "Paquet {} accepté (signature des bornes vérifiée) : sha256 {}, {} octets.",
                p.version_maj, p.sha256, p.taille
            );
            println!("Le proposer aux bornes : maj-diffuser {}", p.version_maj);
        }
        "maj-diffuser" => {
            let n: u64 = arg(0)?.parse().context("VERSION : entier attendu")?;
            admin.maj_diffuser(n)?;
            println!("Paquet {n} proposé aux bornes à leur prochain battement.");
        }
        "maj-etat" => {
            let e = admin.maj_etat()?;
            println!(
                "plancher {}  diffusé {}",
                e.plancher
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "aucun".into()),
                e.diffusee
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "aucun".into())
            );
            for p in &e.paquets {
                println!(
                    "paquet {}  {} octets  sha256 {}  déposé {}",
                    p.version_maj,
                    p.taille,
                    p.sha256,
                    date_utc(p.depose_le)
                );
            }
            for (uuid, s) in &e.bornes {
                println!(
                    "{uuid}  paquet {}  {}  depuis {}",
                    s.version_maj,
                    serde_json::to_string(&s.etat)?.trim_matches('"'),
                    date_utc(s.le)
                );
            }
        }
        "conservation" => {
            let p = barbacane_passerelle::conservation::passe(&admin.stockage, t, "conservation")?;
            match p.limite {
                None => println!(
                    "Conservation : {} jours, en préavis jusqu'au {} : aucune purge d'ici là.",
                    p.reglage.jours,
                    date_utc(p.reglage.effective_le)
                ),
                Some(avant) => println!(
                    "Conservation : {} jours appliqués (limite {}) ; {} rapport(s) de passage purgé(s).",
                    p.reglage.effectifs(t).unwrap_or(0),
                    date_utc(avant),
                    p.passages
                ),
            }
        }
        "conservation-etat" => {
            let r = barbacane_passerelle::conservation::lire(&admin.stockage)?;
            let n = barbacane_passerelle::passages::Passages::ouvrir(&admin.stockage)?.nombre()?;
            match r {
                None => println!("conservation : non réglée (posée à la première passe)"),
                Some(r) => println!(
                    "conservation : {} jours, effective le {}, appliquée aujourd'hui : {}",
                    r.jours,
                    date_utc(r.effective_le),
                    r.effectifs(t)
                        .map(|j| format!("{j} jours"))
                        .unwrap_or_else(|| "aucune purge (préavis)".into())
                ),
            }
            println!("passages : {n}");
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
