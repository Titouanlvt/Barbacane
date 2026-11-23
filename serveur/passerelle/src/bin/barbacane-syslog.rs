//! Exportateur Syslog du serveur Barbacane (v2.3.0, `docs/suite/journal-syslog.md`).
//!
//! ```text
//! barbacane-syslog CONFIG              service : une passe par seconde (au plus), sans fin
//! barbacane-syslog CONFIG --une-passe  une passe, code 0 si à jour ou lot remis, 1 sinon
//! ```
//! Exécuté sous barbacane-svc hors conteneur (service systemd `barbacane-syslog`), avec la vue
//! hôte de passerelle.conf (`registre.conf`). Lit le journal d'audit (file persistante) et le
//! réglage validé dans la Console ; n'écrit que dans `<registre>/syslog/` et au journal d'audit.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Result, bail};
use barbacane_passerelle::Config;
use barbacane_passerelle::outils::maintenant;
use barbacane_passerelle::registre::Stockage;
use barbacane_passerelle::syslog::{Exportateur, Passe};

fn executer(args: &[String]) -> Result<ExitCode> {
    let (config, une) = match args {
        [c] => (c, false),
        [c, o] if o == "--une-passe" => (c, true),
        _ => bail!("usage : barbacane-syslog CONFIG [--une-passe]"),
    };
    let config = Config::lire(&PathBuf::from(config))?;
    let e = Exportateur {
        stockage: Stockage::ouvrir(&config.registre)?,
        serveur: barbacane_audit::structure::nom_serveur(
            &std::fs::read_to_string("/etc/hostname").unwrap_or_default(),
        ),
        file_max: barbacane_passerelle::syslog::FILE_MAX,
    };
    if une {
        return Ok(match e.passe(maintenant())? {
            Passe::Echec(m) => {
                eprintln!("barbacane-syslog : {m}");
                ExitCode::from(1)
            }
            p => {
                println!("{p:?}");
                ExitCode::SUCCESS
            }
        });
    }
    // Attente croissante après un échec (1 s à 60 s) ; relance immédiate tant qu'il reste des
    // lots à remettre.
    let mut attente = 1u64;
    let mut dernier_message = String::new();
    loop {
        match e.passe(maintenant()) {
            Ok(Passe::Remis(_)) => {
                attente = 1;
                dernier_message.clear();
                continue;
            }
            Ok(Passe::AJour) | Ok(Passe::Desactive) => attente = 1,
            Ok(Passe::Echec(m)) => {
                if m != dernier_message {
                    eprintln!("barbacane-syslog : {m}");
                    dernier_message = m;
                }
                attente = (attente * 2).min(60);
            }
            Err(err) => {
                let m = format!("{err:#}");
                if m != dernier_message {
                    eprintln!("barbacane-syslog : {m}");
                    dernier_message = m;
                }
                attente = (attente * 2).min(60);
            }
        }
        std::thread::sleep(Duration::from_secs(attente));
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("barbacane-syslog : {e:#}");
            ExitCode::from(1)
        }
    }
}
