//! Interface web d'administration du serveur Barbacane.
//!
//! ```text
//! barbacane-web CONFIG                              sert l'interface (écoute d'administration)
//! barbacane-web compte IDENTIFIANT RÔLE CERT.pem    ligne du fichier des comptes ; mot de passe
//!                                                   lu sur l'entrée standard (première ligne)
//! ```
//! RÔLE : `administrateur` ou `auditeur`. Voir `docs/suite/serveur-web.md`.
#![forbid(unsafe_code)]

use std::io::BufRead;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use barbacane_web::comptes::{Role, ligne_compte};
use barbacane_web::{Config, Web, servir};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

const USAGE: &str = "usage : barbacane-web CONFIG | barbacane-web compte IDENTIFIANT (administrateur|auditeur) CERT.pem < mot-de-passe";

fn executer(args: &[String]) -> Result<()> {
    match args {
        [c, id, role, cert] if c == "compte" => {
            let role = Role::analyser(role).context("rôle : administrateur ou auditeur")?;
            let der = CertificateDer::from_pem_file(cert)
                .with_context(|| format!("certificat {cert}"))?;
            let mut mdp = String::new();
            std::io::stdin().lock().read_line(&mut mdp)?;
            let mdp = mdp.trim_end_matches(['\r', '\n']);
            println!("{}", ligne_compte(id, role, &der, mdp)?);
            Ok(())
        }
        [config] => {
            let config = Config::lire(&PathBuf::from(config))?;
            let ecoute = TcpListener::bind(config.adresse_ecoute())
                .with_context(|| format!("écoute {}", config.adresse_ecoute()))?;
            eprintln!(
                "barbacane-web : interface d'administration sur {} (TLS 1.3, certificat d'administrateur exigé)",
                config.adresse_ecoute()
            );
            servir(ecoute, Web::nouveau(config)?)
        }
        _ => bail!(USAGE),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("barbacane-web : {e:#}");
            ExitCode::from(1)
        }
    }
}
