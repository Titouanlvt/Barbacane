//! Interface web d'administration du serveur Barbacane.
//!
//! ```text
//! barbacane-web CONFIG                              sert l'interface (écoute d'administration)
//! barbacane-web compte IDENTIFIANT RÔLE CERT.pem    ligne du fichier des comptes ; mot de passe
//!                                                   lu sur l'entrée standard (première ligne)
//! barbacane-web annuaire CONFIG                     synchronise les identifiants (LDAPS)
//! barbacane-web reamorcer PASSERELLE.conf          console locale du serveur seulement (vue hôte
//!                                                   registre.conf) : rouvre l'amorçage (un
//!                                                   administrateur restant crée seul un second
//!                                                   administrateur), journalisé
//! barbacane-web --verifier-config CONFIG            contrôles de démarrage (TLS, CA et CRL des
//!                                                   administrateurs, comptes, clé d'audit,
//!                                                   passerelle, registre) sans écouter ; code 0
//!                                                   si l'interface démarrerait
//! ```
//! RÔLE : `administrateur`, `operateur`, `auditeur` ou `lecture`. Le fichier produit par
//! `compte` (format v2.1.0) est importé au premier démarrage dans la base des comptes gérée par
//! la Console (`docs/suite/comptes-administrateurs.md`). Voir `docs/suite/serveur-web.md`.
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

const USAGE: &str = "usage : barbacane-web CONFIG | barbacane-web compte IDENTIFIANT (administrateur|operateur|auditeur|lecture) CERT.pem < mot-de-passe | barbacane-web annuaire CONFIG | barbacane-web reamorcer PASSERELLE.conf | barbacane-web --verifier-config CONFIG";

fn executer(args: &[String]) -> Result<()> {
    match args {
        [c, id, role, cert] if c == "compte" => {
            let role = Role::analyser(role)
                .context("rôle : administrateur, operateur, auditeur ou lecture")?;
            let der = CertificateDer::from_pem_file(cert)
                .with_context(|| format!("certificat {cert}"))?;
            let mut mdp = String::new();
            std::io::stdin().lock().read_line(&mut mdp)?;
            let mdp = mdp.trim_end_matches(['\r', '\n']);
            println!("{}", ligne_compte(id, role, &der, mdp)?);
            Ok(())
        }
        [c, passerelle] if c == "reamorcer" => {
            barbacane_web::reamorcer(&PathBuf::from(passerelle))?;
            println!(
                "amorçage rouvert : le seul administrateur utilisable peut de nouveau créer seul un second administrateur"
            );
            Ok(())
        }
        [c, config] if c == "annuaire" => {
            let config = Config::lire(&PathBuf::from(config))?;
            let annuaire = config
                .annuaire
                .context("clé « annuaire » absente de la configuration")?;
            let passerelle = barbacane_passerelle::Config::lire(&config.passerelle)?;
            let admin = barbacane_passerelle::admin::Admin::ouvrir(passerelle)?;
            let u = barbacane_passerelle::utilisateurs::Utilisateurs::ouvrir(&admin.stockage)?;
            let b = barbacane_web::annuaire::synchroniser(
                &annuaire,
                &u,
                &barbacane_passerelle::admin::acteur_local(),
                barbacane_passerelle::outils::maintenant(),
            )?;
            println!(
                "annuaire : {} actifs, {} ajoutés, {} retirés, {} ignorés",
                b.actifs, b.ajoutes, b.retires, b.ignores
            );
            Ok(())
        }
        [v, config] if v == "--verifier-config" => {
            let config = Config::lire(&PathBuf::from(config))?;
            let adresse = config.adresse_ecoute();
            Web::verifier(config)?;
            println!("configuration valide : Console sur {adresse}");
            Ok(())
        }
        [config] => {
            let config = Config::lire(&PathBuf::from(config))?;
            let ecoute = TcpListener::bind(config.adresse_ecoute())
                .with_context(|| format!("écoute {}", config.adresse_ecoute()))?;
            eprintln!(
                "barbacane-web : Console sur {} (TLS 1.3, certificat d'administrateur exigé)",
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
