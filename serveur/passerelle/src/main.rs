//! `barbacane-passerelle FICHIER_DE_CONFIGURATION`
//! `barbacane-passerelle --verifier-config FICHIER` : analyse et contrôles de démarrage
//! (certificats, clés, CRL, registre), sans écouter ; code 0 si la passerelle démarrerait.
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context, Result};
use barbacane_passerelle::{Config, Passerelle, servir, servir_enrolement};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let usage = "usage : barbacane-passerelle [--verifier-config] FICHIER_DE_CONFIGURATION";
    let mut premier = args.next().context(usage)?;
    let verifier = premier == "--verifier-config";
    if verifier {
        premier = args.next().context(usage)?;
    }
    let chemin: PathBuf = premier.into();
    let config = Config::lire(&chemin)?;
    // Contrôle au démarrage : certificats, clés, CRL et registre valides, sinon on ne démarre pas.
    let p = Passerelle::nouvelle(config)?;
    if verifier {
        println!(
            "configuration valide : service {}, enrôlement {}",
            p.config.adresse_ecoute(),
            p.config.adresse_enrolement()
        );
        return Ok(());
    }
    let service = TcpListener::bind(p.config.adresse_ecoute())
        .with_context(|| format!("écoute sur {}", p.config.adresse_ecoute()))?;
    let enrolement = TcpListener::bind(p.config.adresse_enrolement())
        .with_context(|| format!("écoute sur {}", p.config.adresse_enrolement()))?;
    eprintln!(
        "passerelle : service (mTLS) sur {}, enrôlement sur {}",
        p.config.adresse_ecoute(),
        p.config.adresse_enrolement()
    );
    let p2 = p.clone();
    std::thread::spawn(move || {
        if let Err(e) = servir_enrolement(enrolement, p2) {
            eprintln!("passerelle : enrôlement arrêté : {e:#}");
            std::process::exit(1);
        }
    });
    servir(service, p)
}
