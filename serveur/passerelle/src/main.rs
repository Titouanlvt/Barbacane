//! `barbacane-passerelle FICHIER_DE_CONFIGURATION`
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context, Result};
use barbacane_passerelle::{Config, Passerelle, servir, servir_enrolement};

fn main() -> Result<()> {
    let chemin: PathBuf = std::env::args_os()
        .nth(1)
        .context("usage : barbacane-passerelle FICHIER_DE_CONFIGURATION")?
        .into();
    let config = Config::lire(&chemin)?;
    // Contrôle au démarrage : certificats, clés, CRL et registre valides, sinon on ne démarre pas.
    let p = Passerelle::nouvelle(config)?;
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
