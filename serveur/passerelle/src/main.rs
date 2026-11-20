//! `barbacane-passerelle FICHIER_DE_CONFIGURATION`
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context, Result};
use barbacane_passerelle::{Config, config_tls, servir};

fn main() -> Result<()> {
    let chemin: PathBuf = std::env::args_os()
        .nth(1)
        .context("usage : barbacane-passerelle FICHIER_DE_CONFIGURATION")?
        .into();
    let config = Config::lire(&chemin)?;
    // Contrôle au démarrage : certificats, clé et CRL valides, sinon on ne démarre pas.
    config_tls(&config)?;
    let ecoute = TcpListener::bind(config.adresse_ecoute())
        .with_context(|| format!("écoute sur {}", config.adresse_ecoute()))?;
    eprintln!("passerelle : écoute sur {}", config.adresse_ecoute());
    servir(ecoute, config)
}
