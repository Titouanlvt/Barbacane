//! `barbacane-agent [FICHIER_DE_CONFIGURATION]` (défaut : `/etc/barbacane/agent.toml`).
//!
//! Boucle sans fin : un cycle (jeton, demande, retrait, renouvellement, battement), puis
//! attente. Toute erreur est publiée dans `etat.json` ; seule une configuration invalide
//! (CA non conforme à l'empreinte épinglée, schéma faux) empêche de démarrer.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::Result;
use barbacane_agent::Agent;
use barbacane_agent::coffre::CoffreFichier;
use barbacane_agent::config::Config;

fn main() -> Result<()> {
    let chemin: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| "/etc/barbacane/agent.toml".into());
    let config = Config::lire(&chemin)?;
    let coffre = CoffreFichier::nouveau(&config.etat);
    eprintln!(
        "agent : serveur {} (enrôlement {}, service {}), CA serveur épinglée {}",
        config.adresse, config.port_enrolement, config.port_service, config.empreinte_ca_serveur
    );
    let mut agent = Agent::nouveau(config, coffre)?;
    loop {
        let attente = agent.cycle();
        std::thread::sleep(attente);
    }
}
