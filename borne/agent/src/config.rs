//! Configuration de l'agent (`/etc/barbacane/agent.toml`), écrite à l'installation par l'ISO
//! du profil en-ligne. Schéma strict : clé inconnue = refus de démarrer.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Adresse IPv4 du serveur : la SEULE destination autorisée (pare-feu et systemd la
    /// reprennent). Pas de nom DNS : la borne n'a pas de résolveur.
    pub adresse: Ipv4Addr,
    /// Nom porté par le certificat du serveur (vérifié par TLS).
    #[serde(default = "nom_serveur_defaut")]
    pub nom_serveur: String,
    /// Port de l'écoute d'enrôlement (D4) ; doit être celui inscrit dans le jeton.
    pub port_enrolement: u16,
    /// Port de l'écoute de service (mTLS) ; doit être celui renvoyé au retrait du certificat.
    pub port_service: u16,
    /// Certificat de la CA « serveur » : seule ancre de confiance (conception §3.5).
    pub ca_serveur: PathBuf,
    /// SHA-256 (hexadécimal) du DER de cette CA, inscrit dans l'ISO : le fichier doit y
    /// correspondre, sinon l'agent refuse de démarrer.
    pub empreinte_ca_serveur: String,
    /// Dossier d'état (clés, certificats, demande en cours, file locale) : 0700.
    #[serde(default = "etat_defaut")]
    pub etat: PathBuf,
    /// Dossier d'exécution (état lisible par l'interface et l'administration locale).
    #[serde(default = "execution_defaut")]
    pub execution: PathBuf,
    /// Intervalle de consultation d'une demande en attente (protocole : 30 s au plus souvent).
    #[serde(default = "trente")]
    pub periode_retrait_s: u64,
    /// Délai maximal entre deux tentatives quand le serveur est injoignable.
    #[serde(default = "trois_cents")]
    pub reessai_max_s: u64,
    /// Capacité de la file locale (rapports non transmis) ; pleine → la borne le signale.
    #[serde(default = "mille")]
    pub file_max: usize,
}

fn nom_serveur_defaut() -> String {
    "passerelle.barbacane.invalid".into()
}
fn etat_defaut() -> PathBuf {
    "/var/lib/barbacane-agent".into()
}
fn execution_defaut() -> PathBuf {
    "/run/barbacane-agent".into()
}
fn trente() -> u64 {
    30
}
fn trois_cents() -> u64 {
    300
}
fn mille() -> usize {
    1000
}

impl Config {
    pub fn lire(chemin: &Path) -> Result<Config> {
        let texte = std::fs::read_to_string(chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        Config::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<Config> {
        let c: Config = toml::from_str(texte).context("configuration de l'agent")?;
        if c.port_enrolement == 0 || c.port_service == 0 || c.port_enrolement == c.port_service {
            bail!("ports nuls ou identiques refusés (deux écoutes distinctes)");
        }
        if !barbacane_protocole::hex_valide(&c.empreinte_ca_serveur, 64) {
            bail!("empreinte_ca_serveur : 64 caractères hexadécimaux minuscules attendus");
        }
        if c.nom_serveur.is_empty()
            || c.nom_serveur.len() > 253
            || !c
                .nom_serveur
                .bytes()
                .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || b".-".contains(&o))
        {
            bail!("nom_serveur invalide");
        }
        if c.adresse.is_unspecified() || c.adresse.is_broadcast() || c.adresse.is_multicast() {
            bail!("adresse du serveur invalide");
        }
        if !(1..=3600).contains(&c.periode_retrait_s) || !(1..=86400).contains(&c.reessai_max_s) {
            bail!("périodes hors bornes");
        }
        if !(1..=100_000).contains(&c.file_max) {
            bail!("file_max hors bornes");
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const CONF: &str = "adresse = \"10.0.2.2\"\nport_enrolement = 43118\nport_service = 43117\nca_serveur = \"/etc/barbacane/agent/ca-serveur.pem\"\nempreinte_ca_serveur = \"0000000000000000000000000000000000000000000000000000000000000000\"\n";

    #[test]
    fn config_minimale() {
        let c = Config::analyser(CONF).unwrap();
        assert_eq!(c.nom_serveur, "passerelle.barbacane.invalid");
        assert_eq!(c.etat, PathBuf::from("/var/lib/barbacane-agent"));
        assert_eq!(c.periode_retrait_s, 30);
    }

    #[test]
    fn config_refusee() {
        assert!(Config::analyser(&format!("{CONF}inconnue = 1\n")).is_err());
        assert!(Config::analyser(&CONF.replace("43118", "43117")).is_err());
        assert!(Config::analyser(&CONF.replace("43118", "0")).is_err());
        assert!(Config::analyser(&CONF.replace("10.0.2.2", "0.0.0.0")).is_err());
        assert!(Config::analyser(&CONF.replace("10.0.2.2", "serveur.lan")).is_err());
        assert!(Config::analyser(&CONF.replace("\"0000", "\"ZZ00")).is_err());
        assert!(
            Config::analyser(&format!("{CONF}nom_serveur = \"a b\"\n")).is_err(),
            "nom de serveur hors jeu de caractères"
        );
    }
}
