//! Durée de conservation côté registre (v2.3.0, `docs/suite/journal-conservation.md`) :
//! lecture et première pose du réglage, application après double validation, purge des
//! rapports de passage. Le réglage lui-même (bornes, préavis) : [`barbacane_audit::conservation`].

use anyhow::{Context, Result};
use barbacane_audit::Evenement;
use barbacane_audit::conservation::{FICHIER, Reglage};

use crate::outils::ecrire_atomique;
use crate::passages::Passages;
use crate::registre::Stockage;
use crate::utilisateurs::CONSERVATION_S;

/// Réglage en vigueur ; posé au premier appel (valeur par défaut, préavis de 7 jours,
/// journalisé) si le serveur n'en a pas encore (installation neuve ou serveur 2.2.0).
pub fn lire_ou_initialiser(stockage: &Stockage, t: u64, par: &str) -> Result<Reglage> {
    let _v = verrou(stockage)?;
    if let Some(r) = Reglage::lire(stockage.dossier())? {
        return Ok(r);
    }
    let r = Reglage::initial(t, par);
    stockage.auditer(
        par,
        Evenement::ConservationReglee {
            jours: r.jours,
            effective_le: r.effective_le,
        },
    )?;
    ecrire(stockage, &r)?;
    Ok(r)
}

/// Lecture seule (`None` : pas encore posé).
pub fn lire(stockage: &Stockage) -> Result<Option<Reglage>> {
    Reglage::lire(stockage.dossier())
}

fn verrou(stockage: &Stockage) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(stockage.dossier().join("conservation.verrou"))
        .context("verrou de la conservation")?;
    f.lock().context("prise du verrou de la conservation")?;
    Ok(f)
}

fn ecrire(stockage: &Stockage, r: &Reglage) -> Result<()> {
    r.valider()?;
    ecrire_atomique(
        &stockage.dossier().join(FICHIER),
        &serde_json::to_vec_pretty(r)?,
    )
}

/// Applique une nouvelle durée (après double validation) ; trace d'abord.
pub fn changer(
    stockage: &Stockage,
    jours: u32,
    t: u64,
    acteur: &str,
    par: &str,
) -> Result<Reglage> {
    let _v = verrou(stockage)?;
    let actuel = Reglage::lire(stockage.dossier())?.unwrap_or_else(|| Reglage::initial(t, par));
    let r = actuel.changer(jours, t, par)?;
    stockage.auditer(
        acteur,
        Evenement::ConservationReglee {
            jours: r.jours,
            effective_le: r.effective_le,
        },
    )?;
    ecrire(stockage, &r)?;
    Ok(r)
}

/// Durée de conservation des correspondances identifiant ↔ pseudonyme : celle des journaux
/// qu'elles servent à exploiter ; 1 an (comportement 2.2.0) tant que le réglage n'est pas en
/// vigueur ou s'il est illisible.
pub fn duree_correspondances_s(stockage: &Stockage, t: u64) -> u64 {
    Reglage::lire(stockage.dossier())
        .ok()
        .flatten()
        .and_then(|r| r.effectifs(t))
        .map(|j| u64::from(j) * 86400)
        .unwrap_or(CONSERVATION_S)
}

/// Bilan d'une passe de conservation (registre).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passe {
    pub reglage: Reglage,
    /// Limite appliquée (`None` : préavis, rien purgé).
    pub limite: Option<u64>,
    pub passages: u64,
}

/// Passe quotidienne côté registre (sous barbacane-svc) : réglage posé si absent, purge des
/// rapports de passage reçus avant la limite.
pub fn passe(stockage: &Stockage, t: u64, acteur: &str) -> Result<Passe> {
    let reglage = lire_ou_initialiser(stockage, t, acteur)?;
    let limite = reglage.limite(t);
    let passages = match limite {
        Some(avant) => Passages::ouvrir(stockage)?.purger(avant, acteur)?,
        None => 0,
    };
    Ok(Passe {
        reglage,
        limite,
        passages,
    })
}
