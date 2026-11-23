//! Durée de conservation des rapports de passage, du journal d'audit et des sauvegardes
//! (v2.3.0, décision de l'utilisateur du 22/11/2026, `docs/suite/journal-conservation.md`).
//!
//! Réglée par un administrateur dans la Console, changement par double validation ; fichier
//! `<registre>/conservation.json` (écrit par la Console, lu par la tâche planifiée
//! `barbacane-conservation` et par `barbacane-sauvegarde`).
//!
//! - **Défaut 365 jours** (CNIL, recommandation journalisation, 6 mois à 1 an) ;
//! - **minimum 180 jours** (6 mois : bas de la fourchette de la CNIL ; en deçà, un incident
//!   découvert tardivement ne pourrait plus être instruit) ;
//! - **plafond 730 jours** (2 ans : au-delà d'1 an, la CNIL demande une justification que
//!   l'organisme consigne dans son AIPD ; au-delà de 2 ans, aucune finalité de sécurité
//!   courante ne le justifie pour ces données). Choix de Claude, à valider (`decisions.md`).
//! - **Préavis de 7 jours** pour toute RÉDUCTION (et pour la valeur posée à la migration
//!   depuis la 2.2.0) : la purge ne commence qu'à la date d'effet, affichée dans la Console ;
//!   une augmentation prend effet aussitôt. Ainsi aucune purge massive n'est jamais
//!   immédiate, et un changement malveillant (même validé par deux administrateurs) laisse le
//!   temps de le voir, au journal comme dans le collecteur Syslog.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const JOURS_DEFAUT: u32 = 365;
pub const JOURS_MIN: u32 = 180;
pub const JOURS_MAX: u32 = 730;
/// Seuil au-delà duquel la Console rappelle la justification à consigner (CNIL).
pub const JOURS_SANS_JUSTIFICATION: u32 = 365;
pub const PREAVIS_S: u64 = 7 * 86400;
/// Nom du fichier dans le dossier du registre.
pub const FICHIER: &str = "conservation.json";

/// Réglage en vigueur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reglage {
    pub version: u16,
    /// Durée choisie (jours).
    pub jours: u32,
    /// Durée appliquée jusqu'à `effective_le` (réduction en préavis) ; `None` : aucune purge
    /// avant `effective_le` (migration depuis la 2.2.0).
    pub precedent: Option<u32>,
    pub effective_le: u64,
    pub regle_le: u64,
    /// `migration-2.2.0`, `installation` ou `web:<compte demandeur>+<compte validateur>`.
    pub par: String,
}

impl Reglage {
    /// Valeur posée au premier démarrage d'un serveur sans réglage (installation neuve ou
    /// migration) : 365 jours, purge après le préavis seulement.
    pub fn initial(t: u64, par: &str) -> Reglage {
        Reglage {
            version: 1,
            jours: JOURS_DEFAUT,
            precedent: None,
            effective_le: t + PREAVIS_S,
            regle_le: t,
            par: par.into(),
        }
    }

    /// Durée appliquée à l'instant `t` (`None` : pas de purge).
    pub fn effectifs(&self, t: u64) -> Option<u32> {
        if t >= self.effective_le {
            Some(self.jours)
        } else {
            self.precedent
        }
    }

    /// Limite de purge à l'instant `t` : tout ce qui est antérieur est purgé.
    pub fn limite(&self, t: u64) -> Option<u64> {
        self.effectifs(t)
            .map(|j| t.saturating_sub(u64::from(j) * 86400))
    }

    /// Nouveau réglage : bornes contrôlées ; réduction avec préavis, augmentation immédiate.
    pub fn changer(&self, jours: u32, t: u64, par: &str) -> Result<Reglage> {
        if !(JOURS_MIN..=JOURS_MAX).contains(&jours) {
            bail!("durée de conservation : de {JOURS_MIN} à {JOURS_MAX} jours");
        }
        if jours == self.jours {
            bail!("durée de conservation inchangée ({jours} jours)");
        }
        let (precedent, effective_le) = match self.effectifs(t) {
            // Encore aucune purge (préavis de migration) : jamais avant un nouveau préavis.
            None => (None, self.effective_le.max(t + PREAVIS_S)),
            Some(a) if jours < a => (Some(a), t + PREAVIS_S),
            Some(_) => (None, t),
        };
        Ok(Reglage {
            version: 1,
            jours,
            precedent,
            effective_le,
            regle_le: t,
            par: par.into(),
        })
    }

    pub fn valider(&self) -> Result<()> {
        if self.version != 1
            || !(JOURS_MIN..=JOURS_MAX).contains(&self.jours)
            || self
                .precedent
                .is_some_and(|p| !(JOURS_MIN..=JOURS_MAX).contains(&p))
            || !crate::ident_valide(&self.par)
        {
            bail!("réglage de conservation hors bornes");
        }
        Ok(())
    }

    /// Lit le réglage (`None` s'il n'existe pas encore) ; contenu hors bornes refusé.
    pub fn lire(dossier_registre: &Path) -> Result<Option<Reglage>> {
        let chemin = dossier_registre.join(FICHIER);
        let o = match std::fs::read(&chemin) {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("{}", chemin.display())),
        };
        if o.len() > 4096 {
            bail!("{} : trop long", chemin.display());
        }
        let r: Reglage = serde_json::from_slice(&o)
            .with_context(|| format!("{} illisible", chemin.display()))?;
        r.valider()?;
        Ok(Some(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preavis_et_bornes() {
        let t = 1_000_000_000;
        let r = Reglage::initial(t, "migration-2.2.0");
        assert_eq!(r.effectifs(t), None);
        assert_eq!(r.effectifs(t + PREAVIS_S - 1), None);
        assert_eq!(r.effectifs(t + PREAVIS_S), Some(365));
        let t2 = t + PREAVIS_S + 10;
        // Réduction : préavis de 7 jours, l'ancienne durée s'applique d'ici là.
        let r2 = r.changer(200, t2, "web:a+b").unwrap();
        assert_eq!(r2.effectifs(t2), Some(365));
        assert_eq!(r2.effectifs(t2 + PREAVIS_S), Some(200));
        assert_eq!(
            r2.limite(t2 + PREAVIS_S),
            Some(t2 + PREAVIS_S - 200 * 86400)
        );
        // Augmentation : immédiate.
        let r3 = r2.changer(400, t2 + 1, "web:a+b").unwrap();
        assert_eq!(r3.effectifs(t2 + 1), Some(400));
        // Réduction pendant le préavis de migration : toujours aucune purge avant la date.
        let r4 = r.changer(180, t + 5, "web:a+b").unwrap();
        assert_eq!(r4.effectifs(t + 5), None);
        assert_eq!(r4.effectifs(t + 5 + PREAVIS_S), Some(180));
        for j in [0, 179, 731, 10_000] {
            assert!(r.changer(j, t, "x").is_err(), "{j}");
        }
        assert!(r.changer(365, t, "x").is_err());
        let mut mauvais = r.clone();
        mauvais.jours = 5;
        assert!(mauvais.valider().is_err());
    }
}
