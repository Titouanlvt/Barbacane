//! Mesure de la progression : quantités, vitesse de la clé, temps restant.
//!
//! Les étapes longues (lecture, effacement, écriture) rapportent des octets.
//! La vitesse est lissée sur une fenêtre glissante : les clés lentes écrivent
//! par à-coups et une mesure instantanée ferait sauter l'estimation.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Fenêtre de lissage de la vitesse.
const FENETRE: Duration = Duration::from_secs(20);
/// Durée minimale de mesure avant d'afficher une vitesse.
const MESURE_MIN: Duration = Duration::from_secs(3);
/// En dessous, la clé est signalée comme lente (octets/s).
pub const CLE_LENTE: f64 = 10.0 * 1_000_000.0;

#[derive(Debug, Default)]
pub struct Mesure {
    points: VecDeque<(Instant, u64)>,
}

impl Mesure {
    /// Nouvelle mesure (à appeler quand l'étape change).
    pub fn vider(&mut self) {
        self.points.clear();
    }

    pub fn ajouter(&mut self, quand: Instant, fait: u64) {
        if self.points.back().is_some_and(|&(_, f)| fait < f) {
            self.points.clear(); // compteur reparti de zéro : nouvelle opération
        }
        self.points.push_back((quand, fait));
        // Garder au moins deux points, ceux de la fenêtre
        while self.points.len() > 2 && quand.duration_since(self.points[1].0) >= FENETRE {
            self.points.pop_front();
        }
    }

    /// Vitesse en octets/s, si la mesure couvre assez de temps.
    pub fn vitesse(&self) -> Option<f64> {
        let (&(t0, f0), &(t1, f1)) = (self.points.front()?, self.points.back()?);
        let dt = t1.duration_since(t0);
        (dt >= MESURE_MIN).then(|| (f1 - f0) as f64 / dt.as_secs_f64())
    }

    /// Temps restant estimé.
    pub fn restant(&self, total: u64) -> Option<Duration> {
        let v = self.vitesse()?;
        let fait = self.points.back()?.1;
        (v > 0.0).then(|| Duration::from_secs_f64(total.saturating_sub(fait) as f64 / v))
    }
}

/// « 1,8 Go », « 512 Mo », « 37 ko » (puissances de 1000, comme sur l'étiquette des clés).
pub fn taille(o: u64) -> String {
    let o = o as f64;
    let (v, u) = if o >= 1e9 {
        (o / 1e9, "Go")
    } else if o >= 1e6 {
        (o / 1e6, "Mo")
    } else if o >= 1e3 {
        (o / 1e3, "ko")
    } else {
        return format!("{o} o");
    };
    let s = if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    };
    format!("{} {u}", s.replace('.', ","))
}

/// « 4,6 Mo/s ».
pub fn debit(v: f64) -> String {
    format!("{}/s", taille(v as u64))
}

/// « environ 20 min », « moins d'une minute », « environ 1 h 15 ».
pub fn duree(d: Duration) -> String {
    let m = d.as_secs().div_ceil(60);
    match m {
        0 | 1 => "moins d'une minute".into(),
        2..=59 => format!("environ {m} min"),
        _ => format!("environ {} h {:02}", m / 60, m % 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(taille(7_300_000_000), "7,3 Go");
        assert_eq!(taille(1_820_000_000), "1,8 Go");
        assert_eq!(taille(512_000_000), "512 Mo");
        assert_eq!(taille(999), "999 o");
        assert_eq!(debit(4_600_000.0), "4,6 Mo/s");
        assert_eq!(duree(Duration::from_secs(30)), "moins d'une minute");
        assert_eq!(duree(Duration::from_secs(20 * 60)), "environ 20 min");
        assert_eq!(duree(Duration::from_secs(75 * 60)), "environ 1 h 15");
    }

    #[test]
    fn vitesse_et_restant() {
        let t = Instant::now();
        let mut m = Mesure::default();
        m.ajouter(t, 0);
        assert!(m.vitesse().is_none());
        m.ajouter(t + Duration::from_secs(1), 4_000_000);
        assert!(m.vitesse().is_none(), "trop tôt pour mesurer");
        m.ajouter(t + Duration::from_secs(10), 40_000_000);
        assert_eq!(m.vitesse().unwrap().round(), 4_000_000.0);
        // 60 Mo restants à 4 Mo/s : 15 s
        assert_eq!(m.restant(100_000_000).unwrap().as_secs(), 15);
    }

    #[test]
    fn fenetre_glissante() {
        let t = Instant::now();
        let mut m = Mesure::default();
        // 100 s à 1 Mo/s puis 10 s à 10 Mo/s : la vitesse suit le régime récent
        for s in 0..=100 {
            m.ajouter(t + Duration::from_secs(s), s * 1_000_000);
        }
        for s in 1..=30 {
            m.ajouter(
                t + Duration::from_secs(100 + s),
                100_000_000 + s * 10_000_000,
            );
        }
        assert!(m.vitesse().unwrap() > 9_000_000.0);
    }

    #[test]
    fn compteur_remis_a_zero() {
        let t = Instant::now();
        let mut m = Mesure::default();
        m.ajouter(t, 50);
        m.ajouter(t + Duration::from_secs(5), 10);
        assert!(m.vitesse().is_none());
    }
}
