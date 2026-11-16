//! Courbes des animations de la charte (docs/charte/components/AnimationAnalyse).
//!
//! Rendu logiciel (tiny-skia) : uniquement des translations et des échelles de formes pleines,
//! 30 images/s au plus, ni flou ni transparence animée. Chaque fonction prend l'avancement
//! `p` de 0 à 1 et rend l'état final pour `p = 1`.

/// Approximation de `cubic-bezier(.5,0,.3,1)` (glissement de la clé) : départ doux, arrivée douce.
pub fn ease_bezier(p: f32) -> f32 {
    let p = p.clamp(0.0, 1.0);
    if p < 0.5 {
        4.0 * p * p * p
    } else {
        1.0 - (-2.0 * p + 2.0).powi(3) / 2.0
    }
}

/// `ease-out` cubique.
pub fn ease_out(p: f32) -> f32 {
    1.0 - (1.0 - p.clamp(0.0, 1.0)).powi(3)
}

/// Bouclier « sain » : 60 % → 108 % → 100 %.
pub fn echelle_bouclier(p: f32) -> f32 {
    let p = p.clamp(0.0, 1.0);
    if p < 0.7 {
        0.6 + 0.48 * ease_out(p / 0.7)
    } else {
        1.08 - 0.08 * ease_out((p - 0.7) / 0.3)
    }
}

/// Herse : chute (0 → 1) pendant 60 % du temps, puis léger tremblement horizontal amorti.
/// Renvoie (chute, décalage horizontal en px).
pub fn herse(p: f32) -> (f32, f32) {
    let p = p.clamp(0.0, 1.0);
    if p >= 1.0 {
        (1.0, 0.0)
    } else if p < 0.6 {
        (ease_bezier(p / 0.6), 0.0)
    } else {
        let q = (p - 0.6) / 0.4;
        (
            1.0,
            (q * std::f32::consts::PI * 6.0).sin() * 4.0 * (1.0 - q),
        )
    }
}

/// Faisceau d'analyse : position verticale (0 en haut, 1 en bas), 1,6 s par aller,
/// aller-retour en boucle, `ease-in-out`.
pub fn balayage(t: f32) -> f32 {
    let phase = (t / 1.6).rem_euclid(2.0);
    let p = if phase < 1.0 { phase } else { 2.0 - phase };
    ease_bezier(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etats_finaux() {
        assert_eq!(ease_bezier(1.0), 1.0);
        assert_eq!(ease_bezier(0.0), 0.0);
        assert!((echelle_bouclier(0.0) - 0.6).abs() < 1e-6);
        assert!((echelle_bouclier(1.0) - 1.0).abs() < 1e-6);
        assert_eq!(herse(1.0), (1.0, 0.0));
        assert_eq!(herse(0.0).0, 0.0);
    }

    #[test]
    fn bouclier_depasse_puis_revient() {
        let max = (0..=100)
            .map(|i| echelle_bouclier(i as f32 / 100.0))
            .fold(0.0, f32::max);
        assert!((max - 1.08).abs() < 0.01, "{max}");
    }

    #[test]
    fn balayage_aller_retour() {
        assert_eq!(balayage(0.0), 0.0);
        assert!((balayage(1.6) - 1.0).abs() < 1e-5);
        assert!(balayage(3.2) < 1e-5);
        for i in 0..100 {
            let y = balayage(i as f32 * 0.07);
            assert!((0.0..=1.0).contains(&y));
        }
    }

    #[test]
    fn tremblement_borne() {
        for i in 0..=100 {
            assert!(herse(i as f32 / 100.0).1.abs() <= 4.0);
        }
    }
}
