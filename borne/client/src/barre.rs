//! Barre de progression de la charte (composant BarreProgression) : elle bouge toujours, même
//! quand le pourcentage est bloqué sur un gros fichier.
//!
//! - rayures pleines qui défilent dans la partie remplie (un motif par 0,9 s) ;
//! - tête laiton au bout, qui pulse toutes les 1,2 s (changement de couleur, pas de transparence) ;
//! - variante « navette » quand le total est inconnu (bloc de 30 % en aller-retour, 1,6 s).
//!
//! Animations réduites : ni rayures ni pulsation (le chronomètre, à côté, continue d'avancer).

use crate::anim;
use crate::app::Msg;
use crate::style;
use iced::widget::{Space, container, row, stack};
use iced::{Background, Border, Color, Element, Length};

const HAUTEUR: f32 = 24.0;
const RAYURE: f32 = 12.0;

fn melange(a: Color, b: Color, t: f32) -> Color {
    Color::from_rgb(
        a.r + (b.r - a.r) * t,
        a.g + (b.g - a.g) * t,
        a.b + (b.b - a.b) * t,
    )
}

fn aplat<'a>(l: f32, h: f32, c: Color, rayon: f32) -> Element<'a, Msg> {
    container(Space::new().width(l).height(h))
        .style(move |_| container::Style {
            background: Some(Background::Color(c)),
            border: Border::default().rounded(rayon),
            ..Default::default()
        })
        .into()
}

/// `fraction` : avancement 0‥1, ou `None` si le total n'est pas encore connu (navette).
/// `t` : secondes écoulées (horloge de l'animation).
pub fn barre<'a>(fraction: Option<f32>, t: f32, largeur: f32) -> Element<'a, Msg> {
    let p = style::c();
    let reduites = style::animations_reduites();
    let mut couches = stack![aplat(largeur, HAUTEUR, p.analyse_fond, 8.0)];
    match fraction {
        Some(f) => {
            let rempli = (largeur * f.clamp(0.0, 1.0)).round();
            if rempli > 0.0 {
                // Rayures : bandes pleines décalées d'une période par 0,9 s (translation).
                let decalage = if reduites {
                    0.0
                } else {
                    (t / 0.9).rem_euclid(1.0) * 2.0 * RAYURE
                };
                let raie = melange(p.analyse, p.analyse_fond, 0.35);
                // Motif : bande de 12 px puis vide de 12 px, commencé à `decalage` ; la bande
                // précédente déborde à gauche si le décalage dépasse une demi-période.
                let mut bandes = if decalage > RAYURE {
                    row![
                        aplat(decalage - RAYURE, HAUTEUR, raie, 0.0),
                        Space::new().width(RAYURE)
                    ]
                } else {
                    row![Space::new().width(decalage)]
                };
                let n = (rempli / (2.0 * RAYURE)).ceil() as usize + 1;
                for _ in 0..n {
                    bandes = bandes
                        .push(aplat(RAYURE, HAUTEUR, raie, 0.0))
                        .push(Space::new().width(RAYURE));
                }
                let remplissage = container(stack![
                    aplat(rempli, HAUTEUR, p.analyse, 0.0),
                    if reduites {
                        Element::from(Space::new().width(0))
                    } else {
                        Element::from(bandes)
                    },
                ])
                .width(rempli)
                .height(HAUTEUR)
                .clip(true);
                couches = couches.push(remplissage);
            }
            // Tête laiton : pulse (laiton ↔ laiton pâle) toutes les 1,2 s.
            let allumee = reduites || (t / 1.2).rem_euclid(1.0) < 0.5;
            let tete = if allumee { p.laiton } else { p.laiton_pale };
            couches = couches.push(row![
                Space::new().width((rempli - 6.0).max(0.0)),
                aplat(6.0, HAUTEUR, tete, 0.0)
            ]);
        }
        None => {
            let phase = (t / 1.6).rem_euclid(2.0);
            let q = if reduites {
                0.5
            } else {
                anim::ease_bezier(if phase < 1.0 { phase } else { 2.0 - phase })
            };
            couches = couches.push(row![
                Space::new().width(largeur * 0.7 * q),
                aplat(largeur * 0.3, HAUTEUR, p.analyse, 8.0)
            ]);
        }
    }
    container(couches)
        .width(Length::Fixed(largeur))
        .height(Length::Fixed(HAUTEUR))
        .clip(true)
        .style(move |_| container::Style {
            border: Border::default().rounded(8).width(1).color(p.trait_),
            ..Default::default()
        })
        .into()
}

/// Chronomètre de la charte : « 6 min 02 s ».
pub fn chrono(secondes: u64) -> String {
    format!("{} min {:02} s", secondes / 60, secondes % 60)
}

#[cfg(test)]
mod tests {
    #[test]
    fn chrono() {
        assert_eq!(super::chrono(0), "0 min 00 s");
        assert_eq!(super::chrono(362), "6 min 02 s");
    }
}
