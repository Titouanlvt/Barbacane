//! Charte graphique Barbacane v2, thèmes « Jour » et « Nuit » (docs/charte/jetons.toml, via build.rs).
//!
//! Lisible à un mètre, souris en main : contrastes ≥ 4,5:1, grandes cibles.
//! Le laiton est la couleur d'identité (logo, focus) ; les couleurs d'état
//! (sain, alerte, menace, analyse) ne servent qu'à leur sens.

use iced::widget::{button, container};
use iced::{Background, Border, Color, Font, Shadow, Theme, border::Radius, font};
use std::sync::atomic::{AtomicBool, Ordering};

const fn hexa(c: u32, a: u8) -> Color {
    Color::from_rgba8((c >> 16) as u8, (c >> 8) as u8, c as u8, a as f32 / 255.0)
}

// Palette, JOUR et NUIT : générés par build.rs depuis docs/charte/jetons.toml (charte v2).
include!(concat!(env!("OUT_DIR"), "/jetons.rs"));

static THEME_NUIT: AtomicBool = AtomicBool::new(false);
static ANIMATIONS_REDUITES: AtomicBool = AtomicBool::new(false);

/// Palette du thème choisi par l'administrateur (barbacane-admind, « Affichage »).
pub fn c() -> &'static Palette {
    if THEME_NUIT.load(Ordering::Relaxed) {
        &NUIT
    } else {
        &JOUR
    }
}

pub fn set_nuit(on: bool) {
    THEME_NUIT.store(on, Ordering::Relaxed);
}

pub fn est_nuit() -> bool {
    THEME_NUIT.load(Ordering::Relaxed)
}

/// Option « Animations réduites » : les animations affichent directement leur état final.
pub fn set_animations_reduites(on: bool) {
    ANIMATIONS_REDUITES.store(on, Ordering::Relaxed);
}

pub fn animations_reduites() -> bool {
    ANIMATIONS_REDUITES.load(Ordering::Relaxed)
}

/// Thème iced (couleur du texte par défaut, barres de défilement…) aligné sur la palette.
pub fn theme_iced() -> Theme {
    let p = c();
    Theme::custom(
        if est_nuit() { "Nuit" } else { "Jour" }.to_string(),
        iced::theme::Palette {
            background: p.surface,
            text: p.encre,
            primary: p.laiton,
            success: p.sain,
            warning: p.alerte,
            danger: p.menace,
        },
    )
}

// Typographie (polices embarquées, voir app::run)
pub const TITRE_POLICE: Font = Font {
    weight: font::Weight::Semibold,
    ..Font::with_name("Barlow Condensed")
};
pub const CORPS: Font = Font::with_name("Atkinson Hyperlegible");
pub const CORPS_GRAS: Font = Font {
    weight: font::Weight::Bold,
    ..Font::with_name("Atkinson Hyperlegible")
};
pub const MONO: Font = Font::with_name("JetBrains Mono");

pub const TITRE: f32 = 48.0;
pub const SOUS_TITRE: f32 = 30.0;
pub const TEXTE_TAILLE: f32 = 22.0;
pub const PETIT: f32 = 18.0;

fn base(bg: Color, fg: Color, status: button::Status) -> button::Style {
    let mut st = relief(bg, bg, fg, Color::TRANSPARENT, status);
    st.border = Border::default().rounded(Radius::new(8));
    st
}

/// Dégradé vertical du relief (charte v2, relief.md) : `haut` → `bas`, avec l'arête de lumière de
/// la face supérieure dans le premier arrêt (une seule lumière, en haut à gauche).
pub fn degrade(haut: Color, bas: Color) -> Background {
    use iced::gradient::{Gradient, Linear};
    let arete = melange_alpha(c().lumiere, haut);
    Background::Gradient(Gradient::Linear(
        Linear::new(iced::Radians(std::f32::consts::PI))
            .add_stop(0.0, arete)
            .add_stop(0.03, haut)
            .add_stop(1.0, bas),
    ))
}

/// Bloc (niveau 2) : dégradé, bord de 1 px ; la tranche nette (4 px dessous) et l'ombre diffuse
/// sont posées derrière par `app::en_relief`. Appui : face assombrie. Désactivé : À PLAT (charte v2 :
/// ce qui ne s'enfonce pas n'a ni tranche ni ombre), fond clair, texte `encre-douce`, bord `trait`.
fn relief(haut: Color, bas: Color, fg: Color, bord: Color, status: button::Status) -> button::Style {
    let (fond, texte, bord) = match status {
        button::Status::Disabled => (Background::Color(c().surface_haute), c().encre_douce, c().trait_),
        button::Status::Pressed => (Background::Color(melange(bas, c().encre, 0.9)), fg, bord),
        button::Status::Hovered => (degrade(melange(haut, Color::WHITE, 0.92), bas), fg, bord),
        _ => (degrade(haut, bas), fg, bord),
    };
    button::Style {
        background: Some(fond),
        text_color: texte,
        border: Border::default().rounded(Radius::new(8)).width(1).color(bord),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Couleur de la tranche du relief selon la variante (charte v2, « Variantes de tranche ») :
/// principal `laiton-fonce`, secondaire `trait-fort`, destructif `menace-fonce` ; `None` : plat.
pub fn tranche(s: fn(&Theme, button::Status) -> button::Style) -> Option<Color> {
    use std::ptr::fn_addr_eq;
    type F = fn(&Theme, button::Status) -> button::Style;
    if fn_addr_eq(s, primaire as F) {
        Some(c().laiton_fonce)
    } else if fn_addr_eq(s, secondaire as F) {
        Some(c().trait_fort)
    } else if fn_addr_eq(s, danger as F) {
        Some(c().menace_fonce)
    } else {
        None
    }
}

/// Bouton principal : un seul par écran, en bas à droite (fond `encre` en dégradé).
pub fn primaire(_: &Theme, s: button::Status) -> button::Style {
    relief(c().encre_haut, c().encre_bas, c().sur_encre, c().encre_bas, s)
}

/// Annuler, Retour (bloc clair, bord `trait-fort`).
pub fn secondaire(_: &Theme, s: button::Status) -> button::Style {
    relief(c().bloc_haut, c().bloc_bas, c().encre, c().trait_fort, s)
}

/// Effacement : toujours suivi d'une confirmation (fond `menace`). Désactivé : rouge pâle à plat.
pub fn danger(_: &Theme, s: button::Status) -> button::Style {
    if matches!(s, button::Status::Disabled) {
        return button::Style {
            background: Some(Background::Color(melange(c().menace, c().surface, 0.4))),
            text_color: c().sur_encre,
            border: Border::default().rounded(Radius::new(8)),
            shadow: Shadow::default(),
            snap: true,
        };
    }
    relief(melange(c().menace, Color::WHITE, 0.9), c().menace, c().sur_encre, c().menace_fonce, s)
}

pub fn discret(_: &Theme, s: button::Status) -> button::Style {
    base(Color::TRANSPARENT, c().encre_douce, s)
}

pub fn key(_: &Theme, s: button::Status) -> button::Style {
    let fond = if matches!(s, button::Status::Hovered) {
        c().laiton_pale
    } else {
        c().surface_haute
    };
    let mut st = base(fond, c().encre, button::Status::Active);
    if matches!(s, button::Status::Pressed) {
        st.background = Some(Background::Color(c().trait_));
    }
    st.border = Border::default()
        .rounded(Radius::new(4))
        .width(1)
        .color(c().trait_);
    st
}

/// Bandeau supérieur : encre, logo et nom de la borne.
pub fn bandeau(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c().bandeau)),
        text_color: Some(c().sur_bandeau),
        ..Default::default()
    }
}

pub fn carte(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c().surface_haute)),
        border: Border::default()
            .rounded(Radius::new(16))
            .width(1)
            .color(c().trait_),
        text_color: Some(c().encre),
        ..Default::default()
    }
}

/// Bandeau de verdict : fond et bordure de la couleur d'état.
pub fn verdict(fond: Color, bord: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(fond)),
        border: Border::default()
            .rounded(Radius::new(16))
            .width(2)
            .color(bord),
        text_color: Some(c().encre),
        ..Default::default()
    }
}

pub fn alerte(t: &Theme) -> container::Style {
    verdict(c().alerte_fond, c().alerte)(t)
}

pub fn fond(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(c().surface)),
        text_color: Some(c().encre),
        ..Default::default()
    }
}

/// Mélange opaque de deux couleurs : `part` de `a`, le reste de `b`.
pub fn melange(a: Color, b: Color, part: f32) -> Color {
    Color {
        r: a.r * part + b.r * (1.0 - part),
        g: a.g * part + b.g * (1.0 - part),
        b: a.b * part + b.b * (1.0 - part),
        a: 1.0,
    }
}

/// Couleur translucide `a` posée sur `fond` opaque, calculée une fois (tiny-skia mélange plus vite
/// une couleur opaque ; charte v2, relief.md).
pub fn melange_alpha(a: Color, fond: Color) -> Color {
    melange(Color { a: 1.0, ..a }, fond, a.a)
}
