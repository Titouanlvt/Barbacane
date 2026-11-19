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
    relief(bg, fg, None, status)
}

/// Bouton (charte, composant Bouton) : aplat, la tranche du relief est posée derrière par
/// `app::bouton` (rectangle plein décalé, comme le logo). L'appui assombrit le bouton.
fn relief(bg: Color, fg: Color, _tranche: Option<Color>, status: button::Status) -> button::Style {
    let (fond, texte) = match status {
        // Désactivé : bouton PLAT et clair, bordure grise, texte gris foncé lisible (convention
        // « indisponible »). Ni encre transparente (tranche laiton visible : paraissait actif), ni
        // aplat beige (18/11 : terne, texte peu lisible).
        button::Status::Disabled => (c().surface_haute, c().encre_douce),
        button::Status::Pressed => (Color { a: 0.82, ..bg }, fg),
        _ => (bg, fg),
    };
    // Désactivé (ex. « Effacer cette clé… » avant le branchement) : bordure grise pour que le
    // bouton reste visible sur la page.
    let border = if matches!(status, button::Status::Disabled) {
        Border::default()
            .rounded(Radius::new(8))
            .width(2)
            .color(c().trait_)
    } else {
        Border::default().rounded(Radius::new(8))
    };
    button::Style {
        background: Some(Background::Color(fond)),
        text_color: texte,
        border,
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Couleur de la tranche du relief selon la variante (principal : laiton, secondaire : trait,
/// destructif : encre) ; `None` : bouton plat.
pub fn tranche(s: fn(&Theme, button::Status) -> button::Style) -> Option<Color> {
    use std::ptr::fn_addr_eq;
    type F = fn(&Theme, button::Status) -> button::Style;
    if fn_addr_eq(s, primaire as F) {
        Some(c().laiton)
    } else if fn_addr_eq(s, secondaire as F) {
        Some(c().trait_)
    } else if fn_addr_eq(s, danger as F) {
        Some(c().encre)
    } else {
        None
    }
}

/// Bouton principal : un seul par écran, en bas à droite.
pub fn primaire(_: &Theme, s: button::Status) -> button::Style {
    relief(c().encre, c().sur_encre, Some(c().laiton), s)
}

/// Annuler, Retour.
pub fn secondaire(_: &Theme, s: button::Status) -> button::Style {
    let mut st = relief(c().surface_haute, c().encre, Some(c().trait_), s);
    st.border = Border::default().rounded(Radius::new(8)).width(2).color(
        if matches!(s, button::Status::Disabled) {
            c().trait_
        } else {
            c().encre
        },
    );
    st
}

/// Effacement : toujours suivi d'une confirmation.
pub fn danger(_: &Theme, s: button::Status) -> button::Style {
    if matches!(s, button::Status::Disabled) {
        // Indisponible (pas encore de destination) : même bouton rouge, pâli ; le relief (tranche) reste posé par app.rs
        return button::Style {
            // Opaque (mélange menace/surface) : une transparence laissait voir la tranche à travers
            background: Some(Background::Color(melange(c().menace, c().surface, 0.4))),
            text_color: c().sur_encre,
            border: Border::default().rounded(Radius::new(8)),
            shadow: Shadow::default(),
            snap: true,
        };
    }
    relief(c().menace, c().sur_encre, Some(c().encre), s)
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
fn melange(a: Color, b: Color, part: f32) -> Color {
    Color {
        r: a.r * part + b.r * (1.0 - part),
        g: a.g * part + b.g * (1.0 - part),
        b: a.b * part + b.b * (1.0 - part),
        a: 1.0,
    }
}
