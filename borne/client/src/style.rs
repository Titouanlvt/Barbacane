//! Charte graphique Barbacane, thèmes « Pierre » et « Nuit » (docs/charte/tokens.json).
//!
//! Lisible à un mètre, souris en main : contrastes ≥ 4,5:1, grandes cibles.
//! Le laiton est la couleur d'identité (logo, focus) ; les couleurs d'état
//! (sain, alerte, menace, analyse) ne servent qu'à leur sens.

use iced::widget::{button, container};
use iced::{Background, Border, Color, Font, Shadow, Theme, border::Radius, font};
use std::sync::atomic::{AtomicBool, Ordering};

const fn hex(c: u32) -> Color {
    Color::from_rgb8((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

/// Jetons de couleur de la charte, pour un thème.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub surface: Color,
    pub surface_haute: Color,
    pub trait_: Color,
    pub encre: Color,
    pub encre_douce: Color,
    pub sur_encre: Color,
    pub laiton: Color,
    pub laiton_pale: Color,
    pub sain: Color,
    pub sain_fond: Color,
    pub alerte: Color,
    pub alerte_fond: Color,
    pub menace: Color,
    pub menace_fond: Color,
    pub analyse: Color,
    pub analyse_fond: Color,
    /// Bandeau supérieur (encre en Pierre, granite surélevé en Nuit)
    pub bandeau: Color,
    pub sur_bandeau: Color,
}

/// Thème « Pierre » (clair, par défaut).
pub const PIERRE: Palette = Palette {
    surface: hex(0xEEEBE4),
    surface_haute: hex(0xF8F6F2),
    trait_: hex(0xCFC9BD),
    encre: hex(0x1C1F22),
    encre_douce: hex(0x565B5F),
    sur_encre: hex(0xF8F6F2),
    laiton: hex(0x8A6420),
    laiton_pale: hex(0xE9DCC0),
    sain: hex(0x1E6B45),
    sain_fond: hex(0xDDEFE3),
    alerte: hex(0x8F5300),
    alerte_fond: hex(0xF7E6C8),
    menace: hex(0xA8231B),
    menace_fond: hex(0xF6D9D5),
    analyse: hex(0x285A86),
    analyse_fond: hex(0xDCE7F2),
    bandeau: hex(0x1C1F22),
    sur_bandeau: hex(0xF8F6F2),
};

/// Thème « Nuit » (sombre, salles peu éclairées) : mêmes rôles, contrastes ≥ 4,5:1.
pub const NUIT: Palette = Palette {
    surface: hex(0x15181B),
    surface_haute: hex(0x1F2327),
    trait_: hex(0x343A40),
    encre: hex(0xECE8E0),
    encre_douce: hex(0xA9ABA7),
    sur_encre: hex(0x15181B),
    laiton: hex(0xD4A64A),
    laiton_pale: hex(0x3A3020),
    sain: hex(0x5CC48F),
    sain_fond: hex(0x15301F),
    alerte: hex(0xF0A93C),
    alerte_fond: hex(0x372812),
    menace: hex(0xFF7B6E),
    menace_fond: hex(0x3D1A17),
    analyse: hex(0x7FB2E0),
    analyse_fond: hex(0x172838),
    bandeau: hex(0x0E1012),
    sur_bandeau: hex(0xECE8E0),
};

static THEME_NUIT: AtomicBool = AtomicBool::new(false);
static ANIMATIONS_REDUITES: AtomicBool = AtomicBool::new(false);

/// Palette du thème choisi par l'administrateur (barbacane-admind, « Affichage »).
pub fn c() -> &'static Palette {
    if THEME_NUIT.load(Ordering::Relaxed) {
        &NUIT
    } else {
        &PIERRE
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
        if est_nuit() { "Nuit" } else { "Pierre" }.to_string(),
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
            background: Some(Background::Color(Color { a: 0.35, ..c().menace })),
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
