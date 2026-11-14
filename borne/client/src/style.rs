//! Charte graphique Barbacane, thème « Pierre » (docs/charte/tokens.json).
//!
//! Lisible à un mètre, souris en main : contrastes ≥ 4,5:1, grandes cibles.
//! Le laiton est la couleur d'identité (logo, focus) ; les couleurs d'état
//! (sain, alerte, menace, analyse) ne servent qu'à leur sens.

use iced::widget::{button, container, progress_bar};
use iced::{Background, Border, Color, Font, Shadow, Theme, border::Radius, font};

const fn hex(c: u32) -> Color {
    Color::from_rgb8((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

// Jetons de la charte (thème Pierre)
pub const SURFACE: Color = hex(0xEEEBE4);
pub const SURFACE_HAUTE: Color = hex(0xF8F6F2);
pub const TRAIT: Color = hex(0xCFC9BD);
pub const ENCRE: Color = hex(0x1C1F22);
pub const ENCRE_DOUCE: Color = hex(0x565B5F);
pub const SUR_ENCRE: Color = hex(0xF8F6F2);
pub const SAIN: Color = hex(0x1E6B45);
pub const SAIN_FOND: Color = hex(0xDDEFE3);
pub const ALERTE: Color = hex(0x8F5300);
pub const ALERTE_FOND: Color = hex(0xF7E6C8);
pub const MENACE: Color = hex(0xA8231B);
pub const MENACE_FOND: Color = hex(0xF6D9D5);
pub const ANALYSE: Color = hex(0x285A86);
pub const ANALYSE_FOND: Color = hex(0xDCE7F2);

// Noms historiques, alignés sur la charte
pub const BLEU: Color = ENCRE;
pub const ROUGE: Color = MENACE;
pub const GRIS: Color = ENCRE_DOUCE;

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
    let bg = match status {
        button::Status::Hovered => Color { a: 0.88, ..bg },
        button::Status::Pressed => Color { a: 0.75, ..bg },
        button::Status::Disabled => Color { a: 0.35, ..bg },
        button::Status::Active => bg,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: fg,
        border: Border::default().rounded(Radius::new(8)),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Bouton principal : un seul par écran, en bas à droite.
pub fn primaire(_: &Theme, s: button::Status) -> button::Style {
    base(ENCRE, SUR_ENCRE, s)
}

/// Annuler, Retour.
pub fn secondaire(_: &Theme, s: button::Status) -> button::Style {
    let mut st = base(SURFACE_HAUTE, ENCRE, s);
    st.border = Border::default()
        .rounded(Radius::new(8))
        .width(2)
        .color(ENCRE);
    st
}

/// Effacement : toujours suivi d'une confirmation.
pub fn danger(_: &Theme, s: button::Status) -> button::Style {
    base(MENACE, SUR_ENCRE, s)
}

pub fn discret(_: &Theme, s: button::Status) -> button::Style {
    base(Color::TRANSPARENT, ENCRE_DOUCE, s)
}

pub fn key(_: &Theme, s: button::Status) -> button::Style {
    let fond = if matches!(s, button::Status::Hovered) {
        hex(0xE9DCC0) // laiton pâle
    } else {
        SURFACE_HAUTE
    };
    let mut st = base(fond, ENCRE, button::Status::Active);
    if matches!(s, button::Status::Pressed) {
        st.background = Some(Background::Color(TRAIT));
    }
    st.border = Border::default()
        .rounded(Radius::new(4))
        .width(1)
        .color(TRAIT);
    st
}

/// Bandeau supérieur : encre, logo et nom de la borne.
pub fn bandeau(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(ENCRE)),
        text_color: Some(SUR_ENCRE),
        ..Default::default()
    }
}

pub fn carte(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE_HAUTE)),
        border: Border::default()
            .rounded(Radius::new(16))
            .width(1)
            .color(TRAIT),
        text_color: Some(ENCRE),
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
        text_color: Some(ENCRE),
        ..Default::default()
    }
}

pub fn alerte(t: &Theme) -> container::Style {
    verdict(ALERTE_FOND, ALERTE)(t)
}

pub fn fond(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE)),
        text_color: Some(ENCRE),
        ..Default::default()
    }
}

/// Jauge des traitements en cours.
pub fn jauge(_: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(ANALYSE_FOND),
        bar: Background::Color(ANALYSE),
        border: Border::default().rounded(Radius::new(8)),
    }
}
