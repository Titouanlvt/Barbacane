//! Objets 3D pré-calculés de la charte v2 (`docs/charte/3d/`, composant Objets3D) : une bande PNG
//! par séquence et par thème, images carrées de 240 px côte à côte.
//!
//! Rendu : la bande entière est chargée UNE fois en poignée d'image (iced la décode et la garde en
//! cache tant que la poignée est la même) ; chaque trame la décale derrière une fenêtre de découpage
//! de la taille d'une image. Aucune 3D ni mise à l'échelle par trame (charte, realisation.md).

use crate::app::Msg;
use crate::style;
use iced::widget::image;
use iced::{Element, Length};

/// Côté d'une image dans les bandes (sequences.json, `cote`).
pub const COTE: f32 = 240.0;

// Herse (verdict bloqué), clé blanche (blanchiment) et disque (gravure) : étapes 5–6 de la charte.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Seq {
    EmblemePivot,
    EmblemeConstruction,
    EmblemeHerse,
    Cle,
    CleDestination,
    CleBlanche,
    Bouclier,
    Disque,
}

impl Seq {
    /// (images, images par seconde) — docs/charte/3d/sequences.json (vérifié par un test).
    pub const fn format(self) -> (u32, u32) {
        match self {
            Seq::EmblemePivot => (24, 15),
            Seq::EmblemeConstruction => (32, 15),
            Seq::EmblemeHerse => (16, 30),
            Seq::Cle => (16, 30),
            Seq::CleDestination => (16, 30),
            Seq::CleBlanche => (1, 1),
            Seq::Bouclier => (14, 30),
            Seq::Disque => (18, 30),
        }
    }

    #[cfg(test)]
    fn nom(self) -> &'static str {
        match self {
            Seq::EmblemePivot => "embleme-pivot",
            Seq::EmblemeConstruction => "embleme-construction",
            Seq::EmblemeHerse => "embleme-herse",
            Seq::Cle => "cle",
            Seq::CleDestination => "cle-destination",
            Seq::CleBlanche => "cle-blanche",
            Seq::Bouclier => "bouclier",
            Seq::Disque => "disque",
        }
    }

    fn octets(self, nuit: bool) -> &'static [u8] {
        macro_rules! bande {
            ($n:literal) => {
                if nuit {
                    include_bytes!(concat!("../../../docs/charte/3d/", $n, "-nuit.png")).as_slice()
                } else {
                    include_bytes!(concat!("../../../docs/charte/3d/", $n, "-jour.png")).as_slice()
                }
            };
        }
        match self {
            Seq::EmblemePivot => bande!("embleme-pivot"),
            Seq::EmblemeConstruction => bande!("embleme-construction"),
            Seq::EmblemeHerse => bande!("embleme-herse"),
            Seq::Cle => bande!("cle"),
            Seq::CleDestination => bande!("cle-destination"),
            Seq::CleBlanche => bande!("cle-blanche"),
            Seq::Bouclier => bande!("bouclier"),
            Seq::Disque => bande!("disque"),
        }
    }

    /// Image `i` pour le thème courant. La bande est décodée une seule fois et découpée en
    /// images RGBA (le découpage par `clip` n'est pas respecté par le rendu tiny-skia).
    fn poignee(self, i: u32) -> image::Handle {
        let nuit = style::est_nuit();
        BANDES.with(|b| {
            let mut b = b.borrow_mut();
            let images = b
                .entry((self, nuit))
                .or_insert_with(|| decouper(self.octets(nuit)));
            images[(i as usize).min(images.len().saturating_sub(1))].clone()
        })
    }

    /// Image correspondant à l'avancement `p` (0 → 1) d'une séquence jouée une fois.
    pub fn image_avancement(self, p: f32) -> u32 {
        let (n, _) = self.format();
        ((p.clamp(0.0, 1.0) * (n - 1) as f32).round() as u32).min(n - 1)
    }

    /// Image au temps `t` (s) d'une séquence en boucle ; `aller_retour` : 0‥n-1‥0.
    pub fn image_boucle(self, t: f32, aller_retour: bool) -> u32 {
        let (n, ips) = self.format();
        let k = (t.max(0.0) * ips as f32) as u32;
        if aller_retour && n > 1 {
            let periode = 2 * (n - 1);
            let i = k % periode;
            if i < n { i } else { periode - i }
        } else {
            k % n
        }
    }
}

thread_local! {
    static BANDES: std::cell::RefCell<std::collections::HashMap<(Seq, bool), Vec<image::Handle>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Découpe une bande PNG horizontale d'images carrées (côté = hauteur) en poignées RGBA.
fn decouper(png: &'static [u8]) -> Vec<image::Handle> {
    let Ok(img) = ::image::load_from_memory_with_format(png, ::image::ImageFormat::Png) else {
        return vec![image::Handle::from_bytes(png)];
    };
    let rgba = img.to_rgba8();
    let cote = rgba.height();
    (0..rgba.width() / cote.max(1))
        .map(|k| {
            let v = ::image::imageops::crop_imm(&rgba, k * cote, 0, cote, cote).to_image();
            image::Handle::from_rgba(cote, cote, v.into_raw())
        })
        .collect()
}

/// Image `i` de la séquence, affichée à `cote` px (240 ou 120 : taille de rendu ou sa moitié exacte).
pub fn vue<'a>(s: Seq, i: u32, cote: f32) -> Element<'a, Msg> {
    let (n, _) = s.format();
    image(s.poignee(i.min(n - 1)))
        .width(Length::Fixed(cote))
        .height(Length::Fixed(cote))
        .into()
}

#[cfg(test)]
mod tests {
    use super::Seq;

    #[test]
    fn format_conforme_a_sequences_json() {
        let j: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/charte/3d/sequences.json")).unwrap();
        assert_eq!(j["cote"], 240);
        for s in [
            Seq::EmblemePivot,
            Seq::EmblemeConstruction,
            Seq::EmblemeHerse,
            Seq::Cle,
            Seq::CleDestination,
            Seq::CleBlanche,
            Seq::Bouclier,
            Seq::Disque,
        ] {
            let (n, ips) = s.format();
            assert_eq!(j["sequences"][s.nom()]["images"], n, "{}", s.nom());
            assert_eq!(j["sequences"][s.nom()]["ips"], ips, "{}", s.nom());
            // Largeur de la bande PNG = n × 240 (en-tête IHDR)
            for nuit in [false, true] {
                let o = s.octets(nuit);
                let l = u32::from_be_bytes([o[16], o[17], o[18], o[19]]);
                let h = u32::from_be_bytes([o[20], o[21], o[22], o[23]]);
                assert_eq!((l, h), (240 * n, 240), "{} nuit={nuit}", s.nom());
            }
        }
    }

    #[test]
    fn boucles() {
        assert_eq!(Seq::EmblemePivot.image_boucle(0.0, true), 0);
        // 15 i/s, 24 images, aller-retour : période 46 images
        assert_eq!(Seq::EmblemePivot.image_boucle(23.0 / 15.0, true), 23);
        assert_eq!(Seq::EmblemePivot.image_boucle(24.0 / 15.0, true), 22);
        assert_eq!(Seq::Disque.image_boucle(18.0 / 30.0, false), 0);
        assert_eq!(Seq::Bouclier.image_avancement(1.0), 13);
        assert_eq!(Seq::Bouclier.image_avancement(0.0), 0);
    }
}
