//! Dessins en relief de la charte (composants AnimationBorne et AnimationAnalyse) et leurs
//! scènes animées.
//!
//! Chaque calque est un SVG de formes pleines (face avant, flanc décalé de 45°, laiton), colorié
//! avec la palette du thème courant ; le mouvement se fait uniquement par placement, échelle
//! de calques entiers (la rotation du disque est dessinée dans le SVG), ce que tiny-skia rend sans flou ni transparence animée.
//! Coordonnées dans une scène de 150 × 150 unités, comme les aperçus de la charte.

use crate::anim;
use crate::app::Msg;
use crate::style::{self, Palette};
use iced::widget::{Space, column, container, pin, stack, svg};
use iced::{Color, Element, Length, Point};

fn hx(c: Color) -> String {
    let [r, g, b, _] = c.into_rgba8();
    format!("#{r:02X}{g:02X}{b:02X}")
}

/// Un calque : viewBox et contenu SVG, couleurs `{encre}`, `{trait}`… remplacées par la palette.
fn calque(viewbox: &str, corps: &str) -> svg::Handle {
    let p: &Palette = style::c();
    let corps = corps
        .replace("{encre}", &hx(p.encre))
        .replace("{douce}", &hx(p.encre_douce))
        .replace("{trait}", &hx(p.trait_))
        .replace("{haute}", &hx(p.surface_haute))
        .replace("{surface}", &hx(p.surface))
        .replace("{laiton}", &hx(p.laiton))
        .replace("{pale}", &hx(p.laiton_pale))
        .replace("{analyse}", &hx(p.analyse))
        .replace("{sain}", &hx(p.sain))
        .replace("{sainfond}", &hx(p.sain_fond))
        .replace("{menace}", &hx(p.menace))
        .replace("{alerte}", &hx(p.alerte))
        .replace("{alertefond}", &hx(p.alerte_fond));
    svg::Handle::from_memory(
        format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"{viewbox}\">{corps}</svg>")
            .into_bytes(),
    )
}

/// Calque placé dans la scène : position (x, y) et taille (l, h) en unités de scène.
struct Pose {
    h: svg::Handle,
    x: f32,
    y: f32,
    l: f32,
    ht: f32,
    /// Fenêtre de découpage (x, y, l, h) : seule la partie du calque qui y tombe est visible.
    fenetre: Option<(f32, f32, f32, f32)>,
}

fn pose(h: svg::Handle, x: f32, y: f32, l: f32, ht: f32) -> Pose {
    Pose {
        h,
        x,
        y,
        l,
        ht,
        fenetre: None,
    }
}

/// Place `e` en (x, y) px, décalages négatifs compris, dans une zone de `l` × `h` px découpée.
fn zone<'a>(e: Element<'a, Msg>, x: f32, y: f32, l: f32, h: f32) -> Element<'a, Msg> {
    container(
        pin(e)
            .position(Point::new(x, y))
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(Length::Fixed(l))
    .height(Length::Fixed(h))
    .clip(true)
    .into()
}

/// Assemble les calques dans une scène carrée de `taille` px, découpée à ses bords.
fn scene<'a>(calques: Vec<Pose>, taille: f32) -> Element<'a, Msg> {
    let k = taille / 150.0;
    let mut s = stack![];
    for c in calques {
        let image: Element<'a, Msg> = svg(c.h).width(c.l * k).height(c.ht * k).into();
        let calque = match c.fenetre {
            None => zone(image, c.x * k, c.y * k, taille, taille),
            Some((fx, fy, fl, fh)) => {
                // Calque vu à travers une fenêtre (fx, fy, fl, fh), découpé à ses bords.
                let f = zone(image, (c.x - fx) * k, (c.y - fy) * k, fl * k, fh * k);
                zone(f, fx * k, fy * k, taille, taille)
            }
        };
        s = s.push(calque);
    }
    container(s)
        .width(Length::Fixed(taille))
        .height(Length::Fixed(taille))
        .clip(true)
        .into()
}

// ------------------------------------------------------------------ calques

const VB: &str = "0 0 150 150";

fn porte_ouverte() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"78\" y=\"30\" width=\"54\" height=\"90\" transform=\"translate(4 -4)\"/>\
         <path fill=\"{encre}\" fill-rule=\"evenodd\" d=\"M78 120V30h54v90ZM92 120V88a13 13 0 0 1 26 0v32Z\"/>\
         <path fill=\"{haute}\" d=\"M92 120V88a13 13 0 0 1 26 0v32Z\"/>",
    )
}

/// Clé USB en relief ; `laiton` : clé de destination (de confiance).
fn cle(laiton: bool) -> svg::Handle {
    let (corps, embout) = if laiton {
        ("{laiton}", "{pale}")
    } else {
        ("{encre}", "{douce}")
    };
    calque(
        VB,
        &format!(
            "<rect fill=\"{{trait}}\" x=\"44\" y=\"54\" width=\"60\" height=\"44\" rx=\"6\" transform=\"translate(4 -4)\"/>\
             <rect fill=\"{corps}\" x=\"44\" y=\"54\" width=\"60\" height=\"44\" rx=\"6\"/>\
             <rect fill=\"{{trait}}\" x=\"104\" y=\"64\" width=\"22\" height=\"24\" transform=\"translate(4 -4)\"/>\
             <rect fill=\"{embout}\" x=\"104\" y=\"64\" width=\"22\" height=\"24\"/>\
             <rect fill=\"{{haute}}\" x=\"110\" y=\"70\" width=\"5\" height=\"4\"/><rect fill=\"{{haute}}\" x=\"110\" y=\"78\" width=\"5\" height=\"4\"/>"
        ),
    )
}

fn fleche(allumee: bool) -> svg::Handle {
    calque(
        VB,
        if allumee {
            "<path fill=\"{laiton}\" d=\"M66 64h10v-6l10 10-10 10v-6H66Z\"/>"
        } else {
            "<path fill=\"{trait}\" d=\"M66 64h10v-6l10 10-10 10v-6H66Z\"/>"
        },
    )
}

/// Disque optique, tourné de `angle` degrés autour de son centre. La rotation est faite DANS le
/// dessin (pas de rotation d'image : mal rendue par tiny-skia, qui laissait une traînée).
fn disque(angle: u32) -> svg::Handle {
    calque(
        "29 24 92 92",
        &format!(
            "<circle fill=\"{{trait}}\" cx=\"75\" cy=\"70\" r=\"46\"/><g transform=\"rotate({angle} 75 70)\">\
             <circle fill=\"{{haute}}\" cx=\"75\" cy=\"70\" r=\"40\"/>\
             <path fill=\"{{laiton}}\" d=\"M75 30a40 40 0 0 1 34.6 20L75 70Z\"/>\
             <path fill=\"{{analyse}}\" d=\"M40.4 90A40 40 0 0 1 35 70h40Z\"/></g>\
             <circle fill=\"{{trait}}\" cx=\"75\" cy=\"70\" r=\"13\"/><circle fill=\"{{surface}}\" cx=\"75\" cy=\"70\" r=\"6\"/>"
        ),
    )
}

fn tiroir() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"18\" y=\"112\" width=\"114\" height=\"22\" rx=\"3\" transform=\"translate(5 -5)\"/>\
         <rect fill=\"{encre}\" x=\"18\" y=\"112\" width=\"114\" height=\"22\" rx=\"3\"/>\
         <rect fill=\"{laiton}\" x=\"106\" y=\"120\" width=\"16\" height=\"4\" rx=\"2\"/>",
    )
}

fn tete_laser() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"108\" y=\"122\" width=\"26\" height=\"16\" rx=\"3\"/>\
         <rect fill=\"{encre}\" x=\"106\" y=\"124\" width=\"26\" height=\"16\" rx=\"3\"/>\
         <path fill=\"{analyse}\" d=\"M117 124 115 70h4Z\"/><circle fill=\"{analyse}\" cx=\"117\" cy=\"70\" r=\"3\"/>",
    )
}

fn fichiers_a_analyser() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"38\" y=\"38\" width=\"74\" height=\"84\" rx=\"4\" transform=\"translate(5 -5)\"/>\
         <rect fill=\"{encre}\" x=\"38\" y=\"38\" width=\"74\" height=\"84\" rx=\"4\"/>\
         <rect fill=\"{haute}\" x=\"48\" y=\"50\" width=\"54\" height=\"8\" rx=\"2\"/><rect fill=\"{haute}\" x=\"48\" y=\"66\" width=\"40\" height=\"8\" rx=\"2\"/>\
         <rect fill=\"{haute}\" x=\"48\" y=\"82\" width=\"48\" height=\"8\" rx=\"2\"/><rect fill=\"{haute}\" x=\"48\" y=\"98\" width=\"30\" height=\"8\" rx=\"2\"/>",
    )
}

fn faisceau() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{analyse}\" x=\"34\" y=\"44\" width=\"82\" height=\"4\" rx=\"2\"/>",
    )
}

fn bouclier() -> svg::Handle {
    calque(
        VB,
        "<path fill=\"{trait}\" d=\"M75 130s38-18 38-48V48L75 34 37 48v34c0 30 38 48 38 48Z\" transform=\"translate(5 -5)\"/>\
         <path fill=\"{sain}\" d=\"M75 130s38-18 38-48V48L75 34 37 48v34c0 30 38 48 38 48Z\"/>\
         <path d=\"m58 82 12 12 24-26\" fill=\"none\" stroke=\"{sainfond}\" stroke-width=\"9\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>",
    )
}

fn chateau() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"35\" y=\"30\" width=\"80\" height=\"100\" transform=\"translate(5 -5)\"/>\
         <path fill=\"{encre}\" fill-rule=\"evenodd\" d=\"M35 130V30h80v100ZM55 130V80a20 20 0 0 1 40 0v50Z\"/>\
         <path fill=\"{haute}\" d=\"M55 130V80a20 20 0 0 1 40 0v50Z\"/>",
    )
}

/// Herse (barreaux) dans un viewBox limité à la porte ; `couleur` : laiton ou menace.
fn herse(couleur: &str) -> svg::Handle {
    calque(
        "55 60 40 72",
        &format!(
            "<rect fill=\"{couleur}\" x=\"55\" y=\"78\" width=\"40\" height=\"5\"/><rect fill=\"{couleur}\" x=\"55\" y=\"94\" width=\"40\" height=\"5\"/>\
             <rect fill=\"{couleur}\" x=\"55\" y=\"110\" width=\"40\" height=\"5\"/><rect fill=\"{couleur}\" x=\"55\" y=\"126\" width=\"40\" height=\"5\"/>\
             <rect fill=\"{couleur}\" x=\"62\" y=\"60\" width=\"4\" height=\"72\"/><rect fill=\"{couleur}\" x=\"73\" y=\"60\" width=\"4\" height=\"72\"/>\
             <rect fill=\"{couleur}\" x=\"84\" y=\"60\" width=\"4\" height=\"72\"/>"
        ),
    )
}

fn porte_copie() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"50\" y=\"40\" width=\"50\" height=\"80\" transform=\"translate(4 -4)\"/>\
         <path fill=\"{encre}\" fill-rule=\"evenodd\" d=\"M50 120V40h50v80ZM62 120V84a13 13 0 0 1 26 0v36Z\"/>\
         <path fill=\"{haute}\" d=\"M62 120V84a13 13 0 0 1 26 0v36Z\"/>",
    )
}

fn fichier() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{analyse}\" x=\"62\" y=\"100\" width=\"14\" height=\"16\" rx=\"2\"/>",
    )
}

fn cle_a_effacer() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"40\" y=\"40\" width=\"70\" height=\"70\" rx=\"6\" transform=\"translate(4 -4)\"/>\
         <rect fill=\"{encre}\" x=\"40\" y=\"40\" width=\"70\" height=\"70\" rx=\"6\"/>\
         <rect fill=\"{haute}\" x=\"48\" y=\"52\" width=\"54\" height=\"48\" rx=\"2\"/>",
    )
}

fn contenu_a_effacer() -> svg::Handle {
    calque(
        "48 52 54 48",
        "<rect fill=\"{douce}\" x=\"54\" y=\"58\" width=\"40\" height=\"5\" rx=\"2\"/>\
         <rect fill=\"{douce}\" x=\"54\" y=\"70\" width=\"30\" height=\"5\" rx=\"2\"/>\
         <rect fill=\"{douce}\" x=\"54\" y=\"82\" width=\"36\" height=\"5\" rx=\"2\"/>",
    )
}

fn barre_laiton() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{laiton}\" x=\"44\" y=\"50\" width=\"62\" height=\"5\" rx=\"2\"/>",
    )
}

fn triangle_alerte() -> svg::Handle {
    calque(
        "50 20 50 44",
        "<path fill=\"{alerte}\" d=\"M75 22 98 62H52Z\"/>\
         <path d=\"M75 36v12M75 54v.5\" stroke=\"{alertefond}\" stroke-width=\"4\" stroke-linecap=\"round\"/>",
    )
}

fn sceau_sain() -> svg::Handle {
    calque(
        "86 38 36 36",
        "<circle fill=\"{sain}\" cx=\"104\" cy=\"56\" r=\"16\"/>\
         <path d=\"m96 56 6 6 10-11\" fill=\"none\" stroke=\"{sainfond}\" stroke-width=\"4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>",
    )
}

fn porte_fermee() -> svg::Handle {
    calque(
        VB,
        "<rect fill=\"{trait}\" x=\"45\" y=\"34\" width=\"60\" height=\"86\" transform=\"translate(4 -4)\"/>\
         <path fill=\"{encre}\" fill-rule=\"evenodd\" d=\"M45 120V34h60v86ZM60 120V86a15 15 0 0 1 30 0v34Z\"/>\
         <path fill=\"{haute}\" d=\"M60 120V86a15 15 0 0 1 30 0v34Z\"/>",
    )
}

fn petite_cle(laiton: bool) -> svg::Handle {
    calque(
        "0 0 34 22",
        if laiton {
            "<rect fill=\"{laiton}\" width=\"34\" height=\"22\" rx=\"4\"/>"
        } else {
            "<rect fill=\"{encre}\" width=\"34\" height=\"22\" rx=\"4\"/>"
        },
    )
}

// ------------------------------------------------------------------- scènes

/// Herse descendue de `dy`, visible seulement dans l'ouverture de la porte (x, y, l, h).
fn herse_dans_porte(couleur: &str, dx: f32, dy: f32, ouverture: (f32, f32, f32, f32)) -> Pose {
    let mut p = pose(herse(couleur), 55.0 + dx, 60.0 + dy, 40.0, 72.0);
    p.fenetre = Some((ouverture.0 + dx, ouverture.1, ouverture.2, ouverture.3));
    p
}

/// Accueil, en attente : la clé fait un aller-retour de 10 px vers la porte (2 s, en boucle),
/// la flèche laiton s'allume à mi-course.
pub fn attente<'a>(t: f32, taille: f32) -> Element<'a, Msg> {
    let phase = (t / 2.0).rem_euclid(1.0);
    let x = 10.0
        * anim::ease_bezier(if phase < 0.5 {
            phase * 2.0
        } else {
            2.0 - phase * 2.0
        });
    scene(
        vec![
            pose(porte_ouverte(), 0.0, 0.0, 150.0, 150.0),
            pose(cle(false), -30.0 + x, 20.0, 150.0, 150.0),
            pose(
                fleche((0.25..0.75).contains(&phase)),
                0.0,
                0.0,
                150.0,
                150.0,
            ),
        ],
        taille,
    )
}

/// Clé détectée : la clé glisse de 60 px vers la porte (600 ms, une fois).
pub fn cle_detectee<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let x = -60.0 + 60.0 * anim::ease_bezier(p);
    scene(vec![pose(cle(false), x, 0.0, 150.0, 150.0)], taille)
}

/// Disque détecté : le tiroir remonte de 40 px avec le disque (600 ms, une fois).
pub fn disque_detecte<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let y = 40.0 * (1.0 - anim::ease_bezier(p));
    scene(
        vec![
            pose(tiroir(), 0.0, y, 150.0, 150.0),
            pose(disque(0), 29.0, 24.0 + y, 92.0, 92.0),
        ],
        taille,
    )
}

/// Lecture du disque : il tourne (1 tour / 1,2 s), la tête laser parcourt les pistes.
pub fn lecture_disque<'a>(t: f32, taille: f32) -> Element<'a, Msg> {
    // Un tour par 1,2 s, par pas de 30° (12 images par tour).
    let angle = ((t / 1.2).rem_euclid(1.0) * 12.0) as u32 * 30;
    let d = pose(disque(angle), 29.0, 24.0, 92.0, 92.0);
    let phase = (t / 2.4).rem_euclid(2.0);
    let laser = -34.0 * anim::ease_bezier(if phase < 1.0 { phase } else { 2.0 - phase });
    scene(
        vec![
            pose(tiroir(), 0.0, 0.0, 150.0, 150.0),
            d,
            pose(tete_laser(), laser, -10.0, 150.0, 150.0),
        ],
        taille,
    )
}

/// Analyse : le faisceau balaie les fichiers de haut en bas (1,6 s par aller).
pub fn analyse<'a>(t: f32, taille: f32) -> Element<'a, Msg> {
    let y = 64.0 * anim::balayage(t);
    scene(
        vec![
            pose(fichiers_a_analyser(), 0.0, 0.0, 150.0, 150.0),
            pose(faisceau(), 0.0, y, 150.0, 150.0),
        ],
        taille,
    )
}

/// Sain : le bouclier s'impose, 60 % → 108 % → 100 % (500 ms, une fois).
pub fn sain<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let e = anim::echelle_bouclier(p) / 1.08;
    let l = 150.0 * e;
    scene(
        vec![pose(bouclier(), (150.0 - l) / 2.0, (150.0 - l) / 2.0, l, l)],
        taille,
    )
}

/// Menace : la herse tombe, la porte se ferme, léger tremblement (700 ms, une fois).
pub fn menace<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let (chute, dx) = anim::herse(p);
    let m = hx(style::c().menace);
    scene(
        vec![
            pose(chateau(), dx, 0.0, 150.0, 150.0),
            herse_dans_porte(&m, dx, -40.0 * (1.0 - chute), (55.0, 60.0, 40.0, 70.0)),
        ],
        taille,
    )
}

/// Copie : les fichiers sains traversent la porte, un toutes les 600 ms (1,8 s chacun).
pub fn copie<'a>(t: f32, taille: f32) -> Element<'a, Msg> {
    let mut c = vec![pose(porte_copie(), 0.0, 0.0, 150.0, 150.0)];
    for decalage in [0.0, 0.6, 1.2] {
        let q = ((t + decalage) / 1.8).rem_euclid(1.0);
        c.push(pose(fichier(), -50.0 + 120.0 * q, 0.0, 150.0, 150.0));
    }
    // La porte repasse devant les fichiers : ils « traversent » l'ouverture.
    scene(c, taille)
}

/// Effacement : une barre laiton descend par paliers et blanchit le contenu (suit `p`).
pub fn effacement<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let palier = (p.clamp(0.0, 1.0) * 6.0).floor() / 6.0;
    let reste = 48.0 * (1.0 - palier);
    let mut c = vec![pose(cle_a_effacer(), 0.0, 0.0, 150.0, 150.0)];
    if reste > 0.5 {
        // Contenu restant : partie basse du dessin, réduite par le haut.
        c.push(pose(
            contenu_a_effacer(),
            48.0,
            52.0 + 48.0 - reste,
            54.0,
            reste,
        ));
    }
    c.push(pose(barre_laiton(), 0.0, 44.0 * palier, 150.0, 150.0));
    scene(c, taille)
}

/// Clé de destination : la clé laiton arrive de la droite, le sceau vert confirme (900 ms).
pub fn destination<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let x = 60.0 * (1.0 - anim::ease_bezier((p / 0.55).min(1.0)));
    let mut c = vec![pose(cle(true), x - 4.0, 0.0, 150.0, 150.0)];
    if p > 0.55 {
        let e = anim::echelle_sceau((p - 0.55) / 0.45);
        let l = 36.0 * e;
        c.push(pose(sceau_sain(), 104.0 - l / 2.0, 56.0 - l / 2.0, l, l));
    }
    scene(c, taille)
}

/// Retrait : les deux clés repartent chacune de leur côté, la herse retombe (1,5 s).
pub fn retrait<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let sortie = anim::ease_bezier(((p - 0.2) / 0.35).clamp(0.0, 1.0));
    let ferme = anim::ease_bezier(((p - 0.55) / 0.25).clamp(0.0, 1.0));
    let l = hx(style::c().laiton);
    scene(
        vec![
            pose(petite_cle(false), 6.0 - 50.0 * sortie, 96.0, 34.0, 22.0),
            pose(petite_cle(true), 110.0 + 50.0 * sortie, 96.0, 34.0, 22.0),
            pose(porte_fermee(), 0.0, 0.0, 150.0, 150.0),
            herse_dans_porte(
                &l,
                2.0,
                12.0 - 34.0 * (1.0 - ferme),
                (60.0, 72.0, 30.0, 48.0),
            ),
        ],
        taille,
    )
}

/// Support illisible : la clé tremble trois fois, le triangle d'alerte apparaît (600 ms).
pub fn illisible<'a>(p: f32, taille: f32) -> Element<'a, Msg> {
    let dx = if p >= 1.0 {
        0.0
    } else {
        (p * std::f32::consts::PI * 6.0).sin() * 6.0 * (1.0 - p)
    };
    let e = anim::echelle_sceau(p);
    let (l, h) = (50.0 * e, 44.0 * e);
    scene(
        vec![
            pose(cle(false), -4.0 + dx, 10.0, 150.0, 150.0),
            pose(triangle_alerte(), 75.0 - l / 2.0, 42.0 - h / 2.0, l, h),
        ],
        taille,
    )
}

/// Démarrage : le logo monte du sol (2,2 s), puis le nom apparaît.
pub fn demarrage<'a>(p: f32, logo: &'static [u8], taille: f32) -> Element<'a, Msg> {
    let h = taille * anim::ease_out((p / 0.6).min(1.0));
    let logo = container(
        svg(svg::Handle::from_memory(logo))
            .width(taille)
            .height(taille),
    )
    .width(taille)
    .height(h)
    .align_bottom(h)
    .clip(true);
    column![
        Space::new().height(taille - h),
        logo,
        if p > 0.7 {
            Element::from(
                iced::widget::text("BARBACANE")
                    .size(taille * 0.16)
                    .font(style::TITRE_POLICE)
                    .color(style::c().encre),
            )
        } else {
            Space::new().height(taille * 0.2).into()
        },
    ]
    .align_x(iced::Alignment::Center)
    .into()
}
