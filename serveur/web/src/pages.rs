//! Pages de l'interface (charte v2, sans JavaScript). Fonctions pures : données en entrée,
//! HTML en sortie ; tout texte variable passe par [`Html::t`] (échappé).

use std::collections::BTreeMap;

use barbacane_audit::{Bilan, Enregistrement};
use barbacane_passerelle::maj::{EtatMaj, EtatMajBorne};
use barbacane_passerelle::outils::date_utc;
use barbacane_passerelle::registre::{Alerte, Borne, Demande, LigneSupervision};
use barbacane_protocole::EtatBorne;

use crate::comptes::Role;
use crate::html::Html;

/// Contexte d'une page authentifiée.
pub struct Contexte<'a> {
    pub compte: &'a str,
    pub role: Role,
    pub csrf: &'a str,
    pub maintenant: u64,
}

impl Contexte<'_> {
    fn admin(&self) -> bool {
        self.role == Role::Administrateur
    }
}

/// Rubrique de navigation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rubrique {
    Supervision,
    Enrolement,
    Maj,
    Audit,
}

const SYMBOLE: &str = "<svg viewBox=\"0 0 64 64\" aria-hidden=\"true\"><path fill-rule=\"evenodd\" d=\"M6 58V12h4v4h4v-4h4v4h4v42ZM12.5 26v10h3V26ZM42 58V16h4v-4h4v4h4v-4h4v46ZM48.5 26v10h3V26ZM22 58V24h20v34ZM27 58V43a5 5 0 0 1 10 0v15Z\"/><rect class=\"b-herse\" x=\"27\" y=\"46\" width=\"10\" height=\"2\"/><rect class=\"b-herse\" x=\"27\" y=\"51\" width=\"10\" height=\"2\"/></svg>";

const NAV: &[(Rubrique, &str, &str, &str)] = &[
    (
        Rubrique::Supervision,
        "/tableau",
        "Supervision",
        "<rect width=\"7\" height=\"7\" x=\"3\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"14\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"14\" y=\"14\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"3\" y=\"14\" rx=\"1\"/>",
    ),
    (
        Rubrique::Enrolement,
        "/enrolement",
        "Enrôlement",
        "<rect width=\"20\" height=\"8\" x=\"2\" y=\"2\" rx=\"2\"/><rect width=\"20\" height=\"8\" x=\"2\" y=\"14\" rx=\"2\"/><path d=\"M6 6h.01M6 18h.01\"/>",
    ),
    (
        Rubrique::Maj,
        "/maj",
        "Mises à jour",
        "<path d=\"M12 3v12\"/><path d=\"m17 8-5-5-5 5\"/><path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"/>",
    ),
    (
        Rubrique::Audit,
        "/audit",
        "Journal d'audit",
        "<path d=\"M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01\"/>",
    ),
];

fn tete(h: &mut Html, titre: &str) {
    h.b("<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
        .t(titre)
        .b(" — Barbacane</title><link rel=\"stylesheet\" href=\"/statique/barbacane.css\"><link rel=\"icon\" href=\"/statique/symbole.svg\" type=\"image/svg+xml\"></head>");
}

/// Champ caché du jeton anti-CSRF (toujours le premier champ du formulaire).
fn csrf(h: &mut Html, jeton: &str) {
    h.b("<input type=\"hidden\" name=\"csrf\" value=\"")
        .t(jeton)
        .b("\">");
}

/// Page complète avec navigation.
fn coque(
    ctx: &Contexte,
    rubrique: Rubrique,
    fil: &str,
    titre: &str,
    actions: Html,
    corps: Html,
) -> String {
    let mut h = Html::new();
    tete(&mut h, titre);
    h.b("<body class=\"b-page\"><a class=\"b-lien-masque\" href=\"#contenu\">Aller au contenu</a><div class=\"b-coque\"><nav class=\"b-nav\" aria-label=\"Navigation\"><div class=\"b-nav__marque\">")
        .b(SYMBOLE)
        .b(" Barbacane</div>");
    for (r, lien, nom, icone) in NAV {
        h.b("<a href=\"").b(lien).b("\"");
        if *r == rubrique {
            h.b(" aria-current=\"page\"");
        }
        h.b("><svg class=\"b-nav__icone\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">")
            .b(icone)
            .b("</svg> ")
            .b(nom)
            .b("</a>");
    }
    h.b("<div class=\"b-nav__pied\"><div><b>")
        .t(ctx.compte)
        .b("</b><br>")
        .b(ctx.role.libelle())
        .b("<br>Certificat et mot de passe</div><form class=\"b-en-ligne\" method=\"post\" action=\"/deconnexion\">");
    csrf(&mut h, ctx.csrf);
    h.b("<button class=\"b-btn\" type=\"submit\">Se déconnecter</button></form></div></nav><main class=\"b-contenu\" id=\"contenu\"><div class=\"b-entete\"><div><div class=\"b-fil\">")
        .t(fil)
        .b("</div><h1>")
        .t(titre)
        .b("</h1></div><div class=\"b-entete__actions\">")
        .h(actions)
        .b("</div></div>")
        .h(corps)
        .b("</main></div></body></html>");
    h.fin()
}

/// Avis (information, alerte, blocage, succès).
fn avis(h: &mut Html, classe: &'static str, texte: &str) {
    h.b("<div class=\"b-avis ")
        .b(classe)
        .b("\" role=\"status\"><span>")
        .t(texte)
        .b("</span></div>");
}

pub fn depuis(maintenant: u64, t: u64) -> String {
    let d = maintenant.saturating_sub(t);
    match d {
        0..60 => format!("il y a {d} s"),
        60..3600 => format!("il y a {} min", d / 60),
        3600..86400 => format!("il y a {} h", d / 3600),
        _ => format!("il y a {} j", d / 86400),
    }
}

/// Empreinte lisible : groupes de 4 caractères.
pub fn grouper(h: &str) -> String {
    h.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn etat(h: &mut Html, classe: &'static str, mot: &'static str) {
    h.b("<span class=\"b-etat b-etat--")
        .b(classe)
        .b("\">")
        .b(mot)
        .b("</span>");
}

fn tuile(h: &mut Html, n: usize, classe: &'static str, nom: &'static str) {
    h.b("<div class=\"b-tuile");
    if n > 0 && !classe.is_empty() {
        h.b(" b-tuile--").b(classe);
    }
    h.b("\"><div class=\"b-tuile__chiffre\">")
        .n(n)
        .b("</div><div class=\"b-tuile__nom\">")
        .b(nom)
        .b("</div></div>");
}

/// État affiché d'une borne : (classe, mot).
pub fn etat_borne(l: &LigneSupervision) -> (&'static str, &'static str) {
    if !l.active {
        ("hors", "Révoquée")
    } else if l.alertes.contains(&Alerte::Silence) {
        ("hors", "Injoignable")
    } else if l.alertes.contains(&Alerte::HorsService) {
        ("alerte", "Hors service")
    } else if l.alertes.contains(&Alerte::Horloge) {
        ("alerte", "Horloge dérivée")
    } else {
        match l.etat {
            Some(EtatBorne::EnService) => ("sain", "En service"),
            Some(EtatBorne::Maintenance) => ("cours", "Maintenance"),
            Some(EtatBorne::HorsService) => ("alerte", "Hors service"),
            None => ("cours", "Premier contact attendu"),
        }
    }
}

fn libelle_alerte(a: Alerte) -> &'static str {
    match a {
        Alerte::Silence => "silence > 5 min",
        Alerte::Horloge => "horloge dérivée > 5 min",
        Alerte::Expiration => "certificat < 30 j",
        Alerte::HorsService => "hors service",
    }
}

// ───────────────────────────── Connexion et erreurs ───────────────────────────────────────────

pub fn connexion(jeton: &str, erreur: Option<&str>) -> String {
    let mut h = Html::new();
    tete(&mut h, "Connexion");
    h.b("<body class=\"b-page\"><main class=\"b-seul\"><div class=\"b-carte\"><div class=\"b-seul__marque\">")
        .b(SYMBOLE)
        .b(" Barbacane</div><h1 class=\"b-carte__titre\">Administration du serveur</h1><p class=\"b-douce\">Votre certificat d'administrateur a été présenté. Saisissez votre identifiant et votre mot de passe.</p>");
    if let Some(e) = erreur {
        avis(&mut h, "b-avis--bloque", e);
    }
    h.b("<form class=\"b-formulaire\" method=\"post\" action=\"/connexion\" autocomplete=\"off\">");
    csrf(&mut h, jeton);
    h.b("<div class=\"b-champ\"><label for=\"identifiant\">Identifiant</label><input class=\"b-saisie\" id=\"identifiant\" name=\"identifiant\" required maxlength=\"32\" autocapitalize=\"none\" spellcheck=\"false\"></div><div class=\"b-champ\"><label for=\"mot_de_passe\">Mot de passe</label><input class=\"b-saisie\" id=\"mot_de_passe\" name=\"mot_de_passe\" type=\"password\" required maxlength=\"256\"></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Se connecter</button></div></form><p class=\"b-aide\">5 échecs verrouillent le compte et le certificat pendant 15 min. Chaque connexion est inscrite au journal d'audit.</p></div></main></body></html>");
    h.fin()
}

/// Page d'erreur sans navigation (avant authentification ou requête refusée).
pub fn erreur(statut: u16, message: &str) -> String {
    let mut h = Html::new();
    tete(&mut h, "Erreur");
    h.b("<body class=\"b-page\"><main class=\"b-seul\"><div class=\"b-carte\"><h1 class=\"b-carte__titre\">Requête refusée (")
        .n(statut)
        .b(")</h1>");
    avis(&mut h, "b-avis--bloque", message);
    h.b("<p><a href=\"/tableau\">Retour au tableau de bord</a></p></div></main></body></html>");
    h.fin()
}

/// Résultat d'une action.
pub fn resultat(
    ctx: &Contexte,
    rubrique: Rubrique,
    titre: &str,
    succes: bool,
    message: &str,
    retour: &'static str,
) -> String {
    let mut c = Html::new();
    avis(
        &mut c,
        if succes {
            "b-avis--sain"
        } else {
            "b-avis--bloque"
        },
        message,
    );
    c.b("<p><a class=\"b-btn\" href=\"")
        .b(retour)
        .b("\">Retour</a></p>");
    coque(ctx, rubrique, "Résultat", titre, Html::new(), c)
}

// ───────────────────────────── Tableau de bord ────────────────────────────────────────────────

pub fn tableau(ctx: &Contexte, lignes: &[LigneSupervision], demandes: usize) -> String {
    let actives = lignes.iter().filter(|l| l.active).count();
    let compte = |classe: &str, mot: &str| {
        lignes
            .iter()
            .filter(|l| l.active && etat_borne(l) == (classe, mot))
            .count()
    };
    let horloge = lignes
        .iter()
        .filter(|l| l.alertes.contains(&Alerte::Horloge))
        .count();
    let mut actions = Html::new();
    actions.b("<a class=\"b-btn\" href=\"/tableau\">Actualiser</a>");
    if ctx.admin() {
        actions.b("<a class=\"b-btn b-btn--principal\" href=\"/enrolement\">Enrôler une borne</a>");
    }
    let mut c = Html::new();
    c.b("<div class=\"b-tuiles\">");
    tuile(&mut c, actives, "", "Bornes actives");
    tuile(&mut c, compte("sain", "En service"), "sain", "En service");
    tuile(
        &mut c,
        compte("hors", "Injoignable"),
        "hors",
        "Injoignables",
    );
    tuile(&mut c, horloge, "alerte", "Horloge dérivée");
    tuile(&mut c, demandes, "cours", "Demandes en attente");
    c.b("</div>");
    let a_traiter: Vec<String> = lignes
        .iter()
        .filter(|l| l.active && !l.alertes.is_empty())
        .map(|l| {
            let alertes: Vec<&str> = l.alertes.iter().map(|a| libelle_alerte(*a)).collect();
            format!("{} : {}", l.nom, alertes.join(", "))
        })
        .chain((demandes > 0).then(|| format!("{demandes} demande(s) d'enrôlement à examiner")))
        .collect();
    if !a_traiter.is_empty() {
        c.b("<div class=\"b-avis b-avis--alerte\" role=\"status\"><span><b>À traiter :</b> ")
            .t(&a_traiter.join(" · "))
            .b("</span></div>");
    }
    c.b("<div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Borne</th><th>Site</th><th>État</th><th>Version</th><th>Dernier contact</th><th class=\"num\">Écart d'horloge</th><th>Certificat</th><th>Alertes</th>");
    if ctx.admin() {
        c.b("<th>Action</th>");
    }
    c.b("</tr></thead><tbody>");
    if lignes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"9\">Aucune borne enrôlée.</td></tr>");
    }
    for l in lignes {
        let (classe, mot) = etat_borne(l);
        c.b("<tr><td><span class=\"b-mono\">")
            .t(&l.nom)
            .b("</span><br><span class=\"b-douce b-mono\">")
            .t(l.uuid.get(..8).unwrap_or(&l.uuid))
            .b("</span></td><td>")
            .t(&l.site)
            .b("</td><td>");
        etat(&mut c, classe, mot);
        c.b("</td><td class=\"b-mono\">")
            .t(l.version_logiciel.as_deref().unwrap_or("—"))
            .b("</td><td>");
        match l.derniere_vue {
            Some(v) => {
                c.t(&depuis(ctx.maintenant, v))
                    .b("<br><span class=\"b-douce\">")
                    .t(&date_utc(v))
                    .b("</span>");
            }
            None => {
                c.b("jamais");
            }
        }
        c.b("</td><td class=\"num\">");
        match l.ecart_horloge_s {
            Some(e) => c.t(&format!("{e:+} s")),
            None => c.b("—"),
        };
        c.b("</td><td>");
        if l.active {
            c.t(&format!(
                "{} j",
                l.expire_le.saturating_sub(ctx.maintenant) / 86400
            ));
        } else {
            c.b("révoqué");
        }
        c.b("</td><td>");
        if l.alertes.is_empty() {
            c.b("<span class=\"b-douce\">aucune</span>");
        }
        for (i, a) in l.alertes.iter().enumerate() {
            if i > 0 {
                c.b("<br>");
            }
            etat(&mut c, "alerte", libelle_alerte(*a));
        }
        c.b("</td>");
        if ctx.admin() {
            c.b("<td>");
            if l.active {
                c.b("<a class=\"b-btn b-btn--petit\" href=\"/bornes/revoquer?uuid=")
                    .u(&l.uuid)
                    .b("\">Révoquer</a>");
            }
            c.b("</td>");
        }
        c.b("</tr>");
    }
    c.b("</tbody></table></div><p class=\"b-aide\">Heure du serveur : ")
        .t(&date_utc(ctx.maintenant))
        .b(". Chaque consultation est inscrite au journal d'audit.</p>");
    coque(
        ctx,
        Rubrique::Supervision,
        "Supervision",
        "Bornes · tous les sites",
        actions,
        c,
    )
}

// ───────────────────────────── Enrôlement ─────────────────────────────────────────────────────

/// Jeton à afficher une seule fois : (texte, expiration, site).
pub struct JetonAffiche<'a> {
    pub texte: &'a str,
    pub expire_le: u64,
    pub site: &'a str,
}

pub fn enrolement(
    ctx: &Contexte,
    demandes: &[Demande],
    jeton: Option<JetonAffiche>,
    erreur_site: Option<(&str, &str)>,
) -> String {
    let mut c = Html::new();
    if let Some(j) = jeton {
        c.b("<div class=\"b-carte\"><h2>Jeton d'enrôlement pour ")
            .t(j.site)
            .b("</h2><div class=\"b-code\">")
            .t(j.texte)
            .b("</div>");
        avis(
            &mut c,
            "b-avis--alerte",
            &format!(
                "Affiché une seule fois. Usage unique, valable jusqu'à {}. Saisissez-le sur la borne, puis examinez sa demande ci-dessous.",
                date_utc(j.expire_le)
            ),
        );
        c.b("</div>");
    }
    c.b("<div class=\"b-cartes\">");
    if ctx.admin() {
        c.b("<div class=\"b-carte\"><h2>Créer un jeton</h2><form class=\"b-formulaire\" method=\"post\" action=\"/enrolement/jeton\">");
        csrf(&mut c, ctx.csrf);
        let (saisie, err) = erreur_site.unwrap_or(("", ""));
        c.b("<div class=\"b-champ");
        if !err.is_empty() {
            c.b(" b-champ--erreur");
        }
        c.b("\"><label for=\"site\">Site</label><input class=\"b-saisie b-mono\" id=\"site\" name=\"site\" required maxlength=\"14\" placeholder=\"site-1\" value=\"")
            .t(saisie)
            .b("\"><span class=\"b-aide\">");
        if err.is_empty() {
            c.b("Forme site-&lt;n&gt;. Le jeton vaut 1 h et ne sert qu'une fois.");
        } else {
            c.t(err);
        }
        c.b("</span></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Créer le jeton</button></div></form></div>");
    }
    c.b("<div class=\"b-carte\"><h2>Procédure</h2><p>1. Créez un jeton pour le site de la borne. 2. Saisissez-le sur la borne : elle dépose sa demande et affiche une empreinte. 3. Examinez la demande ici et <b>retapez l'empreinte lue sur l'écran de la borne</b>. Elle n'est pas affichée sur cette page : une empreinte différente signale une demande qui ne vient pas de cette borne.</p></div></div>");
    c.b("<h2>Demandes en attente</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Demande</th><th>Site</th><th>Déposée</th><th>Logiciel</th><th>Expire</th>");
    if ctx.admin() {
        c.b("<th>Action</th>");
    }
    c.b("</tr></thead><tbody>");
    if demandes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"6\">Aucune demande en attente.</td></tr>");
    }
    for d in demandes {
        c.b("<tr><td class=\"b-mono\">")
            .t(d.id.get(..12).unwrap_or(&d.id))
            .b("</td><td>")
            .t(&d.site)
            .b("</td><td>")
            .t(&depuis(ctx.maintenant, d.deposee_le))
            .b("</td><td class=\"b-mono\">")
            .t(&d.version_logiciel)
            .b("</td><td>")
            .t(&date_utc(d.expire_le))
            .b("</td>");
        if ctx.admin() {
            c.b("<td><a class=\"b-btn b-btn--petit\" href=\"/enrolement/demande?id=")
                .u(&d.id)
                .b("\">Examiner</a></td>");
        }
        c.b("</tr>");
    }
    c.b("</tbody></table></div>");
    coque(
        ctx,
        Rubrique::Enrolement,
        "Enrôlement",
        "Enrôler une borne",
        Html::new(),
        c,
    )
}

/// Examen d'une demande : l'empreinte n'est PAS affichée, elle est à retaper.
pub fn demande(ctx: &Contexte, d: &Demande, erreur: Option<&str>, nom: &str) -> String {
    let mut c = Html::new();
    c.b("<div class=\"b-cartes\"><div class=\"b-carte\"><h2>Demande</h2><dl class=\"b-details\"><dt>Identifiant</dt><dd class=\"b-mono\">")
        .t(&d.id)
        .b("</dd><dt>Site</dt><dd>")
        .t(&d.site)
        .b("</dd><dt>Déposée</dt><dd>")
        .t(&date_utc(d.deposee_le))
        .b("</dd><dt>Logiciel</dt><dd class=\"b-mono\">")
        .t(&d.version_logiciel)
        .b("</dd><dt>Expire</dt><dd>")
        .t(&date_utc(d.expire_le))
        .b("</dd></dl></div><div class=\"b-carte\"><h2>Valider</h2><form class=\"b-formulaire\" method=\"post\" action=\"/enrolement/valider\" autocomplete=\"off\">");
    csrf(&mut c, ctx.csrf);
    c.b("<input type=\"hidden\" name=\"id\" value=\"")
        .t(&d.id)
        .b("\"><div class=\"b-champ");
    if erreur.is_some() {
        c.b(" b-champ--erreur");
    }
    c.b("\"><label for=\"empreinte\">Empreinte affichée par la borne</label><textarea class=\"b-saisie\" id=\"empreinte\" name=\"empreinte\" required maxlength=\"200\" spellcheck=\"false\" rows=\"3\"></textarea><span class=\"b-aide\">");
    match erreur {
        Some(e) => {
            c.t(e);
        }
        None => {
            c.b("64 caractères hexadécimaux, lus sur l'écran de la borne ; les espaces sont ignorés.");
        }
    }
    c.b("</span></div><div class=\"b-champ\"><label for=\"nom\">Nom de la borne (facultatif)</label><input class=\"b-saisie b-mono\" id=\"nom\" name=\"nom\" maxlength=\"32\" value=\"")
        .t(nom)
        .b("\"><span class=\"b-aide\">Lettres minuscules, chiffres et tirets, 32 au plus.</span></div><div class=\"b-formulaire__actions\"><a class=\"b-btn b-btn--discret\" href=\"/enrolement\">Annuler</a><button class=\"b-btn b-btn--principal\" type=\"submit\">Valider et émettre le certificat</button></div></form></div><div class=\"b-carte\"><h2>Refuser</h2><p>La borne devra obtenir un nouveau jeton.</p><form class=\"b-formulaire\" method=\"post\" action=\"/enrolement/refuser\">");
    csrf(&mut c, ctx.csrf);
    c.b("<input type=\"hidden\" name=\"id\" value=\"")
        .t(&d.id)
        .b("\"><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--danger\" type=\"submit\">Refuser la demande</button></div></form></div></div>");
    coque(
        ctx,
        Rubrique::Enrolement,
        "Enrôlement › Demande",
        "Examiner une demande",
        Html::new(),
        c,
    )
}

// ───────────────────────────── Révocation ─────────────────────────────────────────────────────

pub const MOTIFS: &[(&str, &str)] = &[
    ("volee", "Borne volée ou perdue"),
    ("cle-suspecte", "Clé suspecte de compromission"),
    ("reformee", "Borne réformée"),
    ("changement-site", "Changement de site"),
    ("fin-de-vie", "Fin de vie"),
];

pub fn revocation(ctx: &Contexte, b: &Borne, erreur: Option<&str>) -> String {
    let mut c = Html::new();
    c.b("<div class=\"b-cartes\"><div class=\"b-carte\"><h2>Borne</h2><dl class=\"b-details\"><dt>Nom</dt><dd class=\"b-mono\">")
        .t(&b.nom)
        .b("</dd><dt>Site</dt><dd>")
        .t(&b.site)
        .b("</dd><dt>Identifiant</dt><dd class=\"b-mono\">")
        .t(&b.uuid)
        .b("</dd><dt>Certificat</dt><dd class=\"b-mono\">")
        .t(&b.serie)
        .b("</dd></dl></div><div class=\"b-carte\"><h2>Révoquer le certificat</h2>");
    avis(
        &mut c,
        "b-avis--alerte",
        "Irréversible : la borne est refusée dès sa prochaine connexion (CRL republiée). Elle devra être enrôlée de nouveau.",
    );
    c.b("<form class=\"b-formulaire\" method=\"post\" action=\"/bornes/revoquer\" autocomplete=\"off\">");
    csrf(&mut c, ctx.csrf);
    c.b("<input type=\"hidden\" name=\"uuid\" value=\"")
        .t(&b.uuid)
        .b("\"><div class=\"b-champ\"><label for=\"motif\">Motif</label><select class=\"b-saisie\" id=\"motif\" name=\"motif\" required>");
    for (code, libelle) in MOTIFS {
        c.b("<option value=\"")
            .b(code)
            .b("\">")
            .b(libelle)
            .b("</option>");
    }
    c.b("</select></div><div class=\"b-champ");
    if erreur.is_some() {
        c.b(" b-champ--erreur");
    }
    c.b("\"><label for=\"confirmation\">Retapez le nom de la borne</label><input class=\"b-saisie b-mono\" id=\"confirmation\" name=\"confirmation\" required maxlength=\"64\"><span class=\"b-aide\">");
    match erreur {
        Some(e) => {
            c.t(e);
        }
        None => {
            c.b("Confirmation de l'objet de la révocation.");
        }
    }
    c.b("</span></div><div class=\"b-formulaire__actions\"><a class=\"b-btn b-btn--discret\" href=\"/tableau\">Annuler</a><button class=\"b-btn b-btn--danger\" type=\"submit\">Révoquer le certificat</button></div></form></div></div>");
    coque(
        ctx,
        Rubrique::Supervision,
        "Supervision › Révocation",
        &format!("Révoquer la borne {}", b.nom),
        Html::new(),
        c,
    )
}

// ───────────────────────────── Mises à jour ───────────────────────────────────────────────────

fn libelle_maj(e: EtatMajBorne) -> (&'static str, &'static str) {
    match e {
        EtatMajBorne::Proposee => ("cours", "Proposée"),
        EtatMajBorne::Telechargee => ("cours", "Téléchargée"),
        EtatMajBorne::Appliquee => ("sain", "Appliquée"),
        EtatMajBorne::Echec => ("bloque", "Échec"),
    }
}

fn formulaire_fichiers(
    c: &mut Html,
    ctx: &Contexte,
    action: &'static str,
    etiquette: &'static str,
    accepte: &'static str,
    bouton: &'static str,
) {
    c.b("<form class=\"b-formulaire\" method=\"post\" enctype=\"multipart/form-data\" action=\"")
        .b(action)
        .b("\">");
    csrf(c, ctx.csrf);
    c.b("<div class=\"b-champ\"><label>")
        .b(etiquette)
        .b("<input class=\"b-saisie\" type=\"file\" name=\"fichier\" required accept=\"")
        .b(accepte)
        .b("\"></label></div><div class=\"b-champ\"><label>Signature (.minisig)<input class=\"b-saisie\" type=\"file\" name=\"signature\" required accept=\".minisig\"></label></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">")
        .b(bouton)
        .b("</button></div></form>");
}

pub fn maj(
    ctx: &Contexte,
    e: &EtatMaj,
    noms: &BTreeMap<String, String>,
    message: Option<(bool, &str)>,
) -> String {
    let mut c = Html::new();
    if let Some((ok, m)) = message {
        avis(
            &mut c,
            if ok { "b-avis--sain" } else { "b-avis--bloque" },
            m,
        );
    }
    c.b("<div class=\"b-tuiles\"><div class=\"b-tuile\"><div class=\"b-tuile__chiffre\">");
    match e.plancher {
        Some(p) => c.n(p),
        None => c.b("—"),
    };
    c.b("</div><div class=\"b-tuile__nom\">Plancher signé</div></div><div class=\"b-tuile\"><div class=\"b-tuile__chiffre\">");
    match e.diffusee {
        Some(p) => c.n(p),
        None => c.b("—"),
    };
    c.b("</div><div class=\"b-tuile__nom\">Paquet diffusé</div></div>");
    tuile(&mut c, e.paquets.len(), "", "Paquets déposés");
    let echecs = e
        .bornes
        .values()
        .filter(|s| s.etat == EtatMajBorne::Echec)
        .count();
    tuile(&mut c, echecs, "bloque", "Échecs rapportés");
    c.b("</div>");
    if e.plancher.is_none() {
        avis(
            &mut c,
            "b-avis--alerte",
            "Aucun plancher signé : tout dépôt est refusé. Installez d'abord le plancher préparé hors ligne.",
        );
    }
    c.b("<h2>Paquets</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th class=\"num\">Version</th><th class=\"num\">Taille</th><th>SHA-256</th><th>Déposé</th><th>Diffusion</th></tr></thead><tbody>");
    if e.paquets.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"5\">Aucun paquet déposé.</td></tr>");
    }
    for p in e.paquets.iter().rev() {
        c.b("<tr><td class=\"num b-mono\">")
            .n(p.version_maj)
            .b("</td><td class=\"num\">")
            .t(&format!("{:.1} Mio", p.taille as f64 / 1048576.0))
            .b("</td><td class=\"b-mono b-coupe\">")
            .t(&grouper(&p.sha256))
            .b("</td><td>")
            .t(&date_utc(p.depose_le))
            .b("</td><td>");
        let diffusable = e.plancher.is_some_and(|pl| p.version_maj >= pl)
            && e.diffusee.is_none_or(|d| p.version_maj > d);
        if e.diffusee == Some(p.version_maj) {
            etat(&mut c, "sain", "Diffusé");
        } else if diffusable && ctx.admin() {
            c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/maj/diffuser\">");
            csrf(&mut c, ctx.csrf);
            c.b("<input type=\"hidden\" name=\"version\" value=\"")
                .n(p.version_maj)
                .b("\"><button class=\"b-btn b-btn--petit\" type=\"submit\">Diffuser</button></form>");
        } else {
            c.b("<span class=\"b-douce\">—</span>");
        }
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div><h2>État par borne</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Borne</th><th class=\"num\">Paquet</th><th>État</th><th>Depuis</th></tr></thead><tbody>");
    if e.bornes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"4\">Aucune borne n'a encore reçu de proposition.</td></tr>");
    }
    for (uuid, s) in &e.bornes {
        let (classe, mot) = libelle_maj(s.etat);
        c.b("<tr><td class=\"b-mono\">")
            .t(noms.get(uuid).map(String::as_str).unwrap_or(uuid))
            .b("</td><td class=\"num b-mono\">")
            .n(s.version_maj)
            .b("</td><td>");
        etat(&mut c, classe, mot);
        c.b("</td><td>").t(&date_utc(s.le)).b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    if ctx.admin() {
        c.b("<div class=\"b-cartes\"><div class=\"b-carte\"><h2>Déposer un paquet</h2><p class=\"b-douce\">Paquet .bcu signé hors ligne avec la clé des bornes. Signature, version (commentaire signé), plancher et anti-retour sont vérifiés ; tout refus est audité.</p>");
        formulaire_fichiers(
            &mut c,
            ctx,
            "/maj/depot",
            "Paquet (.bcu)",
            ".bcu",
            "Déposer le paquet",
        );
        c.b("</div><div class=\"b-carte\"><h2>Installer un plancher</h2><p class=\"b-douce\">plancher.json préparé hors ligne (barbacane-plancher-prepare). Un plancher en recul est refusé.</p>");
        formulaire_fichiers(
            &mut c,
            ctx,
            "/maj/plancher",
            "Plancher (plancher.json)",
            ".json",
            "Installer le plancher",
        );
        c.b("</div></div>");
    }
    coque(
        ctx,
        Rubrique::Maj,
        "Mises à jour",
        "Mises à jour centralisées",
        Html::new(),
        c,
    )
}

// ───────────────────────────── Audit ──────────────────────────────────────────────────────────

fn libelle_evenement(cle: &str) -> &'static str {
    match cle {
        "jeton_cree" => "Jeton créé",
        "enrolement_demande" => "Demande d'enrôlement",
        "enrolement_valide" => "Enrôlement validé",
        "enrolement_refuse" => "Enrôlement refusé",
        "revocation" => "Révocation",
        "crl_publiee" => "CRL publiée",
        "certificat_renouvele" => "Certificat renouvelé",
        "battement_anormal" => "Battement anormal",
        "plancher_installe" => "Plancher installé",
        "maj_deposee" => "Paquet déposé",
        "maj_refusee" => "Paquet refusé",
        "maj_diffusee" => "Paquet diffusé",
        "maj_proposee" => "Paquet proposé",
        "maj_telechargee" => "Paquet téléchargé",
        "maj_rapportee" => "Mise à jour rapportée",
        "administration" => "Administration",
        "point_de_controle" => "Point de contrôle signé",
        _ => "Autre",
    }
}

/// Détail d'un événement : `champ=valeur` (signatures abrégées).
fn detail_evenement(e: &Enregistrement) -> (String, String) {
    let v = serde_json::to_value(&e.evenement).unwrap_or_default();
    let Some((cle, champs)) = v.as_object().and_then(|o| o.iter().next()) else {
        return ("?".into(), String::new());
    };
    let mut d = Vec::new();
    if let Some(champs) = champs.as_object() {
        for (k, v) in champs {
            let mut s = match v {
                serde_json::Value::String(s) => s.clone(),
                autre => autre.to_string(),
            };
            if s.len() > 24 && (k == "signature" || k == "empreinte" || k == "sha256") {
                s = format!("{}…", &s[..16]);
            }
            d.push(format!("{k}={s}"));
        }
    }
    (cle.clone(), d.join(", "))
}

pub fn audit(
    ctx: &Contexte,
    lignes: &[Result<Enregistrement, String>],
    page: usize,
    pages: usize,
) -> String {
    let mut actions = Html::new();
    actions.b(
        "<a class=\"b-btn b-btn--principal\" href=\"/audit/verification\">Vérifier la chaîne</a>",
    );
    let mut c = Html::new();
    c.b("<div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th class=\"num\">N°</th><th>Reçu le</th><th>Acteur</th><th>Événement</th><th>Détail</th></tr></thead><tbody>");
    if lignes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"5\">Journal vide.</td></tr>");
    }
    for l in lignes {
        match l {
            Ok(e) => {
                let (cle, detail) = detail_evenement(e);
                c.b("<tr><td class=\"num b-mono\">")
                    .n(e.n)
                    .b("</td><td>")
                    .t(&date_utc(e.le))
                    .b("</td><td class=\"b-mono\">")
                    .t(&e.acteur)
                    .b("</td><td>")
                    .b(libelle_evenement(&cle))
                    .b("<br><span class=\"b-douce b-mono\">")
                    .t(&cle)
                    .b("</span></td><td class=\"b-mono b-coupe\">")
                    .t(&detail)
                    .b("</td></tr>");
            }
            Err(cause) => {
                c.b("<tr><td colspan=\"5\">");
                etat(&mut c, "bloque", "Ligne illisible");
                c.b(" ").t(cause).b("</td></tr>");
            }
        }
    }
    c.b("</tbody></table></div><div class=\"b-pagination\">");
    if page > 1 {
        c.b("<a class=\"b-btn\" href=\"/audit?page=")
            .n(page - 1)
            .b("\">Plus récents</a>");
    }
    c.b("<span class=\"b-douce\">Page ")
        .n(page)
        .b(" sur ")
        .n(pages.max(1))
        .b("</span>");
    if page < pages {
        c.b("<a class=\"b-btn\" href=\"/audit?page=")
            .n(page + 1)
            .b("\">Plus anciens</a>");
    }
    c.b("</div>");
    coque(
        ctx,
        Rubrique::Audit,
        "Journal d'audit",
        "Journal d'audit chaîné",
        actions,
        c,
    )
}

pub fn verification(ctx: &Contexte, resultat: Result<Bilan, String>) -> String {
    let mut c = Html::new();
    match resultat {
        Ok(b) => {
            avis(
                &mut c,
                "b-avis--sain",
                &format!(
                    "Chaîne intègre : {} enregistrements, {} points de contrôle signés valides.",
                    b.enregistrements,
                    b.points.len()
                ),
            );
            if b.non_scelles > 0 {
                avis(
                    &mut c,
                    "b-avis--alerte",
                    &format!(
                        "{} enregistrement(s) postérieur(s) au dernier point de contrôle : leur troncature ne serait pas détectable avant le prochain scellement.",
                        b.non_scelles
                    ),
                );
            }
            c.b("<div class=\"b-carte\"><dl class=\"b-details\"><dt>Dernière empreinte (SHA-384)</dt><dd class=\"b-mono\">")
                .t(&grouper(&b.derniere))
                .b("</dd>");
            if let Some(p) = b.points.last() {
                c.b("<dt>Dernier point de contrôle</dt><dd>n° ")
                    .n(p.n)
                    .b(", ")
                    .t(&date_utc(p.le))
                    .b("</dd>");
            }
            c.b("</dl></div>");
        }
        Err(defaut) => {
            avis(
                &mut c,
                "b-avis--bloque",
                &format!(
                    "Journal altéré : {defaut}. Préservez le serveur en l'état et prévenez l'officier de sécurité."
                ),
            );
        }
    }
    c.b("<p class=\"b-aide\">Comparaison aux empreintes exportées hors du serveur : barbacane-audit verifier JOURNAL CLE.pub EXPORT…</p><p><a class=\"b-btn\" href=\"/audit\">Retour au journal</a></p>");
    coque(
        ctx,
        Rubrique::Audit,
        "Journal d'audit › Vérification",
        "Vérification de la chaîne",
        Html::new(),
        c,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ligne(nom: &str) -> LigneSupervision {
        LigneSupervision {
            uuid: "0123456789".into(),
            nom: nom.into(),
            site: "site-1".into(),
            active: true,
            version_logiciel: Some("<i>2.0".into()),
            etat: Some(EtatBorne::EnService),
            derniere_vue: Some(100),
            ecart_horloge_s: Some(-3),
            expire_le: 100 + 80 * 86400,
            alertes: vec![],
        }
    }

    #[test]
    fn tableau_echappe_les_donnees() {
        let ctx = Contexte {
            compte: "a\"<b>",
            role: Role::Administrateur,
            csrf: "j\"x",
            maintenant: 130,
        };
        let p = tableau(&ctx, &[ligne("<script>alert(1)</script>")], 0);
        assert!(!p.contains("<script>"));
        assert!(!p.contains("<i>2.0"));
        assert!(p.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(p.contains("value=\"j&quot;x\""));
        assert!(!p.contains("style="), "attribut style interdit par la CSP");
        assert!(p.contains("il y a 30 s"));
    }

    #[test]
    fn auditeur_sans_action() {
        let ctx = Contexte {
            compte: "aud",
            role: Role::Auditeur,
            csrf: "x",
            maintenant: 130,
        };
        let p = tableau(&ctx, &[ligne("b1")], 0);
        assert!(!p.contains("/bornes/revoquer"));
        assert!(!p.contains("Enrôler une borne"));
    }

    #[test]
    fn etats() {
        let mut l = ligne("b");
        assert_eq!(etat_borne(&l), ("sain", "En service"));
        l.alertes = vec![Alerte::Horloge, Alerte::Silence];
        assert_eq!(etat_borne(&l), ("hors", "Injoignable"));
        l.active = false;
        assert_eq!(etat_borne(&l).1, "Révoquée");
        assert_eq!(depuis(10_000, 10_000 - 7200), "il y a 2 h");
        assert_eq!(grouper("abcdefgh"), "abcd efgh");
    }
}
