//! Pages Utilisateurs, Sites et modes, Clés USB (`docs/suite/serveur-utilisateurs.md`).
//!
//! Pseudonymisation (§6) : l'**auditeur** voit les identifiants en clair ; l'administrateur ne
//! voit que les pseudonymes, sauf pour le compte qu'il saisit lui-même.

use barbacane_passerelle::outils::date_utc;
use barbacane_passerelle::utilisateurs::{BaseUtilisateurs, ReglageSite, Utilisateur, nom_mode};
use barbacane_protocole::utilisateurs::{EntreeNonEnrolees, ModeUtilisateurs};

use crate::comptes::Role;
use crate::html::Html;
use crate::pages::{Contexte, Rubrique, avis, coque, csrf, depuis, etat, tuile};

/// Lignes affichées au plus dans la liste des utilisateurs.
pub const LISTE_MAX: usize = 1000;

/// Données de la page Utilisateurs.
pub struct VueUtilisateurs<'a> {
    pub base: &'a BaseUtilisateurs,
    pub annuaire_configure: bool,
    /// Saisie de recherche et compte trouvé.
    pub recherche: Option<(&'a str, Option<&'a Utilisateur>)>,
    /// PIN tiré : (identifiant, PIN), affiché UNE seule fois.
    pub pin: Option<(&'a str, &'a str)>,
    pub message: Option<(bool, &'a str)>,
    pub maintenant: u64,
}

fn etat_utilisateur(u: &Utilisateur) -> (&'static str, &'static str) {
    if !u.actif {
        ("hors", "Retiré de l'annuaire")
    } else if u.verrouille_le.is_some() {
        ("bloque", "Verrouillé")
    } else if u.pin.is_none() {
        ("cours", "Sans PIN")
    } else if u.pin_a_changer {
        ("cours", "PIN à changer")
    } else {
        ("sain", "Actif")
    }
}

fn message(c: &mut Html, m: Option<(bool, &str)>) {
    if let Some((ok, texte)) = m {
        avis(c, if ok { "b-avis--sain" } else { "b-avis--bloque" }, texte);
    }
}

fn bouton_action(
    c: &mut Html,
    ctx: &Contexte,
    action: &'static str,
    champ: &'static str,
    valeur: &str,
    libelle: &'static str,
    classe: &'static str,
) {
    c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"")
        .b(action)
        .b("\">");
    csrf(c, ctx.csrf);
    c.b("<input type=\"hidden\" name=\"")
        .b(champ)
        .b("\" value=\"")
        .t(valeur)
        .b("\"><button class=\"b-btn b-btn--petit ")
        .b(classe)
        .b("\" type=\"submit\">")
        .b(libelle)
        .b("</button></form>");
}

pub fn utilisateurs(ctx: &Contexte, v: &VueUtilisateurs) -> String {
    let auditeur = ctx.role == Role::Auditeur;
    let b = v.base;
    let actifs: Vec<&Utilisateur> = b.utilisateurs.iter().filter(|u| u.actif).collect();
    let mut c = Html::new();
    message(&mut c, v.message);
    if let Some((id, pin)) = v.pin {
        c.b("<div class=\"b-carte\"><h2>Nouveau PIN de ")
            .t(id)
            .b("</h2><div class=\"b-code\">")
            .t(pin)
            .b("</div>");
        avis(
            &mut c,
            "b-avis--alerte",
            "Affiché une seule fois : remettez-le à l'utilisateur par un canal sûr. Il devra le changer à sa première utilisation d'une borne. Seul son dérivé Argon2id est conservé.",
        );
        c.b("</div>");
    }
    c.b("<div class=\"b-tuiles\">");
    tuile(&mut c, actifs.len(), "", "Utilisateurs actifs");
    tuile(
        &mut c,
        actifs
            .iter()
            .filter(|u| u.pin.is_some() && !u.pin_a_changer)
            .count(),
        "sain",
        "Avec PIN",
    );
    tuile(
        &mut c,
        actifs.iter().filter(|u| u.verrouille_le.is_some()).count(),
        "bloque",
        "Verrouillés",
    );
    tuile(
        &mut c,
        b.utilisateurs.iter().filter(|u| !u.actif).count(),
        "hors",
        "Retirés (conservés 1 an)",
    );
    tuile(
        &mut c,
        b.bornes
            .values()
            .filter(|x| x.bloquee_jusqua > v.maintenant)
            .count(),
        "alerte",
        "Bornes bloquées",
    );
    c.b("</div><div class=\"b-cartes\"><div class=\"b-carte\"><h2>Annuaire</h2>");
    match &b.dernier_import {
        Some(i) => {
            c.b("<p>Dernière synchronisation : ")
                .t(&date_utc(i.le))
                .b(" (")
                .t(&depuis(v.maintenant, i.le))
                .b("), ")
                .n(i.actifs)
                .b(" identifiants, source ")
                .t(&i.source)
                .b(".</p>");
        }
        None => {
            c.b("<p>Aucune synchronisation.</p>");
        }
    }
    if ctx.admin() {
        if v.annuaire_configure {
            c.b("<form class=\"b-formulaire\" method=\"post\" action=\"/utilisateurs/synchroniser\">");
            csrf(&mut c, ctx.csrf);
            c.b("<div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Synchroniser avec l'annuaire</button></div></form>");
        } else {
            c.b("<p class=\"b-aide\">Annuaire non configuré (clé « annuaire » de la configuration de l'interface).</p>");
        }
    }
    c.b("<p class=\"b-aide\">LDAPS en lecture seule, CA de l'annuaire épinglée : seuls les identifiants sont importés, jamais de mot de passe.</p></div>");
    // Recherche d'un compte.
    c.b("<div class=\"b-carte\"><h2>Rechercher un compte</h2><form class=\"b-formulaire\" method=\"get\" action=\"/utilisateurs\"><div class=\"b-champ\"><label for=\"identifiant\">");
    if auditeur {
        c.b("Identifiant ou pseudonyme (u-…)");
    } else {
        c.b("Identifiant");
    }
    c.b("</label><input class=\"b-saisie b-mono\" id=\"identifiant\" name=\"identifiant\" required maxlength=\"64\" autocapitalize=\"none\" spellcheck=\"false\" value=\"")
        .t(v.recherche.map(|r| r.0).unwrap_or(""))
        .b("\"></div><div class=\"b-formulaire__actions\"><button class=\"b-btn\" type=\"submit\">Rechercher</button></div></form>");
    if let Some((saisie, trouve)) = v.recherche {
        match trouve {
            None => avis(
                &mut c,
                "b-avis--alerte",
                &format!("Aucun compte « {saisie} »."),
            ),
            Some(u) => {
                let (classe, mot) = etat_utilisateur(u);
                c.b("<dl class=\"b-details\"><dt>Identifiant</dt><dd class=\"b-mono\">")
                    .t(&u.identifiant)
                    .b("</dd><dt>Pseudonyme</dt><dd class=\"b-mono\">")
                    .t(&u.pseudonyme)
                    .b("</dd><dt>État</dt><dd>");
                etat(&mut c, classe, mot);
                c.b("</dd><dt>Échecs consécutifs</dt><dd>")
                    .n(u.echecs)
                    .b("</dd><dt>Dernière vérification</dt><dd>")
                    .t(&u
                        .derniere_verification
                        .map(date_utc)
                        .unwrap_or_else(|| "jamais".into()))
                    .b("</dd></dl>");
                if ctx.admin() && u.actif {
                    c.b("<div class=\"b-formulaire__actions\">");
                    bouton_action(
                        &mut c,
                        ctx,
                        "/utilisateurs/pin",
                        "identifiant",
                        &u.identifiant,
                        "Réinitialiser le PIN",
                        "b-btn--principal",
                    );
                    if u.verrouille_le.is_some() {
                        bouton_action(
                            &mut c,
                            ctx,
                            "/utilisateurs/deverrouiller",
                            "identifiant",
                            &u.identifiant,
                            "Déverrouiller",
                            "",
                        );
                    }
                    c.b("</div>");
                }
            }
        }
    }
    c.b("</div></div>");
    // Liste : en clair pour l'auditeur, pseudonymisée sinon.
    c.b("<h2>Comptes</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr>");
    if auditeur {
        c.b("<th>Identifiant</th>");
    }
    c.b("<th>Pseudonyme</th><th>État</th><th class=\"num\">Échecs</th><th>Dernière vérification</th></tr></thead><tbody>");
    let mut liste: Vec<&Utilisateur> = b.utilisateurs.iter().collect();
    liste.sort_by_key(|u| (u.verrouille_le.is_none(), !u.actif, u.pseudonyme.clone()));
    if liste.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"5\">Aucun compte : synchronisez l'annuaire.</td></tr>");
    }
    for u in liste.iter().take(LISTE_MAX) {
        let (classe, mot) = etat_utilisateur(u);
        c.b("<tr>");
        if auditeur {
            c.b("<td class=\"b-mono\">").t(&u.identifiant).b("</td>");
        }
        c.b("<td class=\"b-mono\">").t(&u.pseudonyme).b("</td><td>");
        etat(&mut c, classe, mot);
        c.b("</td><td class=\"num\">")
            .n(u.echecs)
            .b("</td><td>")
            .t(&u
                .derniere_verification
                .map(|t| depuis(v.maintenant, t))
                .unwrap_or_else(|| "jamais".into()))
            .b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    if liste.len() > LISTE_MAX {
        c.b("<p class=\"b-aide\">")
            .n(LISTE_MAX)
            .b(" premiers comptes affichés (verrouillés d'abord) ; utilisez la recherche.</p>");
    }
    c.b("<p class=\"b-aide\">");
    if auditeur {
        c.b("Rôle auditeur : identifiants en clair. Le journal d'audit ne contient que les pseudonymes ; chaque consultation est journalisée.");
    } else {
        c.b("Identifiants pseudonymisés (HMAC) : saisissez un identifiant pour agir sur un compte. 5 échecs verrouillent un compte ; 5 refus en 1 h bloquent une borne 15 min (doublé à chaque fois).");
    }
    c.b("</p>");
    coque(
        ctx,
        Rubrique::Utilisateurs,
        "Utilisateurs",
        "Utilisateurs des bornes",
        Html::new(),
        c,
    )
}

/// Ligne de la page Sites : (site, bornes actives, réglage).
pub struct LigneSite {
    pub site: String,
    pub bornes: usize,
    pub reglage: ReglageSite,
    pub cles: usize,
}

fn libelle_mode(m: ModeUtilisateurs) -> &'static str {
    match m {
        ModeUtilisateurs::Aucun => "Aucun (libre service, journal anonyme)",
        ModeUtilisateurs::Identification => "Identification (identifiant)",
        ModeUtilisateurs::Authentification => "Authentification (identifiant + PIN)",
    }
}

pub fn sites(ctx: &Contexte, lignes: &[LigneSite], m: Option<(bool, &str)>) -> String {
    let mut c = Html::new();
    message(&mut c, m);
    c.b("<div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Site</th><th class=\"num\">Bornes</th><th>Mode utilisateur</th><th>Clés non enrôlées en entrée</th><th class=\"num\">Clés enrôlées</th></tr></thead><tbody>");
    if lignes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"5\">Aucun site : enrôlez une borne ou réglez un site ci-dessous.</td></tr>");
    }
    for l in lignes {
        c.b("<tr><td class=\"b-mono\">")
            .t(&l.site)
            .b("</td><td class=\"num\">")
            .n(l.bornes)
            .b("</td><td>");
        if ctx.admin() {
            c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/sites/mode\">");
            csrf(&mut c, ctx.csrf);
            c.b("<input type=\"hidden\" name=\"site\" value=\"")
                .t(&l.site)
                .b("\"><select class=\"b-saisie\" name=\"mode\" aria-label=\"Mode\">");
            for mode in [
                ModeUtilisateurs::Aucun,
                ModeUtilisateurs::Identification,
                ModeUtilisateurs::Authentification,
            ] {
                c.b("<option value=\"").b(nom_mode(mode)).b("\"");
                if mode == l.reglage.mode {
                    c.b(" selected");
                }
                c.b(">").b(libelle_mode(mode)).b("</option>");
            }
            c.b("</select> <button class=\"b-btn b-btn--petit\" type=\"submit\">Appliquer</button></form>");
        } else {
            c.b(libelle_mode(l.reglage.mode));
        }
        c.b("</td><td>");
        let interdite = l.reglage.entree_non_enrolees == EntreeNonEnrolees::Interdite;
        if ctx.admin() {
            c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/sites/entree\">");
            csrf(&mut c, ctx.csrf);
            c.b("<input type=\"hidden\" name=\"site\" value=\"")
                .t(&l.site)
                .b("\"><select class=\"b-saisie\" name=\"entree\" aria-label=\"Entrée\"><option value=\"autorisee\"");
            if !interdite {
                c.b(" selected");
            }
            c.b(">Autorisée (analyse)</option><option value=\"interdite\"");
            if interdite {
                c.b(" selected");
            }
            c.b(">Interdite</option></select> <button class=\"b-btn b-btn--petit\" type=\"submit\">Appliquer</button></form>");
        } else if interdite {
            etat(&mut c, "bloque", "Interdite");
        } else {
            etat(&mut c, "sain", "Autorisée");
        }
        c.b("</td><td class=\"num\">").n(l.cles).b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    if ctx.admin() {
        c.b("<div class=\"b-carte\"><h2>Régler un autre site</h2><form class=\"b-formulaire\" method=\"post\" action=\"/sites/mode\">");
        csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"site\">Site</label><input class=\"b-saisie b-mono\" id=\"site\" name=\"site\" required maxlength=\"14\" placeholder=\"site-1\"></div><div class=\"b-champ\"><label for=\"mode\">Mode</label><select class=\"b-saisie\" id=\"mode\" name=\"mode\"><option value=\"aucun\">Aucun</option><option value=\"identification\">Identification</option><option value=\"authentification\">Authentification</option></select></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Appliquer</button></div></form></div>");
    }
    c.b("<p class=\"b-aide\">Défaut : mode Aucun et clés non enrôlées admises en entrée (comportement de la v1). La sortie (copie, blanchiment) ne se fait que vers une clé enrôlée avec l'usage « sortie ». Le mode Aucun est interdit si la quarantaine est activée. Les bornes appliquent la politique à leur prochain contact (60 s).</p>");
    coque(
        ctx,
        Rubrique::Sites,
        "Sites et modes",
        "Sites : mode utilisateur et politique USB",
        Html::new(),
        c,
    )
}

pub fn cles_usb(ctx: &Contexte, b: &BaseUtilisateurs, m: Option<(bool, &str)>) -> String {
    let mut c = Html::new();
    message(&mut c, m);
    if ctx.admin() {
        c.b("<div class=\"b-carte\"><h2>Enrôler une clé</h2><form class=\"b-formulaire\" method=\"post\" action=\"/cles-usb/enroler\">");
        csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"fabricant\">Fabricant (identifiant USB)</label><input class=\"b-saisie b-mono\" id=\"fabricant\" name=\"fabricant\" required maxlength=\"6\" placeholder=\"0781\"></div><div class=\"b-champ\"><label for=\"serie\">Numéro de série</label><input class=\"b-saisie b-mono\" id=\"serie\" name=\"serie\" required maxlength=\"64\" autocapitalize=\"characters\" spellcheck=\"false\"></div><div class=\"b-champ\"><label for=\"libelle\">Libellé</label><input class=\"b-saisie\" id=\"libelle\" name=\"libelle\" maxlength=\"64\"></div><div class=\"b-champ\"><label for=\"site\">Site (vide : tous les sites)</label><input class=\"b-saisie b-mono\" id=\"site\" name=\"site\" maxlength=\"14\" placeholder=\"site-1\"></div><div class=\"b-champ\"><label><input type=\"checkbox\" name=\"entree\" value=\"1\" checked> Entrée (clé source analysée)</label><label><input type=\"checkbox\" name=\"sortie\" value=\"1\" checked> Sortie (copie, blanchiment)</label></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Enrôler</button></div></form>");
        avis(
            &mut c,
            "b-avis--alerte",
            "Le fabricant et le numéro de série d'une clé sont falsifiables : l'enrôlement sert à la gestion et à la traçabilité. L'analyse reste toujours obligatoire.",
        );
        c.b("</div>");
    }
    c.b("<h2>Clés enrôlées</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Clé</th><th>Libellé</th><th>Fabricant</th><th>Numéro de série</th><th>Site</th><th>Usages</th><th>Enrôlée</th>");
    if ctx.admin() {
        c.b("<th>Action</th>");
    }
    c.b("</tr></thead><tbody>");
    if b.cles_usb.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"8\">Aucune clé enrôlée.</td></tr>");
    }
    for k in &b.cles_usb {
        c.b("<tr><td class=\"b-mono\">")
            .t(&k.id)
            .b("</td><td>")
            .t(&k.libelle)
            .b("</td><td class=\"b-mono\">")
            .t(&k.fabricant)
            .b("</td><td class=\"b-mono b-coupe\">")
            .t(&k.serie)
            .b("</td><td class=\"b-mono\">")
            .t(k.site.as_deref().unwrap_or("tous"))
            .b("</td><td>");
        if k.entree {
            etat(&mut c, "sain", "entrée");
        }
        if k.sortie {
            c.b(" ");
            etat(&mut c, "sain", "sortie");
        }
        c.b("</td><td>").t(&date_utc(k.enrolee_le)).b("</td>");
        if ctx.admin() {
            c.b("<td>");
            bouton_action(
                &mut c,
                ctx,
                "/cles-usb/retirer",
                "id",
                &k.id,
                "Retirer",
                "b-btn--danger",
            );
            c.b("</td>");
        }
        c.b("</tr>");
    }
    c.b("</tbody></table></div>");
    coque(
        ctx,
        Rubrique::ClesUsb,
        "Clés USB",
        "Clés USB enrôlées",
        Html::new(),
        c,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbacane_passerelle::utilisateurs::CleUsb;

    fn ctx(role: Role) -> Contexte<'static> {
        Contexte {
            compte: "a",
            role,
            csrf: "jeton",
            maintenant: 100,
        }
    }

    fn base() -> BaseUtilisateurs {
        let mut b = BaseUtilisateurs::default();
        b.utilisateurs.push(Utilisateur {
            identifiant: "j.dupont".into(),
            pseudonyme: "u-0011223344556677".into(),
            actif: true,
            ajoute_le: 1,
            retire_le: None,
            pin: Some("$argon2id$x".into()),
            pin_le: Some(1),
            pin_a_changer: false,
            echecs: 5,
            verrouille_le: Some(50),
            derniere_verification: Some(50),
        });
        b.cles_usb.push(CleUsb {
            id: "usb-01020304".into(),
            fabricant: "0781".into(),
            serie: "4C53".into(),
            libelle: "<script>alert(1)</script>".into(),
            site: None,
            entree: true,
            sortie: false,
            enrolee_le: 1,
        });
        b
    }

    fn vue(b: &BaseUtilisateurs) -> VueUtilisateurs<'_> {
        VueUtilisateurs {
            base: b,
            annuaire_configure: true,
            recherche: None,
            pin: None,
            message: None,
            maintenant: 100,
        }
    }

    #[test]
    fn pseudonymisation_selon_le_role() {
        let b = base();
        let admin = utilisateurs(&ctx(Role::Administrateur), &vue(&b));
        assert!(
            !admin.contains("j.dupont"),
            "administrateur : pseudonymes seulement"
        );
        assert!(admin.contains("u-0011223344556677") && admin.contains("Verrouillé"));
        assert!(!admin.contains("$argon2id"), "jamais le dérivé");
        let aud = utilisateurs(&ctx(Role::Auditeur), &vue(&b));
        assert!(aud.contains("j.dupont"), "auditeur : en clair");
        assert!(
            !aud.contains("/utilisateurs/synchroniser")
                && !aud.contains("method=\"post\" action=\"/utilisateurs/pin")
        );
    }

    #[test]
    fn echappement_et_formulaires() {
        let b = base();
        let p = cles_usb(&ctx(Role::Administrateur), &b, Some((false, "<b>x</b>")));
        assert!(!p.contains("<script>") && p.contains("&lt;script&gt;"));
        assert!(!p.contains("<b>x</b>"));
        assert!(p.contains("value=\"jeton\""));
        assert!(!p.contains("style=") && !p.contains("<script"));
        let a = cles_usb(&ctx(Role::Auditeur), &b, None);
        assert!(
            !a.contains("<form") || a.matches("<form").count() == 1,
            "déconnexion seule"
        );
        let s = sites(
            &ctx(Role::Auditeur),
            &[LigneSite {
                site: "site-1".into(),
                bornes: 2,
                reglage: ReglageSite::default(),
                cles: 1,
            }],
            None,
        );
        assert!(!s.contains("/sites/mode") && s.contains("Aucun (libre service"));
    }
}
