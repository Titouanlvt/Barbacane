//! Pages « Comptes » (comptes de la Console, demandes de double validation) et « Mot de passe ».
//! Fonctions pures : données en entrée, HTML en sortie (`docs/suite/comptes-administrateurs.md`).

use barbacane_passerelle::outils::date_utc;

use crate::comptes::{BaseComptes, Compte, Droit, MOT_DE_PASSE_MIN, PHRASE_DE_PASSE_MIN, ROLES};
use crate::html::Html;
use crate::pages::{self, Contexte, Rubrique, avis, csrf, etat};
use crate::validations::{DUREE_S, Demande};

/// Secrets remis UNE fois après une création, une réinitialisation ou une émission.
pub struct Remise<'a> {
    pub identifiant: &'a str,
    pub mdp_provisoire: Option<&'a str>,
    /// Mot de passe du `.p12` et jeton du téléchargement unique.
    pub p12: Option<(&'a str, &'a str)>,
}

pub struct VueComptes<'a> {
    pub base: &'a BaseComptes,
    pub demandes: &'a [Demande],
    pub demandes_quarantaine: usize,
    pub ca_presente: bool,
    pub message: Option<(bool, &'a str)>,
    pub remise: Option<Remise<'a>>,
}

fn bouton(
    c: &mut Html,
    ctx: &Contexte,
    route: &'static str,
    champs: &[(&str, &str)],
    libelle: &str,
    danger: bool,
) {
    c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"")
        .b(route)
        .b("\">");
    csrf(c, ctx.csrf);
    for (k, v) in champs {
        c.b("<input type=\"hidden\" name=\"")
            .t(k)
            .b("\" value=\"")
            .t(v)
            .b("\">");
    }
    c.b(if danger {
        "<button class=\"b-btn b-btn--petit b-btn--danger\" type=\"submit\">"
    } else {
        "<button class=\"b-btn b-btn--petit\" type=\"submit\">"
    })
    .t(libelle)
    .b("</button></form> ");
}

fn remise(c: &mut Html, ctx: &Contexte, r: &Remise) {
    c.b("<div class=\"b-carte\"><h2>À remettre à ")
        .t(r.identifiant)
        .b(" — affiché une seule fois</h2>");
    avis(
        c,
        "b-avis--alerte",
        "Notez ces éléments maintenant : ils ne sont conservés nulle part (seul le hachage Argon2id du mot de passe l'est) et ne seront plus affichés. Remettez le certificat et ses deux mots de passe par des canaux séparés.",
    );
    if let Some(m) = r.mdp_provisoire {
        c.b(
            "<p>Mot de passe provisoire (à changer à la première connexion) : <b class=\"b-mono\">",
        )
        .t(m)
        .b("</b></p>");
    }
    if let Some((mdp, jeton)) = r.p12 {
        c.b("<p>Mot de passe du fichier .p12 : <b class=\"b-mono\">")
            .t(mdp)
            .b("</b></p>");
        bouton(
            c,
            ctx,
            "/comptes/p12",
            &[("jeton", jeton)],
            "Télécharger le certificat (.p12, une seule fois)",
            false,
        );
    }
    c.b("</div>");
}

fn ligne(c: &mut Html, ctx: &Contexte, k: &Compte, ca: bool) {
    c.b("<tr><td class=\"b-mono\">")
        .t(&k.identifiant)
        .b("</td><td>")
        .b(k.role.libelle())
        .b("</td><td>");
    if !k.actif {
        etat(c, "hors", "Désactivé");
    } else if k.changer_mot_de_passe {
        etat(c, "cours", "Mot de passe à changer");
    } else {
        etat(c, "sain", "Actif");
    }
    c.b("</td><td>");
    match (&k.empreinte_certificat, &k.serie_certificat) {
        (None, _) => {
            etat(c, "alerte", "Aucun");
        }
        (Some(e), s) => {
            c.b("<span class=\"b-mono\" title=\"SHA-256\">")
                .t(&e[..16])
                .b("…</span>");
            if let Some(s) = s {
                c.b("<br><span class=\"b-douce\">série ").t(s).b("</span>");
            }
            if let Some(x) = k.certificat_expire_le {
                c.b("<br><span class=\"b-douce\">expire le ")
                    .t(&date_utc(x))
                    .b("</span>");
            }
        }
    }
    c.b("</td><td>");
    match k.dernier_acces {
        Some(d) => {
            c.t(&date_utc(d));
        }
        None => {
            c.b("Jamais");
        }
    }
    c.b("<br><span class=\"b-douce\">créé par ")
        .t(&k.cree_par)
        .b("</span></td><td>");
    if ctx.peut(Droit::Administrer) {
        let id = k.identifiant.as_str();
        if k.actif {
            bouton(
                c,
                ctx,
                "/comptes/desactiver",
                &[("identifiant", id)],
                "Désactiver",
                false,
            );
        } else {
            bouton(
                c,
                ctx,
                "/comptes/reactiver",
                &[("identifiant", id)],
                "Réactiver…",
                false,
            );
        }
        c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/comptes/role\">");
        csrf(c, ctx.csrf);
        c.b("<input type=\"hidden\" name=\"identifiant\" value=\"")
            .t(id)
            .b("\"><select class=\"b-saisie\" name=\"role\" aria-label=\"Rôle\">");
        for r in ROLES {
            c.b("<option value=\"").b(r.nom()).b("\"");
            if r == k.role {
                c.b(" selected");
            }
            c.b(">").b(r.libelle()).b("</option>");
        }
        c.b("</select> <button class=\"b-btn b-btn--petit\" type=\"submit\">Changer le rôle</button></form> ");
        if id != ctx.compte {
            bouton(
                c,
                ctx,
                "/comptes/reinitialiser",
                &[("identifiant", id)],
                "Réinitialiser le mot de passe",
                false,
            );
        }
        if ca {
            bouton(
                c,
                ctx,
                "/comptes/emettre",
                &[("identifiant", id)],
                "Nouveau certificat…",
                false,
            );
        }
        if k.empreinte_certificat.is_some() {
            bouton(
                c,
                ctx,
                "/comptes/revoquer",
                &[("identifiant", id)],
                "Révoquer le certificat…",
                true,
            );
        }
        bouton(
            c,
            ctx,
            "/comptes/supprimer",
            &[("identifiant", id)],
            "Supprimer…",
            true,
        );
    }
    c.b("</td></tr>");
}

pub fn comptes(ctx: &Contexte, v: &VueComptes) -> String {
    let mut c = Html::new();
    if let Some((ok, m)) = v.message {
        avis(
            &mut c,
            if ok { "b-avis--sain" } else { "b-avis--bloque" },
            m,
        );
    }
    if let Some(r) = &v.remise {
        remise(&mut c, ctx, r);
    }
    c.b("<h2>Demandes en attente d'un second administrateur</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Action</th><th>Demandée par</th><th>Le</th><th>Expire</th><th>Décision</th></tr></thead><tbody>");
    if v.demandes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"5\">Aucune.</td></tr>");
    }
    for d in v.demandes {
        c.b("<tr><td>")
            .t(&d.operation.libelle())
            .b("</td><td class=\"b-mono\">")
            .t(&d.par)
            .b("</td><td>")
            .t(&date_utc(d.le))
            .b("</td><td>")
            .t(&date_utc(d.le + DUREE_S))
            .b("</td><td>");
        if ctx.peut(Droit::Administrer) {
            if d.par != ctx.compte {
                bouton(
                    &mut c,
                    ctx,
                    "/validations/valider",
                    &[("demande", &d.id)],
                    "Valider (second administrateur)",
                    false,
                );
            } else {
                c.b("<span class=\"b-douce\">Votre demande : un autre administrateur doit la valider.</span> ");
            }
            bouton(
                &mut c,
                ctx,
                "/validations/annuler",
                &[("demande", &d.id)],
                "Annuler",
                false,
            );
        }
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    if v.demandes_quarantaine > 0 {
        c.b("<p>")
            .n(v.demandes_quarantaine)
            .b(" demande(s) de la quarantaine attendent aussi : <a href=\"/quarantaine\">page Quarantaine</a>.</p>");
    }
    c.b("<h2>Comptes</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Compte</th><th>Rôle</th><th>État</th><th>Certificat</th><th>Dernier accès</th><th>Actions</th></tr></thead><tbody>");
    for k in &v.base.comptes {
        ligne(&mut c, ctx, k, v.ca_presente);
    }
    c.b("</tbody></table></div>");
    if ctx.peut(Droit::Administrer) {
        c.b("<div class=\"b-carte\"><h2>Créer un compte</h2><form class=\"b-formulaire\" method=\"post\" action=\"/comptes/creer\" autocomplete=\"off\">");
        csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"identifiant\">Identifiant</label><input class=\"b-saisie b-mono\" id=\"identifiant\" name=\"identifiant\" required maxlength=\"32\" pattern=\"[a-z0-9._\\-]{1,32}\" placeholder=\"admin-02\" autocapitalize=\"none\" spellcheck=\"false\"></div><div class=\"b-champ\"><label for=\"role\">Rôle</label><select class=\"b-saisie\" id=\"role\" name=\"role\">");
        for r in ROLES {
            c.b("<option value=\"")
                .b(r.nom())
                .b("\">")
                .b(r.libelle())
                .b("</option>");
        }
        c.b("</select></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Demander la création</button></div></form>");
        if !v.ca_presente {
            avis(
                &mut c,
                "b-avis--alerte",
                "La clé de la CA des administrateurs n'est pas sur ce serveur : la Console ne peut pas émettre de certificat (création et nouveau certificat refusés).",
            );
        }
        c.b("</div>");
    }
    c.b("<p class=\"b-aide\">Double validation : création, suppression, réactivation, passage au rôle administrateur, émission et révocation de certificat, révocation de toutes les bornes d'un site, activation, désactivation et export de la quarantaine. Une demande expire après 1 h et ne peut pas être validée par son auteur. Seule exception : tant qu'il n'existe qu'UN administrateur utilisable, il crée seul le second administrateur (inscrit au journal). Désactivation, rétrogradation et réinitialisation du mot de passe : un seul administrateur (sens sûr), jamais pour le dernier administrateur.</p>");
    pages::coque(
        ctx,
        Rubrique::Comptes,
        "Comptes",
        "Comptes de la Console",
        Html::new(),
        c,
    )
}

/// Changement de mot de passe (page seule, sans navigation : aussi pendant le changement forcé).
pub fn mot_de_passe(ctx: &Contexte, force: bool, message: Option<(bool, &str)>) -> String {
    let mut h = Html::new();
    pages::tete(&mut h, "Mot de passe");
    h.b("<body class=\"b-page\"><main class=\"b-seul\"><div class=\"b-carte\"><div class=\"b-seul__marque\">")
        .b(pages::SYMBOLE)
        .b(" Barbacane</div><h1 class=\"b-carte__titre\">Changer le mot de passe</h1><p class=\"b-douce\">Compte <b>")
        .t(ctx.compte)
        .b("</b>.</p>");
    if force {
        avis(
            &mut h,
            "b-avis--alerte",
            "Mot de passe provisoire : choisissez votre mot de passe avant d'utiliser la Console.",
        );
    }
    if let Some((ok, m)) = message {
        avis(
            &mut h,
            if ok { "b-avis--sain" } else { "b-avis--bloque" },
            m,
        );
    }
    h.b("<form class=\"b-formulaire\" method=\"post\" action=\"/mot-de-passe\" autocomplete=\"off\">");
    csrf(&mut h, ctx.csrf);
    h.b("<div class=\"b-champ\"><label for=\"actuel\">Mot de passe actuel</label><input class=\"b-saisie\" id=\"actuel\" name=\"actuel\" type=\"password\" required maxlength=\"256\"></div><div class=\"b-champ\"><label for=\"nouveau\">Nouveau mot de passe</label><input class=\"b-saisie\" id=\"nouveau\" name=\"nouveau\" type=\"password\" required maxlength=\"256\"></div><div class=\"b-champ\"><label for=\"confirmation\">Confirmation</label><input class=\"b-saisie\" id=\"confirmation\" name=\"confirmation\" type=\"password\" required maxlength=\"256\"></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Changer</button></div></form><p class=\"b-aide\">")
        .n(MOT_DE_PASSE_MIN)
        .b(" caractères au moins, 3 types parmi minuscules, majuscules, chiffres et autres (ou une phrase de passe de ")
        .n(PHRASE_DE_PASSE_MIN)
        .b(" caractères), sans votre identifiant.</p>");
    if !force {
        h.b("<p><a href=\"/tableau\">Retour au tableau de bord</a></p>");
    }
    h.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/deconnexion\">");
    csrf(&mut h, ctx.csrf);
    h.b("<button class=\"b-btn b-btn--discret\" type=\"submit\">Se déconnecter</button></form></div></main></body></html>");
    h.fin()
}
