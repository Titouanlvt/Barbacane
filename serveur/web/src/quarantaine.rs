//! Page « Quarantaine » (administrateur seulement ; `docs/suite/quarantaine.md`).
//!
//! Désactivée par défaut : la page affiche l'état et sa raison (verrou d'homologation ou absence
//! d'activation). Activation et export par double validation (deux administrateurs distincts).
//! L'export est restitué en pièce jointe neutralisée (nom `quarantaine-<id>.bin`,
//! `application/octet-stream`), jamais affiché. Tout accès est audité. Auditeur : 403.

use std::collections::BTreeMap;

use anyhow::Result;
use barbacane_passerelle::outils::date_utc;
use barbacane_passerelle::quarantaine::{
    Action, CONSERVATION_J, Element, Quarantaine, Statut, Validation,
};

use crate::comptes::Role;
use crate::html::Html;
use crate::http::Reponse;
use crate::pages::{self, Contexte, Rubrique};
use crate::{Utilisateur, Web, refus};

pub const ROUTE: &str = "/quarantaine";
pub const ROUTE_ACTIVER: &str = "/quarantaine/activer";
pub const ROUTE_VALIDER: &str = "/quarantaine/valider";
pub const ROUTE_DESACTIVER: &str = "/quarantaine/desactiver";
pub const ROUTE_EXPORTER: &str = "/quarantaine/exporter";

fn bouton(c: &mut Html, ctx: &Contexte, route: &str, champ: Option<(&str, &str)>, libelle: &str) {
    c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"")
        .t(route)
        .b("\">");
    pages::csrf(c, ctx.csrf);
    if let Some((k, v)) = champ {
        c.b("<input type=\"hidden\" name=\"")
            .t(k)
            .b("\" value=\"")
            .t(v)
            .b("\">");
    }
    c.b("<button class=\"b-btn\" type=\"submit\">")
        .t(libelle)
        .b("</button></form>");
}

pub fn page(
    ctx: &Contexte,
    s: &Statut,
    elements: &[Element],
    message: Option<(bool, &str)>,
) -> String {
    let mut c = Html::new();
    if let Some((ok, m)) = message {
        pages::avis(
            &mut c,
            if ok { "b-avis--sain" } else { "b-avis--bloque" },
            m,
        );
    }
    c.b("<h2>État</h2><p>");
    if s.active {
        pages::etat(&mut c, "alerte", "Active");
        c.b(" Fichiers bloqués reçus, chiffrés, conservés ")
            .t(&CONSERVATION_J.to_string())
            .b(" jours.</p>");
    } else {
        pages::etat(&mut c, "hors", "Désactivée");
        c.b("</p>");
        pages::avis(&mut c, "b-avis--alerte", s.raison.as_deref().unwrap_or(""));
    }
    c.b("<div class=\"b-formulaire__actions\">");
    if s.active {
        bouton(&mut c, ctx, ROUTE_DESACTIVER, None, "Désactiver");
    } else {
        bouton(&mut c, ctx, ROUTE_ACTIVER, None, "Demander l'activation");
    }
    c.b("</div>");
    c.b("<h2>Demandes en attente d'un second administrateur</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Demande</th><th>Par</th><th>Le</th><th>Action</th></tr></thead><tbody>");
    if s.demandes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"4\">Aucune.</td></tr>");
    }
    for d in &s.demandes {
        let quoi = match &d.action {
            Action::Activation => "Activation".to_owned(),
            Action::Export { element } => format!("Export de {element}"),
        };
        c.b("<tr><td>")
            .t(&quoi)
            .b("</td><td>")
            .t(&d.par)
            .b("</td><td>")
            .t(&date_utc(d.le))
            .b("</td><td>");
        bouton(
            &mut c,
            ctx,
            ROUTE_VALIDER,
            Some(("demande", &d.id)),
            "Valider (second administrateur)",
        );
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    c.b("<h2>Éléments chiffrés</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Élément</th><th>Borne</th><th>Reçu</th><th>Purge</th><th>Taille</th><th>Action</th></tr></thead><tbody>");
    if elements.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"6\">Aucun.</td></tr>");
    }
    for e in elements {
        c.b("<tr><td class=\"b-mono\">")
            .t(&e.id)
            .b("</td><td class=\"b-mono\">")
            .t(&e.borne)
            .b("</td><td>")
            .t(&date_utc(e.recu_le))
            .b("</td><td>")
            .t(&date_utc(e.expire_le))
            .b("</td><td>")
            .t(&e.taille.to_string())
            .b("</td><td>");
        if s.active {
            bouton(
                &mut c,
                ctx,
                ROUTE_EXPORTER,
                Some(("element", &e.id)),
                "Demander l'export",
            );
        }
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    pages::coque(
        ctx,
        Rubrique::Quarantaine,
        "Quarantaine",
        "Quarantaine",
        Html::new(),
        c,
    )
}

impl Web {
    fn quarantaine(&self) -> Result<Quarantaine> {
        let stockage = barbacane_passerelle::registre::Stockage::ouvrir(&self.passerelle.registre)?;
        Quarantaine::ouvrir(&stockage)
    }

    pub(crate) fn page_quarantaine(
        &self,
        u: &Utilisateur,
        t: u64,
        message: Option<(bool, &str)>,
    ) -> Result<Reponse> {
        if u.role != Role::Administrateur {
            return Ok(refus(403, "Page réservée aux administrateurs."));
        }
        self.auditer(&u.acteur(), "consultation-quarantaine")?;
        let q = self.quarantaine()?;
        let s = q.statut(t)?;
        let e = q.elements(t)?;
        let statut = if message.is_some_and(|(ok, _)| !ok) {
            400
        } else {
            200
        };
        Ok(Reponse::html(statut, page(&u.contexte(t), &s, &e, message)))
    }

    /// POST de la rubrique ; `None` si la route n'en est pas.
    pub(crate) fn post_quarantaine(
        &self,
        chemin: &str,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Option<Reponse>> {
        if !chemin.starts_with("/quarantaine/") {
            return Ok(None);
        }
        if u.role != Role::Administrateur {
            return Ok(Some(refus(403, "Rôle auditeur : lecture seule.")));
        }
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("");
        let q = self.quarantaine()?;
        let a = u.acteur();
        let r = match chemin {
            ROUTE_ACTIVER => q.demander_activation(&a, t).map(|_| {
                "Activation demandée : un SECOND administrateur doit la valider (1 h).".to_owned()
            }),
            ROUTE_DESACTIVER => q
                .desactiver(&a)
                .map(|_| "Quarantaine désactivée.".to_owned()),
            ROUTE_EXPORTER => q.demander_export(champ("element"), &a, t).map(|_| {
                "Export demandé : un SECOND administrateur doit le valider (1 h).".to_owned()
            }),
            ROUTE_VALIDER => match q.valider(champ("demande"), &a, t) {
                Ok(Validation::Activee) => {
                    Ok("Quarantaine activée (double validation).".to_owned())
                }
                Ok(Validation::Export(e, contenu)) => {
                    let mut rep = Reponse::texte(200, "");
                    rep.type_contenu = "application/octet-stream";
                    rep.corps = contenu;
                    rep.entetes.push((
                        "Content-Disposition",
                        format!("attachment; filename=\"quarantaine-{}.bin\"", e.id),
                    ));
                    return Ok(Some(rep));
                }
                Err(e) => Err(e),
            },
            _ => return Ok(Some(refus(404, "Page introuvable."))),
        };
        Ok(Some(match r {
            Ok(m) => self.page_quarantaine(u, t, Some((true, &m)))?,
            Err(e) => self.page_quarantaine(u, t, Some((false, &format!("{e:#}"))))?,
        }))
    }
}
