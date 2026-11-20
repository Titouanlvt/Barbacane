//! Rapports minimaux de passage (`docs/suite/protocole-agent.md` §10) : lecture seule, pour
//! tous les rôles. Aucun nom de fichier n'existe dans ces données (D2) : taille, SHA-256 et
//! verdict seulement.

use std::collections::BTreeMap;

use barbacane_passerelle::outils::date_utc;
use barbacane_passerelle::passages::{Resume, Stocke};
use barbacane_protocole::passage::Verdict;

use crate::html::Html;
use crate::pages::{Contexte, Rubrique, coque, etat, grouper, tuile};

/// Passages affichés au plus dans la liste.
pub const PASSAGES_AFFICHES: usize = 200;

fn libelle(v: Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::Sain => ("sain", "Sain"),
        Verdict::Menace => ("bloque", "Menace"),
        Verdict::Refuse => ("alerte", "Refusé"),
        Verdict::Erreur => ("alerte", "Erreur d'analyse"),
    }
}

fn nom_borne<'a>(noms: &'a BTreeMap<String, String>, uuid: &'a str) -> &'a str {
    noms.get(uuid).map(String::as_str).unwrap_or(uuid)
}

pub fn liste(ctx: &Contexte, lignes: &[Resume], noms: &BTreeMap<String, String>) -> String {
    let mut c = Html::new();
    let compte = |v: Verdict| lignes.iter().filter(|l| l.verdict == v).count();
    c.b("<div class=\"b-tuiles\">");
    tuile(&mut c, lignes.len(), "", "Parties reçues (affichées)");
    tuile(&mut c, compte(Verdict::Menace), "bloque", "Menaces");
    tuile(&mut c, compte(Verdict::Refuse), "alerte", "Refus");
    tuile(
        &mut c,
        compte(Verdict::Erreur),
        "alerte",
        "Erreurs d'analyse",
    );
    c.b("</div><p class=\"b-douce\">Rapports minimaux envoyés par les bornes en ligne : aucun nom de fichier ni chemin, seulement la taille, l'empreinte SHA-256 et le verdict de chaque fichier. Support : SHA-256 de fabricant, produit et numéro de série.</p>");
    c.b("<div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Reçu le</th><th>Borne</th><th>Passage</th><th>Support</th><th>Verdict</th><th class=\"num\">Fichiers</th><th class=\"num\">Menaces</th><th class=\"num\">Refus</th></tr></thead><tbody>");
    if lignes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"8\">Aucun rapport de passage reçu.</td></tr>");
    }
    for l in lignes {
        let (classe, mot) = libelle(l.verdict);
        c.b("<tr><td>")
            .t(&date_utc(l.recu_le))
            .b("</td><td class=\"b-mono\">")
            .t(nom_borne(noms, &l.borne))
            .b("</td><td class=\"b-mono\"><a href=\"/passages/detail?borne=")
            .u(&l.borne)
            .b("&amp;id=")
            .u(&l.id)
            .b("&amp;partie=")
            .n(l.partie)
            .b("\">")
            .t(&l.id[..8.min(l.id.len())])
            .b("…</a>");
        if l.parties > 1 {
            c.b(" <span class=\"b-douce\">")
                .n(l.partie)
                .b("/")
                .n(l.parties)
                .b("</span>");
        }
        c.b("</td><td class=\"b-mono\">")
            .t(&grouper(&l.support[..16.min(l.support.len())]))
            .b("…</td><td>");
        etat(&mut c, classe, mot);
        c.b("</td><td class=\"num\">")
            .n(l.fichiers)
            .b("</td><td class=\"num\">")
            .n(l.menaces)
            .b("</td><td class=\"num\">")
            .n(l.refuses)
            .b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    coque(
        ctx,
        Rubrique::Passages,
        "Passages",
        "Rapports de passage",
        Html::new(),
        c,
    )
}

pub fn detail(ctx: &Contexte, borne: &str, s: &Stocke, noms: &BTreeMap<String, String>) -> String {
    let r = &s.rapport;
    let (classe, mot) = libelle(r.verdict);
    let mut actions = Html::new();
    actions.b("<a class=\"b-btn\" href=\"/passages\">Retour à la liste</a>");
    let mut c = Html::new();
    c.b("<div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><tbody><tr><th>Borne</th><td class=\"b-mono\">")
        .t(nom_borne(noms, borne))
        .b("</td></tr><tr><th>Passage</th><td class=\"b-mono\">")
        .t(&r.id)
        .b("</td></tr><tr><th>Partie</th><td>")
        .n(r.partie)
        .b(" / ")
        .n(r.parties)
        .b("</td></tr><tr><th>Fin de l'analyse (heure de la borne)</th><td>")
        .t(&date_utc(r.horodatage))
        .b("</td></tr><tr><th>Reçu le</th><td>")
        .t(&date_utc(s.recu_le))
        .b("</td></tr><tr><th>Support</th><td class=\"b-mono b-coupe\">")
        .t(&grouper(&r.support))
        .b("</td></tr><tr><th>Verdict</th><td>");
    etat(&mut c, classe, mot);
    c.b("</td></tr></tbody></table></div><h2>Fichiers</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th class=\"num\">Taille (octets)</th><th>SHA-256</th><th>Verdict</th></tr></thead><tbody>");
    if r.fichiers.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"3\">Aucun fichier.</td></tr>");
    }
    for f in &r.fichiers {
        let (classe, mot) = libelle(f.verdict);
        c.b("<tr><td class=\"num\">")
            .n(f.taille)
            .b("</td><td class=\"b-mono b-coupe\">")
            .t(&grouper(&f.sha256))
            .b("</td><td>");
        etat(&mut c, classe, mot);
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    coque(
        ctx,
        Rubrique::Passages,
        "Passages",
        "Détail d'un passage",
        actions,
        c,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comptes::Role;
    use barbacane_protocole::passage::{FichierPassage, RapportPassage};

    fn ctx() -> Contexte<'static> {
        Contexte {
            compte: "a",
            role: Role::Auditeur,
            csrf: "jeton",
            maintenant: 100,
        }
    }

    #[test]
    fn lecture_seule_sans_javascript() {
        let r = Resume {
            borne: "0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            id: "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            partie: 1,
            parties: 2,
            verdict: Verdict::Menace,
            support: "c".repeat(64),
            horodatage: 1,
            recu_le: 2,
            fichiers: 2,
            menaces: 1,
            refuses: 0,
        };
        let mut noms = BTreeMap::new();
        noms.insert(r.borne.clone(), "<borne-01>".into());
        let p = liste(&ctx(), std::slice::from_ref(&r), &noms);
        assert!(p.contains("&lt;borne-01&gt;") && p.contains("Menace") && p.contains("1/2"));
        assert!(
            !p.contains("<script") && p.matches("<form").count() == 1,
            "déconnexion seule"
        );
        let s = Stocke {
            recu_le: 2,
            rapport: RapportPassage {
                version: 1,
                id: r.id.clone(),
                horodatage: 1,
                verdict: Verdict::Menace,
                support: r.support.clone(),
                partie: 1,
                parties: 2,
                fichiers: vec![FichierPassage {
                    taille: 68,
                    sha256: "a".repeat(64),
                    verdict: Verdict::Menace,
                }],
            },
        };
        let d = detail(&ctx(), &r.borne, &s, &noms);
        assert!(d.contains("aaaa aaaa") && d.contains("68"));
        assert!(!d.contains("<script") && d.matches("<form").count() == 1);
    }
}
