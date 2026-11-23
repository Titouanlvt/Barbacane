//! Page « Conservation et export du journal » (v2.3.0, `docs/suite/journal-conservation.md`,
//! `docs/suite/journal-syslog.md`).
//!
//! Lecture : administrateur et auditeur (droit « journal »). Actions : administrateur seul ;
//! tout changement de la durée de conservation ou de l'export Syslog (y compris sa
//! désactivation) passe par la double validation (`validations.rs`), comme les comptes.
//! L'export du journal structuré (JSON par ligne) est journalisé.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use barbacane_audit::conservation::{
    JOURS_DEFAUT, JOURS_MAX, JOURS_MIN, JOURS_SANS_JUSTIFICATION, Reglage,
};
use barbacane_audit::{Enregistrement, structure};
use barbacane_passerelle::outils::date_utc;
use barbacane_passerelle::syslog::{self, Actif, ConfigSyslog, Etat, Mode};

use crate::comptes::Droit;
use crate::html::Html;
use crate::http::Reponse;
use crate::pages::{self, Contexte, Rubrique};
use crate::validations::{self, Demande, Operation};
use crate::{Utilisateur, Web, refus};

pub const ROUTE: &str = "/journal";
pub const ROUTE_EXPORT: &str = "/journal/export";
pub const ROUTE_CONSERVATION: &str = "/journal/conservation";
pub const ROUTE_SYSLOG: &str = "/journal/syslog";
pub const ROUTE_CLE: &str = "/journal/syslog/cle";
pub const ROUTE_CERTIFICAT: &str = "/journal/syslog/certificat";

/// Données de la page.
pub struct Vue<'a> {
    pub reglage: Option<&'a Reglage>,
    pub passages: u64,
    pub segments: usize,
    pub plus_ancien: Option<u64>,
    pub actif: Option<&'a Actif>,
    pub etat: Option<&'a Etat>,
    pub demandes: &'a [Demande],
    pub csr: Option<&'a str>,
    pub certificat_client: Option<&'a str>,
    pub resumes: &'a BTreeMap<String, String>,
    pub message: Option<(bool, &'a str)>,
}

/// Alertes de l'export (aussi montrées sur le tableau de bord).
pub fn alertes(actif: Option<&Actif>, etat: Option<&Etat>, t: u64) -> Vec<String> {
    let mut v = Vec::new();
    let Some(c) = actif.and_then(|a| a.config.as_ref()) else {
        return v;
    };
    if c.mode.clair() {
        v.push(format!(
            "Export Syslog EN CLAIR ({}) : non recommandé, le journal circule sans chiffrement sur le réseau local.",
            c.mode.libelle()
        ));
    }
    if let Some(e) = etat {
        if e.debordement {
            v.push(format!(
                "File d'export Syslog en DÉBORDEMENT : {} événements en attente (seuil {}). Rien n'est perdu tant que la conservation ne les purge pas ; rétablir le collecteur.",
                e.en_attente,
                syslog::FILE_MAX
            ));
        } else if e.etat == "injoignable" {
            v.push(format!(
                "Collecteur Syslog injoignable depuis le {} ({} événement(s) en attente) : {}",
                date_utc(e.depuis),
                e.en_attente,
                e.derniere_erreur.as_deref().unwrap_or("erreur inconnue")
            ));
        }
        if e.pertes > 0 {
            v.push(format!(
                "{} événement(s) purgé(s) par la conservation avant d'avoir été remis au collecteur (inscrit au journal).",
                e.pertes
            ));
        }
        if e.maj_le + 300 < t {
            v.push(format!(
                "L'exportateur Syslog ne s'est pas manifesté depuis le {} : service barbacane-syslog arrêté ?",
                date_utc(e.maj_le)
            ));
        }
    } else {
        v.push("Export Syslog réglé mais l'exportateur n'a encore rien écrit (service barbacane-syslog).".into());
    }
    v
}

fn ligne(c: &mut Html, terme: &str, valeur: &str) {
    c.b("<dt>").t(terme).b("</dt><dd>").t(valeur).b("</dd>");
}

fn bouton(
    c: &mut Html,
    ctx: &Contexte,
    route: &str,
    champs: &[(&str, &str)],
    libelle: &str,
    classe: &'static str,
) {
    c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"")
        .t(route)
        .b("\">");
    pages::csrf(c, ctx.csrf);
    for (k, v) in champs {
        c.b("<input type=\"hidden\" name=\"")
            .t(k)
            .b("\" value=\"")
            .t(v)
            .b("\">");
    }
    c.b("<button class=\"b-btn ")
        .b(classe)
        .b("\" type=\"submit\">")
        .t(libelle)
        .b("</button></form>");
}

pub fn page(ctx: &Contexte, v: &Vue) -> String {
    let admin = ctx.peut(Droit::Administrer);
    let t = ctx.maintenant;
    let mut c = Html::new();
    if let Some((ok, m)) = v.message {
        pages::avis(
            &mut c,
            if ok { "b-avis--sain" } else { "b-avis--bloque" },
            m,
        );
    }
    for a in alertes(v.actif, v.etat, t) {
        pages::avis(&mut c, "b-avis--alerte", &a);
    }
    // ── Conservation
    c.b("<div class=\"b-carte\"><h2>Conservation</h2><dl class=\"b-details\">");
    match v.reglage {
        None => ligne(
            &mut c,
            "Durée",
            &format!("{JOURS_DEFAUT} jours (défaut, posé au premier démarrage)"),
        ),
        Some(r) => {
            ligne(&mut c, "Durée choisie", &format!("{} jours", r.jours));
            ligne(&mut c, "Date d'effet", &date_utc(r.effective_le));
            ligne(
                &mut c,
                "Appliquée aujourd'hui",
                &match r.effectifs(t) {
                    Some(j) => format!(
                        "{j} jours : purge de ce qui est antérieur au {}",
                        date_utc(t.saturating_sub(u64::from(j) * 86400))
                    ),
                    None => format!(
                        "aucune purge avant le {} (préavis)",
                        date_utc(r.effective_le)
                    ),
                },
            );
            ligne(
                &mut c,
                "Réglée le, par",
                &format!("{} — {}", date_utc(r.regle_le), r.par),
            );
        }
    }
    ligne(
        &mut c,
        "Rapports de passage conservés",
        &v.passages.to_string(),
    );
    ligne(
        &mut c,
        "Journal d'audit",
        &format!(
            "{} segment(s) rangé(s){}",
            v.segments,
            v.plus_ancien
                .map(|p| format!(", plus ancien enregistrement du {}", date_utc(p)))
                .unwrap_or_default()
        ),
    );
    c.b("</dl><p class=\"b-aide\">S'applique aux rapports de passage, au journal d'audit (segments quotidiens scellés ; la chaîne restante reste vérifiable), aux correspondances identifiant ↔ pseudonyme et aux sauvegardes présentes sur le support monté. Purge chaque nuit (tâche barbacane-conservation) et au démarrage. Bornes : ")
        .n(JOURS_MIN)
        .b(" à ")
        .n(JOURS_MAX)
        .b(" jours. Une réduction prend effet après un préavis de 7 jours ; au-delà de ")
        .n(JOURS_SANS_JUSTIFICATION)
        .b(" jours, la justification est à consigner dans l'AIPD (CNIL).</p>");
    if admin {
        c.b("<form class=\"b-formulaire\" method=\"post\" action=\"")
            .b(ROUTE_CONSERVATION)
            .b("\">");
        pages::csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"jours\">Nouvelle durée (jours)</label><input class=\"b-saisie b-mono\" id=\"jours\" name=\"jours\" type=\"number\" required min=\"")
            .n(JOURS_MIN)
            .b("\" max=\"")
            .n(JOURS_MAX)
            .b("\"></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Demander le changement (second administrateur)</button></div></form>");
    }
    c.b("</div>");
    // ── Syslog
    c.b("<div class=\"b-carte\"><h2>Export Syslog</h2><dl class=\"b-details\">");
    match v.actif.and_then(|a| a.config.as_ref()) {
        None => ligne(&mut c, "Réglage", "désactivé"),
        Some(cfg) => {
            ligne(&mut c, "Transport", cfg.mode.libelle());
            ligne(
                &mut c,
                "Collecteur",
                &format!("{}:{}", cfg.adresse, cfg.port),
            );
            if let Some(n) = &cfg.nom {
                ligne(&mut c, "Nom attendu du certificat", n);
            }
            if let Some(h) = &cfg.ac {
                ligne(
                    &mut c,
                    "AC du collecteur",
                    &v.resumes.get(h).cloned().unwrap_or_else(|| h.clone()),
                );
            }
            ligne(
                &mut c,
                "Certificat client (mTLS)",
                cfg.certificat_client.as_deref().unwrap_or("non"),
            );
            if let Some(a) = v.actif {
                ligne(
                    &mut c,
                    "Réglé le, par",
                    &format!("{} — {}", date_utc(a.regle_le), a.par),
                );
            }
        }
    }
    if let Some(e) = v.etat {
        ligne(
            &mut c,
            "État",
            &format!("{} depuis le {}", e.etat, date_utc(e.depuis)),
        );
        ligne(
            &mut c,
            "Remis (confirmé) / dernier",
            &format!(
                "n° {} / n° {} — {} en attente",
                e.curseur, e.dernier, e.en_attente
            ),
        );
        if let Some(r) = e.remis_le {
            ligne(&mut c, "Dernière remise", &date_utc(r));
        }
        if let Some(m) = &e.derniere_erreur {
            ligne(&mut c, "Dernière erreur", m);
        }
    }
    c.b("</dl>");
    if admin {
        c.b("<form class=\"b-formulaire\" method=\"post\" action=\"")
            .b(ROUTE_SYSLOG)
            .b("\">");
        pages::csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"mode\">Transport</label><select class=\"b-saisie\" id=\"mode\" name=\"mode\"><option value=\"tls\">TLS 1.3 (RFC 5425, recommandé)</option><option value=\"tcp-clair\">TCP en clair (non recommandé)</option><option value=\"udp-clair\">UDP en clair, sans confirmation (non recommandé)</option><option value=\"desactive\">Désactiver l'export</option></select></div>");
        c.b("<div class=\"b-champ\"><label for=\"adresse\">Adresse IPv4 du collecteur (réseau local)</label><input class=\"b-saisie b-mono\" id=\"adresse\" name=\"adresse\" maxlength=\"15\" placeholder=\"10.0.3.100\"></div>");
        c.b("<div class=\"b-champ\"><label for=\"port\">Port</label><input class=\"b-saisie b-mono\" id=\"port\" name=\"port\" type=\"number\" min=\"1\" max=\"65535\" placeholder=\"6514\"></div>");
        c.b("<div class=\"b-champ\"><label for=\"nom\">TLS : nom attendu dans le certificat du collecteur</label><input class=\"b-saisie b-mono\" id=\"nom\" name=\"nom\" maxlength=\"253\" placeholder=\"collecteur.exemple.fr\"></div>");
        c.b("<div class=\"b-champ\"><label for=\"ac\">TLS : AC du collecteur (PEM ; vide = garder l'AC actuelle)</label><textarea class=\"b-saisie\" id=\"ac\" name=\"ac\" rows=\"6\"></textarea></div>");
        c.b("<div class=\"b-champ\"><label><input type=\"checkbox\" name=\"mtls\" value=\"oui\"> TLS : présenter le certificat client du serveur (mTLS)</label></div>");
        c.b("<p class=\"b-aide\">Le pare-feu du serveur n'ouvre que la cible validée. Aucun nom DNS : le serveur n'a pas de résolveur. En clair, le journal (pseudonymes, actions des administrateurs) circule sans protection : à réserver à un réseau d'administration physiquement maîtrisé.</p>");
        c.b("<div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Demander le changement (second administrateur)</button></div></form>");
        c.b("<h3>Certificat client (mTLS)</h3>");
        match v.certificat_client {
            Some(h) => {
                c.b("<p>Certificat déposé : <span class=\"b-mono\">")
                    .t(&v.resumes.get(h).cloned().unwrap_or_else(|| h.to_owned()))
                    .b("</span></p>");
            }
            None => {
                c.b("<p class=\"b-douce\">Aucun certificat client déposé.</p>");
            }
        }
        if let Some(csr) = v.csr {
            c.b("<p>Demande de certificat de la clé du serveur (à faire signer par l'AC du collecteur) :</p><pre class=\"b-mono b-coupe\">")
                .t(csr)
                .b("</pre>");
        }
        c.b("<div class=\"b-formulaire__actions\">");
        bouton(
            &mut c,
            ctx,
            ROUTE_CLE,
            &[],
            "Générer une nouvelle clé client",
            "",
        );
        c.b("</div><form class=\"b-formulaire\" method=\"post\" action=\"")
            .b(ROUTE_CERTIFICAT)
            .b("\">");
        pages::csrf(&mut c, ctx.csrf);
        c.b("<div class=\"b-champ\"><label for=\"certificat\">Certificat client signé (PEM)</label><textarea class=\"b-saisie\" id=\"certificat\" name=\"certificat\" rows=\"6\" required></textarea></div><div class=\"b-formulaire__actions\"><button class=\"b-btn\" type=\"submit\">Déposer le certificat</button></div></form>");
    }
    c.b("</div>");
    // ── Demandes
    c.b("<h2>Demandes en attente d'un second administrateur</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Demande</th><th>Par</th><th>Le</th><th>Action</th></tr></thead><tbody>");
    if v.demandes.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"4\">Aucune.</td></tr>");
    }
    for d in v.demandes {
        c.b("<tr><td>")
            .t(&d.operation.libelle())
            .b("</td><td>")
            .t(&d.par)
            .b("</td><td>")
            .t(&date_utc(d.le))
            .b("</td><td>");
        if admin {
            bouton(
                &mut c,
                ctx,
                "/validations/valider",
                &[("demande", &d.id), ("retour", "journal")],
                "Valider (second administrateur)",
                "b-btn--principal",
            );
            bouton(
                &mut c,
                ctx,
                "/validations/annuler",
                &[("demande", &d.id), ("retour", "journal")],
                "Annuler",
                "",
            );
        }
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    c.b("<p class=\"b-aide\">Format structuré (une ligne JSON par événement, horodatage RFC 3339 UTC, identifiant, gravité RFC 5424) : <a href=\"")
        .b(ROUTE_EXPORT)
        .b("\">exporter tout le journal conservé</a> (consultation journalisée). Aucun nom de fichier, pseudonymes seulement pour les utilisateurs des bornes.</p>");
    let mut actions = Html::new();
    actions.b("<a class=\"b-btn\" href=\"/audit\">Journal d'audit</a>");
    pages::coque(
        ctx,
        Rubrique::Audit,
        "Journal · conservation et export",
        "Conservation et export",
        actions,
        c,
    )
}

/// Demandes de la double validation qui concernent cette page.
fn demandes_journal(d: Vec<Demande>) -> Vec<Demande> {
    d.into_iter()
        .filter(|d| {
            matches!(
                d.operation,
                Operation::ChangerConservation { .. } | Operation::ConfigurerSyslog { .. }
            )
        })
        .collect()
}

impl Web {
    pub(crate) fn page_journal(
        &self,
        u: &Utilisateur,
        t: u64,
        message: Option<(bool, &str)>,
        csr: Option<&str>,
    ) -> Result<Reponse> {
        if !u.role.peut(Droit::ConsulterJournal) {
            return Ok(refus(
                403,
                "Page réservée aux administrateurs et aux auditeurs.",
            ));
        }
        let s = self.stockage()?;
        let reglage = barbacane_passerelle::conservation::lire(&s)?;
        let passages = barbacane_passerelle::passages::Passages::ouvrir(&s)?.nombre()?;
        let journal = s.journal_audit();
        let segments = journal.segments()?;
        let plus_ancien = match segments.first() {
            Some((_, c)) => std::fs::read(c).ok(),
            None => journal.lire().ok(),
        }
        .and_then(|o| {
            o.split(|x| *x == b'\n')
                .next()
                .and_then(|l| Enregistrement::analyser(l).ok())
                .map(|e| e.le)
        });
        let actif = syslog::lire_actif(&s)?;
        let etat = syslog::lire_etat(&s).ok().flatten();
        let demandes = demandes_journal(validations::en_attente(&self.comptes, t)?);
        let client = syslog::certificat_client_actuel(&s)?;
        let csr_courant = match csr {
            Some(c) => Some(c.to_owned()),
            None if u.role.peut(Droit::Administrer) => {
                syslog::csr_client(&s, &self.nom_serveur()).ok().flatten()
            }
            None => None,
        };
        let mut resumes = BTreeMap::new();
        let mut resumer = |prefixe: &str, h: &str| {
            if let Some(r) = syslog::resume_pem(&s, prefixe, h) {
                resumes.insert(h.to_owned(), r);
            }
        };
        if let Some(h) = &client {
            resumer("client", h);
        }
        let configs =
            actif
                .iter()
                .filter_map(|a| a.config.clone())
                .chain(demandes.iter().filter_map(|d| match &d.operation {
                    Operation::ConfigurerSyslog { config } => config.clone(),
                    _ => None,
                }));
        for cfg in configs {
            if let Some(h) = &cfg.ac {
                resumer("ac", h);
            }
            if let Some(h) = &cfg.certificat_client {
                resumer("client", h);
            }
        }
        let statut = if message.is_some_and(|(ok, _)| !ok) {
            400
        } else {
            200
        };
        Ok(Reponse::html(
            statut,
            page(
                &u.contexte(t),
                &Vue {
                    reglage: reglage.as_ref(),
                    passages,
                    segments: segments.len(),
                    plus_ancien,
                    actif: actif.as_ref(),
                    etat: etat.as_ref(),
                    demandes: &demandes,
                    csr: csr_courant.as_deref(),
                    certificat_client: client.as_deref(),
                    resumes: &resumes,
                    message,
                },
            ),
        ))
    }

    pub(crate) fn nom_serveur(&self) -> String {
        structure::nom_serveur(&std::fs::read_to_string("/etc/hostname").unwrap_or_default())
    }

    /// Export du journal conservé au format structuré (pièce jointe, journalisé).
    pub(crate) fn export_journal(&self, u: &Utilisateur, t: u64) -> Result<Reponse> {
        let s = self.stockage()?;
        self.auditer_web(&u.acteur(), "export-journal-structure")?;
        let nom = self.nom_serveur();
        let mut corps = Vec::new();
        for contenu in s.journal_audit().contenus()? {
            for l in contenu.split(|o| *o == b'\n').filter(|l| !l.is_empty()) {
                corps.extend_from_slice(structure::structurer(l, &nom)?.json.as_bytes());
                corps.push(b'\n');
            }
        }
        let mut rep = Reponse::texte(200, "");
        rep.type_contenu = "application/x-ndjson";
        rep.corps = corps;
        let jour: String = date_utc(t)
            .chars()
            .filter(|c| c.is_ascii_digit())
            .take(8)
            .collect();
        rep.entetes.push((
            "Content-Disposition",
            format!("attachment; filename=\"journal-barbacane-{jour}.jsonl\""),
        ));
        Ok(rep)
    }

    /// POST de la page ; `None` si la route n'en est pas.
    pub(crate) fn post_journal(
        &self,
        chemin: &str,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Option<Reponse>> {
        if !chemin.starts_with("/journal/") {
            return Ok(None);
        }
        if !u.role.peut(Droit::Administrer) {
            return Ok(Some(refus(403, "Rôle non autorisé.")));
        }
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("").trim();
        let a = u.acteur();
        let s = self.stockage()?;
        let demande = |op: Operation| -> Result<String> {
            let (nom, cible) = (op.nom(), op.cible());
            validations::demander(&self.comptes, op, &u.compte, t, |d| {
                self.auditer_web(
                    &a,
                    &crate::admin_comptes::action("demande", &[nom, &cible, d]),
                )
            })
            .map(|_| {
                "Demande enregistrée : un SECOND administrateur doit la valider (1 h).".to_owned()
            })
        };
        let mut csr = None;
        let r: Result<String> = match chemin {
            ROUTE_CONSERVATION => (|| {
                let jours: u32 = champ("jours")
                    .parse()
                    .context("durée : nombre de jours attendu")?;
                let actuel = barbacane_passerelle::conservation::lire(&s)?
                    .unwrap_or_else(|| Reglage::initial(t, "essai"));
                // Contrôle anticipé (bornes, valeur inchangée) : refus immédiat et lisible.
                actuel.changer(jours, t, "essai")?;
                demande(Operation::ChangerConservation { jours })
            })(),
            ROUTE_SYSLOG => (|| {
                let mode = champ("mode");
                if mode == "desactive" {
                    return demande(Operation::ConfigurerSyslog { config: None });
                }
                let mode = Mode::analyser(mode).context("transport inconnu")?;
                let adresse: Ipv4Addr =
                    champ("adresse").parse().context("adresse IPv4 attendue")?;
                let port: u16 = champ("port").parse().context("port 1–65535 attendu")?;
                let mut c = ConfigSyslog {
                    mode,
                    adresse,
                    port,
                    nom: None,
                    ac: None,
                    certificat_client: None,
                };
                if mode == Mode::Tls {
                    c.nom = Some(champ("nom").to_ascii_lowercase()).filter(|n| !n.is_empty());
                    let pem = f.get("ac").map(String::as_str).unwrap_or("").trim();
                    c.ac = if pem.is_empty() {
                        syslog::lire_actif(&s)?
                            .and_then(|a| a.config)
                            .and_then(|x| x.ac)
                    } else {
                        Some(syslog::deposer_pem(
                            &s,
                            "ac",
                            format!("{pem}\n").as_bytes(),
                        )?)
                    };
                    if champ("mtls") == "oui" {
                        c.certificat_client = Some(
                            syslog::certificat_client_actuel(&s)?
                                .context("mTLS : déposez d'abord le certificat client signé")?,
                        );
                    }
                }
                syslog::controler_demande(&s, &c)?;
                demande(Operation::ConfigurerSyslog { config: Some(c) })
            })(),
            ROUTE_CLE => (|| {
                let r = syslog::generer_cle_client(&s, &self.nom_serveur())?;
                self.auditer_web(&a, "syslog-cle-client-generee")?;
                csr = Some(r);
                Ok("Nouvelle clé client tirée par le serveur (elle ne le quitte jamais) : faites signer la demande ci-dessous par l'AC du collecteur, puis déposez le certificat.".to_owned())
            })(),
            ROUTE_CERTIFICAT => (|| {
                let pem = f.get("certificat").map(String::as_str).unwrap_or("").trim();
                if pem.is_empty() {
                    bail!("certificat PEM attendu");
                }
                let h = syslog::deposer_certificat_client(&s, format!("{pem}\n").as_bytes())?;
                self.auditer_web(
                    &a,
                    &crate::admin_comptes::action("syslog-certificat-client-depose", &[&h[..16]]),
                )?;
                Ok("Certificat client déposé ; il sera présenté si une configuration mTLS est validée.".to_owned())
            })(),
            _ => return Ok(Some(refus(404, "Action introuvable."))),
        };
        Ok(Some(match r {
            Ok(m) => self.page_journal(u, t, Some((true, &m)), csr.as_deref())?,
            Err(e) => {
                let route = chemin.trim_start_matches('/').replace('/', "-");
                self.auditer_web(&a, &crate::admin_comptes::action("refus", &[&route, "-"]))?;
                self.page_journal(u, t, Some((false, &format!("Refusé : {e:#}"))), None)?
            }
        }))
    }
}
