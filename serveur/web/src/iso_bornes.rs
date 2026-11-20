//! Page « ISO des bornes » (administrateur seulement ; `docs/suite/serveur-iso-bornes.md`).
//!
//! - téléchargement de l'ISO générique en ligne et de l'ISO hors ligne v1 embarquées dans
//!   l'ISO du serveur (empreintes de `SHA256SUMS` affichées, à comparer à la note imprimée) ;
//! - préparation d'une ISO **personnalisée** pour un site : jeton créé par le registre (1 h,
//!   usage unique, audité), ISO produite par `barbacane-iso-borne` (remaster sans réseau),
//!   téléchargeable **une seule fois** puis supprimée ; supprimée aussi à l'expiration du jeton ;
//! - chaque préparation et chaque téléchargement sont audités. Le jeton n'est jamais affiché.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use barbacane_passerelle::outils::{aleatoire, date_utc};
use barbacane_protocole::DUREE_JETON_S;

use crate::comptes::Role;
use crate::html::Html;
use crate::http::{ENTETES_SECURITE, Refus, Reponse, Requete, lire_formulaire};
use crate::pages::{self, Contexte, Rubrique};
use crate::sessions::egal;
use rustls::{ServerConnection, StreamOwned};

use crate::{DEBIT_MIN_DEPOT, Flux, Utilisateur, Web, refus};

pub const ROUTE: &str = "/iso-bornes";
pub const ROUTE_PREPARER: &str = "/iso-bornes/preparer";
/// Téléchargement : traité hors de [`Web::repondre`] (réponse envoyée en flux).
pub const ROUTE_TELECHARGER: &str = "/iso-bornes/telecharger";
pub const GENERIQUE: &str = "barbacane-borne-en-ligne.iso";
pub const HORS_LIGNE: &str = "barbacane-borne-hors-ligne.iso";
/// Dossier par défaut des ISO embarquées (`fin-installation-serveur.sh`).
pub const DOSSIER_DEFAUT: &str = "/var/lib/barbacane-serveur/iso-bornes";
pub const OUTIL_DEFAUT: &str = "/usr/local/sbin/barbacane-iso-borne";
/// ISO personnalisées en attente au plus (chacune ≈ 1 Go).
pub const PERSONNALISEES_MAX: usize = 4;

/// ISO personnalisée en attente de téléchargement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Personnalisee {
    pub id: String,
    pub site: String,
    pub expire_le: u64,
}

/// Empreintes `SHA256SUMS` (`hex  ./nom` ou `hex  nom`) des ISO embarquées.
pub fn empreintes(dossier: &Path) -> BTreeMap<String, String> {
    let texte = std::fs::read_to_string(dossier.join("SHA256SUMS")).unwrap_or_default();
    texte
        .lines()
        .filter_map(|l| {
            let (e, n) = l.split_once(char::is_whitespace)?;
            let n = n
                .trim_start()
                .trim_start_matches('*')
                .trim_start_matches("./");
            (e.len() == 64 && e.bytes().all(|c| c.is_ascii_hexdigit()))
                .then(|| (n.to_owned(), e.to_ascii_lowercase()))
        })
        .collect()
}

fn id_valide(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Dépôt des ISO personnalisées : `<registre>/iso-personnalisees/<id>/{borne.iso,site,expire}` (0700).
pub struct Depot {
    pub racine: PathBuf,
}

impl Depot {
    pub fn ouvrir(registre: &Path) -> Result<Depot> {
        let racine = registre.join("iso-personnalisees");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&racine)?;
        Ok(Depot { racine })
    }

    fn lire(&self, id: &str) -> Option<Personnalisee> {
        let d = self.racine.join(id);
        let site = std::fs::read_to_string(d.join("site")).ok()?;
        let expire_le = std::fs::read_to_string(d.join("expire"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some(Personnalisee {
            id: id.to_owned(),
            site: site.trim().to_owned(),
            expire_le,
        })
    }

    /// Supprime les ISO expirées (jeton périmé) ou incomplètes ; liste les autres.
    pub fn purger(&self, t: u64) -> Vec<Personnalisee> {
        let mut v = Vec::new();
        let Ok(entrees) = std::fs::read_dir(&self.racine) else {
            return v;
        };
        for e in entrees.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            match self.lire(&id) {
                Some(p)
                    if id_valide(&id)
                        && p.expire_le > t
                        && e.path().join("borne.iso").is_file() =>
                {
                    v.push(p)
                }
                _ => {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        v.sort_by_key(|p| p.expire_le);
        v
    }

    /// Réserve l'ISO pour UN téléchargement : renommage atomique (un second appel échoue).
    pub fn reserver(&self, id: &str, t: u64) -> Option<(Personnalisee, PathBuf)> {
        if !id_valide(id) {
            return None;
        }
        let p = self.lire(id).filter(|p| p.expire_le > t)?;
        let d = self.racine.join(id);
        let envoi = d.join("borne.iso.envoi");
        std::fs::rename(d.join("borne.iso"), &envoi).ok()?;
        Some((p, envoi))
    }

    pub fn supprimer(&self, id: &str) {
        if id_valide(id) {
            let _ = std::fs::remove_dir_all(self.racine.join(id));
        }
    }

    /// Produit l'ISO personnalisée avec l'outil de remaster (jeton sur l'entrée standard).
    pub fn preparer(
        &self,
        outil: &Path,
        source: &Path,
        site: &str,
        jeton: &str,
        t: u64,
    ) -> Result<Personnalisee> {
        if self.purger(t).len() >= PERSONNALISEES_MAX {
            bail!(
                "déjà {PERSONNALISEES_MAX} ISO personnalisées en attente : téléchargez-les ou attendez leur expiration"
            );
        }
        let id = hex::encode(aleatoire::<16>());
        let d = self.racine.join(&id);
        std::fs::DirBuilder::new().mode(0o700).create(&d)?;
        let resultat = (|| {
            let mut fils = Command::new(outil)
                .arg("personnaliser")
                .arg(source)
                .arg(d.join("borne.iso"))
                .arg(site)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("outil {}", outil.display()))?;
            fils.stdin
                .take()
                .context("entrée de l'outil")?
                .write_all(format!("{jeton}\n").as_bytes())?;
            let sortie = fils.wait_with_output()?;
            if !sortie.status.success() {
                let err = String::from_utf8_lossy(&sortie.stderr);
                bail!(
                    "remaster refusé : {}",
                    err.trim().lines().last().unwrap_or("")
                );
            }
            let expire_le = t + DUREE_JETON_S;
            std::fs::write(d.join("site"), site)?;
            std::fs::write(d.join("expire"), expire_le.to_string())?;
            Ok(Personnalisee {
                id: id.clone(),
                site: site.to_owned(),
                expire_le,
            })
        })();
        if resultat.is_err() {
            let _ = std::fs::remove_dir_all(&d);
        }
        resultat
    }
}

// ───────────────────────────── Page ───────────────────────────────────────────────────────────

fn bouton(c: &mut Html, ctx: &Contexte, fichier: &str, libelle: &'static str) {
    c.b("<form class=\"b-en-ligne\" method=\"post\" action=\"/iso-bornes/telecharger\">");
    pages::csrf(c, ctx.csrf);
    c.b("<input type=\"hidden\" name=\"fichier\" value=\"")
        .t(fichier)
        .b("\"><button class=\"b-btn\" type=\"submit\">")
        .b(libelle)
        .b("</button></form>");
}

pub fn page(
    ctx: &Contexte,
    disponibles: &[(&'static str, &'static str, bool, Option<String>)],
    personnalisees: &[Personnalisee],
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
    pages::avis(
        &mut c,
        "b-avis--alerte",
        "Comparez chaque empreinte SHA-256 à celle de la note de version imprimée (hors bande) avant d'installer : cette page seule ne suffit pas.",
    );
    c.b("<h2>ISO embarquées</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>ISO</th><th>Empreinte SHA-256</th><th>Action</th></tr></thead><tbody>");
    for (cle, nom, present, empreinte) in disponibles {
        c.b("<tr><td>").b(nom).b("</td><td class=\"b-mono\">");
        match empreinte {
            Some(e) => c.t(&pages::grouper(e)),
            None => c.b("absente"),
        };
        c.b("</td><td>");
        if *present && empreinte.is_some() {
            bouton(&mut c, ctx, cle, "Télécharger");
        } else {
            c.b("non embarquée");
        }
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    c.b("<div class=\"b-cartes\"><div class=\"b-carte\"><h2>Préparer une ISO personnalisée</h2><form class=\"b-formulaire\" method=\"post\" action=\"/iso-bornes/preparer\">");
    pages::csrf(&mut c, ctx.csrf);
    c.b("<div class=\"b-champ\"><label for=\"site\">Site</label><input class=\"b-saisie b-mono\" id=\"site\" name=\"site\" required maxlength=\"14\" placeholder=\"site-1\"><span class=\"b-aide\">Un jeton (1 h, usage unique) est créé et inscrit dans l'ISO, qui installe la borne sans saisie. L'ISO n'est téléchargeable qu'une fois, puis supprimée. La demande de la borne reste à valider ici par l'empreinte.</span></div><div class=\"b-formulaire__actions\"><button class=\"b-btn b-btn--principal\" type=\"submit\">Préparer l'ISO</button></div></form></div>");
    c.b("<div class=\"b-carte\"><h2>Borne sans serveur</h2><p>L'ISO hors ligne est la borne v1 : aucun code réseau, aucun lien avec ce serveur.</p></div></div>");
    c.b("<h2>ISO personnalisées en attente</h2><div class=\"b-tableau-cadre\"><table class=\"b-tableau\"><thead><tr><th>Site</th><th>Expire</th><th>Action</th></tr></thead><tbody>");
    if personnalisees.is_empty() {
        c.b("<tr><td class=\"b-vide\" colspan=\"3\">Aucune.</td></tr>");
    }
    for p in personnalisees {
        c.b("<tr><td>")
            .t(&p.site)
            .b("</td><td>")
            .t(&date_utc(p.expire_le))
            .b("</td><td>");
        bouton(&mut c, ctx, &p.id, "Télécharger (une fois)");
        c.b("</td></tr>");
    }
    c.b("</tbody></table></div>");
    pages::coque(
        ctx,
        Rubrique::IsoBornes,
        "ISO des bornes",
        "ISO des bornes",
        Html::new(),
        c,
    )
}

// ───────────────────────────── Traitements ────────────────────────────────────────────────────

impl Web {
    fn depot_iso(&self) -> Result<Depot> {
        Depot::ouvrir(&self.passerelle.registre)
    }

    fn disponibles(&self) -> Vec<(&'static str, &'static str, bool, Option<String>)> {
        let d = &self.config.iso_bornes;
        let e = empreintes(d);
        [
            (
                "generique",
                GENERIQUE,
                "Borne en ligne — générique (enrôlement par jeton saisi)",
            ),
            (
                "hors-ligne",
                HORS_LIGNE,
                "Borne hors ligne v1 — borne sans serveur",
            ),
        ]
        .into_iter()
        .map(|(cle, fichier, nom)| (cle, nom, d.join(fichier).is_file(), e.get(fichier).cloned()))
        .collect()
    }

    pub(crate) fn page_iso(
        &self,
        u: &Utilisateur,
        t: u64,
        message: Option<(bool, &str)>,
    ) -> Result<Reponse> {
        if u.role != Role::Administrateur {
            return Ok(refus(403, "Page réservée aux administrateurs."));
        }
        let ctx = u.contexte(t);
        let attente = self.depot_iso()?.purger(t);
        let statut = if message.is_some_and(|(ok, _)| !ok) {
            400
        } else {
            200
        };
        Ok(Reponse::html(
            statut,
            page(&ctx, &self.disponibles(), &attente, message),
        ))
    }

    pub(crate) fn preparer_iso(
        &self,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Reponse> {
        let site = f.get("site").map(String::as_str).unwrap_or("").trim();
        if !barbacane_passerelle::registre::site_valide(site) {
            return self.page_iso(u, t, Some((false, "Site invalide : forme site-<n>.")));
        }
        let source = self.config.iso_bornes.join(GENERIQUE);
        if !source.is_file() {
            return self.page_iso(u, t, Some((false, "ISO générique non embarquée.")));
        }
        let admin = self.admin(u)?;
        let jeton = admin.creer_jeton(site, t)?.formater();
        let depot = self.depot_iso()?;
        match depot.preparer(&self.config.outil_iso_borne, &source, site, &jeton, t) {
            Ok(p) => {
                self.auditer(&u.acteur(), &format!("iso-borne-preparee:{site}"))?;
                let m = format!(
                    "ISO personnalisée prête pour {site} : téléchargeable une seule fois, avant {} (expiration du jeton).",
                    date_utc(p.expire_le)
                );
                self.page_iso(u, t, Some((true, &m)))
            }
            Err(e) => {
                self.auditer(&u.acteur(), &format!("iso-borne-refusee:{site}"))?;
                self.page_iso(u, t, Some((false, &format!("{e:#}"))))
            }
        }
    }

    /// `POST /iso-bornes/telecharger` : `Ok(None)` si le fichier a été envoyé en flux,
    /// `Ok(Some(réponse))` pour un refus.
    pub(crate) fn telecharger_iso(
        &self,
        r: &Requete,
        flux: &mut StreamOwned<ServerConnection, Flux>,
        empreinte: &str,
    ) -> Result<Option<Reponse>> {
        let t = barbacane_passerelle::outils::maintenant();
        if r.sec_fetch_site
            .as_deref()
            .is_some_and(|s| s != "same-origin" && s != "none")
        {
            return Ok(Some(refus(403, "Requête d'une autre origine refusée.")));
        }
        let Some(u) = self.utilisateur(r, empreinte, t) else {
            return Ok(Some(refus(
                403,
                "Session absente ou expirée : reconnectez-vous.",
            )));
        };
        if u.role != Role::Administrateur {
            return Ok(Some(refus(403, "Rôle auditeur : lecture seule.")));
        }
        let f = match lire_formulaire(r, flux) {
            Ok(f) => f,
            Err(Refus(s)) => return Ok(Some(refus(s, "Formulaire refusé."))),
        };
        if !f.get("csrf").is_some_and(|j| egal(j, &u.session.csrf)) {
            return Ok(Some(refus(403, "Jeton anti-CSRF absent ou invalide.")));
        }
        let choix = f.get("fichier").map(String::as_str).unwrap_or("");
        let depot = self.depot_iso()?;
        let (chemin, nom, action, perso) = match choix {
            "generique" => (
                self.config.iso_bornes.join(GENERIQUE),
                GENERIQUE.to_owned(),
                "iso-borne-telechargee:generique".to_owned(),
                None,
            ),
            "hors-ligne" => (
                self.config.iso_bornes.join(HORS_LIGNE),
                HORS_LIGNE.to_owned(),
                "iso-borne-telechargee:hors-ligne".to_owned(),
                None,
            ),
            id => {
                depot.purger(t);
                let Some((p, chemin)) = depot.reserver(id, t) else {
                    return Ok(Some(refus(
                        404,
                        "ISO personnalisée inconnue, expirée ou déjà téléchargée.",
                    )));
                };
                (
                    chemin,
                    format!("barbacane-borne-{}.iso", p.site),
                    format!("iso-borne-telechargee:{}", p.site),
                    Some(p.id),
                )
            }
        };
        let envoi = (|| -> Result<Option<Reponse>> {
            let Ok(mut fichier) = std::fs::File::open(&chemin) else {
                return Ok(Some(refus(404, "ISO non embarquée.")));
            };
            let taille = fichier.metadata()?.len();
            self.auditer(&u.acteur(), &action)?;
            flux.sock.fin += Duration::from_secs(taille / DEBIT_MIN_DEPOT + 1);
            let mut e = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {taille}\r\nContent-Disposition: attachment; filename=\"{nom}\"\r\nConnection: close\r\nCache-Control: no-store\r\n"
            );
            for (k, v) in ENTETES_SECURITE {
                e.push_str(&format!("{k}: {v}\r\n"));
            }
            e.push_str("\r\n");
            flux.write_all(e.as_bytes())?;
            let n = std::io::copy(&mut (&mut fichier).take(taille), flux)?;
            if n != taille {
                bail!("fichier tronqué pendant l'envoi");
            }
            Ok(None)
        })();
        // Personnalisée : supprimée après UN téléchargement, même interrompu.
        if let Some(id) = perso {
            depot.supprimer(&id);
        }
        envoi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreintes_lues() {
        let d = tempfile::tempdir().unwrap();
        let e = "a".repeat(64);
        std::fs::write(
            d.path().join("SHA256SUMS"),
            format!("{e}  ./{GENERIQUE}\nzz  ./x\n{e} *{HORS_LIGNE}\n"),
        )
        .unwrap();
        let m = empreintes(d.path());
        assert_eq!(m.len(), 2);
        assert_eq!(m[GENERIQUE], e);
        assert_eq!(m[HORS_LIGNE], e);
    }

    #[test]
    fn reservation_unique_et_expiration() {
        let d = tempfile::tempdir().unwrap();
        let depot = Depot::ouvrir(d.path()).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let p = depot.racine.join(id);
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("borne.iso"), b"iso").unwrap();
        std::fs::write(p.join("site"), "site-3").unwrap();
        std::fs::write(p.join("expire"), "1000").unwrap();
        assert_eq!(depot.purger(10).len(), 1);
        assert!(depot.reserver("../x", 10).is_none());
        assert!(depot.reserver(id, 10).is_some());
        assert!(depot.reserver(id, 10).is_none(), "un seul téléchargement");
        depot.supprimer(id);
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("borne.iso"), b"iso").unwrap();
        std::fs::write(p.join("site"), "site-3").unwrap();
        std::fs::write(p.join("expire"), "1000").unwrap();
        assert!(depot.reserver(id, 1000).is_none(), "jeton expiré");
        assert!(depot.purger(1000).is_empty());
        assert!(!p.exists(), "ISO expirée supprimée");
    }
}
