//! Actions de la rubrique « Comptes » : gestion des comptes de la Console, certificats .p12,
//! double validation, mot de passe (`docs/suite/comptes-administrateurs.md`).
//!
//! Rôle et jeton anti-CSRF sont vérifiés AVANT (`Web::repondre`). Chaque action est auditée
//! (acteur `web:<compte>`, action `Administration`) ; aucun secret n'est journalisé.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use barbacane_audit::Evenement;
use barbacane_passerelle::ca::{CaBornes, CertificatEmis, EntreeCrl};
use barbacane_passerelle::registre::Motif;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::comptes::{
    BaseComptes, Compte, Role, empreinte_certificat, identifiant_valide, mot_de_passe_provisoire,
    tirer,
};
use crate::http::Reponse;
use crate::pages::Contexte;
use crate::pages_comptes::{self, Remise, VueComptes};
use crate::validations::{self, Operation, RefusValidation};
use crate::{Utilisateur, Web, page, refus};

/// Validité d'un certificat d'administrateur émis par la Console.
pub const VALIDITE_CERTIFICAT_J: u64 = 365;
/// Délai du téléchargement unique d'un `.p12`.
pub const REMISE_S: u64 = 600;
/// CRL des administrateurs republiée quand il lui reste moins que cela.
pub const RENOUVELLEMENT_CRL_S: u64 = 4 * 24 * 3600;
/// Motifs RFC 5280 : remplacé, privilège retiré.
const MOTIF_REMPLACE: u8 = 4;
const MOTIF_RETRAIT: u8 = 9;

/// CA « administrateurs » présente sur le serveur (clé en fichier 0400 ; TPM prévu en 2.4).
pub struct CaAdmin {
    pub ca: CaBornes,
    pub cert_der: Vec<u8>,
    /// Sujet DER de la CA (pour reconnaître ses CRL).
    pub sujet: Vec<u8>,
    /// CRL gérée par la Console : `<registre>/administrateurs/crl-administrateurs.pem`.
    pub crl: PathBuf,
}

/// `.p12` en attente de son téléchargement unique (mémoire seulement).
pub struct RemiseP12 {
    pub pour: String,
    pub identifiant: String,
    pub octets: Vec<u8>,
    pub expire_le: u64,
}

/// Secrets produits par une validation, à afficher une fois.
pub(crate) struct Secrets {
    identifiant: String,
    mdp_provisoire: Option<String>,
    p12: Option<(String, String)>,
}

fn action(nom: &str, parties: &[&str]) -> String {
    let mut s = nom.to_owned();
    for p in parties {
        s.push(':');
        s.push_str(p);
    }
    s.truncate(128);
    s
}

impl Web {
    pub(crate) fn auditer_web(&self, acteur: &str, a: &str) -> Result<()> {
        self.stockage()?
            .auditer(acteur, Evenement::Administration { action: a.into() })
    }

    pub(crate) fn page_comptes(
        &self,
        u: &Utilisateur,
        t: u64,
        message: Option<(bool, &str)>,
        secrets: Option<&Secrets>,
    ) -> Result<Reponse> {
        let ctx = u.contexte(t);
        let base = self.comptes.lire()?;
        let demandes = validations::en_attente(&self.comptes, t)?;
        let q = barbacane_passerelle::quarantaine::Quarantaine::ouvrir(&self.stockage()?)?
            .statut(t)?
            .demandes
            .len();
        let remise = secrets.map(|s| Remise {
            identifiant: &s.identifiant,
            mdp_provisoire: s.mdp_provisoire.as_deref(),
            p12: s.p12.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
        });
        let statut = if message.is_some_and(|(ok, _)| !ok) {
            400
        } else {
            200
        };
        Ok(page(
            statut,
            pages_comptes::comptes(
                &ctx,
                &VueComptes {
                    base: &base,
                    demandes: &demandes,
                    demandes_quarantaine: q,
                    ca_presente: self.ca_admin.is_some(),
                    message,
                    remise,
                },
            ),
        ))
    }

    // ───────────────────────────── Certificats ────────────────────────────────────────────

    /// Tire une clé P-256, émet le certificat et construit le `.p12` (mot de passe tiré).
    fn emettre(
        &self,
        identifiant: &str,
        t: u64,
    ) -> Result<(CertificatEmis, String, Vec<u8>, String)> {
        let ca = self.ca_admin.as_ref().context(
            "la clé de la CA des administrateurs n'est pas sur ce serveur : émission impossible dans la Console",
        )?;
        let cle = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let c = ca
            .ca
            .emettre_administrateur(&cle, identifiant, VALIDITE_CERTIFICAT_J, t)?;
        let der = CertificateDer::from_pem_slice(c.pem.as_bytes()).context("certificat émis")?;
        let mdp = tirer(
            b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789",
            24,
        );
        let p12 = crate::pkcs12::construire(
            &cle.serialize_der(),
            &[der.as_ref(), &ca.cert_der],
            &format!("Barbacane {identifiant}"),
            &mdp,
        )?;
        Ok((c, empreinte_certificat(&der), p12, mdp))
    }

    /// Ajoute des numéros de série à la CRL gérée (sous le verrou de la CRL).
    fn revoquer_series(&self, series: &[(String, u8)], t: u64) -> Result<()> {
        let Some(ca) = &self.ca_admin else {
            return Ok(());
        };
        if series.is_empty() {
            return Ok(());
        }
        let _v = self.crl_verrou.lock().unwrap_or_else(|e| e.into_inner());
        let entrees: Vec<EntreeCrl> = series
            .iter()
            .map(|(s, m)| EntreeCrl {
                serie: s.clone(),
                le: t,
                motif: *m,
            })
            .collect();
        let n = ca.ca.publier_crl(&ca.crl, &entrees, 0, t)?;
        self.auditer_web(
            "web",
            &action("crl-administrateurs-publiee", &[&n.to_string()]),
        )
    }

    /// Lie un nouveau certificat au compte (l'ancien, s'il est connu, est révoqué).
    fn lier_certificat(&self, k: &mut Compte, acteur: &str, t: u64) -> Result<(String, String)> {
        let (c, empreinte, p12, mdp) = self.emettre(&k.identifiant, t)?;
        if let Some(s) = k.serie_certificat.take() {
            self.revoquer_series(&[(s.clone(), MOTIF_REMPLACE)], t)?;
            self.auditer_web(acteur, &action("certificat-revoque", &[&k.identifiant, &s]))?;
        }
        k.empreinte_certificat = Some(empreinte);
        k.serie_certificat = Some(c.serie.clone());
        k.certificat_expire_le = Some(c.expire_le);
        self.auditer_web(
            acteur,
            &action("certificat-emis", &[&k.identifiant, &c.serie]),
        )?;
        let jeton = hex::encode(barbacane_passerelle::outils::aleatoire::<16>());
        let mut r = self.remises.lock().unwrap_or_else(|e| e.into_inner());
        r.retain(|_, x| x.expire_le > t);
        r.insert(
            jeton.clone(),
            RemiseP12 {
                pour: acteur.into(),
                identifiant: k.identifiant.clone(),
                octets: p12,
                expire_le: t + REMISE_S,
            },
        );
        Ok((mdp, jeton))
    }

    // ───────────────────────────── Exécution d'une demande validée ────────────────────────

    fn executer(
        &self,
        op: &Operation,
        base: &mut BaseComptes,
        validateur: &Utilisateur,
        t: u64,
    ) -> Result<(String, Option<Secrets>)> {
        let a = validateur.acteur();
        let cible = |b: &mut BaseComptes, id: &str, numero: u64| -> Result<()> {
            match b.compte(id) {
                Some(k) if k.numero == numero => Ok(()),
                _ => bail!("compte {id} inconnu ou recréé depuis la demande"),
            }
        };
        Ok(match op {
            Operation::CreerCompte { identifiant, role } => {
                let (m, s) = self.creer(base, identifiant, *role, &a, t)?;
                (m, Some(s))
            }
            Operation::SupprimerCompte {
                identifiant,
                numero,
            } => {
                cible(base, identifiant, *numero)?;
                base.garder_un_administrateur(identifiant)?;
                let k = base.compte(identifiant).cloned().context("compte")?;
                if let Some(s) = &k.serie_certificat {
                    self.revoquer_series(&[(s.clone(), MOTIF_RETRAIT)], t)?;
                }
                base.comptes.retain(|c| c.identifiant != *identifiant);
                self.auditer_web(&a, &action("compte-supprime", &[identifiant]))?;
                (format!("Compte {identifiant} supprimé."), None)
            }
            Operation::EleverCompte {
                identifiant,
                numero,
            } => {
                cible(base, identifiant, *numero)?;
                base.compte_mut(identifiant).context("compte")?.role = Role::Administrateur;
                self.auditer_web(&a, &action("compte-role", &[identifiant, "administrateur"]))?;
                (format!("{identifiant} est administrateur."), None)
            }
            Operation::ReactiverCompte {
                identifiant,
                numero,
            } => {
                cible(base, identifiant, *numero)?;
                base.compte_mut(identifiant).context("compte")?.actif = true;
                self.auditer_web(&a, &action("compte-reactive", &[identifiant]))?;
                (format!("Compte {identifiant} réactivé."), None)
            }
            Operation::EmettreCertificat {
                identifiant,
                numero,
            } => {
                cible(base, identifiant, *numero)?;
                let k = base.compte_mut(identifiant).context("compte")?;
                let (mdp, jeton) = self.lier_certificat(k, &a, t)?;
                (
                    format!("Nouveau certificat émis pour {identifiant} ; l'ancien est révoqué."),
                    Some(Secrets {
                        identifiant: identifiant.clone(),
                        mdp_provisoire: None,
                        p12: Some((mdp, jeton)),
                    }),
                )
            }
            Operation::RevoquerCertificat {
                identifiant,
                numero,
            } => {
                cible(base, identifiant, *numero)?;
                base.garder_un_administrateur(identifiant)?;
                let k = base.compte_mut(identifiant).context("compte")?;
                let serie = k.serie_certificat.take();
                k.empreinte_certificat = None;
                k.certificat_expire_le = None;
                if let Some(s) = &serie {
                    self.revoquer_series(&[(s.clone(), MOTIF_RETRAIT)], t)?;
                }
                self.auditer_web(
                    &a,
                    &action(
                        "certificat-revoque",
                        &[identifiant, serie.as_deref().unwrap_or("serie-inconnue")],
                    ),
                )?;
                (
                    match serie {
                        Some(_) => format!(
                            "Certificat de {identifiant} révoqué (CRL republiée) et délié du compte."
                        ),
                        None => format!(
                            "Certificat de {identifiant} délié du compte (numéro de série inconnu : certificat antérieur à la v2.2.0, non inscrit à la CRL)."
                        ),
                    },
                    None,
                )
            }
            Operation::RevoquerSite { site, motif } => {
                let m = Motif::analyser(motif).context("motif")?;
                let uuids = self.admin(validateur)?.revoquer_site(site, m, t)?;
                (
                    format!(
                        "{} borne(s) du site {site} révoquée(s) ; CRL republiée.",
                        uuids.len()
                    ),
                    None,
                )
            }
        })
    }

    /// Création (après validation, ou seule pour le second administrateur).
    fn creer(
        &self,
        base: &mut BaseComptes,
        identifiant: &str,
        role: Role,
        acteur: &str,
        t: u64,
    ) -> Result<(String, Secrets)> {
        if self.ca_admin.is_none() {
            bail!(
                "la clé de la CA des administrateurs n'est pas sur ce serveur : création impossible dans la Console"
            );
        }
        let provisoire = mot_de_passe_provisoire();
        base.ajouter(identifiant, role, &provisoire, acteur, t)?;
        self.auditer_web(acteur, &action("compte-cree", &[identifiant, role.nom()]))?;
        let k = base.compte_mut(identifiant).context("compte")?;
        let (mdp, jeton) = self.lier_certificat(k, acteur, t)?;
        Ok((
            format!("Compte {identifiant} créé ({}).", role.libelle()),
            Secrets {
                identifiant: identifiant.into(),
                mdp_provisoire: Some(provisoire),
                p12: Some((mdp, jeton)),
            },
        ))
    }

    // ───────────────────────────── Routes ─────────────────────────────────────────────────

    /// POST des rubriques Comptes et Validations ; `None` si la route n'en est pas.
    pub(crate) fn post_comptes(
        &self,
        chemin: &str,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Option<Reponse>> {
        if !chemin.starts_with("/comptes/")
            && !chemin.starts_with("/validations/")
            && chemin != "/bornes/revoquer-site"
        {
            return Ok(None);
        }
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("").trim();
        let a = u.acteur();
        let id = champ("identifiant");
        if chemin == "/comptes/p12" {
            return self.telecharger_p12(champ("jeton"), u, t).map(Some);
        }
        let demande = |op: Operation| -> Result<String> {
            let (nom, cible) = (op.nom(), op.cible().to_owned());
            validations::demander(&self.comptes, op, &u.compte, t, |d| {
                self.auditer_web(&a, &action("demande", &[nom, &cible, d]))
            })
            .map(|_| {
                "Demande enregistrée : un SECOND administrateur doit la valider (1 h).".to_owned()
            })
        };
        let numero = |id: &str| -> Result<u64> {
            Ok(self
                .comptes
                .lire()?
                .compte(id)
                .context("compte inconnu")?
                .numero)
        };
        let mut secrets: Option<Secrets> = None;
        let r: Result<String> = match chemin {
            "/comptes/creer" => (|| {
                let role = Role::analyser(champ("role")).context("rôle inconnu")?;
                if !identifiant_valide(id) {
                    bail!("identifiant invalide ([a-z0-9._-], 1 à 32)");
                }
                let base = self.comptes.lire()?;
                if base.compte(id).is_some() {
                    bail!("identifiant déjà utilisé");
                }
                // Amorçage : un seul administrateur utilisable → il crée seul le second.
                if role == Role::Administrateur && base.administrateurs_utilisables_sauf("") == 1 {
                    let (m, s) = self.comptes.transaction(|b| {
                        if b.administrateurs_utilisables_sauf("") != 1 {
                            bail!("état des comptes changé : recommencez");
                        }
                        self.auditer_web(
                            &a,
                            &action(
                                "creation-sans-double-validation",
                                &[id, "seul-administrateur"],
                            ),
                        )?;
                        self.creer(b, id, role, &a, t)
                    })?;
                    secrets = Some(s);
                    return Ok(format!(
                        "{m} Seul administrateur : création sans second administrateur (inscrite au journal) ; les actions sensibles exigent désormais deux administrateurs."
                    ));
                }
                if self.ca_admin.is_none() {
                    bail!(
                        "la clé de la CA des administrateurs n'est pas sur ce serveur : création impossible dans la Console"
                    );
                }
                demande(Operation::CreerCompte {
                    identifiant: id.into(),
                    role,
                })
            })(),
            "/comptes/supprimer" => numero(id).and_then(|n| {
                self.comptes.lire()?.garder_un_administrateur(id)?;
                demande(Operation::SupprimerCompte {
                    identifiant: id.into(),
                    numero: n,
                })
            }),
            "/comptes/reactiver" => numero(id).and_then(|n| {
                demande(Operation::ReactiverCompte {
                    identifiant: id.into(),
                    numero: n,
                })
            }),
            "/comptes/emettre" => numero(id).and_then(|n| {
                if self.ca_admin.is_none() {
                    bail!("la clé de la CA des administrateurs n'est pas sur ce serveur");
                }
                demande(Operation::EmettreCertificat {
                    identifiant: id.into(),
                    numero: n,
                })
            }),
            "/comptes/revoquer" => numero(id).and_then(|n| {
                self.comptes.lire()?.garder_un_administrateur(id)?;
                demande(Operation::RevoquerCertificat {
                    identifiant: id.into(),
                    numero: n,
                })
            }),
            "/comptes/role" => (|| {
                let role = Role::analyser(champ("role")).context("rôle inconnu")?;
                if role == Role::Administrateur {
                    let n = numero(id)?;
                    if self
                        .comptes
                        .lire()?
                        .compte(id)
                        .is_some_and(|k| k.role == role)
                    {
                        bail!("{id} est déjà administrateur");
                    }
                    return demande(Operation::EleverCompte {
                        identifiant: id.into(),
                        numero: n,
                    });
                }
                self.comptes.transaction(|b| {
                    b.garder_un_administrateur(id)?;
                    let k = b.compte_mut(id).context("compte inconnu")?;
                    k.role = role;
                    self.auditer_web(&a, &action("compte-role", &[id, role.nom()]))?;
                    Ok(format!(
                        "{id} : rôle {} (sa session est fermée).",
                        role.libelle()
                    ))
                })
            })(),
            "/comptes/desactiver" => self.comptes.transaction(|b| {
                b.garder_un_administrateur(id)?;
                let k = b.compte_mut(id).context("compte inconnu")?;
                k.actif = false;
                self.auditer_web(&a, &action("compte-desactive", &[id]))?;
                Ok(format!("Compte {id} désactivé (sa session est fermée)."))
            }),
            "/comptes/reinitialiser" => (|| {
                if id == u.compte {
                    bail!("utilisez « Changer mon mot de passe » pour votre propre compte");
                }
                let provisoire = mot_de_passe_provisoire();
                self.comptes.transaction(|b| {
                    b.definir_mot_de_passe(id, &provisoire, true, t)?;
                    self.auditer_web(&a, &action("mot-de-passe-reinitialise", &[id]))
                })?;
                self.verrous.succes(&[format!("compte:{id}")]);
                secrets = Some(Secrets {
                    identifiant: id.into(),
                    mdp_provisoire: Some(provisoire),
                    p12: None,
                });
                Ok(format!(
                    "Mot de passe de {id} réinitialisé : changement imposé à sa prochaine connexion."
                ))
            })(),
            "/bornes/revoquer-site" => (|| {
                let site = champ("site");
                if !barbacane_passerelle::registre::site_valide(site) {
                    bail!("site invalide");
                }
                if champ("confirmation") != site {
                    bail!("le nom retapé ne correspond pas au site : rien n'a été demandé");
                }
                let motif = champ("motif");
                if Motif::analyser(motif).is_none_or(|m| m == Motif::Remplace) {
                    bail!("motif invalide");
                }
                let n = self
                    .stockage()?
                    .lire()?
                    .bornes
                    .iter()
                    .filter(|b| {
                        b.site == site
                            && b.statut == barbacane_passerelle::registre::StatutBorne::Active
                    })
                    .count();
                if n == 0 {
                    bail!("aucune borne active sur ce site");
                }
                demande(Operation::RevoquerSite {
                    site: site.into(),
                    motif: motif.into(),
                })
            })(),
            "/validations/valider" => (|| {
                let d = champ("demande");
                let (m, s) = validations::valider(
                    &self.comptes,
                    d,
                    &u.compte,
                    t,
                    |raison, dem| {
                        let r = match raison {
                            RefusValidation::Inconnue => "inconnue",
                            RefusValidation::AutoValidation => "auto-validation",
                            RefusValidation::NonAdministrateur => "non-administrateur",
                        };
                        self.auditer_web(
                            &a,
                            &action(
                                "validation-refusee",
                                &[r, dem.map(|x| x.id.as_str()).unwrap_or("-")],
                            ),
                        )
                    },
                    |dem, base| {
                        self.auditer_web(
                            &a,
                            &action(
                                "validation",
                                &[dem.operation.nom(), dem.operation.cible(), &dem.id],
                            ),
                        )?;
                        self.executer(&dem.operation, base, u, t)
                    },
                )?;
                secrets = s;
                Ok(m)
            })(),
            "/validations/annuler" => {
                validations::annuler(&self.comptes, champ("demande"), t, |d| {
                    self.auditer_web(&a, &action("annulation", &[d.operation.nom(), &d.id]))
                })
                .map(|_| "Demande annulée.".to_owned())
            }
            _ => return Ok(Some(refus(404, "Action introuvable."))),
        };
        Ok(Some(match r {
            Ok(m) => self.page_comptes(u, t, Some((true, &m)), secrets.as_ref())?,
            Err(e) => self.page_comptes(u, t, Some((false, &format!("Refusé : {e:#}"))), None)?,
        }))
    }

    fn telecharger_p12(&self, jeton: &str, u: &Utilisateur, t: u64) -> Result<Reponse> {
        let r = {
            let mut m = self.remises.lock().unwrap_or_else(|e| e.into_inner());
            m.retain(|_, x| x.expire_le > t);
            match m.get(jeton) {
                Some(x) if x.pour == u.acteur() => m.remove(jeton),
                _ => None,
            }
        };
        let Some(r) = r else {
            self.auditer_web(&u.acteur(), "p12-refuse")?;
            return Ok(refus(
                404,
                "Certificat déjà téléchargé, expiré (10 min) ou réservé à l'administrateur qui l'a obtenu : demandez un nouveau certificat.",
            ));
        };
        self.auditer_web(&u.acteur(), &action("p12-telecharge", &[&r.identifiant]))?;
        let mut rep = Reponse::texte(200, "");
        rep.type_contenu = "application/x-pkcs12";
        rep.corps = r.octets;
        rep.entetes.push((
            "Content-Disposition",
            format!("attachment; filename=\"barbacane-{}.p12\"", r.identifiant),
        ));
        Ok(rep)
    }

    // ───────────────────────────── Mot de passe ───────────────────────────────────────────

    pub(crate) fn page_mot_de_passe(
        &self,
        u: &Utilisateur,
        t: u64,
        message: Option<(bool, &str)>,
    ) -> Reponse {
        let ctx: Contexte = u.contexte(t);
        page(
            if message.is_some_and(|(ok, _)| !ok) {
                400
            } else {
                200
            },
            pages_comptes::mot_de_passe(&ctx, u.doit_changer, message),
        )
    }

    pub(crate) fn changer_mot_de_passe(
        &self,
        f: &BTreeMap<String, String>,
        u: &Utilisateur,
        t: u64,
    ) -> Result<Reponse> {
        let champ = |k: &str| f.get(k).map(String::as_str).unwrap_or("");
        let cles = [format!("compte:{}", u.compte)];
        if self.verrous.verrouille(&cles, t) {
            self.auditer_web(&u.acteur(), "mot-de-passe-verrouille")?;
            return Ok(self.page_mot_de_passe(
                u,
                t,
                Some((false, "Trop d'échecs : réessayez plus tard.")),
            ));
        }
        let r: Result<()> = (|| {
            if champ("nouveau") != champ("confirmation") {
                bail!("la confirmation ne correspond pas");
            }
            self.comptes.transaction(|b| {
                let k = b.compte(&u.compte).context("compte inconnu")?;
                if !k.verifier(champ("actuel")) {
                    bail!("mot de passe actuel incorrect");
                }
                b.definir_mot_de_passe(&u.compte, champ("nouveau"), false, t)?;
                self.auditer_web(&u.acteur(), "mot-de-passe-change")
            })
        })();
        match r {
            Ok(()) => {
                self.verrous.succes(&cles);
                let mut rep = Reponse::redirection("/tableau");
                rep.statut = 303;
                Ok(rep)
            }
            Err(e) => {
                if format!("{e:#}").contains("actuel incorrect") {
                    self.verrous.echec(&cles, t);
                }
                self.auditer_web(&u.acteur(), "mot-de-passe-refuse")?;
                Ok(self.page_mot_de_passe(u, t, Some((false, &format!("Refusé : {e:#}")))))
            }
        }
    }
}
