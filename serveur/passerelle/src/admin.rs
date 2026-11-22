//! Opérations d'administration locale (commande `barbacane-registre`). L'interface web
//! (D10) viendra les appeler à son tour ; chaque opération est journalisée.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use barbacane_audit::Evenement;
use barbacane_protocole::{DUREE_JETON_S, Jeton};
use serde_json::json;

use crate::Config;
use crate::ca::CaBornes;
use crate::maj::{DepotMaj, EtatMaj, Paquet};
use crate::outils::{aleatoire, nouvel_uuid};
use crate::registre::{Demande, LigneSupervision, Motif, Registre, StatutDemande, Stockage};

/// Republie la CRL à partir du registre (dans une transaction).
pub fn publier_crl(ca: &CaBornes, config: &Config, reg: &mut Registre, t: u64) -> Result<()> {
    reg.numero_crl = ca.publier_crl(&config.crl_bornes, &reg.entrees_crl(), reg.numero_crl, t)?;
    Ok(())
}

/// Acteur audité d'une commande locale : `admin:uid-<n>` (compte du processus).
pub fn acteur_local() -> String {
    match std::fs::metadata("/proc/self") {
        Ok(m) => format!("admin:uid-{}", m.uid()),
        Err(_) => "admin:uid-inconnu".into(),
    }
}

pub struct Admin {
    pub config: Config,
    pub stockage: Stockage,
    pub maj: DepotMaj,
    acteur: String,
}

impl Admin {
    pub fn ouvrir(config: Config) -> Result<Admin> {
        let stockage = Stockage::ouvrir(&config.registre)?;
        let maj = DepotMaj::ouvrir(&stockage)?;
        Ok(Admin {
            config,
            stockage,
            maj,
            acteur: acteur_local(),
        })
    }

    /// Comme [`Admin::ouvrir`], pour un acteur audité donné (interface web : `web:<compte>`).
    /// L'acteur doit respecter le schéma d'audit (`barbacane_audit::ident_valide`).
    pub fn ouvrir_pour(config: Config, acteur: &str) -> Result<Admin> {
        if !barbacane_audit::ident_valide(acteur) {
            anyhow::bail!("acteur d'audit invalide");
        }
        let mut admin = Admin::ouvrir(config)?;
        admin.acteur = acteur.to_owned();
        Ok(admin)
    }

    fn auditer(&self, evenement: Evenement) -> Result<()> {
        self.stockage.auditer(&self.acteur, evenement)
    }

    fn ca(&self) -> Result<CaBornes> {
        CaBornes::charger(&self.config.ca_bornes, &self.config.cle_ca_bornes)
    }

    /// Nouveau jeton (1 h, usage unique) pour un site ; le secret n'est affiché qu'une fois.
    pub fn creer_jeton(&self, site: &str, t: u64) -> Result<Jeton> {
        // D13 : pas de nouvelle borne sur un site en mode Aucun si la quarantaine est active.
        if crate::utilisateurs::quarantaine_active(&self.stockage)
            && crate::utilisateurs::Utilisateurs::ouvrir(&self.stockage)?
                .lire()?
                .reglage(site)
                .mode
                == barbacane_protocole::utilisateurs::ModeUtilisateurs::Aucun
        {
            anyhow::bail!("{}", crate::utilisateurs::REFUS_D13_JETON);
        }
        let jeton = Jeton::nouveau(self.config.port_enrolement, &aleatoire::<16>());
        self.stockage.transaction(|r| {
            r.creer_jeton(site, &jeton.secret, t)?;
            self.auditer(Evenement::JetonCree {
                site: site.into(),
                expire_le: t + DUREE_JETON_S,
            })
        })?;
        self.stockage.journaliser(
            t,
            "jeton_cree",
            json!({"site": site, "expire_le": t + DUREE_JETON_S}),
        );
        Ok(jeton)
    }

    /// Demandes en attente de décision (non expirées).
    pub fn demandes(&self, t: u64) -> Result<Vec<Demande>> {
        self.auditer(Evenement::Administration {
            action: "consultation-demandes".into(),
        })?;
        Ok(self
            .stockage
            .lire()?
            .demandes
            .into_iter()
            .filter(|d| d.statut == StatutDemande::EnAttente && d.expire_le > t)
            .collect())
    }

    /// Valide une demande dont l'empreinte a été comparée à celle affichée par la borne.
    pub fn valider(&self, id: &str, empreinte: &str, nom: Option<&str>, t: u64) -> Result<String> {
        let ca = self.ca()?;
        let uuid = nouvel_uuid();
        let uuid = self.stockage.transaction(|r| {
            let uuid = r.valider(&ca, id, empreinte, nom, &uuid, t)?;
            self.auditer(Evenement::EnrolementValide {
                demande: id.into(),
                borne: uuid.clone(),
            })?;
            Ok(uuid)
        })?;
        self.stockage
            .journaliser(t, "demande_validee", json!({"demande": id, "borne": uuid}));
        Ok(uuid)
    }

    pub fn refuser(&self, id: &str, t: u64) -> Result<()> {
        self.stockage.transaction(|r| {
            r.refuser(id, t)?;
            self.auditer(Evenement::EnrolementRefuse { demande: id.into() })
        })?;
        self.stockage
            .journaliser(t, "demande_refusee", json!({"demande": id}));
        Ok(())
    }

    /// Révoque une borne et republie la CRL dans la même transaction.
    pub fn revoquer(&self, uuid: &str, motif: Motif, t: u64) -> Result<()> {
        let ca = self.ca()?;
        self.stockage.transaction(|r| {
            r.revoquer(uuid, motif, t)?;
            publier_crl(&ca, &self.config, r, t)?;
            self.auditer(Evenement::Revocation {
                borne: uuid.into(),
                motif: serde_json::to_value(motif)?
                    .as_str()
                    .unwrap_or("inconnu")
                    .into(),
            })
        })?;
        self.stockage
            .journaliser(t, "borne_revoquee", json!({"borne": uuid, "motif": motif}));
        Ok(())
    }

    /// Révocation MASSIVE : toutes les bornes actives d'un site, une seule CRL republiée, dans
    /// une seule transaction (rien n'est révoqué si une étape échoue). Exécutée après la double
    /// validation de la Console. Renvoie les uuid révoqués.
    pub fn revoquer_site(&self, site: &str, motif: Motif, t: u64) -> Result<Vec<String>> {
        let ca = self.ca()?;
        let uuids = self.stockage.transaction(|r| {
            let uuids: Vec<String> = r
                .bornes
                .iter()
                .filter(|b| b.site == site && b.statut == crate::registre::StatutBorne::Active)
                .map(|b| b.uuid.clone())
                .collect();
            if uuids.is_empty() {
                anyhow::bail!("aucune borne active sur ce site");
            }
            for u in &uuids {
                r.revoquer(u, motif, t)?;
            }
            publier_crl(&ca, &self.config, r, t)?;
            for u in &uuids {
                self.auditer(Evenement::Revocation {
                    borne: u.clone(),
                    motif: serde_json::to_value(motif)?
                        .as_str()
                        .unwrap_or("inconnu")
                        .into(),
                })?;
            }
            Ok(uuids)
        })?;
        self.stockage.journaliser(
            t,
            "site_revoque",
            json!({"site": site, "bornes": uuids, "motif": motif}),
        );
        Ok(uuids)
    }

    /// Republication de la CRL (quotidienne, D8). Renvoie son numéro.
    pub fn publier_crl(&self, t: u64) -> Result<u64> {
        let ca = self.ca()?;
        let n = self.stockage.transaction(|r| {
            publier_crl(&ca, &self.config, r, t)?;
            self.auditer(Evenement::CrlPubliee {
                numero: r.numero_crl,
            })?;
            Ok(r.numero_crl)
        })?;
        self.stockage
            .journaliser(t, "crl_publiee", json!({"numero": n}));
        Ok(n)
    }

    pub fn supervision(&self, t: u64) -> Result<Vec<LigneSupervision>> {
        self.auditer(Evenement::Administration {
            action: "consultation-supervision".into(),
        })?;
        Ok(self.stockage.lire().context("registre")?.supervision(t))
    }

    /// Installe un plancher signé hors ligne (`FICHIER` + `FICHIER.minisig`).
    pub fn maj_plancher(&self, fichier: &Path) -> Result<u64> {
        self.maj.installer_plancher(fichier, &self.acteur)
    }

    /// Dépose un `.bcu` (+ `.minisig`) vérifié avec la clé des bornes.
    pub fn maj_deposer(&self, bcu: &Path) -> Result<Paquet> {
        self.maj.deposer(bcu, &self.acteur)
    }

    pub fn maj_diffuser(&self, version: u64) -> Result<()> {
        self.maj.diffuser(version, &self.acteur)
    }

    pub fn maj_etat(&self) -> Result<EtatMaj> {
        self.auditer(Evenement::Administration {
            action: "consultation-maj".into(),
        })?;
        self.maj.lire()
    }
}
