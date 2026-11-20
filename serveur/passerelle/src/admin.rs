//! Opérations d'administration locale (commande `barbacane-registre`). L'interface web
//! (D10) viendra les appeler à son tour ; chaque opération est journalisée.

use anyhow::{Context, Result};
use barbacane_protocole::{DUREE_JETON_S, Jeton};
use serde_json::json;

use crate::Config;
use crate::ca::CaBornes;
use crate::outils::{aleatoire, nouvel_uuid};
use crate::registre::{Demande, LigneSupervision, Motif, Registre, StatutDemande, Stockage};

/// Republie la CRL à partir du registre (dans une transaction).
pub fn publier_crl(ca: &CaBornes, config: &Config, reg: &mut Registre, t: u64) -> Result<()> {
    reg.numero_crl = ca.publier_crl(&config.crl_bornes, &reg.entrees_crl(), reg.numero_crl, t)?;
    Ok(())
}

pub struct Admin {
    pub config: Config,
    pub stockage: Stockage,
}

impl Admin {
    pub fn ouvrir(config: Config) -> Result<Admin> {
        let stockage = Stockage::ouvrir(&config.registre)?;
        Ok(Admin { config, stockage })
    }

    fn ca(&self) -> Result<CaBornes> {
        CaBornes::charger(&self.config.ca_bornes, &self.config.cle_ca_bornes)
    }

    /// Nouveau jeton (1 h, usage unique) pour un site ; le secret n'est affiché qu'une fois.
    pub fn creer_jeton(&self, site: &str, t: u64) -> Result<Jeton> {
        let jeton = Jeton::nouveau(self.config.port_enrolement, &aleatoire::<16>());
        self.stockage
            .transaction(|r| r.creer_jeton(site, &jeton.secret, t))?;
        self.stockage.journaliser(
            t,
            "jeton_cree",
            json!({"site": site, "expire_le": t + DUREE_JETON_S}),
        );
        Ok(jeton)
    }

    /// Demandes en attente de décision (non expirées).
    pub fn demandes(&self, t: u64) -> Result<Vec<Demande>> {
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
        let uuid = self
            .stockage
            .transaction(|r| r.valider(&ca, id, empreinte, nom, &uuid, t))?;
        self.stockage
            .journaliser(t, "demande_validee", json!({"demande": id, "borne": uuid}));
        Ok(uuid)
    }

    pub fn refuser(&self, id: &str, t: u64) -> Result<()> {
        self.stockage.transaction(|r| r.refuser(id, t))?;
        self.stockage
            .journaliser(t, "demande_refusee", json!({"demande": id}));
        Ok(())
    }

    /// Révoque une borne et republie la CRL dans la même transaction.
    pub fn revoquer(&self, uuid: &str, motif: Motif, t: u64) -> Result<()> {
        let ca = self.ca()?;
        self.stockage.transaction(|r| {
            r.revoquer(uuid, motif, t)?;
            publier_crl(&ca, &self.config, r, t)
        })?;
        self.stockage
            .journaliser(t, "borne_revoquee", json!({"borne": uuid, "motif": motif}));
        Ok(())
    }

    /// Republication de la CRL (quotidienne, D8). Renvoie son numéro.
    pub fn publier_crl(&self, t: u64) -> Result<u64> {
        let ca = self.ca()?;
        let n = self.stockage.transaction(|r| {
            publier_crl(&ca, &self.config, r, t)?;
            Ok(r.numero_crl)
        })?;
        self.stockage
            .journaliser(t, "crl_publiee", json!({"numero": n}));
        Ok(n)
    }

    pub fn supervision(&self, t: u64) -> Result<Vec<LigneSupervision>> {
        Ok(self.stockage.lire().context("registre")?.supervision(t))
    }
}
