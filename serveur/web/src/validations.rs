//! Double validation généralisée (conception §3.10, étude E1 §2.2 ;
//! `docs/suite/comptes-administrateurs.md` §5).
//!
//! Une action sensible est d'abord DEMANDÉE par un administrateur, puis VALIDÉE par un SECOND
//! administrateur distinct (identifiant ET numéro de compte différents) avant [`DUREE_S`] ;
//! l'auto-validation est refusée et auditée ; une demande dont le demandeur n'est plus un
//! administrateur utilisable tombe. Demandes dans `<registre>/administrateurs/validations.json`,
//! sous le même verrou que les comptes. Les actions de la quarantaine gardent leur propre
//! file (`barbacane_passerelle::quarantaine`, mêmes règles).

use anyhow::{Context, Result, bail};
use barbacane_passerelle::outils::{aleatoire, ecrire_atomique};
use serde::{Deserialize, Serialize};

use crate::comptes::{BaseComptes, Comptes, Role};

/// Validité d'une demande.
pub const DUREE_S: u64 = 3600;
const DEMANDES_MAX: usize = 32;

/// Actions soumises à la double validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Création d'un compte (tout rôle) : certificat et mot de passe provisoire remis au
    /// validateur.
    CreerCompte {
        identifiant: String,
        role: Role,
    },
    SupprimerCompte {
        identifiant: String,
        numero: u64,
    },
    /// Changement de rôle VERS administrateur (élévation).
    EleverCompte {
        identifiant: String,
        numero: u64,
    },
    ReactiverCompte {
        identifiant: String,
        numero: u64,
    },
    /// Nouveau certificat (.p12) pour un compte existant (l'ancien est révoqué).
    EmettreCertificat {
        identifiant: String,
        numero: u64,
    },
    RevoquerCertificat {
        identifiant: String,
        numero: u64,
    },
    /// Révocation de toutes les bornes actives d'un site.
    RevoquerSite {
        site: String,
        motif: String,
    },
}

impl Operation {
    /// Nom court (audit, ASCII).
    pub fn nom(&self) -> &'static str {
        match self {
            Operation::CreerCompte { .. } => "creation-compte",
            Operation::SupprimerCompte { .. } => "suppression-compte",
            Operation::EleverCompte { .. } => "elevation-compte",
            Operation::ReactiverCompte { .. } => "reactivation-compte",
            Operation::EmettreCertificat { .. } => "emission-certificat",
            Operation::RevoquerCertificat { .. } => "revocation-certificat",
            Operation::RevoquerSite { .. } => "revocation-site",
        }
    }

    /// Libellé affiché.
    pub fn libelle(&self) -> String {
        match self {
            Operation::CreerCompte { identifiant, role } => {
                format!("Créer le compte {identifiant} ({})", role.libelle())
            }
            Operation::SupprimerCompte { identifiant, .. } => {
                format!("Supprimer le compte {identifiant}")
            }
            Operation::EleverCompte { identifiant, .. } => {
                format!("Passer {identifiant} administrateur")
            }
            Operation::ReactiverCompte { identifiant, .. } => {
                format!("Réactiver le compte {identifiant}")
            }
            Operation::EmettreCertificat { identifiant, .. } => {
                format!("Émettre un nouveau certificat pour {identifiant}")
            }
            Operation::RevoquerCertificat { identifiant, .. } => {
                format!("Révoquer le certificat de {identifiant}")
            }
            Operation::RevoquerSite { site, .. } => {
                format!("Révoquer toutes les bornes du site {site}")
            }
        }
    }

    /// Cible (audit, ASCII : identifiant de compte ou site).
    pub fn cible(&self) -> &str {
        match self {
            Operation::CreerCompte { identifiant, .. }
            | Operation::SupprimerCompte { identifiant, .. }
            | Operation::EleverCompte { identifiant, .. }
            | Operation::ReactiverCompte { identifiant, .. }
            | Operation::EmettreCertificat { identifiant, .. }
            | Operation::RevoquerCertificat { identifiant, .. } => identifiant,
            Operation::RevoquerSite { site, .. } => site,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Demande {
    pub id: String,
    pub operation: Operation,
    /// Identifiant et numéro du compte demandeur.
    pub par: String,
    pub par_numero: u64,
    pub le: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fichier {
    demandes: Vec<Demande>,
}

fn chemin(c: &Comptes) -> std::path::PathBuf {
    c.dossier().join("validations.json")
}

fn lire(c: &Comptes) -> Result<Vec<Demande>> {
    match std::fs::read(chemin(c)) {
        Ok(o) => Ok(serde_json::from_slice::<Fichier>(&o)
            .context("validations.json illisible")?
            .demandes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).context("lecture des demandes"),
    }
}

fn ecrire(c: &Comptes, demandes: Vec<Demande>) -> Result<()> {
    ecrire_atomique(
        &chemin(c),
        &serde_json::to_vec_pretty(&Fichier { demandes })?,
    )
}

/// Demandes encore valables : non expirées, demandeur toujours administrateur utilisable
/// sous le même numéro.
fn valables(d: Vec<Demande>, base: &BaseComptes, t: u64) -> Vec<Demande> {
    d.into_iter()
        .filter(|d| {
            d.le + DUREE_S > t
                && base
                    .compte(&d.par)
                    .is_some_and(|c| c.numero == d.par_numero && c.administrateur_utilisable())
        })
        .collect()
}

/// Liste des demandes en attente (lecture sous verrou).
pub fn en_attente(c: &Comptes, t: u64) -> Result<Vec<Demande>> {
    let _v = c.verrou()?;
    let base = c.lire_sans_verrou()?;
    Ok(valables(lire(c)?, &base, t))
}

/// Enregistre une demande ; `auditer(id)` est appelé avant l'écriture.
pub fn demander(
    c: &Comptes,
    operation: Operation,
    par: &str,
    t: u64,
    auditer: impl FnOnce(&str) -> Result<()>,
) -> Result<String> {
    let _v = c.verrou()?;
    let base = c.lire_sans_verrou()?;
    let compte = base
        .compte(par)
        .filter(|c| c.administrateur_utilisable())
        .context("seul un administrateur peut demander une action sensible")?;
    let mut d = valables(lire(c)?, &base, t);
    if d.len() >= DEMANDES_MAX {
        bail!("trop de demandes en attente ({DEMANDES_MAX})");
    }
    if d.iter().any(|x| x.operation == operation) {
        bail!("une demande identique attend déjà sa validation");
    }
    let id = hex::encode(aleatoire::<16>());
    auditer(&id)?;
    d.push(Demande {
        id: id.clone(),
        operation,
        par: par.into(),
        par_numero: compte.numero,
        le: t,
    });
    ecrire(c, d)?;
    Ok(id)
}

/// Refus d'une validation (pour l'audit).
#[derive(Debug)]
pub enum RefusValidation {
    Inconnue,
    AutoValidation,
    NonAdministrateur,
}

/// Retire la demande `id` pour l'exécuter, si `validateur` est un administrateur utilisable
/// DISTINCT du demandeur. Sous verrou : `executer` reçoit la demande et la base des comptes
/// (modifiable, écrite si `executer` réussit, avec la file des demandes) ; rien n'est écrit en
/// cas d'échec, sauf le retrait de la demande quand `executer` échoue (une demande dont
/// l'exécution est refusée tombe).
pub fn valider<T>(
    c: &Comptes,
    id: &str,
    validateur: &str,
    t: u64,
    refuser: impl FnOnce(RefusValidation, Option<&Demande>) -> Result<()>,
    executer: impl FnOnce(&Demande, &mut BaseComptes) -> Result<T>,
) -> Result<T> {
    let _v = c.verrou()?;
    let mut base = c.lire_sans_verrou()?;
    let mut d = valables(lire(c)?, &base, t);
    let Some(i) = d.iter().position(|x| x.id == id) else {
        refuser(RefusValidation::Inconnue, None)?;
        bail!("demande inconnue ou expirée");
    };
    let v = base.compte(validateur).cloned();
    let Some(v) = v.filter(|v| v.administrateur_utilisable()) else {
        refuser(RefusValidation::NonAdministrateur, Some(&d[i]))?;
        bail!("seul un administrateur peut valider");
    };
    if v.identifiant == d[i].par || v.numero == d[i].par_numero {
        refuser(RefusValidation::AutoValidation, Some(&d[i]))?;
        bail!(
            "double validation : la demande doit être validée par un second administrateur, distinct du demandeur"
        );
    }
    let demande = d.remove(i);
    match executer(&demande, &mut base) {
        Ok(r) => {
            c.ecrire(&base)?;
            ecrire(c, d)?;
            Ok(r)
        }
        Err(e) => {
            ecrire(c, d)?;
            Err(e)
        }
    }
}

/// Annule une demande (tout administrateur, dont le demandeur) ; `auditer` avant l'écriture.
pub fn annuler(
    c: &Comptes,
    id: &str,
    t: u64,
    auditer: impl FnOnce(&Demande) -> Result<()>,
) -> Result<()> {
    let _v = c.verrou()?;
    let base = c.lire_sans_verrou()?;
    let mut d = valables(lire(c)?, &base, t);
    let i = d
        .iter()
        .position(|x| x.id == id)
        .context("demande inconnue ou expirée")?;
    auditer(&d[i])?;
    d.remove(i);
    ecrire(c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (tempfile::TempDir, Comptes) {
        let d = tempfile::tempdir().unwrap();
        let c = Comptes::ouvrir(d.path()).unwrap();
        let mut b = BaseComptes::default();
        for (id, role) in [
            ("a1", Role::Administrateur),
            ("a2", Role::Administrateur),
            ("op", Role::Operateur),
        ] {
            b.ajouter(id, role, "mot de passe de TEST long", "test", 0)
                .unwrap();
            b.compte_mut(id).unwrap().empreinte_certificat =
                Some(format!("{:064}", b.prochain_numero));
        }
        c.ecrire(&b).unwrap();
        (d, c)
    }

    fn op() -> Operation {
        Operation::RevoquerSite {
            site: "s".into(),
            motif: "volee".into(),
        }
    }

    #[test]
    fn auto_validation_expiration_et_non_administrateur() {
        let (_d, c) = base();
        assert!(
            demander(&c, op(), "op", 10, |_| Ok(())).is_err(),
            "opérateur"
        );
        let id = demander(&c, op(), "a1", 10, |_| Ok(())).unwrap();
        assert!(demander(&c, op(), "a2", 11, |_| Ok(())).is_err(), "doublon");
        let mut refus = Vec::new();
        let r = valider(
            &c,
            &id,
            "a1",
            20,
            |r, _| {
                refus.push(format!("{r:?}"));
                Ok(())
            },
            |_, _| Ok(()),
        );
        assert!(r.is_err());
        let r = valider(
            &c,
            &id,
            "op",
            20,
            |r, _| {
                refus.push(format!("{r:?}"));
                Ok(())
            },
            |_, _| Ok(()),
        );
        assert!(r.is_err());
        assert_eq!(refus, ["AutoValidation", "NonAdministrateur"]);
        assert_eq!(
            en_attente(&c, 20).unwrap().len(),
            1,
            "un refus ne consomme pas la demande"
        );
        // Expirée après DUREE_S.
        let r = valider(&c, &id, "a2", 10 + DUREE_S, |_, _| Ok(()), |_, _| Ok(()));
        assert!(r.is_err());
        // Nouvelle demande validée par a2 : exécutée une seule fois.
        let id = demander(&c, op(), "a1", 5000, |_| Ok(())).unwrap();
        let mut fois = 0;
        valider(
            &c,
            &id,
            "a2",
            5001,
            |_, _| Ok(()),
            |d, _| {
                fois += 1;
                assert_eq!(d.par, "a1");
                Ok(())
            },
        )
        .unwrap();
        assert!(valider(&c, &id, "a2", 5002, |_, _| Ok(()), |_, _| Ok(())).is_err());
        assert_eq!(fois, 1);
        // Demandeur désactivé : sa demande tombe.
        let id = demander(&c, op(), "a1", 6000, |_| Ok(())).unwrap();
        c.transaction(|b| {
            b.compte_mut("a1").unwrap().actif = false;
            Ok(())
        })
        .unwrap();
        assert!(en_attente(&c, 6001).unwrap().is_empty());
        assert!(valider(&c, &id, "a2", 6001, |_, _| Ok(()), |_, _| Ok(())).is_err());
    }
}
