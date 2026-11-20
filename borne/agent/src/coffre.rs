//! Stockage de la clé privée de la borne et des fichiers d'état.
//!
//! Décision D9 : la clé de la borne doit être générée et conservée **dans le TPM**
//! (non exportable). Ce jalon fournit l'implémentation **fichier** ([`CoffreFichier`]) utilisée
//! au lab : clé ECDSA P-256 générée localement (aléa du noyau), écrite en PKCS#8 avec les
//! droits 0600 dans le dossier d'état de l'agent (0700, compte dédié). Limite assumée et
//! documentée (`borne/agent/README.md`) : un vol du disque donne la clé ; la parade est la
//! révocation. Le reste de l'agent ne manipule la clé qu'au travers de [`Coffre`], pour que
//! l'implémentation TPM s'y substitue sans autre changement.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;

/// Emplacements de clé : en attente de certificat, courante, nouvelle (renouvellement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emplacement {
    Attente,
    Courante,
    Nouvelle,
}

impl Emplacement {
    fn fichier(self) -> &'static str {
        match self {
            Emplacement::Attente => "cle-attente.pem",
            Emplacement::Courante => "cle.pem",
            Emplacement::Nouvelle => "cle-nouvelle.pem",
        }
    }
}

/// Opérations sur la clé de la borne. La clé ne sort jamais du coffre sauf pour la
/// poignée de main TLS (implémentation fichier ; un TPM signerait lui-même).
pub trait Coffre {
    /// Génère une clé P-256 à cet emplacement (remplace l'ancienne) et renvoie la demande
    /// PKCS#10 signée par elle, ainsi que la clé publique (SubjectPublicKeyInfo DER).
    fn generer(&self, ou: Emplacement) -> Result<(String, Vec<u8>)>;
    /// Clé privée pour rustls.
    fn charger(&self, ou: Emplacement) -> Result<PrivateKeyDer<'static>>;
    /// Clé publique (SubjectPublicKeyInfo DER).
    fn publique(&self, ou: Emplacement) -> Result<Vec<u8>>;
    fn existe(&self, ou: Emplacement) -> bool;
    /// Déplace une clé (attente → courante, nouvelle → courante), atomiquement.
    fn deplacer(&self, de: Emplacement, vers: Emplacement) -> Result<()>;
    fn supprimer(&self, ou: Emplacement) -> Result<()>;
}

/// Clés dans des fichiers 0600 (lab ; à remplacer par le TPM, D9).
pub struct CoffreFichier {
    dossier: PathBuf,
}

impl CoffreFichier {
    pub fn nouveau(dossier: &Path) -> CoffreFichier {
        CoffreFichier {
            dossier: dossier.to_owned(),
        }
    }

    fn chemin(&self, ou: Emplacement) -> PathBuf {
        self.dossier.join(ou.fichier())
    }

    fn paire(&self, ou: Emplacement) -> Result<KeyPair> {
        let chemin = self.chemin(ou);
        verifier_droits(&chemin)?;
        let pem = std::fs::read_to_string(&chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        KeyPair::from_pem(&pem).context("clé de la borne illisible")
    }
}

/// Une clé privée lisible par d'autres que le propriétaire est refusée (jamais utilisée).
fn verifier_droits(chemin: &Path) -> Result<()> {
    let meta = std::fs::metadata(chemin).with_context(|| format!("{}", chemin.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} : droits {:o} trop larges (0600 exigé) : clé refusée",
            chemin.display(),
            meta.permissions().mode() & 0o777
        );
    }
    Ok(())
}

impl Coffre for CoffreFichier {
    fn generer(&self, ou: Emplacement) -> Result<(String, Vec<u8>)> {
        let cle = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("génération de clé")?;
        // Le serveur ignore le sujet demandé (il fixe nom, site et identifiant) : sujet minimal.
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "borne");
        params.distinguished_name = dn;
        let csr = params
            .serialize_request(&cle)
            .context("demande de certificat")?
            .pem()
            .context("demande PEM")?;
        ecrire_atomique(&self.chemin(ou), cle.serialize_pem().as_bytes(), 0o600)?;
        Ok((csr, cle.subject_public_key_info()))
    }

    fn charger(&self, ou: Emplacement) -> Result<PrivateKeyDer<'static>> {
        let chemin = self.chemin(ou);
        verifier_droits(&chemin)?;
        PrivateKeyDer::from_pem_file(&chemin).context("clé de la borne illisible")
    }

    fn publique(&self, ou: Emplacement) -> Result<Vec<u8>> {
        Ok(self.paire(ou)?.subject_public_key_info())
    }

    fn existe(&self, ou: Emplacement) -> bool {
        self.chemin(ou).exists()
    }

    fn deplacer(&self, de: Emplacement, vers: Emplacement) -> Result<()> {
        std::fs::rename(self.chemin(de), self.chemin(vers)).context("déplacement de la clé")?;
        synchroniser_dossier(&self.dossier)
    }

    fn supprimer(&self, ou: Emplacement) -> Result<()> {
        match std::fs::remove_file(self.chemin(ou)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("suppression de la clé"),
        }
    }
}

fn synchroniser_dossier(dossier: &Path) -> Result<()> {
    File::open(dossier)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("synchronisation de {}", dossier.display()))
}

/// Écrit un fichier sans jamais laisser d'état à moitié écrit : fichier temporaire créé avec
/// les droits demandés (jamais plus larges), `fsync`, renommage, `fsync` du dossier.
pub fn ecrire_atomique(chemin: &Path, octets: &[u8], mode: u32) -> Result<()> {
    let dossier = chemin.parent().context("chemin sans dossier")?;
    let temporaire = chemin.with_extension("tmp");
    let _ = std::fs::remove_file(&temporaire);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporaire)
        .with_context(|| format!("création de {}", temporaire.display()))?;
    // Le masque de création peut avoir restreint davantage ; jamais élargi au-delà de `mode`.
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    f.write_all(octets)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&temporaire, chemin)
        .with_context(|| format!("renommage vers {}", chemin.display()))?;
    synchroniser_dossier(dossier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cle_generee_0600_et_demande_p256() {
        let d = tempfile::tempdir().unwrap();
        let c = CoffreFichier::nouveau(d.path());
        let (csr, publique) = c.generer(Emplacement::Attente).unwrap();
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let mode = std::fs::metadata(d.path().join("cle-attente.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(c.publique(Emplacement::Attente).unwrap(), publique);
        c.deplacer(Emplacement::Attente, Emplacement::Courante)
            .unwrap();
        assert!(!c.existe(Emplacement::Attente));
        assert!(c.charger(Emplacement::Courante).is_ok());
    }

    #[test]
    fn cle_trop_ouverte_refusee() {
        let d = tempfile::tempdir().unwrap();
        let c = CoffreFichier::nouveau(d.path());
        c.generer(Emplacement::Courante).unwrap();
        std::fs::set_permissions(
            d.path().join("cle.pem"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(c.charger(Emplacement::Courante).is_err());
    }
}
