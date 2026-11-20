//! Mises à jour proposées par le serveur (`docs/suite/protocole-agent.md` §9).
//!
//! L'agent ne fait que **transporter** : il télécharge le `.bcu` annoncé (mTLS), contrôle la
//! taille et le SHA-256 annoncés, puis le dépose dans `<etat>/maj/` pour `barbacane-admind`.
//! L'agent n'installe RIEN : l'administrateur local décide de l'application, et admind vérifie
//! la signature minisign avec SA clé publique (`/etc/barbacane/maj.pub`), l'anti-retour et le
//! manifeste, exactement comme pour un paquet lu sur clé USB. La signature reste la seule
//! autorité ; l'empreinte annoncée ne sert qu'à écarter tôt un transfert corrompu.
//!
//! Dossier `<etat>/maj/` (0700, compte de l'agent) :
//! - `barbacane-maj-N.bcu` et `.bcu.minisig` : paquet reçu ;
//! - `annonce.json` : écrit EN DERNIER (paquet complet et contrôlé) ;
//! - `resultat.json` : déposé par admind après l'application (ou son refus), transmis au serveur
//!   par `POST /maj/rapport`, puis tout le dossier est vidé.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use barbacane_protocole::maj::{MiseAJourDisponible, ResultatMaj, TAILLE_SIGNATURE_MAX};
use serde::{Deserialize, Serialize};

use crate::coffre::ecrire_atomique;

/// Marge d'espace libre gardée en plus du paquet.
pub const MARGE_ESPACE: u64 = 64 << 20;
/// Taille maximale des petits fichiers JSON du dossier.
const JSON_MAX: u64 = 4096;

/// Paquet reçu et contrôlé (taille, SHA-256), prêt pour admind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Annonce {
    pub version_maj: u64,
    pub sha256: String,
    pub taille: u64,
}

/// Résultat déposé par admind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resultat {
    pub version_maj: u64,
    pub resultat: ResultatMaj,
}

/// Mise à jour vue dans `etat.json` (aucun secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtatMiseAJour {
    pub version_maj: u64,
    pub taille: u64,
    /// Vrai quand le paquet est téléchargé et contrôlé : admind peut le vérifier et l'appliquer.
    pub prete: bool,
    /// Vrai quand admind a rendu son résultat, pas encore transmis au serveur.
    pub rapport_en_attente: bool,
}

pub struct DossierMaj {
    pub dossier: PathBuf,
}

/// Lit un petit fichier JSON ordinaire (pas de lien), borné ; absent → `None`.
fn lire_json<T: for<'de> Deserialize<'de>>(chemin: &Path) -> Result<Option<T>> {
    let meta = match std::fs::symlink_metadata(chemin) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", chemin.display())),
    };
    if !meta.file_type().is_file() || meta.len() > JSON_MAX {
        bail!(
            "{} : pas un fichier ordinaire ou trop gros",
            chemin.display()
        );
    }
    let o = std::fs::read(chemin)?;
    Ok(Some(serde_json::from_slice(&o).with_context(|| {
        format!("{} illisible", chemin.display())
    })?))
}

pub fn nom_paquet(version_maj: u64) -> String {
    format!("barbacane-maj-{version_maj}.bcu")
}

impl DossierMaj {
    pub fn nouveau(etat: &Path) -> DossierMaj {
        DossierMaj {
            dossier: etat.join("maj"),
        }
    }

    fn creer(&self) -> Result<()> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dossier)
            .with_context(|| format!("dossier {}", self.dossier.display()))
    }

    pub fn annonce(&self) -> Result<Option<Annonce>> {
        let a: Option<Annonce> = lire_json(&self.dossier.join("annonce.json"))?;
        // Annonce sans paquet (supprimé à la main) : considérée absente.
        Ok(a.filter(|a| self.dossier.join(nom_paquet(a.version_maj)).is_file()))
    }

    pub fn resultat(&self) -> Result<Option<Resultat>> {
        lire_json(&self.dossier.join("resultat.json"))
    }

    /// État publié pour l'interface.
    pub fn etat(&self) -> Option<EtatMiseAJour> {
        let r = self.resultat().ok().flatten();
        let a = self.annonce().ok().flatten();
        match (a, r) {
            (Some(a), r) => Some(EtatMiseAJour {
                version_maj: a.version_maj,
                taille: a.taille,
                prete: r.is_none(),
                rapport_en_attente: r.is_some(),
            }),
            (None, Some(r)) => Some(EtatMiseAJour {
                version_maj: r.version_maj,
                taille: 0,
                prete: false,
                rapport_en_attente: true,
            }),
            (None, None) => None,
        }
    }

    /// Faut-il télécharger cette proposition ? Non si le même paquet est déjà prêt, ou si un
    /// résultat pour cette version attend d'être transmis.
    pub fn a_telecharger(&self, m: &MiseAJourDisponible) -> Result<bool> {
        if self
            .resultat()?
            .is_some_and(|r| r.version_maj == m.version_maj)
        {
            return Ok(false);
        }
        Ok(!self
            .annonce()?
            .is_some_and(|a| a.version_maj == m.version_maj && a.sha256 == m.sha256))
    }

    /// Fichier temporaire de réception (créé neuf, 0600, sans suivre de lien).
    pub fn ouvrir_reception(&self) -> Result<(PathBuf, std::fs::File)> {
        self.creer()?;
        let chemin = self.dossier.join(".reception");
        match std::fs::remove_file(&chemin) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("ancien fichier de réception"),
        }
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&chemin)
            .context("fichier de réception")?;
        Ok((chemin, f))
    }

    /// Paquet reçu et contrôlé : remplace tout paquet précédent, écrit la signature puis
    /// l'annonce (en dernier). Un résultat d'une AUTRE version encore présent est conservé.
    pub fn installer(
        &self,
        reception: &Path,
        m: &MiseAJourDisponible,
        sha256_recu: &str,
    ) -> Result<()> {
        if sha256_recu != m.sha256 {
            let _ = std::fs::remove_file(reception);
            bail!(
                "empreinte du paquet reçu ({sha256_recu}) différente de l'empreinte annoncée : paquet écarté"
            );
        }
        if m.signature_minisign.len() > TAILLE_SIGNATURE_MAX {
            bail!("signature trop grosse");
        }
        self.vider_paquets()?;
        let paquet = self.dossier.join(nom_paquet(m.version_maj));
        let mut signature = paquet.as_os_str().to_owned();
        signature.push(".minisig");
        ecrire_atomique(
            Path::new(&signature),
            m.signature_minisign.as_bytes(),
            0o600,
        )?;
        std::fs::rename(reception, &paquet).context("dépôt du paquet")?;
        let annonce = Annonce {
            version_maj: m.version_maj,
            sha256: m.sha256.clone(),
            taille: m.taille,
        };
        ecrire_atomique(
            &self.dossier.join("annonce.json"),
            &serde_json::to_vec(&annonce)?,
            0o600,
        )
    }

    /// Supprime annonce, paquets et signatures (jamais `resultat.json`).
    fn vider_paquets(&self) -> Result<()> {
        let _ = std::fs::remove_file(self.dossier.join("annonce.json"));
        let Ok(lecture) = std::fs::read_dir(&self.dossier) else {
            return Ok(());
        };
        for e in lecture.flatten() {
            let nom = e.file_name();
            let nom = nom.to_string_lossy();
            if nom.starts_with("barbacane-maj-") {
                std::fs::remove_file(e.path()).with_context(|| format!("suppression de {nom}"))?;
            }
        }
        Ok(())
    }

    /// Rapport transmis (ou sans objet pour le serveur) : dossier vidé.
    pub fn solder(&self) -> Result<()> {
        self.vider_paquets()?;
        match std::fs::remove_file(self.dossier.join("resultat.json")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("suppression du résultat"),
        }
    }
}

/// Écrit tout le fichier de réception sur disque avant de l'installer.
pub fn synchroniser(f: &mut std::fs::File) -> Result<()> {
    f.flush()?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &str =
        "untrusted comment: x\nRUQ=\ntrusted comment: barbacane-maj version 7\nAA==\n";

    fn proposee(sha: &str) -> MiseAJourDisponible {
        MiseAJourDisponible {
            version_maj: 7,
            sha256: sha.into(),
            taille: 3,
            signature_minisign: SIG.into(),
        }
    }

    #[test]
    fn empreinte_fausse_ecartee_puis_bonne_installee_et_soldee() {
        let d = tempfile::tempdir().unwrap();
        let m = DossierMaj::nouveau(d.path());
        let p = proposee(&"a".repeat(64));
        assert!(m.a_telecharger(&p).unwrap());
        let (chemin, mut f) = m.ouvrir_reception().unwrap();
        f.write_all(b"abc").unwrap();
        assert!(m.installer(&chemin, &p, &"b".repeat(64)).is_err());
        assert!(!chemin.exists(), "paquet corrompu supprimé");
        assert_eq!(m.etat(), None);

        let (chemin, mut f) = m.ouvrir_reception().unwrap();
        f.write_all(b"abc").unwrap();
        m.installer(&chemin, &p, &"a".repeat(64)).unwrap();
        assert!(!m.a_telecharger(&p).unwrap(), "déjà prêt");
        let e = m.etat().unwrap();
        assert!(e.prete && !e.rapport_en_attente);
        assert_eq!(
            std::fs::read_to_string(m.dossier.join("barbacane-maj-7.bcu.minisig")).unwrap(),
            SIG
        );
        // Résultat d'admind : plus « prête », rapport en attente, pas de nouveau téléchargement.
        std::fs::write(
            m.dossier.join("resultat.json"),
            r#"{"version_maj":7,"resultat":"appliquee"}"#,
        )
        .unwrap();
        let e = m.etat().unwrap();
        assert!(!e.prete && e.rapport_en_attente);
        m.vider_paquets().unwrap();
        assert!(
            !m.a_telecharger(&p).unwrap(),
            "rapport à transmettre d'abord"
        );
        m.solder().unwrap();
        assert_eq!(m.etat(), None);
        assert!(m.a_telecharger(&p).unwrap());
    }

    #[test]
    fn resultat_hostile_refuse() {
        let d = tempfile::tempdir().unwrap();
        let m = DossierMaj::nouveau(d.path());
        m.creer().unwrap();
        std::fs::write(
            m.dossier.join("resultat.json"),
            r#"{"version_maj":7,"resultat":"appliquee","x":1}"#,
        )
        .unwrap();
        assert!(m.resultat().is_err());
        std::fs::remove_file(m.dossier.join("resultat.json")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", m.dossier.join("resultat.json")).unwrap();
        assert!(m.resultat().is_err(), "lien refusé");
    }
}
