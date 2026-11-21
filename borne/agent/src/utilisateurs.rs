//! Utilisateurs et clés USB, côté agent (`docs/suite/serveur-utilisateurs.md` §4).
//!
//! - **Politique du site** : téléchargée après chaque battement accepté
//!   (`POST /utilisateurs/politique`), validée par le schéma strict, gardée seulement si sa
//!   `version_politique` n'est pas plus ancienne que celle déjà appliquée (anti-rejeu), dans
//!   `<etat>/politique.json` (0600 ; lue par admind, root). Elle survit à un redémarrage :
//!   serveur injoignable → la dernière politique valide reste appliquée.
//! - **Relais** : admind (root) demande une vérification d'identifiant ou un changement de
//!   PIN sur la socket `<execution>/relais.sock` (0600 : seuls l'agent et root s'y
//!   connectent) ; l'agent fait l'appel mTLS et rend la réponse du serveur telle quelle
//!   (revalidée). **Le PIN ne vit qu'en mémoire** : jamais écrit, jamais journalisé, effacé
//!   des tampons de l'agent après l'envoi (`zeroize`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use barbacane_protocole::utilisateurs::{
    DemandeChangementPin, DemandePolitique, DemandeVerification, PolitiqueSite,
    ReponseVerification, route,
};
use barbacane_protocole::{Message, ReponseErreur, VERSION, decoder, encoder};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::coffre::{Coffre, Emplacement, ecrire_atomique};
use crate::config::Config;
use crate::transport::{self, Client, Identite};

/// Politique du site, dans le dossier d'état.
pub const POLITIQUE: &str = "politique.json";
/// Socket du relais, dans le dossier d'exécution.
pub const RELAIS: &str = "relais.sock";
/// Requête d'admind lue au plus.
const REQUETE_MAX: u64 = 4096;

/// Dernière politique valide enregistrée (None : jamais reçue ou illisible).
pub fn politique_enregistree(etat: &Path) -> Option<PolitiqueSite> {
    let o = std::fs::read(etat.join(POLITIQUE)).ok()?;
    decoder::<PolitiqueSite>(&o).ok()
}

/// Garde la politique reçue si elle n'est pas plus ancienne que l'enregistrée. Renvoie vrai si
/// elle a été écrite (nouvelle version).
pub fn enregistrer_politique(etat: &Path, p: &PolitiqueSite) -> Result<bool> {
    if let Some(a) = politique_enregistree(etat) {
        if p.version_politique < a.version_politique {
            anyhow::bail!(
                "politique du serveur plus ancienne ({} < {}) : ignorée",
                p.version_politique,
                a.version_politique
            );
        }
        if p.version_politique == a.version_politique {
            return Ok(false);
        }
    }
    let o = encoder(p).map_err(|c| anyhow::anyhow!("politique : {c}"))?;
    ecrire_atomique(&etat.join(POLITIQUE), &o, 0o600)?;
    Ok(true)
}

/// Requête d'admind. Les PIN sont effacés de la mémoire à la destruction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DemandeRelais {
    op: String,
    identifiant: String,
    #[serde(default)]
    pin: Option<String>,
    #[serde(default)]
    nouveau_pin: Option<String>,
}

impl Drop for DemandeRelais {
    fn drop(&mut self) {
        self.pin.zeroize();
        self.nouveau_pin.zeroize();
    }
}

/// Relais admind → serveur (vérification, changement de PIN).
pub struct Relais<C: Coffre> {
    client: Client,
    adresse: SocketAddr,
    etat: PathBuf,
    coffre: C,
}

fn erreur(m: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "erreur": m })).unwrap_or_default()
}

impl<C: Coffre> Relais<C> {
    pub fn nouveau(config: &Config, coffre: C) -> Result<Relais<C>> {
        let ca = transport::charger_ca(&config.ca_serveur, &config.empreinte_ca_serveur)?;
        Ok(Relais {
            client: Client::nouveau(ca, &config.nom_serveur)?,
            adresse: SocketAddr::new(config.adresse.into(), config.port_service),
            etat: config.etat.clone(),
            coffre,
        })
    }

    fn identite(&self) -> Result<Identite, &'static str> {
        if self.etat.join("refusee").exists() {
            return Err("borne refusée par le serveur");
        }
        let pem = std::fs::read(self.etat.join("chaine.pem")).map_err(|_| "borne non enrôlée")?;
        let chaine = crate::lire_chaine(&pem).map_err(|_| "certificat de la borne illisible")?;
        let cle = self
            .coffre
            .charger(Emplacement::Courante)
            .map_err(|_| "clé de la borne illisible")?;
        Ok(Identite { chaine, cle })
    }

    /// Une requête d'admind (JSON) → la réponse du serveur (`ReponseVerification`) ou
    /// `{"erreur": …}`. Aucun message ne contient le PIN.
    pub fn traiter(&self, requete: &[u8]) -> Vec<u8> {
        let Ok(d) = serde_json::from_slice::<DemandeRelais>(requete) else {
            return erreur("requête invalide");
        };
        let (chemin, corps) = match d.op.as_str() {
            "verification" => {
                let mut m = DemandeVerification {
                    version: VERSION,
                    identifiant: d.identifiant.clone(),
                    pin: d.pin.clone(),
                };
                let o = encoder(&m);
                m.pin.zeroize();
                (route::VERIFICATION, o)
            }
            "pin" => {
                let (Some(pin), Some(nouveau)) = (&d.pin, &d.nouveau_pin) else {
                    return erreur("requête invalide");
                };
                let mut m = DemandeChangementPin {
                    version: VERSION,
                    identifiant: d.identifiant.clone(),
                    pin: pin.clone(),
                    nouveau_pin: nouveau.clone(),
                };
                let o = encoder(&m);
                m.pin.zeroize();
                m.nouveau_pin.zeroize();
                (route::PIN, o)
            }
            _ => return erreur("opération inconnue"),
        };
        drop(d);
        let Ok(corps) = corps.map(Zeroizing::new) else {
            return erreur("identifiant ou PIN de forme invalide");
        };
        let identite = match self.identite() {
            Ok(i) => i,
            Err(m) => return erreur(m),
        };
        let (statut, reponse) =
            match self
                .client
                .requete(self.adresse, Some(identite), "POST", chemin, &corps)
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("agent : relais utilisateurs : {e}");
                    return erreur("serveur injoignable");
                }
            };
        drop(corps);
        if statut != 200 {
            let code = decoder::<ReponseErreur>(&reponse)
                .map(|e| e.code.to_string())
                .unwrap_or_else(|_| format!("HTTP {statut}"));
            eprintln!("agent : relais utilisateurs : refus du serveur ({code})");
            return erreur(&format!("refus du serveur ({code})"));
        }
        match decoder::<ReponseVerification>(&reponse) {
            Ok(r) => encoder(&r).unwrap_or_else(|_| erreur("réponse du serveur invalide")),
            Err(_) => erreur("réponse du serveur invalide"),
        }
    }

    /// Une connexion d'admind : une ligne, une réponse.
    fn servir_connexion(&self, s: UnixStream) -> Result<()> {
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut ligne = Zeroizing::new(Vec::new());
        BufReader::new((&s).take(REQUETE_MAX)).read_until(b'\n', &mut ligne)?;
        let mut r = self.traiter(&ligne);
        r.push(b'\n');
        (&s).write_all(&r)?;
        Ok(())
    }

    /// Ouvre la socket (0600) et sert les connexions une à une, sans fin.
    pub fn servir(self, execution: &Path) -> Result<()> {
        std::fs::create_dir_all(execution)?;
        let chemin = execution.join(RELAIS);
        let _ = std::fs::remove_file(&chemin);
        let ecoute =
            UnixListener::bind(&chemin).with_context(|| format!("socket {}", chemin.display()))?;
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600))?;
        for s in ecoute.incoming() {
            match s {
                Ok(s) => {
                    if let Err(e) = self.servir_connexion(s) {
                        eprintln!("agent : relais utilisateurs : connexion : {e}");
                    }
                }
                Err(e) => eprintln!("agent : relais utilisateurs : {e}"),
            }
        }
        Ok(())
    }
}

/// Corps de la demande de politique.
pub fn demande_politique() -> Result<Vec<u8>> {
    encoder(&DemandePolitique { version: VERSION }).map_err(|c| anyhow::anyhow!("politique : {c}"))
}

/// Contrôle de forme du message reçu (même code que le serveur).
pub fn valider(p: &PolitiqueSite) -> bool {
    p.valider().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbacane_protocole::utilisateurs::{EntreeNonEnrolees, ModeUtilisateurs};

    fn p(v: u64, mode: ModeUtilisateurs) -> PolitiqueSite {
        PolitiqueSite {
            version: VERSION,
            site: "site-1".into(),
            mode,
            version_politique: v,
            entree_non_enrolees: EntreeNonEnrolees::Autorisee,
            cles: vec![],
            heure_serveur: 1,
        }
    }

    #[test]
    fn politique_jamais_plus_ancienne() {
        let d = tempfile::tempdir().unwrap();
        assert!(politique_enregistree(d.path()).is_none());
        assert!(enregistrer_politique(d.path(), &p(3, ModeUtilisateurs::Identification)).unwrap());
        assert!(!enregistrer_politique(d.path(), &p(3, ModeUtilisateurs::Aucun)).unwrap());
        assert!(enregistrer_politique(d.path(), &p(2, ModeUtilisateurs::Aucun)).is_err());
        let g = politique_enregistree(d.path()).unwrap();
        assert_eq!(
            (g.version_politique, g.mode),
            (3, ModeUtilisateurs::Identification)
        );
        let m = std::fs::metadata(d.path().join(POLITIQUE)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        assert!(enregistrer_politique(d.path(), &p(4, ModeUtilisateurs::Aucun)).unwrap());
    }
}
