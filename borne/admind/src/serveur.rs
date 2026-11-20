//! Borne EN LIGNE seulement : liaison avec `barbacane-agent` (profil `en-ligne` de l'ISO).
//!
//! **Inactif en profil hors ligne** : tout dépend de la présence de la configuration de
//! l'agent (`/etc/barbacane/agent.toml`, posée uniquement par l'ISO en ligne). Sans elle,
//! [`Liaison::ouvrir`] rend `None`, l'état d'admind ne porte aucune clé nouvelle et les
//! opérations `serveur_*` sont refusées : la borne v1 est strictement inchangée.
//!
//! Échanges avec l'agent, par fichiers seulement (jamais de socket, jamais de commande) :
//! - jeton d'enrôlement : validé ici (format, port de l'ISO), écrit atomiquement dans
//!   `<etat agent>/jeton` (0600, propriétaire = compte de l'agent) ;
//! - état : `<exécution agent>/etat.json` (aucun secret), lu et borné ;
//! - mise à jour relayée par le serveur : `<etat agent>/maj/` (voir `borne/agent/src/maj.rs`).
//!   Le paquet est COPIÉ dans le dossier privé d'admind avant toute vérification (l'agent ne
//!   peut plus le modifier ensuite), puis passe par la chaîne existante (`update::apply_from`) :
//!   signature minisign avec la clé de la borne, anti-retour, manifeste. Le résultat est rendu
//!   à l'agent (`resultat.json`), qui le transmet au serveur.
#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use barbacane_protocole::Jeton;
use barbacane_protocole::maj::{ResultatMaj, TAILLE_BCU_MAX, TAILLE_SIGNATURE_MAX};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Ctx;

/// Taille maximale des fichiers d'état lus (etat.json, annonce.json, agent.toml).
const PETIT_MAX: u64 = 64 * 1024;

/// Ce qu'admind sait de l'agent (lu dans `agent.toml`).
pub struct Liaison {
    /// Dossier d'état de l'agent (0700, compte de l'agent).
    pub etat: PathBuf,
    /// Dossier d'exécution (etat.json).
    pub execution: PathBuf,
    pub port_enrolement: u16,
    pub adresse: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Annonce {
    version_maj: u64,
    sha256: String,
    taille: u64,
}

#[derive(Debug, Serialize)]
struct Resultat {
    version_maj: u64,
    resultat: ResultatMaj,
}

/// Lit un fichier ordinaire (lien refusé), borné à `max` octets.
fn lire_borne(chemin: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(sans_lien())
        .open(chemin)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", chemin.display())),
    };
    let m = f.metadata()?;
    if !m.file_type().is_file() || m.len() > max {
        bail!(
            "{} : pas un fichier ordinaire ou trop gros",
            chemin.display()
        );
    }
    let mut o = Vec::new();
    f.take(max + 1).read_to_end(&mut o)?;
    if o.len() as u64 > max {
        bail!("{} : trop gros", chemin.display());
    }
    Ok(Some(o))
}

/// Ne jamais suivre un lien posé par l'agent (constante, aucun code `unsafe`).
const fn sans_lien() -> i32 {
    libc::O_NOFOLLOW
}

/// Uid d'un compte (`/etc/passwd`).
fn uid_de(compte: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let mut it = l.split(':');
            (it.next()? == compte).then(|| it.nth(1)?.parse().ok())?
        })
}

fn chemin_absolu(t: &toml::Table, cle: &str, defaut: &str) -> Result<PathBuf> {
    let p = PathBuf::from(t.get(cle).and_then(|v| v.as_str()).unwrap_or(defaut));
    if !p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir) {
        bail!("agent.toml : {cle} doit être un chemin absolu");
    }
    Ok(p)
}

impl Liaison {
    /// `None` en profil hors ligne (pas de configuration d'agent).
    pub fn ouvrir(ctx: &Ctx) -> Result<Option<Liaison>> {
        let Some(o) = lire_borne(&ctx.conf.agent_config, PETIT_MAX)? else {
            return Ok(None);
        };
        let t: toml::Table = toml::from_str(std::str::from_utf8(&o).context("agent.toml")?)
            .context("agent.toml illisible")?;
        let port_enrolement = t
            .get("port_enrolement")
            .and_then(|v| v.as_integer())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .context("agent.toml : port_enrolement")?;
        Ok(Some(Liaison {
            etat: chemin_absolu(&t, "etat", "/var/lib/barbacane-agent")?,
            execution: chemin_absolu(&t, "execution", "/run/barbacane-agent")?,
            port_enrolement,
            adresse: t
                .get("adresse")
                .and_then(|v| v.as_str())
                .filter(|a| a.parse::<std::net::Ipv4Addr>().is_ok())
                .unwrap_or("?")
                .to_string(),
        }))
    }

    /// Exige le profil en ligne.
    pub fn exiger(ctx: &Ctx) -> Result<Liaison> {
        Liaison::ouvrir(ctx)?
            .context("borne hors ligne : aucune liaison avec un serveur sur cette borne")
    }

    fn dossier_maj(&self) -> PathBuf {
        self.etat.join("maj")
    }

    /// Bloc `serveur` de l'état d'admind (profil en ligne seulement).
    pub fn etat(&self) -> Value {
        let etat = lire_borne(&self.execution.join("etat.json"), PETIT_MAX)
            .ok()
            .flatten()
            .and_then(|o| serde_json::from_slice::<Value>(&o).ok())
            .filter(Value::is_object);
        // Seuls les champs connus sont relayés à l'interface.
        let etat = etat.map(|e| {
            let mut v = json!({});
            for k in [
                "mode",
                "empreinte",
                "derniere_liaison",
                "ecart_horloge_s",
                "horloge_derivee",
                "certificat_expire_le",
                "rapports_en_attente",
                "file_pleine",
                "message",
                "mise_a_jour",
            ] {
                v[k] = e[k].clone();
            }
            v
        });
        json!({
            "adresse": self.adresse,
            "port_enrolement": self.port_enrolement,
            "agent": etat,
        })
    }

    /// Dépose le jeton saisi par l'administrateur pour l'agent.
    pub fn deposer_jeton(&self, ctx: &Ctx, saisie: &str) -> Result<()> {
        if saisie.len() > 128 {
            bail!("jeton trop long");
        }
        let j = Jeton::analyser(saisie).context(
            "jeton mal formé : attendu PORT-SECRET (chiffres, tiret, 26 caractères A à Z et 2 à 7)",
        )?;
        if j.port != self.port_enrolement {
            bail!(
                "ce jeton a été émis pour le port {} ; cette borne est installée pour le port {} (jeton d'un autre serveur ?)",
                j.port,
                self.port_enrolement
            );
        }
        let uid = match uid_de(&ctx.conf.agent_compte) {
            Some(u) => Some(u),
            None if ctx.conf.dry_run => None,
            None => bail!("compte {} introuvable", ctx.conf.agent_compte),
        };
        let meta = std::fs::symlink_metadata(&self.etat)
            .with_context(|| format!("dossier de l'agent {}", self.etat.display()))?;
        if !meta.file_type().is_dir() || uid.is_some_and(|u| meta.uid() != u) {
            bail!("dossier de l'agent invalide (propriétaire ou type)");
        }
        let tmp = self.etat.join(".jeton.admind");
        let _ = std::fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(sans_lien())
            .open(&tmp)
            .context("fichier de jeton")?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        if let Some(u) = uid {
            std::os::unix::fs::fchown(&f, Some(u), None).context("propriétaire du jeton")?;
        }
        f.write_all(format!("{}\n", j.formater()).as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, self.etat.join("jeton")).context("dépôt du jeton")?;
        // Le secret n'est jamais journalisé.
        log::info!("jeton d'enrôlement déposé pour l'agent (port {})", j.port);
        Ok(())
    }

    /// Copie le paquet annoncé dans `dst` (dossier privé d'admind) en contrôlant taille et
    /// empreinte annoncées ; renvoie la version annoncée.
    fn copier_paquet(&self, dst: &Path) -> Result<u64> {
        let d = self.dossier_maj();
        let a: Annonce = serde_json::from_slice(
            &lire_borne(&d.join("annonce.json"), 4096)?
                .context("aucune mise à jour téléchargée depuis le serveur")?,
        )
        .context("annonce de mise à jour illisible")?;
        if a.taille == 0 || a.taille > TAILLE_BCU_MAX {
            bail!("taille annoncée hors bornes");
        }
        let nom = format!("barbacane-maj-{}.bcu", a.version_maj);
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(sans_lien())
            .open(d.join(&nom))
            .context("paquet téléchargé absent")?;
        let m = source.metadata()?;
        if !m.file_type().is_file() || m.len() != a.taille {
            bail!("paquet téléchargé : taille différente de la taille annoncée");
        }
        let mut sortie = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst.join(&nom))?;
        let mut h = Sha256::new();
        let mut tampon = vec![0u8; 1 << 16];
        let mut lecteur = source.take(a.taille + 1);
        let mut total = 0u64;
        loop {
            let n = lecteur.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > a.taille {
                bail!("paquet téléchargé modifié pendant la copie");
            }
            h.update(&tampon[..n]);
            sortie.write_all(&tampon[..n])?;
        }
        sortie.sync_all()?;
        if total != a.taille || hex::encode(h.finalize()) != a.sha256 {
            bail!("paquet téléchargé : empreinte différente de l'empreinte annoncée");
        }
        let sig = lire_borne(
            &d.join(format!("{nom}.minisig")),
            TAILLE_SIGNATURE_MAX as u64,
        )?
        .context("signature du paquet absente")?;
        let mut f = File::create(dst.join(format!("{nom}.minisig")))?;
        f.write_all(&sig)?;
        Ok(a.version_maj)
    }

    /// Rend le résultat à l'agent (lisible par lui : aucun secret).
    fn rendre(&self, version_maj: u64, resultat: ResultatMaj) -> Result<()> {
        let d = self.dossier_maj();
        let tmp = d.join(".resultat.admind");
        let _ = std::fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(sans_lien())
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.write_all(&serde_json::to_vec(&Resultat {
            version_maj,
            resultat,
        })?)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, d.join("resultat.json"))?;
        Ok(())
    }

    /// Application, décidée par l'administrateur, du paquet relayé par le serveur.
    pub fn appliquer_maj(&self, ctx: &Ctx) -> Result<crate::update::Outcome> {
        std::fs::create_dir_all(&ctx.conf.state_dir)?;
        let copie = tempfile::Builder::new()
            .prefix("serveur-")
            .tempdir_in(&ctx.conf.state_dir)?;
        let version = self.copier_paquet(copie.path())?;
        let r = crate::update::apply_from(ctx, copie.path(), Some(version));
        let resultat = if r.is_ok() {
            ResultatMaj::Appliquee
        } else {
            ResultatMaj::Echec
        };
        if let Err(e) = self.rendre(version, resultat) {
            log::warn!("résultat de la mise à jour non rendu à l'agent : {e:#}");
        }
        match &r {
            Ok(o) => log::info!("mise à jour {} (serveur) appliquée", o.version),
            Err(e) => log::warn!("mise à jour {version} (serveur) refusée : {e:#}"),
        }
        r
    }
}
