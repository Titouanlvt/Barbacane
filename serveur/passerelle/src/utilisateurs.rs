//! Utilisateurs, sites et clés USB (`docs/suite/serveur-utilisateurs.md`).
//!
//! - Base `<registre>/utilisateurs/base.json` (0600) sous verrou exclusif `base.verrou`,
//!   réécrite atomiquement (même approche que le registre des bornes, aucune dépendance) ;
//! - identifiants importés de l'annuaire (jamais de mot de passe d'annuaire) ;
//! - PIN Barbacane dérivé par **Argon2id** (64 Mio, 3 passes) **poivré** par une clé du serveur
//!   (`poivre-pin`, 0600) : la base seule ne permet pas d'attaque hors ligne ;
//! - **pseudonyme** `u-<16 hex>` = HMAC-SHA256(`cle-pseudonyme`, identifiant) : seul nom porté
//!   par le journal d'audit ; la correspondance n'est lisible que dans cette base ;
//! - anti force brute : compte verrouillé après 5 échecs consécutifs (jusqu'au déverrouillage
//!   par un administrateur), borne bloquée après 5 échecs en 1 h (15 min, doublé à chaque
//!   blocage, 16 h au plus) ; réponse identique quel que soit le motif ;
//! - conservation : PIN effacé dès le retrait de l'annuaire, correspondance
//!   identifiant ↔ pseudonyme purgée 1 an après (exploitation des journaux d'un an).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use barbacane_audit::{Evenement, ResultatUtilisateur};
use barbacane_protocole::VERSION;
use barbacane_protocole::utilisateurs::{
    CLES_PAR_SITE_MAX, CleUsbAutorisee, DecisionUtilisateur, DemandeChangementPin,
    DemandeVerification, EntreeNonEnrolees, ModeUtilisateurs, PolitiqueSite, ReponseVerification,
    normaliser_fabricant, normaliser_identifiant, normaliser_serie, pin_acceptable,
};
use serde::{Deserialize, Serialize};

use crate::outils::{aleatoire, ecrire_atomique, sha256_hex};
use crate::registre::{Identite, SITE_INVALIDE, Stockage, site_valide};

/// Échecs consécutifs avant verrouillage d'un compte.
pub const ECHECS_COMPTE_MAX: u32 = 5;
/// Échecs sur une borne (fenêtre d'une heure) avant blocage de la borne.
pub const ECHECS_BORNE_MAX: u32 = 5;
pub const FENETRE_ECHECS_BORNE_S: u64 = 3600;
/// Premier blocage d'une borne ; doublé à chaque blocage dans les 24 h (6 fois au plus).
pub const BLOCAGE_BORNE_S: u64 = 15 * 60;
/// Durée d'une session utilisateur (rapports rattachés).
pub const DUREE_SESSION_S: u32 = 30 * 60;
/// Sessions conservées au plus.
pub const SESSIONS_MAX: usize = 1000;
/// Utilisateurs au plus (import refusé au-delà).
pub const UTILISATEURS_MAX: usize = 10_000;
/// Correspondance identifiant ↔ pseudonyme conservée après retrait de l'annuaire (journaux
/// conservés 1 an, conception §1).
pub const CONSERVATION_S: u64 = 365 * 86400;
/// Longueur du PIN tiré à la réinitialisation (affiché une fois, à changer au premier usage).
pub const LONGUEUR_PIN_INITIAL: usize = 8;
/// Paramètres Argon2id (RFC 9106, 2e choix recommandé : 64 Mio ; 3 passes ; 1 voie).
pub const ARGON2_MEMOIRE_KIO: u32 = 64 * 1024;
pub const ARGON2_PASSES: u32 = 3;

/// Une seule dérivation Argon2 à la fois dans le processus : mémoire bornée (64 Mio) même
/// sous attaque, et vérification + enregistrement de l'échec sans entrelacement.
static ARGON2: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Utilisateur {
    /// Identifiant normalisé (annuaire).
    pub identifiant: String,
    /// `u-<16 hex>` : seul nom écrit dans le journal d'audit.
    pub pseudonyme: String,
    /// Présent dans le dernier import de l'annuaire.
    pub actif: bool,
    pub ajoute_le: u64,
    pub retire_le: Option<u64>,
    /// PHC Argon2id poivré ; jamais le PIN.
    pub pin: Option<String>,
    pub pin_le: Option<u64>,
    /// PIN tiré par un administrateur : à changer avant toute utilisation.
    pub pin_a_changer: bool,
    pub echecs: u32,
    pub verrouille_le: Option<u64>,
    pub derniere_verification: Option<u64>,
}

/// Réglages d'un site (défauts : mode Aucun, D13 ; clés non enrôlées admises en entrée, v1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReglageSite {
    pub mode: ModeUtilisateurs,
    pub entree_non_enrolees: EntreeNonEnrolees,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleUsb {
    /// `usb-<8 hex>` tiré par le serveur.
    pub id: String,
    pub fabricant: String,
    pub serie: String,
    pub libelle: String,
    /// `None` : tous les sites.
    pub site: Option<String>,
    pub entree: bool,
    pub sortie: bool,
    pub enrolee_le: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchecsBorne {
    pub echecs: u32,
    pub dernier_echec: u64,
    pub blocages: u32,
    pub bloquee_jusqua: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionUtilisateur {
    /// SHA-256 de l'identifiant de session (l'identifiant lui-même n'est pas conservé).
    pub empreinte: String,
    pub borne: String,
    pub pseudonyme: String,
    pub expire_le: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub le: u64,
    pub source: String,
    pub actifs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseUtilisateurs {
    pub version: u16,
    /// Croît à chaque changement de politique (mode, entrée, clés).
    pub version_politique: u64,
    pub sites: BTreeMap<String, ReglageSite>,
    pub utilisateurs: Vec<Utilisateur>,
    pub cles_usb: Vec<CleUsb>,
    /// Échecs par uuid de borne.
    pub bornes: BTreeMap<String, EchecsBorne>,
    pub sessions: Vec<SessionUtilisateur>,
    /// Dernière version de politique servie à chaque borne (audit au changement).
    pub politique_servie: BTreeMap<String, u64>,
    pub dernier_import: Option<Import>,
}

impl Default for BaseUtilisateurs {
    fn default() -> Self {
        BaseUtilisateurs {
            version: 1,
            version_politique: 1,
            sites: BTreeMap::new(),
            utilisateurs: Vec::new(),
            cles_usb: Vec::new(),
            bornes: BTreeMap::new(),
            sessions: Vec::new(),
            politique_servie: BTreeMap::new(),
            dernier_import: None,
        }
    }
}

impl BaseUtilisateurs {
    pub fn reglage(&self, site: &str) -> ReglageSite {
        self.sites.get(site).copied().unwrap_or_default()
    }

    pub fn utilisateur(&self, identifiant: &str) -> Option<&Utilisateur> {
        self.utilisateurs
            .iter()
            .find(|u| u.identifiant == identifiant)
    }

    fn utilisateur_mut(&mut self, identifiant: &str) -> Option<&mut Utilisateur> {
        self.utilisateurs
            .iter_mut()
            .find(|u| u.identifiant == identifiant)
    }

    pub fn par_pseudonyme(&self, pseudonyme: &str) -> Option<&Utilisateur> {
        self.utilisateurs
            .iter()
            .find(|u| u.pseudonyme == pseudonyme)
    }

    /// Clés valables pour un site (celles du site et celles de tous les sites).
    pub fn cles_du_site(&self, site: &str) -> impl Iterator<Item = &CleUsb> {
        self.cles_usb
            .iter()
            .filter(move |c| c.site.as_deref().is_none_or(|s| s == site))
    }

    /// Politique servie aux bornes d'un site.
    pub fn politique(&self, site: &str, t: u64) -> PolitiqueSite {
        let r = self.reglage(site);
        PolitiqueSite {
            version: VERSION,
            site: site.into(),
            mode: r.mode,
            version_politique: self.version_politique,
            entree_non_enrolees: r.entree_non_enrolees,
            cles: self
                .cles_du_site(site)
                .map(|c| CleUsbAutorisee {
                    fabricant: c.fabricant.clone(),
                    serie: c.serie.clone(),
                    entree: c.entree,
                    sortie: c.sortie,
                })
                .collect(),
            heure_serveur: t,
        }
    }

    /// Borne bloquée à l'instant `t` : secondes restantes.
    pub fn attente_borne(&self, uuid: &str, t: u64) -> Option<u64> {
        self.bornes
            .get(uuid)
            .map(|b| b.bloquee_jusqua)
            .filter(|j| *j > t)
            .map(|j| j - t)
    }

    /// Purge : correspondances retirées depuis plus d'un an, sessions échues, compteurs de
    /// bornes sans échec depuis 24 h. Renvoie le nombre d'utilisateurs purgés.
    fn purger(&mut self, t: u64) -> u64 {
        let avant = self.utilisateurs.len();
        self.utilisateurs
            .retain(|u| u.retire_le.is_none_or(|r| r + CONSERVATION_S > t));
        self.sessions.retain(|s| s.expire_le > t);
        self.bornes
            .retain(|_, b| b.bloquee_jusqua > t || b.dernier_echec + 86400 > t);
        (avant - self.utilisateurs.len()) as u64
    }

    /// Échec sur une borne ; renvoie la fin du blocage s'il vient d'être décidé.
    fn echec_borne(&mut self, uuid: &str, t: u64) -> Option<u64> {
        let b = self.bornes.entry(uuid.to_owned()).or_default();
        if b.dernier_echec + FENETRE_ECHECS_BORNE_S <= t {
            b.echecs = 0;
        }
        b.echecs += 1;
        b.dernier_echec = t;
        if b.echecs < ECHECS_BORNE_MAX {
            return None;
        }
        b.blocages = if b.bloquee_jusqua + 86400 <= t {
            1
        } else {
            b.blocages + 1
        };
        b.echecs = 0;
        b.bloquee_jusqua = t + (BLOCAGE_BORNE_S << (b.blocages - 1).min(6));
        Some(b.bloquee_jusqua)
    }

    fn ouvrir_session(&mut self, borne: &str, pseudonyme: &str, t: u64) -> String {
        let id = hex::encode(aleatoire::<16>());
        if self.sessions.len() >= SESSIONS_MAX {
            self.sessions.sort_by_key(|s| s.expire_le);
            self.sessions.remove(0);
        }
        self.sessions.push(SessionUtilisateur {
            empreinte: sha256_hex(id.as_bytes()),
            borne: borne.into(),
            pseudonyme: pseudonyme.into(),
            expire_le: t + u64::from(DUREE_SESSION_S),
        });
        id
    }

    /// Session valide d'une borne : pseudonyme de l'utilisateur (rapports, étape 3).
    pub fn session(&self, borne: &str, id: &str, t: u64) -> Option<&str> {
        let h = sha256_hex(id.as_bytes());
        self.sessions
            .iter()
            .find(|s| s.empreinte == h && s.borne == borne && s.expire_le > t)
            .map(|s| s.pseudonyme.as_str())
    }
}

/// Résultat d'un import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BilanImport {
    pub ajoutes: u64,
    pub retires: u64,
    pub actifs: u64,
    /// Identifiants de l'annuaire non conformes (`[a-z0-9._-]`, 1 à 64), ignorés.
    pub ignores: u64,
}

/// Décision interne d'une vérification (avant réponse).
struct Constat {
    resultat: ResultatUtilisateur,
    pseudonyme: Option<String>,
    attente: Option<u64>,
}

fn reponse(
    decision: DecisionUtilisateur,
    session: Option<String>,
    attente: Option<u64>,
    t: u64,
) -> ReponseVerification {
    ReponseVerification {
        version: VERSION,
        decision,
        duree_session_s: session.as_ref().map(|_| DUREE_SESSION_S),
        session,
        attente_s: attente.map(|a| a.min(u64::from(u32::MAX)) as u32),
        heure_serveur: t,
    }
}

fn refusee(attente: Option<u64>, t: u64) -> ReponseVerification {
    reponse(DecisionUtilisateur::Refusee, None, attente, t)
}

/// Lit (ou crée, 0600) un secret de 32 octets ; refusé s'il est lisible par d'autres comptes.
fn secret(chemin: &Path) -> Result<[u8; 32]> {
    match std::fs::read(chemin) {
        Ok(o) => {
            let mode = std::fs::metadata(chemin)?.permissions().mode();
            if mode & 0o077 != 0 {
                bail!(
                    "{} : accessible à d'autres comptes (0600 attendu)",
                    chemin.display()
                );
            }
            o.try_into()
                .map_err(|_| anyhow::anyhow!("{} : 32 octets attendus", chemin.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = aleatoire::<32>();
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(chemin)
                .with_context(|| format!("création de {}", chemin.display()))?;
            std::io::Write::write_all(&mut f, &s)?;
            f.sync_all()?;
            Ok(s)
        }
        Err(e) => Err(e).with_context(|| format!("lecture de {}", chemin.display())),
    }
}

/// Tire un PIN initial de [`LONGUEUR_PIN_INITIAL`] chiffres, uniforme, acceptable.
pub fn tirer_pin() -> String {
    const N: u64 = 100_000_000;
    loop {
        let v = u64::from_le_bytes(aleatoire::<8>());
        if v >= u64::MAX - u64::MAX % N {
            continue;
        }
        let pin = format!("{:08}", v % N);
        if pin_acceptable(&pin) {
            return pin;
        }
    }
}

/// Base des utilisateurs, sites et clés USB.
#[derive(Debug, Clone)]
pub struct Utilisateurs {
    dossier: PathBuf,
    stockage: Stockage,
    cle_pseudonyme: [u8; 32],
    poivre: [u8; 32],
}

impl Utilisateurs {
    pub fn ouvrir(stockage: &Stockage) -> Result<Utilisateurs> {
        let dossier = stockage.dossier().join("utilisateurs");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dossier)
            .with_context(|| format!("dossier {}", dossier.display()))?;
        Ok(Utilisateurs {
            cle_pseudonyme: secret(&dossier.join("cle-pseudonyme"))?,
            poivre: secret(&dossier.join("poivre-pin"))?,
            dossier,
            stockage: stockage.clone(),
        })
    }

    pub fn dossier(&self) -> &Path {
        &self.dossier
    }

    /// Stockage (journal d'audit) de la base.
    pub fn stockage(&self) -> &Stockage {
        &self.stockage
    }

    /// Pseudonyme d'un identifiant : `u-` + 64 bits de HMAC-SHA256.
    pub fn pseudonyme(&self, identifiant: &str) -> String {
        let cle = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.cle_pseudonyme);
        let tag = ring::hmac::sign(&cle, identifiant.as_bytes());
        format!("u-{}", hex::encode(&tag.as_ref()[..8]))
    }

    fn argon2(&self) -> Result<Argon2<'_>> {
        let p = Params::new(ARGON2_MEMOIRE_KIO, ARGON2_PASSES, 1, None)
            .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))?;
        Argon2::new_with_secret(&self.poivre, Algorithm::Argon2id, Version::V0x13, p)
            .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))
    }

    fn hacher(&self, pin: &str) -> Result<String> {
        Ok(self
            .argon2()?
            .hash_password(pin.as_bytes())
            .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))?
            .to_string())
    }

    /// Vérifie un PIN contre un PHC ; `None` : hachage factice (temps identique).
    fn verifier_pin(&self, phc: Option<&str>, pin: &str) -> Result<bool> {
        static FACTICE: OnceLock<String> = OnceLock::new();
        let factice = match FACTICE.get() {
            Some(f) => f.as_str(),
            None => FACTICE
                .get_or_init(|| self.hacher(&tirer_pin()).unwrap_or_default())
                .as_str(),
        };
        let a = self.argon2()?;
        let ok = a
            .verify_password(pin.as_bytes(), phc.unwrap_or(factice))
            .is_ok();
        Ok(ok && phc.is_some())
    }

    fn auditer(&self, acteur: &str, e: Evenement) -> Result<()> {
        self.stockage.auditer(acteur, e)
    }

    fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("base.verrou"))
            .context("verrou des utilisateurs")?;
        f.lock().context("prise du verrou des utilisateurs")?;
        Ok(f)
    }

    fn lire_sans_verrou(&self) -> Result<(BaseUtilisateurs, Vec<u8>)> {
        match std::fs::read(self.dossier.join("base.json")) {
            Ok(o) => {
                let b: BaseUtilisateurs =
                    serde_json::from_slice(&o).context("utilisateurs/base.json illisible")?;
                if b.version != 1 {
                    bail!("version de utilisateurs/base.json non gérée");
                }
                Ok((b, o))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((BaseUtilisateurs::default(), Vec::new()))
            }
            Err(e) => Err(e).context("lecture de utilisateurs/base.json"),
        }
    }

    /// Lecture cohérente (sous verrou).
    pub fn lire(&self) -> Result<BaseUtilisateurs> {
        let _v = self.verrou()?;
        Ok(self.lire_sans_verrou()?.0)
    }

    /// Transaction : verrou, lecture, purge (auditée), modification, écriture atomique si
    /// quelque chose a changé. Rien n'est écrit si `f` échoue.
    pub fn transaction<T>(
        &self,
        t: u64,
        f: impl FnOnce(&mut BaseUtilisateurs) -> Result<T>,
    ) -> Result<T> {
        let _v = self.verrou()?;
        let (mut base, avant) = self.lire_sans_verrou()?;
        let purges = base.purger(t);
        if purges > 0 {
            self.auditer(
                "passerelle",
                Evenement::UtilisateursPurges { nombre: purges },
            )?;
        }
        let r = f(&mut base)?;
        let apres = serde_json::to_vec_pretty(&base)?;
        if apres != avant {
            ecrire_atomique(&self.dossier.join("base.json"), &apres)?;
        }
        Ok(r)
    }

    // ───────────── Administration (interface web) ─────────────

    /// Remplace la liste des identifiants par celle de l'annuaire. Les absents sont retirés
    /// (PIN effacé aussitôt, sessions fermées) ; les présents retrouvent leur compte (sans
    /// PIN : réinitialisation nécessaire). Une liste vide est refusée (filtre d'annuaire
    /// erroné : cela retirerait tout le monde).
    pub fn importer(
        &self,
        identifiants: &[String],
        source: &str,
        acteur: &str,
        t: u64,
    ) -> Result<BilanImport> {
        let mut liste: Vec<String> = Vec::new();
        let mut ignores = 0;
        for i in identifiants {
            match normaliser_identifiant(i) {
                Some(n) => liste.push(n),
                None => ignores += 1,
            }
        }
        liste.sort();
        liste.dedup();
        if liste.is_empty() {
            bail!("import refusé : aucun identifiant valide (filtre de l'annuaire à vérifier)");
        }
        if liste.len() > UTILISATEURS_MAX {
            bail!("import refusé : plus de {UTILISATEURS_MAX} identifiants");
        }
        self.transaction(t, |b| {
            let (mut ajoutes, mut retires) = (0, 0);
            for u in b.utilisateurs.iter_mut() {
                let present = liste.binary_search(&u.identifiant).is_ok();
                if u.actif && !present {
                    u.actif = false;
                    u.retire_le = Some(t);
                    u.pin = None;
                    u.pin_le = None;
                    u.pin_a_changer = false;
                    retires += 1;
                } else if !u.actif && present {
                    u.actif = true;
                    u.retire_le = None;
                    ajoutes += 1;
                }
            }
            let retires_ps: Vec<String> = b
                .utilisateurs
                .iter()
                .filter(|u| !u.actif)
                .map(|u| u.pseudonyme.clone())
                .collect();
            b.sessions.retain(|s| !retires_ps.contains(&s.pseudonyme));
            for i in &liste {
                if b.utilisateur(i).is_none() {
                    b.utilisateurs.push(Utilisateur {
                        identifiant: i.clone(),
                        pseudonyme: self.pseudonyme(i),
                        actif: true,
                        ajoute_le: t,
                        retire_le: None,
                        pin: None,
                        pin_le: None,
                        pin_a_changer: false,
                        echecs: 0,
                        verrouille_le: None,
                        derniere_verification: None,
                    });
                    ajoutes += 1;
                }
            }
            let actifs = liste.len() as u64;
            b.dernier_import = Some(Import {
                le: t,
                source: source.into(),
                actifs,
            });
            self.auditer(
                acteur,
                Evenement::UtilisateursImportes {
                    source: source.into(),
                    ajoutes,
                    retires,
                    actifs,
                },
            )?;
            Ok(BilanImport {
                ajoutes,
                retires,
                actifs,
                ignores,
            })
        })
    }

    /// Tire un nouveau PIN (affiché une seule fois par l'appelant), à changer au premier
    /// usage ; déverrouille le compte. Seul le dérivé est conservé.
    pub fn reinitialiser_pin(&self, identifiant: &str, acteur: &str, t: u64) -> Result<String> {
        let pin = tirer_pin();
        let phc = {
            let _un = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
            self.hacher(&pin)?
        };
        self.transaction(t, |b| {
            let Some(u) = b.utilisateur_mut(identifiant).filter(|u| u.actif) else {
                bail!("utilisateur inconnu ou retiré de l'annuaire");
            };
            u.pin = Some(phc);
            u.pin_le = Some(t);
            u.pin_a_changer = true;
            u.echecs = 0;
            u.verrouille_le = None;
            let p = u.pseudonyme.clone();
            b.sessions.retain(|s| s.pseudonyme != p);
            self.auditer(acteur, Evenement::PinReinitialise { utilisateur: p })
        })?;
        Ok(pin)
    }

    pub fn deverrouiller(&self, identifiant: &str, acteur: &str, t: u64) -> Result<()> {
        self.transaction(t, |b| {
            let Some(u) = b.utilisateur_mut(identifiant) else {
                bail!("utilisateur inconnu");
            };
            u.echecs = 0;
            u.verrouille_le = None;
            let p = u.pseudonyme.clone();
            self.auditer(
                acteur,
                Evenement::UtilisateurDeverrouille { utilisateur: p },
            )
        })
    }

    /// Mode d'un site. `quarantaine_active` : D13, le mode Aucun est interdit si la
    /// quarantaine est activée. La Console passe par [`Utilisateurs::definir_mode_d13`].
    pub fn definir_mode(
        &self,
        site: &str,
        mode: ModeUtilisateurs,
        quarantaine_active: bool,
        acteur: &str,
        t: u64,
    ) -> Result<()> {
        if !site_valide(site) {
            bail!("{SITE_INVALIDE}");
        }
        if mode == ModeUtilisateurs::Aucun && quarantaine_active {
            bail!("{REFUS_D13_MODE}");
        }
        self.transaction(t, |b| {
            b.sites.entry(site.into()).or_default().mode = mode;
            b.version_politique += 1;
            self.auditer(
                acteur,
                Evenement::ModeSite {
                    site: site.into(),
                    mode: nom_mode(mode).into(),
                },
            )
        })
    }

    /// [`Utilisateurs::definir_mode`] avec l'état RÉEL de la quarantaine, lu sous son verrou
    /// (une activation validée en même temps ne peut pas s'intercaler, D13).
    pub fn definir_mode_d13(
        &self,
        site: &str,
        mode: ModeUtilisateurs,
        acteur: &str,
        t: u64,
    ) -> Result<()> {
        let q = crate::quarantaine::Quarantaine::ouvrir(&self.stockage)?;
        let _v = q.verrouiller()?;
        self.definir_mode(site, mode, quarantaine_active(&self.stockage), acteur, t)
    }

    pub fn definir_entree(
        &self,
        site: &str,
        entree: EntreeNonEnrolees,
        acteur: &str,
        t: u64,
    ) -> Result<()> {
        if !site_valide(site) {
            bail!("{SITE_INVALIDE}");
        }
        self.transaction(t, |b| {
            b.sites.entry(site.into()).or_default().entree_non_enrolees = entree;
            b.version_politique += 1;
            self.auditer(
                acteur,
                Evenement::PolitiqueUsbSite {
                    site: site.into(),
                    entree_non_enrolees: match entree {
                        EntreeNonEnrolees::Autorisee => "autorisee",
                        EntreeNonEnrolees::Interdite => "interdite",
                    }
                    .into(),
                },
            )
        })
    }

    /// Enrôle une clé USB (fabricant + numéro de série) pour un site ou tous (`None`).
    #[allow(clippy::too_many_arguments)]
    pub fn enroler_cle(
        &self,
        fabricant: &str,
        serie: &str,
        libelle: &str,
        site: Option<&str>,
        entree: bool,
        sortie: bool,
        acteur: &str,
        t: u64,
    ) -> Result<String> {
        let fabricant = normaliser_fabricant(fabricant)
            .context("fabricant invalide (identifiant USB à 4 chiffres hexadécimaux)")?;
        let serie = normaliser_serie(serie)
            .context("numéro de série invalide (1 à 64 caractères ASCII sans espace)")?;
        let libelle = libelle.trim();
        if libelle.chars().count() > 64 || libelle.chars().any(char::is_control) {
            bail!("libellé invalide (64 caractères au plus)");
        }
        if site.is_some_and(|s| !site_valide(s)) {
            bail!("{SITE_INVALIDE}");
        }
        if !entree && !sortie {
            bail!("choisir au moins un usage (entrée ou sortie)");
        }
        let id = format!("usb-{}", hex::encode(aleatoire::<4>()));
        self.transaction(t, |b| {
            if b.cles_usb
                .iter()
                .any(|c| c.fabricant == fabricant && c.serie == serie)
            {
                bail!("clé déjà enrôlée");
            }
            let pleins: Vec<String> = match site {
                Some(s) => vec![s.to_owned()],
                None => b.sites.keys().cloned().collect(),
            };
            let sans_site = b.cles_usb.iter().filter(|c| c.site.is_none()).count();
            if sans_site + 1 > CLES_PAR_SITE_MAX
                || pleins
                    .iter()
                    .any(|s| b.cles_du_site(s).count() + 1 > CLES_PAR_SITE_MAX)
            {
                bail!("{CLES_PAR_SITE_MAX} clés au plus par site");
            }
            b.cles_usb.push(CleUsb {
                id: id.clone(),
                fabricant: fabricant.clone(),
                serie: serie.clone(),
                libelle: libelle.into(),
                site: site.map(str::to_owned),
                entree,
                sortie,
                enrolee_le: t,
            });
            b.version_politique += 1;
            self.auditer(
                acteur,
                Evenement::CleUsbEnrolee {
                    cle: id.clone(),
                    fabricant: fabricant.clone(),
                    site: site.unwrap_or("tous").into(),
                },
            )
        })?;
        Ok(id)
    }

    pub fn retirer_cle(&self, id: &str, acteur: &str, t: u64) -> Result<()> {
        self.transaction(t, |b| {
            let avant = b.cles_usb.len();
            b.cles_usb.retain(|c| c.id != id);
            if b.cles_usb.len() == avant {
                bail!("clé inconnue");
            }
            b.version_politique += 1;
            self.auditer(acteur, Evenement::CleUsbRetiree { cle: id.into() })
        })
    }

    // ───────────── Bornes (passerelle, mTLS) ─────────────

    /// Politique du site de la borne (site lu dans son certificat). Auditée quand la version
    /// servie à cette borne change.
    pub fn politique_pour(&self, borne: &Identite, acteur: &str, t: u64) -> Result<PolitiqueSite> {
        self.transaction(t, |b| {
            let p = b.politique(&borne.site, t);
            if b.politique_servie.get(&borne.uuid) != Some(&p.version_politique) {
                b.politique_servie
                    .insert(borne.uuid.clone(), p.version_politique);
                self.auditer(
                    acteur,
                    Evenement::PolitiqueServie {
                        borne: borne.uuid.clone(),
                        version_politique: p.version_politique,
                    },
                )?;
            }
            Ok(p)
        })
    }

    /// Contrôles préalables communs : mode du site, blocage de la borne, compte.
    /// Renvoie `Err(constat)` si la demande est refusée sans vérification de PIN.
    fn preparer(
        &self,
        b: &BaseUtilisateurs,
        borne: &Identite,
        identifiant: &str,
        avec_pin: bool,
        t: u64,
    ) -> std::result::Result<(ModeUtilisateurs, Option<Utilisateur>), Constat> {
        let mode = b.reglage(&borne.site).mode;
        let compatible = match mode {
            ModeUtilisateurs::Aucun => false,
            ModeUtilisateurs::Identification => !avec_pin,
            ModeUtilisateurs::Authentification => avec_pin,
        };
        if !compatible {
            return Err(Constat {
                resultat: ResultatUtilisateur::HorsMode,
                pseudonyme: None,
                attente: None,
            });
        }
        if let Some(a) = b.attente_borne(&borne.uuid, t) {
            return Err(Constat {
                resultat: ResultatUtilisateur::BorneBloquee,
                pseudonyme: None,
                attente: Some(a),
            });
        }
        Ok((
            mode,
            b.utilisateur(identifiant).filter(|u| u.actif).cloned(),
        ))
    }

    /// Enregistre l'issue d'une vérification : compteurs, verrouillage, blocage, session,
    /// audit. `ok` : PIN (ou identifiant) correct ET compte non verrouillé.
    fn conclure(
        &self,
        borne: &Identite,
        identifiant: &str,
        verifie: bool,
        authentification: bool,
        acteur: &str,
        t: u64,
    ) -> Result<Constat> {
        self.transaction(t, |b| {
            let mut constat = Constat {
                resultat: ResultatUtilisateur::Refusee,
                pseudonyme: None,
                attente: None,
            };
            let mut verrouillage = None;
            if let Some(u) = b.utilisateur_mut(identifiant).filter(|u| u.actif) {
                constat.pseudonyme = Some(u.pseudonyme.clone());
                u.derniere_verification = Some(t);
                if u.verrouille_le.is_some() {
                    constat.resultat = ResultatUtilisateur::Verrouille;
                } else if verifie {
                    u.echecs = 0;
                    constat.resultat = if authentification && u.pin_a_changer {
                        ResultatUtilisateur::PinAChanger
                    } else {
                        ResultatUtilisateur::Acceptee
                    };
                } else {
                    u.echecs += 1;
                    if u.echecs >= ECHECS_COMPTE_MAX {
                        u.verrouille_le = Some(t);
                        verrouillage = Some(u.pseudonyme.clone());
                    }
                }
            }
            let refus = !matches!(
                constat.resultat,
                ResultatUtilisateur::Acceptee | ResultatUtilisateur::PinAChanger
            );
            self.auditer(
                acteur,
                Evenement::UtilisateurVerifie {
                    borne: borne.uuid.clone(),
                    utilisateur: constat
                        .pseudonyme
                        .clone()
                        .unwrap_or_else(|| "inconnu".into()),
                    resultat: constat.resultat,
                },
            )?;
            if let Some(p) = verrouillage {
                self.auditer(
                    acteur,
                    Evenement::UtilisateurVerrouille {
                        utilisateur: p,
                        borne: borne.uuid.clone(),
                    },
                )?;
            }
            if refus && let Some(jusqua) = b.echec_borne(&borne.uuid, t) {
                self.auditer(
                    acteur,
                    Evenement::BorneBloquee {
                        borne: borne.uuid.clone(),
                        jusqua,
                    },
                )?;
            }
            Ok(constat)
        })
    }

    /// Refus sans vérification (mode incompatible, borne bloquée) : audité, rien d'autre
    /// n'est conservé (en mode Aucun, l'identifiant reçu n'est écrit nulle part).
    fn refus_prealable(
        &self,
        borne: &Identite,
        c: Constat,
        acteur: &str,
        t: u64,
    ) -> Result<ReponseVerification> {
        self.auditer(
            acteur,
            Evenement::UtilisateurVerifie {
                borne: borne.uuid.clone(),
                utilisateur: "inconnu".into(),
                resultat: c.resultat,
            },
        )?;
        Ok(refusee(c.attente, t))
    }

    /// `POST /utilisateurs/verification` (borne authentifiée par mTLS).
    pub fn verifier(
        &self,
        borne: &Identite,
        d: &DemandeVerification,
        acteur: &str,
        t: u64,
    ) -> Result<ReponseVerification> {
        let _un = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
        let prep = {
            let b = self.lire()?;
            self.preparer(&b, borne, &d.identifiant, d.pin.is_some(), t)
        };
        let (mode, u) = match prep {
            Ok(x) => x,
            Err(c) => return self.refus_prealable(borne, c, acteur, t),
        };
        let verifie = match (mode, d.pin.as_deref()) {
            (ModeUtilisateurs::Authentification, Some(pin)) => {
                // Toujours une dérivation (compte inconnu, sans PIN ou verrouillé compris) :
                // le temps de réponse ne renseigne pas sur le compte.
                self.verifier_pin(u.as_ref().and_then(|u| u.pin.as_deref()), pin)?
            }
            _ => u.is_some(),
        };
        let auth = mode == ModeUtilisateurs::Authentification;
        let c = self.conclure(borne, &d.identifiant, verifie, auth, acteur, t)?;
        self.repondre(borne, c, t)
    }

    fn repondre(&self, borne: &Identite, c: Constat, t: u64) -> Result<ReponseVerification> {
        Ok(match (c.resultat, c.pseudonyme) {
            (ResultatUtilisateur::Acceptee, Some(p)) => {
                let s = self.transaction(t, |b| Ok(b.ouvrir_session(&borne.uuid, &p, t)))?;
                reponse(DecisionUtilisateur::Acceptee, Some(s), None, t)
            }
            (ResultatUtilisateur::PinAChanger, _) => {
                reponse(DecisionUtilisateur::PinAChanger, None, None, t)
            }
            _ => refusee(c.attente, t),
        })
    }

    /// `POST /utilisateurs/pin` : ancien PIN vérifié (mêmes compteurs), nouveau PIN
    /// acceptable et différent ; session ouverte en cas de succès.
    pub fn changer_pin(
        &self,
        borne: &Identite,
        d: &DemandeChangementPin,
        acteur: &str,
        t: u64,
    ) -> Result<ReponseVerification> {
        let _un = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
        let prep = {
            let b = self.lire()?;
            self.preparer(&b, borne, &d.identifiant, true, t)
        };
        let (_, u) = match prep {
            Ok(x) => x,
            Err(c) => return self.refus_prealable(borne, c, acteur, t),
        };
        let verifie = self.verifier_pin(u.as_ref().and_then(|u| u.pin.as_deref()), &d.pin)?;
        let c = self.conclure(borne, &d.identifiant, verifie, true, acteur, t)?;
        let accepte = matches!(
            c.resultat,
            ResultatUtilisateur::Acceptee | ResultatUtilisateur::PinAChanger
        );
        if !accepte {
            return self.repondre(borne, c, t);
        }
        if !pin_acceptable(&d.nouveau_pin) || d.nouveau_pin == d.pin {
            return Ok(refusee(None, t));
        }
        let phc = self.hacher(&d.nouveau_pin)?;
        let p = self.transaction(t, |b| {
            let Some(u) = b.utilisateur_mut(&d.identifiant).filter(|u| u.actif) else {
                bail!("utilisateur retiré pendant le changement");
            };
            u.pin = Some(phc);
            u.pin_le = Some(t);
            u.pin_a_changer = false;
            let p = u.pseudonyme.clone();
            self.auditer(
                acteur,
                Evenement::PinChange {
                    utilisateur: p.clone(),
                    borne: borne.uuid.clone(),
                },
            )?;
            Ok(p)
        })?;
        let s = self.transaction(t, |b| Ok(b.ouvrir_session(&borne.uuid, &p, t)))?;
        Ok(reponse(DecisionUtilisateur::Acceptee, Some(s), None, t))
    }
}

/// Nom court d'un mode (audit, pages).
pub fn nom_mode(m: ModeUtilisateurs) -> &'static str {
    match m {
        ModeUtilisateurs::Aucun => "aucun",
        ModeUtilisateurs::Identification => "identification",
        ModeUtilisateurs::Authentification => "authentification",
    }
}

/// Message de refus D13 (activation de la quarantaine avec un site en mode Aucun).
pub const REFUS_D13_QUARANTAINE: &str = "D13 : la quarantaine ne peut pas être activée tant qu'un site est en mode Aucun ; passez d'abord ces sites en Identification ou Authentification";
/// Message de refus D13 (mode Aucun demandé alors que la quarantaine est active).
pub const REFUS_D13_MODE: &str =
    "mode Aucun interdit : la quarantaine est activée (D13) ; désactivez-la d'abord";
/// Message de refus D13 (jeton d'enrôlement pour un site en mode Aucun, quarantaine active).
pub const REFUS_D13_JETON: &str = "D13 : la quarantaine est active et ce site est en mode Aucun ; choisissez d'abord Identification ou Authentification pour ce site (Sites et modes)";

/// État RÉEL de la quarantaine (D13). Fail-closed : un état illisible compte comme actif.
pub fn quarantaine_active(stockage: &Stockage) -> bool {
    match crate::quarantaine::Quarantaine::ouvrir(stockage)
        .and_then(|q| q.statut(crate::outils::maintenant()))
    {
        Ok(s) => s.active,
        Err(_) => true,
    }
}

/// Sites en mode Aucun (D13) : sites réglés, sites des bornes actives, des jetons valides, des
/// demandes d'enrôlement en attente et des clés USB (un site jamais réglé est en mode Aucun).
pub fn sites_en_mode_aucun(stockage: &Stockage, t: u64) -> Result<Vec<String>> {
    let reg = stockage.lire()?;
    let base = Utilisateurs::ouvrir(stockage)?.lire()?;
    let mut sites: std::collections::BTreeSet<String> = base.sites.keys().cloned().collect();
    sites.extend(
        reg.bornes
            .iter()
            .filter(|b| b.statut == crate::registre::StatutBorne::Active)
            .map(|b| b.site.clone()),
    );
    sites.extend(
        reg.jetons
            .iter()
            .filter(|j| j.utilise_le.is_none() && j.expire_le > t)
            .map(|j| j.site.clone()),
    );
    sites.extend(
        reg.demandes
            .iter()
            .filter(|d| d.statut == crate::registre::StatutDemande::EnAttente)
            .map(|d| d.site.clone()),
    );
    sites.extend(base.cles_usb.iter().filter_map(|c| c.site.clone()));
    Ok(sites
        .into_iter()
        .filter(|s| base.reglage(s).mode == ModeUtilisateurs::Aucun)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbacane_protocole::utilisateurs::Sens;

    fn base() -> (tempfile::TempDir, Utilisateurs) {
        let d = tempfile::tempdir().unwrap();
        let s = Stockage::ouvrir(&d.path().join("etat")).unwrap();
        let u = Utilisateurs::ouvrir(&s).unwrap();
        (d, u)
    }

    fn borne(site: &str) -> Identite {
        Identite {
            uuid: "0000aaaa-0000-4000-8000-000000000001".into(),
            site: site.into(),
            serie: "01".into(),
        }
    }

    fn verif(id: &str, pin: Option<&str>) -> DemandeVerification {
        DemandeVerification {
            version: VERSION,
            identifiant: id.into(),
            pin: pin.map(str::to_owned),
        }
    }

    #[test]
    fn pin_tire_et_secrets() {
        for _ in 0..50 {
            let p = tirer_pin();
            assert_eq!(p.len(), LONGUEUR_PIN_INITIAL);
            assert!(pin_acceptable(&p));
        }
        let (_d, u) = base();
        let p = u.pseudonyme("j.dupont");
        assert!(p.starts_with("u-") && p.len() == 18);
        assert!(barbacane_audit::ident_valide(&p));
        let mode = std::fs::metadata(u.dossier().join("poivre-pin"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // Même poivre relu : même pseudonyme.
        let u2 = Utilisateurs::ouvrir(&u.stockage).unwrap();
        assert_eq!(u2.pseudonyme("j.dupont"), p);
    }

    #[test]
    fn poivre_exige() {
        let (_d, u) = base();
        let phc = u.hacher("48291637").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(u.verifier_pin(Some(&phc), "48291637").unwrap());
        assert!(!u.verifier_pin(Some(&phc), "48291638").unwrap());
        let (_d2, autre) = base();
        assert!(
            !autre.verifier_pin(Some(&phc), "48291637").unwrap(),
            "sans le poivre du serveur, le dérivé ne se vérifie pas"
        );
        assert!(!u.verifier_pin(None, "48291637").unwrap());
    }

    #[test]
    fn import_retrait_et_purge() {
        let (_d, u) = base();
        let t = 1_800_000_000;
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let b = u
            .importer(
                &ids(&["A.Martin", "b.durand", "x y", "b.durand"]),
                "annuaire",
                "web:a",
                t,
            )
            .unwrap();
        assert_eq!((b.ajoutes, b.retires, b.actifs, b.ignores), (2, 0, 2, 1));
        assert!(u.importer(&ids(&["x y"]), "annuaire", "web:a", t).is_err());
        u.reinitialiser_pin("b.durand", "web:a", t).unwrap();
        let b = u
            .importer(&ids(&["a.martin"]), "annuaire", "web:a", t + 10)
            .unwrap();
        assert_eq!((b.ajoutes, b.retires), (0, 1));
        let base = u.lire().unwrap();
        let parti = base.utilisateur("b.durand").unwrap();
        assert!(!parti.actif && parti.pin.is_none(), "PIN effacé au départ");
        assert!(u.reinitialiser_pin("b.durand", "web:a", t + 20).is_err());
        // Purgé un an après le retrait (à la transaction suivante).
        u.transaction(t + 10 + CONSERVATION_S, |_| Ok(())).unwrap();
        assert!(u.lire().unwrap().utilisateur("b.durand").is_none());
        assert!(u.lire().unwrap().utilisateur("a.martin").is_some());
    }

    #[test]
    fn mode_aucun_interdit_avec_quarantaine() {
        let (_d, u) = base();
        let t = 1_800_000_000;
        assert!(
            u.definir_mode("site-1", ModeUtilisateurs::Aucun, true, "web:a", t)
                .is_err()
        );
        u.definir_mode("site-1", ModeUtilisateurs::Identification, true, "web:a", t)
            .unwrap();
        assert!(
            u.definir_mode(
                "site 1",
                ModeUtilisateurs::Identification,
                false,
                "web:a",
                t
            )
            .is_err()
        );
    }

    #[test]
    fn verrouillage_apres_cinq_echecs() {
        let (_d, u) = base();
        let t = 1_800_000_000;
        u.importer(&["j.dupont".into()], "annuaire", "web:a", t)
            .unwrap();
        u.definir_mode(
            "site-1",
            ModeUtilisateurs::Authentification,
            false,
            "web:a",
            t,
        )
        .unwrap();
        let pin = u.reinitialiser_pin("j.dupont", "web:a", t).unwrap();
        let faux = if pin == "48291637" {
            "48291638"
        } else {
            "48291637"
        };
        // Bornes différentes : seul le compteur du compte joue.
        for i in 0..ECHECS_COMPTE_MAX {
            let mut b = borne("site-1");
            b.uuid = format!("0000aaaa-0000-4000-8000-00000000000{i}");
            let r = u
                .verifier(&b, &verif("j.dupont", Some(faux)), "passerelle", t)
                .unwrap();
            assert_eq!(r.decision, DecisionUtilisateur::Refusee);
        }
        let base = u.lire().unwrap();
        assert!(
            base.utilisateur("j.dupont")
                .unwrap()
                .verrouille_le
                .is_some()
        );
        let r = u
            .verifier(
                &borne("site-1"),
                &verif("j.dupont", Some(&pin)),
                "passerelle",
                t,
            )
            .unwrap();
        assert_eq!(
            r.decision,
            DecisionUtilisateur::Refusee,
            "verrouillé : bon PIN refusé"
        );
        u.deverrouiller("j.dupont", "web:a", t).unwrap();
        let r = u
            .verifier(
                &borne("site-1"),
                &verif("j.dupont", Some(&pin)),
                "passerelle",
                t,
            )
            .unwrap();
        assert_eq!(r.decision, DecisionUtilisateur::PinAChanger);
    }

    #[test]
    fn borne_bloquee_apres_cinq_echecs() {
        let (_d, u) = base();
        let t = 1_800_000_000;
        u.importer(&["j.dupont".into()], "annuaire", "web:a", t)
            .unwrap();
        u.definir_mode(
            "site-1",
            ModeUtilisateurs::Identification,
            false,
            "web:a",
            t,
        )
        .unwrap();
        for i in 0..ECHECS_BORNE_MAX {
            let r = u
                .verifier(
                    &borne("site-1"),
                    &verif(&format!("inconnu{i}"), None),
                    "passerelle",
                    t,
                )
                .unwrap();
            assert_eq!(r.decision, DecisionUtilisateur::Refusee);
        }
        let r = u
            .verifier(
                &borne("site-1"),
                &verif("j.dupont", None),
                "passerelle",
                t + 1,
            )
            .unwrap();
        assert_eq!(r.decision, DecisionUtilisateur::Refusee);
        assert_eq!(r.attente_s, Some(BLOCAGE_BORNE_S as u32 - 1));
        let r = u
            .verifier(
                &borne("site-1"),
                &verif("j.dupont", None),
                "passerelle",
                t + BLOCAGE_BORNE_S,
            )
            .unwrap();
        assert_eq!(r.decision, DecisionUtilisateur::Acceptee);
        let s = r.session.unwrap();
        let base = u.lire().unwrap();
        assert_eq!(
            base.session(&borne("site-1").uuid, &s, t + BLOCAGE_BORNE_S),
            Some(u.pseudonyme("j.dupont").as_str())
        );
        // Délai croissant : second blocage dans les 24 h = 30 min.
        let mut b = base.clone();
        let t2 = t + BLOCAGE_BORNE_S + 10;
        let mut fin = None;
        for _ in 0..ECHECS_BORNE_MAX {
            fin = b.echec_borne(&borne("site-1").uuid, t2);
        }
        assert_eq!(fin, Some(t2 + 2 * BLOCAGE_BORNE_S));
    }

    #[test]
    fn politique_des_cles_par_site() {
        let (_d, u) = base();
        let t = 1_800_000_000;
        let id = u
            .enroler_cle(
                "0x0781",
                "4c530001",
                "Clé du SOC",
                Some("site-1"),
                true,
                true,
                "web:a",
                t,
            )
            .unwrap();
        u.enroler_cle("0951", "SORTIE", "", None, false, true, "web:a", t)
            .unwrap();
        assert!(
            u.enroler_cle("0781", "4C530001", "", None, true, true, "web:a", t)
                .is_err(),
            "doublon"
        );
        assert!(
            u.enroler_cle("781", "X", "", None, true, true, "web:a", t)
                .is_err()
        );
        u.definir_entree("site-1", EntreeNonEnrolees::Interdite, "web:a", t)
            .unwrap();
        let b = u.lire().unwrap();
        let p1 = b.politique("site-1", t);
        let p2 = b.politique("site-2", t);
        assert_eq!(p1.cles.len(), 2);
        assert_eq!(p2.cles.len(), 1, "clé du site 1 absente du site 2");
        assert!(
            !p1.autorise("1234", "INCONNUE", Sens::Entree),
            "non enrôlée refusée"
        );
        assert!(
            p2.autorise("1234", "INCONNUE", Sens::Entree),
            "site 2 : défaut v1"
        );
        assert!(!p2.autorise("1234", "INCONNUE", Sens::Sortie));
        assert!(p1.autorise("0781", "4C530001", Sens::Sortie));
        assert!(!p2.autorise("0781", "4C530001", Sens::Sortie));
        let v = p1.version_politique;
        u.retirer_cle(&id, "web:a", t).unwrap();
        let p1 = u.lire().unwrap().politique("site-1", t);
        assert!(p1.version_politique > v && p1.cles.len() == 1);
        assert!(barbacane_protocole::encoder(&p1).is_ok());
    }
}
