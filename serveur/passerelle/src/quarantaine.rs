//! Quarantaine côté serveur (étape 11, `docs/suite/quarantaine.md`) — **implémentée mais
//! DÉSACTIVÉE par défaut** (niveau Diffusion Restreinte, `docs/suite/dossier-homologation.md`).
//!
//! - **Verrou d'homologation** : rien n'est activable, reçu ni exporté tant que le dossier
//!   d'homologation installé ne contient pas exactement la ligne [`LIGNE_EN_PLACE`] (relu à
//!   CHAQUE opération : remettre `non` désactive aussitôt). Refus explicites et audités.
//! - **Double validation** (conception §3.10) : activation et export sont demandés par un
//!   administrateur et validés par un SECOND administrateur distinct (demande valable 1 h).
//! - **Stockage chiffré** : chaque fichier est chiffré en AES-256-GCM par une clé neuve qui lui
//!   est propre ; cette clé est enveloppée (AES-256-GCM) par la clé de quarantaine du serveur
//!   (fichier 0600, derrière le trait [`CleQuarantaine`] pour un futur TPM). Les métadonnées
//!   (minimales : identifiant, borne, dates, empreinte, taille — jamais de nom de fichier) sont
//!   liées au chiffré comme données associées : toute altération du chiffré, de la clé
//!   enveloppée ou des métadonnées est détectée à la lecture, puis l'empreinte est revérifiée.
//! - **Conservation bornée** : [`CONSERVATION_J`] jours, purge à chaque opération.
//! - Chaque accès est audité ([`Evenement::Quarantaine`]).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use barbacane_audit::Evenement;
use barbacane_protocole::CodeErreur;
use barbacane_protocole::quarantaine::{DepotQuarantaine, TAILLE_FICHIER_MAX};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};

use crate::outils::{aleatoire, ecrire_atomique, sha256_hex};
use crate::registre::{Refus, Stockage};

/// Seule ligne du dossier d'homologation qui autorise la quarantaine.
pub const LIGNE_EN_PLACE: &str = "mesures_dr_serveur: en place";
const CHAMP: &str = "mesures_dr_serveur";
/// Copie installée du dossier d'homologation, par défaut. Configurable sans toucher à la
/// configuration de la passerelle : `<registre>/quarantaine.conf`, ligne
/// `dossier_homologation = CHEMIN` (voir [`chemin_homologation`]).
pub const DOSSIER_HOMOLOGATION_DEFAUT: &str =
    "/usr/share/doc/barbacane-serveur/dossier-homologation.md";
/// Durée de conservation (conception §3.6 : 30 jours, purge automatique).
pub const CONSERVATION_J: u64 = 30;
/// Validité d'une demande en attente de seconde validation.
pub const DUREE_DEMANDE_S: u64 = 3600;
const TAILLE_DOSSIER_MAX: u64 = 1 << 20;
const DEMANDES_MAX: usize = 32;

/// Contrôle du dossier d'homologation : `Ok` seulement si UNE ligne porte le champ et qu'elle
/// vaut exactement [`LIGNE_EN_PLACE`]. `Err` donne la raison, affichable.
pub fn mesures_dr(chemin: &Path) -> Result<(), String> {
    let mut texte = String::new();
    File::open(chemin)
        .and_then(|f| f.take(TAILLE_DOSSIER_MAX + 1).read_to_string(&mut texte))
        .map_err(|e| {
            format!(
                "dossier d'homologation {} illisible ({e})",
                chemin.display()
            )
        })?;
    if texte.len() as u64 > TAILLE_DOSSIER_MAX {
        return Err("dossier d'homologation trop grand".into());
    }
    let lignes: Vec<&str> = texte
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| l.trim_start().starts_with(CHAMP))
        .collect();
    match lignes.as_slice() {
        [l] if *l == LIGNE_EN_PLACE => Ok(()),
        [l] => Err(format!(
            "le dossier d'homologation indique « {} » : les mesures DR du serveur ne sont pas en place (il faut exactement « {LIGNE_EN_PLACE} », après décision de l'autorité d'homologation)",
            l.chars().take(80).collect::<String>()
        )),
        [] => Err("le dossier d'homologation ne porte pas le champ mesures_dr_serveur".into()),
        _ => Err("champ mesures_dr_serveur répété dans le dossier d'homologation".into()),
    }
}

/// Chemin du dossier d'homologation : `<registre>/quarantaine.conf` s'il existe (une seule clé
/// `dossier_homologation`, toute autre ligne refusée), sinon [`DOSSIER_HOMOLOGATION_DEFAUT`].
pub fn chemin_homologation(stockage: &Stockage) -> Result<PathBuf> {
    let f = stockage.dossier().join("quarantaine.conf");
    let texte = match std::fs::read_to_string(&f) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PathBuf::from(DOSSIER_HOMOLOGATION_DEFAUT));
        }
        Err(e) => return Err(e).context("quarantaine.conf"),
    };
    let mut chemin = None;
    for (n, l) in texte.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        match l.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
            Some(("dossier_homologation", v)) if chemin.is_none() && !v.is_empty() => {
                chemin = Some(PathBuf::from(v));
            }
            _ => bail!(
                "quarantaine.conf, ligne {} : « dossier_homologation = CHEMIN » attendu",
                n + 1
            ),
        }
    }
    Ok(chemin.unwrap_or_else(|| PathBuf::from(DOSSIER_HOMOLOGATION_DEFAUT)))
}

// ───────────────────────────── Chiffrement ────────────────────────────────────────────────────

fn sceller(cle: &[u8; 32], aad: &[u8], clair: &[u8]) -> Result<Vec<u8>> {
    let k = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, cle).map_err(|_| anyhow::anyhow!("clé AES"))?,
    );
    let n = aleatoire::<NONCE_LEN>();
    let mut tampon = clair.to_vec();
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::from(aad), &mut tampon)
        .map_err(|_| anyhow::anyhow!("chiffrement"))?;
    let mut sortie = n.to_vec();
    sortie.extend_from_slice(&tampon);
    Ok(sortie)
}

fn ouvrir(cle: &[u8; 32], aad: &[u8], scelle: &[u8]) -> Result<Vec<u8>> {
    if scelle.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        bail!("chiffré tronqué");
    }
    let k = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, cle).map_err(|_| anyhow::anyhow!("clé AES"))?,
    );
    let (n, c) = scelle.split_at(NONCE_LEN);
    let n = Nonce::try_assume_unique_for_key(n).map_err(|_| anyhow::anyhow!("nonce"))?;
    let mut tampon = c.to_vec();
    let clair = k
        .open_in_place(n, Aad::from(aad), &mut tampon)
        .map_err(|_| anyhow::anyhow!("intégrité AES-GCM en défaut"))?;
    Ok(clair.to_vec())
}

/// Clé de quarantaine du serveur : enveloppe les clés de fichier. Trait prévu pour un TPM
/// (clé scellée, jamais extraite) ; implémentation actuelle : [`CleFichier`].
pub trait CleQuarantaine {
    fn envelopper(&self, aad: &[u8], cle: &[u8; 32]) -> Result<Vec<u8>>;
    fn desenvelopper(&self, aad: &[u8], enveloppe: &[u8]) -> Result<[u8; 32]>;
}

/// Clé de quarantaine dans un fichier 0600 (32 octets aléatoires, créée au premier usage).
pub struct CleFichier([u8; 32]);

impl CleFichier {
    pub fn ouvrir_ou_creer(chemin: &Path) -> Result<CleFichier> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(chemin)
        {
            Ok(mut f) => {
                let k = aleatoire::<32>();
                f.write_all(&k)?;
                f.sync_all()?;
                return Ok(CleFichier(k));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).context("création de la clé de quarantaine"),
        }
        let m = std::fs::metadata(chemin).context("clé de quarantaine")?;
        if m.permissions().mode() & 0o077 != 0 {
            bail!(
                "clé de quarantaine {} : droits trop larges (0600 exigé)",
                chemin.display()
            );
        }
        let o = std::fs::read(chemin).context("lecture de la clé de quarantaine")?;
        let k: [u8; 32] = o
            .try_into()
            .map_err(|_| anyhow::anyhow!("clé de quarantaine : 32 octets attendus"))?;
        Ok(CleFichier(k))
    }
}

impl CleQuarantaine for CleFichier {
    fn envelopper(&self, aad: &[u8], cle: &[u8; 32]) -> Result<Vec<u8>> {
        sceller(&self.0, aad, cle)
    }
    fn desenvelopper(&self, aad: &[u8], enveloppe: &[u8]) -> Result<[u8; 32]> {
        ouvrir(&self.0, aad, enveloppe)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("clé de fichier : taille"))
    }
}

// ───────────────────────────── État ───────────────────────────────────────────────────────────

/// Action soumise à double validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Activation,
    Export { element: String },
}

/// Demande en attente de la validation d'un SECOND administrateur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Demande {
    pub id: String,
    pub action: Action,
    pub par: String,
    pub le: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Etat {
    active: bool,
    demandes: Vec<Demande>,
}

/// Métadonnées minimales d'un élément (aucun nom de fichier).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Element {
    pub id: String,
    pub borne: String,
    pub recu_le: u64,
    pub expire_le: u64,
    pub sha256: String,
    pub taille: u64,
    /// Clé du fichier enveloppée par la clé de quarantaine (hex : nonce ‖ chiffré ‖ étiquette).
    pub cle_enveloppee: String,
}

impl Element {
    /// Données associées du contenu : toute métadonnée modifiée rend le déchiffrement impossible.
    fn aad(&self) -> Vec<u8> {
        format!(
            "barbacane-quarantaine-v1|{}|{}|{}|{}|{}|{}",
            self.id, self.borne, self.recu_le, self.expire_le, self.sha256, self.taille
        )
        .into_bytes()
    }
    fn aad_cle(&self) -> Vec<u8> {
        format!("barbacane-quarantaine-cle-v1|{}", self.id).into_bytes()
    }
}

/// État affiché par l'interface.
#[derive(Debug, Clone)]
pub struct Statut {
    pub active: bool,
    /// Raison de la désactivation (`None` si active).
    pub raison: Option<String>,
    /// Le dossier d'homologation autorise-t-il l'activation ?
    pub autorisee: bool,
    pub demandes: Vec<Demande>,
}

fn id_valide(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Résultat d'une seconde validation.
#[derive(Debug)]
pub enum Validation {
    Activee,
    /// Export : contenu en clair et métadonnées (à restituer sans aperçu).
    Export(Element, Vec<u8>),
}

pub struct Quarantaine {
    dossier: PathBuf,
    homologation: PathBuf,
    stockage: Stockage,
}

impl Quarantaine {
    /// Dossier `quarantaine/` du registre (0700), `elements/` dedans.
    pub fn ouvrir(stockage: &Stockage) -> Result<Quarantaine> {
        let homologation = chemin_homologation(stockage)?;
        let dossier = stockage.dossier().join("quarantaine");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dossier.join("elements"))
            .context("dossier de quarantaine")?;
        Ok(Quarantaine {
            dossier,
            homologation,
            stockage: stockage.clone(),
        })
    }

    fn auditer(&self, acteur: &str, action: &str, element: &str) -> Result<()> {
        self.stockage.auditer(
            acteur,
            Evenement::Quarantaine {
                action: action.into(),
                element: element.into(),
            },
        )
    }

    fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("verrou"))
            .context("verrou de quarantaine")?;
        f.lock().context("verrou de quarantaine")?;
        Ok(f)
    }

    fn lire_etat(&self) -> Result<Etat> {
        match std::fs::read(self.dossier.join("etat.json")) {
            Ok(o) => serde_json::from_slice(&o).context("etat.json de quarantaine illisible"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Etat::default()),
            Err(e) => Err(e).context("état de quarantaine"),
        }
    }

    fn ecrire_etat(&self, e: &Etat) -> Result<()> {
        ecrire_atomique(
            &self.dossier.join("etat.json"),
            &serde_json::to_vec_pretty(e)?,
        )
    }

    fn cle(&self) -> Result<CleFichier> {
        CleFichier::ouvrir_ou_creer(&self.dossier.join("cle-quarantaine"))
    }

    /// Active = activée par double validation ET dossier d'homologation à « en place ».
    pub fn statut(&self, t: u64) -> Result<Statut> {
        let mut etat = self.lire_etat()?;
        etat.demandes.retain(|d| d.le + DUREE_DEMANDE_S > t);
        let m = mesures_dr(&self.homologation);
        let raison = match (&m, etat.active) {
            (Err(r), _) => Some(format!("Verrou d'homologation : {r}.")),
            (Ok(()), false) => Some(
                "Non activée : l'activation exige deux administrateurs distincts (demande puis validation).".into(),
            ),
            (Ok(()), true) => None,
        };
        Ok(Statut {
            active: raison.is_none(),
            raison,
            autorisee: m.is_ok(),
            demandes: etat.demandes,
        })
    }

    pub fn active(&self) -> bool {
        self.statut(crate::outils::maintenant())
            .is_ok_and(|s| s.active)
    }

    fn nouvelle_demande(
        &self,
        etat: &mut Etat,
        action: Action,
        par: &str,
        t: u64,
    ) -> Result<String> {
        etat.demandes.retain(|d| d.le + DUREE_DEMANDE_S > t);
        if etat.demandes.len() >= DEMANDES_MAX {
            bail!("trop de demandes en attente");
        }
        let id = hex::encode(aleatoire::<16>());
        etat.demandes.push(Demande {
            id: id.clone(),
            action,
            par: par.into(),
            le: t,
        });
        Ok(id)
    }

    /// Premier temps de l'activation : refusée (et auditée) si le dossier d'homologation ne
    /// porte pas [`LIGNE_EN_PLACE`].
    pub fn demander_activation(&self, acteur: &str, t: u64) -> Result<String> {
        let _v = self.verrou()?;
        if let Err(r) = mesures_dr(&self.homologation) {
            self.auditer(acteur, "activation-refusee", "-")?;
            bail!("activation refusée : {r}");
        }
        let mut etat = self.lire_etat()?;
        if etat.active {
            bail!("quarantaine déjà active");
        }
        let id = self.nouvelle_demande(&mut etat, Action::Activation, acteur, t)?;
        self.auditer(acteur, "activation-demandee", &id)?;
        self.ecrire_etat(&etat)?;
        Ok(id)
    }

    /// Premier temps de l'export d'un élément (quarantaine active seulement).
    pub fn demander_export(&self, element: &str, acteur: &str, t: u64) -> Result<String> {
        let _v = self.verrou()?;
        if !self.statut(t)?.active {
            self.auditer(acteur, "export-refuse", "-")?;
            bail!("export refusé : quarantaine désactivée");
        }
        self.metadonnees(element)?;
        let mut etat = self.lire_etat()?;
        let id = self.nouvelle_demande(
            &mut etat,
            Action::Export {
                element: element.into(),
            },
            acteur,
            t,
        )?;
        self.auditer(acteur, "export-demande", &id)?;
        self.ecrire_etat(&etat)?;
        Ok(id)
    }

    /// Second temps : un administrateur DISTINCT du demandeur valide. Refus audités.
    pub fn valider(&self, demande: &str, acteur: &str, t: u64) -> Result<Validation> {
        let _v = self.verrou()?;
        let mut etat = self.lire_etat()?;
        etat.demandes.retain(|d| d.le + DUREE_DEMANDE_S > t);
        let Some(i) = etat.demandes.iter().position(|d| d.id == demande) else {
            self.auditer(acteur, "validation-refusee", "-")?;
            bail!("demande inconnue ou expirée");
        };
        let d = etat.demandes[i].clone();
        if d.par == acteur {
            self.auditer(acteur, "validation-refusee", &d.id)?;
            bail!(
                "double validation : la demande doit être validée par un second administrateur, distinct du demandeur"
            );
        }
        if let Err(r) = mesures_dr(&self.homologation) {
            self.auditer(acteur, "validation-refusee", &d.id)?;
            bail!("refusé : {r}");
        }
        etat.demandes.remove(i);
        let v = match &d.action {
            Action::Activation => {
                etat.active = true;
                self.auditer(acteur, "activation-validee", &d.id)?;
                Validation::Activee
            }
            Action::Export { element } => {
                if !etat.active {
                    bail!("export refusé : quarantaine désactivée");
                }
                let (e, clair) = self.dechiffrer(element, acteur)?;
                self.auditer(acteur, "export-valide", element)?;
                Validation::Export(e, clair)
            }
        };
        self.ecrire_etat(&etat)?;
        Ok(v)
    }

    /// Désactivation : un seul administrateur suffit (sens sûr). Les éléments restent
    /// chiffrés jusqu'à leur purge.
    pub fn desactiver(&self, acteur: &str) -> Result<()> {
        let _v = self.verrou()?;
        let mut etat = self.lire_etat()?;
        etat.active = false;
        etat.demandes.clear();
        self.auditer(acteur, "desactivation", "-")?;
        self.ecrire_etat(&etat)
    }

    fn chemins(&self, id: &str) -> (PathBuf, PathBuf) {
        let e = self.dossier.join("elements");
        (e.join(format!("{id}.json")), e.join(format!("{id}.bin")))
    }

    pub fn metadonnees(&self, id: &str) -> Result<Element> {
        if !id_valide(id) {
            bail!("identifiant d'élément invalide");
        }
        let (m, _) = self.chemins(id);
        let o = std::fs::read(&m).context("élément inconnu")?;
        let e: Element = serde_json::from_slice(&o).context("métadonnées illisibles")?;
        if e.id != id {
            bail!("métadonnées incohérentes");
        }
        Ok(e)
    }

    /// Lecture vérifiée (clé enveloppée, AES-GCM avec métadonnées, puis SHA-256). Toute
    /// altération est auditée (`alteration-detectee`).
    fn dechiffrer(&self, id: &str, acteur: &str) -> Result<(Element, Vec<u8>)> {
        let r = (|| -> Result<(Element, Vec<u8>)> {
            let e = self.metadonnees(id)?;
            let (_, b) = self.chemins(id);
            let env = hex::decode(&e.cle_enveloppee).context("clé enveloppée")?;
            let cle = self.cle()?.desenvelopper(&e.aad_cle(), &env)?;
            let clair = ouvrir(
                &cle,
                &e.aad(),
                &std::fs::read(&b).context("contenu absent")?,
            )?;
            if clair.len() as u64 != e.taille || sha256_hex(&clair) != e.sha256 {
                bail!("empreinte du contenu en défaut");
            }
            Ok((e, clair))
        })();
        if let Err(err) = &r {
            let el = if id_valide(id) { id } else { "-" };
            self.auditer(acteur, "alteration-detectee", el)?;
            bail!("élément {el} : intégrité en défaut ({err:#})");
        }
        r
    }

    /// Trace d'un dépôt refusé avant lecture du corps (quarantaine désactivée).
    pub fn refuser_reception(&self, acteur: &str, borne: &str) -> Result<()> {
        let b = if barbacane_audit::ident_valide(borne) {
            borne
        } else {
            "-"
        };
        self.auditer(acteur, "reception-refusee", b)
    }

    /// Dépôt d'une borne authentifiée : refusé (audité) si la quarantaine n'est pas active.
    pub fn recevoir(
        &self,
        borne: &str,
        d: &DepotQuarantaine,
        acteur: &str,
        t: u64,
    ) -> Result<Element> {
        if !self.statut(t)?.active {
            self.auditer(acteur, "reception-refusee", borne)?;
            return Err(Refus(CodeErreur::QuarantaineDesactivee).into());
        }
        let clair = data_encoding::BASE64
            .decode(d.contenu_b64.as_bytes())
            .map_err(|_| Refus(CodeErreur::RequeteInvalide))?;
        if clair.len() > TAILLE_FICHIER_MAX
            || clair.len() as u64 != d.taille
            || sha256_hex(&clair) != d.sha256
        {
            return Err(Refus(CodeErreur::RequeteInvalide).into());
        }
        self.purger(t)?;
        let mut e = Element {
            id: hex::encode(aleatoire::<16>()),
            borne: borne.into(),
            recu_le: t,
            expire_le: t + CONSERVATION_J * 86400,
            sha256: d.sha256.clone(),
            taille: d.taille,
            cle_enveloppee: String::new(),
        };
        let cle = aleatoire::<32>();
        let scelle = sceller(&cle, &e.aad(), &clair)?;
        e.cle_enveloppee = hex::encode(self.cle()?.envelopper(&e.aad_cle(), &cle)?);
        let (m, b) = self.chemins(&e.id);
        ecrire_atomique(&b, &scelle)?;
        ecrire_atomique(&m, &serde_json::to_vec_pretty(&e)?)?;
        self.auditer(acteur, "reception", &e.id)?;
        Ok(e)
    }

    /// Éléments présents (métadonnées seules, aucun déchiffrement), purge faite.
    pub fn elements(&self, t: u64) -> Result<Vec<Element>> {
        self.purger(t)?;
        let mut v = Vec::new();
        for f in std::fs::read_dir(self.dossier.join("elements"))? {
            let n = f?.file_name().to_string_lossy().into_owned();
            if let Some(id) = n.strip_suffix(".json")
                && let Ok(e) = self.metadonnees(id)
            {
                v.push(e);
            }
        }
        v.sort_by_key(|e| e.recu_le);
        Ok(v)
    }

    /// Supprime les éléments arrivés à échéance (date de réception + [`CONSERVATION_J`], quelle
    /// que soit la date inscrite). Renvoie leur nombre.
    pub fn purger(&self, t: u64) -> Result<usize> {
        let mut n = 0;
        for f in std::fs::read_dir(self.dossier.join("elements"))? {
            let nom = f?.file_name().to_string_lossy().into_owned();
            let Some(id) = nom.strip_suffix(".json") else {
                continue;
            };
            let Ok(e) = self.metadonnees(id) else {
                continue;
            };
            if e.expire_le.min(e.recu_le + CONSERVATION_J * 86400) <= t {
                let (m, b) = self.chemins(id);
                let _ = std::fs::remove_file(&b);
                std::fs::remove_file(&m)?;
                self.auditer("quarantaine", "purge", id)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barbacane_protocole::VERSION;

    struct Banc {
        _d: tempfile::TempDir,
        dossier: PathBuf,
        q: Quarantaine,
        stockage: Stockage,
    }

    fn banc(ligne: &str) -> Banc {
        let d = tempfile::tempdir().unwrap();
        let dossier = d.path().join("dossier-homologation.md");
        std::fs::write(
            &dossier,
            format!("# Dossier\n\n{ligne}\n\n## 9. Décision\n"),
        )
        .unwrap();
        let stockage = Stockage::ouvrir(&d.path().join("etat")).unwrap();
        std::fs::write(
            d.path().join("etat/quarantaine.conf"),
            format!("dossier_homologation = {}\n", dossier.display()),
        )
        .unwrap();
        let q = Quarantaine::ouvrir(&stockage).unwrap();
        Banc {
            _d: d,
            dossier,
            q,
            stockage,
        }
    }

    fn depot(contenu: &[u8]) -> DepotQuarantaine {
        DepotQuarantaine {
            version: VERSION,
            sha256: sha256_hex(contenu),
            taille: contenu.len() as u64,
            contenu_b64: data_encoding::BASE64.encode(contenu),
        }
    }

    fn actions(s: &Stockage) -> Vec<String> {
        let c = s.journal_audit().lire().unwrap();
        c.split(|o| *o == b'\n')
            .filter(|l| !l.is_empty())
            .filter_map(
                |l| match barbacane_audit::Enregistrement::analyser(l).ok()?.evenement {
                    Evenement::Quarantaine { action, .. } => Some(action),
                    _ => None,
                },
            )
            .collect()
    }

    fn activer(b: &Banc) {
        let id = b.q.demander_activation("web:alice", 100).unwrap();
        assert!(matches!(
            b.q.valider(&id, "web:carole", 101).unwrap(),
            Validation::Activee
        ));
    }

    #[test]
    fn ligne_exacte_exigee() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("d.md");
        for (texte, ok) in [
            ("mesures_dr_serveur: non\n", false),
            ("mesures_dr_serveur: en place\n", true),
            ("mesures_dr_serveur: en place\r\n", true),
            ("mesures_dr_serveur: en place \n", false),
            ("mesures_dr_serveur:en place\n", false),
            ("  mesures_dr_serveur: en place\n", false),
            (
                "mesures_dr_serveur: en place\nmesures_dr_serveur: non\n",
                false,
            ),
            ("rien\n", false),
        ] {
            std::fs::write(&p, texte).unwrap();
            assert_eq!(mesures_dr(&p).is_ok(), ok, "{texte:?}");
        }
        assert!(mesures_dr(&d.path().join("absent")).is_err());
        // Le dossier du dépôt reste à « non » : la quarantaine n'est pas activable.
        let depot =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/suite/dossier-homologation.md");
        assert!(
            mesures_dr(&depot)
                .unwrap_err()
                .contains("« mesures_dr_serveur: non »")
        );
    }

    #[test]
    fn activation_refusee_avec_non() {
        let b = banc("mesures_dr_serveur: non");
        let s = b.q.statut(1).unwrap();
        assert!(!s.active && !s.autorisee);
        assert!(s.raison.unwrap().contains("mesures_dr_serveur: non"));
        let e = b.q.demander_activation("web:alice", 1).unwrap_err();
        assert!(format!("{e:#}").contains("activation refusée"));
        assert_eq!(actions(&b.stockage), ["activation-refusee"]);
        assert!(!b.q.active());
    }

    #[test]
    fn activation_acceptee_avec_en_place_et_double_validation() {
        let b = banc("mesures_dr_serveur: en place");
        let id = b.q.demander_activation("web:alice", 100).unwrap();
        assert!(
            !b.q.statut(100).unwrap().active,
            "une seule personne ne suffit pas"
        );
        assert!(
            b.q.valider(&id, "web:alice", 101).is_err(),
            "même administrateur"
        );
        assert!(matches!(
            b.q.valider(&id, "web:carole", 102).unwrap(),
            Validation::Activee
        ));
        assert!(b.q.statut(103).unwrap().active);
        // Dossier remis à « non » : désactivée aussitôt (verrou relu à chaque opération).
        std::fs::write(&b.dossier, "mesures_dr_serveur: non\n").unwrap();
        assert!(!b.q.statut(104).unwrap().active);
        assert_eq!(
            actions(&b.stockage),
            [
                "activation-demandee",
                "validation-refusee",
                "activation-validee"
            ]
        );
    }

    #[test]
    fn demande_expiree() {
        let b = banc("mesures_dr_serveur: en place");
        let id = b.q.demander_activation("web:alice", 100).unwrap();
        assert!(
            b.q.valider(&id, "web:carole", 100 + DUREE_DEMANDE_S)
                .is_err()
        );
    }

    #[test]
    fn reception_refusee_si_desactivee() {
        let b = banc("mesures_dr_serveur: non");
        let e =
            b.q.recevoir("borne-1", &depot(b"X5O!P%"), "passerelle", 1)
                .unwrap_err();
        assert_eq!(
            crate::registre::code_de(&e),
            CodeErreur::QuarantaineDesactivee
        );
        assert_eq!(
            std::fs::read_dir(b.q.dossier.join("elements"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(actions(&b.stockage), ["reception-refusee"]);
    }

    #[test]
    fn chiffrement_dechiffrement_et_cle_0600() {
        let b = banc("mesures_dr_serveur: en place");
        activer(&b);
        let contenu = b"contenu malveillant de TEST".repeat(100);
        let e =
            b.q.recevoir("borne-1", &depot(&contenu), "passerelle", 200)
                .unwrap();
        let (_, bin) = b.q.chemins(&e.id);
        let brut = std::fs::read(&bin).unwrap();
        assert!(
            !brut.windows(11).any(|w| w == b"malveillant"),
            "stocké chiffré"
        );
        let mode = std::fs::metadata(b.q.dossier.join("cle-quarantaine"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let (_, clair) = b.q.dechiffrer(&e.id, "web:alice").unwrap();
        assert_eq!(clair, contenu);
        // Mauvaise empreinte annoncée : refusée.
        let mut d = depot(b"abc");
        d.sha256 = "0".repeat(64);
        assert!(b.q.recevoir("borne-1", &d, "passerelle", 200).is_err());
    }

    #[test]
    fn alteration_detectee() {
        let b = banc("mesures_dr_serveur: en place");
        activer(&b);
        let e =
            b.q.recevoir("borne-1", &depot(b"fichier de TEST"), "passerelle", 200)
                .unwrap();
        let (m, bin) = b.q.chemins(&e.id);
        // Un octet du chiffré.
        let orig = std::fs::read(&bin).unwrap();
        let mut o = orig.clone();
        o[20] ^= 1;
        std::fs::write(&bin, &o).unwrap();
        assert!(b.q.dechiffrer(&e.id, "web:alice").is_err());
        std::fs::write(&bin, &orig).unwrap();
        // Une métadonnée (prolongation de conservation).
        let mut e2 = e.clone();
        e2.expire_le += 86400;
        std::fs::write(&m, serde_json::to_vec(&e2).unwrap()).unwrap();
        assert!(b.q.dechiffrer(&e.id, "web:alice").is_err());
        std::fs::write(&m, serde_json::to_vec(&e).unwrap()).unwrap();
        assert!(b.q.dechiffrer(&e.id, "web:alice").is_ok());
        assert_eq!(
            actions(&b.stockage)
                .iter()
                .filter(|a| *a == "alteration-detectee")
                .count(),
            2
        );
    }

    #[test]
    fn export_double_validation() {
        let b = banc("mesures_dr_serveur: en place");
        activer(&b);
        let e =
            b.q.recevoir("borne-1", &depot(b"fichier de TEST"), "passerelle", 200)
                .unwrap();
        let d = b.q.demander_export(&e.id, "web:alice", 300).unwrap();
        // Export simple (le demandeur valide lui-même) : refusé.
        assert!(b.q.valider(&d, "web:alice", 301).is_err());
        match b.q.valider(&d, "web:carole", 302).unwrap() {
            Validation::Export(m, c) => {
                assert_eq!(m.id, e.id);
                assert_eq!(c, b"fichier de TEST");
            }
            _ => panic!("export attendu"),
        }
        assert!(
            b.q.valider(&d, "web:carole", 303).is_err(),
            "demande consommée"
        );
        let a = actions(&b.stockage);
        assert!(a.ends_with(&[
            "export-demande".into(),
            "validation-refusee".into(),
            "export-valide".into(),
            "validation-refusee".into()
        ]));
    }

    #[test]
    fn purge_a_echeance() {
        let b = banc("mesures_dr_serveur: en place");
        activer(&b);
        let e =
            b.q.recevoir("borne-1", &depot(b"x"), "passerelle", 1000)
                .unwrap();
        assert_eq!(
            b.q.elements(1000 + CONSERVATION_J * 86400 - 1)
                .unwrap()
                .len(),
            1
        );
        assert!(
            b.q.elements(1000 + CONSERVATION_J * 86400)
                .unwrap()
                .is_empty()
        );
        let (m, bin) = b.q.chemins(&e.id);
        assert!(!m.exists() && !bin.exists());
    }
}
