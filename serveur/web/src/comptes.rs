//! Comptes d'administration de la Console (`docs/suite/comptes-administrateurs.md`).
//!
//! - Rôles distincts et matrice de droits ([`Role::peut`]) ;
//! - mot de passe Argon2id, politique de robustesse ([`politique_mot_de_passe`]), changement
//!   forcé après création ou réinitialisation ;
//! - compte lié à UN certificat client (empreinte SHA-256 du DER) ;
//! - base `<registre>/administrateurs/comptes.json` (0600, verrou, écriture atomique), gérée
//!   dans la Console ; migration sans perte du fichier texte de la v2.1.0 ([`Comptes::migrer`]).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use barbacane_passerelle::outils::{aleatoire, ecrire_atomique};
use serde::{Deserialize, Serialize};

/// Longueur minimale d'un mot de passe.
pub const MOT_DE_PASSE_MIN: usize = 12;
/// Longueur maximale d'un mot de passe (formulaire limité à 256 octets).
pub const MOT_DE_PASSE_MAX: usize = 128;
/// À partir de cette longueur, une phrase de passe n'a pas besoin de 3 classes de caractères.
pub const PHRASE_DE_PASSE_MIN: usize = 20;
/// Échecs admis avant verrouillage.
pub const ECHECS_MAX: u32 = 5;
/// Premier verrouillage (doublé à chaque nouvel échec, 16 fois au plus).
pub const VERROU_S: u64 = 15 * 60;
/// Comptes au plus (quelques administrateurs).
pub const COMPTES_MAX: usize = 64;

/// Rôles de la Console (matrice : [`Role::peut`], `docs/suite/comptes-administrateurs.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Tout, dont les comptes, la quarantaine et la double validation.
    Administrateur,
    /// Exploitation du parc (enrôlement, mises à jour, ISO, utilisateurs, clés, sites).
    Operateur,
    /// Lecture seule de la supervision (ni données personnelles, ni journal).
    Lecture,
    /// Lecture seule, avec le journal d'audit et la liste des comptes (contrôle).
    Auditeur,
}

/// Tous les rôles, du plus au moins privilégié.
pub const ROLES: [Role; 4] = [
    Role::Administrateur,
    Role::Operateur,
    Role::Auditeur,
    Role::Lecture,
];

/// Droits élémentaires d'une route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Droit {
    /// Parc, enrôlement, mises à jour, ISO, sites, clés : consultation.
    Consulter,
    /// Utilisateurs et rapports de passage (données personnelles).
    ConsulterPersonnel,
    /// Journal d'audit et sa vérification.
    ConsulterJournal,
    /// Liste des comptes et des demandes de double validation.
    ConsulterComptes,
    /// Actions d'exploitation du parc.
    Exploiter,
    /// Comptes, double validation, quarantaine, révocation d'un site.
    Administrer,
}

impl Role {
    pub fn analyser(s: &str) -> Option<Role> {
        ROLES.into_iter().find(|r| r.nom() == s)
    }

    pub fn nom(self) -> &'static str {
        match self {
            Role::Administrateur => "administrateur",
            Role::Operateur => "operateur",
            Role::Lecture => "lecture",
            Role::Auditeur => "auditeur",
        }
    }

    pub fn libelle(self) -> &'static str {
        match self {
            Role::Administrateur => "Administrateur",
            Role::Operateur => "Opérateur",
            Role::Lecture => "Lecture seule",
            Role::Auditeur => "Auditeur (lecture seule)",
        }
    }

    /// Matrice des droits (refus par défaut).
    pub fn peut(self, d: Droit) -> bool {
        use Droit::*;
        match self {
            Role::Administrateur => true,
            Role::Operateur => matches!(d, Consulter | ConsulterPersonnel | Exploiter),
            Role::Auditeur => matches!(
                d,
                Consulter | ConsulterPersonnel | ConsulterJournal | ConsulterComptes
            ),
            Role::Lecture => matches!(d, Consulter),
        }
    }
}

/// Identifiant de compte : `[a-z0-9._-]`, 1 à 32 (compatible avec l'acteur d'audit).
pub fn identifiant_valide(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

pub fn empreinte_certificat(der: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, der))
}

fn empreinte_valide(e: &str) -> bool {
    e.len() == 64 && e.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn hacher(mot_de_passe: &str) -> Result<String> {
    Ok(argon2::Argon2::default()
        .hash_password(mot_de_passe.as_bytes())
        .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))?
        .to_string())
}

fn hachage_valide(h: &str) -> bool {
    h.starts_with("$argon2id$") && PasswordHash::new(h).is_ok()
}

/// Politique de robustesse (ANSSI, recommandations relatives à l'authentification) :
/// 12 à 128 caractères ; 3 classes parmi minuscules, majuscules, chiffres, autres — ou une
/// phrase de passe d'au moins 20 caractères ; 6 caractères distincts au moins ; ne contient
/// pas l'identifiant. Le message ne reprend jamais le mot de passe.
pub fn politique_mot_de_passe(mdp: &str, identifiant: &str) -> Result<()> {
    let n = mdp.chars().count();
    if n < MOT_DE_PASSE_MIN {
        bail!("mot de passe trop court ({MOT_DE_PASSE_MIN} caractères au moins)");
    }
    if n > MOT_DE_PASSE_MAX {
        bail!("mot de passe trop long ({MOT_DE_PASSE_MAX} caractères au plus)");
    }
    if mdp.chars().any(char::is_control) {
        bail!("mot de passe : caractères de contrôle refusés");
    }
    let classes = [
        mdp.chars().any(|c| c.is_lowercase()),
        mdp.chars().any(|c| c.is_uppercase()),
        mdp.chars().any(|c| c.is_ascii_digit()),
        mdp.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if classes < 3 && n < PHRASE_DE_PASSE_MIN {
        bail!(
            "mot de passe trop simple : 3 types de caractères parmi minuscules, majuscules, chiffres et autres, ou une phrase de passe de {PHRASE_DE_PASSE_MIN} caractères au moins"
        );
    }
    let mut distincts: Vec<char> = mdp.chars().collect();
    distincts.sort_unstable();
    distincts.dedup();
    if distincts.len() < 6 {
        bail!("mot de passe trop répétitif (6 caractères différents au moins)");
    }
    if identifiant.len() >= 3 && mdp.to_lowercase().contains(identifiant) {
        bail!("le mot de passe ne doit pas contenir l'identifiant");
    }
    Ok(())
}

/// Tire un caractère uniforme dans `alphabet` (rejet des octets biaisés).
pub fn tirer(alphabet: &[u8], n: usize) -> String {
    let limite = 256 - 256 % alphabet.len();
    let mut s = String::with_capacity(n);
    while s.len() < n {
        for o in aleatoire::<32>() {
            if (o as usize) < limite && s.len() < n {
                s.push(alphabet[o as usize % alphabet.len()] as char);
            }
        }
    }
    s
}

/// Mot de passe provisoire : 4 groupes de 5 caractères sans ambiguïté (≈ 113 bits), conforme
/// à la politique. Affiché une seule fois, jamais journalisé.
pub fn mot_de_passe_provisoire() -> String {
    const A: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    loop {
        let brut = tirer(A, 20);
        let m = brut
            .as_bytes()
            .chunks(5)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-");
        if politique_mot_de_passe(&m, "").is_ok() {
            return m;
        }
    }
}

// ───────────────────────────── Format v2.1.0 (texte) ──────────────────────────────────────────

/// Compte du fichier texte de la v2.1.0 (`identifiant rôle empreinte $argon2id$…`).
#[derive(Debug, Clone)]
pub struct CompteAncien {
    pub identifiant: String,
    pub role: Role,
    pub empreinte_certificat: String,
    hachage: String,
}

/// Ligne du fichier des comptes (format v2.1.0, toujours produit par `barbacane-web compte`
/// pour le premier compte de l'installation ; importé au premier démarrage).
pub fn ligne_compte(identifiant: &str, role: Role, cert_der: &[u8], mdp: &str) -> Result<String> {
    if !identifiant_valide(identifiant) {
        bail!("identifiant invalide ([a-z0-9._-], 1 à 32)");
    }
    politique_mot_de_passe(mdp, identifiant)?;
    Ok(format!(
        "{identifiant} {} {} {}",
        role.nom(),
        empreinte_certificat(cert_der),
        hacher(mdp)?
    ))
}

/// Analyse le fichier texte (lignes vides et `#` ignorées).
pub fn analyser_comptes(texte: &str) -> Result<Vec<CompteAncien>> {
    let mut comptes: Vec<CompteAncien> = Vec::new();
    for (n, ligne) in texte.lines().enumerate() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        let champs: Vec<&str> = ligne.split_ascii_whitespace().collect();
        let [id, role, empreinte, hachage] = champs[..] else {
            bail!("comptes, ligne {} : 4 champs attendus", n + 1);
        };
        let role =
            Role::analyser(role).with_context(|| format!("comptes, ligne {} : rôle", n + 1))?;
        if !identifiant_valide(id) || !empreinte_valide(empreinte) || !hachage_valide(hachage) {
            bail!("comptes, ligne {} : champ invalide", n + 1);
        }
        if comptes
            .iter()
            .any(|c| c.identifiant == id || c.empreinte_certificat == empreinte)
        {
            bail!(
                "comptes, ligne {} : identifiant ou certificat répété",
                n + 1
            );
        }
        comptes.push(CompteAncien {
            identifiant: id.into(),
            role,
            empreinte_certificat: empreinte.into(),
            hachage: hachage.into(),
        });
    }
    Ok(comptes)
}

fn droits_0600(chemin: &Path) -> Result<()> {
    let meta = std::fs::metadata(chemin)
        .with_context(|| format!("fichier des comptes {}", chemin.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} : accessible à d'autres comptes (0600 attendu)",
            chemin.display()
        );
    }
    Ok(())
}

/// Lit le fichier texte v2.1.0 ; refusé s'il est accessible à d'autres comptes que le service.
pub fn lire_comptes(chemin: &Path) -> Result<Vec<CompteAncien>> {
    droits_0600(chemin)?;
    analyser_comptes(&std::fs::read_to_string(chemin)?)
}

// ───────────────────────────── Base des comptes (v2.2.0) ──────────────────────────────────────

/// Compte de la Console.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compte {
    /// Numéro unique, jamais réutilisé (distingue un compte recréé sous le même identifiant).
    pub numero: u64,
    pub identifiant: String,
    pub role: Role,
    /// Faux : compte désactivé (aucune connexion).
    pub actif: bool,
    /// SHA-256 du certificat client DER lié ; `None` : certificat révoqué ou pas encore émis.
    pub empreinte_certificat: Option<String>,
    /// Numéro de série (hexadécimal normalisé) du certificat lié, s'il est connu.
    pub serie_certificat: Option<String>,
    pub certificat_expire_le: Option<u64>,
    hachage: String,
    /// Vrai après création ou réinitialisation : seul le changement de mot de passe est permis.
    pub changer_mot_de_passe: bool,
    pub cree_le: u64,
    /// Acteur d'audit de la création (`migration-2.1.0` pour un compte importé).
    pub cree_par: String,
    /// Dernière connexion réussie.
    pub dernier_acces: Option<u64>,
    pub mot_de_passe_change_le: Option<u64>,
    /// Acteur qui a reçu le `.p12` en cours (séparation des remises : il ne peut pas recevoir
    /// aussi un mot de passe provisoire de ce compte).
    #[serde(default)]
    pub certificat_remis_a: Option<String>,
    /// Acteur qui connaît le mot de passe PROVISOIRE en cours (effacé quand le titulaire choisit
    /// le sien) : il ne peut pas recevoir aussi le certificat de ce compte.
    #[serde(default)]
    pub mot_de_passe_remis_a: Option<String>,
}

impl Compte {
    /// Administrateur actif avec un certificat lié : peut se connecter et valider.
    pub fn administrateur_utilisable(&self) -> bool {
        self.actif && self.role == Role::Administrateur && self.empreinte_certificat.is_some()
    }

    pub fn verifier(&self, mdp: &str) -> bool {
        verifier_mot_de_passe(Some(self), mdp)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseComptes {
    pub version: u32,
    pub prochain_numero: u64,
    pub comptes: Vec<Compte>,
    /// Vrai dès qu'un second administrateur a existé : l'amorçage (création seule du second
    /// administrateur) n'est plus jamais possible, sauf `barbacane-web reamorcer` (console locale).
    #[serde(default)]
    pub second_administrateur_cree: bool,
}

impl Default for BaseComptes {
    fn default() -> Self {
        BaseComptes {
            version: 2,
            prochain_numero: 1,
            comptes: Vec::new(),
            second_administrateur_cree: false,
        }
    }
}

impl BaseComptes {
    pub fn compte(&self, identifiant: &str) -> Option<&Compte> {
        self.comptes.iter().find(|c| c.identifiant == identifiant)
    }

    pub fn compte_mut(&mut self, identifiant: &str) -> Option<&mut Compte> {
        self.comptes
            .iter_mut()
            .find(|c| c.identifiant == identifiant)
    }

    /// Compte lié à ce certificat.
    pub fn par_certificat(&self, empreinte: &str) -> Option<&Compte> {
        self.comptes
            .iter()
            .find(|c| c.empreinte_certificat.as_deref() == Some(empreinte))
    }

    /// Administrateurs utilisables autres que `sauf`.
    pub fn administrateurs_utilisables_sauf(&self, sauf: &str) -> usize {
        self.comptes
            .iter()
            .filter(|c| c.identifiant != sauf && c.administrateur_utilisable())
            .count()
    }

    /// Garde-fou : après l'opération sur `cible`, il doit rester au moins un administrateur
    /// utilisable (donc jamais le dernier, ni soi-même sans un second).
    pub fn garder_un_administrateur(&self, cible: &str) -> Result<()> {
        let c = self.compte(cible).context("compte inconnu")?;
        if c.administrateur_utilisable() && self.administrateurs_utilisables_sauf(cible) == 0 {
            bail!(
                "refusé : {cible} est le dernier administrateur utilisable (il en faut toujours un ; créez d'abord un second administrateur)"
            );
        }
        Ok(())
    }

    fn valider(&self) -> Result<()> {
        if self.version != 2 {
            bail!("version de la base des comptes non gérée");
        }
        if self.comptes.len() > COMPTES_MAX {
            bail!("trop de comptes");
        }
        for (i, c) in self.comptes.iter().enumerate() {
            if !identifiant_valide(&c.identifiant)
                || !hachage_valide(&c.hachage)
                || c.numero == 0
                || c.numero >= self.prochain_numero
                || c.empreinte_certificat
                    .as_deref()
                    .is_some_and(|e| !empreinte_valide(e))
            {
                bail!("base des comptes : compte {} invalide", c.identifiant);
            }
            if self.comptes[..i].iter().any(|d| {
                d.identifiant == c.identifiant
                    || d.numero == c.numero
                    || (d.empreinte_certificat.is_some()
                        && d.empreinte_certificat == c.empreinte_certificat)
            }) {
                bail!("base des comptes : identifiant, numéro ou certificat répété");
            }
        }
        Ok(())
    }

    /// Amorçage permis : un seul administrateur utilisable et jamais de second auparavant.
    pub fn amorcage_possible(&self) -> bool {
        !self.second_administrateur_cree && self.administrateurs_utilisables_sauf("") == 1
    }

    /// Ajoute un compte (mot de passe provisoire, changement forcé, remis à `par`). Renvoie son
    /// numéro.
    pub fn ajouter(
        &mut self,
        identifiant: &str,
        role: Role,
        mdp_provisoire: &str,
        par: &str,
        t: u64,
    ) -> Result<u64> {
        if !identifiant_valide(identifiant) {
            bail!("identifiant invalide ([a-z0-9._-], 1 à 32)");
        }
        if self.compte(identifiant).is_some() {
            bail!("identifiant déjà utilisé");
        }
        if self.comptes.len() >= COMPTES_MAX {
            bail!("trop de comptes ({COMPTES_MAX} au plus)");
        }
        let numero = self.prochain_numero;
        self.prochain_numero += 1;
        self.comptes.push(Compte {
            numero,
            identifiant: identifiant.into(),
            role,
            actif: true,
            empreinte_certificat: None,
            serie_certificat: None,
            certificat_expire_le: None,
            hachage: hacher(mdp_provisoire)?,
            changer_mot_de_passe: true,
            cree_le: t,
            cree_par: par.into(),
            dernier_acces: None,
            mot_de_passe_change_le: None,
            certificat_remis_a: None,
            mot_de_passe_remis_a: Some(par.into()),
        });
        if role == Role::Administrateur {
            self.second_administrateur_cree = true;
        }
        Ok(numero)
    }

    /// Nouveau mot de passe ; `provisoire` : changement forcé à la prochaine connexion.
    pub fn definir_mot_de_passe(
        &mut self,
        identifiant: &str,
        mdp: &str,
        provisoire: bool,
        t: u64,
    ) -> Result<()> {
        politique_mot_de_passe(mdp, identifiant)?;
        let c = self.compte_mut(identifiant).context("compte inconnu")?;
        if !provisoire && c.verifier(mdp) {
            bail!("le nouveau mot de passe doit être différent de l'actuel");
        }
        c.hachage = hacher(mdp)?;
        c.changer_mot_de_passe = provisoire;
        c.mot_de_passe_change_le = Some(t);
        if !provisoire {
            c.mot_de_passe_remis_a = None;
        }
        Ok(())
    }
}

/// Base `<registre>/administrateurs/` : comptes, demandes de double validation, CRL gérée.
#[derive(Debug, Clone)]
pub struct Comptes {
    dossier: PathBuf,
}

impl Comptes {
    /// Dossier `administrateurs/` du registre (0700).
    pub fn ouvrir(registre: &Path) -> Result<Comptes> {
        let dossier = registre.join("administrateurs");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dossier)
            .with_context(|| format!("dossier {}", dossier.display()))?;
        Ok(Comptes { dossier })
    }

    pub fn dossier(&self) -> &Path {
        &self.dossier
    }

    pub fn fichier(&self) -> PathBuf {
        self.dossier.join("comptes.json")
    }

    pub fn existe(&self) -> bool {
        self.fichier().exists()
    }

    /// Verrou exclusif de la base (comptes et demandes de double validation).
    pub fn verrou(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dossier.join("verrou"))
            .context("verrou des comptes")?;
        f.lock().context("verrou des comptes")?;
        Ok(f)
    }

    pub(crate) fn lire_sans_verrou(&self) -> Result<BaseComptes> {
        let f = self.fichier();
        match std::fs::read(&f) {
            Ok(o) => {
                droits_0600(&f)?;
                let b: BaseComptes =
                    serde_json::from_slice(&o).context("comptes.json illisible")?;
                b.valider()?;
                Ok(b)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("base des comptes absente ({})", f.display())
            }
            Err(e) => Err(e).context("lecture des comptes"),
        }
    }

    pub fn lire(&self) -> Result<BaseComptes> {
        let _v = self.verrou()?;
        self.lire_sans_verrou()
    }

    pub(crate) fn ecrire(&self, b: &BaseComptes) -> Result<()> {
        b.valider()?;
        ecrire_atomique(&self.fichier(), &serde_json::to_vec_pretty(b)?)
    }

    /// Transaction : verrou, lecture, modification, écriture atomique ; rien n'est écrit si
    /// `f` échoue. `f` doit auditer DANS la transaction (aucune action sans trace).
    pub fn transaction<T>(&self, f: impl FnOnce(&mut BaseComptes) -> Result<T>) -> Result<T> {
        let _v = self.verrou()?;
        let mut b = self.lire_sans_verrou()?;
        let r = f(&mut b)?;
        self.ecrire(&b)?;
        Ok(r)
    }

    /// Migration depuis la v2.1.0 : si la base n'existe pas, importe SANS PERTE le fichier
    /// texte `ancien` (identifiant, rôle, certificat, hachage Argon2id inchangés ; pas de
    /// changement de mot de passe imposé). `auditer` est appelé avant l'écriture. Renvoie le
    /// nombre de comptes importés (`None` : base déjà présente, rien n'est fait).
    pub fn migrer(
        &self,
        ancien: &Path,
        t: u64,
        auditer: impl FnOnce(usize) -> Result<()>,
    ) -> Result<Option<usize>> {
        let _v = self.verrou()?;
        if self.existe() {
            return Ok(None);
        }
        let anciens = lire_comptes(ancien)?;
        let b = depuis_anciens(&anciens, t);
        auditer(anciens.len())?;
        self.ecrire(&b)?;
        Ok(Some(anciens.len()))
    }
}

/// Conversion v2.1.0 → v2.2.0 (fonction pure, testée).
pub fn depuis_anciens(anciens: &[CompteAncien], t: u64) -> BaseComptes {
    let mut b = BaseComptes::default();
    for a in anciens {
        b.comptes.push(Compte {
            numero: b.prochain_numero,
            identifiant: a.identifiant.clone(),
            role: a.role,
            actif: true,
            empreinte_certificat: Some(a.empreinte_certificat.clone()),
            serie_certificat: None,
            certificat_expire_le: None,
            hachage: a.hachage.clone(),
            changer_mot_de_passe: false,
            cree_le: t,
            cree_par: "migration-2.1.0".into(),
            dernier_acces: None,
            mot_de_passe_change_le: None,
            certificat_remis_a: None,
            mot_de_passe_remis_a: None,
        });
        b.prochain_numero += 1;
    }
    b.second_administrateur_cree = anciens
        .iter()
        .filter(|a| a.role == Role::Administrateur)
        .count()
        >= 2;
    b
}

/// Une seule vérification Argon2 à la fois : mémoire bornée (19 Mio) même sous attaque.
static ARGON2: Mutex<()> = Mutex::new(());

/// Vérifie un mot de passe ; `None` (compte inconnu) vérifie contre un hachage factice pour
/// un temps de réponse identique.
pub fn verifier_mot_de_passe(compte: Option<&Compte>, mdp: &str) -> bool {
    static FACTICE: OnceLock<String> = OnceLock::new();
    let factice =
        FACTICE.get_or_init(|| hacher(&hex::encode(aleatoire::<16>())).unwrap_or_default());
    let hachage = compte.map(|c| c.hachage.as_str()).unwrap_or(factice);
    let _un_seul = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
    let ok = PasswordHash::new(hachage)
        .map(|h| {
            argon2::Argon2::default()
                .verify_password(mdp.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false);
    ok && compte.is_some()
}

/// Échecs de connexion par clé (`compte:<id>` ou `cert:<empreinte>`), en mémoire.
#[derive(Default)]
pub struct Verrous {
    echecs: Mutex<HashMap<String, (u32, u64)>>,
}

impl Verrous {
    /// Vrai si l'une des clés est verrouillée à l'instant `t`.
    pub fn verrouille(&self, cles: &[String], t: u64) -> bool {
        let m = self.echecs.lock().unwrap_or_else(|e| e.into_inner());
        cles.iter()
            .any(|k| m.get(k).is_some_and(|(_, jusqua)| *jusqua > t))
    }

    pub fn echec(&self, cles: &[String], t: u64) {
        let mut m = self.echecs.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 10_000 {
            m.retain(|_, (_, jusqua)| *jusqua > t);
        }
        for k in cles {
            let e = m.entry(k.clone()).or_insert((0, 0));
            e.0 += 1;
            if e.0 >= ECHECS_MAX {
                e.1 = t + (VERROU_S << (e.0 - ECHECS_MAX).min(4));
            }
        }
    }

    pub fn succes(&self, cles: &[String]) {
        let mut m = self.echecs.lock().unwrap_or_else(|e| e.into_inner());
        for k in cles {
            m.remove(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDP: &str = "un mot de passe long";

    #[test]
    fn ligne_aller_retour_et_migration_sans_perte() {
        let l = ligne_compte("alice", Role::Auditeur, b"cert", MDP).unwrap();
        let a = analyser_comptes(&format!("# commentaire\n{l}\n")).unwrap();
        assert_eq!(a[0].role, Role::Auditeur);
        let b = depuis_anciens(&a, 7);
        b.valider().unwrap();
        let c = &b.comptes[0];
        assert_eq!(c.identifiant, "alice");
        assert_eq!(c.role, Role::Auditeur);
        assert_eq!(
            c.empreinte_certificat.as_deref(),
            Some(empreinte_certificat(b"cert").as_str())
        );
        assert_eq!(c.hachage, a[0].hachage, "hachage repris tel quel");
        assert!(c.actif && !c.changer_mot_de_passe);
        assert!(c.verifier(MDP));
        assert!(!c.verifier("un mot de passe lonG"));
        assert!(!verifier_mot_de_passe(None, MDP));
        assert!(ligne_compte("alice", Role::Auditeur, b"c", "court").is_err());
        assert!(ligne_compte("Alice B", Role::Auditeur, b"c", MDP).is_err());
        assert!(analyser_comptes(&format!("{l}\n{l}\n")).is_err());
        assert!(analyser_comptes("alice root 00 $argon2id$x").is_err());
    }

    #[test]
    fn politique() {
        for bon in [
            "Abcdefgh1234",
            "un mot de passe long",
            "abc-def-ghi-12",
            &mot_de_passe_provisoire(),
        ] {
            assert!(politique_mot_de_passe(bon, "alice").is_ok(), "{bon}");
        }
        for mauvais in [
            "Abc1234",            // court
            "abcdefghijkl",       // une classe
            "abcdefgh1234",       // deux classes, < 20
            "aaaaaaAAAAAA111111", // 3 classes mais répétitif
            "Alice-Est-La-2026",  // contient l'identifiant
            &"Ab1-".repeat(40),   // trop long
            "Abcdefgh123\u{7}",   // contrôle
        ] {
            assert!(
                politique_mot_de_passe(mauvais, "alice").is_err(),
                "{mauvais}"
            );
        }
        let a = mot_de_passe_provisoire();
        assert_eq!(a.len(), 23);
        assert_ne!(a, mot_de_passe_provisoire());
    }

    #[test]
    fn matrice_des_droits() {
        use Droit::*;
        let tous = [
            Consulter,
            ConsulterPersonnel,
            ConsulterJournal,
            ConsulterComptes,
            Exploiter,
            Administrer,
        ];
        assert!(tous.iter().all(|d| Role::Administrateur.peut(*d)));
        assert!(!Role::Operateur.peut(Administrer) && !Role::Operateur.peut(ConsulterJournal));
        assert!(Role::Operateur.peut(Exploiter));
        assert!(!Role::Auditeur.peut(Exploiter) && !Role::Auditeur.peut(Administrer));
        assert!(Role::Auditeur.peut(ConsulterJournal) && Role::Auditeur.peut(ConsulterComptes));
        assert_eq!(
            tous.iter().filter(|d| Role::Lecture.peut(**d)).count(),
            1,
            "lecture seule : consultation du parc seulement"
        );
        for r in ROLES {
            assert_eq!(Role::analyser(r.nom()), Some(r));
        }
        assert_eq!(Role::analyser("root"), None);
    }

    #[test]
    fn base_garde_fous_et_fichier() {
        let d = tempfile::tempdir().unwrap();
        let ancien = d.path().join("comptes");
        let l = ligne_compte("admin-01", Role::Administrateur, b"c1", MDP).unwrap();
        std::fs::write(&ancien, format!("{l}\n")).unwrap();
        std::fs::set_permissions(&ancien, std::fs::Permissions::from_mode(0o644)).unwrap();
        let c = Comptes::ouvrir(d.path()).unwrap();
        assert!(c.migrer(&ancien, 1, |_| Ok(())).is_err(), "0644 refusé");
        std::fs::set_permissions(&ancien, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(c.migrer(&ancien, 1, |_| bail!("audit")).is_err());
        assert!(!c.existe(), "rien d'écrit sans audit");
        assert_eq!(
            c.migrer(&ancien, 1, |n| {
                assert_eq!(n, 1);
                Ok(())
            })
            .unwrap(),
            Some(1)
        );
        assert_eq!(
            c.migrer(&ancien, 2, |_| Ok(())).unwrap(),
            None,
            "une seule fois"
        );
        let mode = std::fs::metadata(c.fichier()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Dernier administrateur : ni désactivation, ni rétrogradation.
        let b = c.lire().unwrap();
        assert!(b.garder_un_administrateur("admin-01").is_err());
        c.transaction(|b| {
            let n = b.ajouter("admin-02", Role::Administrateur, MDP, "web:admin-01", 3)?;
            assert_eq!(n, 2);
            assert!(b.ajouter("admin-02", Role::Lecture, MDP, "x", 3).is_err());
            Ok(())
        })
        .unwrap();
        let b = c.lire().unwrap();
        assert!(
            b.garder_un_administrateur("admin-01").is_err(),
            "admin-02 sans certificat n'est pas utilisable"
        );
        c.transaction(|b| {
            b.compte_mut("admin-02").unwrap().empreinte_certificat =
                Some(empreinte_certificat(b"c2"));
            Ok(())
        })
        .unwrap();
        let b = c.lire().unwrap();
        assert!(b.garder_un_administrateur("admin-01").is_ok());
        assert!(b.compte("admin-02").unwrap().changer_mot_de_passe);
        // Échec dans la transaction : rien n'est écrit.
        let r: Result<()> = c.transaction(|b| {
            b.comptes.clear();
            bail!("non")
        });
        assert!(r.is_err());
        assert_eq!(c.lire().unwrap().comptes.len(), 2);
        // Changement de mot de passe : politique, différent de l'actuel.
        c.transaction(|b| {
            assert!(
                b.definir_mot_de_passe("admin-02", "court", false, 4)
                    .is_err()
            );
            assert!(b.definir_mot_de_passe("admin-02", MDP, false, 4).is_err());
            b.definir_mot_de_passe("admin-02", "Nouveau-mot-2026", false, 4)
        })
        .unwrap();
        let b = c.lire().unwrap();
        assert!(!b.compte("admin-02").unwrap().changer_mot_de_passe);
        assert!(b.compte("admin-02").unwrap().verifier("Nouveau-mot-2026"));
        // Fichier altéré (certificat en double) : refusé.
        let texte = std::fs::read_to_string(c.fichier()).unwrap();
        let e1 = empreinte_certificat(b"c1");
        let e2 = empreinte_certificat(b"c2");
        std::fs::write(c.fichier(), texte.replace(&e2, &e1)).unwrap();
        assert!(c.lire().is_err());
    }

    #[test]
    fn verrouillage_croissant() {
        let v = Verrous::default();
        let k = vec!["compte:a".to_string()];
        for _ in 0..ECHECS_MAX - 1 {
            v.echec(&k, 100);
        }
        assert!(!v.verrouille(&k, 100));
        v.echec(&k, 100);
        assert!(v.verrouille(&k, 100 + VERROU_S - 1));
        assert!(!v.verrouille(&k, 100 + VERROU_S));
        v.echec(&k, 2000);
        assert!(v.verrouille(&k, 2000 + 2 * VERROU_S - 1));
        v.succes(&k);
        assert!(!v.verrouille(&k, 2001));
    }
}
