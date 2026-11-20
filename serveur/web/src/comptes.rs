//! Comptes d'administration : rôle, certificat lié, mot de passe Argon2id, anti force brute.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

/// Longueur minimale d'un mot de passe.
pub const MOT_DE_PASSE_MIN: usize = 12;
/// Échecs admis avant verrouillage.
pub const ECHECS_MAX: u32 = 5;
/// Premier verrouillage (doublé à chaque nouvel échec, 16 fois au plus).
pub const VERROU_S: u64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Administrateur,
    /// Lecture seule.
    Auditeur,
}

impl Role {
    pub fn analyser(s: &str) -> Option<Role> {
        match s {
            "administrateur" => Some(Role::Administrateur),
            "auditeur" => Some(Role::Auditeur),
            _ => None,
        }
    }

    pub fn nom(self) -> &'static str {
        match self {
            Role::Administrateur => "administrateur",
            Role::Auditeur => "auditeur",
        }
    }

    pub fn libelle(self) -> &'static str {
        match self {
            Role::Administrateur => "Administrateur",
            Role::Auditeur => "Auditeur (lecture seule)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Compte {
    pub identifiant: String,
    pub role: Role,
    /// SHA-256 (hexadécimal) du certificat client DER lié au compte.
    pub empreinte_certificat: String,
    hachage: String,
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

fn hacher(mot_de_passe: &str) -> Result<String> {
    Ok(argon2::Argon2::default()
        .hash_password(mot_de_passe.as_bytes())
        .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))?
        .to_string())
}

/// Ligne du fichier des comptes : `identifiant rôle empreinte $argon2id$…`.
pub fn ligne_compte(identifiant: &str, role: Role, cert_der: &[u8], mdp: &str) -> Result<String> {
    if !identifiant_valide(identifiant) {
        bail!("identifiant invalide ([a-z0-9._-], 1 à 32)");
    }
    if mdp.chars().count() < MOT_DE_PASSE_MIN {
        bail!("mot de passe trop court ({MOT_DE_PASSE_MIN} caractères au moins)");
    }
    Ok(format!(
        "{identifiant} {} {} {}",
        role.nom(),
        empreinte_certificat(cert_der),
        hacher(mdp)?
    ))
}

/// Analyse le fichier des comptes (lignes vides et `#` ignorées).
pub fn analyser_comptes(texte: &str) -> Result<Vec<Compte>> {
    let mut comptes: Vec<Compte> = Vec::new();
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
        if !identifiant_valide(id)
            || empreinte.len() != 64
            || !empreinte
                .bytes()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            || PasswordHash::new(hachage).is_err()
            || !hachage.starts_with("$argon2id$")
        {
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
        comptes.push(Compte {
            identifiant: id.into(),
            role,
            empreinte_certificat: empreinte.into(),
            hachage: hachage.into(),
        });
    }
    Ok(comptes)
}

/// Lit le fichier des comptes ; refusé s'il est accessible à d'autres comptes que le service.
pub fn lire_comptes(chemin: &Path) -> Result<Vec<Compte>> {
    let meta = std::fs::metadata(chemin)
        .with_context(|| format!("fichier des comptes {}", chemin.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} : accessible à d'autres comptes (0600 attendu)",
            chemin.display()
        );
    }
    analyser_comptes(&std::fs::read_to_string(chemin)?)
}

/// Une seule vérification Argon2 à la fois : mémoire bornée (19 Mio) même sous attaque.
static ARGON2: Mutex<()> = Mutex::new(());

/// Vérifie un mot de passe ; `None` (compte inconnu) vérifie contre un hachage factice pour
/// un temps de réponse identique.
pub fn verifier_mot_de_passe(compte: Option<&Compte>, mdp: &str) -> bool {
    static FACTICE: OnceLock<String> = OnceLock::new();
    let factice = FACTICE.get_or_init(|| {
        hacher(&hex::encode(barbacane_passerelle::outils::aleatoire::<16>())).unwrap_or_default()
    });
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

    #[test]
    fn ligne_aller_retour_et_verification() {
        let l = ligne_compte("alice", Role::Auditeur, b"cert", "un mot de passe long").unwrap();
        let c = analyser_comptes(&format!("# commentaire\n{l}\n")).unwrap();
        assert_eq!(c[0].role, Role::Auditeur);
        assert_eq!(c[0].empreinte_certificat, empreinte_certificat(b"cert"));
        assert!(verifier_mot_de_passe(Some(&c[0]), "un mot de passe long"));
        assert!(!verifier_mot_de_passe(Some(&c[0]), "un mot de passe lonG"));
        assert!(!verifier_mot_de_passe(None, "un mot de passe long"));
        assert!(ligne_compte("alice", Role::Auditeur, b"c", "court").is_err());
        assert!(ligne_compte("Alice B", Role::Auditeur, b"c", "un mot de passe long").is_err());
        assert!(analyser_comptes(&format!("{l}\n{l}\n")).is_err());
        assert!(analyser_comptes("alice root 00 $argon2id$x").is_err());
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
