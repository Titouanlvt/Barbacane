//! Synchronisation des identifiants depuis l'annuaire (LDAPS, lecture seule,
//! `docs/suite/serveur-utilisateurs.md` §2).
//!
//! - `ldaps://` seulement (ni `ldap://` ni StartTLS) ; TLS 1.3 (D6) ; **seule ancre : la CA de
//!   l'annuaire épinglée** (fichier PEM), nom du serveur vérifié par rustls ;
//! - liaison simple avec un **compte de service en lecture seule** (mot de passe dans un fichier
//!   0600) ; recherche paginée d'UN attribut ; aucune écriture dans l'annuaire ;
//! - seuls des identifiants sortent d'ici (jamais de mot de passe d'utilisateur).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use barbacane_passerelle::fournisseur;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};

/// Délai de connexion et de chaque opération.
pub const DELAI: Duration = Duration::from_secs(30);
/// Taille des pages de la recherche (AD limite à 1000 par défaut).
pub const PAGE: i32 = 500;

#[derive(Debug, Clone)]
pub struct ConfigAnnuaire {
    /// `ldaps://hôte[:port]`.
    pub url: String,
    /// CA de l'annuaire (PEM) : seule ancre de confiance.
    pub ca: PathBuf,
    /// DN du compte de service (lecture seule).
    pub compte: String,
    /// Fichier (0600) contenant le mot de passe du compte de service.
    pub mot_de_passe_fichier: PathBuf,
    pub base: String,
    /// Filtre LDAP, par exemple `(&(objectClass=user)(memberOf=CN=Barbacane,…))`.
    pub filtre: String,
    /// Attribut d'identifiant (`sAMAccountName`, `uid`).
    pub attribut: String,
}

fn texte_sur(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

impl ConfigAnnuaire {
    pub fn lire(chemin: &Path) -> Result<ConfigAnnuaire> {
        let texte = std::fs::read_to_string(chemin)
            .with_context(|| format!("lecture de {}", chemin.display()))?;
        ConfigAnnuaire::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<ConfigAnnuaire> {
        const CLES: &[&str] = &[
            "url",
            "ca",
            "compte",
            "mot_de_passe_fichier",
            "base",
            "filtre",
            "attribut",
        ];
        let mut v: BTreeMap<&str, &str> = BTreeMap::new();
        for (n, ligne) in texte.lines().enumerate() {
            let ligne = ligne.trim();
            if ligne.is_empty() || ligne.starts_with('#') {
                continue;
            }
            let Some((k, val)) = ligne.split_once('=') else {
                bail!("annuaire, ligne {} : « cle = valeur » attendu", n + 1);
            };
            let k = k.trim();
            if !CLES.contains(&k) {
                bail!("annuaire, ligne {} : clé inconnue « {k} »", n + 1);
            }
            if v.insert(k, val.trim()).is_some() {
                bail!("annuaire, ligne {} : clé répétée", n + 1);
            }
        }
        let obtenir = |k: &str| {
            v.get(k)
                .copied()
                .with_context(|| format!("annuaire : {k} absent"))
        };
        let url = obtenir("url")?;
        let hote = url
            .strip_prefix("ldaps://")
            .context("annuaire : seul ldaps:// est accepté (ni ldap:// ni StartTLS)")?;
        if hote.is_empty()
            || hote.contains(['/', '?', '@', ' '])
            || !hote
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
        {
            bail!("annuaire : url ldaps://hôte[:port] attendue");
        }
        let compte = obtenir("compte")?;
        let base = obtenir("base")?;
        let filtre = obtenir("filtre")?;
        let attribut = obtenir("attribut")?;
        if !texte_sur(compte, 512) || !texte_sur(base, 512) {
            bail!("annuaire : compte ou base invalide");
        }
        if !texte_sur(filtre, 1024) || !filtre.starts_with('(') || !filtre.ends_with(')') {
            bail!("annuaire : filtre LDAP « (…) » attendu");
        }
        if !(1..=64).contains(&attribut.len())
            || !attribut
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            bail!("annuaire : attribut invalide");
        }
        Ok(ConfigAnnuaire {
            url: url.into(),
            ca: obtenir("ca")?.into(),
            compte: compte.into(),
            mot_de_passe_fichier: obtenir("mot_de_passe_fichier")?.into(),
            base: base.into(),
            filtre: filtre.into(),
            attribut: attribut.into(),
        })
    }

    /// Mot de passe du compte de service : fichier 0600 (refusé s'il est lisible par d'autres).
    fn mot_de_passe(&self) -> Result<String> {
        let c = &self.mot_de_passe_fichier;
        let meta = std::fs::metadata(c).with_context(|| format!("annuaire : {}", c.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} : accessible à d'autres comptes (0600 attendu)",
                c.display()
            );
        }
        let mdp = std::fs::read_to_string(c)?;
        let mdp = mdp.trim_end_matches(['\r', '\n']);
        if mdp.is_empty() || mdp.len() > 256 {
            bail!("annuaire : mot de passe du compte de service vide ou trop long");
        }
        Ok(mdp.into())
    }

    /// Client TLS : la CA de l'annuaire est la SEULE ancre (aucun magasin du système).
    fn tls(&self) -> Result<Arc<ClientConfig>> {
        let mut ancres = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(&self.ca)
            .with_context(|| format!("CA de l'annuaire {}", self.ca.display()))?
        {
            ancres.add(c.context("CA de l'annuaire illisible")?)?;
        }
        if ancres.is_empty() {
            bail!("aucune CA de l'annuaire dans {}", self.ca.display());
        }
        Ok(Arc::new(
            ClientConfig::builder_with_provider(Arc::new(fournisseur()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(ancres)
                .with_no_client_auth(),
        ))
    }
}

/// Lit les identifiants (valeurs de l'attribut configuré) : liaison du compte de service,
/// recherche paginée, déconnexion. Limité à `max` valeurs (au-delà : refus).
pub fn lire_identifiants(c: &ConfigAnnuaire, max: usize) -> Result<Vec<String>> {
    let mdp = c.mot_de_passe()?;
    let reglages = LdapConnSettings::new()
        .set_conn_timeout(DELAI)
        .set_starttls(false)
        .set_config(c.tls()?);
    let mut ldap = LdapConn::with_settings(reglages, &c.url)
        .with_context(|| format!("connexion LDAPS à {}", c.url))?;
    ldap.with_timeout(DELAI)
        .simple_bind(&c.compte, &mdp)
        .context("liaison du compte de service")?
        .success()
        .context("liaison du compte de service refusée")?;
    let adaptateurs: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(PAGE)),
    ];
    let mut ids = Vec::new();
    {
        let mut recherche = ldap
            .with_timeout(DELAI)
            .streaming_search_with(
                adaptateurs,
                &c.base,
                Scope::Subtree,
                &c.filtre,
                vec![c.attribut.as_str()],
            )
            .context("recherche dans l'annuaire")?;
        while let Some(e) = recherche.next().context("lecture des résultats")? {
            let e = SearchEntry::construct(e);
            for (nom, valeurs) in e.attrs {
                if nom.eq_ignore_ascii_case(&c.attribut) {
                    ids.extend(valeurs);
                }
            }
            if ids.len() > max {
                bail!("annuaire : plus de {max} identifiants");
            }
        }
        recherche
            .result()
            .success()
            .context("recherche dans l'annuaire refusée")?;
    }
    let _ = ldap.unbind();
    Ok(ids)
}

/// Synchronise la base des utilisateurs avec l'annuaire (page web ou
/// `barbacane-web annuaire CONFIG`).
pub fn synchroniser(
    config: &Path,
    utilisateurs: &barbacane_passerelle::utilisateurs::Utilisateurs,
    acteur: &str,
    t: u64,
) -> Result<barbacane_passerelle::utilisateurs::BilanImport> {
    let c = ConfigAnnuaire::lire(config)?;
    let ids = lire_identifiants(&c, barbacane_passerelle::utilisateurs::UTILISATEURS_MAX)?;
    utilisateurs.importer(&ids, "annuaire", acteur, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "url = ldaps://annuaire.exemple.invalid:636\nca = /a\ncompte = CN=svc,DC=x\nmot_de_passe_fichier = /b\nbase = DC=x\nfiltre = (objectClass=user)\nattribut = sAMAccountName\n";

    #[test]
    fn configuration() {
        let c = ConfigAnnuaire::analyser(CONF).unwrap();
        assert_eq!(c.attribut, "sAMAccountName");
        for mauvais in [
            CONF.replace("ldaps://", "ldap://"),
            CONF.replace("ldaps://annuaire.exemple.invalid:636", "ldaps://a/b"),
            CONF.replace("(objectClass=user)", "objectClass=user"),
            CONF.replace("sAMAccountName", "sam;x"),
            format!("{CONF}url = ldaps://b\n"),
            format!("{CONF}inconnue = 1\n"),
            CONF.replace("base = DC=x\n", ""),
        ] {
            assert!(ConfigAnnuaire::analyser(&mauvais).is_err(), "{mauvais}");
        }
    }
}
