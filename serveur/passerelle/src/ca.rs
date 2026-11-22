//! CA « bornes » : vérification des demandes PKCS#10, émission des certificats de borne
//! (politique de certification §3) et publication de la CRL (D8).
//!
//! Clé de la CA en fichier PEM pour le lab ; dans le TPM ensuite (politique §6).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use barbacane_protocole::{CodeErreur, DUREE_CERTIFICAT_JOURS};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, PublicKeyData,
    RevocationReason, RevokedCertParams, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer,
};
use time::OffsetDateTime;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use crate::outils::{aleatoire, ecrire_atomique, serie_hex, sha256_hex};

/// Validité de la CRL (D8).
pub const VALIDITE_CRL_S: u64 = 7 * 24 * 3600;
const JOUR: u64 = 24 * 3600;

/// Demande de certificat vérifiée : signature correcte, clé ECDSA P-256.
#[derive(Debug, Clone)]
pub struct CsrVerifiee {
    pub der: Vec<u8>,
    /// SHA-256 de la demande DER (affichée sur la borne, comparée par l'administrateur).
    pub empreinte: String,
    spki: Vec<u8>,
}

/// Analyse et vérifie une demande PEM. Le sujet et les extensions demandés sont ignorés.
pub fn verifier_csr(pem: &str) -> Result<CsrVerifiee, CodeErreur> {
    let invalide = |_| CodeErreur::DemandeInvalide;
    let der = CertificateSigningRequestDer::from_pem_slice(pem.as_bytes()).map_err(invalide)?;
    let (reste, csr) = X509CertificationRequest::from_der(der.as_ref())
        .map_err(|_| CodeErreur::DemandeInvalide)?;
    if !reste.is_empty() {
        return Err(CodeErreur::DemandeInvalide);
    }
    let spki = &csr.certification_request_info.subject_pki;
    let courbe = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok());
    let point = spki.subject_public_key.data.as_ref();
    let p256 = spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && courbe == Some(OID_EC_P256)
        && point.len() == 65
        && point[0] == 4;
    if !p256 || csr.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(CodeErreur::DemandeInvalide);
    }
    csr.verify_signature()
        .map_err(|_| CodeErreur::DemandeInvalide)?;
    Ok(CsrVerifiee {
        empreinte: sha256_hex(der.as_ref()),
        spki: spki.raw.to_vec(),
        der: der.as_ref().to_vec(),
    })
}

/// Certificat émis.
#[derive(Debug, Clone)]
pub struct CertificatEmis {
    pub pem: String,
    /// Numéro de série en hexadécimal normalisé (`outils::serie_hex`).
    pub serie: String,
    pub emis_le: u64,
    pub expire_le: u64,
}

/// Motif de révocation (politique §5) et son code RFC 5280.
pub fn code_motif(code: u8) -> Option<RevocationReason> {
    Some(match code {
        0 => RevocationReason::Unspecified,
        1 => RevocationReason::KeyCompromise,
        2 => RevocationReason::CaCompromise,
        3 => RevocationReason::AffiliationChanged,
        4 => RevocationReason::Superseded,
        5 => RevocationReason::CessationOfOperation,
        6 => RevocationReason::CertificateHold,
        9 => RevocationReason::PrivilegeWithdrawn,
        10 => RevocationReason::AaCompromise,
        _ => return None,
    })
}

/// Entrée de CRL : numéro de série (hexadécimal normalisé), date, code de motif.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntreeCrl {
    pub serie: String,
    pub le: u64,
    pub motif: u8,
}

pub struct CaBornes {
    issuer: Issuer<'static, KeyPair>,
    /// Certificat de la CA bornes (PEM), joint à la chaîne renvoyée à la borne.
    pub cert_pem: String,
    organisation: String,
    ski: Vec<u8>,
}

fn temps(secondes: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(secondes)?).context("date hors bornes")
}

impl CaBornes {
    /// Charge le certificat et la clé de la CA bornes ; refuse une clé non P-384 (D6) ou qui ne
    /// correspond pas au certificat.
    pub fn charger(cert: &Path, cle: &Path) -> Result<CaBornes> {
        let cert_pem = std::fs::read_to_string(cert)
            .with_context(|| format!("lecture de {}", cert.display()))?;
        let cle_pem = std::fs::read_to_string(cle)
            .with_context(|| format!("lecture de {}", cle.display()))?;
        CaBornes::depuis_pem(&cert_pem, &cle_pem)
    }

    /// Comme [`CaBornes::charger`], depuis le texte PEM (certificat de la CA, clé PKCS#8).
    pub fn depuis_pem(cert_pem: &str, cle_pem: &str) -> Result<CaBornes> {
        let cert_pem = cert_pem.to_owned();
        let cle = KeyPair::from_pem(cle_pem).context("clé de la CA bornes illisible")?;
        if cle.algorithm() != &rcgen::PKCS_ECDSA_P384_SHA384 {
            bail!("clé de la CA bornes : ECDSA P-384 exigée (D6)");
        }
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .context("certificat de la CA bornes illisible")?;
        let (_, x509) = X509Certificate::from_der(der.as_ref())
            .map_err(|e| anyhow::anyhow!("certificat de la CA bornes : {e}"))?;
        if x509.public_key().raw != cle.subject_public_key_info().as_slice() {
            bail!("la clé ne correspond pas au certificat de la CA bornes");
        }
        let organisation = x509
            .subject()
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .context("CA bornes sans organisation (O)")?
            .to_owned();
        let ski = x509
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                _ => None,
            })
            .context("CA bornes sans subjectKeyIdentifier")?;
        let issuer = Issuer::from_ca_cert_der(&der, cle).context("CA bornes")?;
        Ok(CaBornes {
            issuer,
            cert_pem,
            organisation,
            ski,
        })
    }

    /// Émet un certificat de borne (90 jours) pour la clé de la demande. Le serveur fixe seul
    /// le sujet, les noms et les extensions.
    pub fn emettre(
        &self,
        csr: &CsrVerifiee,
        nom: &str,
        site: &str,
        uuid: &str,
        maintenant: u64,
    ) -> Result<CertificatEmis> {
        let cle = SubjectPublicKeyInfo::from_der(&csr.spki).context("clé de la demande")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("borne {nom}"));
        dn.push(DnType::OrganizationalUnitName, site);
        dn.push(DnType::OrganizationName, self.organisation.as_str());
        let mut p = CertificateParams::default();
        p.distinguished_name = dn;
        p.subject_alt_names = vec![
            SanType::URI(format!("urn:barbacane:borne:{site}:{uuid}").try_into()?),
            SanType::DnsName(format!("{uuid}.bornes.barbacane.invalid").try_into()?),
        ];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.use_authority_key_identifier_extension = true;
        let mut serie = aleatoire::<16>();
        serie[0] &= 0x7f; // entier positif
        serie[0] |= 0x40; // longueur fixe (pas de zéro de tête)
        p.serial_number = Some(SerialNumber::from_slice(&serie));
        let emis_le = maintenant.saturating_sub(60);
        let expire_le = maintenant + DUREE_CERTIFICAT_JOURS * JOUR;
        p.not_before = temps(emis_le)?;
        p.not_after = temps(expire_le)?;
        let cert = p.signed_by(&cle, &self.issuer)?;
        Ok(CertificatEmis {
            pem: cert.pem(),
            serie: serie_hex(&serie),
            emis_le,
            expire_le,
        })
    }

    /// Émet un certificat d'ADMINISTRATEUR de la Console (clientAuth, `validite_j` jours) pour
    /// une clé P-256 tirée par le serveur (`docs/suite/comptes-administrateurs.md` §4). Même
    /// code pour toute CA chargée par [`CaBornes::charger`] (ici la CA « administrateurs »).
    pub fn emettre_administrateur(
        &self,
        cle: &impl PublicKeyData,
        identifiant: &str,
        validite_j: u64,
        maintenant: u64,
    ) -> Result<CertificatEmis> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("administrateur {identifiant}"));
        dn.push(DnType::OrganizationName, self.organisation.as_str());
        let mut p = CertificateParams::default();
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.use_authority_key_identifier_extension = true;
        let mut serie = aleatoire::<16>();
        serie[0] &= 0x7f;
        serie[0] |= 0x40;
        p.serial_number = Some(SerialNumber::from_slice(&serie));
        let emis_le = maintenant.saturating_sub(60);
        let expire_le = maintenant + validite_j * JOUR;
        p.not_before = temps(emis_le)?;
        p.not_after = temps(expire_le)?;
        let cert = p.signed_by(cle, &self.issuer)?;
        Ok(CertificatEmis {
            pem: cert.pem(),
            serie: serie_hex(&serie),
            emis_le,
            expire_le,
        })
    }

    /// Chaîne renvoyée à la borne : son certificat puis la CA bornes.
    pub fn chaine(&self, certificat_pem: &str) -> String {
        format!("{}{}", certificat_pem, self.cert_pem)
    }

    /// Republie la CRL dans `chemin` (écriture atomique) : entrées déjà présentes dans le
    /// fichier actuel (s'il est lisible) + `entrees`, numéro strictement croissant. Renvoie le
    /// numéro utilisé.
    pub fn publier_crl(
        &self,
        chemin: &Path,
        entrees: &[EntreeCrl],
        numero_precedent: u64,
        maintenant: u64,
    ) -> Result<u64> {
        let mut toutes: BTreeMap<String, EntreeCrl> = BTreeMap::new();
        let mut numero = numero_precedent;
        if let Ok(actuelle) = CertificateRevocationListDer::from_pem_file(chemin) {
            let (_, crl) = CertificateRevocationList::from_der(actuelle.as_ref())
                .map_err(|e| anyhow::anyhow!("CRL actuelle : {e}"))?;
            if let Some(n) = crl.crl_number() {
                let octets = n.to_bytes_be();
                if octets.len() <= 8 {
                    let mut tampon = [0u8; 8];
                    tampon[8 - octets.len()..].copy_from_slice(&octets);
                    numero = numero.max(u64::from_be_bytes(tampon));
                }
            }
            for r in crl.iter_revoked_certificates() {
                let e = EntreeCrl {
                    serie: serie_hex(r.raw_serial()),
                    le: u64::try_from(r.revocation_date.timestamp()).unwrap_or(0),
                    motif: r.reason_code().map(|(_, c)| c.0).unwrap_or(0),
                };
                toutes.insert(e.serie.clone(), e);
            }
        }
        for e in entrees {
            toutes.entry(e.serie.clone()).or_insert_with(|| e.clone());
        }
        let numero = numero + 1;
        let revoked_certs = toutes
            .values()
            .map(|e| {
                Ok(RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&hex::decode(&e.serie)?),
                    revocation_time: temps(e.le)?,
                    reason_code: code_motif(e.motif),
                    invalidity_date: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let params = CertificateRevocationListParams {
            this_update: temps(maintenant)?,
            next_update: temps(maintenant + VALIDITE_CRL_S)?,
            crl_number: SerialNumber::from(numero),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::PreSpecified(self.ski.clone()),
        };
        let crl = params.signed_by(&self.issuer)?;
        ecrire_atomique(chemin, crl.pem()?.as_bytes())?;
        Ok(numero)
    }
}
