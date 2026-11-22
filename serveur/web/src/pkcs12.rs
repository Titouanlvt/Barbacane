//! Fichier PKCS#12 (`.p12`, RFC 7292) d'un certificat d'administrateur et de sa clé.
//!
//! Profil moderne, lu par OpenSSL 3, Firefox, Chrome et Windows 10+ :
//! - clé privée PKCS#8 dans un `pkcs8ShroudedKeyBag`, chiffrée en **PBES2** (PBKDF2-HMAC-SHA256,
//!   [`ITERATIONS_PBKDF2`] itérations, sel de 16 octets) + **AES-256-CBC** (IV aléatoire) ;
//! - certificats (administrateur puis CA) en clair dans un `certBag` (données publiques) ;
//! - intégrité : MAC **HMAC-SHA256** (clé dérivée par la KDF PKCS#12, annexe B, sur le mot de
//!   passe en BMPString), [`ITERATIONS_MAC`] itérations.
//!
//! Le mot de passe est tiré par le serveur (ASCII seul : même octets pour PBKDF2 et la KDF
//! PKCS#12), affiché une fois ; le fichier n'est jamais écrit sur disque.

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use anyhow::{Result, bail};
use barbacane_passerelle::outils::aleatoire;
use ring::{digest, hmac, pbkdf2};

pub const ITERATIONS_PBKDF2: u32 = 210_000;
pub const ITERATIONS_MAC: u32 = 10_000;

// ───────────────────────────── DER minimal ────────────────────────────────────────────────────

fn tlv(tag: u8, contenu: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    let n = contenu.len();
    if n < 0x80 {
        o.push(n as u8);
    } else {
        let octets: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        o.push(0x80 | octets.len() as u8);
        o.extend_from_slice(&octets);
    }
    o.extend_from_slice(contenu);
    o
}

fn seq(parties: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parties.concat())
}

fn set(parties: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parties.concat())
}

fn octets(o: &[u8]) -> Vec<u8> {
    tlv(0x04, o)
}

fn explicite0(o: &[u8]) -> Vec<u8> {
    tlv(0xa0, o)
}

fn entier(n: u32) -> Vec<u8> {
    let mut o: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    if o.is_empty() || o[0] & 0x80 != 0 {
        o.insert(0, 0);
    }
    tlv(0x02, &o)
}

/// Identifiant d'objet en notation pointée.
fn oid(pointe: &str) -> Vec<u8> {
    let arcs: Vec<u64> = pointe.split('.').map(|a| a.parse().unwrap_or(0)).collect();
    let mut o = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut groupe = vec![(a & 0x7f) as u8];
        let mut r = a >> 7;
        while r > 0 {
            groupe.push(0x80 | (r & 0x7f) as u8);
            r >>= 7;
        }
        groupe.reverse();
        o.extend(groupe);
    }
    tlv(0x06, &o)
}

const NUL: &[u8] = &[0x05, 0x00];
const DATA: &str = "1.2.840.113549.1.7.1";
const KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const X509: &str = "1.2.840.113549.1.9.22.1";
const LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";
const FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const PBES2: &str = "1.2.840.113549.1.5.13";
const PBKDF2: &str = "1.2.840.113549.1.5.12";
const HMAC_SHA256: &str = "1.2.840.113549.2.9";
const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";

// ───────────────────────────── Cryptographie ──────────────────────────────────────────────────

fn aes256_cbc(cle: &[u8; 32], iv: &[u8; 16], clair: &[u8]) -> Vec<u8> {
    let c = Aes256::new(cle.into());
    let bourrage = 16 - clair.len() % 16;
    let mut donnees = clair.to_vec();
    donnees.extend(std::iter::repeat_n(bourrage as u8, bourrage));
    let mut precedent = *iv;
    for bloc in donnees.chunks_mut(16) {
        for (o, p) in bloc.iter_mut().zip(precedent) {
            *o ^= p;
        }
        let b: &mut [u8; 16] = bloc.try_into().expect("bloc de 16 octets");
        c.encrypt_block(b.into());
        precedent = *b;
    }
    donnees
}

/// KDF PKCS#12 (RFC 7292 annexe B.2), SHA-256, 32 octets, identifiant 3 (clé de MAC).
fn kdf_mac(mdp_bmp: &[u8], sel: &[u8], iterations: u32) -> [u8; 32] {
    const V: usize = 64;
    let etendre = |s: &[u8]| -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        let n = V * s.len().div_ceil(V);
        s.iter().copied().cycle().take(n).collect()
    };
    let mut entree = vec![3u8; V];
    entree.extend(etendre(sel));
    entree.extend(etendre(mdp_bmp));
    let mut a = digest::digest(&digest::SHA256, &entree);
    for _ in 1..iterations {
        a = digest::digest(&digest::SHA256, a.as_ref());
    }
    a.as_ref().try_into().expect("SHA-256 : 32 octets")
}

fn bmp(s: &str) -> Vec<u8> {
    let mut o: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    o.extend([0, 0]);
    o
}

fn attributs(id_cle: &[u8], nom: &str) -> Vec<u8> {
    let nom_bmp: Vec<u8> = nom.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    set(&[
        &seq(&[&oid(FRIENDLY_NAME), &set(&[&tlv(0x1e, &nom_bmp)])]),
        &seq(&[&oid(LOCAL_KEY_ID), &set(&[&octets(id_cle)])]),
    ])
}

fn contenu_data(o: &[u8]) -> Vec<u8> {
    seq(&[&oid(DATA), &explicite0(&octets(o))])
}

/// Construit le `.p12`. `certificats` : DER, celui de l'administrateur en premier.
pub fn construire(
    cle_pkcs8: &[u8],
    certificats: &[&[u8]],
    nom: &str,
    mdp: &str,
) -> Result<Vec<u8>> {
    if !mdp.is_ascii() || mdp.len() < 12 {
        bail!("mot de passe du .p12 : ASCII, 12 caractères au moins");
    }
    let Some(premier) = certificats.first() else {
        bail!("aucun certificat");
    };
    let empreinte = digest::digest(&digest::SHA256, premier);
    let id_cle = &empreinte.as_ref()[..20];
    // Clé privée chiffrée (PBES2).
    let sel = aleatoire::<16>();
    let iv = aleatoire::<16>();
    let mut cle = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(ITERATIONS_PBKDF2).expect("non nul"),
        &sel,
        mdp.as_bytes(),
        &mut cle,
    );
    let chiffre = aes256_cbc(&cle, &iv, cle_pkcs8);
    let algo = seq(&[
        &oid(PBES2),
        &seq(&[
            &seq(&[
                &oid(PBKDF2),
                &seq(&[
                    &octets(&sel),
                    &entier(ITERATIONS_PBKDF2),
                    &seq(&[&oid(HMAC_SHA256), NUL]),
                ]),
            ]),
            &seq(&[&oid(AES256_CBC), &octets(&iv)]),
        ]),
    ]);
    let sac_cle = seq(&[
        &oid(KEY_BAG),
        &explicite0(&seq(&[&algo, &octets(&chiffre)])),
        &attributs(id_cle, nom),
    ]);
    // Certificats.
    let mut sacs_cert = Vec::new();
    for (i, c) in certificats.iter().enumerate() {
        let valeur = explicite0(&seq(&[&oid(X509), &explicite0(&octets(c))]));
        sacs_cert.push(if i == 0 {
            seq(&[&oid(CERT_BAG), &valeur, &attributs(id_cle, nom)])
        } else {
            seq(&[&oid(CERT_BAG), &valeur])
        });
    }
    let refs: Vec<&[u8]> = sacs_cert.iter().map(Vec::as_slice).collect();
    let coffre = seq(&[&contenu_data(&seq(&refs)), &contenu_data(&seq(&[&sac_cle]))]);
    // Intégrité (MAC).
    let sel_mac = aleatoire::<16>();
    let cle_mac = kdf_mac(&bmp(mdp), &sel_mac, ITERATIONS_MAC);
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &cle_mac), &coffre);
    let donnees_mac = seq(&[
        &seq(&[&seq(&[&oid(SHA256), NUL]), &octets(mac.as_ref())]),
        &octets(&sel_mac),
        &entier(ITERATIONS_MAC),
    ]);
    Ok(seq(&[&entier(3), &contenu_data(&coffre), &donnees_mac]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_et_aes() {
        assert_eq!(
            oid("1.2.840.113549.1.7.1"),
            hex::decode("06092a864886f70d010701").unwrap()
        );
        assert_eq!(entier(3), vec![2, 1, 3]);
        assert_eq!(entier(210_000), hex::decode("0203033450").unwrap());
        assert_eq!(tlv(4, &[0; 200])[..3], [4, 0x81, 200]);
        // FIPS 197 / SP 800-38A F.2.5 (AES-256-CBC, premier bloc).
        let cle: [u8; 32] =
            hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .unwrap()
                .try_into()
                .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let c = aes256_cbc(
            &cle,
            &iv,
            &hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        );
        assert_eq!(hex::encode(&c[..16]), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assert_eq!(c.len(), 32, "bloc de bourrage complet");
    }
}
