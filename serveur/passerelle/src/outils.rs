//! Petits outils : aléa, empreintes, dates, écriture atomique.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};

/// Octets aléatoires du système (getrandom). Panique si le noyau n'en fournit pas : rien de
/// sûr n'est possible sans aléa.
pub fn aleatoire<const N: usize>() -> [u8; N] {
    let mut o = [0u8; N];
    SystemRandom::new()
        .fill(&mut o)
        .expect("aléa du système indisponible");
    o
}

pub fn sha256_hex(octets: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, octets))
}

/// Numéro de série normalisé : hexadécimal minuscule sans octet nul de tête.
pub fn serie_hex(brut: &[u8]) -> String {
    let debut = brut
        .iter()
        .position(|o| *o != 0)
        .unwrap_or(brut.len().saturating_sub(1));
    hex::encode(&brut[debut..])
}

/// Identifiant de borne : UUID version 4 tiré par le serveur.
pub fn nouvel_uuid() -> String {
    let mut o = aleatoire::<16>();
    o[6] = (o[6] & 0x0f) | 0x40;
    o[8] = (o[8] & 0x3f) | 0x80;
    let h = hex::encode(o);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Heure du serveur (secondes Unix, UTC) : la référence du site.
pub fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `AAAA-MM-JJ HH:MM:SS UTC`.
pub fn date_utc(secondes: u64) -> String {
    match i64::try_from(secondes)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
    {
        Some(d) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute(),
            d.second()
        ),
        None => format!("@{secondes}"),
    }
}

/// Écrit un fichier sans jamais laisser d'état intermédiaire : temporaire 0600, `fsync`,
/// renommage, `fsync` du dossier.
pub fn ecrire_atomique(chemin: &Path, contenu: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dossier = chemin.parent().context("chemin sans dossier")?;
    let nom = chemin.file_name().context("chemin sans nom")?;
    let temporaire = dossier.join(format!(".{}.tmp", nom.to_string_lossy()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporaire)
        .with_context(|| format!("écriture de {}", temporaire.display()))?;
    f.write_all(contenu)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&temporaire, chemin)
        .with_context(|| format!("renommage vers {}", chemin.display()))?;
    std::fs::File::open(dossier)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serie_normalisee() {
        assert_eq!(serie_hex(&[0, 0, 0x8a, 1]), "8a01");
        assert_eq!(serie_hex(&[0]), "00");
    }

    #[test]
    fn uuid_v4() {
        let u = nouvel_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }

    #[test]
    fn date() {
        assert_eq!(date_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(date_utc(1_795_000_000), "2026-11-18 11:06:40 UTC");
    }
}
