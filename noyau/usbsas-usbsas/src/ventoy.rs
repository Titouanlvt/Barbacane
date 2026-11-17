//! Barbacane (écart n° 9) : disposition d'une clé Ventoy reconstruite.
//!
//! Mêmes emplacements que `Ventoy2Disk.sh` en mode MBR : code de démarrage de `boot.img` dans
//! les 440 premiers octets, identifiant de disque aléatoire (octets 384 à 399), `core.img` à
//! partir du secteur 1, partition 1 (données, active) du secteur 2048 jusqu'à la partition 2
//! (`VTOYEFI`, type 0xEF) qui occupe la fin de la clé. Tout vient de la version de Ventoy
//! embarquée dans la borne ; rien n'est repris de la clé d'origine.

use usbsas_mbr::{MbrPartitionEntry, SECTOR_START};

pub const SECTOR: u64 = 512;

/// Premier secteur de la partition `VTOYEFI` : fin de la clé moins l'image, aligné sur 1 Mio.
/// La partition de données (écrite par files2fs) s'arrête juste avant.
pub fn part2_start(dev_size: u64, disk_len: u64) -> Option<u64> {
    let total = dev_size / SECTOR;
    let p2 = total.checked_sub(disk_len.div_ceil(SECTOR))? / 2048 * 2048;
    // au moins 64 Mio de données, et des tailles qui tiennent dans la table MBR (2 Tio)
    (p2 >= SECTOR_START + 131_072 && total <= u64::from(u32::MAX)).then_some(p2)
}

/// Secteur 0 : code de démarrage Ventoy, identifiants, table de partitions.
pub fn mbr(boot: &[u8], data_ptype: u8, p2: u64, disk_len: u64, uuid: [u8; 16]) -> [u8; 512] {
    let mut m = [0u8; 512];
    m[..440].copy_from_slice(&boot[..440]);
    m[384..400].copy_from_slice(&uuid);
    m[440..444].copy_from_slice(&uuid[12..16]);
    let mut p1 =
        MbrPartitionEntry::new(data_ptype, SECTOR_START as u32, (p2 - SECTOR_START) as u32);
    p1.boot_indicator = 0x80;
    let p2e = MbrPartitionEntry::new(0xEF, p2 as u32, disk_len.div_ceil(SECTOR) as u32);
    m[446..462].copy_from_slice(&p1.to_bytes().expect("16 octets"));
    m[462..478].copy_from_slice(&p2e.to_bytes().expect("16 octets"));
    m[510] = 0x55;
    m[511] = 0xAA;
    m
}

/// Découpe `data` en écritures de `max` octets au plus (complétées à un nombre entier de
/// secteurs), à partir du secteur `start`.
pub fn ecritures(start: u64, data: &[u8], max: usize) -> Vec<(u64, Vec<u8>)> {
    let max = max / SECTOR as usize * SECTOR as usize;
    data.chunks(max)
        .enumerate()
        .map(|(i, c)| {
            let mut v = c.to_vec();
            v.resize(c.len().div_ceil(SECTOR as usize) * SECTOR as usize, 0);
            (start + (i * max) as u64 / SECTOR, v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_cle_16_go() {
        let dev = 15_376_000_000u64 / 512 * 512;
        let disk = 32 * 1024 * 1024;
        let p2 = part2_start(dev, disk).unwrap();
        assert_eq!(p2 % 2048, 0);
        assert!(p2 * 512 + disk <= dev, "VTOYEFI dépasse la clé");
        assert!(
            dev - (p2 * 512 + disk) < 1024 * 1024,
            "plus de 1 Mio perdu en fin de clé"
        );
        let boot = vec![0xAB; 512];
        let m = mbr(&boot, 0x07, p2, disk, [7; 16]);
        assert_eq!(&m[..384], &boot[..384]);
        assert_eq!(&m[384..400], &[7; 16]);
        assert_eq!(m[446], 0x80, "partition 1 active");
        assert_eq!(m[450], 0x07);
        assert_eq!(u32::from_le_bytes(m[454..458].try_into().unwrap()), 2048);
        assert_eq!(
            u32::from_le_bytes(m[458..462].try_into().unwrap()) as u64,
            p2 - 2048
        );
        assert_eq!(m[466], 0xEF);
        assert_eq!(
            u32::from_le_bytes(m[470..474].try_into().unwrap()) as u64,
            p2
        );
        assert_eq!(u32::from_le_bytes(m[474..478].try_into().unwrap()), 65536);
        assert_eq!(&m[510..], &[0x55, 0xAA]);
    }

    #[test]
    fn trop_petite_ou_trop_grande() {
        assert!(part2_start(32 * 1024 * 1024, 32 * 1024 * 1024).is_none());
        assert!(part2_start(4 << 40, 32 * 1024 * 1024).is_none());
    }

    #[test]
    fn decoupage() {
        let w = ecritures(1, &[1u8; 1000], 512);
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].0, 1);
        assert_eq!(w[1].0, 2);
        assert_eq!(w[1].1.len(), 512);
        assert_eq!(w[1].1[487], 1);
        assert_eq!(w[1].1[488], 0);
    }
}
