//! Opérations sur le disque : identification, lecture de TOUTES les sessions, effacement
//! complet vérifié, gravure à vitesse sûre vérifiée par relecture (sha256 de chaque fichier).

use crate::outil::{Outil, percent};
use crate::toc::{Media, parse_toc, slowest_write_speed};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Avancement d'une opération longue : (pourcentage, phase).
pub type Suivi<'a> = &'a mut dyn FnMut(f32, &str);

/// Identification du disque inséré (sans rien écrire). Sur un lecteur, `-outdev` donne aussi
/// l'état vierge et les vitesses d'écriture ; un disque en lecture seule (DVD-ROM, CD pressé)
/// le refuse : on relit alors en `-indev`. Toute la sortie est analysée, même en cas d'erreur.
pub fn identifier(o: &Outil) -> Result<(Media, Option<u32>)> {
    let dev = o.device.display().to_string();
    let mut sortie = String::new();
    if o.is_drive() {
        let (_, s) = o.run_brut(
            &[
                "-outdev".into(),
                dev.clone(),
                "-toc".into(),
                "-list_speeds".into(),
            ],
            None,
            None,
        )?;
        sortie = s;
    }
    let mut m = parse_toc(&sortie);
    if m.absent() || (!m.blank && m.data_sessions().next().is_none()) {
        let (_, s) = o.run_brut(&["-indev".into(), dev, "-toc".into()], None, None)?;
        let m2 = parse_toc(&s);
        if !m2.absent() {
            m = m2;
        }
        sortie.push_str(&s);
    }
    Ok((m, slowest_write_speed(&sortie)))
}

/// Erreur claire pour les disques sans données (CD audio, vierge, illisible).
fn verifier_lisible(m: &Media) -> Result<()> {
    if m.absent() {
        bail!("aucun disque dans le lecteur");
    }
    if m.blank {
        bail!("le disque est vierge : rien à analyser");
    }
    if m.data_sessions().next().is_none() {
        if m.sessions.is_empty() {
            bail!("disque illisible : aucune session de données");
        }
        bail!("disque sans données (CD audio ?) : seuls les disques de données sont acceptés");
    }
    Ok(())
}

/// Lit toutes les sessions de données dans `dest/session-N/` (dossier vide). Renvoie le
/// nombre de fichiers extraits. Liens symboliques et fichiers spéciaux sont supprimés.
pub fn lire(o: &Outil, dest: &Path, suivi: Suivi) -> Result<u64> {
    let (m, _) = identifier(o)?;
    verifier_lisible(&m)?;
    std::fs::create_dir_all(dest)?;
    if std::fs::read_dir(dest)?.next().is_some() {
        bail!("dossier d'extraction non vide : {}", dest.display());
    }
    let sessions: Vec<_> = m.data_sessions().cloned().collect();
    let n = sessions.len();
    for (i, s) in sessions.iter().enumerate() {
        suivi(
            i as f32 * 100.0 / n as f32,
            &format!("lecture de la session {}", s.index),
        );
        let d = dest.join(format!("session-{}", s.index));
        std::fs::create_dir(&d)?;
        let args: Vec<String> = vec![
            "-osirrox".into(),
            "on:auto_chmod_on".into(),
            "-indev".into(),
            o.device.display().to_string(),
            "-load".into(),
            "sbsector".into(),
            s.lba.to_string(),
            "-extract".into(),
            "/".into(),
            d.display().to_string(),
        ];
        o.run(&args, Some(dest), None, |_| ())
            .with_context(|| format!("lecture de la session {}", s.index))?;
    }
    suivi(100.0, "lecture terminée");
    nettoyer(dest)
}

/// Ne garde que des dossiers et des fichiers ordinaires ; rend le tout lisible.
fn nettoyer(dir: &Path) -> Result<u64> {
    use std::os::unix::fs::PermissionsExt;
    let mut n = 0;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let t = e.file_type()?;
        let p = e.path();
        if t.is_dir() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750))?;
            n += nettoyer(&p)?;
        } else if t.is_file() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640))?;
            n += 1;
        } else {
            log::warn!("élément non ordinaire ignoré : {}", p.display());
            std::fs::remove_file(&p)?;
        }
    }
    Ok(n)
}

/// sha256 de chaque fichier, chemins relatifs à `racine`.
pub fn empreintes(racine: &Path) -> Result<BTreeMap<String, String>> {
    fn walk(r: &Path, d: &Path, acc: &mut BTreeMap<String, String>) -> Result<()> {
        for e in std::fs::read_dir(d)? {
            let e = e?;
            let p = e.path();
            if e.file_type()?.is_dir() {
                walk(r, &p, acc)?;
            } else if e.file_type()?.is_file() {
                let mut h = Sha256::new();
                let mut f = std::fs::File::open(&p)?;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let k = f.read(&mut buf)?;
                    if k == 0 {
                        break;
                    }
                    h.update(&buf[..k]);
                }
                let rel = p.strip_prefix(r)?.to_string_lossy().into_owned();
                acc.insert(rel, hex::encode(h.finalize()));
            }
        }
        Ok(())
    }
    let mut acc = BTreeMap::new();
    walk(racine, racine, &mut acc)?;
    Ok(acc)
}

#[derive(Debug, Clone, Serialize)]
pub struct Mesure {
    pub operation: String,
    pub secondes: u64,
    pub octets: u64,
    pub vitesse_ko_s: u32,
}

/// Effacement COMPLET (jamais l'effacement rapide), puis vérification par relecture.
pub fn effacer(o: &Outil, suivi: Suivi) -> Result<Mesure> {
    let (m, _) = identifier(o)?;
    if m.absent() {
        bail!("aucun disque dans le lecteur");
    }
    if !m.rewritable() {
        bail!(
            "disque {} non réinscriptible : il ne peut être ni effacé ni regravé (détruisez-le si besoin)",
            m.kind
        );
    }
    let debut = Instant::now();
    let dev = o.device.display().to_string();
    if m.overwritable() {
        // DVD+RW, BD-RE, DVD-RAM : pas d'état vierge ; formatage complet puis zéros partout.
        o.run(
            &[
                "-outdev".into(),
                dev.clone(),
                "-format".into(),
                "full".into(),
            ],
            None,
            None,
            |l| {
                if let Some(p) = percent(l) {
                    suivi(p / 2.0, "formatage complet");
                }
            },
        )?;
        remplir_zeros(o, &m, suivi)?;
    } else {
        o.run(
            &["-outdev".into(), dev, "-blank".into(), "all".into()],
            None,
            None,
            |l| {
                if let Some(p) = percent(l) {
                    suivi(p, "effacement complet");
                }
            },
        )?;
    }
    let secondes = debut.elapsed().as_secs();
    verifier_efface(o, &m)?;
    suivi(100.0, "effacement vérifié");
    Ok(Mesure {
        operation: format!("effacement complet {}", m.kind),
        secondes,
        octets: m.capacity(),
        vitesse_ko_s: (m.capacity() / 1024 / secondes.max(1)) as u32,
    })
}

/// Disques à réécriture directe : un fichier de zéros remplit toute la surface.
fn remplir_zeros(o: &Outil, m: &Media, suivi: Suivi) -> Result<()> {
    let t = tempfile::tempdir()?;
    let f = t.path().join("zeros");
    let taille = m.capacity().saturating_sub(16 << 20);
    std::fs::File::create(&f)?.set_len(taille)?;
    o.run(
        &[
            "-outdev".into(),
            o.device.display().to_string(),
            "-map".into(),
            f.display().to_string(),
            "/zeros".into(),
            "-commit".into(),
        ],
        None,
        Some(t.path()),
        |l| {
            if let Some(p) = percent(l) {
                suivi(50.0 + p / 2.0, "remplissage de zéros");
            }
        },
    )?;
    Ok(())
}

/// Après effacement : le disque doit être vierge (CD-RW, DVD-RW) et une lecture brute de
/// secteurs répartis sur la surface ne doit renvoyer aucune donnée.
pub fn verifier_efface(o: &Outil, avant: &Media) -> Result<()> {
    let (m, _) = identifier(o)?;
    if !avant.overwritable() && !m.blank {
        bail!(
            "vérification : le disque n'est pas vierge après effacement ({})",
            m.label()
        );
    }
    if !avant.overwritable() && m.data_sessions().next().is_some() {
        bail!("vérification : une session reste lisible après effacement");
    }
    let lus = secteurs_lisibles(&o.device, avant.overall_blocks.max(avant.readable_blocks))?;
    if lus > 0 && !avant.overwritable() {
        bail!("vérification : {lus} secteur(s) encore lisibles après effacement");
    }
    Ok(())
}

/// Nombre de secteurs (parmi 64 répartis sur la surface) qui se lisent ET contiennent autre
/// chose que des zéros.
pub fn secteurs_lisibles(dev: &Path, blocs: u64) -> Result<u32> {
    let Ok(mut f) = std::fs::File::open(dev) else {
        return Ok(0); // disque vierge : le noyau refuse même l'ouverture
    };
    let mut n = 0;
    let mut buf = [0u8; 2048];
    for i in 0..64u64 {
        let lba = blocs.max(1) * i / 64;
        if f.seek(SeekFrom::Start(lba * 2048)).is_err() {
            continue;
        }
        if f.read_exact(&mut buf).is_ok() && buf.iter().any(|&b| b != 0) {
            n += 1;
        }
    }
    Ok(n)
}

/// Grave `source` (fichiers sains) sur un disque réinscriptible, à la plus basse vitesse
/// annoncée, après un effacement complet ; puis relit tout et compare chaque sha256.
pub fn graver(o: &Outil, source: &Path, travail: &Path, suivi: Suivi) -> Result<Vec<Mesure>> {
    let (m, vitesse) = identifier(o)?;
    if m.absent() {
        bail!("aucun disque dans le lecteur");
    }
    if !m.rewritable() {
        bail!(
            "disque {} non réinscriptible : utilisez un CD-RW, DVD-RW, DVD+RW ou BD-RE",
            m.kind
        );
    }
    let attendu = empreintes(source)?;
    let total: u64 = attendu
        .keys()
        .map(|k| {
            std::fs::metadata(source.join(k))
                .map(|x| x.len())
                .unwrap_or(0)
        })
        .sum();
    if total + (2 << 20) > m.capacity() {
        bail!(
            "disque trop petit : {} Mo à graver, {} Mo disponibles",
            total / 1_000_000,
            m.capacity() / 1_000_000
        );
    }
    let mut mesures = Vec::new();
    if !m.blank {
        mesures.push(effacer(o, &mut |p, ph| suivi(p * 0.4, ph))?);
    }
    let vitesse = vitesse.unwrap_or(0);
    let debut = Instant::now();
    let mut args: Vec<String> = vec!["-outdev".into(), o.device.display().to_string()];
    if vitesse > 0 {
        args.extend(["-speed".into(), format!("{vitesse}k")]);
    }
    args.extend([
        "-volid".into(),
        "BARBACANE".into(),
        "-joliet".into(),
        "on".into(),
        "-close".into(),
        "on".into(),
        "-map".into(),
        source.display().to_string(),
        "/".into(),
        "-commit".into(),
    ]);
    o.run(&args, None, Some(source), |l| {
        if let Some(p) = percent(l) {
            suivi(40.0 + p * 0.4, "gravure");
        }
    })?;
    let secondes = debut.elapsed().as_secs();
    mesures.push(Mesure {
        operation: format!("gravure {} ({} ko/s demandés)", m.kind, vitesse),
        secondes,
        octets: total,
        vitesse_ko_s: (total / 1024 / secondes.max(1)) as u32,
    });
    // Relecture complète par le même chemin que l'entrée, puis comparaison
    suivi(80.0, "relecture et vérification");
    let relu = travail.join("relecture");
    let _ = std::fs::remove_dir_all(&relu);
    lire(o, &relu, &mut |_, _| ())?;
    let obtenu = empreintes(&relu.join("session-1"))?;
    let _ = std::fs::remove_dir_all(&relu);
    comparer(&attendu, &obtenu)?;
    suivi(100.0, "gravure vérifiée");
    Ok(mesures)
}

/// Chaque fichier attendu doit être relu à l'identique, et rien d'autre ne doit apparaître.
pub fn comparer(
    attendu: &BTreeMap<String, String>,
    obtenu: &BTreeMap<String, String>,
) -> Result<()> {
    let mut fautes = Vec::new();
    for (f, h) in attendu {
        match obtenu.get(f) {
            Some(x) if x == h => (),
            Some(_) => fautes.push(format!("{f} différent")),
            None => fautes.push(format!("{f} absent")),
        }
    }
    for f in obtenu.keys().filter(|f| !attendu.contains_key(*f)) {
        fautes.push(format!("{f} inattendu"));
    }
    if !fautes.is_empty() {
        bail!("vérification après gravure : {}", fautes.join(", "));
    }
    Ok(())
}

/// Éjecte le disque (fin d'opération, échange de disque).
pub fn ejecter(o: &Outil) -> Result<()> {
    if o.is_drive() {
        o.run(
            &[
                "-outdev".into(),
                o.device.display().to_string(),
                "-eject".into(),
                "all".into(),
            ],
            None,
            None,
            |_| (),
        )?;
    }
    Ok(())
}

/// Dossier vide prêt à recevoir une extraction.
pub fn vider(d: &PathBuf) -> Result<()> {
    if d.exists() {
        for e in std::fs::read_dir(d)? {
            let p = e?.path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p)?;
            } else {
                std::fs::remove_file(&p)?;
            }
        }
    }
    Ok(())
}
