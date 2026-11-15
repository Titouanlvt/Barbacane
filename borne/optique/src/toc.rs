//! Lecture des sorties de `xorriso -toc` et `-list_speeds` (type de disque, sessions, vitesses).

use serde::Serialize;

/// Une session du disque (table des matières).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    pub index: u32,
    /// Premier secteur (bloc de 2048 octets)
    pub lba: u64,
    /// Taille en blocs
    pub blocks: u64,
    /// Session contenant un système de fichiers ISO 9660 (sinon : audio, UDF seul, inconnue)
    pub iso: bool,
    pub volume: String,
}

/// État du disque inséré.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Media {
    /// Tel que libburn le nomme : « CD-RW », « DVD+RW », « BD-RE »…
    pub kind: String,
    pub blank: bool,
    pub closed: bool,
    pub sessions: Vec<Session>,
    pub readable_blocks: u64,
    pub overall_blocks: u64,
}

impl Media {
    /// Disque réinscriptible (gravure et effacement autorisés).
    pub fn rewritable(&self) -> bool {
        let k = self.kind.to_ascii_uppercase();
        k.starts_with("CD-RW")
            || k.starts_with("DVD-RW")
            || k.starts_with("DVD+RW")
            || k.starts_with("BD-RE")
            || k.starts_with("DVD-RAM")
    }

    /// Disque à réécriture directe (pas d'état « vierge » : DVD+RW, BD-RE, DVD-RAM, DVD-RW
    /// en mode « restricted overwrite ») : l'effacement complet est un remplissage de zéros.
    pub fn overwritable(&self) -> bool {
        let k = self.kind.to_ascii_uppercase();
        k.starts_with("DVD+RW")
            || k.starts_with("BD-RE")
            || k.starts_with("DVD-RAM")
            || k.contains("RESTRICTED OVERWRITE")
    }

    /// Aucun disque dans le lecteur.
    pub fn absent(&self) -> bool {
        self.kind.is_empty() || self.kind == "is not recognizable" || self.kind.contains("no media")
    }

    /// Sessions lisibles comme système de fichiers (ISO 9660 / UDF).
    pub fn data_sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter().filter(|s| s.iso)
    }

    /// Capacité en octets.
    pub fn capacity(&self) -> u64 {
        self.overall_blocks * 2048
    }

    /// Libellé lisible pour l'interface et les rapports.
    pub fn label(&self) -> String {
        let etat = if self.blank {
            "vierge".to_string()
        } else {
            let o = self.data_sessions().map(|s| s.blocks).sum::<u64>() * 2048;
            let taille = if o >= 1_000_000 {
                format!("{} Mo", o / 1_000_000)
            } else {
                format!("{} ko", o.div_ceil(1000))
            };
            format!("{} session(s), {taille}", self.sessions.len())
        };
        format!("{} ({etat})", self.kind)
    }
}

fn champ<'a>(l: &'a str, nom: &str) -> Option<&'a str> {
    let (k, v) = l.split_once(':')?;
    (k.trim() == nom).then(|| v.trim())
}

/// Analyse la sortie de `xorriso -indev DEV -toc` (ou `-outdev`).
pub fn parse_toc(out: &str) -> Media {
    let mut m = Media::default();
    for l in out.lines() {
        if let Some(v) = champ(l, "Media current") {
            m.kind = v.to_string();
        } else if let Some(v) = champ(l, "Media status") {
            m.blank = v.contains("is blank");
            m.closed = v.contains("is closed");
        } else if let Some(v) = champ(l, "Media blocks") {
            // « 189327 readable , 0 writable , 359847 overall »
            for part in v.split(',') {
                let mut it = part.split_whitespace();
                if let (Some(n), Some(w)) = (it.next(), it.next()) {
                    let n = n.parse().unwrap_or(0);
                    match w {
                        "readable" => m.readable_blocks = n,
                        "overall" => m.overall_blocks = n,
                        _ => (),
                    }
                }
            }
        } else if let Some((k, v)) = l.split_once(':') {
            let k = k.trim();
            let iso = k == "ISO session";
            if iso || k == "Other session" || k == "Audio track" || k == "Data track" {
                // « 1 ,         0 ,    189325s , VOLID »
                let p: Vec<&str> = v.splitn(4, ',').map(str::trim).collect();
                if p.len() >= 3 {
                    m.sessions.push(Session {
                        index: p[0].parse().unwrap_or(0),
                        lba: p[1].parse().unwrap_or(0),
                        blocks: p[2].trim_end_matches('s').parse().unwrap_or(0),
                        iso,
                        volume: p.get(3).map(|s| s.to_string()).unwrap_or_default(),
                    });
                }
            }
        }
    }
    m
}

/// Plus basse vitesse d'écriture annoncée par le lecteur pour ce disque, en ko/s
/// (`xorriso -list_speeds`, ligne « Write speed L »). `None` : disque non inscriptible.
pub fn slowest_write_speed(out: &str) -> Option<u32> {
    let mut min = None;
    for l in out.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let k = k.trim();
        if k == "Write speed L" || k == "Write speed" || k == "Write speed l" {
            let kb = v.split(',').next()?.trim().trim_end_matches('k');
            if let Ok(n) = kb.trim().parse::<u32>() {
                min = Some(min.map_or(n, |m: u32| m.min(n)));
            }
        }
    }
    min
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sortie réelle : CD-RW du lab (MATSHITA UJ8E2Q), 15/11/2026.
    const CDRW: &str = "\
Drive current: -indev '/dev/sr0'
Media current: CD-RW
Media product: 97m26s65f/79m59s74f , CMC Magnetics Corporation
Media status : is written , is closed
Media blocks : 189327 readable , 0 writable , 359847 overall
Boot record  : El Torito
TOC layout   : Idx ,  sbsector ,       Size , Volume Id
ISO session  :   1 ,         0 ,    189325s , HP-ESXI-6.0.0-ISO-600.9.3.30.2
Media summary: 1 session, 189327 data blocks,  370m data,     0 free
";
    const VITESSES: &str = "\
Read speed   :   3353k , 19.0xC
Write speed  :   1764k , 10.0xC
Write speed l:    706k ,  4.0xC
Write speed L:    706k ,  4.0xC
Write speed H:   1764k , 10.0xC
";

    #[test]
    fn cd_rw_du_lab() {
        let m = parse_toc(CDRW);
        assert_eq!(m.kind, "CD-RW");
        assert!(m.rewritable() && !m.overwritable() && !m.blank && m.closed);
        assert_eq!(m.sessions.len(), 1);
        assert_eq!(m.sessions[0].lba, 0);
        assert_eq!(m.sessions[0].blocks, 189325);
        assert_eq!(m.sessions[0].volume, "HP-ESXI-6.0.0-ISO-600.9.3.30.2");
        assert_eq!(m.overall_blocks, 359847);
        assert_eq!(m.data_sessions().count(), 1);
        assert_eq!(m.label(), "CD-RW (1 session(s), 387 Mo)");
    }

    #[test]
    fn vitesse_la_plus_basse() {
        assert_eq!(slowest_write_speed(VITESSES), Some(706));
        assert_eq!(slowest_write_speed("Read speed : 3353k , 19.0xC\n"), None);
    }

    #[test]
    fn multisession_et_sessions_non_iso() {
        let m = parse_toc(
            "Media current: CD-RW\nMedia status : is written , is appendable\n\
             ISO session  :   1 ,         0 ,       200s , ANCIENNE\n\
             ISO session  :   2 ,     11552 ,       300s , RECENTE\n\
             Other session:   3 ,     20000 ,        50s , \n",
        );
        assert_eq!(m.sessions.len(), 3);
        assert_eq!(
            m.data_sessions().map(|s| s.lba).collect::<Vec<_>>(),
            [0, 11552]
        );
        assert!(!m.closed);
    }

    #[test]
    fn non_reinscriptibles_refuses() {
        for k in [
            "CD-R",
            "DVD-R sequential recording",
            "DVD+R",
            "BD-R sequential recording",
            "CD-ROM",
        ] {
            let m = Media {
                kind: k.into(),
                ..Default::default()
            };
            assert!(!m.rewritable(), "{k}");
        }
        for k in ["DVD+RW", "BD-RE", "DVD-RW restricted overwrite"] {
            let m = Media {
                kind: k.into(),
                ..Default::default()
            };
            assert!(m.rewritable() && m.overwritable(), "{k}");
        }
        let m = Media {
            kind: "DVD-RW sequential recording".into(),
            ..Default::default()
        };
        assert!(m.rewritable() && !m.overwritable());
    }

    #[test]
    fn cd_audio_sans_session_de_donnees() {
        let m = parse_toc(
            "Media current: CD-ROM\nMedia status : is written , is closed\nAudio track  :   1 ,  0 , 20000s , \n",
        );
        assert_eq!(m.data_sessions().count(), 0);
        assert!(!m.rewritable());
    }
}
