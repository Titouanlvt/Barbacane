//! Segments scellés du journal d'audit (v2.3.0, `docs/suite/journal-conservation.md`).
//!
//! - **Rotation** ([`Journal::tourner`]) : une fois par jour (UTC), le journal actif est vérifié,
//!   scellé (point de contrôle), puis rangé dans `audit-segments/<premier n sur 20 chiffres>.jsonl` ;
//!   le nouveau journal actif s'ouvre par [`Evenement::SegmentOuvert`], signé par la clé
//!   d'audit, qui reprend le numéro et l'empreinte de la dernière ligne rangée. La chaîne
//!   continue donc d'un fichier à l'autre sans rupture de numérotation.
//! - **Purge** ([`Journal::purger_segments`]) : les segments les plus anciens dont la DERNIÈRE ligne
//!   est antérieure à la limite sont supprimés, du plus ancien au plus récent (jamais un segment
//!   du milieu, jamais le journal actif), seulement si toute la chaîne est intègre ; chaque
//!   suppression est d'abord inscrite ([`Evenement::SegmentPurge`]).
//! - **Vérification** ([`Journal::verifier_tout`]) : chaque fichier, dans l'ordre ; le premier
//!   présent part du tout premier enregistrement ou de son ancre signée (partie purgée) ; chacun
//!   des suivants doit s'ouvrir par une ancre qui prolonge exactement le précédent.
//!
//! Écritures sûres face à une interruption : nouveau journal écrit à part (`.nouveau`), segment
//! rangé (`rename`), puis nouveau journal mis en place (`rename`) ; un journal actif absent est
//! repris depuis `.nouveau` ou refusé (jamais recréé vide).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::{
    Bilan, CleAudit, ClePublique, Defaut, Enregistrement, Evenement, Journal, PointExporte,
    VERSION_SCHEMA, aligner_proprietaire, controler_exports, message_ancre, verifier_segment,
};

/// Nom d'un segment rangé : numéro de son premier enregistrement sur 20 chiffres.
pub fn nom_segment(premier: u64) -> String {
    format!("{premier:020}.jsonl")
}

/// Lecture d'une suite d'enregistrements (export Syslog).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lecture {
    /// Premier numéro encore présent (0 : journal vide).
    pub premier: u64,
    /// Lignes de numéro > `apres` (au plus `max`), dans l'ordre.
    pub lignes: Vec<Vec<u8>>,
    /// Dernier numéro du journal (0 : vide).
    pub dernier: u64,
}

/// Segment supprimé par la conservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentPurge {
    pub premier: u64,
    pub dernier: u64,
    /// Heure de sa dernière ligne.
    pub dernier_le: u64,
}

fn premier_enr(contenu: &[u8]) -> Option<Enregistrement> {
    let ligne = contenu.split(|o| *o == b'\n').next()?;
    Enregistrement::analyser(ligne).ok()
}

/// Date des données d'un segment : celle de son dernier enregistrement autre que le point de
/// contrôle de fermeture (écrit à la rotation, le lendemain).
fn date_donnees(contenu: &[u8]) -> u64 {
    contenu
        .split(|o| *o == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| Enregistrement::analyser(l).ok())
        .filter(|e| !matches!(e.evenement, Evenement::PointDeControle { .. }))
        .map(|e| e.le)
        .max()
        .unwrap_or(u64::MAX)
}

fn synchroniser_dossier(d: &std::path::Path) {
    if let Ok(f) = File::open(d) {
        let _ = f.sync_all();
    }
}

impl Journal {
    /// Dossier des segments rangés.
    pub fn dossier_segments(&self) -> PathBuf {
        self.dossier().join("audit-segments")
    }

    /// Segments rangés, du plus ancien au plus récent : (premier numéro, chemin). Un nom qui
    /// n'a pas la forme attendue est refusé (fichier étranger dans le dossier).
    pub fn segments(&self) -> Result<Vec<(u64, PathBuf)>> {
        let d = self.dossier_segments();
        let lecture = match std::fs::read_dir(&d) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("dossier des segments d'audit"),
        };
        let mut v = Vec::new();
        for x in lecture {
            let x = x?;
            let nom = x.file_name().to_string_lossy().into_owned();
            let n = nom
                .strip_suffix(".jsonl")
                .filter(|s| s.len() == 20 && s.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|s| s.parse::<u64>().ok())
                .with_context(|| format!("fichier inattendu dans {} : {nom}", d.display()))?;
            v.push((n, x.path()));
        }
        v.sort();
        Ok(v)
    }

    /// Lit, sous le verrou du journal (aucune rotation ne peut s'intercaler), au plus `max`
    /// enregistrements de numéro > `apres`, sans relire les segments entièrement antérieurs.
    pub fn lire_depuis(&self, apres: u64, max: usize) -> Result<Lecture> {
        let _v = self.verrou()?;
        let segments = self.segments()?;
        let actif = self.lire()?;
        let premier_actif = actif
            .split(|o| *o == b'\n')
            .next()
            .and_then(|l| Enregistrement::analyser(l).ok())
            .map(|e| e.n);
        // (premier numéro, chemin du segment ou None pour le journal actif)
        let mut fichiers: Vec<(u64, Option<&PathBuf>)> =
            segments.iter().map(|(n, c)| (*n, Some(c))).collect();
        if let Some(p) = premier_actif {
            fichiers.push((p, None));
        }
        let mut l = Lecture {
            premier: fichiers.first().map(|f| f.0).unwrap_or(0),
            ..Default::default()
        };
        let debut = fichiers.iter().rposition(|f| f.0 <= apres + 1).unwrap_or(0);
        let derniers = fichiers.len().saturating_sub(1);
        for (i, (_, chemin)) in fichiers.iter().enumerate() {
            // Segments entièrement antérieurs : non relus ; le dernier fichier est toujours lu
            // (dernier numéro).
            if i < debut && i != derniers {
                continue;
            }
            let lu;
            let contenu: &[u8] = match chemin {
                None => &actif,
                Some(c) => {
                    lu = std::fs::read(c).with_context(|| format!("{}", c.display()))?;
                    &lu
                }
            };
            for ligne in contenu.split(|o| *o == b'\n').filter(|x| !x.is_empty()) {
                let e = Enregistrement::analyser(ligne)
                    .map_err(|c| anyhow::anyhow!("journal d'audit illisible : {c}"))?;
                l.dernier = e.n;
                if e.n > apres && l.lignes.len() < max {
                    l.lignes.push(ligne.to_vec());
                }
            }
        }
        Ok(l)
    }

    /// Contenu de tous les fichiers, segments rangés puis journal actif.
    pub fn contenus(&self) -> Result<Vec<Vec<u8>>> {
        let mut v = Vec::new();
        for (_, c) in self.segments()? {
            v.push(std::fs::read(&c).with_context(|| format!("{}", c.display()))?);
        }
        let actif = self.lire()?;
        if !actif.is_empty() || v.is_empty() {
            v.push(actif);
        }
        Ok(v)
    }

    /// Vérifie toute la chaîne (segments rangés puis journal actif) et l'accord avec les
    /// empreintes exportées.
    pub fn verifier_tout(&self, cle: &ClePublique, exports: &[PointExporte]) -> Result<Bilan> {
        let segments = self.segments()?;
        let mut fichiers: Vec<(String, Option<u64>, Vec<u8>)> = Vec::new();
        for (n, c) in &segments {
            fichiers.push((
                c.display().to_string(),
                Some(*n),
                std::fs::read(c).with_context(|| format!("{}", c.display()))?,
            ));
        }
        let actif = self.lire()?;
        if !actif.is_empty() || segments.is_empty() {
            fichiers.push((self.chemin().display().to_string(), None, actif));
        } else if !self.chemin().exists() {
            return Err(Defaut::Segment {
                fichier: self.chemin().display().to_string(),
                cause: "journal actif absent",
            }
            .into());
        }
        Ok(verifier_fichiers(&fichiers, cle, exports)?)
    }

    /// Rotation : si le premier enregistrement du journal actif date d'un jour (UTC) antérieur
    /// à `le` (ou si `forcer`), vérifie et scelle le journal actif, le range comme segment et
    /// ouvre le nouveau par une ancre signée. Renvoie le premier numéro du segment rangé.
    pub fn tourner(&self, cle: &CleAudit, le: u64, forcer: bool) -> Result<Option<u64>> {
        let _v = self.verrou()?;
        let mut f = self.ouvrir()?;
        let mut contenu = Vec::new();
        f.read_to_end(&mut contenu)?;
        let Some(premier) = premier_enr(&contenu) else {
            if contenu.is_empty() {
                return Ok(None);
            }
            bail!("journal d'audit : première ligne illisible (vérification requise)");
        };
        if !forcer && premier.le / 86400 >= le / 86400 {
            return Ok(None);
        }
        let dernier_est_point = matches!(
            Journal::dernier_enr(&mut f)?.map(|(_, _, e)| e.evenement),
            Some(Evenement::PointDeControle { .. })
        );
        if !dernier_est_point {
            // Vérifie toute la chaîne avant de signer quoi que ce soit.
            self.sceller_sous_verrou(&mut f, cle, le)?;
        } else {
            self.verifier_tout(&cle.publique(), &[])
                .map_err(|d| anyhow::anyhow!("journal d'audit altéré, pas de rotation : {d}"))?;
        }
        let (n, h, _) = Journal::dernier_enr(&mut f)?.context("journal d'audit vide")?;
        let ancre = Enregistrement {
            v: VERSION_SCHEMA,
            n: n + 1,
            le,
            acteur: "audit".into(),
            evenement: Evenement::SegmentOuvert {
                precedent: n,
                empreinte: h.clone(),
                cle: cle.publique().id(),
                signature: cle.signer(&message_ancre(n, &h))?,
            },
            prec: h,
        };
        let mut ligne = ancre.ligne()?;
        ligne.push(b'\n');
        // 1. nouveau journal à part
        let nouveau = self.chemin_nouveau();
        let _ = std::fs::remove_file(&nouveau);
        let mut g = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&nouveau)
            .context("nouveau journal d'audit")?;
        aligner_proprietaire(&g, self.dossier())?;
        g.write_all(&ligne)?;
        g.sync_all()?;
        // 2. segment rangé (jamais par-dessus un segment existant)
        let d = self.dossier_segments();
        if !d.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&d)
                .context("dossier des segments d'audit")?;
            aligner_proprietaire(&File::open(&d)?, self.dossier())?;
        }
        let cible = d.join(nom_segment(premier.n));
        if cible.exists() {
            bail!(
                "segment {} déjà présent : rotation refusée",
                cible.display()
            );
        }
        std::fs::rename(self.chemin(), &cible).context("rangement du segment d'audit")?;
        synchroniser_dossier(&d);
        // 3. nouveau journal en place
        std::fs::rename(&nouveau, self.chemin()).context("mise en place du journal d'audit")?;
        synchroniser_dossier(self.dossier());
        Ok(Some(premier.n))
    }

    /// Purge les segments rangés dont le dernier enregistrement (hors point de contrôle de
    /// fermeture, daté de la rotation) est antérieur à `avant`, du plus ancien
    /// au plus récent, si toute la chaîne est intègre. Chaque suppression est inscrite au journal
    /// actif (acteur `acteur`) AVANT d'être faite.
    pub fn purger_segments(
        &self,
        cle: &ClePublique,
        le: u64,
        avant: u64,
        acteur: &str,
    ) -> Result<Vec<SegmentPurge>> {
        let _v = self.verrou()?;
        let mut f = self.ouvrir()?;
        self.verifier_tout(cle, &[])
            .map_err(|e| anyhow::anyhow!("chaîne d'audit altérée, aucune purge : {e:#}"))?;
        let mut purges = Vec::new();
        for (premier, chemin) in self.segments()? {
            let mut s = File::open(&chemin)?;
            let (dernier, h, _) = Journal::dernier_enr(&mut s)?.context("segment d'audit vide")?;
            let mut contenu = Vec::new();
            s.seek(std::io::SeekFrom::Start(0))?;
            s.read_to_end(&mut contenu)?;
            let date = date_donnees(&contenu);
            if date >= avant {
                break;
            }
            Journal::ecrire(
                &mut f,
                le,
                acteur,
                Evenement::SegmentPurge {
                    premier,
                    dernier,
                    empreinte: h,
                },
            )?;
            std::fs::remove_file(&chemin).context("suppression d'un segment d'audit")?;
            synchroniser_dossier(&self.dossier_segments());
            purges.push(SegmentPurge {
                premier,
                dernier,
                dernier_le: date,
            });
        }
        Ok(purges)
    }
}

/// Vérifie une suite de fichiers (nom, premier numéro attendu d'après le nom, contenu).
fn verifier_fichiers(
    fichiers: &[(String, Option<u64>, Vec<u8>)],
    cle: &ClePublique,
    exports: &[PointExporte],
) -> Result<Bilan, Defaut> {
    let mut total: Option<Bilan> = None;
    for (nom, attendu, contenu) in fichiers {
        if attendu.is_some() && contenu.is_empty() {
            return Err(Defaut::Segment {
                fichier: nom.clone(),
                cause: "segment vide",
            });
        }
        let depart = total.as_ref().map(|b| (b.dernier, b.derniere.clone()));
        let b = verifier_segment(contenu, cle, depart.as_ref())?;
        if let Some(a) = attendu
            && *a != b.premier
        {
            return Err(Defaut::Segment {
                fichier: nom.clone(),
                cause: "nom différent du premier numéro du segment",
            });
        }
        total = Some(match total {
            None => b,
            Some(mut t) => {
                t.enregistrements += b.enregistrements;
                t.points.extend(b.points);
                t.non_scelles = if b.non_scelles == b.enregistrements {
                    t.non_scelles + b.non_scelles
                } else {
                    b.non_scelles
                };
                t.derniere = b.derniere;
                t.dernier = b.dernier;
                t.segments += 1;
                t
            }
        });
    }
    let total = total.unwrap_or(Bilan {
        enregistrements: 0,
        points: Vec::new(),
        non_scelles: 0,
        derniere: crate::empreinte_initiale(),
        dernier: 0,
        premier: 0,
        purges: 0,
        segments: 0,
        exports_purges: 0,
    });
    controler_exports(total, exports)
}
