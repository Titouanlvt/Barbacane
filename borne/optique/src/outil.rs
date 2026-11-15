//! Lancement confiné de `xorriso` (lecture, gravure, effacement) : bubblewrap sans réseau,
//! système en lecture seule, seul le lecteur (ou l'image de test) et le dossier de travail
//! visibles, limites de ressources. Le disque est hostile : son système de fichiers n'est
//! jamais monté par le noyau, il est lu en espace utilisateur dans ce bac à sable.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct Outil {
    pub xorriso: PathBuf,
    /// `None` : pas de bac à sable (tests unitaires seulement)
    pub bwrap: Option<PathBuf>,
    /// Lecteur (`/dev/sr0`) ou image ISO (tests)
    pub device: PathBuf,
    /// Périphériques SCSI génériques du même lecteur, rendus visibles pour la gravure
    pub extra_devices: Vec<PathBuf>,
    /// Taille maximale d'un fichier écrit par xorriso (octets)
    pub max_file: u64,
}

impl Outil {
    pub fn new(device: impl Into<PathBuf>) -> Self {
        Outil {
            xorriso: "/usr/bin/xorriso".into(),
            bwrap: Some("/usr/bin/bwrap".into()),
            device: device.into(),
            extra_devices: Vec::new(),
            max_file: 64 << 30,
        }
    }

    /// Le périphérique est-il un vrai lecteur (et non une image de test) ?
    pub fn is_drive(&self) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(&self.device)
            .map(|m| m.file_type().is_block_device() || m.file_type().is_char_device())
            .unwrap_or(false)
    }

    /// Commande xorriso confinée ; `rw` : dossier accessible en écriture (extraction), `ro` :
    /// dossier en lecture seule (fichiers à graver).
    pub fn command(&self, args: &[String], rw: Option<&Path>, ro: Option<&Path>) -> Command {
        let mut c = match &self.bwrap {
            Some(b) => {
                let mut c = Command::new(b);
                c.args([
                    "--unshare-all",
                    "--die-with-parent",
                    "--new-session",
                    "--cap-drop",
                    "ALL",
                    "--clearenv",
                    "--setenv",
                    "PATH",
                    "/usr/bin",
                    "--setenv",
                    "LANG",
                    "C.UTF-8",
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--symlink",
                    "usr/lib",
                    "/lib",
                    "--symlink",
                    "usr/lib64",
                    "/lib64",
                    "--symlink",
                    "usr/bin",
                    "/bin",
                    "--dev",
                    "/dev",
                    "--tmpfs",
                    "/tmp",
                ]);
                // Le lecteur (ou l'image) au même chemin que dehors : xorriso le désigne ainsi.
                // « -try » : un lecteur absent (débranché, pas encore détecté) ne doit pas empêcher
                // xorriso de démarrer ; il répond alors « aucun disque ».
                if self.is_drive() {
                    c.arg("--dev-bind-try").arg(&self.device).arg(&self.device);
                } else {
                    c.arg("--bind-try").arg(&self.device).arg(&self.device);
                }
                for d in &self.extra_devices {
                    c.arg("--dev-bind-try").arg(d).arg(d);
                }
                if let Some(d) = rw {
                    c.arg("--bind").arg(d).arg(d);
                }
                if let Some(d) = ro {
                    c.arg("--ro-bind").arg(d).arg(d);
                }
                c.arg("--").arg(&self.xorriso);
                c
            }
            None => Command::new(&self.xorriso),
        };
        c.args(["-abort_on", "FAILURE", "-return_with", "SORRY", "32"])
            .args(args);
        let fsize = self.max_file;
        unsafe {
            c.pre_exec(move || {
                let lim = libc::rlimit {
                    rlim_cur: fsize,
                    rlim_max: fsize,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &zero);
                Ok(())
            });
        }
        c
    }

    /// Lance xorriso et renvoie (réussite, toute la sortie), même en cas d'échec de xorriso
    /// (l'identification d'un disque en lecture seule en a besoin). Échec seulement si
    /// bubblewrap ou xorriso ne démarrent pas.
    pub fn run_brut(
        &self,
        args: &[String],
        rw: Option<&Path>,
        ro: Option<&Path>,
    ) -> Result<(bool, String)> {
        let out = self
            .command(args, rw, ro)
            .stdin(Stdio::null())
            .output()
            .context("lancement de xorriso")?;
        let all = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        if let Some(l) = all.lines().find(|l| l.starts_with("bwrap:")) {
            bail!("bac à sable indisponible ({l})");
        }
        Ok((out.status.success(), all))
    }

    /// Lance xorriso ; chaque ligne de sortie est passée à `ligne` (progression). Renvoie
    /// toute la sortie. Échec si xorriso sort en erreur ou si bubblewrap ne démarre pas.
    pub fn run(
        &self,
        args: &[String],
        rw: Option<&Path>,
        ro: Option<&Path>,
        mut ligne: impl FnMut(&str),
    ) -> Result<String> {
        let mut child = self
            .command(args, rw, ro)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("lancement de xorriso")?;
        let mut out = child.stdout.take().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        });
        let mut all = String::new();
        for l in BufReader::new(child.stderr.take().unwrap())
            .lines()
            .map_while(Result::ok)
        {
            ligne(&l);
            all.push_str(&l);
            all.push('\n');
        }
        let st = child.wait()?;
        let stdout = t.join().unwrap_or_default();
        all.push_str(&stdout);
        if let Some(l) = all.lines().find(|l| l.starts_with("bwrap:")) {
            bail!("bac à sable indisponible ({l})");
        }
        if !st.success() {
            let why = all
                .lines()
                .rfind(|l| l.contains("FAILURE") || l.contains("SORRY") || l.contains("FATAL"))
                .unwrap_or("erreur inconnue")
                .to_string();
            bail!("xorriso : {why}");
        }
        Ok(all)
    }
}

/// Progression signalée par xorriso (« UPDATE : Writing: … 34.5% » ou « Blanking ( 12.3% done »).
pub fn percent(l: &str) -> Option<f32> {
    if !l.contains("UPDATE") {
        return None;
    }
    let i = l.find('%')?;
    let debut = l[..i]
        .rfind(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map_or(0, |p| p + 1);
    l[debut..i].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::percent;

    #[test]
    fn progression() {
        assert_eq!(
            percent(
                "xorriso : UPDATE : Writing:      12345s   34.5%   fifo 100%  buf  50%    4.0xC"
            ),
            Some(34.5)
        );
        assert_eq!(
            percent("xorriso : UPDATE : Blanking  ( 12.3% done in 34 seconds )"),
            Some(12.3)
        );
        assert_eq!(percent("xorriso : NOTE : 50% de rien"), None);
    }
}
