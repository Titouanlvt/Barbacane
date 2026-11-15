//! Service `barbacane-optique` : socket Unix locale (une requête JSON par ligne, une réponse
//! par ligne), une seule opération longue à la fois, suivie par l'interface.
//!
//! Requêtes : `etat`, `lire` (disque → dossier d'entrée, toutes les sessions), `graver`
//! (dossier de préparation → disque, vérifié), `effacer` (complet, vérifié), `ejecter`.

use anyhow::{Result, bail};
use barbacane_optique::{ops, outil::Outil, toc::Media};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(default)]
struct Config {
    socket: PathBuf,
    socket_group: String,
    /// Lecteur optique
    device: PathBuf,
    /// Autres nœuds du même lecteur (scsi-generic) nécessaires à la gravure
    extra_devices: Vec<PathBuf>,
    /// Disque extrait ici (déclaré dans `[[src_local_dirs]]` d'usbsas)
    entree_dir: PathBuf,
    /// Fichiers sains à graver (dossier de préparation de l'analyseur)
    stage_dir: PathBuf,
    /// Relecture après gravure
    travail_dir: PathBuf,
    bwrap: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket: "/run/barbacane/optique.sock".into(),
            socket_group: "barbacane-kiosk".into(),
            device: "/dev/sr0".into(),
            extra_devices: vec![],
            entree_dir: "/var/lib/barbacane/optique/entree".into(),
            stage_dir: "/var/lib/barbacane/sortie".into(),
            travail_dir: "/var/lib/barbacane/optique/travail".into(),
            bwrap: Some("/usr/bin/bwrap".into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct Travail {
    op: String,
    phase: String,
    pourcent: f32,
    /// Secondes écoulées / estimation du temps restant
    ecoule: u64,
    restant: Option<u64>,
    fini: bool,
    erreur: Option<String>,
    fichiers: u64,
    mesures: Vec<ops::Mesure>,
    #[serde(skip)]
    debut: Option<Instant>,
}

struct Ctx {
    conf: Config,
    outil: Outil,
    travail: Arc<Mutex<Travail>>,
}

impl Ctx {
    fn lancer(
        &self,
        op: &str,
        f: impl FnOnce(&Outil, &mut dyn FnMut(f32, &str)) -> Result<Travail> + Send + 'static,
    ) -> Result<Value> {
        {
            let mut t = self.travail.lock().unwrap();
            if t.debut.is_some() && !t.fini {
                bail!("une opération est déjà en cours ({})", t.op);
            }
            *t = Travail {
                op: op.into(),
                phase: "démarrage".into(),
                debut: Some(Instant::now()),
                ..Default::default()
            };
        }
        let (o, t) = (self.outil.clone(), self.travail.clone());
        let op = op.to_string();
        std::thread::spawn(move || {
            let t2 = t.clone();
            let mut suivi = move |p: f32, ph: &str| {
                let mut x = t2.lock().unwrap();
                x.pourcent = p.clamp(0.0, 100.0);
                x.phase = ph.into();
            };
            let r = f(&o, &mut suivi);
            let mut x = t.lock().unwrap();
            x.fini = true;
            x.ecoule = x.debut.map_or(0, |d| d.elapsed().as_secs());
            match r {
                Ok(fin) => {
                    x.pourcent = 100.0;
                    x.phase = "terminé".into();
                    x.fichiers = fin.fichiers;
                    for m in &fin.mesures {
                        log::info!(
                            "mesure : {} : {} s, {} octets, {} ko/s",
                            m.operation,
                            m.secondes,
                            m.octets,
                            m.vitesse_ko_s
                        );
                    }
                    x.mesures = fin.mesures;
                    log::info!("{op} terminé en {} s ({} fichier(s))", x.ecoule, x.fichiers);
                }
                Err(e) => {
                    log::warn!("{op} : échec : {e:#}");
                    x.erreur = Some(format!("{e:#}"));
                }
            }
        });
        Ok(json!({"message": "opération lancée"}))
    }

    fn etat(&self) -> Value {
        let mut t = self.travail.lock().unwrap().clone();
        if let (Some(d), false) = (t.debut, t.fini) {
            t.ecoule = d.elapsed().as_secs();
            t.restant = (t.pourcent > 1.0)
                .then(|| (t.ecoule as f32 * (100.0 - t.pourcent) / t.pourcent) as u64);
        }
        // Pas d'interrogation du lecteur pendant une opération (il est occupé)
        let media: Option<(Media, Option<u32>)> = if t.debut.is_none() || t.fini {
            ops::identifier(&self.outil).ok()
        } else {
            None
        };
        let media = media.map(|(m, v)| {
            json!({
                "present": !m.absent(),
                "type": m.kind,
                "libelle": m.label(),
                "vierge": m.blank,
                "reinscriptible": m.rewritable(),
                "sessions": m.sessions,
                "donnees": m.data_sessions().count(),
                "capacite": m.capacity(),
                "vitesse_gravure_ko_s": v,
            })
        });
        json!({"disque": media, "travail": if t.debut.is_some() { serde_json::to_value(&t).unwrap_or_default() } else { Value::Null }})
    }

    fn handle(&self, req: Value) -> Result<Value> {
        match req["op"].as_str().unwrap_or("") {
            "etat" => Ok(self.etat()),
            "lire" => {
                let d = self.conf.entree_dir.clone();
                self.lancer("lecture", move |o, s| {
                    ops::vider(&d)?;
                    let n = ops::lire(o, &d, s)?;
                    Ok(Travail {
                        fichiers: n,
                        ..Default::default()
                    })
                })
            }
            "graver" => {
                let (src, w) = (self.conf.stage_dir.clone(), self.conf.travail_dir.clone());
                self.lancer("gravure", move |o, s| {
                    std::fs::create_dir_all(&w)?;
                    let mesures = ops::graver(o, &src, &w, s)?;
                    let n = ops::empreintes(&src)?.len() as u64;
                    Ok(Travail {
                        fichiers: n,
                        mesures,
                        ..Default::default()
                    })
                })
            }
            "effacer" => self.lancer("effacement", move |o, s| {
                let m = ops::effacer(o, s)?;
                Ok(Travail {
                    mesures: vec![m],
                    ..Default::default()
                })
            }),
            "vider_entree" => {
                ops::vider(&self.conf.entree_dir)?;
                Ok(json!({"message": "dossier d'entrée vidé"}))
            }
            "ejecter" => {
                ops::ejecter(&self.outil)?;
                Ok(json!({"message": "disque éjecté"}))
            }
            o => bail!("opération inconnue : {o}"),
        }
    }
}

fn serve_conn(ctx: &Ctx, s: UnixStream) -> Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = String::new();
    BufReader::new(std::io::Read::take(&s, 64 * 1024)).read_line(&mut line)?;
    let rep = match serde_json::from_str::<Value>(&line) {
        Ok(req) => ctx
            .handle(req)
            .unwrap_or_else(|e| json!({"error": format!("{e:#}")})),
        Err(e) => json!({"error": format!("requête invalide : {e}")}),
    };
    let mut out = serde_json::to_vec(&rep)?;
    out.push(b'\n');
    (&s).write_all(&out)?;
    Ok(())
}

fn gid_of(group: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|l| {
            let mut it = l.split(':');
            (it.next()? == group).then(|| it.nth(1)?.parse().ok())?
        })
}

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));
    let args: Vec<String> = std::env::args().collect();
    let conf_path = args
        .iter()
        .skip_while(|a| *a != "-c")
        .nth(1)
        .cloned()
        .unwrap_or_else(|| "/etc/barbacane/optique.toml".into());
    let conf: Config = match std::fs::read_to_string(&conf_path) {
        Ok(s) => toml::from_str(&s)?,
        Err(_) => Config::default(),
    };
    let mut outil = Outil::new(&conf.device);
    outil.bwrap = conf.bwrap.clone();
    outil.extra_devices = conf.extra_devices.clone();
    // Autotest du bac à sable (même leçon que l'analyseur : un échec doit se voir au journal)
    match outil.run(&["-version".into()], None, None, |_| ()) {
        Ok(_) => log::info!("bac à sable optique : OK"),
        Err(e) => log::error!("bac à sable optique INUTILISABLE : {e:#}"),
    }
    let ctx = Ctx {
        conf,
        outil,
        travail: Arc::default(),
    };
    let sock = &ctx.conf.socket;
    if let Some(p) = sock.parent() {
        std::fs::create_dir_all(p)?;
    }
    let _ = std::fs::remove_file(sock);
    let l = UnixListener::bind(sock)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660))?;
    if let Some(g) = gid_of(&ctx.conf.socket_group) {
        let _ = std::os::unix::fs::chown(sock, None, Some(g));
    }
    log::info!(
        "écoute sur {} (lecteur {})",
        sock.display(),
        ctx.conf.device.display()
    );
    std::thread::scope(|sc| {
        for s in l.incoming().flatten() {
            let ctx = &ctx;
            sc.spawn(move || {
                if let Err(e) = serve_conn(ctx, s) {
                    log::warn!("connexion : {e:#}");
                }
            });
        }
    });
    Ok(())
}
