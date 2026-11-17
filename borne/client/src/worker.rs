//! Fil de travail : tient la session usbsas (socket du service
//! usbsas-server), surveille les clés branchées et exécute les parcours de
//! `barbacane-parcours`. Il ne bloque jamais l'interface.

use barbacane_parcours::{self as parcours, Analyzer, Devices, Event, proto::common::UsbDevice};
use iced::futures::channel::mpsc::UnboundedSender;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;
use usbsas_comm::Comm;

type Usbsas = Comm<barbacane_parcours::proto::usbsas::Request, UnixStream, UnixStream>;

/// Ordres de l'interface.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Lire et analyser la clé
    Analyse(UsbDevice),
    /// Préparer puis écrire sur `dst` ; `wipe` : effacer `dst` d'abord (Blanchir)
    Write {
        src: UsbDevice,
        dst: UsbDevice,
        wipe: bool,
        /// Clé Ventoy reconstruite démarrable (écart n° 9)
        demarrable: bool,
        /// Clé Etcher / Rufus « mode DD » : son image officielle réécrite (écart n° 11)
        image: bool,
        job: String,
    },
    /// Écrire un dossier local (export admin) sur une clé
    Export { dst: UsbDevice },
}

/// Nouvelles pour l'interface.
#[derive(Debug, Clone)]
pub enum Ev {
    /// Canal d'ordres du fil de travail
    Ready(Sender<Cmd>),
    Connected(bool),
    Devices(Devices),
    Op(Event),
    Analysed(Result<std::sync::Arc<parcours::Analysis>, String>),
    Written(Result<u64, String>),
    Exported(Result<(), String>),
    /// Avancement d'une opération sur le disque optique (phase, %, secondes restantes)
    Optique(crate::optique::Avancement),
}

/// Chemins des dossiers locaux déclarés dans `[[src_local_dirs]]` d'usbsas.
#[derive(Clone)]
pub struct Dirs {
    pub stage: String,
    pub export: String,
    /// Socket de barbacane-optique et dossier où le disque est extrait
    pub optique_socket: String,
    pub optique_entree: String,
}

pub struct Worker {
    pub socket: String,
    dirs: Dirs,
    pub analyzer: Analyzer,
    out: UnboundedSender<Ev>,
    session: Option<Usbsas>,
    devices: Devices,
}

/// Lance le fil de travail ; les nouvelles arrivent sur `out`.
pub fn spawn(socket: String, dirs: Dirs, analyzer: Analyzer, out: UnboundedSender<Ev>) {
    let (tx, rx) = channel();
    let _ = out.unbounded_send(Ev::Ready(tx));
    std::thread::spawn(move || {
        Worker {
            socket,
            dirs,
            analyzer,
            out,
            session: None,
            devices: Devices::default(),
        }
        .run(rx)
    });
}

impl Worker {
    fn send(&self, ev: Ev) {
        let _ = self.out.unbounded_send(ev);
    }

    fn connect(&self) -> Option<Usbsas> {
        // usbsas-server se relance après chaque session : la socket réapparaît en quelques instants.
        let s = UnixStream::connect(format!("{}/usbsas.sock", self.socket.trim_end_matches('/')))
            .ok()?;
        let s2 = s.try_clone().ok()?;
        Some(Comm::new(s, s2))
    }

    /// Session usbsas prête (déjà ouverte ou nouvelle).
    fn session(&mut self) -> Option<&mut Usbsas> {
        if self.session.is_none() {
            self.session = self.connect();
            self.send(Ev::Connected(self.session.is_some()));
        }
        self.session.as_mut()
    }

    /// Session neuve pour une opération (l'ancienne est terminée par l'opération précédente).
    fn fresh(&mut self) -> Result<Usbsas, String> {
        if let Some(mut s) = self.session.take()
            && parcours::devices(&mut s).is_ok()
        {
            return Ok(s);
        }
        // Juste après la fin d'une session, la connexion peut encore aboutir chez l'ancien
        // processus usbsas qui se termine (« Connection reset by peer » au premier échange,
        // constaté après un effacement de 13 min) : la session n'est rendue qu'après une
        // première requête réussie.
        for _ in 0..50 {
            if let Some(mut s) = self.connect()
                && parcours::devices(&mut s).is_ok()
            {
                return Ok(s);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err("le service usbsas ne répond pas".into())
    }

    fn poll(&mut self) {
        let Some(s) = self.session() else { return };
        match parcours::devices(s) {
            Ok(d) => {
                self.devices = d.clone();
                self.send(Ev::Devices(d));
            }
            Err(e) => {
                log::warn!("liste des clés : {e}");
                self.session = None;
                self.send(Ev::Connected(false));
            }
        }
    }

    fn run(mut self, rx: Receiver<Cmd>) {
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(cmd) => self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => self.poll(),
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn handle(&mut self, cmd: Cmd) {
        let (etx, erx) = channel::<Event>();
        // Relais des événements de l'opération vers l'interface.
        let out = self.out.clone();
        let relay = std::thread::spawn(move || {
            for e in erx {
                let _ = out.unbounded_send(Ev::Op(e));
            }
        });
        match cmd {
            Cmd::Analyse(src) => {
                let r = self.analyse(&src, &etx);
                self.send(Ev::Analysed(
                    r.map(std::sync::Arc::new).map_err(|e| e.to_string()),
                ));
            }
            Cmd::Write {
                src,
                dst,
                wipe,
                demarrable,
                image,
                job,
            } => {
                let r = if image {
                    self.reecrire_image(&src, &job, &etx)
                } else {
                    self.write(&src, &dst, wipe, demarrable, &job, &etx)
                };
                self.send(Ev::Written(r.map_err(|e| e.to_string())));
            }
            Cmd::Export { dst } => {
                let r = self.export(&dst, &etx);
                self.send(Ev::Exported(r.map_err(|e| e.to_string())));
            }
        }
        drop(etx);
        let _ = relay.join();
    }

    fn analyse(
        &mut self,
        src: &UsbDevice,
        ev: &Sender<Event>,
    ) -> Result<parcours::Analysis, String> {
        if parcours::est_optique(src) {
            return self.analyse_optique(ev);
        }
        let mut s = self.fresh()?;
        let devs = parcours::devices(&mut s).map_err(|e| e.to_string())?;
        let id = devs.find(src, false).ok_or("la clé a été retirée")?;
        let sink = devs
            .sink
            .ok_or("configuration usbsas incomplète ([command] absent)")?;
        parcours::analyse(&mut s, &self.analyzer, id, sink, ev).map_err(|e| e.to_string())
    }

    /// Disque optique : barbacane-optique extrait TOUTES les sessions dans le dossier d'entrée,
    /// puis ce dossier suit le parcours d'une clé inconnue (usbsas → analyseur).
    fn analyse_optique(&mut self, ev: &Sender<Event>) -> Result<parcours::Analysis, String> {
        let sock = self.dirs.optique_socket.clone();
        let out = self.out.clone();
        crate::optique::executer(&sock, "lire", &mut |a| {
            let _ = out.unbounded_send(Ev::Optique(a));
        })
        .map_err(|e| format!("lecture du disque : {e}"))?;
        let mut s = self.fresh()?;
        let devs = parcours::devices(&mut s).map_err(|e| e.to_string())?;
        let entree = self.dirs.optique_entree.clone();
        let id = devs.local_dir(&entree).ok_or_else(|| {
            format!("configuration usbsas incomplète ([[src_local_dirs]] {entree})")
        })?;
        let sink = devs
            .sink
            .ok_or("configuration usbsas incomplète ([command] absent)")?;
        let r = parcours::analyse_dossier(&mut s, &self.analyzer, id, sink, ev)
            .map_err(|e| e.to_string());
        // Le contenu brut du disque n'a plus d'usage : seuls les fichiers sains sont préparés.
        let _ = crate::optique::requete(&sock, "vider_entree");
        r
    }

    fn write(
        &mut self,
        src: &UsbDevice,
        dst: &UsbDevice,
        wipe: bool,
        demarrable: bool,
        job: &str,
        ev: &Sender<Event>,
    ) -> Result<u64, String> {
        let n = self
            .analyzer
            .stage(job, &parcours::describe(src))
            .map_err(|e| e.to_string())?;
        if parcours::est_optique(dst) {
            // Gravure : effacement complet du disque, gravure à vitesse sûre, relecture sha256
            let out = self.out.clone();
            let t = crate::optique::executer(&self.dirs.optique_socket, "graver", &mut |a| {
                let _ = out.unbounded_send(Ev::Optique(a));
            })
            .map_err(|e| format!("gravure : {e}"))?;
            let _ = crate::optique::requete(&self.dirs.optique_socket, "ejecter");
            return Ok(t["fichiers"].as_u64().unwrap_or(n));
        }
        if !wipe {
            // usbsas mesure l'espace de travail libre au début de chaque session ; celle qui
            // attend a démarré avant que l'analyseur vide sa copie de travail (« Not enough
            // space » sur une clé de 9 Go) : elle est close, la suivante voit l'espace libéré.
            // (Un blanchiment passe déjà par une session d'effacement.)
            let mut s = self.fresh()?;
            parcours::terminer(&mut s);
        }
        if wipe {
            let mut s = self.fresh()?;
            let devs = parcours::devices(&mut s).map_err(|e| e.to_string())?;
            let id = devs.same_as_dst(dst).ok_or("la clé a été retirée")?;
            parcours::wipe(&mut s, id, ev).map_err(|e| format!("effacement : {e}"))?;
        }
        let stage = self.dirs.stage.clone();
        self.write_stage_mode(dst, ev, &stage, demarrable)?;
        Ok(n)
    }

    /// Clé Etcher / Rufus « mode DD » : la borne relit l'image de la clé, la compare à la liste
    /// des images officielles et, si elle y figure, efface la clé et réécrit exactement cette
    /// image (zone de démarrage comprise). Sinon : erreur claire, clé non modifiée.
    fn reecrire_image(
        &mut self,
        src: &UsbDevice,
        job: &str,
        ev: &Sender<Event>,
    ) -> Result<u64, String> {
        // Préparation des fichiers sains (non écrits ici) : vide la copie de travail
        let n = self
            .analyzer
            .stage(job, &parcours::describe(src))
            .map_err(|e| e.to_string())?;
        let images = parcours::images_officielles(parcours::LISTE_IMAGES);
        if images.is_empty() {
            return Err("aucune image officielle déclarée par l'administrateur".into());
        }
        let mut s = self.fresh()?;
        let devs = parcours::devices(&mut s).map_err(|e| e.to_string())?;
        let id = devs
            .same_as_dst(src)
            .or_else(|| devs.find(src, false))
            .ok_or("la clé a été retirée")?;
        parcours::reecrire_image(&mut s, id, &images, ev).map_err(|e| {
            format!("{e} — la clé n'a pas été modifiée ; choisissez « Blanchir la clé »")
        })?;
        Ok(n)
    }

    /// Écrit un dossier local déclaré dans `[[src_local_dirs]]` sur `dst`.
    fn write_stage(
        &mut self,
        dst: &UsbDevice,
        ev: &Sender<Event>,
        dir: &str,
    ) -> Result<(), String> {
        self.write_stage_mode(dst, ev, dir, false)
    }

    /// `demarrable` : clé Ventoy reconstruite (zone de démarrage de la borne, écart n° 9)
    fn write_stage_mode(
        &mut self,
        dst: &UsbDevice,
        ev: &Sender<Event>,
        dir: &str,
        demarrable: bool,
    ) -> Result<(), String> {
        let mut s = self.fresh()?;
        let devs = parcours::devices(&mut s).map_err(|e| e.to_string())?;
        let id = devs
            .find(dst, true)
            .or_else(|| devs.same_as_dst(dst))
            .ok_or("la clé de sortie a été retirée")?;
        let stage = devs
            .local_dir(dir)
            .ok_or_else(|| format!("configuration usbsas incomplète ([[src_local_dirs]] {dir})"))?;
        let w = if demarrable {
            parcours::write_demarrable
        } else {
            parcours::write
        };
        w(&mut s, stage, id, ev)
            .map(|_| ())
            .map_err(|e| format!("écriture : {e}"))
    }

    fn export(&mut self, dst: &UsbDevice, ev: &Sender<Event>) -> Result<(), String> {
        let export = self.dirs.export.clone();
        self.write_stage(dst, ev, &export)
    }
}
