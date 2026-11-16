//! Écrans et logique de l'interface Barbacane.
//!
//! Parcours : clé inconnue branchée → Copier / Blanchir → analyse (mots de
//! passe d'archives au clavier virtuel) → résumé → écriture → fin.

use crate::admin_ui::{self, AdminMsg, AdminUi};
use crate::anim;
use crate::barre;
use crate::config::Config;
use crate::dessin;
use crate::keyboard::{Input, Key};
use crate::mesure::{self, Mesure};
use crate::style;
use crate::worker::{self, Cmd, Ev};
use barbacane_parcours::est_optique;
use barbacane_parcours::{
    Analysis, Analyzer, Devices, Event, PasswordRequest,
    proto::common::{Status, UsbDevice},
};
use iced::widget::{Column, Space, button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Subscription, Task};
use std::sync::Arc;
use std::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Copier,
    Blanchir,
    /// Graver les fichiers sains sur un disque optique réinscriptible
    Graver,
}

#[derive(Debug)]
pub enum Screen {
    Connexion,
    Accueil,
    Choix,
    Analyse,
    MotDePasse(PasswordRequest),
    Resume,
    Sortie,
    ConfirmBlanchir,
    Ecriture,
    Fin(u64),
    Erreur { message: String, retry: bool },
    Admin,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Worker(Ev),
    Choisir(Mode),
    Key(Key),
    Valider,
    Ignorer,
    Repondu(Result<(), String>),
    VersSortie,
    Ecrire,
    Blanchir,
    Reessayer,
    Terminer,
    Etat(Result<serde_json::Value, String>),
    Tick,
    Admin(AdminMsg),
    /// Interrogation périodique du lecteur optique
    OptiqueTick,
    Optique(Result<crate::optique::Etat, String>),
    Ejecter,
    Fait(Result<serde_json::Value, String>),
    /// Image suivante d'une animation (30 images/s au plus)
    Anim,
    /// Bouton « Maintenir pour effacer » enfoncé (true) ou relâché (false)
    Maintien(bool),
}

pub struct App {
    pub cfg: Config,
    pub screen: Screen,
    pub cmd: Option<Sender<Cmd>>,
    pub devices: Devices,
    src: Option<UsbDevice>,
    dst: Option<UsbDevice>,
    mode: Mode,
    progress: Option<(Status, u64, u64)>,
    /// Vitesse et temps restant de l'étape en cours
    mesure: Mesure,
    analysis_progress: (u64, u64, u64),
    input: Input,
    analysis: Option<Arc<Analysis>>,
    pub analyzer: Analyzer,
    /// État renvoyé par barbacane-admind (clés enrôlées, âge des signatures…)
    pub etat: Option<serde_json::Value>,
    dst_refused: Option<String>,
    pub admin: AdminUi,
    /// Dernier état connu du lecteur optique (None : pas de lecteur ou service absent)
    optique: Option<crate::optique::Etat>,
    /// Avancement de l'opération en cours sur le disque
    optique_avance: Option<crate::optique::Avancement>,
    /// Disque → disque : le disque analysé a bien été retiré (échange effectué)
    echange_fait: bool,
    /// Disque écarté (« Abandonner », fin d'opération) : ignoré jusqu'à son retrait, pour ne pas
    /// le reprendre en boucle et laisser choisir une clé quand un disque reste dans le lecteur
    disque_ecarte: bool,
    /// Réponses « pas de disque » consécutives (deux avant de conclure au retrait : évite un
    /// clignotement si une interrogation du lecteur échoue)
    absent_n: u8,
    /// Dernière erreur du service optique journalisée (un message par changement)
    optique_err: Option<String>,
    /// Entrée dans l'écran courant (départ des animations de la charte)
    depuis: std::time::Instant,
    /// Accueil atteint depuis l'écran « Terminé » : animation de retrait des clés
    retour_fin: bool,
    /// « Maintenir pour effacer » : début de l'appui
    maintien: Option<std::time::Instant>,
    /// Barre de progression : dernière valeur affichée (jamais en recul) et son heure
    barre_val: f32,
    barre_maj: std::time::Instant,
}

pub fn run(cfg: Config) -> iced::Result {
    iced::application(move || App::new(cfg.clone()), App::update, App::view)
        .title(|a: &App| a.cfg.title.clone())
        // Polices de la charte, embarquées : rien ne vient du réseau ni du système.
        .font(include_bytes!("../ressources/polices/AtkinsonHyperlegible-Regular.ttf").as_slice())
        .font(include_bytes!("../ressources/polices/AtkinsonHyperlegible-Bold.ttf").as_slice())
        .font(include_bytes!("../ressources/polices/BarlowCondensed-SemiBold.ttf").as_slice())
        .font(include_bytes!("../ressources/polices/BarlowCondensed-Bold.ttf").as_slice())
        .font(include_bytes!("../ressources/polices/JetBrainsMono.ttf").as_slice())
        .default_font(style::CORPS)
        .theme(|_: &App| style::theme_iced())
        .subscription(App::subscription)
        .run()
}

/// Libellé d'une étape usbsas.
fn etape(s: Status) -> &'static str {
    match s {
        Status::ReadSrc => "Lecture de la clé",
        Status::UploadAv => "Envoi des fichiers à l'analyseur",
        Status::Analyze => "Analyse des fichiers",
        Status::MkFs => "Préparation de la clé de destination",
        Status::MkArchive | Status::ExecCmd => "Fin de la lecture",
        Status::WriteDst => "Écriture sur la clé",
        Status::Wipe => "Effacement complet de la clé",
        Status::AllDone => "Terminé",
        _ => "Traitement en cours",
    }
}

impl App {
    fn new(cfg: Config) -> (Self, Task<Msg>) {
        let analyzer = Analyzer::new(&cfg.analyzer_url);
        let admin = AdminUi::new(cfg.admin_socket.clone());
        let app = App {
            cfg,
            screen: Screen::Connexion,
            cmd: None,
            devices: Devices::default(),
            src: None,
            dst: None,
            mode: Mode::Copier,
            progress: None,
            mesure: Mesure::default(),
            analysis_progress: (0, 0, 0),
            input: Input::text(128),
            analysis: None,
            analyzer,
            etat: None,
            dst_refused: None,
            admin,
            optique: None,
            optique_avance: None,
            echange_fait: false,
            disque_ecarte: false,
            absent_n: 0,
            optique_err: None,
            depuis: std::time::Instant::now(),
            retour_fin: false,
            maintien: None,
            barre_val: 0.0,
            barre_maj: std::time::Instant::now(),
        };
        let t = app.refresh_etat();
        (app, t)
    }

    pub fn refresh_etat(&self) -> Task<Msg> {
        let sock = self.cfg.admin_socket.clone();
        Task::perform(
            crate::admin::call(sock, serde_json::json!({"op": "status"})),
            Msg::Etat,
        )
    }

    fn subscription(&self) -> Subscription<Msg> {
        let w = Subscription::run_with(
            (
                self.cfg.usbsas_socket.clone(),
                self.cfg.stage_dir.clone(),
                self.cfg.export_dir.clone(),
                self.cfg.analyzer_url.clone(),
                self.cfg.optique_socket.clone(),
                self.cfg.optique_entree.clone(),
            ),
            |(sock, stage, export, url, optique_socket, optique_entree)| {
                let (sock, stage, export, url) =
                    (sock.clone(), stage.clone(), export.clone(), url.clone());
                let (optique_socket, optique_entree) =
                    (optique_socket.clone(), optique_entree.clone());
                iced::stream::channel(
                    100,
                    move |mut out: iced::futures::channel::mpsc::Sender<Ev>| async move {
                        use iced::futures::{SinkExt, StreamExt};
                        let (tx, mut rx) = iced::futures::channel::mpsc::unbounded();
                        worker::spawn(
                            sock,
                            worker::Dirs {
                                stage,
                                export,
                                optique_socket,
                                optique_entree,
                            },
                            Analyzer::new(&url),
                            tx,
                        );
                        while let Some(ev) = rx.next().await {
                            if out.send(ev).await.is_err() {
                                break;
                            }
                        }
                    },
                )
            },
        )
        .map(Msg::Worker);
        let tick = iced::time::every(std::time::Duration::from_secs(60)).map(|_| Msg::Tick);
        let mut subs = vec![w, tick];
        if let Some(d) = self.anime() {
            subs.push(iced::time::every(d).map(|_| Msg::Anim));
        }
        if !self.cfg.optique_socket.is_empty() {
            subs.push(
                iced::time::every(std::time::Duration::from_secs(2)).map(|_| Msg::OptiqueTick),
            );
        }
        Subscription::batch(subs)
    }

    fn send(&self, c: Cmd) {
        if let Some(tx) = &self.cmd {
            let _ = tx.send(c);
        }
    }

    /// Mode « clés enrôlées » : liste blanche des clés de sortie (None : toute clé acceptée).
    fn enrolled(&self) -> Option<Vec<serde_json::Value>> {
        let e = self.etat.as_ref()?;
        if e["enrolled_mode"].as_bool() != Some(true) {
            return None;
        }
        Some(e["enrolled"].as_array().cloned().unwrap_or_default())
    }

    fn is_enrolled(&self, d: &UsbDevice) -> bool {
        match self.enrolled() {
            None => true,
            Some(list) => list.iter().any(|k| {
                k["vendorid"].as_u64() == Some(d.vendorid as u64)
                    && k["productid"].as_u64() == Some(d.productid as u64)
                    && k["serial"].as_str() == Some(d.serial.as_str())
            }),
        }
    }

    fn same(a: &UsbDevice, b: &UsbDevice) -> bool {
        a.busnum == b.busnum && a.devnum == b.devnum
    }

    fn on_devices(&mut self, d: Devices) {
        self.devices = d;
        let first_src = self.devices.sources().next().map(|(_, u)| u.clone());
        match &self.screen {
            Screen::Connexion => self.screen = Screen::Accueil,
            Screen::Accueil => {
                if let Some(s) = first_src {
                    self.src = Some(s);
                    self.screen = Screen::Choix;
                }
            }
            Screen::Choix | Screen::Resume => {
                // Disque optique : sa présence est suivie par on_optique (pas une clé USB).
                let still = self.src.as_ref().is_some_and(|s| {
                    est_optique(s) || self.devices.sources().any(|(_, u)| Self::same(u, s))
                });
                if !still {
                    self.reset();
                }
            }
            Screen::Sortie if self.mode == Mode::Graver => (),
            Screen::Sortie => {
                let src = self.src.clone();
                let cand = self
                    .devices
                    .destinations()
                    .map(|(_, u)| u.clone())
                    .find(|u| src.as_ref().is_none_or(|s| !Self::same(u, s)));
                self.dst_refused = None;
                self.dst = None;
                if let Some(c) = cand {
                    if self.is_enrolled(&c) {
                        self.dst = Some(c);
                    } else {
                        self.dst_refused = Some(format!(
                            "Cette clé ({}) n'est pas enrôlée : elle ne peut pas servir de clé de destination.",
                            barbacane_parcours::describe(&c)
                        ));
                    }
                }
            }
            Screen::Fin(_) if self.devices.usb.is_empty() => {
                self.reset();
            }
            _ => (),
        }
    }

    /// Nouvel état du lecteur optique.
    fn on_optique(&mut self, e: Option<crate::optique::Etat>) {
        let Some(e) = e else {
            self.optique = None;
            return;
        };
        let occupe = e
            .travail
            .as_ref()
            .is_some_and(|t| t["fini"].as_bool() != Some(true));
        self.absent_n = if e.present {
            0
        } else {
            self.absent_n.saturating_add(1)
        };
        let retire = self.absent_n >= 2;
        if retire {
            self.disque_ecarte = false;
        }
        match &self.screen {
            // Un disque de données inséré est une source inconnue, comme une clé.
            Screen::Accueil if e.present && e.donnees && !occupe && !self.disque_ecarte => {
                self.src = Some(barbacane_parcours::optique(&e.libelle));
                self.screen = Screen::Choix;
            }
            // Disque retiré avant le choix : retour à l'accueil
            Screen::Choix if self.src.as_ref().is_some_and(est_optique) && retire => {
                self.optique = Some(e);
                self.reset();
                return;
            }
            _ => (),
        }
        if self.screen_sortie_graver() {
            if self.src.as_ref().is_some_and(est_optique) && retire {
                self.echange_fait = true;
            }
            self.optique = Some(e);
            self.choisir_disque();
        } else {
            self.optique = Some(e);
        }
    }

    fn screen_sortie_graver(&self) -> bool {
        matches!(self.screen, Screen::Sortie) && self.mode == Mode::Graver
    }

    /// Destination « disque » : retenue seulement si elle est utilisable.
    fn choisir_disque(&mut self) {
        if !self.screen_sortie_graver() {
            return;
        }
        self.dst = None;
        self.dst_refused = None;
        if self.enrolled().is_some() {
            self.dst_refused = Some(
                "Le mode « clés enrôlées » est actif : seules les clés enrôlées sont acceptées en sortie, \
                 la gravure sur disque n'est pas autorisée."
                    .into(),
            );
            return;
        }
        let Some(e) = &self.optique else { return };
        let attente = self.src.as_ref().is_some_and(est_optique) && !self.echange_fait;
        if attente || !e.present {
            return;
        }
        if !e.reinscriptible {
            self.dst_refused = Some(format!(
                "Ce disque ({}) n'est pas réinscriptible : utilisez un CD-RW, DVD-RW, DVD+RW ou BD-RE.",
                e.libelle
            ));
            return;
        }
        self.dst = Some(barbacane_parcours::optique(&e.libelle));
    }

    /// Ordre simple au service optique (éjection…), sans bloquer l'interface.
    fn optique_op(&self, op: &'static str) -> Task<Msg> {
        let sock = self.cfg.optique_socket.clone();
        Task::perform(
            smol::unblock(move || crate::optique::requete(&sock, op)),
            Msg::Fait,
        )
    }

    fn reset(&mut self) {
        // Seul le disque qui vient d'être traité est écarté : un disque déjà présent au
        // démarrage (ou inséré pendant une session clé) doit être proposé.
        if self.src.as_ref().is_some_and(est_optique)
            && self.optique.as_ref().is_some_and(|e| e.present)
        {
            self.disque_ecarte = true;
        }
        self.screen = Screen::Accueil;
        self.src = None;
        self.dst = None;
        self.analysis = None;
        self.progress = None;
        self.dst_refused = None;
        self.input = Input::text(128);
    }

    fn update(&mut self, m: Msg) -> Task<Msg> {
        let avant = std::mem::discriminant(&self.screen);
        let etait_fin = matches!(self.screen, Screen::Fin(_));
        let etape_avant = self.progress.map(|(s, _, _)| s);
        let t = self.maj(m);
        if std::mem::discriminant(&self.screen) != avant {
            self.depuis = std::time::Instant::now();
            self.retour_fin = etait_fin && matches!(self.screen, Screen::Accueil);
            self.maintien = None;
        }
        // Barre : jamais en recul ; repart à chaque écran ou étape ; horodatée à chaque avancée
        // (au-delà de 30 s sans avancée, le message « fichier volumineux » s'affiche).
        let f = self.fraction().unwrap_or(0.0);
        let etape = self.progress.map(|(s, _, _)| s);
        let nouvelle = std::mem::discriminant(&self.screen) != avant || etape != etape_avant;
        if nouvelle || f > self.barre_val + 0.0005 {
            self.barre_val = f;
            self.barre_maj = std::time::Instant::now();
        }
        t
    }

    fn maj(&mut self, m: Msg) -> Task<Msg> {
        match m {
            Msg::Worker(ev) => self.on_worker(ev),
            Msg::Choisir(mode) => {
                if let Some(src) = self.src.clone() {
                    self.mode = mode;
                    self.progress = None;
                    self.optique_avance = None;
                    self.analysis_progress = (0, 0, 0);
                    self.screen = Screen::Analyse;
                    self.send(Cmd::Analyse(src));
                }
                Task::none()
            }
            Msg::Key(k) => {
                self.input.press(k);
                Task::none()
            }
            Msg::Valider | Msg::Ignorer => {
                let Screen::MotDePasse(req) = &self.screen else {
                    return Task::none();
                };
                let pw = matches!(m, Msg::Valider).then(|| self.input.value.to_string());
                let (an, job) = (self.analyzer.clone(), req.job.clone());
                self.input = Input::text(128);
                self.screen = Screen::Analyse;
                Task::perform(
                    smol::unblock(move || {
                        an.answer(&job, pw.as_deref()).map_err(|e| e.to_string())
                    }),
                    Msg::Repondu,
                )
            }
            Msg::Repondu(r) => {
                if let Err(e) = r {
                    log::warn!("réponse mot de passe : {e}");
                }
                Task::none()
            }
            Msg::VersSortie => {
                self.dst = None;
                self.dst_refused = None;
                self.echange_fait = false;
                self.screen = Screen::Sortie;
                // Disque → disque : le disque analysé est éjecté pour l'échange
                if self.mode == Mode::Graver && self.src.as_ref().is_some_and(est_optique) {
                    return self.optique_op("ejecter");
                }
                self.choisir_disque();
                Task::none()
            }
            Msg::Ecrire => self.start_write(false),
            Msg::Blanchir => match self.screen {
                Screen::Resume => {
                    self.screen = Screen::ConfirmBlanchir;
                    Task::none()
                }
                _ => self.start_write(true),
            },
            Msg::Reessayer => self.start_write(false),
            Msg::Terminer => {
                self.reset();
                Task::none()
            }
            Msg::Etat(r) => {
                match r {
                    Ok(v) => {
                        // Préférences d'affichage (thème Nuit, animations réduites)
                        let p = &v["preferences"];
                        style::set_nuit(p["theme"].as_str() == Some("nuit"));
                        style::set_animations_reduites(
                            p["animations_reduites"].as_bool() == Some(true),
                        );
                        self.etat = Some(v)
                    }
                    Err(e) => log::warn!("état admin : {e}"),
                }
                Task::none()
            }
            Msg::Tick => self.refresh_etat(),
            Msg::Anim => {
                // « Maintenir pour effacer » : 2 s d'appui continu valent confirmation.
                if self
                    .maintien
                    .is_some_and(|d| d.elapsed() >= std::time::Duration::from_secs(2))
                {
                    self.maintien = None;
                    return self.maj(Msg::Blanchir);
                }
                Task::none()
            }
            Msg::Maintien(appui) => {
                self.maintien = if appui && matches!(self.screen, Screen::ConfirmBlanchir) {
                    self.maintien.or(Some(std::time::Instant::now()))
                } else {
                    None
                };
                Task::none()
            }
            Msg::OptiqueTick => Task::perform(
                crate::optique::etat_async(self.cfg.optique_socket.clone()),
                Msg::Optique,
            ),
            Msg::Optique(r) => {
                let err = r.as_ref().err().cloned();
                if err != self.optique_err {
                    if let Some(e) = &err {
                        log::warn!("lecteur optique : {e}");
                    } else {
                        log::info!("lecteur optique : service joignable");
                    }
                    self.optique_err = err;
                }
                self.on_optique(r.ok());
                Task::none()
            }
            Msg::Ejecter => self.optique_op("ejecter"),
            Msg::Fait(r) => {
                if let Err(e) = r {
                    log::warn!("lecteur optique : {e}");
                }
                Task::none()
            }
            Msg::Admin(am) => admin_ui::update(self, am),
        }
    }

    fn start_write(&mut self, wipe: bool) -> Task<Msg> {
        let (Some(src), Some(an)) = (self.src.clone(), self.analysis.clone()) else {
            return Task::none();
        };
        let dst = match self.mode {
            Mode::Blanchir => src.clone(),
            Mode::Copier | Mode::Graver => match self.dst.clone() {
                Some(d) => d,
                None => return Task::none(),
            },
        };
        self.progress = None;
        self.optique_avance = None;
        self.screen = Screen::Ecriture;
        self.send(Cmd::Write {
            src,
            dst,
            wipe,
            job: an.report.id.clone(),
        });
        Task::none()
    }

    fn on_worker(&mut self, ev: Ev) -> Task<Msg> {
        match ev {
            Ev::Ready(tx) => self.cmd = Some(tx),
            Ev::Connected(false) => {
                if matches!(self.screen, Screen::Accueil | Screen::Choix) {
                    self.screen = Screen::Connexion;
                }
            }
            Ev::Connected(true) => (),
            Ev::Devices(d) => self.on_devices(d),
            Ev::Op(Event::Progress {
                status,
                current,
                total,
            }) => {
                if self.progress.is_none_or(|(s, _, _)| s != status) {
                    self.mesure.vider();
                }
                self.mesure.ajouter(std::time::Instant::now(), current);
                self.progress = Some((status, current, total));
            }
            Ev::Op(Event::Analysis {
                done,
                total,
                scanned,
            }) => self.analysis_progress = (done, total, scanned),
            Ev::Op(Event::Password(req)) => {
                if matches!(self.screen, Screen::Analyse | Screen::MotDePasse(_)) {
                    self.input = Input::text(128);
                    self.screen = Screen::MotDePasse(req);
                }
            }
            Ev::Op(Event::PasswordDone) => {
                if matches!(self.screen, Screen::MotDePasse(_)) {
                    self.screen = Screen::Analyse;
                }
            }
            Ev::Analysed(r) if matches!(self.screen, Screen::Admin) => {
                return admin_ui::analysed(self, r.map(|_| ()));
            }
            Ev::Analysed(Ok(a)) => {
                self.analysis = Some(a);
                self.screen = Screen::Resume;
            }
            Ev::Analysed(Err(e)) => {
                self.screen = Screen::Erreur {
                    message: format!(
                        "L'analyse n'a pas pu aboutir : {e}. Aucun fichier n'a été copié."
                    ),
                    retry: false,
                }
            }
            Ev::Written(Ok(n)) => {
                self.screen = Screen::Fin(n);
                // Disque source rendu à l'utilisateur (la gravure éjecte déjà le disque gravé)
                if self.src.as_ref().is_some_and(est_optique) {
                    return self.optique_op("ejecter");
                }
            }
            Ev::Written(Err(e)) => {
                self.screen = Screen::Erreur {
                    message: match self.mode {
                        Mode::Blanchir => format!(
                            "Le blanchiment a échoué : {e}.\nLa clé a peut-être été effacée sans être réécrite : ne l'utilisez pas en l'état. \
                             Laissez-la branchée et réessayez l'écriture."
                        ),
                        Mode::Copier => format!(
                            "L'écriture sur la clé de destination a échoué : {e}.\nNe l'utilisez pas en l'état ; réessayez."
                        ),
                        Mode::Graver => format!(
                            "La gravure du disque a échoué : {e}.\nNe l'utilisez pas en l'état ; réessayez, ou essayez un autre disque."
                        ),
                    },
                    retry: true,
                }
            }
            Ev::Exported(r) => return admin_ui::exported(self, r),
            Ev::Optique(a) => self.optique_avance = Some(a),
        }
        Task::none()
    }

    // ---------------------------------------------------------------- vue

    fn view(&self) -> Element<'_, Msg> {
        let body: Element<Msg> = match &self.screen {
            Screen::Connexion => {
                // Charte : le logo se construit, puis « Préparation de la borne… » tant que les
                // services ne répondent pas ; au-delà de 2 min, le service en cause est nommé.
                let logo = if style::est_nuit() { LOGO_NUIT } else { LOGO };
                let mut c = column![dessin::demarrage(self.avancement(2200), logo, 170.0)];
                if self.depuis.elapsed().as_secs() < 120 {
                    c = c.push(texte("Préparation de la borne…"));
                } else {
                    c = c
                        .push(titre("La borne n'est pas prête."))
                        .push(texte("Prévenez l'administrateur."))
                        .push(
                            text("usbsas-server (lecture des clés USB)")
                                .size(style::PETIT)
                                .font(style::MONO)
                                .color(style::c().encre_douce),
                        );
                }
                centre(c)
            }
            Screen::Accueil => centre(column![
                // Charte : en attente, la clé invite à entrer ; après une copie, les clés
                // repartent et la herse se referme (1,5 s), puis l'attente reprend.
                if self.retour_fin && self.depuis.elapsed().as_millis() < 1500 {
                    dessin::retrait(self.avancement(1500), 170.0)
                } else {
                    dessin::attente(self.depuis.elapsed().as_secs_f32(), 170.0)
                },
                // Charte : « clé à analyser » / « disque à analyser » ; les deux si un lecteur existe
                titre(if self.optique.is_some() {
                    "Insérez la clé ou le disque à analyser"
                } else {
                    "Insérez la clé à analyser"
                }),
                texte(if self.optique.is_some() {
                    "sur le port d'entrée ou dans le lecteur de la borne."
                } else {
                    "sur le port d'entrée de la borne."
                }),
                Space::new().height(30),
                petit(
                    "Tous les fichiers seront analysés, y compris le contenu des archives.\nSeuls les fichiers sains seront copiés."
                ),
            ]),
            Screen::Choix => self.view_choix(),
            Screen::Analyse => self.view_progress("Analyse en cours", "Ne retirez pas la clé."),
            Screen::MotDePasse(req) => self.view_password(req),
            Screen::Resume => self.view_resume(),
            Screen::Sortie => self.view_sortie(),
            Screen::ConfirmBlanchir => centre(column![
                titre("Blanchir cette clé ?"),
                carte(column![
                    texte_c(
                        "La clé va être ENTIÈREMENT EFFACÉE, puis seuls les fichiers sains y seront réécrits.",
                        style::c().menace
                    ),
                    texte(&format!(
                        "{} fichier(s) seront réécrits.",
                        self.analysis
                            .as_ref()
                            .map(|a| a.report.copied().count())
                            .unwrap_or(0)
                    )),
                    petit("Les fichiers refusés seront définitivement supprimés de la clé."),
                ]),
                Space::new().height(20),
                row![
                    bouton("Annuler", Msg::Terminer, style::secondaire),
                    self.maintenir("Maintenir pour effacer"),
                ]
                .spacing(30)
                .align_y(Alignment::Center),
                petit("Gardez le bouton enfoncé 2 secondes ; le relâcher avant annule."),
            ]),
            Screen::Ecriture => {
                let disque =
                    self.src.as_ref().is_some_and(est_optique) || self.mode == Mode::Graver;
                self.view_progress(
                    match self.mode {
                        Mode::Copier => "Écriture sur la clé de destination",
                        Mode::Graver => "Gravure du disque",
                        Mode::Blanchir if disque => "Blanchiment du disque",
                        Mode::Blanchir => "Blanchiment de la clé",
                    },
                    if disque {
                        "Ne retirez ni la clé ni le disque."
                    } else {
                        "Ne retirez aucune clé."
                    },
                )
            }
            Screen::Fin(n) => centre(column![
                dessin::sain(self.avancement(500), 130.0),
                titre("Terminé"),
                texte(&format!(
                    "{n} fichier(s) sain(s) écrit(s), avec le rapport (rapport-barbacane-…txt / .html)."
                )),
                texte("Vous pouvez retirer les clés."),
                Space::new().height(20),
                bouton("Nouveau transfert", Msg::Terminer, style::primaire),
            ]),
            Screen::Erreur { message, retry } => {
                let mut b = row![bouton(
                    "Recommencer depuis le début",
                    Msg::Terminer,
                    style::secondaire
                )]
                .spacing(30);
                if *retry {
                    b = b.push(bouton(
                        "Réessayer l'écriture",
                        Msg::Reessayer,
                        style::primaire,
                    ));
                }
                centre(column![
                    dessin::illisible(self.avancement(600), 130.0),
                    titre("Une erreur est survenue"),
                    carte(column![texte(message)]),
                    Space::new().height(20),
                    b,
                ])
            }
            Screen::Admin => admin_ui::view(self),
        };
        let page = column![
            self.view_header(),
            self.view_etapes(),
            container(body)
                .padding(iced::Padding {
                    top: 30.0,
                    bottom: 30.0,
                    // Charte : le nouvel écran arrive de 24 px à droite (300 ms).
                    left: 30.0 + anim::arrivee(self.avancement(300)),
                    right: 30.0,
                })
                .width(Length::Fill)
                .height(Length::Fill),
            self.view_footer()
        ];
        container(page)
            .style(style::fond)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_header(&self) -> Element<'_, Msg> {
        let mut r = row![
            icone(LOGO_NUIT, 52.0),
            text(self.cfg.title.to_uppercase())
                .size(34)
                .font(style::TITRE_POLICE)
                .color(style::c().sur_bandeau),
            Space::new().width(Length::Fill)
        ]
        .spacing(14)
        .align_y(Alignment::Center);
        let age = self
            .etat
            .as_ref()
            .and_then(|e| e["signatures_age_days"].as_u64());
        match age {
            Some(a) if a > self.cfg.signatures_max_age_days => r = r.push(
                container(
                    text(format!(
                        "⚠ Signatures antivirales anciennes ({a} jours) : prévenez l'administrateur"
                    ))
                    .size(style::PETIT)
                    .shaping(text::Shaping::Advanced),
                )
                .padding(8)
                .style(style::alerte),
            ),
            Some(a) => {
                r = r.push(
                    text(format!("Signatures antivirales : {a} jour(s)"))
                        .size(style::PETIT)
                        .color(style::c().sur_bandeau),
                )
            }
            None if self.etat.is_some() => {
                r = r.push(
                    container(
                        text("⚠ Base antivirale absente ou illisible : prévenez l'administrateur")
                            .size(style::PETIT)
                            .shaping(text::Shaping::Advanced),
                    )
                    .padding(8)
                    .style(style::alerte),
                )
            }
            None => (),
        }
        container(r)
            .padding([14, 30])
            .style(style::bandeau)
            .width(Length::Fill)
            .into()
    }

    fn view_footer(&self) -> Element<'_, Msg> {
        let admin_ok = matches!(
            self.screen,
            Screen::Accueil | Screen::Connexion | Screen::Choix
        );
        let mut adm = button(text("Administration").size(style::PETIT)).style(style::discret);
        if admin_ok {
            adm = adm.on_press(Msg::Admin(AdminMsg::Ouvrir));
        }
        let mut r = row![
            petit(&format!(
                "Barbacane {} — station blanche hors ligne",
                env!("CARGO_PKG_VERSION")
            )),
            Space::new().width(Length::Fill),
        ]
        .align_y(Alignment::Center);
        if self.enrolled().is_some() {
            r = r
                .push(petit("Mode clés enrôlées"))
                .push(Space::new().width(20));
        }
        container(r.push(adm))
            .padding([6, 30])
            .width(Length::Fill)
            .into()
    }

    fn view_choix(&self) -> Element<'_, Msg> {
        let d = self
            .src
            .as_ref()
            .map(barbacane_parcours::describe)
            .unwrap_or_default();
        let disque = self.src.as_ref().is_some_and(est_optique);
        let mut choix = row![grand_choix(
            "Copier vers une clé de destination",
            if disque {
                "Toutes les sessions du disque sont analysées ; les fichiers sains sont copiés sur une clé effacée et formatée."
            } else {
                "Les fichiers sains sont copiés sur une clé de destination, qui sera effacée et formatée."
            },
            Msg::Choisir(Mode::Copier)
        )]
        .spacing(30)
        .width(Length::Fill);
        if self.optique.is_some() {
            choix = choix.push(grand_choix(
                "Graver sur un disque",
                if disque {
                    "Les fichiers sains sont gravés sur un disque réinscriptible (échange de disque demandé), puis vérifiés."
                } else {
                    "Les fichiers sains sont gravés sur un disque réinscriptible (CD-RW, DVD-RW, DVD+RW, BD-RE), puis vérifiés."
                },
                Msg::Choisir(Mode::Graver),
            ));
        }
        let reinscriptible = self.optique.as_ref().is_some_and(|e| e.reinscriptible);
        if !disque {
            choix = choix.push(grand_choix(
                "Blanchir cette clé",
                "La clé est analysée, entièrement effacée, puis seuls ses fichiers sains y sont réécrits.",
                Msg::Choisir(Mode::Blanchir),
            ));
        } else if reinscriptible {
            choix = choix.push(grand_choix(
                "Blanchir ce disque",
                "Le disque est analysé, effacé COMPLÈTEMENT (vérifié), puis seuls ses fichiers sains y sont regravés.",
                Msg::Choisir(Mode::Blanchir),
            ));
        }
        // Charte : la clé glisse vers la porte, ou le tiroir remonte avec le disque (600 ms).
        let mut c = column![
            if disque {
                dessin::disque_detecte(self.avancement(600), 120.0)
            } else {
                dessin::cle_detectee(self.avancement(600), 120.0)
            },
            titre(if disque {
                "Disque détecté"
            } else {
                "Clé détectée"
            }),
            texte(&d),
            Space::new().height(30),
            choix,
        ]
        .max_width(1460);
        if disque && !reinscriptible {
            c = c.push(petit(
                "Ce disque n'est pas réinscriptible : il ne peut pas être blanchi (seulement lu).",
            ));
        }
        if disque {
            // Utiliser une clé alors qu'un disque est dans le lecteur : le disque est ignoré
            // jusqu'à son retrait.
            c = c.push(Space::new().height(10)).push(bouton(
                "Ignorer ce disque",
                Msg::Terminer,
                style::secondaire,
            ));
        }
        centre(c)
    }

    fn view_progress(&self, t: &str, sub: &str) -> Element<'_, Msg> {
        let temps = self.depuis.elapsed().as_secs_f32();
        let disque_source = self.src.as_ref().is_some_and(est_optique);
        // Animation du moment, au centre, au-dessus de la consigne (charte).
        let scene: Element<Msg> = match (&self.screen, self.mode) {
            (Screen::Analyse, _) if disque_source && self.optique_avance.is_some() => {
                dessin::lecture_disque(temps, 140.0)
            }
            (Screen::Analyse, _) => dessin::analyse(temps, 140.0),
            (Screen::Ecriture, Mode::Graver) => dessin::lecture_disque(temps, 140.0),
            (Screen::Ecriture, _) if matches!(self.progress, Some((Status::Wipe, _, _))) => {
                dessin::effacement(self.fraction().unwrap_or(0.0), 140.0)
            }
            _ => dessin::copie(temps, 140.0),
        };
        let mut c = column![scene, titre(t), texte(sub)]
            .spacing(8)
            .align_x(Alignment::Center);
        let mut etape_txt = None;
        let mut details = None;
        if let Some((s, cur, tot)) = self.progress {
            etape_txt = Some(etape(s).to_string());
            // Étapes en octets : quantité, vitesse de la clé, temps restant
            if tot > 0 && matches!(s, Status::ReadSrc | Status::WriteDst | Status::Wipe) {
                let mut l = format!(
                    "{} sur {}  ({} %)",
                    mesure::taille(cur),
                    mesure::taille(tot),
                    cur * 100 / tot
                );
                if let (Some(v), Some(r)) = (self.mesure.vitesse(), self.mesure.restant(tot)) {
                    l.push_str(&format!(
                        "  ·  {}  ·  reste {}",
                        mesure::debit(v),
                        mesure::duree(r)
                    ));
                }
                details = Some(l);
            }
        }
        if let Some((phase, p, restant)) = &self.optique_avance {
            etape_txt = Some(format!("Disque : {phase}"));
            let mut l = format!("{p:.0} %");
            if let Some(r) = restant {
                l.push_str(&format!(
                    "  ·  reste environ {}",
                    mesure::duree(std::time::Duration::from_secs(*r))
                ));
            }
            details = Some(l);
        }
        let (done, total, scanned) = self.analysis_progress;
        if matches!(self.screen, Screen::Analyse) && total > 0 {
            details = Some(format!(
                "{done} / {total} fichiers ({scanned} avec le contenu des archives)"
            ));
        }
        if let Some(e) = etape_txt {
            c = c.push(texte(&e));
        }
        // Barre vivante + chronomètre (charte : la borne montre qu'elle travaille).
        c = c.push(barre::barre(
            self.fraction().map(|f| f.max(self.barre_val)),
            temps,
            700.0,
        ));
        c = c.push(
            row![
                text(details.unwrap_or_default())
                    .size(style::PETIT)
                    .color(style::c().encre_douce)
                    .shaping(text::Shaping::Advanced),
                Space::new().width(Length::Fill),
                text(barre::chrono(self.depuis.elapsed().as_secs()))
                    .size(style::PETIT)
                    .font(style::MONO)
                    .color(style::c().encre_douce),
            ]
            .width(Length::Fixed(700.0)),
        );
        // Fichier long : la barre n'a pas bougé depuis 30 s.
        if self.barre_maj.elapsed().as_secs() >= 30 {
            let pal = style::c();
            let point_allume = style::animations_reduites() || (temps / 1.2).rem_euclid(1.0) < 0.5;
            c = c.push(
                container(
                    row![
                        container(Space::new().width(10).height(10)).style(move |_| {
                            container::Style {
                                background: Some(iced::Background::Color(if point_allume {
                                    pal.laiton
                                } else {
                                    pal.laiton_pale
                                })),
                                border: iced::Border::default().rounded(5),
                                ..Default::default()
                            }
                        }),
                        text("Ce fichier est volumineux. L'opération continue, la borne n'est pas bloquée.")
                            .size(style::PETIT)
                            .color(pal.encre)
                            .shaping(text::Shaping::Advanced),
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                )
                .padding([8, 16])
                .style(move |_| container::Style {
                    background: Some(iced::Background::Color(pal.laiton_pale)),
                    border: iced::Border::default().rounded(4),
                    ..Default::default()
                }),
            );
        }
        if self.mesure.vitesse().is_some_and(|v| v < mesure::CLE_LENTE) {
            c = c.push(petit(
                "Clé lente : l'opération prend du temps, c'est normal. Ne la retirez pas.",
            ));
        }
        if self.optique_avance.is_some() {
            c = c.push(petit("Ne retirez pas le disque pendant l'opération."));
        }
        centre(c)
    }

    /// Avancement affiché par la barre (jamais en recul), `None` tant que le total est inconnu.
    fn fraction(&self) -> Option<f32> {
        let (done, total, _) = self.analysis_progress;
        if let Some((_, p, _)) = &self.optique_avance {
            return Some(p / 100.0);
        }
        if matches!(self.screen, Screen::Analyse) && total > 0 {
            return Some(done as f32 / total as f32);
        }
        match self.progress {
            Some((_, cur, tot)) if tot > 0 => Some(cur as f32 / tot as f32),
            _ => None,
        }
    }

    // ------------------------------------------------ charte : étapes et animations

    /// Animation à rafraîchir : analyse (en boucle) ou un moment joué une fois, pas encore fini.
    /// Cadence de rafraîchissement : 30 images/s pendant une animation, 1/s pour le seul
    /// chronomètre (animations réduites), rien sinon.
    fn anime(&self) -> Option<std::time::Duration> {
        use std::time::Duration;
        let ms = self.depuis.elapsed().as_millis();
        let en_cours = matches!(
            self.screen,
            Screen::Analyse | Screen::Ecriture | Screen::Connexion
        );
        if self.maintien.is_some() {
            return Some(Duration::from_millis(33));
        }
        if style::animations_reduites() {
            return en_cours.then_some(Duration::from_secs(1));
        }
        let anime = ms < 300
            || en_cours
            || match self.screen {
                Screen::Accueil => true,
                Screen::Choix => ms < 600,
                Screen::Resume => ms < 700,
                Screen::Fin(_) => ms < 500,
                Screen::Erreur { .. } => ms < 600,
                Screen::Sortie => ms < 900,
                _ => false,
            };
        anime.then_some(Duration::from_millis(33))
    }

    /// Bouton destructif « Maintenir pour effacer » (charte) : un voile encre remplit le bouton
    /// pendant 2 s ; relâcher avant la fin annule. Animations réduites : compte à rebours.
    fn maintenir(&self, libelle: &str) -> Element<'_, Msg> {
        const L: f32 = 380.0;
        const H: f32 = 72.0;
        let pal = style::c();
        let p = self
            .maintien
            .map_or(0.0, |d| (d.elapsed().as_secs_f32() / 2.0).min(1.0));
        let texte_bouton = match self.maintien {
            Some(d) if style::animations_reduites() => {
                format!("{}…", 2 - d.elapsed().as_secs().min(1))
            }
            _ => libelle.to_string(),
        };
        let fond = container(Space::new().width(L).height(H)).style(move |_| container::Style {
            background: Some(iced::Background::Color(pal.menace)),
            border: iced::Border::default().rounded(8),
            ..Default::default()
        });
        let voile =
            container(Space::new().width(L * p).height(H)).style(move |_| container::Style {
                background: Some(iced::Background::Color(pal.encre)),
                border: iced::Border::default().rounded(8),
                ..Default::default()
            });
        let etiquette = container(
            text(texte_bouton)
                .size(24)
                .font(style::CORPS_GRAS)
                .color(pal.sur_encre)
                .shaping(text::Shaping::Advanced),
        )
        .center_x(L)
        .center_y(H);
        en_relief(
            iced::widget::mouse_area(iced::widget::stack![fond, voile, etiquette])
                .on_press(Msg::Maintien(true))
                .on_release(Msg::Maintien(false))
                .on_exit(Msg::Maintien(false))
                .into(),
            Some(pal.encre),
        )
    }

    /// Avancement (0 → 1) d'une animation de `duree_ms` jouée une fois depuis l'entrée dans
    /// l'écran ; 1 directement si les animations sont réduites.
    fn avancement(&self, duree_ms: u64) -> f32 {
        if style::animations_reduites() {
            return 1.0;
        }
        (self.depuis.elapsed().as_millis() as f32 / duree_ms as f32).clamp(0.0, 1.0)
    }

    /// Bandeau d'étapes (charte, composant Etapes) : faites en encre avec une coche, en cours
    /// sur laiton pâle bordée de laiton, à venir en encre douce. Masqué hors du parcours.
    fn view_etapes(&self) -> Element<'_, Msg> {
        let actuelle = match self.screen {
            Screen::Choix => 0,
            Screen::Analyse | Screen::MotDePasse(_) => 1,
            Screen::Resume => 2,
            Screen::Sortie | Screen::ConfirmBlanchir => 3,
            Screen::Ecriture => 4,
            Screen::Fin(_) => 5,
            _ => return Space::new().height(0).into(),
        };
        let (dest, ecriture) = match (&self.screen, self.mode) {
            (Screen::Choix, _) => ("Sortie", "Écriture"),
            (_, Mode::Copier) => ("Clé de destination", "Écriture"),
            (_, Mode::Graver) => ("Disque de destination", "Gravure"),
            (_, Mode::Blanchir) => ("Confirmation", "Blanchiment"),
        };
        let support = if self.src.as_ref().is_some_and(est_optique) {
            "Disque"
        } else {
            "Clé"
        };
        let noms = [support, "Analyse", "Résultat", dest, ecriture, "Terminé"];
        let pal = style::c();
        let mut r = row![].spacing(6).align_y(Alignment::Center);
        for (i, nom) in noms.iter().enumerate() {
            if i > 0 {
                r = r.push(text("›").size(style::PETIT).color(pal.encre_douce));
            }
            let (lib, coul) = if i < actuelle {
                (format!("✓ {nom}"), pal.encre)
            } else {
                (
                    format!("{} {nom}", i + 1),
                    if i == actuelle {
                        pal.encre
                    } else {
                        pal.encre_douce
                    },
                )
            };
            let t = text(lib)
                .size(style::PETIT)
                .color(coul)
                .font(if i == actuelle {
                    style::CORPS_GRAS
                } else {
                    style::CORPS
                })
                .shaping(text::Shaping::Advanced);
            let c = container(t).padding([4, 12]);
            r = r.push(if i == actuelle {
                c.style(move |_| container::Style {
                    background: Some(iced::Background::Color(pal.laiton_pale)),
                    border: iced::Border::default()
                        .rounded(8)
                        .width(2)
                        .color(pal.laiton),
                    ..Default::default()
                })
            } else {
                c
            });
        }
        container(r)
            .padding([6, 30])
            .center_x(Length::Fill)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(pal.surface_haute)),
                border: iced::Border::default().width(0),
                ..Default::default()
            })
            .into()
    }

    fn view_password(&self, req: &PasswordRequest) -> Element<'_, Msg> {
        centre(column![
            titre("Archive protégée par mot de passe"),
            texte(&format!("« {} »", req.archive)),
            petit(&format!(
                "Saisissez son mot de passe pour en analyser le contenu (essai {} sur {}). Sans mot de passe, l'archive sera refusée.",
                req.attempt, req.max_attempts
            )),
            container(
                text(self.input.shown())
                    .size(30)
                    .shaping(text::Shaping::Advanced)
            )
            .padding(14)
            .width(Length::Fixed(700.0))
            .style(style::carte),
            self.input.view(Msg::Key),
            row![
                bouton("Ignorer cette archive", Msg::Ignorer, style::secondaire),
                bouton("Valider", Msg::Valider, style::primaire),
            ]
            .spacing(30),
        ])
    }

    fn view_resume(&self) -> Element<'_, Msg> {
        let Some(a) = &self.analysis else {
            return centre(column![titre("…")]);
        };
        let copied = a.report.copied().count();
        let refused: Vec<_> = a.report.refused().collect();
        let mut list = Column::new().spacing(8);
        let est_menace = |r: &str| r.contains("menace");
        let menaces = refused.iter().filter(|f| est_menace(&f.reason)).count();
        for f in &refused {
            let (ic, c) = if est_menace(&f.reason) {
                (ICONE_MENACE, style::c().menace)
            } else {
                (ICONE_ALERTE, style::c().alerte)
            };
            list = list.push(
                row![
                    icone_etat(ic, 26.0, c),
                    column![
                        text(&f.path)
                            .size(style::PETIT)
                            .font(style::MONO)
                            .color(style::c().encre)
                            .shaping(text::Shaping::Advanced),
                        petit(&f.reason)
                    ]
                    .spacing(2)
                ]
                .spacing(12),
            );
        }
        for f in &a.filtered {
            list = list.push(
                column![
                    text(f.trim_start_matches('/'))
                        .size(style::TEXTE_TAILLE)
                        .color(style::c().encre_douce)
                        .shaping(text::Shaping::Advanced),
                    petit("fichier système écarté")
                ]
                .spacing(2),
            );
        }
        let unpacked: Vec<_> = a
            .report
            .files
            .iter()
            .filter(|f| a.report.is_unpacked(f))
            .collect();
        // Verdict (charte) : un seul bandeau, la menace l'emporte sur l'alerte.
        let ecartes = refused.len() - menaces + a.filtered.len();
        let (ic, c, fond, titre_v) = if menaces > 0 {
            (
                ICONE_MENACE,
                style::c().menace,
                style::c().menace_fond,
                format!("{menaces} menace(s) détectée(s)"),
            )
        } else if ecartes > 0 {
            (
                ICONE_ALERTE,
                style::c().alerte,
                style::c().alerte_fond,
                format!("{ecartes} fichier(s) écarté(s)"),
            )
        } else {
            (
                ICONE_SAIN,
                style::c().sain,
                style::c().sain_fond,
                "Aucune menace détectée".to_string(),
            )
        };
        let verdict = container(
            row![
                if menaces > 0 {
                    dessin::menace(self.avancement(700), 72.0)
                } else if ecartes > 0 {
                    icone_etat(ic, 48.0, c)
                } else {
                    dessin::sain(self.avancement(500), 72.0)
                },
                column![
                    text(titre_v).size(36).font(style::TITRE_POLICE).color(c),
                    texte(&format!(
                        "{copied} fichier(s) sain(s) à copier · {} refusé(s)",
                        refused.len() + a.filtered.len()
                    )),
                ]
                .spacing(2)
            ]
            .spacing(20)
            .align_y(Alignment::Center),
        )
        .padding([16, 28])
        .width(Length::Fixed(900.0))
        .style(style::verdict(fond, c));
        let mut c = column![titre("Résultat de l'analyse"), verdict]
            .spacing(16)
            .align_x(Alignment::Center);
        if !unpacked.is_empty() {
            c = c.push(petit(&format!(
                "{} archive(s) contenant des fichiers refusés : leurs fichiers sains seront copiés dans un dossier « <archive>.extrait ».",
                unpacked.len()
            )));
        }
        if !refused.is_empty() || !a.filtered.is_empty() {
            c = c.push(texte("Ce qui ne passe pas, et pourquoi :")).push(
                container(
                    // Hauteur bornée : les boutons doivent rester visibles en 1280×768.
                    scrollable(list)
                        .height(Length::Fixed(130.0))
                        .width(Length::Fixed(900.0)),
                )
                .padding(16)
                .style(style::carte),
            );
        }
        let action = match self.mode {
            Mode::Copier => bouton(
                "Choisir la clé de destination",
                Msg::VersSortie,
                style::primaire,
            ),
            Mode::Graver => bouton(
                "Choisir le disque de destination",
                Msg::VersSortie,
                style::primaire,
            ),
            Mode::Blanchir if self.src.as_ref().is_some_and(est_optique) => {
                bouton("Blanchir le disque", Msg::Blanchir, style::danger)
            }
            Mode::Blanchir => bouton("Blanchir la clé", Msg::Blanchir, style::danger),
        };
        c = c.push(Space::new().height(10)).push(
            row![
                bouton("Abandonner", Msg::Terminer, style::secondaire),
                action
            ]
            .spacing(30),
        );
        centre(c)
    }

    fn view_sortie_disque(&self) -> Element<'_, Msg> {
        let attente = self.src.as_ref().is_some_and(est_optique) && !self.echange_fait;
        let mut c = if attente {
            column![
                titre("Retirez le disque analysé"),
                texte("puis insérez le disque réinscriptible de destination dans le lecteur."),
            ]
        } else {
            column![
                titre("Insérez le disque de destination"),
                texte("CD-RW, DVD-RW, DVD+RW ou BD-RE, dans le lecteur de la borne."),
            ]
        }
        .spacing(14)
        .align_x(Alignment::Center);
        if let Some(r) = &self.dst_refused {
            c = c.push(container(texte(r)).padding(12).style(style::alerte));
        }
        let mut go = button(
            text("Effacer ce disque et y graver les fichiers")
                .size(24)
                .font(style::CORPS_GRAS),
        )
        .padding([18, 30])
        .style(style::primaire);
        if let Some(d) = &self.dst {
            c = c.push(carte(column![
                texte(&format!("Disque de destination : {}", d.description)),
                texte_c(
                    "Son contenu actuel sera entièrement effacé (effacement complet), puis les fichiers \
                     gravés à vitesse réduite et relus pour vérification.",
                    style::c().menace
                ),
            ]));
            go = go.on_press(Msg::Ecrire);
        }
        c = c.push(Space::new().height(20)).push(
            row![
                bouton("Abandonner", Msg::Terminer, style::secondaire),
                bouton("Éjecter le disque", Msg::Ejecter, style::secondaire),
                en_relief(go.into(), Some(style::c().laiton))
            ]
            .spacing(30),
        );
        centre(c)
    }

    fn view_sortie(&self) -> Element<'_, Msg> {
        if self.mode == Mode::Graver {
            return self.view_sortie_disque();
        }
        // Charte : la clé de confiance (laiton) arrive de la droite, le sceau vert la confirme.
        let scene = if self.dst.is_some() {
            dessin::destination(self.avancement(900), 110.0)
        } else {
            Space::new().height(0).into()
        };
        let mut c = column![
            scene,
            titre("Insérez la clé de destination"),
            texte("sur le port de sortie de la borne.")
        ]
        .spacing(14)
        .align_x(Alignment::Center);
        if let Some(r) = &self.dst_refused {
            c = c.push(container(texte(r)).padding(12).style(style::alerte));
        }
        let mut go = button(
            text("Effacer cette clé et y copier les fichiers")
                .size(24)
                .font(style::CORPS_GRAS),
        )
        .padding([18, 30])
        .style(style::primaire);
        if let Some(d) = &self.dst {
            c = c.push(carte(column![
                texte(&format!(
                    "Clé de destination : {}",
                    barbacane_parcours::describe(d)
                )),
                texte_c(
                    "Son contenu actuel sera entièrement effacé.",
                    style::c().menace
                ),
            ]));
            go = go.on_press(Msg::Ecrire);
        }
        c = c
            .push(Space::new().height(20))
            .push(
                row![
                    bouton("Abandonner", Msg::Terminer, style::secondaire),
                    en_relief(go.into(), Some(style::c().laiton))
                ]
                .spacing(30),
            );
        centre(c)
    }
}

// ---------------------------------------------------------------- briques

pub fn centre<'a>(c: Column<'a, Msg>) -> Element<'a, Msg> {
    container(c.spacing(16).align_x(Alignment::Center))
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

/// Logo en relief (version nuit sur le bandeau encre).
const LOGO: &[u8] = include_bytes!("../ressources/icones/barbacane-relief.svg");
const LOGO_NUIT: &[u8] = include_bytes!("../ressources/icones/barbacane-relief-nuit.svg");
pub const ICONE_SAIN: &[u8] = include_bytes!("../ressources/icones/shield-check.svg");
pub const ICONE_ALERTE: &[u8] = include_bytes!("../ressources/icones/triangle-alert.svg");
pub const ICONE_MENACE: &[u8] = include_bytes!("../ressources/icones/octagon-x.svg");

/// Image SVG embarquée, carrée.
pub fn icone<'a>(svg: &'static [u8], taille: f32) -> Element<'a, Msg> {
    iced::widget::svg(iced::widget::svg::Handle::from_memory(svg))
        .width(taille)
        .height(taille)
        .into()
}

/// Icône au trait (Lucide) colorée selon l'état.
pub fn icone_etat<'a>(svg: &'static [u8], taille: f32, c: iced::Color) -> Element<'a, Msg> {
    iced::widget::svg(iced::widget::svg::Handle::from_memory(svg))
        .width(taille)
        .height(taille)
        .style(move |_, _| iced::widget::svg::Style { color: Some(c) })
        .into()
}

pub fn titre<'a>(t: &str) -> Element<'a, Msg> {
    text(t.to_string())
        .size(style::TITRE)
        .font(style::TITRE_POLICE)
        .color(style::c().encre)
        .shaping(text::Shaping::Advanced)
        .into()
}

pub fn texte<'a>(t: &str) -> Element<'a, Msg> {
    text(t.to_string())
        .size(style::TEXTE_TAILLE)
        .shaping(text::Shaping::Advanced)
        .into()
}

pub fn texte_c<'a>(t: &str, c: iced::Color) -> Element<'a, Msg> {
    text(t.to_string())
        .size(style::TEXTE_TAILLE)
        .color(c)
        .shaping(text::Shaping::Advanced)
        .into()
}

pub fn petit<'a>(t: &str) -> Element<'a, Msg> {
    text(t.to_string())
        .size(style::PETIT)
        .color(style::c().encre_douce)
        .shaping(text::Shaping::Advanced)
        .into()
}

pub fn carte<'a>(c: Column<'a, Msg>) -> Element<'a, Msg> {
    container(c.spacing(10))
        .padding(20)
        .style(style::carte)
        .into()
}

pub fn bouton<'a>(
    t: &str,
    m: Msg,
    s: fn(&iced::Theme, button::Status) -> button::Style,
) -> Element<'a, Msg> {
    // Charte : 24 px gras, cible d'au moins 64 px (72 px visés en 1080p)
    en_relief(
        button(
            text(t.to_string())
                .size(24)
                .font(style::CORPS_GRAS)
                .shaping(text::Shaping::Advanced),
        )
        .padding([18, 32])
        .style(s)
        .on_press(m)
        .into(),
        style::tranche(s),
    )
}

/// Relief de la charte : tranche pleine décalée de 6 px vers le bas à droite, posée derrière.
pub fn en_relief<'a>(b: Element<'a, Msg>, tranche: Option<iced::Color>) -> Element<'a, Msg> {
    let Some(t) = tranche else { return b };
    let base = container(b).padding(iced::Padding {
        right: 6.0,
        bottom: 6.0,
        ..iced::Padding::ZERO
    });
    let dessous = container(
        container(Space::new().width(Length::Fill).height(Length::Fill)).style(move |_| {
            container::Style {
                background: Some(iced::Background::Color(t)),
                border: iced::Border::default().rounded(8),
                ..Default::default()
            }
        }),
    )
    .padding(iced::Padding {
        left: 6.0,
        top: 6.0,
        ..iced::Padding::ZERO
    })
    .width(Length::Fill)
    .height(Length::Fill);
    iced::widget::Stack::new()
        .push(base)
        .push_under(dessous)
        .into()
}

fn grand_choix<'a>(t: &str, d: &str, m: Msg) -> Element<'a, Msg> {
    let b = button(
        column![
            text(t.to_string()).size(style::SOUS_TITRE),
            text(d.to_string()).size(style::PETIT)
        ]
        .spacing(14)
        .align_x(Alignment::Center),
    )
    .padding(30)
    // Largeur partagée : trois choix (clé + lecteur optique) tiennent sur un écran de 1280 px.
    .width(Length::FillPortion(1))
    .style(style::primaire)
    .on_press(m);
    // La carte remplit sa part de largeur : le relief l'accompagne.
    container(en_relief(b.into(), Some(style::c().laiton)))
        .width(Length::FillPortion(1))
        .into()
}
