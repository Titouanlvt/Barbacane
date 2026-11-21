//! Écrans du mode administrateur (PIN au clavier virtuel). Toutes les
//! actions sont exécutées par barbacane-admind, qui vérifie le jeton.

use crate::app::{App, Msg, Screen, bouton, carte, petit, texte, texte_c, titre};
use crate::keyboard::{Input, Key};
use crate::style;
use crate::worker::Cmd;
use barbacane_parcours::proto::common::UsbDevice;
use iced::widget::{Column, Space, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Task};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub enum Page {
    Pin,
    Menu,
    Etat,
    MiseAJour,
    Export,
    Enrolement,
    Limites,
    NouveauPin,
    /// Thème Pierre / Nuit, animations réduites
    Affichage,
    /// Crédits : projets sur lesquels repose Barbacane
    APropos,
    /// Borne en ligne seulement : liaison avec le serveur de gestion
    Serveur,
    /// Borne en ligne seulement : saisie du jeton d'enrôlement
    Jeton,
    Confirmer(&'static str),
}

#[derive(Debug, Clone)]
pub enum AdminMsg {
    Ouvrir,
    Key(Key),
    Login,
    Aller(Page),
    Quitter,
    Resp(&'static str, Result<Value, String>),
    /// Lire la clé admin (via usbsas) puis appliquer la mise à jour
    LireMaj,
    Exporter,
    Enroler(UsbDevice),
    Retirer(Value),
    ModeEnrole(bool),
    Limite(&'static str, i64),
    EnregistrerLimites,
    EnregistrerPin,
    Executer(&'static str),
    /// Thème (« pierre » ou « nuit ») et animations réduites
    Affichage(&'static str, bool),
    /// Borne en ligne : jeton saisi, à déposer par admind
    EnregistrerJeton,
    /// Borne en ligne : vérifier et appliquer la mise à jour reçue du serveur
    AppliquerMajServeur,
    /// Relire l'état (page Serveur)
    Actualiser,
}

pub struct AdminUi {
    socket: String,
    pub page: Page,
    token: Option<String>,
    input: Input,
    first_pin: Option<zeroize::Zeroizing<String>>,
    message: Option<(bool, String)>,
    /// Texte de l'accusé « Jeton enregistré… » : retiré dès que l'agent a quitté l'état
    /// « non enrôlée » (défaut du labo 21/11 : il restait affiché sur la borne connectée).
    message_jeton: Option<String>,
    limits: Value,
    busy: bool,
}

impl AdminUi {
    pub fn new(socket: String) -> Self {
        AdminUi {
            socket,
            page: Page::Pin,
            token: None,
            input: Input::digits(12),
            first_pin: None,
            message: None,
            message_jeton: None,
            limits: json!({}),
            busy: false,
        }
    }

    /// Nouvel état d'admind : l'accusé du jeton devient périmé dès que l'enrôlement avance.
    pub fn apres_etat(&mut self, etat: &Value) {
        let mode = etat["serveur"]["agent"]["mode"].as_str();
        if self.message_jeton.is_some() && mode.is_some_and(|m| m != "non_enrolee") {
            let j = self.message_jeton.take();
            if self.message.as_ref().map(|(_, t)| t) == j.as_ref() {
                self.message = None;
            }
        }
    }

    fn call(&mut self, tag: &'static str, mut req: Value) -> Task<Msg> {
        if let Some(t) = &self.token {
            req["token"] = json!(t);
        }
        self.busy = true;
        Task::perform(crate::admin::call(self.socket.clone(), req), move |r| {
            Msg::Admin(AdminMsg::Resp(tag, r))
        })
    }
}

pub fn update(app: &mut App, m: AdminMsg) -> Task<Msg> {
    let a = &mut app.admin;
    match m {
        AdminMsg::Ouvrir => {
            a.page = Page::Pin;
            a.input = Input::digits(12);
            a.message = None;
            app.screen = Screen::Admin;
        }
        AdminMsg::Key(k) => a.input.press(k),
        AdminMsg::Login => {
            let pin = a.input.value.to_string();
            a.input = Input::digits(12);
            return a.call("login", json!({"op": "login", "pin": pin}));
        }
        AdminMsg::Aller(p) => {
            a.message = None;
            a.input = if p == Page::Jeton {
                Input {
                    visible: true,
                    ..Input::text(40)
                }
            } else {
                Input::digits(12)
            };
            a.first_pin = None;
            if p == Page::Limites {
                a.limits = app
                    .etat
                    .as_ref()
                    .map(|e| e["limits"].clone())
                    .unwrap_or(json!({}));
            }
            a.page = p;
            return app.refresh_etat();
        }
        AdminMsg::Quitter => {
            let t = if a.token.is_some() {
                a.call("logout", json!({"op": "logout"}))
            } else {
                Task::none()
            };
            a.token = None;
            app.screen = Screen::Accueil;
            return Task::batch([t, app.refresh_etat()]);
        }
        AdminMsg::Resp(tag, r) => {
            a.busy = false;
            match (tag, r) {
                ("login", Ok(v)) => {
                    a.token = v["token"].as_str().map(str::to_string);
                    a.page = Page::Menu;
                }
                ("logout", _) => (),
                ("prepare_export", Ok(_)) => {
                    // Fichiers prêts : écriture sur la clé admin via usbsas.
                    match app.devices.destinations().next().map(|(_, d)| d.clone()) {
                        Some(dst) => {
                            app.admin.busy = true;
                            app.admin.message =
                                Some((true, "Écriture des journaux sur la clé…".into()));
                            if let Some(tx) = app_cmd(app) {
                                let _ = tx.send(Cmd::Export { dst });
                            }
                        }
                        None => {
                            app.admin.message = Some((
                                false,
                                "Branchez la clé administrateur sur le port de sortie.".into(),
                            ))
                        }
                    }
                }
                ("arm_import", Ok(_)) => match app.devices.sources().next().map(|(_, d)| d.clone())
                {
                    Some(src) => {
                        app.admin.busy = true;
                        app.admin.message =
                            Some((true, "Lecture de la clé administrateur…".into()));
                        if let Some(tx) = app_cmd(app) {
                            let _ = tx.send(Cmd::Analyse(src));
                        }
                    }
                    None => {
                        app.admin.message = Some((
                            false,
                            "Branchez la clé administrateur sur le port d'entrée.".into(),
                        ))
                    }
                },
                ("apply_update", Ok(v)) => {
                    let txt = v["report"]
                        .as_str()
                        .unwrap_or("Mise à jour appliquée.")
                        .to_string();
                    app.admin.message = Some((true, txt));
                    return app.refresh_etat();
                }
                (_, Ok(v)) => {
                    app.admin.message =
                        Some((true, v["message"].as_str().unwrap_or("Fait.").to_string()));
                    if tag == "set_pin" {
                        app.admin.page = Page::Menu;
                    }
                    if tag == "serveur_jeton" {
                        app.admin.message_jeton =
                            app.admin.message.as_ref().map(|(_, t)| t.clone());
                        app.admin.input = Input::digits(12);
                        app.admin.page = Page::Serveur;
                    }
                    return app.refresh_etat();
                }
                ("login", Err(e)) => a.message = Some((false, e)),
                (_, Err(e)) => {
                    if e.contains("session") {
                        a.token = None;
                        a.page = Page::Pin;
                    }
                    a.message = Some((false, e));
                }
            }
        }
        AdminMsg::Affichage(theme, reduites) => {
            a.message = None;
            return a.call(
                "set_preferences",
                json!({"op": "set_preferences", "theme": theme, "animations_reduites": reduites}),
            );
        }
        AdminMsg::LireMaj => {
            a.message = None;
            return a.call("arm_import", json!({"op": "arm_import"}));
        }
        AdminMsg::Exporter => {
            a.message = None;
            return a.call("prepare_export", json!({"op": "prepare_export"}));
        }
        AdminMsg::Enroler(d) => {
            return a.call(
                "enroll_add",
                json!({"op": "enroll_add", "vendorid": d.vendorid, "productid": d.productid, "serial": d.serial,
                       "description": barbacane_parcours::describe(&d)}),
            );
        }
        AdminMsg::Retirer(k) => {
            return a.call("enroll_remove", json!({"op": "enroll_remove", "key": k}));
        }
        AdminMsg::ModeEnrole(on) => {
            return a.call(
                "set_enrolled_mode",
                json!({"op": "set_enrolled_mode", "enabled": on}),
            );
        }
        AdminMsg::Limite(k, delta) => {
            let cur = a.limits[k].as_i64().unwrap_or(0);
            let step = match k {
                "max_depth" => 1,
                "max_files" => 1000,
                _ => 512 * 1024 * 1024,
            };
            a.limits[k] = json!((cur + delta * step).max(step));
        }
        AdminMsg::EnregistrerLimites => {
            let l = a.limits.clone();
            return a.call("set_limits", json!({"op": "set_limits", "limits": l}));
        }
        AdminMsg::EnregistrerPin => {
            let v = a.input.value.clone();
            a.input = Input::digits(12);
            match a.first_pin.take() {
                None => {
                    if v.len() < 6 {
                        a.message =
                            Some((false, "Le PIN doit comporter au moins 6 chiffres.".into()));
                    } else {
                        a.first_pin = Some(v);
                        a.message = Some((true, "Saisissez à nouveau le nouveau PIN.".into()));
                    }
                }
                Some(first) if *first == *v => {
                    return a.call("set_pin", json!({"op": "set_pin", "pin": v.as_str()}));
                }
                Some(_) => {
                    a.message = Some((false, "Les deux saisies diffèrent, recommencez.".into()))
                }
            }
        }
        AdminMsg::Executer(op) => return a.call(op, json!({"op": op})),
        AdminMsg::EnregistrerJeton => {
            let j = a.input.value.to_string();
            a.message = None;
            return a.call("serveur_jeton", json!({"op": "serveur_jeton", "jeton": j}));
        }
        AdminMsg::AppliquerMajServeur => {
            a.message = Some((
                true,
                "Vérification et application de la mise à jour…".into(),
            ));
            // Même réponse que la mise à jour par clé : même affichage du compte rendu.
            return a.call("apply_update", json!({"op": "serveur_appliquer_maj"}));
        }
        AdminMsg::Actualiser => return app.refresh_etat(),
    }
    Task::none()
}

fn app_cmd(app: &App) -> Option<std::sync::mpsc::Sender<Cmd>> {
    app.cmd.clone()
}

/// Fin de lecture de la clé admin (transfert usbsas) : demande l'application.
pub fn analysed(app: &mut App, r: Result<(), String>) -> Task<Msg> {
    match r {
        Ok(()) => {
            app.admin.message = Some((
                true,
                "Vérification et application de la mise à jour…".into(),
            ));
            app.admin
                .call("apply_update", json!({"op": "apply_update"}))
        }
        Err(e) => {
            app.admin.busy = false;
            app.admin.message = Some((false, format!("Lecture de la clé impossible : {e}")));
            Task::none()
        }
    }
}

pub fn exported(app: &mut App, r: Result<(), String>) -> Task<Msg> {
    app.admin.busy = false;
    app.admin.message = Some(match r {
        Ok(()) => (
            true,
            "Journaux et rapports exportés. Vous pouvez retirer la clé.".into(),
        ),
        Err(e) => (false, format!("Export impossible : {e}")),
    });
    Task::none()
}

fn am(m: AdminMsg) -> Msg {
    Msg::Admin(m)
}

fn menu_btn<'a>(t: &str, p: Page) -> Element<'a, Msg> {
    bouton(t, am(AdminMsg::Aller(p)), style::secondaire)
}

pub fn view(app: &App) -> Element<'_, Msg> {
    let a = &app.admin;
    let etat = app.etat.clone().unwrap_or(json!({}));
    let msg: Element<Msg> = match &a.message {
        Some((true, m)) => container(texte(m)).padding(12).style(style::carte).into(),
        Some((false, m)) => container(texte_c(m, style::c().menace))
            .padding(12)
            .style(style::alerte)
            .into(),
        None => Space::new().height(0).into(),
    };
    let retour = bouton(
        "Retour au menu",
        am(AdminMsg::Aller(Page::Menu)),
        style::secondaire,
    );
    let body: Element<Msg> = match &a.page {
        Page::Pin => column![
            titre("Mode administrateur"),
            texte(if app.etat.as_ref().is_some_and(|e| e["pin_set"] == false) {
                "Premier démarrage : choisissez le PIN administrateur (6 chiffres minimum)."
            } else {
                "Saisissez le PIN administrateur."
            }),
            container(text(a.input.shown()).size(30)).padding(8).width(Length::Fixed(360.0)).style(style::carte),
            a.input.view(|k| am(AdminMsg::Key(k))),
            msg,
            row![bouton("Annuler", am(AdminMsg::Quitter), style::secondaire), bouton("Valider", am(AdminMsg::Login), style::primaire)].spacing(30),
        ]
        .spacing(12) // tient en 1280×768
        .align_x(Alignment::Center)
        .into(),
        Page::Menu => column![
            titre("Administration"),
            {
                let r = row![menu_btn("État de la borne", Page::Etat), menu_btn("Mettre à jour", Page::MiseAJour), menu_btn("Exporter les journaux", Page::Export)].spacing(20);
                // Borne en ligne seulement (absent en profil hors ligne : menu v1 inchangé).
                if profil_en_ligne(&etat) { r.push(menu_btn("Serveur", Page::Serveur)) } else { r }
            },
            row![menu_btn("Clés de sortie enrôlées", Page::Enrolement), menu_btn("Limites d'analyse", Page::Limites), menu_btn("Changer le PIN", Page::NouveauPin)].spacing(20),
            row![
                menu_btn("Affichage", Page::Affichage),
                menu_btn("À propos", Page::APropos),
                bouton("Redémarrer", am(AdminMsg::Aller(Page::Confirmer("reboot"))), style::danger),
                bouton("Éteindre", am(AdminMsg::Aller(Page::Confirmer("poweroff"))), style::danger),
            ]
            .spacing(20),
            msg,
            bouton("Quitter le mode administrateur", am(AdminMsg::Quitter), style::primaire),
        ]
        .spacing(20)
        .align_x(Alignment::Center)
        .into(),
        Page::Etat => {
            let mut c = Column::new().spacing(6);
            let line = |k: &str, v: String| row![text(format!("{k} :")).size(style::TEXTE_TAILLE).width(Length::Fixed(380.0)), texte(&v)];
            c = c.push(line("Version Barbacane", etat["versions"]["barbacane"].as_str().unwrap_or("?").into()));
            c = c.push(line("Version usbsas", etat["versions"]["usbsas"].as_str().unwrap_or("?").into()));
            c = c.push(line("ClamAV", etat["versions"]["clamav"].as_str().unwrap_or("?").into()));
            c = c.push(line("Âge des signatures", format!("{} jour(s)", etat["signatures_age_days"].as_u64().map(|d| d.to_string()).unwrap_or("?".into()))));
            c = c.push(line("Règles YARA", etat["yara_rules"].as_u64().map(|n| format!("{n} fichier(s)")).unwrap_or("?".into())));
            c = c.push(line("Version du dernier paquet de mise à jour", etat["update_version"].as_u64().map(|n| n.to_string()).unwrap_or("aucun".into())));
            c = c.push(line("Espace disque libre", etat["disk_free"].as_str().unwrap_or("?").into()));
            c = c.push(line("Espace de travail (analyse)", espace_travail(&etat["espace_travail"])));
            c = c.push(line("Transferts journalisés", etat["reports"].as_u64().map(|n| n.to_string()).unwrap_or("?".into())));
            column![titre("État de la borne"), carte(c), retour].spacing(20).align_x(Alignment::Center).into()
        }
        Page::MiseAJour => column![
            titre("Mise à jour hors ligne"),
            carte(column![
                texte("1. Branchez la clé administrateur contenant le paquet de mise à jour (*.bcu et *.bcu.minisig) sur le port d'entrée."),
                texte("2. Lancez la lecture : le paquet est lu par usbsas, sa signature et sa version sont vérifiées, puis il est appliqué."),
                petit("Un paquet non signé, corrompu ou plus ancien que la version installée est refusé."),
            ]),
            msg,
            row![retour, bouton_busy("Lire et appliquer", am(AdminMsg::LireMaj), a.busy)].spacing(30),
        ]
        .spacing(20)
        .align_x(Alignment::Center)
        .into(),
        Page::Export => column![
            titre("Exporter les journaux et rapports"),
            carte(column![
                texte("Branchez la clé administrateur sur le port de sortie."),
                texte_c("Elle sera effacée et formatée en exFAT.", style::c().menace),
            ]),
            msg,
            row![retour, bouton_busy("Exporter", am(AdminMsg::Exporter), a.busy)].spacing(30),
        ]
        .spacing(20)
        .align_x(Alignment::Center)
        .into(),
        Page::Enrolement => {
            let on = etat["enrolled_mode"].as_bool() == Some(true);
            let mut list = Column::new().spacing(8);
            for k in etat["enrolled"].as_array().cloned().unwrap_or_default() {
                list = list.push(
                    row![
                        container(texte(k["description"].as_str().unwrap_or("?"))).width(Length::Fill),
                        bouton("Retirer", am(AdminMsg::Retirer(k.clone())), style::secondaire)
                    ]
                    .spacing(20)
                    .align_y(Alignment::Center),
                );
            }
            let plugged: Vec<UsbDevice> = app.devices.usb.iter().map(|(_, d)| d.clone()).collect();
            let mut add = Column::new().spacing(8);
            let deja: Vec<serde_json::Value> = etat["enrolled"].as_array().cloned().unwrap_or_default();
            for d in plugged {
                // Une clé déjà enrôlée n'est plus proposée.
                if deja.iter().any(|k| k["serial"].as_str() == Some(d.serial.as_str())
                    && k["vendorid"].as_u64() == Some(u64::from(d.vendorid))
                    && k["productid"].as_u64() == Some(u64::from(d.productid)))
                {
                    continue;
                }
                add = add.push(bouton(&format!("Enrôler : {}", barbacane_parcours::describe(&d)), am(AdminMsg::Enroler(d)), style::primaire));
            }
            column![
                titre("Clés de sortie enrôlées"),
                row![
                    texte(if on { "Mode clés enrôlées : ACTIVÉ (seules ces clés sont acceptées en sortie)" } else { "Mode clés enrôlées : désactivé (toute clé acceptée en sortie)" }),
                    bouton(if on { "Désactiver" } else { "Activer" }, am(AdminMsg::ModeEnrole(!on)), style::secondaire),
                ]
                .spacing(20)
                .align_y(Alignment::Center),
                container(scrollable(list).height(Length::Fixed(120.0)).width(Length::Fixed(1000.0))).padding(12).style(style::carte),
                petit("Pour enrôler une clé, branchez-la : elle apparaît ci-dessous."),
                add,
                row![msg, retour].spacing(20).align_y(Alignment::Center),
            ]
            .spacing(20)
            .align_x(Alignment::Center)
            .into()
        }
        Page::Affichage => {
            let p = &etat["preferences"];
            let nuit = p["theme"].as_str() == Some("nuit");
            let reduites = p["animations_reduites"].as_bool() == Some(true);
            let choix = |lib: &str, actif: bool, m: AdminMsg| {
                bouton(
                    &if actif { format!("✓ {lib}") } else { lib.to_string() },
                    am(m),
                    if actif { style::primaire } else { style::secondaire },
                )
            };
            column![
                titre("Affichage"),
                carte(column![
                    texte("Thème"),
                    row![
                        choix("Pierre (clair)", !nuit, AdminMsg::Affichage("pierre", reduites)),
                        choix("Nuit (sombre)", nuit, AdminMsg::Affichage("nuit", reduites)),
                    ]
                    .spacing(20),
                    petit("Pierre : bureau éclairé (par défaut). Nuit : salle peu éclairée."),
                    Space::new().height(10),
                    texte("Animations"),
                    row![
                        choix("Normales", !reduites, AdminMsg::Affichage(if nuit { "nuit" } else { "pierre" }, false)),
                        choix("Réduites", reduites, AdminMsg::Affichage(if nuit { "nuit" } else { "pierre" }, true)),
                    ]
                    .spacing(20),
                    petit("Réduites : chaque écran s'affiche directement dans son état final."),
                ]),
                row![msg, retour].spacing(20).align_y(Alignment::Center),
            ]
            .spacing(20)
            .align_x(Alignment::Center)
            .into()
        }
        Page::APropos => {
            // Charte, composant Credits : nom, rôle, éditeur, licence et adresse ; pas de logos
            // redessinés ; mention « non affilié » obligatoire.
            let pal = style::c();
            let projet = |nom: &str, role: &str, editeur: &str, adresse: &str| {
                container(
                    column![
                        text(nom.to_string()).size(30).font(style::TITRE_POLICE),
                        text(role.to_string()).size(style::PETIT),
                        text(editeur.to_string())
                            .size(15)
                            .font(style::MONO)
                            .color(pal.encre_douce),
                        text(adresse.to_string())
                            .size(15)
                            .font(style::MONO)
                            .color(pal.encre_douce),
                    ]
                    .spacing(4),
                )
                .padding(iced::Padding { top: 14.0, ..iced::Padding::ZERO })
                .width(Length::Fixed(300.0))
                .style(move |_| container::Style {
                    border: iced::Border::default().width(0),
                    ..Default::default()
                })
            };
            let filet = || {
                container(Space::new().width(300).height(4)).style(move |_| container::Style {
                    background: Some(iced::Background::Color(pal.laiton)),
                    ..Default::default()
                })
            };
            column![
                titre("À propos"),
                carte(column![
                    text("BARBACANE S'APPUIE SUR").size(26).font(style::TITRE_POLICE),
                    row![
                        column![filet(), projet("usbsas", "Lecture isolée des supports USB", "CEA-SEC · GPLv3", "github.com/cea-sec/usbsas")],
                        column![filet(), projet("ClamAV", "Moteur antivirus et signatures", "Cisco Talos · GPLv2", "clamav.net")],
                        column![filet(), projet("YARA", "Règles de détection", "VirusTotal · BSD-3-Clause", "virustotal.github.io/yara")],
                    ]
                    .spacing(24),
                    petit("Marques et logos appartenant à leurs détenteurs. Barbacane n'est ni affilié ni approuvé par eux."),
                ]),
                petit(&format!("Barbacane {} — {}", env!("CARGO_PKG_VERSION"), crate::app::mention_station(&etat))),
                retour,
            ]
            .spacing(20)
            .align_x(Alignment::Center)
            .into()
        }
        Page::Limites => {
            let l = &a.limits;
            let ligne = |lib: &str, k: &'static str, v: String| {
                row![
                    text(lib.to_string()).size(style::TEXTE_TAILLE).width(Length::Fixed(420.0)),
                    bouton("−", am(AdminMsg::Limite(k, -1)), style::secondaire),
                    text(v).size(style::TEXTE_TAILLE).width(Length::Fixed(160.0)).center(),
                    bouton("+", am(AdminMsg::Limite(k, 1)), style::secondaire),
                ]
                .spacing(14)
                .align_y(Alignment::Center)
            };
            column![
                titre("Limites d'analyse des archives"),
                carte(column![
                    ligne("Profondeur d'imbrication", "max_depth", l["max_depth"].to_string()),
                    ligne("Nombre de fichiers par transfert", "max_files", l["max_files"].to_string()),
                    ligne(
                        "Taille décompressée par transfert",
                        "max_total_size",
                        format!("{:.1} Go", l["max_total_size"].as_f64().unwrap_or(0.0) / 1073741824.0)
                    ),
                ]),
                msg,
                row![retour, bouton_busy("Enregistrer", am(AdminMsg::EnregistrerLimites), a.busy)].spacing(30),
            ]
            .spacing(20)
            .align_x(Alignment::Center)
            .into()
        }
        Page::NouveauPin => column![
            titre("Changer le PIN"),
            texte(if a.first_pin.is_some() { "Confirmez le nouveau PIN." } else { "Nouveau PIN (6 chiffres minimum)." }),
            container(text(a.input.shown()).size(30)).padding(8).width(Length::Fixed(360.0)).style(style::carte),
            a.input.view(|k| am(AdminMsg::Key(k))),
            msg,
            row![retour, bouton("Valider", am(AdminMsg::EnregistrerPin), style::primaire)].spacing(30),
        ]
        .spacing(12) // tient en 1280×768
        .align_x(Alignment::Center)
        .into(),
        Page::Serveur => view_serveur(&etat, msg, retour, a.busy),
        Page::Jeton => column![
            titre("Jeton d'enrôlement"),
            texte("Saisissez le jeton remis par l'administrateur du serveur (forme 43118-ABCD…)."),
            container(text(a.input.value.to_uppercase()).size(26).font(style::MONO)).padding(8).width(Length::Fixed(720.0)).style(style::carte),
            a.input.view(|k| am(AdminMsg::Key(k))),
            msg,
            row![
                bouton("Annuler", am(AdminMsg::Aller(Page::Serveur)), style::secondaire),
                bouton_busy("Valider", am(AdminMsg::EnregistrerJeton), a.busy),
            ]
            .spacing(30),
        ]
        .spacing(12) // tient en 1280×768
        .align_x(Alignment::Center)
        .into(),
        Page::Confirmer(op) => column![
            titre(if *op == "reboot" { "Redémarrer la borne ?" } else { "Éteindre la borne ?" }),
            msg,
            row![retour, bouton("Confirmer", am(AdminMsg::Executer(op)), style::danger)].spacing(30),
        ]
        .spacing(20)
        .align_x(Alignment::Center)
        .into(),
    };
    container(body)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

fn bouton_busy<'a>(t: &str, m: Msg, busy: bool) -> Element<'a, Msg> {
    if busy {
        iced::widget::button(text("Patientez…").size(style::TEXTE_TAILLE))
            .padding([18, 30])
            .style(style::secondaire)
            .into()
    } else {
        bouton(t, m, style::primaire)
    }
}

/// « 120,3 Go libres sur 128,0 Go : contenu analysable jusqu'à 40,1 Go environ »
fn espace_travail(v: &serde_json::Value) -> String {
    match (v["libre"].as_u64(), v["total"].as_u64()) {
        (Some(libre), Some(total)) => format!(
            "{} libres sur {} : contenu analysable jusqu'à {} environ",
            barbacane_parcours::go(libre),
            barbacane_parcours::go(total),
            barbacane_parcours::go(libre / barbacane_parcours::FACTEUR_ESPACE)
        ),
        _ => "non monté".into(),
    }
}

/// Profil en ligne : admind ne publie le bloc `serveur` que si l'agent est configuré.
pub fn profil_en_ligne(etat: &Value) -> bool {
    etat["serveur"].is_object()
}

/// « il y a 42 s », « il y a 5 min »… (heure de la borne).
fn il_y_a(t: Option<u64>) -> String {
    let Some(t) = t else {
        return "jamais".into();
    };
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = maintenant.saturating_sub(t);
    match d {
        0..60 => format!("il y a {d} s"),
        60..3600 => format!("il y a {} min", d / 60),
        3600..86400 => format!("il y a {} h", d / 3600),
        _ => format!("il y a {} jour(s)", d / 86400),
    }
}

/// Empreinte en groupes de 4, sur deux lignes (à faire retaper côté serveur).
fn empreinte_groupee(e: &str) -> String {
    let groupes: Vec<String> = e
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    groupes
        .chunks(8)
        .map(|l| l.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn mode_lisible(mode: Option<&str>) -> &'static str {
    match mode {
        Some("non_enrolee") => "Non enrôlée : saisissez un jeton d'enrôlement",
        Some("attente_validation") => "En attente de validation par l'administrateur du serveur",
        Some("connectee") => "Enrôlée, liaison établie",
        Some("degradee") => "Mode dégradé : serveur injoignable (la borne fonctionne hors ligne)",
        Some("refusee") => "Refusée par le serveur : nouvel enrôlement nécessaire",
        _ => "Agent arrêté (aucun état publié)",
    }
}

fn view_serveur<'a>(
    etat: &Value,
    msg: Element<'a, Msg>,
    retour: Element<'a, Msg>,
    busy: bool,
) -> Element<'a, Msg> {
    let s = &etat["serveur"];
    let ag = &s["agent"];
    let line = |k: &str, v: String| {
        row![
            text(format!("{k} :"))
                .size(style::TEXTE_TAILLE)
                .width(Length::Fixed(380.0)),
            texte(&v)
        ]
    };
    let mut c = Column::new().spacing(6);
    c = c.push(line(
        "Serveur",
        s["adresse"].as_str().unwrap_or("?").to_string(),
    ));
    c = c.push(line("État", mode_lisible(ag["mode"].as_str()).into()));
    if let Some(e) = ag["empreinte"].as_str() {
        c = c.push(texte(
            "Empreinte de la demande, à faire retaper par l'administrateur du serveur :",
        ));
        c = c.push(text(empreinte_groupee(e)).size(22).font(style::MONO));
    }
    c = c.push(line(
        "Dernière synchronisation",
        il_y_a(ag["derniere_liaison"].as_u64()),
    ));
    c = c.push(line(
        "Écart d'horloge",
        match ag["ecart_horloge_s"].as_i64() {
            Some(e) if ag["horloge_derivee"] == true => {
                format!("{e:+} s (horloge décalée : signalé au serveur)")
            }
            Some(e) => format!("{e:+} s"),
            None => "inconnu".into(),
        },
    ));
    c = c.push(line(
        "Rapports en attente d'envoi",
        ag["rapports_en_attente"].as_u64().unwrap_or(0).to_string(),
    ));
    if let Some(m) = ag["message"].as_str().or(s["erreur"].as_str()) {
        c = c.push(petit(m));
    }
    let maj = &ag["mise_a_jour"];
    let mut actions = row![retour].spacing(30);
    if maj["prete"] == true {
        c = c.push(Space::new().height(8));
        c = c.push(texte(&format!(
            "Mise à jour {} reçue du serveur ({}).",
            maj["version_maj"].as_u64().unwrap_or(0),
            barbacane_parcours::go(maj["taille"].as_u64().unwrap_or(0))
        )));
        c = c.push(petit("Sa signature et sa version sont vérifiées par la borne avant l'application, comme pour une clé administrateur."));
        actions = actions.push(bouton_busy(
            "Vérifier et appliquer",
            am(AdminMsg::AppliquerMajServeur),
            busy,
        ));
    } else if maj["rapport_en_attente"] == true {
        c = c.push(petit(&format!(
            "Résultat de la mise à jour {} en attente de transmission au serveur.",
            maj["version_maj"].as_u64().unwrap_or(0)
        )));
    }
    actions = actions
        .push(bouton(
            "Actualiser",
            am(AdminMsg::Actualiser),
            style::secondaire,
        ))
        .push(bouton(
            "Saisir un jeton",
            am(AdminMsg::Aller(Page::Jeton)),
            style::secondaire,
        ));
    column![titre("Serveur de gestion"), carte(c), msg, actions]
        .spacing(20)
        .align_x(Alignment::Center)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hors_ligne_sans_page_serveur() {
        // État d'admind v1 (aucun bloc « serveur ») : profil hors ligne.
        assert!(!profil_en_ligne(&json!({"pin_set": true, "reports": 3})));
        assert!(profil_en_ligne(&json!({"serveur": {"agent": null}})));
        use crate::app::mention_station;
        assert_eq!(
            mention_station(&json!({"pin_set": true})),
            "station blanche hors ligne"
        );
        assert_eq!(mention_station(&Value::Null), "station blanche hors ligne");
        assert_eq!(
            mention_station(&json!({"serveur": {"agent": null}})),
            "station blanche hors ligne",
            "agent arrêté"
        );
        assert_eq!(
            mention_station(&json!({"serveur": {"agent": {"mode": "connectee"}}})),
            "station blanche en ligne"
        );
    }

    #[test]
    fn accuse_du_jeton_retire_apres_enrolement() {
        let mut a = AdminUi::new(String::new());
        let accuse = "Jeton enregistré : la demande d'enrôlement va être envoyée au serveur.";
        a.message = Some((true, accuse.into()));
        a.message_jeton = Some(accuse.into());
        let etat = |m: &str| json!({"serveur": {"agent": {"mode": m}}});
        a.apres_etat(&etat("non_enrolee"));
        assert!(
            a.message.is_some(),
            "demande pas encore déposée : l'accusé reste"
        );
        a.apres_etat(&etat("connectee"));
        assert!(a.message.is_none(), "borne connectée : l'accusé disparaît");
        assert!(a.message_jeton.is_none());
        // Un autre message (affiché après l'accusé) n'est jamais effacé.
        a.message = Some((false, "autre".into()));
        a.message_jeton = Some(accuse.into());
        a.apres_etat(&etat("attente_validation"));
        assert_eq!(a.message.as_ref().map(|(_, t)| t.as_str()), Some("autre"));
    }

    #[test]
    fn empreinte_sur_deux_lignes() {
        let e = "0123456789abcdef".repeat(4);
        let g = empreinte_groupee(&e);
        assert_eq!(g.lines().count(), 2);
        assert_eq!(g.replace([' ', '\n'], ""), e);
        assert!(g.starts_with("0123 4567 89ab cdef"));
    }

    #[test]
    fn durees() {
        assert_eq!(il_y_a(None), "jamais");
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(il_y_a(Some(t - 300)), "il y a 5 min");
    }
}
