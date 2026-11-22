//! Parcours Barbacane au-dessus d'usbsas, sans interface graphique :
//!
//! - **analyse** : transfert usbsas « clé inconnue → commande » avec analyse,
//!   suivi des demandes de mot de passe de l'analyseur ;
//! - **préparation** : l'analyseur remplit le dossier lu par usbsas ;
//! - **écriture** : transfert usbsas « dossier de préparation → clé » (exFAT) ;
//! - **effacement** : wipe usbsas (option « Blanchir »).
//!
//! Chaque opération usbsas se fait dans une session neuve (usbsas relance ses
//! processus entre deux opérations). Le client graphique exécute ces fonctions
//! dans un fil dédié et reçoit des [`Event`].

use serde::Deserialize;
use std::io;
use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use usbsas_comm::ProtoReqUsbsas;
pub use usbsas_proto as proto;
use usbsas_proto::common::{FsType, PartitionInfo, Status, UsbDevice, device::Device};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Usbsas(io::Error),
    Analyzer(String),
    /// Erreur à présenter telle quelle à l'utilisateur
    User(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Usbsas(e) => write!(f, "usbsas : {e}"),
            Error::Analyzer(e) => write!(f, "analyseur : {e}"),
            Error::User(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Usbsas(e)
    }
}
/// Taille maximale d'une réponse de l'analyseur. ureq coupe à 10 Mo par défaut ; le rapport d'une
/// ISO d'installation (des milliers de fichiers, paquets extraits) dépasse 18 Mo.
const LIMITE_REPONSE: u64 = 512 * 1024 * 1024;

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Error::Analyzer(e.to_string())
    }
}

/// Événements envoyés à l'interface pendant une opération.
#[derive(Debug, Clone)]
pub enum Event {
    /// Étape usbsas et avancement (`current`/`total`, en octets ou fichiers)
    Progress {
        status: Status,
        current: u64,
        total: u64,
    },
    /// Avancement de l'analyse (fichiers de la clé analysés / total, fichiers analysés au total)
    Analysis { done: u64, total: u64, scanned: u64 },
    /// L'analyseur attend un mot de passe (répondre avec [`Analyzer::answer`])
    Password(PasswordRequest),
    /// Plus de mot de passe attendu
    PasswordDone,
    /// Estimation de durée, calculée sur l'inventaire de la clé AVANT la copie vers l'analyseur
    Estimation { images: u64, secondes: u64 },
    /// Vérification de l'empreinte d'une image candidate à la liste officielle (taille connue)
    Verification { nom: String, taille: u64 },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PasswordRequest {
    /// Analyse concernée (rempli par le suivi, absent de la réponse de l'analyseur)
    #[serde(default)]
    pub job: String,
    pub archive: String,
    pub attempt: u32,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Progress {
    pub id: String,
    pub status: String,
    pub error: Option<String>,
    pub done: u64,
    pub total: u64,
    pub scanned: u64,
    pub password_request: Option<PasswordRequest>,
}

/// Ligne du rapport détaillé de l'analyseur.
#[derive(Debug, Clone, Deserialize)]
pub struct FileLine {
    pub path: String,
    pub container: Option<String>,
    pub size: u64,
    pub verdict: String,
    pub reason: String,
    pub output: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Report {
    pub id: String,
    pub status: String,
    pub files: Vec<FileLine>,
}

impl Report {
    /// Fichiers qui seront écrits sur la clé de sortie.
    pub fn copied(&self) -> impl Iterator<Item = &FileLine> {
        self.files.iter().filter(|f| f.output.is_some())
    }

    /// Archive refusée dont le contenu a été extrait (pas un refus pour l'utilisateur).
    pub fn is_unpacked(&self, f: &FileLine) -> bool {
        f.verdict == "DIRTY"
            && self
                .files
                .iter()
                .any(|c| c.container.as_deref() == Some(&f.path))
    }

    /// Fichiers refusés, avec leur raison.
    pub fn refused(&self) -> impl Iterator<Item = &FileLine> {
        self.files
            .iter()
            .filter(|f| f.verdict == "DIRTY" && !self.is_unpacked(f))
    }
}

/// Client de l'API de barbacane-analyzer.
#[derive(Clone)]
pub struct Analyzer {
    base: String,
    http: ureq::Agent,
}

impl Analyzer {
    /// `base` : par exemple `http://127.0.0.1:8042`
    pub fn new(base: &str) -> Self {
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(600)))
            .http_status_as_error(false)
            .build()
            .into();
        Analyzer {
            base: base.trim_end_matches('/').to_string(),
            http,
        }
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let mut r = self.http.get(format!("{}{path}", self.base)).call()?;
        match r.status().as_u16() {
            404 => Ok(None),
            200 => Ok(Some(
                r.body_mut()
                    .with_config()
                    .limit(LIMITE_REPONSE)
                    .read_json()?,
            )),
            c => Err(Error::Analyzer(format!("{path} : HTTP {c}"))),
        }
    }

    fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let mut r = self
            .http
            .post(format!("{}{path}", self.base))
            .send_json(body)?;
        match r.status().as_u16() {
            200 => Ok(r
                .body_mut()
                .with_config()
                .limit(LIMITE_REPONSE)
                .read_json()?),
            204 => Ok(serde_json::Value::Null),
            c => Err(Error::Analyzer(format!(
                "{path} : HTTP {c} {}",
                r.body_mut().read_to_string().unwrap_or_default()
            ))),
        }
    }

    /// Analyse en cours (ou dernière) de la borne `uid`.
    pub fn current(&self, uid: &str) -> Result<Option<Progress>> {
        self.get(&format!("/barbacane/v1/users/{uid}/current"))
    }

    /// Mot de passe (`Some`) ou abandon (`None`) pour l'archive en attente.
    pub fn answer(&self, id: &str, password: Option<&str>) -> Result<()> {
        let body = match password {
            Some(p) => serde_json::json!({"password": p}),
            None => serde_json::json!({"abandon": true}),
        };
        self.post(&format!("/barbacane/v1/scans/{id}/password"), body)
            .map(|_| ())
    }

    pub fn report(&self, id: &str) -> Result<Report> {
        self.get(&format!("/barbacane/v1/scans/{id}/report"))?
            .ok_or_else(|| Error::Analyzer("rapport introuvable".into()))
    }

    /// Remplit le dossier de préparation ; renvoie le nombre de fichiers.
    pub fn stage(&self, id: &str, device: &str) -> Result<u64> {
        let r = self.post(
            &format!("/barbacane/v1/scans/{id}/stage"),
            serde_json::json!({"device": device}),
        )?;
        Ok(r["files"].as_u64().unwrap_or(0))
    }

    /// État de l'analyseur (versions, âge de la base antivirale).
    pub fn status(&self) -> Result<serde_json::Value> {
        self.get("/barbacane/v1/status")?
            .ok_or_else(|| Error::Analyzer("état indisponible".into()))
    }
}

/// Périphériques et destinations connus d'usbsas.
#[derive(Debug, Clone, Default)]
pub struct Devices {
    pub usb: Vec<(u64, UsbDevice)>,
    /// Dossiers locaux (`[[src_local_dirs]]`) : identifiant, chemin
    pub local_dirs: Vec<(u64, String)>,
    /// Destination « commande » utilisée pour l'analyse seule
    pub sink: Option<u64>,
}

impl Devices {
    pub fn sources(&self) -> impl Iterator<Item = &(u64, UsbDevice)> {
        self.usb.iter().filter(|(_, d)| d.is_src)
    }

    pub fn destinations(&self) -> impl Iterator<Item = &(u64, UsbDevice)> {
        self.usb.iter().filter(|(_, d)| d.is_dst)
    }

    /// La même clé physique vue comme destination (pour « Blanchir »).
    pub fn same_as_dst(&self, src: &UsbDevice) -> Option<u64> {
        self.destinations()
            .find(|(_, d)| {
                d.serial == src.serial && d.vendorid == src.vendorid && d.productid == src.productid
            })
            .map(|(id, _)| *id)
    }

    /// Dossier local déclaré dans la configuration usbsas.
    pub fn local_dir(&self, path: &str) -> Option<u64> {
        self.local_dirs
            .iter()
            .find(|(_, p)| p.trim_end_matches('/') == path.trim_end_matches('/'))
            .map(|(id, _)| *id)
    }

    pub fn find(&self, dev: &UsbDevice, dst: bool) -> Option<u64> {
        self.usb
            .iter()
            .find(|(_, d)| {
                d.busnum == dev.busnum
                    && d.devnum == dev.devnum
                    && d.serial == dev.serial
                    && if dst { d.is_dst } else { d.is_src }
            })
            .map(|(id, _)| *id)
    }
}

/// Description d'une clé pour les rapports (horodatage + n° de série).
/// Numéro de série du pseudo-périphérique « lecteur optique » (jamais celui d'une vraie clé :
/// usbsas ne connaît que l'USB ; le disque passe par un dossier local).
pub const OPTIQUE: &str = "BARBACANE-LECTEUR-OPTIQUE";

/// Le périphérique désigne-t-il le lecteur optique ?
pub fn est_optique(d: &UsbDevice) -> bool {
    d.serial == OPTIQUE && d.vendorid == 0 && d.productid == 0
}

/// Pseudo-périphérique « lecteur optique », décrit par `libelle` (type et contenu du disque).
pub fn optique(libelle: &str) -> UsbDevice {
    UsbDevice {
        manufacturer: "Disque optique".into(),
        description: libelle.into(),
        serial: OPTIQUE.into(),
        is_src: true,
        is_dst: true,
        ..Default::default()
    }
}

pub fn describe(d: &UsbDevice) -> String {
    if est_optique(d) {
        return format!("{} : {}", d.manufacturer, d.description);
    }
    format!(
        "{} {} (n° de série {}, {:04x}:{:04x})",
        d.manufacturer.trim(),
        d.description.trim(),
        serie_courte(&d.serial),
        d.vendorid,
        d.productid
    )
}

/// Numéro de série lisible à l'écran : certaines clés en ont un de plus de 100
/// caractères, qui déborde. L'enrôlement compare toujours le numéro complet.
pub fn serie_courte(s: &str) -> String {
    let c: Vec<char> = s.trim().chars().collect();
    if c.len() <= 20 {
        return c.into_iter().collect();
    }
    let debut: String = c[..10].iter().collect();
    let fin: String = c[c.len() - 6..].iter().collect();
    format!("{debut}…{fin}")
}

#[cfg(test)]
mod tests_affichage {
    #[test]
    fn serie_courte() {
        assert_eq!(super::serie_courte("CA003B87786AA493"), "CA003B87786AA493");
        let longue = "0501f66b357c3cb8eaaf6efb1d11265cc6fcdab3ce4e06b163ad06c25b56858f2dd9";
        assert_eq!(super::serie_courte(longue), "0501f66b35…8f2dd9");
    }
}

pub fn devices(comm: &mut impl ProtoReqUsbsas) -> Result<Devices> {
    let list = comm
        .devices(proto::usbsas::RequestDevices { include_alt: true })?
        .devices;
    let mut out = Devices::default();
    for d in list {
        match d.device {
            Some(Device::Usb(u)) => out.usb.push((d.id, u)),
            Some(Device::LocalDir(l)) => out.local_dirs.push((d.id, l.path)),
            Some(Device::Command(_)) => out.sink = Some(d.id),
            _ => (),
        }
    }
    Ok(out)
}

/// Choix de partition par défaut : la plus grande dont le système de fichiers est reconnu.
// shortcut: une seule partition analysée par transfert ; proposer le choix à l'utilisateur si des clés multi-partitions se présentent
pub fn default_partition(parts: &[PartitionInfo]) -> Option<u32> {
    parts
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.type_str.is_empty() && !p.type_str.eq_ignore_ascii_case("unknown"))
        .max_by_key(|(_, p)| p.size)
        .map(|(i, _)| i as u32)
}

/// Résultat de l'analyse d'une clé.
#[derive(Debug)]
pub struct Analysis {
    pub uid: String,
    pub report: Report,
    /// Fichiers écartés par les filtres usbsas (fichiers système)
    pub filtered: Vec<String>,
    /// Clé Ventoy (partition `VTOYEFI`) : peut être reconstruite démarrable
    pub ventoy: bool,
    /// Autre clé démarrable (image Rufus/Etcher : ISO hybride, partition EFI) : sa partie
    /// démarrage n'est pas vérifiable ; un blanchiment ne la garde pas démarrable.
    pub demarrable_autre: bool,
    /// Image officielle (fichier à la racine, empreinte et taille dans la liste signée) : copiée
    /// intacte sans analyse (écart n° 14) ; rien d'autre n'est copié pendant ce passage.
    pub officielle: Option<Officielle>,
}

/// Image officielle reconnue sur la clé source.
#[derive(Debug, Clone, PartialEq)]
pub struct Officielle {
    pub chemin: String,
    pub nom: String,
    pub taille: u64,
    /// Autres éléments de la clé, non copiés pendant ce passage
    pub ignores: usize,
}

/// Image démarrable écrite par Rufus « mode DD », balenaEtcher ou dd : ISO 9660 lue sur la
/// clé, ou partition EFI (type 0xEF, ou étiquette EFI) ; hors Ventoy.
pub fn est_image_demarrable(parts: &[PartitionInfo]) -> bool {
    !est_ventoy(parts)
        && parts.iter().any(|p| {
            p.type_str == "ISO9660"
                || p.ptype == 0xEF
                || p.name_str.trim().eq_ignore_ascii_case("EFI")
                || p.name_str.trim().eq_ignore_ascii_case("UEFI_NTFS")
        })
}

/// Clé Ventoy : une partition étiquetée `VTOYEFI` à côté de la partition de données.
pub fn est_ventoy(parts: &[PartitionInfo]) -> bool {
    parts.len() >= 2
        && parts
            .iter()
            .any(|p| p.name_str.trim().eq_ignore_ascii_case("VTOYEFI"))
}

/// Dossier de l'espace de travail chiffré de la borne (usbsas et analyseur).
pub const ESPACE_TRAVAIL: &str = "/var/lib/barbacane/travail";

/// Une analyse occupe environ 3 fois le contenu dans l'espace de travail : archive de session
/// d'usbsas, copie reçue par l'analyseur, extraction des archives (mesuré le 16/11/2026 : la
/// réception seule prend 2 fois le contenu).
pub const FACTEUR_ESPACE: u64 = 3;

/// (taille totale, espace libre) du système de fichiers qui porte `chemin`, en octets.
pub fn espace(chemin: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(chemin).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY : chemin terminé par NUL, structure de sortie initialisée.
    (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0).then(|| {
        (
            st.f_blocks as u64 * st.f_frsize as u64,
            st.f_bavail as u64 * st.f_frsize as u64,
        )
    })
}

/// Go lisibles (1 décimale)
pub fn go(octets: u64) -> String {
    format!("{:.1} Go", octets as f64 / 1e9).replace('.', ",")
}

/// Refus clair, avant toute copie, d'un contenu que l'espace de travail ne peut pas contenir.
pub fn verifier_espace(contenu: u64, libre: u64) -> Result<()> {
    if contenu.saturating_mul(FACTEUR_ESPACE) > libre {
        return Err(Error::User(format!(
            "contenu trop volumineux pour cette borne : {} à analyser, il faut environ {} \
             d'espace de travail et {} sont disponibles. Rien n'a été copié.",
            go(contenu),
            go(contenu.saturating_mul(FACTEUR_ESPACE)),
            go(libre)
        )));
    }
    Ok(())
}

/// Une image disque (ISO…) analysée intégralement occupe environ 16 fois sa taille dans l'espace
/// de travail (mesure du 21/11/2026 : Debian 13 netinst de 756 Mo, ~77 000 fichiers extraits,
/// ~12 Go de disque).
pub const FACTEUR_IMAGE: u64 = 16;

/// Plafond explicite des images disque analysées intégralement : 4 Go (environ 3 h d'analyse).
/// Au-delà, seule une image officielle déclarée par l'administrateur peut passer.
pub const PLAFOND_IMAGES: u64 = 4_000_000_000;

/// Durée mesurée de l'analyse complète d'une image disque : environ 45 min par Go (Debian 13
/// netinst : 35 min pour 756 Mo sur la borne 950).
pub const SECONDES_PAR_GO_IMAGE: u64 = 45 * 60;
/// Autres fichiers : environ 2 min par Go (copie, envoi à l'analyseur, antivirus).
pub const SECONDES_PAR_GO_AUTRES: u64 = 120;

/// Image disque reconnue à son extension (ce que l'analyseur ouvre et parcourt entièrement).
pub fn est_image_disque(chemin: &str) -> bool {
    let c = chemin.to_ascii_lowercase();
    [
        ".iso", ".img", ".wim", ".esd", ".vhd", ".vhdx", ".vmdk", ".dmg",
    ]
    .iter()
    .any(|e| c.ends_with(e))
}

/// Inventaire d'une source (lecture des répertoires seulement, aucun contenu).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Inventaire {
    /// Taille des images disque
    pub images: u64,
    /// Taille des autres fichiers
    pub autres: u64,
    /// Entrées de la racine : (chemin, taille, fichier ordinaire)
    pub racine: Vec<(String, u64, bool)>,
    /// Inventaire interrompu (trop d'entrées) : tailles minorées
    pub partiel: bool,
}

/// Au-delà, l'inventaire s'arrête (tailles minorées, estimation indicative).
const INVENTAIRE_MAX: usize = 50_000;

/// Parcourt la source ouverte (après `OpenPartition`) par `ReadDir`.
pub fn inventaire(comm: &mut impl ProtoReqUsbsas) -> Result<Inventaire> {
    let mut inv = Inventaire::default();
    let mut a_voir = vec!["/".to_string()];
    let mut vus = 0usize;
    while let Some(d) = a_voir.pop() {
        let r = comm.readdir(proto::usbsas::RequestReadDir { path: d.clone() })?;
        for f in r.filesinfo {
            vus += 1;
            if vus > INVENTAIRE_MAX {
                inv.partiel = true;
                return Ok(inv);
            }
            let fichier = f.ftype == proto::common::FileType::Regular as i32;
            if d == "/" {
                inv.racine.push((f.path.clone(), f.size, fichier));
            }
            if f.ftype == proto::common::FileType::Directory as i32 {
                a_voir.push(f.path);
            } else if fichier {
                if est_image_disque(&f.path) {
                    inv.images += f.size;
                } else {
                    inv.autres += f.size;
                }
            }
        }
        inv.partiel |= r.max_depth_reached;
    }
    Ok(inv)
}

/// Durée estimée de l'analyse complète (secondes).
pub fn estimation(inv: &Inventaire) -> u64 {
    let par_go = |o: u64, s: u64| (o as u128 * s as u128 / 1_000_000_000) as u64;
    par_go(inv.images, SECONDES_PAR_GO_IMAGE) + par_go(inv.autres, SECONDES_PAR_GO_AUTRES)
}

/// Durée lisible arrondie (« environ 35 min », « environ 2 h 15 »).
pub fn duree_lisible(s: u64) -> String {
    let min = s.div_ceil(60).max(1);
    if min < 60 {
        format!("environ {min} min")
    } else {
        let m = (min % 60) / 5 * 5;
        if m == 0 {
            format!("environ {} h", min / 60)
        } else {
            format!("environ {} h {m:02}", min / 60)
        }
    }
}

/// Refus clair et tôt (avant toute copie) d'une analyse complète impossible : plafond des
/// images disque, puis espace de travail (images × 16, autres × 3).
pub fn verifier_analyse(inv: &Inventaire, libre: Option<u64>) -> Result<()> {
    if inv.images > PLAFOND_IMAGES {
        return Err(Error::User(format!(
            "image disque trop volumineuse pour une analyse complète : {} d'images (plafond {}, \
             analyse estimée à {}). Seule une image officielle déclarée par l'administrateur \
             (liste signée) peut passer au-delà. Rien n'a été copié.",
            go(inv.images),
            go(PLAFOND_IMAGES),
            duree_lisible(estimation(inv))
        )));
    }
    let besoin = inv
        .images
        .saturating_mul(FACTEUR_IMAGE)
        .saturating_add(inv.autres.saturating_mul(FACTEUR_ESPACE));
    if let Some(libre) = libre
        && besoin > libre
    {
        return Err(Error::User(format!(
            "contenu trop volumineux pour cette borne : {} à analyser (dont {} d'images disque), \
             il faut environ {} d'espace de travail et {} sont disponibles. Rien n'a été copié.",
            go(inv.images + inv.autres),
            go(inv.images),
            go(besoin),
            go(libre)
        )));
    }
    Ok(())
}

/// Entrée de la liste signée des images officielles : « sha256 taille nom » (v2.1.0) ou
/// « sha256  nom » (v2.0, sans taille : reconnue seulement par l'analyseur et l'écart 11).
#[derive(Debug, Clone, PartialEq)]
pub struct ImageListe {
    pub sha256: [u8; 32],
    pub taille: Option<u64>,
    pub nom: String,
}

/// Lit la liste ; lignes invalides ignorées ; absente : liste vide.
pub fn liste_images(chemin: &str) -> Vec<ImageListe> {
    let Ok(t) = std::fs::read_to_string(chemin) else {
        return Vec::new();
    };
    t.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let h = it.next()?;
            if h.len() != 64 {
                return None;
            }
            let mut o = [0u8; 32];
            for (i, b) in o.iter_mut().enumerate() {
                *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            let reste: Vec<&str> = it.collect();
            let (taille, nom) = match reste.split_first() {
                Some((t, n)) if !n.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) => {
                    (t.parse().ok(), n.join(" "))
                }
                _ => (None, reste.join(" ")),
            };
            Some(ImageListe {
                sha256: o,
                taille,
                nom,
            })
        })
        .collect()
}

/// Fichiers de la racine candidats à la liste officielle : taille présente dans la liste.
pub fn candidats<'a>(inv: &'a Inventaire, liste: &[ImageListe]) -> Vec<&'a (String, u64, bool)> {
    inv.racine
        .iter()
        .filter(|(_, t, f)| *f && liste.iter().any(|i| i.taille == Some(*t)))
        .collect()
}

/// Empreintes et tailles de la liste au format de la requête `OfficialFile`.
fn requete_liste(liste: &[ImageListe]) -> (Vec<Vec<u8>>, Vec<u64>) {
    liste
        .iter()
        .filter_map(|i| Some((i.sha256.to_vec(), i.taille?)))
        .unzip()
}

/// FAT32 : aucun fichier de plus de 4 Gio - 1. Refus clair AVANT toute écriture.
pub fn verifier_format(fstype: FsType, tailles: impl IntoIterator<Item = u64>) -> Result<()> {
    if fstype == FsType::Fat
        && let Some(t) = tailles.into_iter().filter(|t| *t > 0xFFFF_FFFF).max()
    {
        return Err(Error::User(format!(
            "un fichier fait {} : le format FAT32 n'accepte pas les fichiers de plus de 4 Go. \
             Choisissez exFAT (recommandé) ou NTFS. Rien n'a été écrit.",
            go(t)
        )));
    }
    Ok(())
}

/// Nom lisible d'un format de sortie.
pub fn nom_format(f: FsType) -> &'static str {
    match f {
        FsType::Fat => "FAT32",
        FsType::Exfat => "exFAT",
        FsType::Ntfs => "NTFS",
    }
}

fn wait_done(comm: &mut impl ProtoReqUsbsas, ev: &Sender<Event>) -> io::Result<()> {
    wait_done_espace(comm, ev, None).map_err(|e| match e {
        Error::Usbsas(e) => e,
        e => io::Error::other(e.to_string()),
    })
}

/// Comme `wait_done` ; avec `libre`, interrompt la lecture dès que usbsas annonce la taille
/// totale du contenu si elle dépasse l'espace de travail.
fn wait_done_espace(
    comm: &mut impl ProtoReqUsbsas,
    ev: &Sender<Event>,
    libre: Option<u64>,
) -> Result<()> {
    let mut verifie = libre.is_none();
    loop {
        let st = comm.recv_status()?;
        let status = Status::try_from(st.status).unwrap_or(Status::Unknown);
        if !verifie && status == Status::ReadSrc && st.total > 0 {
            verifie = true;
            if let Some(libre) = libre {
                verifier_espace(st.total, libre)?;
            }
        }
        let _ = ev.send(Event::Progress {
            status,
            current: st.current,
            total: st.total,
        });
        if status == Status::AllDone {
            return Ok(());
        }
    }
}

/// Lit la clé inconnue et la fait analyser. La session usbsas est terminée au retour.
pub fn analyse(
    comm: &mut impl ProtoReqUsbsas,
    analyzer: &Analyzer,
    src: u64,
    sink: u64,
    ev: &Sender<Event>,
) -> Result<Analysis> {
    analyse_source(comm, analyzer, src, sink, true, ev)
}

/// Analyse d'un dossier local déclaré dans `[[src_local_dirs]]` (disque optique extrait par
/// barbacane-optique) : même parcours qu'une clé inconnue, sans choix de partition.
pub fn analyse_dossier(
    comm: &mut impl ProtoReqUsbsas,
    analyzer: &Analyzer,
    src: u64,
    sink: u64,
    ev: &Sender<Event>,
) -> Result<Analysis> {
    analyse_source(comm, analyzer, src, sink, false, ev)
}

fn analyse_source(
    comm: &mut impl ProtoReqUsbsas,
    analyzer: &Analyzer,
    src: u64,
    sink: u64,
    usb: bool,
    ev: &Sender<Event>,
) -> Result<Analysis> {
    let uid = comm.userid(proto::usbsas::RequestUserId {})?.userid;
    comm.inittransfer(proto::usbsas::RequestInitTransfer {
        source: src,
        destination: sink,
        fstype: None,
        pin: None,
        bootable: false,
    })?;
    let mut ventoy = false;
    let mut demarrable_autre = false;
    if usb {
        let parts = comm
            .partitions(proto::usbsas::RequestPartitions {})?
            .partitions;
        ventoy = est_ventoy(&parts);
        demarrable_autre = est_image_demarrable(&parts);
        let Some(index) = default_partition(&parts) else {
            let _ = comm.end();
            return Err(Error::User(
                "aucun système de fichiers lisible sur la clé".into(),
            ));
        };
        comm.openpartition(proto::usbsas::RequestOpenPartition { index })?;
    }
    // Inventaire (répertoires seulement) : image officielle, plafond, espace, estimation —
    // tout est décidé avant de copier quoi que ce soit.
    let inv = match inventaire(comm) {
        Ok(i) => i,
        Err(e) => {
            let _ = comm.end();
            return Err(e);
        }
    };
    let liste = liste_images(LISTE_IMAGES);
    if usb && let Some(o) = chercher_officielle(comm, &inv, &liste, ev) {
        let _ = comm.end();
        let o = o?;
        return Ok(Analysis {
            uid,
            report: Report {
                id: String::new(),
                status: "officielle".into(),
                files: vec![FileLine {
                    path: o.chemin.clone(),
                    container: None,
                    size: o.taille,
                    verdict: "CLEAN".into(),
                    reason: format!(
                        "image officielle reconnue (liste de l'administrateur : {})",
                        o.nom
                    ),
                    output: Some(o.chemin.clone()),
                }],
            },
            filtered: Vec::new(),
            ventoy,
            demarrable_autre,
            officielle: Some(o),
        });
    }
    let libre = espace(ESPACE_TRAVAIL).map(|(_, l)| l);
    if let Err(e) = verifier_analyse(&inv, libre) {
        let _ = comm.end();
        return Err(e);
    }
    let _ = ev.send(Event::Estimation {
        images: inv.images,
        secondes: estimation(&inv),
    });
    comm.selectfiles(proto::usbsas::RequestSelectFiles {
        selected: vec!["/".into()],
    })?;

    // Suivi de l'analyseur en parallèle : usbsas reste bloqué tant qu'un mot de passe est attendu.
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (stop, analyzer, ev, uid) = (stop.clone(), analyzer.clone(), ev.clone(), uid.clone());
        std::thread::spawn(move || {
            let mut asked = None;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(Some(p)) = analyzer.current(&uid) {
                    let _ = ev.send(Event::Analysis {
                        done: p.done,
                        total: p.total,
                        scanned: p.scanned,
                    });
                    let mut req = p.password_request;
                    if let Some(r) = req.as_mut() {
                        r.job = p.id.clone();
                    }
                    if req != asked {
                        let _ = ev.send(match &req {
                            Some(r) => Event::Password(r.clone()),
                            None => Event::PasswordDone,
                        });
                        asked = req;
                    }
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        })
    };
    let res = wait_done_espace(comm, ev, libre);
    stop.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    let filtered = match res {
        Ok(()) => comm
            .report(proto::usbsas::RequestReport {})
            .ok()
            .and_then(|r| r.report)
            .map(|r| r.filtered)
            .unwrap_or_default(),
        // Rien de sain parmi les fichiers de la clé : le contenu extrait des archives peut l'être.
        Err(e) if e.to_string().contains("Nothing to copy after analyzer") => Vec::new(),
        Err(e @ Error::User(_)) => {
            let _ = comm.end();
            return Err(e);
        }
        Err(e) => {
            let _ = comm.end();
            return Err(e);
        }
    };
    let _ = comm.end();
    let p = analyzer
        .current(&uid)?
        .ok_or_else(|| Error::Analyzer("analyse introuvable".into()))?;
    if p.status != "scanned" {
        return Err(Error::Analyzer(
            p.error.unwrap_or_else(|| format!("statut {}", p.status)),
        ));
    }
    let report = analyzer.report(&p.id)?;
    Ok(Analysis {
        uid,
        report,
        filtered,
        ventoy,
        demarrable_autre,
        officielle: None,
    })
}

/// Cherche une image officielle parmi les fichiers de la racine dont la taille figure dans la
/// liste : empreinte calculée par usbsas (lecture seule, rien n'est stocké). `None` : aucune
/// (analyse normale). Une empreinte différente retombe sur l'analyse normale.
pub fn chercher_officielle(
    comm: &mut impl ProtoReqUsbsas,
    inv: &Inventaire,
    liste: &[ImageListe],
    ev: &Sender<Event>,
) -> Option<Result<Officielle>> {
    let (sha256, size) = requete_liste(liste);
    for (chemin, taille, _) in candidats(inv, liste) {
        let _ = ev.send(Event::Verification {
            nom: chemin.trim_start_matches('/').to_string(),
            taille: *taille,
        });
        let r = match comm.officialfile(proto::usbsas::RequestOfficialFile {
            path: chemin.clone(),
            sha256: sha256.clone(),
            size: size.clone(),
            copy: false,
        }) {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };
        if !r.matched {
            log::info!("{chemin} : empreinte absente de la liste, analyse normale");
            continue;
        }
        let nom = liste
            .iter()
            .find(|i| i.sha256.as_slice() == r.sha256.as_slice() && i.taille == Some(*taille))
            .map(|i| i.nom.clone())
            .unwrap_or_default();
        return Some(Ok(Officielle {
            chemin: chemin.clone(),
            nom,
            taille: *taille,
            ignores: inv.racine.len() - 1,
        }));
    }
    None
}

/// Copie l'image officielle `chemin` de la clé `src` sur `dst` (formatée en `fstype`), sans
/// analyse : usbsas la relit en flux, la hache au passage et n'écrit `dst` que si l'empreinte
/// figure dans la liste (écart n° 14). Contrôles de format et de place avant toute écriture.
pub fn ecrire_officielle(
    comm: &mut impl ProtoReqUsbsas,
    src: u64,
    dst: u64,
    o: &Officielle,
    fstype: FsType,
    ev: &Sender<Event>,
) -> Result<()> {
    ecrire_officielle_avec(comm, src, dst, o, fstype, &liste_images(LISTE_IMAGES), ev)
}

/// Comme [`ecrire_officielle`], avec la liste donnée (tests).
pub fn ecrire_officielle_avec(
    comm: &mut impl ProtoReqUsbsas,
    src: u64,
    dst: u64,
    o: &Officielle,
    fstype: FsType,
    liste: &[ImageListe],
    ev: &Sender<Event>,
) -> Result<()> {
    verifier_format(fstype, [o.taille])?;
    let (sha256, size) = requete_liste(liste);
    if sha256.is_empty() {
        return Err(Error::User(
            "liste des images officielles absente : rien n'a été écrit".into(),
        ));
    }
    let r = (|| -> Result<()> {
        comm.userid(proto::usbsas::RequestUserId {})?;
        comm.inittransfer(proto::usbsas::RequestInitTransfer {
            source: src,
            destination: dst,
            fstype: Some(fstype.into()),
            pin: None,
            bootable: false,
        })?;
        let parts = comm
            .partitions(proto::usbsas::RequestPartitions {})?
            .partitions;
        let index = default_partition(&parts)
            .ok_or_else(|| Error::User("aucun système de fichiers lisible sur la clé".into()))?;
        comm.openpartition(proto::usbsas::RequestOpenPartition { index })?;
        comm.officialfile(proto::usbsas::RequestOfficialFile {
            path: o.chemin.clone(),
            sha256,
            size,
            copy: true,
        })?;
        Ok(wait_done(comm, ev)?)
    })();
    let _ = comm.end();
    r
}

/// Écrit le dossier de préparation sur la clé `dst` (effacée et formatée en `fstype` par usbsas).
pub fn write(
    comm: &mut impl ProtoReqUsbsas,
    stage: u64,
    dst: u64,
    fstype: FsType,
    ev: &Sender<Event>,
) -> Result<proto::common::TransferReport> {
    write_mode(comm, stage, dst, false, fstype, ev)
}

/// Écrit le dossier de préparation sur `dst` reconstruite en clé Ventoy démarrable (écart n° 9) :
/// zone de démarrage de la version embarquée, fichiers sains seulement, dossier `ventoy/`
/// (configuration et greffons de la clé d'origine) jamais recopié.
pub fn write_demarrable(
    comm: &mut impl ProtoReqUsbsas,
    stage: u64,
    dst: u64,
    ev: &Sender<Event>,
) -> Result<proto::common::TransferReport> {
    write_mode(comm, stage, dst, true, FsType::Exfat, ev)
}

/// Liste des images officielles livrée par mise à jour signée (aussi lue par l'analyseur).
pub const LISTE_IMAGES: &str = "/var/lib/barbacane/listes/images-officielles.sha256";

/// Lecture d'une image disque limitée à 16 Gio (les ISO d'installation font moins de 10 Go).
pub const IMAGE_MAX: u64 = 16 << 30;

/// Empreintes SHA-256 de la liste ; absente : liste vide.
pub fn images_officielles(chemin: &str) -> Vec<[u8; 32]> {
    liste_images(chemin).into_iter().map(|i| i.sha256).collect()
}

/// Clé Etcher / Rufus « mode DD » : réécrit l'image qu'elle porte si ses premiers octets sont
/// une image officielle de la liste (écart n° 11). Sinon erreur, et la clé n'est pas modifiée.
pub fn reecrire_image(
    comm: &mut impl ProtoReqUsbsas,
    dev: u64,
    images: &[[u8; 32]],
    ev: &Sender<Event>,
) -> Result<()> {
    comm.rewriteimage(proto::usbsas::RequestRewriteImage {
        id: dev,
        sha256: images.iter().map(|h| h.to_vec()).collect(),
        max_size: IMAGE_MAX,
    })?;
    let res = wait_done(comm, ev);
    let _ = comm.end();
    Ok(res?)
}

/// Sélection : tout, sauf `ventoy/` à la racine pour une clé Ventoy reconstruite.
pub fn selection(racine: &[String], demarrable: bool) -> Vec<String> {
    if !demarrable {
        return vec!["/".into()];
    }
    racine
        .iter()
        .filter(|p| {
            !p.trim_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .eq_ignore_ascii_case("ventoy")
        })
        .cloned()
        .collect()
}

fn write_mode(
    comm: &mut impl ProtoReqUsbsas,
    stage: u64,
    dst: u64,
    demarrable: bool,
    fstype: FsType,
    ev: &Sender<Event>,
) -> Result<proto::common::TransferReport> {
    comm.userid(proto::usbsas::RequestUserId {})?;
    comm.inittransfer(proto::usbsas::RequestInitTransfer {
        source: stage,
        destination: dst,
        fstype: Some(fstype.into()),
        pin: None,
        bootable: demarrable,
    })?;
    let racine: Vec<String> = if demarrable {
        comm.readdir(proto::usbsas::RequestReadDir { path: "/".into() })?
            .filesinfo
            .into_iter()
            .map(|f| f.path)
            .collect()
    } else {
        Vec::new()
    };
    comm.selectfiles(proto::usbsas::RequestSelectFiles {
        selected: selection(&racine, demarrable),
    })?;
    let res = wait_done(comm, ev);
    let report = res.and_then(|_| comm.report(proto::usbsas::RequestReport {}));
    let _ = comm.end();
    let report = report?
        .report
        .ok_or_else(|| Error::User("rapport d'écriture absent".into()))?;
    if !report.errors.is_empty() {
        return Err(Error::User(format!(
            "{} fichier(s) n'ont pas pu être écrits : {}",
            report.errors.len(),
            report.errors.join(", ")
        )));
    }
    Ok(report)
}

/// Termine la session usbsas sans rien faire (le service en démarre une nouvelle).
pub fn terminer(comm: &mut impl ProtoReqUsbsas) {
    let _ = comm.end();
}

/// Efface entièrement la clé (zéros) et crée un système de fichiers exFAT vide.
pub fn wipe(comm: &mut impl ProtoReqUsbsas, dev: u64, ev: &Sender<Event>) -> Result<()> {
    comm.wipe(proto::usbsas::RequestWipe {
        id: dev,
        quick: false,
        fstype: FsType::Exfat.into(),
    })?;
    let res = wait_done(comm, ev);
    let _ = comm.end();
    Ok(res?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ventoy_detecte_et_dossier_ventoy_ecarte() {
        let p = |n: &str| PartitionInfo {
            name_str: n.into(),
            ..Default::default()
        };
        assert!(est_ventoy(&[p("Ventoy"), p("VTOYEFI")]));
        assert!(!est_ventoy(&[p("VTOYEFI")]));
        assert!(!est_ventoy(&[p("DONNEES"), p("EFI")]));
        assert!(est_image_demarrable(&[p("DONNEES"), p("EFI")]));
        assert!(!est_image_demarrable(&[p("Ventoy"), p("VTOYEFI")]));
        assert!(!est_image_demarrable(&[p("CLE")]));
        let r = ["/ISO".to_string(), "/ventoy".into(), "/notes.txt".into()];
        assert_eq!(selection(&r, true), ["/ISO", "/notes.txt"]);
        assert_eq!(selection(&r, false), ["/"]);
    }

    #[test]
    fn liste_images_lue() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("l.sha256");
        std::fs::write(
            &f,
            "6f1e0c6b714f041eb55f852d2c8622ea57e4a20e67d086a1ecb6109d8e47da4d  Win11.iso\n\
             # commentaire\nzz  mauvais\n",
        )
        .unwrap();
        let l = images_officielles(f.to_str().unwrap());
        assert_eq!(l.len(), 1);
        assert_eq!(l[0][0], 0x6f);
        assert_eq!(l[0][31], 0x4d);
        assert!(images_officielles("/nexiste/pas").is_empty());
    }

    #[test]
    fn liste_avec_tailles() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("l.sha256");
        let h = "6f1e0c6b714f041eb55f852d2c8622ea57e4a20e67d086a1ecb6109d8e47da4d";
        std::fs::write(
            &f,
            format!("{h} 8945637376 Win11 26H2.iso\n{h}  ancien_format.iso\n"),
        )
        .unwrap();
        let l = liste_images(f.to_str().unwrap());
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].taille, Some(8_945_637_376));
        assert_eq!(l[0].nom, "Win11 26H2.iso");
        assert_eq!(l[1].taille, None);
        assert_eq!(l[1].nom, "ancien_format.iso");
        // seules les entrées avec taille vont à usbsas
        let (h2, t2) = requete_liste(&l);
        assert_eq!((h2.len(), t2), (1, vec![8_945_637_376]));
        let inv = Inventaire {
            racine: vec![
                ("/Win11.iso".into(), 8_945_637_376, true),
                ("/autre.iso".into(), 12, true),
                ("/dossier".into(), 8_945_637_376, false),
            ],
            ..Default::default()
        };
        let c = candidats(&inv, &l);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, "/Win11.iso");
    }

    #[test]
    fn plafond_espace_et_estimation() {
        // Debian 13 netinst mesurée : 756 Mo → ~34 min, 12 Go de travail, passe sur 15 Go
        let deb = Inventaire {
            images: 756_000_000,
            ..Default::default()
        };
        assert_eq!(duree_lisible(estimation(&deb)), "environ 35 min");
        assert!(verifier_analyse(&deb, Some(15_000_000_000)).is_ok());
        assert!(verifier_analyse(&deb, Some(10_000_000_000)).is_err());
        // Windows 11 (8,9 Go) : au-delà du plafond, message clair
        let win = Inventaire {
            images: 8_900_000_000,
            ..Default::default()
        };
        let m = verifier_analyse(&win, None).unwrap_err().to_string();
        assert!(m.contains("plafond") && m.contains("officielle"), "{m}");
        assert!(!m.contains("Not enough space"));
        // autres fichiers : facteur 3
        let doc = Inventaire {
            autres: 4_000_000_000,
            ..Default::default()
        };
        assert!(verifier_analyse(&doc, Some(15_000_000_000)).is_ok());
        let m = verifier_analyse(&doc, Some(11_000_000_000))
            .unwrap_err()
            .to_string();
        assert!(m.contains("12,0 Go") && m.contains("11,0 Go"), "{m}");
        assert_eq!(duree_lisible(0), "environ 1 min");
        assert_eq!(duree_lisible(3 * 3600 + 17 * 60), "environ 3 h 15");
        assert_eq!(duree_lisible(7200), "environ 2 h");
        assert!(est_image_disque("/A/Win11.ISO") && !est_image_disque("/notes.txt"));
    }

    #[test]
    fn fat32_refuse_plus_de_4_go() {
        let e = verifier_format(FsType::Fat, [10, 8_945_637_376]).unwrap_err();
        let m = e.to_string();
        assert!(
            m.contains("FAT32") && m.contains("8,9 Go") && m.contains("exFAT"),
            "{m}"
        );
        assert!(verifier_format(FsType::Fat, [0xFFFF_FFFF]).is_ok());
        assert!(verifier_format(FsType::Exfat, [8_945_637_376]).is_ok());
        assert!(verifier_format(FsType::Ntfs, [u64::MAX]).is_ok());
        assert_eq!(nom_format(FsType::Exfat), "exFAT");
    }

    #[test]
    fn espace_insuffisant_refuse_clairement() {
        // 20 Go de contenu demandent environ 60 Go ; 45 Go libres : refus avant copie
        let e = verifier_espace(20_000_000_000, 45_000_000_000).unwrap_err();
        let m = e.to_string();
        assert!(
            m.contains("20,0 Go") && m.contains("60,0 Go") && m.contains("45,0 Go"),
            "{m}"
        );
        assert!(matches!(e, Error::User(_)));
        assert!(verifier_espace(10_000_000_000, 45_000_000_000).is_ok());
        // tailles 64 bits : un NVMe de 4 To ne déborde pas
        assert!(verifier_espace(4_000_000_000_000, u64::MAX).is_ok());
    }

    #[test]
    fn partition_choice() {
        let p = |size, t: &str| PartitionInfo {
            size,
            type_str: t.into(),
            ..Default::default()
        };
        assert_eq!(
            default_partition(&[p(10, "Unknown"), p(5, "FAT"), p(8, "NTFS")]),
            Some(2)
        );
        assert_eq!(default_partition(&[p(10, "Unknown")]), None);
    }
}
