//! HTTP/1.1 minimal et borné : une requête par connexion, en-têtes analysés par `httparse`,
//! tailles contrôlées AVANT lecture, `Transfer-Encoding` refusé, en-têtes de sécurité sur
//! toute réponse.

use std::collections::BTreeMap;
use std::io::{Read, Write};

/// Taille maximale des en-têtes d'une requête.
pub const TAILLE_ENTETE_MAX: usize = 8 * 1024;
/// Taille maximale d'un formulaire `application/x-www-form-urlencoded`.
pub const TAILLE_FORMULAIRE_MAX: usize = 16 * 1024;
/// Nombre maximal d'en-têtes.
const ENTETES_MAX: usize = 48;

/// Politique de sécurité du contenu : aucun script, ressources du serveur seulement.
pub const CSP: &str = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// En-têtes ajoutés à TOUTE réponse.
pub const ENTETES_SECURITE: &[(&str, &str)] = &[
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Strict-Transport-Security", "max-age=31536000"),
    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), usb=(), serial=(), hid=(), payment=()",
    ),
];

/// Erreur de requête : statut HTTP à renvoyer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refus(pub u16);

#[derive(Debug, Clone)]
pub struct Requete {
    pub methode: String,
    /// Chemin sans la partie requête.
    pub chemin: String,
    /// Paramètres de la partie requête (`?a=b`), clés uniques.
    pub parametres: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub type_contenu: Option<String>,
    /// `Content-Length` (0 sans corps).
    pub longueur: u64,
    pub sec_fetch_site: Option<String>,
    /// Octets du corps déjà lus avec les en-têtes.
    pub debut_corps: Vec<u8>,
}

/// Paires `cle=valeur` d'un formulaire ou d'une requête ; clé répétée → refus.
pub fn paires(octets: &[u8]) -> Result<BTreeMap<String, String>, Refus> {
    let mut m = BTreeMap::new();
    for (k, v) in form_urlencoded::parse(octets) {
        if m.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(Refus(400));
        }
    }
    Ok(m)
}

/// Lit et analyse les en-têtes. Le corps n'est PAS lu (voir [`lire_formulaire`] et
/// [`lecteur_corps`]) : l'appelant contrôle la session et le rôle avant.
pub fn lire_entete(flux: &mut impl Read) -> Result<Requete, Refus> {
    let mut tampon = Vec::new();
    let mut bloc = [0u8; 2048];
    let fin = loop {
        if let Some(p) = tampon.windows(4).position(|f| f == b"\r\n\r\n") {
            break p + 4;
        }
        if tampon.len() > TAILLE_ENTETE_MAX {
            return Err(Refus(431));
        }
        let n = flux.read(&mut bloc).map_err(|_| Refus(400))?;
        if n == 0 {
            return Err(Refus(400));
        }
        tampon.extend_from_slice(&bloc[..n]);
    };
    if fin > TAILLE_ENTETE_MAX {
        return Err(Refus(431));
    }
    let mut entetes = [httparse::EMPTY_HEADER; ENTETES_MAX];
    let mut req = httparse::Request::new(&mut entetes);
    match req.parse(&tampon[..fin]) {
        Ok(httparse::Status::Complete(n)) if n == fin => {}
        Err(httparse::Error::TooManyHeaders) => return Err(Refus(431)),
        _ => return Err(Refus(400)),
    }
    if req.version != Some(1) {
        return Err(Refus(400));
    }
    let methode = req.method.ok_or(Refus(400))?.to_owned();
    let cible = req.path.ok_or(Refus(400))?;
    if !cible.starts_with('/') || cible.len() > 2048 {
        return Err(Refus(400));
    }
    let (chemin, requete) = cible.split_once('?').unwrap_or((cible, ""));
    let mut r = Requete {
        methode,
        chemin: chemin.to_owned(),
        parametres: paires(requete.as_bytes())?,
        cookies: BTreeMap::new(),
        type_contenu: None,
        longueur: 0,
        sec_fetch_site: None,
        debut_corps: tampon[fin..].to_vec(),
    };
    let mut longueur = None;
    for e in req.headers.iter() {
        let valeur = std::str::from_utf8(e.value).map_err(|_| Refus(400))?.trim();
        match e.name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if longueur.is_some()
                    || valeur.is_empty()
                    || valeur.len() > 12
                    || !valeur.bytes().all(|c| c.is_ascii_digit())
                {
                    return Err(Refus(400));
                }
                longueur = Some(valeur.parse::<u64>().map_err(|_| Refus(400))?);
            }
            "transfer-encoding" => return Err(Refus(400)),
            "content-type" => {
                if r.type_contenu.replace(valeur.to_owned()).is_some() {
                    return Err(Refus(400));
                }
            }
            "sec-fetch-site" => r.sec_fetch_site = Some(valeur.to_ascii_lowercase()),
            "cookie" => {
                for morceau in valeur.split(';') {
                    if let Some((k, v)) = morceau.trim().split_once('=') {
                        // Cookie répété : ambigu (injection d'un cookie par un sous-domaine) → refus.
                        if r.cookies.insert(k.to_owned(), v.to_owned()).is_some() {
                            return Err(Refus(400));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    r.longueur = match (r.methode.as_str(), longueur) {
        ("POST", None) => return Err(Refus(411)),
        (_, l) => l.unwrap_or(0),
    };
    if r.debut_corps.len() as u64 > r.longueur {
        return Err(Refus(400));
    }
    Ok(r)
}

/// Lecteur du corps exactement borné à `Content-Length`.
pub fn lecteur_corps<'a>(r: &'a Requete, flux: &'a mut impl Read) -> impl Read + 'a {
    let reste = r.longueur - r.debut_corps.len() as u64;
    r.debut_corps.as_slice().chain(flux.take(reste))
}

/// Lit un formulaire urlencodé (taille bornée avant lecture).
pub fn lire_formulaire(
    r: &Requete,
    flux: &mut impl Read,
) -> Result<BTreeMap<String, String>, Refus> {
    let type_contenu = r.type_contenu.as_deref().unwrap_or_default();
    let type_contenu = type_contenu.split(';').next().unwrap_or_default().trim();
    if !type_contenu.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Err(Refus(415));
    }
    if r.longueur > TAILLE_FORMULAIRE_MAX as u64 {
        return Err(Refus(413));
    }
    let mut corps = Vec::new();
    lecteur_corps(r, flux)
        .read_to_end(&mut corps)
        .map_err(|_| Refus(400))?;
    if corps.len() as u64 != r.longueur {
        return Err(Refus(400));
    }
    paires(&corps)
}

/// Réponse à écrire.
pub struct Reponse {
    pub statut: u16,
    pub type_contenu: &'static str,
    pub corps: Vec<u8>,
    pub entetes: Vec<(&'static str, String)>,
    /// Ressource statique : mise en cache privée autorisée.
    pub statique: bool,
}

impl Reponse {
    pub fn html(statut: u16, corps: String) -> Reponse {
        Reponse {
            statut,
            type_contenu: "text/html; charset=utf-8",
            corps: corps.into_bytes(),
            entetes: Vec::new(),
            statique: false,
        }
    }

    /// Redirection après un POST ou vers la connexion (303 : la suite est un GET).
    pub fn redirection(vers: &'static str) -> Reponse {
        let mut r = Reponse::html(303, String::new());
        r.entetes.push(("Location", vers.into()));
        r
    }

    pub fn texte(statut: u16, texte: &str) -> Reponse {
        Reponse {
            statut,
            type_contenu: "text/plain; charset=utf-8",
            corps: texte.as_bytes().to_vec(),
            entetes: Vec::new(),
            statique: false,
        }
    }

    pub fn octets(&self) -> Vec<u8> {
        let mut e = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.statut,
            texte_statut(self.statut),
            self.type_contenu,
            self.corps.len()
        );
        for (k, v) in ENTETES_SECURITE {
            e.push_str(&format!("{k}: {v}\r\n"));
        }
        e.push_str(if self.statique {
            "Cache-Control: private, max-age=86400\r\n"
        } else {
            "Cache-Control: no-store\r\n"
        });
        for (k, v) in &self.entetes {
            // Valeurs produites par le serveur ; garde-fou contre l'injection d'en-tête.
            if !v.contains(['\r', '\n']) {
                e.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        e.push_str("\r\n");
        let mut o = e.into_bytes();
        o.extend_from_slice(&self.corps);
        o
    }

    pub fn ecrire(&self, flux: &mut impl Write) -> std::io::Result<()> {
        flux.write_all(&self.octets())
    }
}

pub fn texte_statut(statut: u16) -> &'static str {
    match statut {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lire(brut: &str) -> Result<Requete, Refus> {
        lire_entete(&mut brut.as_bytes())
    }

    #[test]
    fn requetes_valides() {
        let r = lire("GET /audit?page=2 HTTP/1.1\r\nHost: x\r\nCookie: a=1; b=2\r\nSec-Fetch-Site: same-origin\r\n\r\n").unwrap();
        assert_eq!(r.chemin, "/audit");
        assert_eq!(r.parametres["page"], "2");
        assert_eq!(r.cookies["b"], "2");
        assert_eq!(r.sec_fetch_site.as_deref(), Some("same-origin"));
        let mut brut = &b"POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\na=1&b=%3Cc"[..];
        let r = lire_entete(&mut brut).unwrap();
        let f = lire_formulaire(&r, &mut brut).unwrap();
        assert_eq!((f["a"].as_str(), f["b"].as_str()), ("1", "<c"));
    }

    #[test]
    fn requetes_refusees() {
        let cas = [
            ("POST /x HTTP/1.1\r\n\r\n", 411),
            ("GET /x HTTP/1.0\r\n\r\n", 400),
            ("GET x HTTP/1.1\r\n\r\n", 400),
            (
                "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                400,
            ),
            (
                "POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                400,
            ),
            ("POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
            ("GET /x HTTP/1.1\r\nCookie: a=1; a=2\r\n\r\n", 400),
            ("GET /x?a=1&a=2 HTTP/1.1\r\n\r\n", 400),
            ("GET /x HTTP/1.1\r\nContent-Length: 1\r\n\r\nab", 400),
        ];
        for (brut, statut) in cas {
            assert_eq!(lire(brut).unwrap_err(), Refus(statut), "{brut:?}");
        }
        let gros = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(9000));
        assert_eq!(lire(&gros).unwrap_err(), Refus(431));
        let mut brut = &b"POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 99999\r\n\r\n"[..];
        let r = lire_entete(&mut brut).unwrap();
        assert_eq!(lire_formulaire(&r, &mut brut).unwrap_err(), Refus(413));
        let mut brut =
            &b"POST /x HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\na"[..];
        let r = lire_entete(&mut brut).unwrap();
        assert_eq!(lire_formulaire(&r, &mut brut).unwrap_err(), Refus(415));
    }

    #[test]
    fn reponse_avec_entetes_de_securite() {
        let mut r = Reponse::html(200, "<p>x</p>".into());
        r.entetes.push(("Set-Cookie", "a=b\r\nX: injecte".into()));
        let texte = String::from_utf8(r.octets()).unwrap();
        assert!(texte.contains("Content-Security-Policy: default-src 'none';"));
        assert!(texte.contains("Cache-Control: no-store"));
        assert!(!texte.contains("injecte"));
    }
}
