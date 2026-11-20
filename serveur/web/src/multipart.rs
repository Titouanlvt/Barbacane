//! Lecture en flux de `multipart/form-data` (dépôt de fichiers sans JavaScript).
//!
//! Le corps n'est jamais chargé en mémoire : chaque partie est copiée vers sa destination au
//! fil de la lecture, avec une taille maximale par partie. Seules les formes produites par un
//! navigateur sont acceptées (pas de préambule, en-têtes de partie ≤ 2 Kio, CRLF).

use std::io::{Read, Write};

use crate::http::Refus;

const TAILLE_ENTETE_PARTIE_MAX: usize = 2048;
const BLOC: usize = 64 * 1024;

/// Paramètre `boundary` d'un `Content-Type: multipart/form-data; boundary=…`.
pub fn frontiere(type_contenu: &str) -> Option<String> {
    let mut morceaux = type_contenu.split(';');
    if !morceaux
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    for m in morceaux {
        if let Some((k, v)) = m.trim().split_once('=')
            && k.trim().eq_ignore_ascii_case("boundary")
        {
            let v = v.trim().trim_matches('"');
            let ok = (1..=70).contains(&v.len())
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&c));
            return ok.then(|| v.to_owned());
        }
    }
    None
}

/// En-tête d'une partie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partie {
    pub nom: String,
    /// Partie de type fichier (`filename=` présent ; le nom du fichier n'est pas conservé, D2).
    pub fichier: bool,
}

pub struct Multipart<R: Read> {
    r: R,
    delim: Vec<u8>,
    tampon: Vec<u8>,
    debut: bool,
    fini: bool,
}

/// Position de `aiguille` (qui commence par `\r`) dans `botte`.
fn chercher(botte: &[u8], aiguille: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(p) = botte[i..].iter().position(|o| *o == aiguille[0]) {
        let p = i + p;
        if botte.len() - p < aiguille.len() {
            return None;
        }
        if botte[p..].starts_with(aiguille) {
            return Some(p);
        }
        i = p + 1;
    }
    None
}

impl<R: Read> Multipart<R> {
    pub fn new(r: R, frontiere: &str) -> Multipart<R> {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(frontiere.as_bytes());
        Multipart {
            r,
            delim,
            // Le corps commence par « --frontière » : on le voit comme « \r\n--frontière ».
            tampon: b"\r\n".to_vec(),
            debut: true,
            fini: false,
        }
    }

    /// Lit un bloc de plus ; faux à la fin du corps.
    fn remplir(&mut self) -> Result<bool, Refus> {
        let mut bloc = vec![0u8; BLOC];
        let n = self.r.read(&mut bloc).map_err(|_| Refus(400))?;
        self.tampon.extend_from_slice(&bloc[..n]);
        Ok(n > 0)
    }

    fn au_moins(&mut self, n: usize) -> Result<(), Refus> {
        while self.tampon.len() < n {
            if !self.remplir()? {
                return Err(Refus(400));
            }
        }
        Ok(())
    }

    /// Partie suivante, ou `None` à la fin. La partie précédente doit avoir été lue.
    pub fn suivante(&mut self) -> Result<Option<Partie>, Refus> {
        if self.fini {
            return Ok(None);
        }
        if self.debut {
            self.au_moins(self.delim.len())?;
            if !self.tampon.starts_with(&self.delim) {
                return Err(Refus(400));
            }
            self.tampon.drain(..self.delim.len());
            self.debut = false;
        }
        self.au_moins(2)?;
        match &self.tampon[..2] {
            b"--" => {
                self.fini = true;
                return Ok(None);
            }
            b"\r\n" => {
                self.tampon.drain(..2);
            }
            _ => return Err(Refus(400)),
        }
        let fin = loop {
            if let Some(p) = self.tampon.windows(4).position(|f| f == b"\r\n\r\n") {
                break p;
            }
            if self.tampon.len() > TAILLE_ENTETE_PARTIE_MAX || !self.remplir()? {
                return Err(Refus(400));
            }
        };
        if fin > TAILLE_ENTETE_PARTIE_MAX {
            return Err(Refus(400));
        }
        let entete = std::str::from_utf8(&self.tampon[..fin]).map_err(|_| Refus(400))?;
        let mut partie = None;
        for ligne in entete.split("\r\n") {
            let (k, v) = ligne.split_once(':').ok_or(Refus(400))?;
            if !k.trim().eq_ignore_ascii_case("content-disposition") {
                continue;
            }
            let mut morceaux = v.split(';').map(str::trim);
            if morceaux.next() != Some("form-data") || partie.is_some() {
                return Err(Refus(400));
            }
            let (mut nom, mut fichier) = (None, false);
            for m in morceaux {
                match m.split_once('=') {
                    Some(("name", n)) => nom = Some(n.trim_matches('"').to_owned()),
                    Some(("filename", _)) => fichier = true,
                    _ => {}
                }
            }
            partie = Some(Partie {
                nom: nom.ok_or(Refus(400))?,
                fichier,
            });
        }
        self.tampon.drain(..fin + 4);
        partie.ok_or(Refus(400)).map(Some)
    }

    /// Copie les données de la partie courante vers `sortie` (au plus `max` octets, sinon
    /// 413). Renvoie la taille copiée.
    pub fn copier(&mut self, sortie: &mut impl Write, max: u64) -> Result<u64, Refus> {
        let mut total = 0u64;
        let mut ecrire = |o: &[u8], total: &mut u64| -> Result<(), Refus> {
            *total += o.len() as u64;
            if *total > max {
                return Err(Refus(413));
            }
            sortie.write_all(o).map_err(|_| Refus(500))
        };
        loop {
            if let Some(p) = chercher(&self.tampon, &self.delim) {
                ecrire(&self.tampon[..p], &mut total)?;
                self.tampon.drain(..p + self.delim.len());
                return Ok(total);
            }
            let garde = self.delim.len() - 1;
            if self.tampon.len() > garde {
                let n = self.tampon.len() - garde;
                ecrire(&self.tampon[..n], &mut total)?;
                self.tampon.drain(..n);
            }
            if !self.remplir()? {
                return Err(Refus(400));
            }
        }
    }

    /// Lit une petite partie texte (≤ `max` octets, UTF-8).
    pub fn texte(&mut self, max: u64) -> Result<String, Refus> {
        let mut o = Vec::new();
        self.copier(&mut o, max)?;
        String::from_utf8(o).map_err(|_| Refus(400))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lecteur qui rend un octet à la fois (frontières à cheval sur les lectures).
    struct Goutte<'a>(&'a [u8]);
    impl Read for Goutte<'_> {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() || b.is_empty() {
                return Ok(0);
            }
            b[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    fn corps(binaire: &[u8]) -> Vec<u8> {
        let mut c = b"--XyZ\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\njeton\r\n--XyZ\r\nContent-Disposition: form-data; name=\"bcu\"; filename=\"a.bcu\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        c.extend_from_slice(binaire);
        c.extend_from_slice(b"\r\n--XyZ--\r\n");
        c
    }

    #[test]
    fn deux_parties_lues_en_flux() {
        let binaire: Vec<u8> = (0..5000u32)
            .flat_map(|i| [(i % 256) as u8, b'\r', b'\n', b'-'])
            .chain(b"\r\n--XyZ".iter().take(6).copied())
            .collect();
        let c = corps(&binaire);
        for lent in [false, true] {
            let mut m: Multipart<Box<dyn Read + '_>> = Multipart::new(
                if lent {
                    Box::new(Goutte(&c))
                } else {
                    Box::new(&c[..])
                },
                "XyZ",
            );
            let p = m.suivante().unwrap().unwrap();
            assert_eq!(p.nom, "csrf");
            assert!(!p.fichier);
            assert_eq!(m.texte(64).unwrap(), "jeton");
            let p = m.suivante().unwrap().unwrap();
            assert_eq!(
                p,
                Partie {
                    nom: "bcu".into(),
                    fichier: true
                }
            );
            let mut o = Vec::new();
            assert_eq!(m.copier(&mut o, 1 << 20).unwrap(), binaire.len() as u64);
            assert_eq!(o, binaire);
            assert_eq!(m.suivante().unwrap(), None);
        }
    }

    #[test]
    fn formes_refusees() {
        let c = corps(&[1u8; 100]);
        let mut m = Multipart::new(&c[..], "XyZ");
        m.suivante().unwrap();
        assert_eq!(m.texte(3).unwrap_err(), Refus(413));
        let mut m = Multipart::new(&c[..c.len() - 12], "XyZ");
        m.suivante().unwrap();
        m.texte(64).unwrap();
        m.suivante().unwrap();
        assert_eq!(m.copier(&mut Vec::new(), 1000).unwrap_err(), Refus(400));
        let mut m = Multipart::new(&b"preambule\r\n--XyZ\r\n"[..], "XyZ");
        assert_eq!(m.suivante().unwrap_err(), Refus(400));
        assert_eq!(
            frontiere("multipart/form-data; boundary=----abc"),
            Some("----abc".into())
        );
        assert_eq!(frontiere("multipart/form-data; boundary=a\"b"), None);
        assert_eq!(frontiere("text/plain; boundary=abc"), None);
    }
}
