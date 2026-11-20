//! Construction des pages, **sûre par défaut** : tout texte variable est échappé.
//!
//! Le seul moyen d'insérer du HTML non échappé est [`Html::b`], qui n'accepte que des
//! littéraux (`&'static str`) écrits dans le code : une donnée venue d'une borne, d'un fichier
//! ou d'une requête ne peut pas y entrer sans une conversion volontaire et visible.

/// Échappe un texte pour un contenu d'élément ou une valeur d'attribut entre guillemets.
pub fn echapper(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            // Caractères de contrôle (sauf saut de ligne et tabulation) : remplacés.
            c if c.is_control() && c != '\n' && c != '\t' => o.push('\u{fffd}'),
            c => o.push(c),
        }
    }
    o
}

/// Encode un composant d'URL (paramètre de requête) : tout sauf `[A-Za-z0-9._~-]`.
pub fn url(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"._~-".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Tampon HTML.
#[derive(Default)]
pub struct Html {
    s: String,
}

impl Html {
    pub fn new() -> Html {
        Html::default()
    }

    /// HTML brut : **littéral du code seulement**.
    pub fn b(&mut self, brut: &'static str) -> &mut Html {
        self.s.push_str(brut);
        self
    }

    /// Texte (échappé).
    pub fn t(&mut self, texte: &str) -> &mut Html {
        self.s.push_str(&echapper(texte));
        self
    }

    /// Nombre.
    pub fn n(&mut self, n: impl std::fmt::Display) -> &mut Html {
        self.t(&n.to_string())
    }

    /// Paramètre d'URL (encodé puis échappé).
    pub fn u(&mut self, composant: &str) -> &mut Html {
        self.t(&url(composant))
    }

    /// Ajoute un fragment déjà construit (lui-même sûr).
    pub fn h(&mut self, autre: Html) -> &mut Html {
        self.s.push_str(&autre.s);
        self
    }

    pub fn fin(self) -> String {
        self.s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echappement() {
        assert_eq!(
            echapper("<script>alert('x')</script>&\"y\""),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;y&quot;"
        );
        assert_eq!(echapper("a\u{0}b\u{1b}c\nd"), "a\u{fffd}b\u{fffd}c\nd");
        assert_eq!(echapper("Révoquée — ok"), "Révoquée — ok");
        let mut h = Html::new();
        h.b("<p title=\"")
            .t("\" onmouseover=\"x")
            .b("\">")
            .t("<b>")
            .b("</p>");
        assert_eq!(
            h.fin(),
            "<p title=\"&quot; onmouseover=&quot;x\">&lt;b&gt;</p>"
        );
    }

    #[test]
    fn encodage_url() {
        assert_eq!(url("ab-12_~."), "ab-12_~.");
        assert_eq!(url("a b&c=\"<"), "a%20b%26c%3D%22%3C");
        assert_eq!(url("é"), "%C3%A9");
    }
}
