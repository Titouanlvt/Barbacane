//! Sessions en mémoire : identifiant de 256 bits, liées au certificat client, courtes.

use std::collections::HashMap;
use std::sync::Mutex;

use barbacane_passerelle::outils::aleatoire;

use crate::comptes::Role;

/// Nom du cookie (`__Host-` : Secure, Path=/, sans Domain, imposé par le navigateur).
pub const COOKIE: &str = "__Host-barbacane";
/// Expiration après inactivité.
pub const INACTIVITE_S: u64 = 15 * 60;
/// Durée maximale d'une session.
pub const DUREE_MAX_S: u64 = 8 * 3600;
/// Sessions (et pré-sessions de connexion) en mémoire au plus.
pub const SESSIONS_MAX: usize = 64;

#[derive(Debug, Clone)]
pub struct Session {
    /// `None` : pré-session (page de connexion, porte seulement le jeton anti-CSRF).
    pub compte: Option<(String, Role)>,
    /// Certificat client auquel la session est liée.
    pub empreinte_certificat: String,
    /// Jeton anti-CSRF de la session.
    pub csrf: String,
    pub creee_le: u64,
    pub vue_le: u64,
}

/// Valeur de `Set-Cookie` pour une session.
pub fn cookie(id: &str) -> String {
    format!("{COOKIE}={id}; Secure; HttpOnly; SameSite=Strict; Path=/")
}

/// Valeur de `Set-Cookie` qui efface le cookie.
pub fn cookie_efface() -> String {
    format!("{COOKIE}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// Comparaison à temps constant.
pub fn egal(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[derive(Default)]
pub struct Sessions {
    m: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    fn expiree(s: &Session, t: u64) -> bool {
        t >= s.vue_le + INACTIVITE_S || t >= s.creee_le + DUREE_MAX_S
    }

    /// Crée une session (ou pré-session) ; une session de compte remplace toute autre session
    /// du même compte. Renvoie son identifiant.
    pub fn creer(
        &self,
        compte: Option<(String, Role)>,
        empreinte_certificat: &str,
        t: u64,
    ) -> (String, Session) {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, s| !Sessions::expiree(s, t));
        if let Some((id, _)) = &compte {
            m.retain(|_, s| s.compte.as_ref().is_none_or(|(c, _)| c != id));
        }
        while m.len() >= SESSIONS_MAX {
            // Place : la pré-session la plus ancienne, sinon la session la plus ancienne.
            let Some(k) = m
                .iter()
                .min_by_key(|(_, s)| (s.compte.is_some(), s.vue_le))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            m.remove(&k);
        }
        let id = hex::encode(aleatoire::<32>());
        let s = Session {
            compte,
            empreinte_certificat: empreinte_certificat.into(),
            csrf: hex::encode(aleatoire::<32>()),
            creee_le: t,
            vue_le: t,
        };
        m.insert(id.clone(), s.clone());
        (id, s)
    }

    /// Session valide pour ce certificat (inactivité remise à zéro), sinon `None` (et la
    /// session expirée ou présentée avec un autre certificat est détruite).
    pub fn obtenir(&self, id: &str, empreinte_certificat: &str, t: u64) -> Option<Session> {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let s = m.get_mut(id)?;
        if Sessions::expiree(s, t) || !egal(&s.empreinte_certificat, empreinte_certificat) {
            m.remove(id);
            return None;
        }
        s.vue_le = t;
        Some(s.clone())
    }

    pub fn supprimer(&self, id: &str) {
        self.m.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_et_liaison_au_certificat() {
        let s = Sessions::default();
        let (id, _) = s.creer(Some(("a".into(), Role::Auditeur)), "c1", 1000);
        assert!(s.obtenir(&id, "c2", 1001).is_none());
        assert!(
            s.obtenir(&id, "c1", 1001).is_none(),
            "détruite après usage avec un autre certificat"
        );
        let (id, _) = s.creer(Some(("a".into(), Role::Auditeur)), "c1", 1000);
        assert!(s.obtenir(&id, "c1", 1000 + INACTIVITE_S - 1).is_some());
        assert!(s.obtenir(&id, "c1", 1000 + 2 * INACTIVITE_S - 2).is_some());
        assert!(s.obtenir(&id, "c1", 1000 + 3 * INACTIVITE_S).is_none());
        let (id, _) = s.creer(Some(("a".into(), Role::Auditeur)), "c1", 0);
        let mut t = 0;
        while t + 600 < DUREE_MAX_S {
            t += 600;
            assert!(s.obtenir(&id, "c1", t).is_some());
        }
        assert!(s.obtenir(&id, "c1", DUREE_MAX_S).is_none());
    }

    #[test]
    fn une_session_par_compte_et_nombre_borne() {
        let s = Sessions::default();
        let (a, _) = s.creer(Some(("a".into(), Role::Administrateur)), "c", 5);
        let (b, _) = s.creer(Some(("a".into(), Role::Administrateur)), "c", 6);
        assert!(s.obtenir(&a, "c", 7).is_none());
        assert!(s.obtenir(&b, "c", 7).is_some());
        for i in 0..200 {
            s.creer(None, "x", 10 + i);
        }
        assert!(
            s.obtenir(&b, "c", 300).is_some(),
            "les pré-sessions partent d'abord"
        );
        assert!(egal("abc", "abc") && !egal("abc", "abd") && !egal("abc", "ab"));
    }
}
