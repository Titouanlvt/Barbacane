//! Borne EN LIGNE seulement : identification des utilisateurs et politique USB du site
//! (`docs/suite/serveur-utilisateurs.md` §4).
//!
//! Tout part de `etat["serveur"]["politique"]`, publié par admind uniquement quand
//! `/etc/barbacane/agent.toml` existe ET que l'agent a reçu une politique. Sans elle (borne
//! hors ligne v1, ou politique jamais reçue), chaque fonction rend la réponse de la v1 :
//! aucun écran d'identification, toute clé acceptée (seul le mode « clés enrôlées » local de
//! la v1 s'applique, inchangé).

use barbacane_parcours::proto::common::UsbDevice;
use barbacane_protocole::utilisateurs::{ModeUtilisateurs, PolitiqueSite, Sens};
use serde_json::Value;

/// Étapes de l'écran d'identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etape {
    Identifiant,
    Pin,
    /// PIN initial accepté : choix du nouveau PIN (puis confirmation)
    NouveauPin,
    Confirmation,
}

/// Politique du site (None : v1).
pub fn politique(etat: Option<&Value>) -> Option<PolitiqueSite> {
    let p = etat?.get("serveur")?.get("politique")?;
    if p.is_null() {
        return None;
    }
    serde_json::from_value(p.clone()).ok()
}

/// Mode exigeant un écran d'identification (None : v1, ou mode Aucun).
pub fn identification(etat: Option<&Value>) -> Option<ModeUtilisateurs> {
    politique(etat)
        .map(|p| p.mode)
        .filter(|m| *m != ModeUtilisateurs::Aucun)
}

fn autorise(etat: Option<&Value>, d: &UsbDevice, sens: Sens) -> bool {
    match politique(etat) {
        None => true,
        Some(p) => {
            // Disque optique : aucun identifiant de fabricant ni de série.
            if barbacane_parcours::est_optique(d) {
                return sens == Sens::Entree
                    && p.entree_non_enrolees
                        == barbacane_protocole::utilisateurs::EntreeNonEnrolees::Autorisee;
            }
            p.autorise(&format!("{:04x}", d.vendorid), &d.serial, sens)
        }
    }
}

/// Clé source acceptée par la politique du site (toujours vrai en v1).
pub fn entree_autorisee(etat: Option<&Value>, d: &UsbDevice) -> bool {
    autorise(etat, d, Sens::Entree)
}

/// Sortie de fichiers (copie, gravure) autorisée vers ce support (toujours vrai en v1).
/// Le blanchiment n'est pas concerné (décision du 21/11).
pub fn sortie_autorisee(etat: Option<&Value>, d: &UsbDevice) -> bool {
    autorise(etat, d, Sens::Sortie)
}

/// Une politique impose la sortie vers une clé enrôlée (gravure impossible) ; faux en v1.
pub fn sortie_restreinte(etat: Option<&Value>) -> bool {
    politique(etat).is_some()
}

/// Message de refus d'une vérification (réponse minimale du serveur).
pub fn message_refus(mode: ModeUtilisateurs, attente_s: Option<u64>) -> String {
    match attente_s {
        Some(s) => format!(
            "Borne bloquée après trop d'essais : réessayez dans {} min.",
            s.div_ceil(60).max(1)
        ),
        None if mode == ModeUtilisateurs::Authentification => "Identifiant ou PIN refusé.".into(),
        None => "Identifiant refusé.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cle(v: u32, serie: &str) -> UsbDevice {
        UsbDevice {
            vendorid: v,
            serial: serie.into(),
            ..Default::default()
        }
    }

    fn etat(mode: &str, entree: &str) -> Value {
        json!({"serveur": {"agent": {}, "politique": {
            "version": 1, "site": "site-1", "mode": mode, "version_politique": 3,
            "entree_non_enrolees": entree,
            "cles": [{"fabricant": "0781", "serie": "4C530001", "entree": true, "sortie": true}],
            "heure_serveur": 1}}})
    }

    #[test]
    fn hors_ligne_comportement_v1() {
        // Borne hors ligne (sans agent.toml) : état v1, sans « serveur ».
        let v1 = json!({"pin_set": true, "enrolled_mode": false, "enrolled": []});
        // Borne en ligne sans politique reçue : comme la v1.
        let sans = json!({"serveur": {"agent": {}, "politique": null}});
        for e in [None, Some(&v1), Some(&sans)] {
            assert!(politique(e).is_none());
            assert!(identification(e).is_none(), "aucun écran d'identification");
            assert!(entree_autorisee(e, &cle(0x1234, "X")));
            assert!(sortie_autorisee(e, &cle(0x1234, "X")));
            assert!(sortie_autorisee(e, &barbacane_parcours::optique("CD")));
            assert!(!sortie_restreinte(e));
        }
    }

    #[test]
    fn politique_appliquee() {
        let e = etat("aucun", "interdite");
        assert!(
            identification(Some(&e)).is_none(),
            "mode Aucun : pas d'écran"
        );
        assert!(
            !entree_autorisee(Some(&e), &cle(0x1234, "X")),
            "non enrôlée refusée"
        );
        assert!(entree_autorisee(Some(&e), &cle(0x0781, "4c530001")));
        assert!(!sortie_autorisee(Some(&e), &cle(0x1234, "X")));
        assert!(sortie_autorisee(Some(&e), &cle(0x0781, "4C530001")));
        assert!(!sortie_autorisee(
            Some(&e),
            &barbacane_parcours::optique("CD")
        ));
        assert!(!entree_autorisee(
            Some(&e),
            &barbacane_parcours::optique("CD")
        ));
        let e = etat("authentification", "autorisee");
        assert_eq!(
            identification(Some(&e)),
            Some(ModeUtilisateurs::Authentification)
        );
        assert!(entree_autorisee(Some(&e), &cle(0x1234, "X")));
        assert!(entree_autorisee(
            Some(&e),
            &barbacane_parcours::optique("CD")
        ));
        // Politique invalide (schéma strict) : ignorée.
        let mut faux = etat("identification", "autorisee");
        faux["serveur"]["politique"]["inconnu"] = json!(1);
        assert!(politique(Some(&faux)).is_none());
    }

    #[test]
    fn messages() {
        use ModeUtilisateurs::*;
        assert_eq!(
            message_refus(Authentification, None),
            "Identifiant ou PIN refusé."
        );
        assert_eq!(message_refus(Identification, None), "Identifiant refusé.");
        assert!(message_refus(Authentification, Some(900)).contains("15 min"));
    }
}
