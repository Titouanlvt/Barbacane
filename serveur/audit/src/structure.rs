//! Format structuré du journal (v2.3.0, `docs/suite/journal-structure.md`) : une ligne JSON par
//! événement, champs stables, et son enveloppe Syslog RFC 5424.
//!
//! Champs (tous présents) : `schema` (`barbacane.journal/1`), `serveur`, `id` (32 premiers
//! caractères hexadécimaux de l'empreinte : identifiant unique et stable, pour dédoublonner),
//! `n` (numéro d'ordre dans la chaîne), `horodatage` (RFC 3339, UTC, à la seconde),
//! `gravite` et `gravite_code` (RFC 5424 : 3 erreur, 4 avertissement, 5 avis, 6 info),
//! `categorie`, `type`, `acteur`, `donnees` (champs de l'événement, tels que dans le journal
//! chaîné), `empreinte` et `prec` (SHA-384 de la ligne et de la précédente : la chaîne reste
//! vérifiable chez le collecteur). Le contenu vient du journal chaîné, dont le schéma strict
//! interdit tout nom de fichier (D2) et ne porte que des pseudonymes d'utilisateurs.

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::{
    Enregistrement, Evenement, ResultatMaj, ResultatUtilisateur, VerdictPassage, empreinte,
};

pub const SCHEMA: &str = "barbacane.journal/1";
/// Facilité Syslog : 13 (« log audit », RFC 5424 §6.2.1).
pub const FACILITE: u8 = 13;
/// Identifiant des données structurées (SD-ID) : numéro d'entreprise privé réservé à la
/// documentation (RFC 5612) tant que le projet n'a pas le sien (choix à valider).
pub const SD_ID: &str = "barbacane@32473";

/// Gravité RFC 5424 (code, nom français).
pub fn gravite(e: &Evenement) -> (u8, &'static str) {
    use Evenement::*;
    let code = match e {
        Revocation { .. }
        | BattementAnormal { .. }
        | MajRefusee { .. }
        | MajRapportee {
            resultat: ResultatMaj::Echec,
            ..
        } => 4,
        UtilisateurVerifie { resultat, .. } => match resultat {
            ResultatUtilisateur::Acceptee | ResultatUtilisateur::PinAChanger => 6,
            _ => 4,
        },
        RapportPassage { verdict, .. } => match verdict {
            VerdictPassage::Sain => 6,
            _ => 4,
        },
        UtilisateurVerrouille { .. } | BorneBloquee { .. } => 3,
        Administration { action } => {
            if action.contains("refus") || action.contains("verrouill") {
                4
            } else if action.starts_with("consultation")
                || action.starts_with("export")
                || action == "connexion"
                || action == "verification-audit"
            {
                6
            } else {
                5
            }
        }
        Quarantaine { action, .. } => {
            if action.contains("refus") {
                4
            } else {
                5
            }
        }
        Syslog { action, .. } => match action.as_str() {
            "debordement" | "perte" => 3,
            "clair" | "injoignable" => 4,
            _ => 5,
        },
        EnrolementValide { .. }
        | EnrolementRefuse { .. }
        | PlancherInstalle { .. }
        | ModeSite { .. }
        | PolitiqueUsbSite { .. }
        | CleUsbEnrolee { .. }
        | CleUsbRetiree { .. }
        | PinReinitialise { .. }
        | UtilisateurDeverrouille { .. }
        | UtilisateursPurges { .. }
        | SegmentPurge { .. }
        | Purge { .. }
        | ConservationReglee { .. } => 5,
        _ => 6,
    };
    (
        code,
        match code {
            3 => "erreur",
            4 => "avertissement",
            5 => "avis",
            _ => "info",
        },
    )
}

/// Catégorie stable.
pub fn categorie(e: &Evenement) -> &'static str {
    use Evenement::*;
    match e {
        JetonCree { .. }
        | EnrolementDemande { .. }
        | EnrolementValide { .. }
        | EnrolementRefuse { .. }
        | Revocation { .. }
        | CrlPubliee { .. }
        | CertificatRenouvele { .. }
        | BattementAnormal { .. }
        | PolitiqueServie { .. } => "bornes",
        PlancherInstalle { .. }
        | MajDeposee { .. }
        | MajRefusee { .. }
        | MajDiffusee { .. }
        | MajProposee { .. }
        | MajTelechargee { .. }
        | MajRapportee { .. } => "mises_a_jour",
        UtilisateursImportes { .. }
        | UtilisateurVerifie { .. }
        | UtilisateurVerrouille { .. }
        | BorneBloquee { .. }
        | PinReinitialise { .. }
        | PinChange { .. }
        | UtilisateurDeverrouille { .. }
        | UtilisateursPurges { .. }
        | ModeSite { .. }
        | PolitiqueUsbSite { .. }
        | CleUsbEnrolee { .. }
        | CleUsbRetiree { .. } => "utilisateurs",
        RapportPassage { .. } => "passages",
        Administration { .. } => "administration",
        Quarantaine { .. } => "quarantaine",
        PointDeControle { .. }
        | SegmentOuvert { .. }
        | SegmentPurge { .. }
        | Purge { .. }
        | ConservationReglee { .. }
        | Syslog { .. } => "journal",
    }
}

/// `AAAA-MM-JJTHH:MM:SSZ` (RFC 3339, UTC).
pub fn rfc3339(secondes: u64) -> String {
    let d = crate::date_utc(secondes); // « AAAA-MM-JJ HH:MM:SS UTC »
    format!("{}T{}Z", &d[..10], &d[11..19])
}

/// Événement structuré : enregistrement analysé et ligne JSON (sans saut de ligne).
#[derive(Debug, Clone)]
pub struct Structure {
    pub enregistrement: Enregistrement,
    pub id: String,
    pub json: String,
}

/// Nom de serveur utilisable (RFC 5424 HOSTNAME) : `[A-Za-z0-9.-]`, 1 à 64, sinon défaut.
pub fn nom_serveur(s: &str) -> String {
    let s = s.trim();
    if (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        s.to_owned()
    } else {
        "barbacane-serveur".to_owned()
    }
}

/// Structure une ligne du journal chaîné (analysée strictement).
pub fn structurer(ligne: &[u8], serveur: &str) -> Result<Structure> {
    let e = Enregistrement::analyser(ligne)
        .map_err(|c| anyhow::anyhow!("ligne du journal refusée : {c}"))?;
    let h = empreinte(ligne);
    let (type_, donnees) = match serde_json::to_value(&e.evenement)? {
        Value::Object(m) if m.len() == 1 => m.into_iter().next().context("événement vide")?,
        _ => anyhow::bail!("événement de forme inattendue"),
    };
    let (code, nom) = gravite(&e.evenement);
    let id = h[..32].to_owned();
    let v = json!({
        "schema": SCHEMA,
        "serveur": nom_serveur(serveur),
        "id": id,
        "n": e.n,
        "horodatage": rfc3339(e.le),
        "gravite": nom,
        "gravite_code": code,
        "categorie": categorie(&e.evenement),
        "type": type_,
        "acteur": e.acteur,
        "donnees": donnees,
        "empreinte": h,
        "prec": e.prec,
    });
    Ok(Structure {
        enregistrement: e,
        id,
        json: serde_json::to_string(&v)?,
    })
}

/// Message Syslog RFC 5424 : `<PRI>1 HORODATAGE SERVEUR barbacane - TYPE [SD] BOM JSON`.
/// `reprise` : message renvoyé après une coupure (il a pu être déjà reçu ; le collecteur le
/// reconnaît à son `id`), jamais un doublon silencieux.
pub fn message_syslog(s: &Structure, serveur: &str, reprise: bool) -> Vec<u8> {
    let (code, _) = gravite(&s.enregistrement.evenement);
    let pri = u16::from(FACILITE) * 8 + u16::from(code);
    let msgid: String = serde_json::to_value(&s.enregistrement.evenement)
        .ok()
        .and_then(|v| v.as_object().and_then(|m| m.keys().next().cloned()))
        .unwrap_or_else(|| "evenement".into())
        .chars()
        .take(32)
        .collect();
    let mut m = format!(
        "<{pri}>1 {} {} barbacane - {msgid} [{SD_ID} n=\"{}\" id=\"{}\" reprise=\"{}\"] ",
        rfc3339(s.enregistrement.le),
        nom_serveur(serveur),
        s.enregistrement.n,
        s.id,
        u8::from(reprise)
    )
    .into_bytes();
    m.extend_from_slice("\u{feff}".as_bytes());
    m.extend_from_slice(s.json.as_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION_SCHEMA, empreinte_initiale};

    fn ligne(ev: Evenement) -> Vec<u8> {
        serde_json::to_vec(&Enregistrement {
            v: VERSION_SCHEMA,
            n: 7,
            le: 1_795_000_000,
            acteur: "passerelle".into(),
            evenement: ev,
            prec: empreinte_initiale(),
        })
        .unwrap()
    }

    #[test]
    fn structure_et_syslog() {
        let l = ligne(Evenement::RapportPassage {
            borne: "0b6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            passage: "1c6f4b0e-6a43-4c8e-9a51-2f7d0f3c9e11".into(),
            partie: 1,
            verdict: VerdictPassage::Menace,
            fichiers: 2,
        });
        let s = structurer(&l, "srv-1").unwrap();
        let v: Value = serde_json::from_str(&s.json).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["horodatage"], "2026-11-18T11:06:40Z");
        assert_eq!(v["gravite"], "avertissement");
        assert_eq!(v["gravite_code"], 4);
        assert_eq!(v["categorie"], "passages");
        assert_eq!(v["type"], "rapport_passage");
        assert_eq!(v["n"], 7);
        assert_eq!(v["donnees"]["fichiers"], 2);
        assert_eq!(v["id"].as_str().unwrap().len(), 32);
        assert_eq!(v["empreinte"], empreinte(&l));
        let m = String::from_utf8(message_syslog(&s, "srv-1", true)).unwrap();
        assert!(
            m.starts_with(&format!(
                "<108>1 2026-11-18T11:06:40Z srv-1 barbacane - rapport_passage [barbacane@32473 n=\"7\" id=\"{}\" reprise=\"1\"] \u{feff}{{",
                s.id
            )),
            "{m}"
        );
        assert_eq!(nom_serveur("a b"), "barbacane-serveur");
        // Ligne altérée : refusée.
        let mut l2 = l.clone();
        l2.insert(1, b' ');
        assert!(structurer(&l2, "srv").is_err());
    }
}
