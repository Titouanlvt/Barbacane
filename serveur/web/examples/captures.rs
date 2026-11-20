//! Rend les pages de l'interface avec des données d'EXEMPLE dans un dossier, en thème Jour et
//! Nuit, pour les captures de la documentation (`tests/web/captures.sh`).
//!
//! ```text
//! cargo run -p barbacane-web --example captures -- DOSSIER
//! ```
//! Les pages sont celles du serveur (mêmes fonctions de rendu) ; seuls les chemins
//! `/statique/…` deviennent relatifs pour une ouverture en `file://`.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use barbacane_audit::{Bilan, Enregistrement, Evenement, PointExporte, empreinte_initiale};
use barbacane_passerelle::maj::{EtatMaj, EtatMajBorne, Paquet, SuiviBorne};
use barbacane_passerelle::registre::{
    Alerte, Borne, Demande, LigneSupervision, StatutBorne, StatutDemande,
};
use barbacane_protocole::EtatBorne;
use barbacane_web::comptes::Role;
use barbacane_web::pages::{self, Contexte, JetonAffiche};

const T: u64 = 1_795_600_000;

fn ligne(
    nom: &str,
    site: &str,
    etat: Option<EtatBorne>,
    vue: u64,
    ecart: i64,
    alertes: Vec<Alerte>,
) -> LigneSupervision {
    LigneSupervision {
        uuid: format!(
            "{:08x}-7c1e-4f0a-9b2d-5e8f0a1b2c3d",
            nom.len() as u32 * 7919 + vue as u32
        ),
        nom: nom.into(),
        site: site.into(),
        active: true,
        version_logiciel: Some("2.0.0".into()),
        etat,
        derniere_vue: Some(T - vue),
        ecart_horloge_s: Some(ecart),
        expire_le: T + 71 * 86400,
        alertes,
    }
}

fn main() {
    let sortie = std::env::args().nth(1).expect("usage : captures DOSSIER");
    let sortie = Path::new(&sortie);
    std::fs::create_dir_all(sortie.join("statique/polices")).unwrap();
    std::fs::write(
        sortie.join("statique/barbacane.css"),
        barbacane_web::css().replace("/statique/polices/", "polices/"),
    )
    .unwrap();
    for p in [
        "symbole.svg",
        "polices/AtkinsonHyperlegible-Regular.ttf",
        "polices/AtkinsonHyperlegible-Bold.ttf",
        "polices/BarlowCondensed-SemiBold.ttf",
        "polices/BarlowCondensed-Bold.ttf",
        "polices/JetBrainsMono.ttf",
    ] {
        let r = barbacane_web::statique(&format!("/statique/{p}")).unwrap();
        std::fs::write(sortie.join("statique").join(p), r.corps).unwrap();
    }
    let ctx = Contexte {
        compte: "admin.site-1",
        role: Role::Administrateur,
        csrf: "exemple",
        maintenant: T,
    };
    let mut lignes = vec![
        ligne(
            "b-s1-01",
            "site-1",
            Some(EtatBorne::EnService),
            30,
            1,
            vec![],
        ),
        ligne(
            "b-s1-02",
            "site-1",
            Some(EtatBorne::EnService),
            12,
            -2,
            vec![],
        ),
        ligne(
            "b-s1-03",
            "site-1",
            Some(EtatBorne::Maintenance),
            4,
            0,
            vec![],
        ),
        ligne(
            "b-s2-01",
            "site-2",
            Some(EtatBorne::EnService),
            540,
            0,
            vec![Alerte::Silence],
        ),
        ligne(
            "b-s2-02",
            "site-2",
            Some(EtatBorne::EnService),
            41,
            412,
            vec![Alerte::Horloge],
        ),
    ];
    let mut revoquee = ligne("b-s3-01", "site-3", None, 9 * 86400, 0, vec![]);
    revoquee.active = false;
    lignes.push(revoquee);
    let demande = Demande {
        id: "3f9c2a7e51b04d8e9a61c0d2e4f6a8b1".into(),
        site: "site-2".into(),
        csr_pem: String::new(),
        empreinte: "0".repeat(64),
        version_logiciel: "2.0.0".into(),
        deposee_le: T - 180,
        expire_le: T + 86400 - 180,
        statut: StatutDemande::EnAttente,
    };
    let borne = Borne {
        uuid: lignes[3].uuid.clone(),
        nom: "b-s2-01".into(),
        site: "site-2".into(),
        statut: StatutBorne::Active,
        certificat_pem: String::new(),
        serie: "4c1d9e0a7b3f52866d01e9a4c2b7f310".into(),
        serie_precedente: None,
        emis_le: T - 19 * 86400,
        expire_le: T + 71 * 86400,
        derniere_vue: Some(T - 540),
        ecart_horloge_s: Some(0),
        dernier_battement: None,
    };
    let mut suivi = BTreeMap::new();
    let mut noms = BTreeMap::new();
    for (l, e) in lignes.iter().zip([
        EtatMajBorne::Appliquee,
        EtatMajBorne::Appliquee,
        EtatMajBorne::Telechargee,
        EtatMajBorne::Proposee,
        EtatMajBorne::Echec,
    ]) {
        suivi.insert(
            l.uuid.clone(),
            SuiviBorne {
                version_maj: 202611181500,
                etat: e,
                le: T - 3600,
            },
        );
        noms.insert(l.uuid.clone(), l.nom.clone());
    }
    let maj = EtatMaj {
        version: 1,
        plancher: Some(202611170000),
        paquets: vec![
            Paquet {
                version_maj: 202611171453,
                sha256: "3ee0fcec".repeat(8),
                taille: 48_234_112,
                depose_le: T - 3 * 86400,
            },
            Paquet {
                version_maj: 202611181500,
                sha256: "9a1b7d02".repeat(8),
                taille: 51_002_368,
                depose_le: T - 86400,
            },
            Paquet {
                version_maj: 202611191030,
                sha256: "c4e85f31".repeat(8),
                taille: 51_118_080,
                depose_le: T - 7200,
            },
        ],
        diffusee: Some(202611181500),
        bornes: suivi,
    };
    let evenements = [
        (
            "web:admin.site-1",
            Evenement::Administration {
                action: "connexion".into(),
            },
        ),
        (
            "web:admin.site-1",
            Evenement::JetonCree {
                site: "site-2".into(),
                expire_le: T + 3600,
            },
        ),
        (
            "passerelle",
            Evenement::EnrolementDemande {
                demande: demande.id.clone(),
                empreinte: "5d".repeat(32),
            },
        ),
        (
            "web:admin.site-1",
            Evenement::EnrolementValide {
                demande: demande.id.clone(),
                borne: lignes[1].uuid.clone(),
            },
        ),
        (
            "passerelle",
            Evenement::BattementAnormal {
                borne: lignes[4].uuid.clone(),
                anomalie: barbacane_audit::Anomalie::HorlogeDerivee,
                ecart_s: 412,
            },
        ),
        (
            "web:admin.site-1",
            Evenement::MajDiffusee {
                version_maj: 202611181500,
            },
        ),
        (
            "web:admin.site-1",
            Evenement::Revocation {
                borne: "0a1b2c3d-7c1e-4f0a-9b2d-5e8f0a1b2c3d".into(),
                motif: "volee".into(),
            },
        ),
        (
            "audit",
            Evenement::PointDeControle {
                jusqua: 7,
                empreinte: "ab".repeat(48),
                cle: "0123456789abcdef".into(),
                signature: "cd".repeat(96),
            },
        ),
    ];
    let journal: Vec<Result<Enregistrement, String>> = evenements
        .into_iter()
        .enumerate()
        .rev()
        .map(|(i, (acteur, evenement))| {
            Ok(Enregistrement {
                v: 1,
                n: i as u64 + 1,
                le: T - 3600 + 300 * i as u64,
                acteur: acteur.into(),
                evenement,
                prec: empreinte_initiale(),
            })
        })
        .collect();
    let bilan = Bilan {
        enregistrements: 8,
        points: vec![PointExporte {
            n: 8,
            le: T - 3600 + 2100,
            empreinte: "ab".repeat(48),
        }],
        non_scelles: 0,
        derniere: "7e".repeat(48),
    };
    let pages_rendues = [
        ("connexion", pages::connexion("exemple", None)),
        ("tableau", pages::tableau(&ctx, &lignes, 1)),
        (
            "enrolement",
            pages::enrolement(
                &ctx,
                std::slice::from_ref(&demande),
                Some(JetonAffiche {
                    texte: "43218-K7QF2M9XWA4R6TB3NC5PDYHJEU",
                    expire_le: T + 3600,
                    site: "site-2",
                }),
                None,
            ),
        ),
        (
            "demande",
            pages::demande(
                &ctx,
                &demande,
                Some(
                    "empreinte différente de celle de la demande : NE PAS valider, vérifier la borne",
                ),
                "b-s2-03",
            ),
        ),
        ("revocation", pages::revocation(&ctx, &borne, None)),
        (
            "maj",
            pages::maj(
                &ctx,
                &maj,
                &noms,
                Some((
                    true,
                    "Paquet 202611191030 accepté (signature des bornes vérifiée), 51118080 octets. Diffusez-le pour le proposer aux bornes.",
                )),
            ),
        ),
        ("audit", pages::audit(&ctx, &journal, 1, 1)),
        ("verification", pages::verification(&ctx, Ok(bilan))),
    ];
    for (nom, html) in pages_rendues {
        let html = html.replace("\"/statique/", "\"statique/");
        std::fs::write(
            sortie.join(format!("{nom}-jour.html")),
            html.replacen(
                "<html lang=\"fr\">",
                "<html lang=\"fr\" data-theme=\"jour\">",
                1,
            ),
        )
        .unwrap();
        std::fs::write(
            sortie.join(format!("{nom}-nuit.html")),
            html.replacen(
                "<html lang=\"fr\">",
                "<html lang=\"fr\" data-theme=\"nuit\">",
                1,
            ),
        )
        .unwrap();
    }
    println!("{}", sortie.display());
}
