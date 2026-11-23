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
use barbacane_passerelle::utilisateurs::{
    BaseUtilisateurs, CleUsb, EchecsBorne, Import, ReglageSite, Utilisateur,
};
use barbacane_protocole::EtatBorne;
use barbacane_protocole::utilisateurs::{EntreeNonEnrolees, ModeUtilisateurs};
use barbacane_web::comptes::Role;
use barbacane_web::pages::{self, Contexte, JetonAffiche};
use barbacane_web::pages_utilisateurs::{self as pu, LigneSite, VueUtilisateurs};

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
        dernier: 8,
        premier: 1,
        purges: 0,
        segments: 1,
        exports_purges: 0,
    };
    // Utilisateurs, sites, clés USB (données d'EXEMPLE ; PIN fictif).
    let mut base = BaseUtilisateurs::default();
    for (i, (id, pin, echecs, verrou)) in [
        ("a.martin", true, 0, false),
        ("b.durand", true, 5, true),
        ("c.leroy", false, 0, false),
        ("j.dupont", true, 1, false),
    ]
    .into_iter()
    .enumerate()
    {
        base.utilisateurs.push(Utilisateur {
            identifiant: id.into(),
            pseudonyme: format!(
                "u-{:016x}",
                0x3a7f_19c2_0d4e_8b61_u64.wrapping_mul(i as u64 + 3)
            ),
            actif: true,
            ajoute_le: T - 86400 * 30,
            retire_le: None,
            pin: pin.then(|| "(dérivé)".into()),
            pin_le: pin.then_some(T - 86400),
            pin_a_changer: false,
            echecs,
            verrouille_le: verrou.then_some(T - 600),
            derniere_verification: pin.then_some(T - 600 * (i as u64 + 1)),
        });
    }
    base.dernier_import = Some(Import {
        le: T - 7200,
        source: "annuaire".into(),
        actifs: 4,
    });
    base.bornes.insert(
        "b2".into(),
        EchecsBorne {
            echecs: 0,
            dernier_echec: T - 60,
            blocages: 1,
            bloquee_jusqua: T + 840,
        },
    );
    base.cles_usb.push(CleUsb {
        id: "usb-5e21a9c4".into(),
        fabricant: "0781".into(),
        serie: "4C530001230517112263".into(),
        libelle: "Clé de sortie du SOC".into(),
        site: Some("site-1".into()),
        entree: false,
        sortie: true,
        enrolee_le: T - 86400 * 3,
    });
    let ctx_audit = Contexte {
        compte: "bob",
        role: Role::Auditeur,
        csrf: "exemple",
        maintenant: T,
    };
    let sites = [
        LigneSite {
            site: "site-1".into(),
            bornes: 3,
            reglage: ReglageSite {
                mode: ModeUtilisateurs::Authentification,
                entree_non_enrolees: EntreeNonEnrolees::Interdite,
            },
            cles: 1,
        },
        LigneSite {
            site: "site-2".into(),
            bornes: 2,
            reglage: ReglageSite::default(),
            cles: 0,
        },
    ];
    let trouve = base.utilisateur("j.dupont").cloned();
    let pages_rendues = [
        ("connexion", pages::connexion("exemple", None)),
        ("tableau", pages::tableau(&ctx, &lignes, 1, &[])),
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
        (
            "utilisateurs",
            pu::utilisateurs(
                &ctx,
                &VueUtilisateurs {
                    base: &base,
                    annuaire_configure: true,
                    recherche: Some(("j.dupont", trouve.as_ref())),
                    pin: Some(("j.dupont", "58204716")),
                    message: None,
                    maintenant: T,
                },
            ),
        ),
        (
            "utilisateurs-auditeur",
            pu::utilisateurs(
                &ctx_audit,
                &VueUtilisateurs {
                    base: &base,
                    annuaire_configure: true,
                    recherche: None,
                    pin: None,
                    message: None,
                    maintenant: T,
                },
            ),
        ),
        ("sites", pu::sites(&ctx, &sites, None)),
        ("cles-usb", pu::cles_usb(&ctx, &base, None)),
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
