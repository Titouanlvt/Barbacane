use super::*;
use sha2::{Digest, Sha256};
use std::process::Command;

fn ctx(dir: &Path) -> Ctx {
    let conf = Config {
        socket: dir.join("admin.sock"),
        state_dir: dir.join("etat"),
        analyzer_config: dir.join("analyzer.toml"),
        analyzer_url: "http://127.0.0.1:9".into(),
        import_dir: dir.join("import"),
        export_dir: dir.join("export"),
        reports_dir: dir.join("rapports"),
        clamav_dir: dir.join("clamav"),
        yara_dir: dir.join("yara"),
        listes_dir: dir.join("listes"),
        update_pubkey: dir.join("maj.pub"),
        dry_run: true,
        // Absente : borne hors ligne (profil v1), sauf dans les tests « serveur ».
        agent_config: dir.join("agent.toml"),
        ..Config::default()
    };
    for d in [
        &conf.state_dir,
        &conf.import_dir,
        &conf.reports_dir,
        &conf.clamav_dir,
        &conf.yara_dir,
        &conf.listes_dir,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(
        &conf.analyzer_config,
        "listen = \"127.0.0.1:8042\"\n[limits]\nmax_depth = 5\n",
    )
    .unwrap();
    Ctx {
        conf,
        session: Mutex::new(None),
        op: Mutex::new(()),
    }
}

fn req(c: &Ctx, v: Value) -> Result<Value> {
    c.handle(v)
}

#[test]
fn premier_pin() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    assert_eq!(req(&c, json!({"op": "status"})).unwrap()["pin_set"], false);
    assert!(
        req(&c, json!({"op": "login", "pin": "12"})).is_err(),
        "PIN trop court"
    );
    assert!(req(&c, json!({"op": "login", "pin": "246813"})).unwrap()["token"].is_string());
    assert_eq!(req(&c, json!({"op": "status"})).unwrap()["pin_set"], true);
    assert!(
        req(&c, json!({"op": "login", "pin": "111111"})).is_err(),
        "PIN fixé"
    );
}

#[test]
fn pin_et_verrouillage() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    assert!(c.set_pin("123").is_err(), "PIN trop court");
    c.set_pin("246813").unwrap();
    assert!(
        !std::fs::read_to_string(c.path("pin"))
            .unwrap()
            .contains("246813"),
        "PIN stocké en clair"
    );
    assert!(
        req(&c, json!({"op": "set_pin", "pin": "111111"})).is_err(),
        "opération sans jeton"
    );
    let tok = req(&c, json!({"op": "login", "pin": "246813"})).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    req(&c, json!({"op": "set_pin", "pin": "135790", "token": tok})).unwrap();
    assert!(
        req(
            &c,
            json!({"op": "set_pin", "pin": "135790", "token": "faux"})
        )
        .is_err()
    );
    for i in 1..MAX_FAILURES {
        let e = req(&c, json!({"op": "login", "pin": "000000"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains(&format!("{} essai", MAX_FAILURES - i)), "{e}");
    }
    let e = req(&c, json!({"op": "login", "pin": "000000"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("verrouillé 15 min"), "{e}");
    // Même le bon PIN est refusé pendant le verrouillage.
    let e = req(&c, json!({"op": "login", "pin": "135790"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("verrouillé"), "{e}");
}

fn login(c: &Ctx) -> String {
    c.set_pin("246813").unwrap();
    req(c, json!({"op": "login", "pin": "246813"})).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn enrolement_et_limites() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let tok = login(&c);
    assert!(
        req(
            &c,
            json!({"op": "set_enrolled_mode", "enabled": true, "token": tok})
        )
        .is_err(),
        "aucune clé enrôlée"
    );
    let key = json!({"op": "enroll_add", "vendorid": 4660, "productid": 22136, "serial": "ABC123", "description": "Clé A", "token": tok});
    req(&c, key.clone()).unwrap();
    req(&c, key).unwrap();
    req(
        &c,
        json!({"op": "set_enrolled_mode", "enabled": true, "token": tok}),
    )
    .unwrap();
    let st = c.status();
    assert_eq!(st["enrolled_mode"], true);
    assert_eq!(
        st["enrolled"].as_array().unwrap().len(),
        1,
        "pas de doublon"
    );
    assert!(
        req(
            &c,
            json!({"op": "enroll_add", "vendorid": 1, "productid": 1, "serial": "", "token": tok})
        )
        .is_err()
    );
    req(&c, json!({"op": "enroll_remove", "key": {"vendorid": 4660, "productid": 22136, "serial": "ABC123"}, "token": tok})).unwrap();
    assert_eq!(c.status()["enrolled"].as_array().unwrap().len(), 0);

    // Préférences d'affichage : défaut Pierre, Nuit enregistrée, thème inconnu refusé.
    assert_eq!(c.status()["preferences"]["theme"], "pierre");
    req(&c, json!({"op": "set_preferences", "theme": "nuit", "animations_reduites": true, "token": tok})).unwrap();
    assert_eq!(c.status()["preferences"]["theme"], "nuit");
    assert_eq!(c.status()["preferences"]["animations_reduites"], true);
    assert!(
        req(
            &c,
            json!({"op": "set_preferences", "theme": "rose", "token": tok})
        )
        .is_err()
    );
    assert!(
        req(&c, json!({"op": "set_preferences", "theme": "pierre"})).is_err(),
        "sans jeton"
    );
    assert_eq!(c.status()["preferences"]["theme"], "nuit");
    assert!(req(&c, json!({"op": "set_limits", "limits": {"max_depth": 0, "max_files": 10, "max_total_size": 1}, "token": tok})).is_err());
    req(&c, json!({"op": "set_limits", "limits": {"max_depth": 7, "max_files": 20000, "max_total_size": 8589934592u64}, "token": tok})).unwrap();
    let l = c.limits();
    assert_eq!(
        (l["max_depth"].as_i64(), l["max_files"].as_i64()),
        (Some(7), Some(20000))
    );
    // Le reste de la configuration de l'analyseur est conservé.
    assert!(
        std::fs::read_to_string(&c.conf.analyzer_config)
            .unwrap()
            .contains("listen")
    );
}

#[test]
fn export() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    std::fs::write(c.conf.reports_dir.join("r1.json"), "{}").unwrap();
    let tok = login(&c);
    req(&c, json!({"op": "prepare_export", "token": tok})).unwrap();
    let d: Vec<_> = std::fs::read_dir(&c.conf.export_dir).unwrap().collect();
    assert_eq!(d.len(), 1);
    let root = d.into_iter().next().unwrap().unwrap().path();
    assert!(
        root.join("rapports/r1.json").is_file()
            && root.join("journal.txt").is_file()
            && root.join("etat.json").is_file()
    );
}

/// Construit un paquet signé ; `tamper` modifie le contenu après signature.
fn paquet(
    dir: &Path,
    key: &Path,
    version: u64,
    extra: Option<(&str, &str)>,
    bad_hash: bool,
) -> PathBuf {
    paquet_x(dir, key, version, extra, bad_hash, None)
}

/// `cle` : nouvelle clé publique embarquée (rotation), listée dans le manifeste.
fn paquet_x(
    dir: &Path,
    key: &Path,
    version: u64,
    extra: Option<(&str, &str)>,
    bad_hash: bool,
    cle: Option<&Path>,
) -> PathBuf {
    let src = dir.join(format!(
        "src-{version}-{}",
        key.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(src.join("clamav")).unwrap();
    std::fs::create_dir_all(src.join("yara")).unwrap();
    std::fs::write(
        src.join("clamav/daily.cld"),
        format!("ClamAV-VDB:01 Jan 2026 00-00 +0000:{version}:"),
    )
    .unwrap();
    std::fs::write(src.join("yara/regles.yar"), "rule r { condition: false }").unwrap();
    std::fs::create_dir_all(src.join("listes")).unwrap();
    std::fs::write(
        src.join("listes/images-officielles.sha256"),
        format!("{}  Win11_26H2_French_x64.iso\n", "ab".repeat(32)),
    )
    .unwrap();
    let mut rels = vec![
        "clamav/daily.cld",
        "yara/regles.yar",
        "listes/images-officielles.sha256",
    ];
    if let Some(c) = cle {
        std::fs::create_dir_all(src.join("cles")).unwrap();
        std::fs::copy(c, src.join("cles/maj.pub")).unwrap();
        rels.push("cles/maj.pub");
    }
    let mut files = serde_json::Map::new();
    for rel in rels {
        let mut h = Sha256::new();
        h.update(std::fs::read(src.join(rel)).unwrap());
        let mut hx = hex::encode(h.finalize());
        if bad_hash {
            hx = "0".repeat(64);
        }
        files.insert(rel.into(), json!(hx));
    }
    if let Some((rel, content)) = extra {
        std::fs::write(src.join(rel), content).unwrap();
    }
    std::fs::write(
        src.join("manifest.json"),
        serde_json::to_vec(
            &json!({"format": 1, "version": version, "date": "2026-10-26", "files": files}),
        )
        .unwrap(),
    )
    .unwrap();
    let pkg = dir.join(format!("barbacane-maj-{version:06}.bcu"));
    let f = std::fs::File::create(&pkg).unwrap();
    let mut b = tar::Builder::new(zstd::Encoder::new(f, 3).unwrap().auto_finish());
    b.append_dir_all(".", &src).unwrap();
    b.into_inner().unwrap();
    let st = Command::new("minisign")
        .args(["-S", "-s"])
        .arg(key)
        .arg("-m")
        .arg(&pkg)
        .args(["-t", "barbacane"])
        .status()
        .unwrap();
    assert!(st.success());
    pkg
}

fn deposer(c: &Ctx, pkg: &Path) {
    for e in std::fs::read_dir(&c.conf.import_dir).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    let name = pkg.file_name().unwrap().to_string_lossy().to_string();
    std::fs::copy(pkg, c.conf.import_dir.join(&name)).unwrap();
    std::fs::copy(
        format!("{}.minisig", pkg.display()),
        c.conf.import_dir.join(format!("{name}.minisig")),
    )
    .unwrap();
}

#[test]
fn mises_a_jour() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let tok = login(&c);
    let k = t.path().join("k");
    std::fs::create_dir_all(&k).unwrap();
    let st = Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(&c.conf.update_pubkey)
        .arg("-s")
        .arg(k.join("maj.key"))
        .status()
        .unwrap();
    assert!(st.success());
    let st = Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(k.join("autre.pub"))
        .arg("-s")
        .arg(k.join("autre.key"))
        .status()
        .unwrap();
    assert!(st.success());
    let apply = |c: &Ctx| req(c, json!({"op": "apply_update", "token": tok}));
    std::fs::write(c.conf.clamav_dir.join("daily.cld"), "ancienne base").unwrap();

    // Valide
    let p2 = paquet(t.path(), &k.join("maj.key"), 2, None, false);
    deposer(&c, &p2);
    let r = apply(&c).unwrap();
    assert_eq!(r["version"], 2);
    assert!(
        std::fs::read_to_string(c.conf.clamav_dir.join("daily.cld"))
            .unwrap()
            .contains(":2:")
    );
    assert!(c.conf.yara_dir.join("regles.yar").is_file());
    assert!(
        std::fs::read_to_string(c.conf.listes_dir.join("images-officielles.sha256"))
            .unwrap()
            .contains("Win11")
    );
    assert!(
        r["report"].as_str().unwrap_or_default().contains("1 image"),
        "{r}"
    );
    assert_eq!(c.update_version(), 2);
    assert!(c.status()["signatures_age_days"].as_u64().is_some());

    // Version plus ancienne ou identique : refusée
    let p1 = paquet(t.path(), &k.join("maj.key"), 1, None, false);
    deposer(&c, &p1);
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("retour arrière")
    );
    deposer(&c, &p2);
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("retour arrière")
    );

    // Signature d'une autre clé : refusée
    let pa = paquet(t.path(), &k.join("autre.key"), 3, None, false);
    deposer(&c, &pa);
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("signature invalide")
    );

    // Paquet modifié après signature : refusé
    let p3 = paquet(t.path(), &k.join("maj.key"), 3, None, false);
    deposer(&c, &p3);
    let target = c.conf.import_dir.join(p3.file_name().unwrap());
    let mut bytes = std::fs::read(&target).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 0xff;
    std::fs::write(&target, bytes).unwrap();
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("signature invalide")
    );

    // Signé mais manifeste incohérent (empreinte ou fichier non listé) : refusé
    let p4 = paquet(t.path(), &k.join("maj.key"), 4, None, true);
    deposer(&c, &p4);
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("empreinte incorrecte")
    );
    let p5 = paquet(
        t.path(),
        &k.join("maj.key"),
        5,
        Some(("clamav/intrus.cvd", "x")),
        false,
    );
    deposer(&c, &p5);
    assert!(apply(&c).unwrap_err().to_string().contains("non listé"));

    // Signature absente
    deposer(&c, &p3);
    std::fs::remove_file(c.conf.import_dir.join(format!(
        "{}.minisig",
        p3.file_name().unwrap().to_string_lossy()
    )))
    .unwrap();
    assert!(apply(&c).unwrap_err().to_string().contains("signature"));

    // Rien n'a bougé depuis la version 2.
    assert_eq!(c.update_version(), 2);
    assert!(
        std::fs::read_to_string(c.conf.clamav_dir.join("daily.cld"))
            .unwrap()
            .contains(":2:")
    );
}

#[test]
fn retour_arriere_si_echec() {
    let t = tempfile::tempdir().unwrap();
    let mut c = ctx(t.path());
    let tok = login(&c);
    let k = t.path().join("k");
    std::fs::create_dir_all(&k).unwrap();
    Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(&c.conf.update_pubkey)
        .arg("-s")
        .arg(k.join("maj.key"))
        .status()
        .unwrap();
    std::fs::write(c.conf.clamav_dir.join("daily.cld"), "ancienne base").unwrap();
    let p = paquet(t.path(), &k.join("maj.key"), 2, None, false);
    deposer(&c, &p);
    // systemctl échoue (exécution réelle d'une commande absente)
    c.conf.dry_run = false;
    let e = req(&c, json!({"op": "apply_update", "token": tok}));
    // systemctl peut exister sur la machine de test : on n'exige le retour arrière que s'il a échoué.
    if let Err(e) = e {
        assert!(e.to_string().contains("restaurées"), "{e}");
        assert_eq!(
            std::fs::read_to_string(c.conf.clamav_dir.join("daily.cld")).unwrap(),
            "ancienne base"
        );
        assert_eq!(c.update_version(), 0);
    }
}

#[test]
fn rotation_de_cle() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let tok = login(&c);
    let k = t.path().join("k");
    std::fs::create_dir_all(&k).unwrap();
    for n in ["maj", "nouvelle"] {
        let pubk = if n == "maj" {
            c.conf.update_pubkey.clone()
        } else {
            k.join("nouvelle.pub")
        };
        let st = Command::new("minisign")
            .args(["-G", "-W", "-p"])
            .arg(pubk)
            .arg("-s")
            .arg(k.join(format!("{n}.key")))
            .status()
            .unwrap();
        assert!(st.success());
    }
    let apply = |c: &Ctx| req(c, json!({"op": "apply_update", "token": tok}));
    // Paquet signé par l'ancienne clé, apportant la nouvelle clé publique.
    let p = paquet_x(
        t.path(),
        &k.join("maj.key"),
        2,
        None,
        false,
        Some(&k.join("nouvelle.pub")),
    );
    deposer(&c, &p);
    assert!(
        apply(&c).unwrap()["report"]
            .as_str()
            .unwrap()
            .contains("clé de signature")
    );
    assert_eq!(
        std::fs::read(&c.conf.update_pubkey).unwrap(),
        std::fs::read(k.join("nouvelle.pub")).unwrap()
    );
    // L'ancienne clé n'est plus acceptée, la nouvelle l'est.
    deposer(&c, &paquet(t.path(), &k.join("maj.key"), 3, None, false));
    assert!(
        apply(&c)
            .unwrap_err()
            .to_string()
            .contains("signature invalide")
    );
    deposer(
        &c,
        &paquet(t.path(), &k.join("nouvelle.key"), 3, None, false),
    );
    apply(&c).unwrap();
    assert_eq!(c.update_version(), 3);
}

#[test]
fn installation_des_paquets_sans_no_download() {
    let debs = vec![std::path::PathBuf::from(
        "/var/lib/barbacane/admin/maj-x/debs/a_1-2_amd64.deb",
    )];
    let argv = crate::update::apt_install_argv(&debs);
    // apt hors du confinement d'admind (initramfs sans modules sinon)
    assert_eq!(argv[..3], ["systemd-run", "--wait", "--pipe"]);
    let apt = argv.iter().position(|a| a == "apt-get").unwrap();
    assert_eq!(argv[apt..apt + 3], ["apt-get", "install", "-y"]);
    assert!(!argv.iter().any(|a| a == "--no-download"));
    assert!(argv.contains(&"Dir::Etc::SourceList=/dev/null".to_string()));
    assert!(argv.contains(&"Dir::Etc::SourceParts=/dev/null".to_string()));
    assert!(argv.last().unwrap().starts_with('/'));
}

// ───────────── Borne en ligne (agent) : inactif en profil hors ligne ─────────────

/// Profil en ligne simulé : configuration d'agent, dossiers d'état et d'exécution.
fn en_ligne(c: &Ctx, t: &Path) -> (PathBuf, PathBuf) {
    let etat = t.join("agent");
    let run = t.join("run");
    std::fs::create_dir_all(etat.join("maj")).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(
        &c.conf.agent_config,
        format!(
            "adresse = \"10.0.2.2\"\nport_enrolement = 43118\nport_service = 43117\nca_serveur = \"/x\"\nempreinte_ca_serveur = \"{}\"\netat = \"{}\"\nexecution = \"{}\"\n",
            "0".repeat(64),
            etat.display(),
            run.display()
        ),
    )
    .unwrap();
    (etat, run)
}

/// Secret bien formé (26 caractères base32 décodant 16 octets).
fn secret() -> String {
    barbacane_protocole::Jeton::nouveau(1, &[7; 16]).secret
}

#[test]
fn hors_ligne_aucune_fonction_serveur() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let tok = login(&c);
    let st = req(&c, json!({"op": "status"})).unwrap();
    assert!(st.get("serveur").is_none(), "état v1 inchangé : {st}");
    for op in ["serveur_jeton", "serveur_appliquer_maj"] {
        let e = req(
            &c,
            json!({"op": op, "token": tok, "jeton": format!("43118-{}", secret())}),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("hors ligne"), "{op} : {e}");
    }
}

#[test]
fn jeton_valide_strictement_et_depose() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let (etat, run) = en_ligne(&c, t.path());
    assert!(
        req(
            &c,
            json!({"op": "serveur_jeton", "jeton": format!("43118-{}", secret())})
        )
        .is_err(),
        "sans session"
    );
    let tok = login(&c);
    let s = secret();
    for (mauvais, motif) in [
        ("n'importe quoi".to_string(), "mal formé"),
        (format!("43118-{}", &s[..25]), "mal formé"),
        (format!("43118-{s}\n../x"), "mal formé"),
        (format!("1234-{s}"), "port"),
        ("4".repeat(200), "trop long"),
    ] {
        let e = req(
            &c,
            json!({"op": "serveur_jeton", "token": tok, "jeton": mauvais}),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains(motif), "{mauvais} : {e}");
        assert!(!etat.join("jeton").exists());
    }
    // Espaces et minuscules tolérés (saisie au clavier virtuel), normalisé.
    req(
        &c,
        json!({"op": "serveur_jeton", "token": tok, "jeton": format!(" 43118 - {}", s.to_lowercase())}),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(etat.join("jeton")).unwrap(),
        format!("43118-{s}\n")
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(etat.join("jeton"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // État de l'agent relayé (champs connus seulement).
    std::fs::write(
        run.join("etat.json"),
        r#"{"mode":"attente_validation","empreinte":"ab12","secret":"x","message":"m"}"#,
    )
    .unwrap();
    let st = req(&c, json!({"op": "status"})).unwrap();
    assert_eq!(st["serveur"]["agent"]["mode"], "attente_validation");
    assert_eq!(st["serveur"]["agent"]["empreinte"], "ab12");
    assert!(st["serveur"]["agent"].get("secret").is_none());
    assert_eq!(st["serveur"]["port_enrolement"], 43118);
}

/// Dépose dans le dossier de l'agent un paquet « téléchargé » et son annonce.
fn annoncer(etat: &Path, pkg: &Path, version: u64, sha: Option<String>) {
    let d = etat.join("maj");
    for e in std::fs::read_dir(&d).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    let nom = format!("barbacane-maj-{version}.bcu");
    std::fs::copy(pkg, d.join(&nom)).unwrap();
    std::fs::copy(
        format!("{}.minisig", pkg.display()),
        d.join(format!("{nom}.minisig")),
    )
    .unwrap();
    let octets = std::fs::read(pkg).unwrap();
    let sha = sha.unwrap_or_else(|| hex::encode(Sha256::digest(&octets)));
    std::fs::write(
        d.join("annonce.json"),
        json!({"version_maj": version, "sha256": sha, "taille": octets.len()}).to_string(),
    )
    .unwrap();
}

#[test]
fn maj_du_serveur_verifiee_par_la_borne() {
    let t = tempfile::tempdir().unwrap();
    let c = ctx(t.path());
    let (etat, _) = en_ligne(&c, t.path());
    let tok = login(&c);
    let k = t.path().join("k");
    std::fs::create_dir_all(&k).unwrap();
    for (p, s) in [
        (c.conf.update_pubkey.clone(), k.join("maj.key")),
        (k.join("autre.pub"), k.join("autre.key")),
    ] {
        assert!(
            Command::new("minisign")
                .args(["-G", "-W", "-p"])
                .arg(p)
                .arg("-s")
                .arg(s)
                .status()
                .unwrap()
                .success()
        );
    }
    let appliquer = || req(&c, json!({"op": "serveur_appliquer_maj", "token": tok}));
    let resultat = || {
        serde_json::from_slice::<Value>(&std::fs::read(etat.join("maj/resultat.json")).unwrap())
            .unwrap()
    };
    assert!(
        appliquer()
            .unwrap_err()
            .to_string()
            .contains("aucune mise à jour")
    );

    // Signé par une autre clé que celle de la borne : refusé, échec rendu à l'agent.
    let p = paquet(t.path(), &k.join("autre.key"), 300, None, false);
    annoncer(&etat, &p, 300, None);
    assert!(
        appliquer()
            .unwrap_err()
            .to_string()
            .contains("signature invalide")
    );
    assert_eq!(resultat(), json!({"version_maj": 300, "resultat": "echec"}));
    assert_eq!(c.update_version(), 0);

    // Empreinte annoncée fausse : refusé avant toute vérification.
    let p = paquet(t.path(), &k.join("maj.key"), 301, None, false);
    annoncer(&etat, &p, 301, Some("0".repeat(64)));
    assert!(appliquer().unwrap_err().to_string().contains("empreinte"));
    // Version annoncée différente du manifeste signé : refusé.
    annoncer(&etat, &p, 302, None);
    assert!(appliquer().unwrap_err().to_string().contains("annonçait"));
    assert_eq!(resultat()["resultat"], "echec");

    // Valide : appliqué par la chaîne existante (signature, anti-retour, manifeste).
    annoncer(&etat, &p, 301, None);
    let r = appliquer().unwrap();
    assert_eq!(r["version"], 301);
    assert_eq!(c.update_version(), 301);
    assert_eq!(
        resultat(),
        json!({"version_maj": 301, "resultat": "appliquee"})
    );
    // Rejeu du même paquet : retour arrière refusé.
    annoncer(&etat, &p, 301, None);
    assert!(
        appliquer()
            .unwrap_err()
            .to_string()
            .contains("retour arrière")
    );

    // Lien symbolique posé à la place du paquet : refusé.
    annoncer(&etat, &p, 301, None);
    let bcu = etat.join("maj/barbacane-maj-301.bcu");
    std::fs::remove_file(&bcu).unwrap();
    std::os::unix::fs::symlink(&p, &bcu).unwrap();
    assert!(appliquer().is_err());
}
