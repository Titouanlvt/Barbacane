//! Client du service `barbacane-optique` (même protocole que barbacane-admind) et attente
//! des opérations longues (lecture, gravure, effacement) avec leur progression.

use serde_json::{Value, json};
use std::time::Duration;

/// État du lecteur et de l'opération en cours.
#[derive(Debug, Clone, Default)]
pub struct Etat {
    pub present: bool,
    pub donnees: bool,
    pub reinscriptible: bool,
    pub libelle: String,
    /// Opération en cours ou terminée
    pub travail: Option<Value>,
}

impl Etat {
    pub fn from(v: &Value) -> Self {
        let d = &v["disque"];
        Etat {
            present: d["present"].as_bool() == Some(true),
            donnees: d["donnees"].as_u64().unwrap_or(0) > 0,
            reinscriptible: d["reinscriptible"].as_bool() == Some(true),
            libelle: d["libelle"].as_str().unwrap_or("").to_string(),
            travail: (!v["travail"].is_null()).then(|| v["travail"].clone()),
        }
    }
}

pub fn requete(socket: &str, op: &str) -> Result<Value, String> {
    if socket.is_empty() {
        return Err("aucun lecteur optique configuré".into());
    }
    crate::admin::request(socket, json!({ "op": op }))
}

pub fn etat(socket: &str) -> Result<Etat, String> {
    requete(socket, "etat").map(|v| Etat::from(&v))
}

pub async fn etat_async(socket: String) -> Result<Etat, String> {
    smol::unblock(move || etat(&socket)).await
}

/// Avancement d'une opération : (phase, pourcentage, secondes restantes estimées).
pub type Avancement = (String, f32, Option<u64>);

/// Lance `op` puis attend sa fin en relayant l'avancement. Renvoie l'état final du travail.
pub fn executer(
    socket: &str,
    op: &str,
    avance: &mut dyn FnMut(Avancement),
) -> Result<Value, String> {
    requete(socket, op)?;
    loop {
        std::thread::sleep(Duration::from_millis(700));
        let v = requete(socket, "etat")?;
        let t = &v["travail"];
        avance((
            t["phase"].as_str().unwrap_or("").to_string(),
            t["pourcent"].as_f64().unwrap_or(0.0) as f32,
            t["restant"].as_u64(),
        ));
        if t["fini"].as_bool() == Some(true) {
            return match t["erreur"].as_str() {
                Some(e) => Err(e.to_string()),
                None => Ok(t.clone()),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Etat;
    use serde_json::json;

    #[test]
    fn etat_du_service() {
        let e = Etat::from(
            &json!({"disque": {"present": true, "donnees": 1, "reinscriptible": true,
            "libelle": "CD-RW (1 session(s), 387 Mo)"}, "travail": null}),
        );
        assert!(e.present && e.donnees && e.reinscriptible && e.travail.is_none());
        let e = Etat::from(&json!({"disque": null, "travail": {"op": "gravure", "fini": false}}));
        assert!(!e.present && !e.donnees && e.travail.is_some());
    }
}
