//! barbacane-client : interface graphique de la borne Barbacane (plein écran,
//! souris uniquement, en français).

mod admin;
mod admin_ui;
mod anim;
mod app;
mod barre;
mod config;
mod dessin;
mod keyboard;
mod mesure;
mod optique;
mod sequences;
mod style;
mod worker;

fn main() -> iced::Result {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or(
        "info,wgpu_hal=error,iced_winit=error,iced_wgpu=error,wgpu_core=error,cosmic_text=error,naga=error,sctk=error,winit=error,zbus=error",
    ));
    let path = std::env::args()
        .skip_while(|a| a != "-c")
        .nth(1)
        .unwrap_or_else(|| "/etc/barbacane/client.toml".into());
    app::run(config::Config::load(&path))
}
