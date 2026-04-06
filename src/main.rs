//! `atrium` — the unified PlausiDen desktop front door.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod docs;
mod file_manager;
mod formats;
mod pages;
mod theme;
mod widgets;

use app::AtriumApp;

fn env_precheck() {
    if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
        eprintln!();
        eprintln!("┌─ Atrium startup warning ────────────────────────────────");
        eprintln!("│ Neither DISPLAY nor WAYLAND_DISPLAY is set.");
        eprintln!("│ If you are running under sudo, try:");
        eprintln!("│");
        eprintln!("│   sudo -E atrium");
        eprintln!("│");
        eprintln!("│ Or grant root one-time X access and relaunch:");
        eprintln!("│");
        eprintln!("│   xhost +si:localuser:root");
        eprintln!("│   sudo atrium");
        eprintln!("└────────────────────────────────────────────────────────");
        eprintln!();
    }
}

fn main() -> eframe::Result<()> {
    env_precheck();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([980.0, 640.0])
            .with_title("PlausiDen Atrium"),
        ..Default::default()
    };

    eframe::run_native(
        "PlausiDen Atrium",
        options,
        Box::new(|cc| Ok(Box::new(AtriumApp::new(cc)))),
    )
}
