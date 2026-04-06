//! `atrium` — the unified PlausiDen desktop front door.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod disk_wipe;
mod docs;
mod file_manager;
mod forensic;
mod formats;
mod pages;
mod theme;
mod widgets;
mod wipe_config;
mod wipe_runner;

use app::AtriumApp;

fn env_precheck() {
    let display_ok = std::env::var("DISPLAY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let wayland_ok = std::env::var("WAYLAND_DISPLAY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if display_ok || wayland_ok {
        return;
    }
    eprintln!();
    eprintln!("┌─ Atrium startup warning ────────────────────────────────");
    eprintln!("│ Neither DISPLAY nor WAYLAND_DISPLAY is set to a value.");
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

fn load_icon() -> Option<egui::IconData> {
    // Try a compiled-in fallback icon — a flat gradient square — so
    // window managers always have something to display even if the
    // SVG asset isn't on disk.
    const SIZE: usize = 64;
    let mut rgba = Vec::with_capacity(SIZE * SIZE * 4);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let t = (x + y) as f32 / (SIZE * 2) as f32;
            let r = (91.0 * (1.0 - t) + 164.0 * t) as u8;
            let g = (141.0 * (1.0 - t) + 91.0 * t) as u8;
            let b = (239.0 * (1.0 - t) + 239.0 * t) as u8;
            rgba.extend_from_slice(&[r, g, b, 255]);
        }
    }
    Some(egui::IconData {
        rgba,
        width: SIZE as u32,
        height: SIZE as u32,
    })
}

fn main() -> eframe::Result<()> {
    env_precheck();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([980.0, 640.0])
        .with_title("PlausiDen Atrium");
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "PlausiDen Atrium",
        options,
        Box::new(|cc| Ok(Box::new(AtriumApp::new(cc)))),
    )
}
