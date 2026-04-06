//! Purge page — antiforensic destruction UI (currently an explainer +
//! link to send selected Tidy plan items through Purge).

use crate::theme::Palette;
use egui::{RichText, Ui};
use plausiden_tidy::environment::EnvironmentReport;

pub fn show(ui: &mut Ui, palette: &Palette, env: &EnvironmentReport) {
    ui.label(
        RichText::new("Purge")
            .color(palette.text)
            .size(24.0)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Forensic-grade destruction. Not everyday cleanup — use Tidy for that.",
        )
        .color(palette.text_dim),
    );
    ui.add_space(10.0);

    egui::Frame::none()
        .fill(palette.bg_panel)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Two backends")
                    .color(palette.text)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "forensic_wipe — repeatedly overwrites a file with patterns. Effective on bare-metal HDD; best-effort on SSD due to wear-leveling.",
                )
                .color(palette.text),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "crypto_shred — single-pass encryption of the file with a 256-bit ChaCha20-Poly1305 key that is destroyed the instant the write completes. The file's bytes are now cryptographically worthless because the key no longer exists. Recommended on VPS, SSD, copy-on-write filesystems, and network storage.",
                )
                .color(palette.text),
            );
            ui.add_space(10.0);
            ui.label(
                RichText::new(format!(
                    "On this host: {} — {} recommended",
                    if env.overwrite_effective {
                        "forensic_wipe is meaningful"
                    } else {
                        "forensic_wipe is not meaningful"
                    },
                    if env.crypto_shred_recommended {
                        "crypto_shred"
                    } else {
                        "either backend"
                    }
                ))
                .color(palette.text_dim),
            );
        });

    ui.add_space(10.0);
    ui.label(
        RichText::new(
            "To purge specific files: build a cleanup plan in the Tidy tab, set the action for an item to 'secure purge (delegate to PlausiDen-Purge)', and commit. The Tidy page is the one-stop place to pick items — this page is the reference for what Purge does behind the scenes.",
        )
        .color(palette.text_dim),
    );
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "NOTE: Purge delegation requires a compatible PlausiDen-Purge install and is wired up in a subsequent release. For now, the SecurePurge action returns PurgeUnavailable so you can plan with it without risk of destructive action.",
        )
        .color(palette.warn),
    );
}
