//! Importance badge — coloured pill with a short label.

use crate::theme::Palette;
use egui::{Color32, Response, Ui};
use plausiden_tidy::importance::Importance;

/// Draw a coloured importance badge, returning its egui response.
pub fn importance_badge(ui: &mut Ui, palette: &Palette, imp: Importance) -> Response {
    let (color, label) = colour_and_label(palette, imp);
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(74.0, 18.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::Rounding::same(4.0), color);
    let text_color = if matches!(imp, Importance::Critical | Importance::High) {
        Color32::WHITE
    } else {
        Color32::BLACK
    };
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::monospace(10.0),
        text_color,
    );
    response
}

pub fn colour_and_label(palette: &Palette, imp: Importance) -> (Color32, &'static str) {
    match imp {
        Importance::Critical => (palette.critical, "CRITICAL"),
        Importance::High => (palette.high, "HIGH"),
        Importance::Medium => (palette.medium, "MEDIUM"),
        Importance::Low => (palette.low, "LOW"),
        Importance::Trash => (palette.trash, "TRASH"),
    }
}
