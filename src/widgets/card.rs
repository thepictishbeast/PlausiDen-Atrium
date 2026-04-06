//! Card frame helper — elevated rounded container used on the Home page.

use crate::theme::Palette;
use egui::{InnerResponse, Ui};

pub fn card_frame<R>(
    ui: &mut Ui,
    palette: &Palette,
    contents: impl FnOnce(&mut Ui) -> R,
) -> InnerResponse<R> {
    egui::Frame::none()
        .fill(palette.bg_panel)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::same(16.0))
        .outer_margin(egui::Margin::same(6.0))
        .show(ui, contents)
}
