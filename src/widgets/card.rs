//! Card frame helper — elevated rounded container with a soft drop shadow.

use crate::theme::{tokens, Palette};
use egui::{Color32, InnerResponse, Shadow, Ui};

pub fn card_frame<R>(
    ui: &mut Ui,
    palette: &Palette,
    contents: impl FnOnce(&mut Ui) -> R,
) -> InnerResponse<R> {
    egui::Frame::none()
        .fill(palette.bg_panel)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .rounding(egui::Rounding::same(tokens::RADIUS_LG))
        .inner_margin(egui::Margin::same(20.0))
        .outer_margin(egui::Margin::same(4.0))
        .shadow(Shadow {
            offset: egui::vec2(0.0, 4.0),
            blur: 18.0,
            spread: 0.0,
            color: Color32::from_black_alpha(40),
        })
        .show(ui, contents)
}
