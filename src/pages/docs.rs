//! Docs page — render the static how-to sections.

use crate::docs::SECTIONS;
use crate::theme::Palette;
use egui::{RichText, ScrollArea, Ui};

pub fn show(ui: &mut Ui, palette: &Palette) {
    ui.label(
        RichText::new("How to use Atrium safely")
            .color(palette.text)
            .size(24.0)
            .strong(),
    );
    ui.add_space(8.0);

    ScrollArea::vertical().show(ui, |ui| {
        for section in SECTIONS {
            egui::Frame::none()
                .fill(palette.bg_panel)
                .stroke(egui::Stroke::new(1.0, palette.border))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(14.0))
                .outer_margin(egui::Margin::symmetric(0.0, 6.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(section.title)
                            .color(palette.text)
                            .size(18.0)
                            .strong(),
                    );
                    ui.add_space(4.0);
                    ui.label(RichText::new(section.body).color(palette.text));
                });
        }
    });
}
