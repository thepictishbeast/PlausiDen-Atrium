//! Inline size bar — a coloured horizontal fill proportional to a max value.

use egui::{Color32, Rounding, Sense, Ui};

/// Draw an inline size bar sized to fill the available width and
/// filled proportionally to `size` over `max`. Returns the response.
pub fn size_bar(ui: &mut Ui, size: u64, max: u64, color: Color32) {
    let width = ui.available_width().max(32.0).min(220.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 10.0), Sense::hover());
    ui.painter().rect_filled(
        rect,
        Rounding::same(3.0),
        color.linear_multiply(0.18),
    );
    if max == 0 || size == 0 {
        return;
    }
    let ratio = (size as f32 / max as f32).clamp(0.0, 1.0);
    let mut filled = rect;
    filled.set_width(rect.width() * ratio);
    ui.painter().rect_filled(filled, Rounding::same(3.0), color);
}
