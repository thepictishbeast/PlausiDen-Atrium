//! Typed duration input — amount + unit.

use crate::formats::{DurationUnit, TypedDuration};
use egui::Ui;

/// Render a compact duration input. Returns true if the value changed.
pub fn duration_input(ui: &mut Ui, label: &str, value: &mut TypedDuration, id_salt: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let drag = ui.add(
            egui::DragValue::new(&mut value.amount)
                .speed(0.5)
                .range(0..=10_000),
        );
        if drag.changed() {
            changed = true;
        }
        egui::ComboBox::from_id_salt(format!("duration-unit-{}", id_salt))
            .selected_text(value.unit.label())
            .show_ui(ui, |ui| {
                for unit in DurationUnit::ALL {
                    if ui
                        .selectable_value(&mut value.unit, unit, unit.label())
                        .changed()
                    {
                        changed = true;
                    }
                }
            });
    });
    changed
}
