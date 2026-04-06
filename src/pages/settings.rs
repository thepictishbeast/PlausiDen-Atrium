//! Settings page — theme, protected paths, safety lock.

use crate::config::AtriumConfig;
use crate::theme::{Palette, ThemeMode};
use egui::{RichText, TextEdit, Ui};
use plausiden_tidy::environment::EnvironmentReport;
use std::path::PathBuf;

pub struct SettingsContext<'a> {
    pub palette: &'a Palette,
    pub config: &'a mut AtriumConfig,
    pub new_protected: &'a mut String,
    pub env: &'a EnvironmentReport,
}

/// Intent returned from the Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsIntent {
    None,
    ThemeChanged,
    ProtectedChanged,
    LockChanged,
    Save,
}

pub fn show(ui: &mut Ui, cx: &mut SettingsContext) -> SettingsIntent {
    let mut intent = SettingsIntent::None;

    ui.label(
        RichText::new("Settings")
            .color(cx.palette.text)
            .size(24.0)
            .strong(),
    );
    ui.add_space(10.0);

    // ── Theme ──────────────────────────────────────────────────
    ui.label(
        RichText::new("Theme")
            .color(cx.palette.text)
            .size(16.0)
            .strong(),
    );
    ui.horizontal(|ui| {
        for mode in ThemeMode::ALL {
            if ui
                .selectable_value(&mut cx.config.theme, mode, mode.label())
                .changed()
            {
                intent = SettingsIntent::ThemeChanged;
            }
        }
    });

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(10.0);

    // ── Protected paths ────────────────────────────────────────
    ui.label(
        RichText::new("Protected paths")
            .color(cx.palette.text)
            .size(16.0)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Anything under a protected path is refused by the importance classifier — even if you bulk-add it.",
        )
        .color(cx.palette.text_dim),
    );
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(cx.new_protected)
                .hint_text("/home/user/secret")
                .desired_width(360.0),
        );
        if ui.button("Add").clicked() && !cx.new_protected.trim().is_empty() {
            cx.config
                .protected_paths
                .push(cx.new_protected.trim().to_string());
            cx.new_protected.clear();
            intent = SettingsIntent::ProtectedChanged;
        }
        if ui.button("Pick…").clicked()
            && let Some(dir) = rfd::FileDialog::new().pick_folder()
        {
            cx.config
                .protected_paths
                .push(dir.to_string_lossy().into_owned());
            intent = SettingsIntent::ProtectedChanged;
        }
    });

    let mut to_remove = None;
    for (i, p) in cx.config.protected_paths.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("  • {}", p));
            if ui.small_button("remove").clicked() {
                to_remove = Some(i);
            }
        });
    }
    if let Some(i) = to_remove {
        cx.config.protected_paths.remove(i);
        intent = SettingsIntent::ProtectedChanged;
    }

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(10.0);

    // ── Safety lock ────────────────────────────────────────────
    ui.label(
        RichText::new("Safety lock")
            .color(cx.palette.text)
            .size(16.0)
            .strong(),
    );
    ui.label(
        RichText::new(
            "While the safety lock is ON, every committed plan is a dry run. Releasing the lock allows destructive actions to touch disk.",
        )
        .color(cx.palette.text_dim),
    );
    if ui
        .checkbox(&mut cx.config.dry_run_locked, "Keep dry-run lock engaged")
        .changed()
    {
        intent = SettingsIntent::LockChanged;
    }
    if !cx.config.dry_run_locked {
        ui.label(
            RichText::new(
                "⚠  Safety lock released. Destructive actions in the Plan tab are now live.",
            )
            .color(cx.palette.critical),
        );
    }

    ui.add_space(14.0);
    ui.separator();
    ui.add_space(10.0);

    // ── Environment ────────────────────────────────────────────
    ui.label(
        RichText::new("Environment")
            .color(cx.palette.text)
            .size(16.0)
            .strong(),
    );
    ui.label(format!("Virtualization: {}", cx.env.virtualization.label()));
    ui.label(format!("Storage class: {}", cx.env.storage_class.label()));
    ui.label(format!(
        "Overwrite effective: {}",
        if cx.env.overwrite_effective {
            "yes"
        } else {
            "no — crypto-shred recommended"
        }
    ));
    for note in &cx.env.notes {
        ui.label(
            RichText::new(format!("• {}", note))
                .color(cx.palette.text_dim)
                .small(),
        );
    }

    ui.add_space(14.0);
    if ui.button("Save settings").clicked() {
        intent = SettingsIntent::Save;
    }

    intent
}

/// Apply the classifier configuration to a fresh `ImportanceClassifier`.
pub fn rebuild_classifier(
    config: &AtriumConfig,
) -> plausiden_tidy::importance::ImportanceClassifier {
    let mut c = plausiden_tidy::importance::ImportanceClassifier::new();
    for p in &config.protected_paths {
        c.protect(PathBuf::from(p));
    }
    c
}
