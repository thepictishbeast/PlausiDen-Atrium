//! Theme management — dark / light / automatic with persistence.

use egui::{Color32, Style, Visuals};
use serde::{Deserialize, Serialize};

/// User's preferred theme mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeMode {
    Dark,
    Light,
    Auto,
}

impl Default for ThemeMode {
    fn default() -> Self {
        ThemeMode::Auto
    }
}

impl ThemeMode {
    pub const ALL: [ThemeMode; 3] = [ThemeMode::Dark, ThemeMode::Light, ThemeMode::Auto];

    pub fn label(&self) -> &'static str {
        match self {
            ThemeMode::Dark => "Dark",
            ThemeMode::Light => "Light",
            ThemeMode::Auto => "Auto (system)",
        }
    }
}

/// Resolved palette after Auto has been matched to a concrete value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    Dark,
    Light,
}

/// Resolve Auto against the system preference. Currently defaults to
/// Dark for Auto until a portable preference API is wired in.
pub fn resolve(mode: ThemeMode, system_prefers_dark: bool) -> Resolved {
    match mode {
        ThemeMode::Dark => Resolved::Dark,
        ThemeMode::Light => Resolved::Light,
        ThemeMode::Auto => {
            if system_prefers_dark {
                Resolved::Dark
            } else {
                Resolved::Light
            }
        }
    }
}

/// Palette accessible from render code.
pub struct Palette {
    pub bg: Color32,
    pub bg_panel: Color32,
    pub bg_elevated: Color32,
    pub accent: Color32,
    pub accent_dim: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub border: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub warn_bg: Color32,
    pub critical: Color32,
    pub high: Color32,
    pub medium: Color32,
    pub low: Color32,
    pub trash: Color32,
}

impl Palette {
    pub const DARK: Palette = Palette {
        bg: Color32::from_rgb(20, 22, 28),
        bg_panel: Color32::from_rgb(28, 30, 38),
        bg_elevated: Color32::from_rgb(36, 40, 50),
        accent: Color32::from_rgb(96, 160, 255),
        accent_dim: Color32::from_rgb(64, 120, 200),
        text: Color32::from_rgb(235, 236, 240),
        text_dim: Color32::from_rgb(160, 164, 180),
        border: Color32::from_rgb(48, 52, 62),
        ok: Color32::from_rgb(120, 200, 140),
        warn: Color32::from_rgb(240, 166, 92),
        warn_bg: Color32::from_rgb(80, 48, 30),
        critical: Color32::from_rgb(228, 94, 110),
        high: Color32::from_rgb(240, 166, 92),
        medium: Color32::from_rgb(226, 200, 100),
        low: Color32::from_rgb(110, 180, 240),
        trash: Color32::from_rgb(120, 200, 140),
    };

    pub const LIGHT: Palette = Palette {
        bg: Color32::from_rgb(248, 248, 250),
        bg_panel: Color32::from_rgb(255, 255, 255),
        bg_elevated: Color32::from_rgb(240, 242, 246),
        accent: Color32::from_rgb(44, 108, 200),
        accent_dim: Color32::from_rgb(98, 148, 222),
        text: Color32::from_rgb(28, 30, 36),
        text_dim: Color32::from_rgb(108, 112, 126),
        border: Color32::from_rgb(218, 222, 232),
        ok: Color32::from_rgb(48, 148, 72),
        warn: Color32::from_rgb(204, 120, 32),
        warn_bg: Color32::from_rgb(253, 240, 216),
        critical: Color32::from_rgb(200, 50, 66),
        high: Color32::from_rgb(204, 120, 32),
        medium: Color32::from_rgb(196, 162, 40),
        low: Color32::from_rgb(56, 116, 200),
        trash: Color32::from_rgb(48, 148, 72),
    };

    pub fn for_resolved(resolved: Resolved) -> &'static Palette {
        match resolved {
            Resolved::Dark => &Palette::DARK,
            Resolved::Light => &Palette::LIGHT,
        }
    }
}

/// Apply a theme to an egui context.
pub fn apply(ctx: &egui::Context, resolved: Resolved) {
    let palette = Palette::for_resolved(resolved);
    let mut style = (*ctx.style()).clone();
    install_visuals(&mut style, palette, resolved);
    install_spacing(&mut style);
    ctx.set_style(style);
}

fn install_visuals(style: &mut Style, p: &Palette, resolved: Resolved) {
    let mut v = match resolved {
        Resolved::Dark => Visuals::dark(),
        Resolved::Light => Visuals::light(),
    };
    v.override_text_color = Some(p.text);
    v.panel_fill = p.bg;
    v.window_fill = p.bg_panel;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = p.bg_panel;
    v.code_bg_color = p.bg_elevated;

    v.widgets.noninteractive.bg_fill = p.bg_panel;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, p.border);
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, p.text_dim);

    v.widgets.inactive.bg_fill = p.bg_elevated;
    v.widgets.inactive.weak_bg_fill = p.bg_panel;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, p.border);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, p.text);

    v.widgets.hovered.bg_fill = p.accent_dim;
    v.widgets.hovered.weak_bg_fill = p.bg_elevated;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, p.accent);
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, p.text);

    v.widgets.active.bg_fill = p.accent;
    v.widgets.active.weak_bg_fill = p.accent_dim;
    v.widgets.active.bg_stroke = egui::Stroke::new(1.5, p.accent);
    v.widgets.active.fg_stroke = egui::Stroke::new(2.0, p.text);

    v.selection.bg_fill = p.accent_dim;
    v.selection.stroke = egui::Stroke::new(1.5, p.accent);

    v.window_rounding = egui::Rounding::same(10.0);
    v.menu_rounding = egui::Rounding::same(8.0);
    v.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
    v.widgets.inactive.rounding = egui::Rounding::same(6.0);
    v.widgets.hovered.rounding = egui::Rounding::same(6.0);
    v.widgets.active.rounding = egui::Rounding::same(6.0);

    style.visuals = v;
}

fn install_spacing(style: &mut Style) {
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.menu_margin = egui::Margin::same(6.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.indent = 18.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dark() {
        assert_eq!(resolve(ThemeMode::Dark, false), Resolved::Dark);
        assert_eq!(resolve(ThemeMode::Dark, true), Resolved::Dark);
    }

    #[test]
    fn test_resolve_light() {
        assert_eq!(resolve(ThemeMode::Light, true), Resolved::Light);
    }

    #[test]
    fn test_resolve_auto_follows_system() {
        assert_eq!(resolve(ThemeMode::Auto, true), Resolved::Dark);
        assert_eq!(resolve(ThemeMode::Auto, false), Resolved::Light);
    }

    #[test]
    fn test_theme_mode_all_labels_nonempty() {
        for m in ThemeMode::ALL {
            assert!(!m.label().is_empty());
        }
    }

    #[test]
    fn test_palette_for_resolved() {
        let dark = Palette::for_resolved(Resolved::Dark);
        assert_eq!(dark.bg.a(), 255);
        let light = Palette::for_resolved(Resolved::Light);
        assert_ne!(light.bg, dark.bg);
    }
}
