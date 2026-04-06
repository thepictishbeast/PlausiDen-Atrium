//! Home page — the hero landing, environment banner, and quick-start cards.

use crate::formats::format_bytes;
use crate::theme::{paint_horizontal_gradient, tokens, Palette};
use crate::widgets::card_frame;
use egui::{Color32, RichText, TextStyle, Ui};
use plausiden_tidy::environment::EnvironmentReport;

pub struct HomeContext<'a> {
    pub palette: &'a Palette,
    pub env: &'a EnvironmentReport,
    pub last_scan_files: u64,
    pub last_scan_bytes: u64,
    pub plan_items: usize,
    pub plan_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeIntent {
    None,
    OpenTidy,
    OpenPurge,
    OpenDocs,
    OpenSettings,
}

pub fn show(ui: &mut Ui, cx: &HomeContext) -> HomeIntent {
    let mut intent = HomeIntent::None;

    hero(ui, cx);

    ui.add_space(tokens::SPACE_LG);

    if let Some(banner) = cx.env.warning_banner() {
        warn_banner(ui, cx.palette, &banner, &cx.env.notes);
        ui.add_space(tokens::SPACE_MD);
    }

    // Primary action row: Tidy + Purge as big gradient/panel cards.
    ui.columns(2, |cols| {
        if primary_card(
            &mut cols[0],
            cx.palette,
            "Tidy up",
            "Find duplicates, old files, and space hogs. Everyday cleanup with a safety net.",
            &format!(
                "{} files · {} on disk",
                cx.last_scan_files,
                format_bytes(cx.last_scan_bytes)
            ),
            "Open Tidy",
            true,
        ) {
            intent = HomeIntent::OpenTidy;
        }
        if primary_card(
            &mut cols[1],
            cx.palette,
            "Purge",
            "Forensic-grade destruction when you actually need it. Crypto-shred, multi-pass wipe, and more.",
            &if cx.env.overwrite_effective {
                "Overwrite is effective on this host".to_string()
            } else {
                "Crypto-shred recommended on this host".to_string()
            },
            "Open Purge",
            false,
        ) {
            intent = HomeIntent::OpenPurge;
        }
    });

    ui.add_space(tokens::SPACE_MD);

    // Secondary row: plan + environment.
    ui.columns(2, |cols| {
        card_frame(&mut cols[0], cx.palette, |ui| {
            ui.label(
                RichText::new("Cleanup plan")
                    .color(cx.palette.text)
                    .text_style(TextStyle::Name("H2".into())),
            );
            ui.add_space(tokens::SPACE_XS);
            ui.label(
                RichText::new(format!(
                    "{} item(s) · {} ready to reclaim",
                    cx.plan_items,
                    format_bytes(cx.plan_bytes)
                ))
                .color(cx.palette.text_dim),
            );
            ui.add_space(tokens::SPACE_SM);
            if ui.button("Review in Tidy").clicked() {
                intent = HomeIntent::OpenTidy;
            }
        });

        card_frame(&mut cols[1], cx.palette, |ui| {
            ui.label(
                RichText::new("Environment")
                    .color(cx.palette.text)
                    .text_style(TextStyle::Name("H2".into())),
            );
            ui.add_space(tokens::SPACE_XS);
            ui.label(
                RichText::new(format!(
                    "{} · {}",
                    cx.env.virtualization.label(),
                    cx.env.storage_class.label()
                ))
                .color(cx.palette.text),
            );
            ui.label(
                RichText::new(if cx.env.overwrite_effective {
                    "Overwrite-based wipe is meaningful here."
                } else {
                    "Crypto-shred recommended."
                })
                .color(cx.palette.text_dim)
                .small(),
            );
        });
    });

    ui.add_space(tokens::SPACE_MD);

    ui.columns(2, |cols| {
        card_frame(&mut cols[0], cx.palette, |ui| {
            ui.label(
                RichText::new("First time here?")
                    .color(cx.palette.text)
                    .text_style(TextStyle::Name("H2".into())),
            );
            ui.add_space(tokens::SPACE_XS);
            ui.label(
                RichText::new("Read the docs — safety model, keyboard shortcuts, and the Tidy/Purge split.")
                    .color(cx.palette.text_dim),
            );
            ui.add_space(tokens::SPACE_SM);
            if ui.button("Open Docs").clicked() {
                intent = HomeIntent::OpenDocs;
            }
        });

        card_frame(&mut cols[1], cx.palette, |ui| {
            ui.label(
                RichText::new("Settings")
                    .color(cx.palette.text)
                    .text_style(TextStyle::Name("H2".into())),
            );
            ui.add_space(tokens::SPACE_XS);
            ui.label(
                RichText::new("Theme, protected paths, safety lock.")
                    .color(cx.palette.text_dim),
            );
            ui.add_space(tokens::SPACE_SM);
            if ui.button("Open Settings").clicked() {
                intent = HomeIntent::OpenSettings;
            }
        });
    });

    intent
}

/// The gradient hero section at the top of Home.
fn hero(ui: &mut Ui, cx: &HomeContext) {
    let available_width = ui.available_width();
    let hero_height = 180.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(available_width, hero_height),
        egui::Sense::hover(),
    );

    // Gradient background with rounded corners: paint the gradient
    // inside a clipped rect, then stroke/round over it.
    let painter = ui.painter();
    paint_horizontal_gradient(painter, rect, cx.palette.gradient_a, cx.palette.gradient_b);

    // Soft darken overlay along the bottom so the text stays readable.
    let overlay = egui::Rect::from_min_size(
        rect.left_top(),
        egui::vec2(rect.width(), rect.height()),
    );
    painter.rect_filled(
        overlay,
        egui::Rounding::same(tokens::RADIUS_LG),
        Color32::from_black_alpha(25),
    );
    // The rounding on a filled rect via rect_filled covers the corners.
    // Round again with a subtle stroke for crispness.
    painter.rect_stroke(
        rect,
        egui::Rounding::same(tokens::RADIUS_LG),
        egui::Stroke::new(1.0, Color32::from_white_alpha(30)),
    );

    // Clip the inner content so we can lay text on top.
    let inner_margin = 28.0;
    let content_rect = rect.shrink(inner_margin);
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(content_rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    let child_ui = &mut child;
    child_ui.label(
        RichText::new("PlausiDen")
            .color(Color32::from_white_alpha(190))
            .text_style(TextStyle::Name("H2".into())),
    );
    child_ui.add_space(2.0);
    child_ui.label(
        RichText::new("Atrium")
            .color(Color32::WHITE)
            .text_style(TextStyle::Name("Display".into()))
            .strong(),
    );
    child_ui.add_space(6.0);
    child_ui.label(
        RichText::new("A sexy front door to your data sovereignty toolkit.")
            .color(Color32::from_white_alpha(225))
            .size(15.0),
    );
    child_ui.add_space(10.0);
    child_ui.label(
        RichText::new("Tidy • Purge • Disk analysis • Docs")
            .color(Color32::from_white_alpha(180))
            .text_style(TextStyle::Small),
    );
}

/// A gradient-filled primary card for the Home page action row.
fn primary_card(
    ui: &mut Ui,
    palette: &Palette,
    title: &str,
    subtitle: &str,
    meta: &str,
    button: &str,
    is_primary: bool,
) -> bool {
    let mut clicked = false;
    let available = ui.available_width();
    let height = 150.0;
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(available, height), egui::Sense::hover());

    // Background fill: brand-tinted panel with a subtle gradient.
    let (top, bottom) = if is_primary {
        (palette.gradient_a, palette.gradient_b)
    } else {
        (palette.bg_elevated, palette.bg_panel)
    };
    let painter = ui.painter();
    paint_horizontal_gradient(painter, rect, top, bottom);
    painter.rect_stroke(
        rect,
        egui::Rounding::same(tokens::RADIUS_LG),
        egui::Stroke::new(1.0, palette.border_strong),
    );
    // Soft inner rounded mask (mirrored vignette) for polish.
    painter.rect_filled(
        rect.shrink(0.5),
        egui::Rounding::same(tokens::RADIUS_LG),
        Color32::TRANSPARENT,
    );

    let inner = rect.shrink(22.0);
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    let child_ui = &mut child;

    let title_color = if is_primary {
        Color32::WHITE
    } else {
        palette.text
    };
    let body_color = if is_primary {
        Color32::from_white_alpha(225)
    } else {
        palette.text_dim
    };
    let meta_color = if is_primary {
        Color32::from_white_alpha(180)
    } else {
        palette.text_subtle
    };

    child_ui.label(
        RichText::new(title)
            .color(title_color)
            .text_style(TextStyle::Name("H2".into()))
            .strong(),
    );
    child_ui.add_space(4.0);
    child_ui.label(RichText::new(subtitle).color(body_color));
    child_ui.add_space(8.0);
    child_ui.label(
        RichText::new(meta)
            .color(meta_color)
            .text_style(TextStyle::Small),
    );
    child_ui.add_space(10.0);
    let btn = child_ui.add(
        egui::Button::new(
            RichText::new(format!("{}  →", button))
                .color(title_color)
                .strong(),
        )
        .fill(if is_primary {
            Color32::from_white_alpha(30)
        } else {
            palette.accent_soft
        })
        .stroke(egui::Stroke::new(
            1.0,
            if is_primary {
                Color32::from_white_alpha(80)
            } else {
                palette.accent
            },
        )),
    );
    if btn.clicked() {
        clicked = true;
    }

    clicked
}

fn warn_banner(ui: &mut Ui, palette: &Palette, text: &str, notes: &[String]) {
    egui::Frame::none()
        .fill(palette.warn_bg)
        .stroke(egui::Stroke::new(1.0, palette.warn))
        .rounding(egui::Rounding::same(tokens::RADIUS_MD))
        .inner_margin(egui::Margin::symmetric(18.0, 12.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("⚠  {}", text))
                    .color(palette.warn)
                    .strong(),
            );
            for n in notes {
                ui.label(
                    RichText::new(format!("  • {}", n))
                        .color(palette.text_dim),
                );
            }
        });
}
