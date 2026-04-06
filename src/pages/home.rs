//! Home page — environment summary and quick-start cards.

use crate::formats::format_bytes;
use crate::theme::Palette;
use crate::widgets::card_frame;
use egui::{RichText, Ui};
use plausiden_tidy::environment::EnvironmentReport;

pub struct HomeContext<'a> {
    pub palette: &'a Palette,
    pub env: &'a EnvironmentReport,
    pub last_scan_files: u64,
    pub last_scan_bytes: u64,
    pub plan_items: usize,
    pub plan_bytes: u64,
}

/// Intent returned from the Home page when the user clicks a card button.
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

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("PlausiDen Atrium")
                .color(cx.palette.text)
                .size(28.0)
                .strong(),
        );
        ui.label(
            RichText::new("the friendly front door to Tidy and Purge")
                .color(cx.palette.text_dim)
                .italics(),
        );
    });
    ui.add_space(12.0);

    if let Some(banner) = cx.env.warning_banner() {
        egui::Frame::none()
            .fill(cx.palette.warn_bg)
            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
            .rounding(egui::Rounding::same(8.0))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("⚠  {}", banner))
                        .color(cx.palette.warn)
                        .strong(),
                );
                for note in &cx.env.notes {
                    ui.label(RichText::new(format!("  • {}", note)).color(cx.palette.text_dim));
                }
            });
        ui.add_space(10.0);
    }

    // Card grid — two columns.
    ui.columns(2, |cols| {
        card_frame(&mut cols[0], cx.palette, |ui| {
            ui.label(
                RichText::new("Tidy up")
                    .color(cx.palette.text)
                    .size(18.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(RichText::new("Find duplicates, old files, and space hogs").color(cx.palette.text_dim));
            ui.add_space(8.0);
            if cx.last_scan_files > 0 {
                ui.label(
                    RichText::new(format!(
                        "Last scan: {} files · {}",
                        cx.last_scan_files,
                        format_bytes(cx.last_scan_bytes)
                    ))
                    .color(cx.palette.text_dim)
                    .small(),
                );
                ui.add_space(4.0);
            }
            if ui.button(RichText::new("Open Tidy →").size(14.0)).clicked() {
                intent = HomeIntent::OpenTidy;
            }
        });

        card_frame(&mut cols[1], cx.palette, |ui| {
            ui.label(
                RichText::new("Purge")
                    .color(cx.palette.text)
                    .size(18.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Forensic-grade destruction. Use sparingly.")
                    .color(cx.palette.text_dim),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(match cx.env.overwrite_effective {
                    true => "Overwrite is effective on this host.",
                    false => "Crypto-shred is the right choice on this host.",
                })
                .color(cx.palette.text_dim)
                .small(),
            );
            ui.add_space(4.0);
            if ui.button(RichText::new("Open Purge →").size(14.0)).clicked() {
                intent = HomeIntent::OpenPurge;
            }
        });
    });

    ui.add_space(6.0);
    ui.columns(2, |cols| {
        card_frame(&mut cols[0], cx.palette, |ui| {
            ui.label(
                RichText::new("Current cleanup plan")
                    .color(cx.palette.text)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(format!(
                "{} item(s) · {} could be reclaimed",
                cx.plan_items,
                format_bytes(cx.plan_bytes)
            ));
            ui.add_space(6.0);
            if ui.button("Review in Tidy").clicked() {
                intent = HomeIntent::OpenTidy;
            }
        });

        card_frame(&mut cols[1], cx.palette, |ui| {
            ui.label(
                RichText::new("Environment")
                    .color(cx.palette.text)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(format!(
                "{} · {}",
                cx.env.virtualization.label(),
                cx.env.storage_class.label()
            ));
            ui.label(
                RichText::new(match cx.env.overwrite_effective {
                    true => "Overwrite-based wipe is meaningful.",
                    false => "Crypto-shred recommended.",
                })
                .color(cx.palette.text_dim)
                .small(),
            );
        });
    });

    ui.add_space(6.0);
    ui.columns(2, |cols| {
        card_frame(&mut cols[0], cx.palette, |ui| {
            ui.label(
                RichText::new("First time here?")
                    .color(cx.palette.text)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Read the docs — the safety model and keyboard shortcuts.")
                    .color(cx.palette.text_dim),
            );
            ui.add_space(6.0);
            if ui.button("Open Docs").clicked() {
                intent = HomeIntent::OpenDocs;
            }
        });

        card_frame(&mut cols[1], cx.palette, |ui| {
            ui.label(
                RichText::new("Settings")
                    .color(cx.palette.text)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Theme, protected paths, safety lock.")
                    .color(cx.palette.text_dim),
            );
            ui.add_space(6.0);
            if ui.button("Open Settings").clicked() {
                intent = HomeIntent::OpenSettings;
            }
        });
    });

    intent
}
