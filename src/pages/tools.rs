//! Tools page — forensic tools, wipe presets, disk devices.
//!
//! Purge deliberately does not get its own top-level tab — destruction
//! is configured per-item in the Tidy Plan view. This page is the
//! *meta*-tools drawer: which forensic recovery tools are detected,
//! which wipe presets exist, and which block devices Atrium can see.

use crate::disk_wipe::{self, DeviceInfo};
use crate::forensic::{self, ForensicTool, ToolInventory, INSTALL_HINT};
use crate::formats::format_bytes;
use crate::theme::{tokens, Palette};
use crate::widgets::card_frame;
use crate::wipe_config::WipePreset;
use egui::{RichText, ScrollArea, TextStyle, Ui};

pub struct ToolsState {
    pub inventory: ToolInventory,
    pub devices: Vec<DeviceInfo>,
    #[allow(dead_code)]
    pub refresh_requested: bool,
}

impl Default for ToolsState {
    fn default() -> Self {
        Self {
            inventory: forensic::detect_tools(),
            devices: disk_wipe::list_block_devices(),
            refresh_requested: false,
        }
    }
}

impl ToolsState {
    pub fn refresh(&mut self) {
        self.inventory = forensic::detect_tools();
        self.devices = disk_wipe::list_block_devices();
    }
}

pub fn show(ui: &mut Ui, palette: &Palette, state: &mut ToolsState) {
    ui.label(
        RichText::new("Tools")
            .color(palette.text)
            .text_style(TextStyle::Heading)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Forensic recovery verification, wipe presets, and disk devices. The destructive actions themselves are chosen per-item in the Tidy Plan — this drawer is read-only metadata and a place to review the options.",
        )
        .color(palette.text_dim),
    );
    ui.add_space(tokens::SPACE_MD);

    if ui.button("Refresh").clicked() {
        state.refresh();
    }

    ui.add_space(tokens::SPACE_SM);

    ScrollArea::vertical().show(ui, |ui| {
        forensic_tools_card(ui, palette, &state.inventory);
        ui.add_space(tokens::SPACE_SM);
        wipe_presets_card(ui, palette);
        ui.add_space(tokens::SPACE_SM);
        disk_devices_card(ui, palette, &state.devices);
    });
}

fn forensic_tools_card(ui: &mut Ui, palette: &Palette, inv: &ToolInventory) {
    card_frame(ui, palette, |ui| {
        ui.label(
            RichText::new("Forensic recovery verification")
                .color(palette.text)
                .text_style(TextStyle::Name("H2".into())),
        );
        ui.label(
            RichText::new(
                "After a wipe, Atrium can run the tools below against a device or image and count how many files come back. If anything is recoverable, the wipe loop re-runs until nothing remains.",
            )
            .color(palette.text_dim),
        );
        ui.add_space(tokens::SPACE_SM);

        if inv.is_any_available() {
            ui.label(
                RichText::new(format!("Detected {} tool(s)", inv.available.len()))
                    .color(palette.ok)
                    .strong(),
            );
        } else {
            ui.label(
                RichText::new("No forensic recovery tools detected.")
                    .color(palette.warn)
                    .strong(),
            );
            ui.label(
                RichText::new(INSTALL_HINT)
                    .color(palette.text_dim)
                    .text_style(TextStyle::Small),
            );
            return;
        }

        ui.add_space(6.0);
        for tool in &inv.available {
            tool_row(ui, palette, *tool, true);
        }
        if !inv.missing.is_empty() {
            ui.add_space(8.0);
            ui.label(
                RichText::new("Missing (install for fuller coverage)")
                    .color(palette.text_subtle)
                    .text_style(TextStyle::Name("Tiny".into()))
                    .strong(),
            );
            for tool in &inv.missing {
                tool_row(ui, palette, *tool, false);
            }
        }
    });
}

fn tool_row(ui: &mut Ui, palette: &Palette, tool: ForensicTool, available: bool) {
    ui.horizontal(|ui| {
        let dot_color = if available { palette.ok } else { palette.text_subtle };
        let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, dot_color);
        ui.label(
            RichText::new(tool.binary())
                .color(palette.text)
                .monospace(),
        );
        ui.label(
            RichText::new(tool.description())
                .color(palette.text_dim)
                .small(),
        );
    });
}

fn wipe_presets_card(ui: &mut Ui, palette: &Palette) {
    card_frame(ui, palette, |ui| {
        ui.label(
            RichText::new("Wipe presets")
                .color(palette.text)
                .text_style(TextStyle::Name("H2".into())),
        );
        ui.label(
            RichText::new(
                "These recipes are available in the Tidy Plan view. Pick one per item or compose a Custom sequence passing multiple algorithms.",
            )
            .color(palette.text_dim),
        );
        ui.add_space(tokens::SPACE_SM);

        for preset in WipePreset::ALL {
            let config = crate::wipe_config::WipeConfig::preset(*preset);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(preset.label())
                        .color(palette.text)
                        .monospace()
                        .strong(),
                );
                ui.label(
                    RichText::new(format!("{} pass(es)", config.total_passes()))
                        .color(palette.accent)
                        .small(),
                );
            });
            ui.label(
                RichText::new(preset.description())
                    .color(palette.text_dim)
                    .small(),
            );
            ui.add_space(4.0);
        }
    });
}

fn disk_devices_card(ui: &mut Ui, palette: &Palette, devices: &[DeviceInfo]) {
    card_frame(ui, palette, |ui| {
        ui.label(
            RichText::new("Block devices")
                .color(palette.text)
                .text_style(TextStyle::Name("H2".into())),
        );
        ui.label(
            RichText::new(
                "All block devices visible in /sys/block. Disk-range wiping lets you target a specific byte interval on one of these — an advanced feature guarded behind the safety lock in Settings.",
            )
            .color(palette.text_dim),
        );
        ui.add_space(tokens::SPACE_SM);

        if devices.is_empty() {
            ui.label(
                RichText::new("No block devices visible (permissions?).")
                    .color(palette.warn),
            );
            return;
        }

        for dev in devices {
            ui.horizontal(|ui| {
                let color = if dev.rotational {
                    palette.tier_high
                } else {
                    palette.tier_low
                };
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 6.0, color);
                ui.label(
                    RichText::new(format!("/dev/{}", dev.name))
                        .color(palette.text)
                        .monospace()
                        .strong(),
                );
                ui.label(
                    RichText::new(format!("{} · {}", format_bytes(dev.size_bytes), dev.storage_label()))
                        .color(palette.text_dim),
                );
            });
        }

        ui.add_space(tokens::SPACE_SM);
        ui.label(
            RichText::new(
                "⚠  Writing to the wrong device will destroy data. Atrium refuses to run disk wipes unless the safety lock is explicitly released in Settings.",
            )
            .color(palette.warn)
            .small(),
        );
    });
}
