//! Tools page — forensic tools, wipe presets, disk devices.
//!
//! Purge deliberately does not get its own top-level tab — destruction
//! is configured per-item in the Tidy Plan view. This page is the
//! *meta*-tools drawer: which forensic recovery tools are detected,
//! which wipe presets exist, and which block devices Atrium can see.

use crate::disk_wipe::{self, DeviceInfo};
use crate::forensic::{self, ForensicTool, ToolInventory, VerificationReport, INSTALL_HINT};
use crate::formats::format_bytes;
use crate::theme::{tokens, Palette};
use crate::widgets::card_frame;
use crate::wipe_config::WipePreset;
use egui::{RichText, ScrollArea, TextEdit, TextStyle, Ui};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct VerifyInFlight {
    #[allow(dead_code)]
    pub tool: ForensicTool,
    #[allow(dead_code)]
    pub target: PathBuf,
    pub result: Option<VerificationReport>,
}

pub struct ToolsState {
    pub inventory: ToolInventory,
    pub devices: Vec<DeviceInfo>,
    pub verify_tool: Option<ForensicTool>,
    pub verify_target: String,
    pub verify_in_flight: Option<Arc<Mutex<VerifyInFlight>>>,
    pub verify_last_report: Option<VerificationReport>,
}

impl Default for ToolsState {
    fn default() -> Self {
        let inventory = forensic::detect_tools();
        let first_tool = inventory.preferred();
        Self {
            inventory,
            devices: disk_wipe::list_block_devices(),
            verify_tool: first_tool,
            verify_target: String::new(),
            verify_in_flight: None,
            verify_last_report: None,
        }
    }
}

impl ToolsState {
    pub fn refresh(&mut self) {
        self.inventory = forensic::detect_tools();
        self.devices = disk_wipe::list_block_devices();
        if self.verify_tool.is_none() {
            self.verify_tool = self.inventory.preferred();
        }
    }

    pub fn start_verify(&mut self, ctx: &egui::Context) {
        let Some(tool) = self.verify_tool else { return };
        let target = PathBuf::from(self.verify_target.trim());
        if target.as_os_str().is_empty() || !target.exists() {
            return;
        }
        let shared = Arc::new(Mutex::new(VerifyInFlight {
            tool,
            target: target.clone(),
            result: None,
        }));
        let shared_clone = shared.clone();
        let ctx_clone = ctx.clone();
        self.verify_in_flight = Some(shared);
        self.verify_last_report = None;
        std::thread::spawn(move || {
            let out_dir = std::env::temp_dir()
                .join(format!("atrium-verify-{}", std::process::id()));
            let report = forensic::run_verification(tool, &target, &out_dir);
            if let Ok(mut guard) = shared_clone.lock() {
                guard.result = Some(report);
            }
            ctx_clone.request_repaint();
        });
    }

    pub fn poll_verify(&mut self) {
        let Some(shared) = self.verify_in_flight.clone() else { return };
        let Ok(mut guard) = shared.lock() else { return };
        if let Some(report) = guard.result.take() {
            drop(guard);
            self.verify_in_flight = None;
            self.verify_last_report = Some(report);
        }
    }
}

pub fn show(ui: &mut Ui, palette: &Palette, state: &mut ToolsState, ctx: &egui::Context) {
    state.poll_verify();

    ui.label(
        RichText::new("Tools")
            .color(palette.text)
            .text_style(TextStyle::Heading)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Forensic recovery verification, wipe presets, and disk devices. The destructive actions themselves are chosen per-item in the Tidy Plan — this drawer is for running verification runs and reviewing the options.",
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
        verification_run_card(ui, palette, state, ctx);
        ui.add_space(tokens::SPACE_SM);
        wipe_presets_card(ui, palette);
        ui.add_space(tokens::SPACE_SM);
        disk_devices_card(ui, palette, &state.devices);
    });
}

fn verification_run_card(
    ui: &mut Ui,
    palette: &Palette,
    state: &mut ToolsState,
    ctx: &egui::Context,
) {
    card_frame(ui, palette, |ui| {
        ui.label(
            RichText::new("Run forensic verification")
                .color(palette.text)
                .text_style(TextStyle::Name("H2".into())),
        );
        ui.label(
            RichText::new(
                "Launch a detected recovery tool against a target (a disk image, a freespace scan, or a test directory). This runs the tool in a worker thread and surfaces the result when it completes. Forensic tools can take minutes on large targets; Atrium will not block the rest of the UI while one runs.",
            )
            .color(palette.text_dim),
        );
        ui.add_space(tokens::SPACE_SM);

        if !state.inventory.is_any_available() {
            ui.label(
                RichText::new("No forensic tools detected — install one first.")
                    .color(palette.warn)
                    .strong(),
            );
            return;
        }

        ui.horizontal(|ui| {
            ui.label("Tool:");
            let current_label = state
                .verify_tool
                .map(|t| t.binary())
                .unwrap_or("(none)");
            egui::ComboBox::from_id_salt("forensic-tool-picker")
                .selected_text(current_label)
                .show_ui(ui, |ui| {
                    for tool in &state.inventory.available {
                        ui.selectable_value(
                            &mut state.verify_tool,
                            Some(*tool),
                            tool.binary(),
                        );
                    }
                });
        });

        ui.horizontal(|ui| {
            ui.label("Target:");
            ui.add(
                TextEdit::singleline(&mut state.verify_target)
                    .hint_text("/tmp or /dev/sdX or a disk image")
                    .desired_width(420.0),
            );
            if ui.button("Pick directory…").clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                state.verify_target = d.to_string_lossy().into_owned();
            }
            if ui.button("Pick file…").clicked()
                && let Some(f) = rfd::FileDialog::new().pick_file()
            {
                state.verify_target = f.to_string_lossy().into_owned();
            }
        });

        ui.add_space(4.0);
        let running = state.verify_in_flight.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!running, egui::Button::new("Run verification"))
                .clicked()
            {
                state.start_verify(ctx);
            }
            if running {
                ui.spinner();
                ui.label(RichText::new("running…").color(palette.text_dim));
                ctx.request_repaint_after(std::time::Duration::from_millis(300));
            }
        });

        if let Some(report) = &state.verify_last_report {
            ui.add_space(tokens::SPACE_SM);
            ui.separator();
            ui.add_space(4.0);
            let verdict_color = if report.success && report.files_recovered == 0 {
                palette.ok
            } else if report.files_recovered > 0 {
                palette.warn
            } else {
                palette.critical
            };
            ui.label(
                RichText::new(format!(
                    "{} · {} files recovered",
                    report.tool.binary(),
                    report.files_recovered
                ))
                .color(verdict_color)
                .strong(),
            );
            ui.label(
                RichText::new(format!("target: {}", report.target.display()))
                    .color(palette.text_dim)
                    .small()
                    .monospace(),
            );
            if let Some(err) = &report.error {
                ui.label(
                    RichText::new(format!("error: {}", err))
                        .color(palette.critical)
                        .small(),
                );
            }
            if !report.raw_output.is_empty() {
                ui.collapsing("Tool output", |ui| {
                    ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                        ui.label(
                            RichText::new(&report.raw_output)
                                .color(palette.text_dim)
                                .monospace()
                                .small(),
                        );
                    });
                });
            }
        }
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
