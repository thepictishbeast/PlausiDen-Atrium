//! Tools page — forensic tools, wipe presets, disk devices.
//!
//! Purge deliberately does not get its own top-level tab — destruction
//! is configured per-item in the Tidy Plan view. This page is the
//! *meta*-tools drawer: which forensic recovery tools are detected,
//! which wipe presets exist, and which block devices Atrium can see.

use crate::disk_wipe::{self, DeviceInfo, DiskRange, DiskWipeReport};
use crate::forensic::{self, ForensicTool, ToolInventory, VerificationReport, INSTALL_HINT};
use crate::formats::format_bytes;
use crate::theme::{tokens, Palette};
use crate::widgets::card_frame;
use crate::wipe_config::{WipeConfig, WipePreset};
use egui::{RichText, ScrollArea, TextEdit, TextStyle, Ui};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Per-device disk-range wipe form state.
#[derive(Debug, Clone)]
pub struct RangeForm {
    pub start_text: String,
    pub end_text: String,
    pub preset: WipePreset,
    pub confirm_device: String,
    pub last_report: Option<DiskWipeReport>,
}

impl Default for RangeForm {
    fn default() -> Self {
        Self {
            start_text: "0".into(),
            end_text: "0".into(),
            preset: WipePreset::Quick,
            confirm_device: String::new(),
            last_report: None,
        }
    }
}

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
    /// Per-device disk-range wipe forms, keyed by device name.
    pub range_forms: HashMap<String, RangeForm>,
    /// Which device's range form is currently open (collapsible).
    pub range_open_for: Option<String>,
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
            range_forms: HashMap::new(),
            range_open_for: None,
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

pub fn show(
    ui: &mut Ui,
    palette: &Palette,
    state: &mut ToolsState,
    ctx: &egui::Context,
    safety_lock_on: bool,
) {
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
        disk_devices_card(ui, palette, state, safety_lock_on);
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

fn disk_devices_card(ui: &mut Ui, palette: &Palette, state: &mut ToolsState, safety_lock_on: bool) {
    card_frame(ui, palette, |ui| {
        ui.label(
            RichText::new("Block devices · disk-range wipe")
                .color(palette.text)
                .text_style(TextStyle::Name("H2".into())),
        );
        ui.label(
            RichText::new(
                "Target a specific byte interval on a block device with any WipeConfig preset. Extremely destructive. Guarded behind the safety lock in Settings, a per-wipe confirmation, and a dry-run fallback.",
            )
            .color(palette.text_dim),
        );
        ui.add_space(tokens::SPACE_SM);

        if state.devices.is_empty() {
            ui.label(
                RichText::new("No block devices visible (permissions?).")
                    .color(palette.warn),
            );
            return;
        }

        // Clone the device list so we can mutate state inside the loop.
        let devices: Vec<DeviceInfo> = state.devices.clone();

        for dev in &devices {
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
                    RichText::new(format!(
                        "{} · {}",
                        format_bytes(dev.size_bytes),
                        dev.storage_label()
                    ))
                    .color(palette.text_dim),
                );
                let open = state
                    .range_open_for
                    .as_ref()
                    .map(|n| n == &dev.name)
                    .unwrap_or(false);
                let label = if open { "Hide wipe form" } else { "Wipe a range…" };
                if ui.button(label).clicked() {
                    if open {
                        state.range_open_for = None;
                    } else {
                        state.range_open_for = Some(dev.name.clone());
                    }
                }
            });

            // Show the expanded form under the device row.
            if state
                .range_open_for
                .as_ref()
                .map(|n| n == &dev.name)
                .unwrap_or(false)
            {
                ui.indent(format!("range-form-{}", dev.name), |ui| {
                    range_form_for(ui, palette, dev, state, safety_lock_on);
                });
            }
        }

        ui.add_space(tokens::SPACE_SM);
        ui.label(
            RichText::new(
                "⚠  Disk-range wipe writes directly to /dev/*. Pointing this at the wrong device will destroy data. Keep the safety lock engaged unless you are certain.",
            )
            .color(palette.warn)
            .small(),
        );
    });
}

fn range_form_for(
    ui: &mut Ui,
    palette: &Palette,
    dev: &DeviceInfo,
    state: &mut ToolsState,
    safety_lock_on: bool,
) {
    let form = state
        .range_forms
        .entry(dev.name.clone())
        .or_insert_with(RangeForm::default);

    egui::Frame::none()
        .fill(palette.bg_panel)
        .stroke(egui::Stroke::new(1.0, palette.warn))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("Range wipe: /dev/{}", dev.name))
                    .color(palette.warn)
                    .strong(),
            );
            ui.label(
                RichText::new(format!(
                    "Device size: {} ({}).",
                    format_bytes(dev.size_bytes),
                    dev.storage_label()
                ))
                .color(palette.text_dim)
                .small(),
            );
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Start (bytes):");
                ui.add(
                    TextEdit::singleline(&mut form.start_text)
                        .desired_width(140.0)
                        .hint_text("0"),
                );
                ui.label("End (bytes):");
                ui.add(
                    TextEdit::singleline(&mut form.end_text)
                        .desired_width(140.0)
                        .hint_text(&format!("{}", dev.size_bytes)),
                );
            });

            ui.horizontal(|ui| {
                ui.label("Preset:");
                egui::ComboBox::from_id_salt(format!("range-preset-{}", dev.name))
                    .selected_text(form.preset.label())
                    .show_ui(ui, |ui| {
                        for preset in WipePreset::ALL {
                            ui.selectable_value(&mut form.preset, *preset, preset.label());
                        }
                    });
                let config = WipeConfig::preset(form.preset);
                ui.label(
                    RichText::new(format!("{} pass(es)", config.total_passes()))
                        .color(palette.accent)
                        .small(),
                );
            });

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Type the device name to confirm:")
                        .color(palette.text_dim),
                );
                ui.add(
                    TextEdit::singleline(&mut form.confirm_device)
                        .desired_width(140.0)
                        .hint_text(&dev.name),
                );
            });

            let start = form.start_text.trim().parse::<u64>().unwrap_or(0);
            let end = form.end_text.trim().parse::<u64>().unwrap_or(0);
            let range_valid = end > start && end <= dev.size_bytes;
            let name_matches = form.confirm_device.trim() == dev.name;
            let live = !safety_lock_on;
            let can_run = range_valid && name_matches;

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let label = if live {
                    "Run range wipe (LIVE)"
                } else {
                    "Run range wipe (DRY-RUN)"
                };
                let color = if live { palette.critical } else { palette.accent };
                if ui
                    .add_enabled(
                        can_run,
                        egui::Button::new(RichText::new(label).color(color)),
                    )
                    .clicked()
                {
                    let range = DiskRange {
                        device: PathBuf::from(format!("/dev/{}", dev.name)),
                        start,
                        end,
                        label: format!("/dev/{} [{:?}..{:?}]", dev.name, start, end),
                    };
                    let config = WipeConfig::preset(form.preset);
                    let report = disk_wipe::wipe_range(&range, &config, !live);
                    form.last_report = Some(report);
                }
                ui.label(
                    RichText::new(format!(
                        "range: {} bytes",
                        format_bytes(end.saturating_sub(start))
                    ))
                    .color(palette.text_subtle)
                    .small(),
                );
            });

            if !range_valid {
                ui.label(
                    RichText::new(
                        "Range invalid: end must be greater than start and within the device size.",
                    )
                    .color(palette.critical)
                    .small(),
                );
            }
            if !name_matches {
                ui.label(
                    RichText::new("Device name confirmation doesn't match.")
                        .color(palette.critical)
                        .small(),
                );
            }

            if let Some(report) = &form.last_report {
                ui.add_space(6.0);
                let color = if report.success {
                    palette.ok
                } else {
                    palette.critical
                };
                ui.label(
                    RichText::new(format!(
                        "{}: {} pass(es) · {} written",
                        if report.success { "OK" } else { "FAIL" },
                        report.passes_run,
                        format_bytes(report.bytes_written)
                    ))
                    .color(color)
                    .strong(),
                );
                for err in &report.errors {
                    ui.label(
                        RichText::new(format!("  · {}", err))
                            .color(palette.text_dim)
                            .small(),
                    );
                }
            }
        });
}
