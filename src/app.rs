//! Top-level Atrium application shell.

use crate::config::AtriumConfig;
use crate::pages::{
    docs as docs_page,
    home::{self, HomeContext, HomeIntent},
    purge as purge_page,
    settings::{self, SettingsContext, SettingsIntent},
    tidy::{self, TidyContext, TidyState},
    Page,
};
use crate::theme::{self, Palette, Resolved, ThemeMode};
use egui::{RichText, Ui};
use plausiden_tidy::environment::{self, EnvironmentReport};
use plausiden_tidy::importance::ImportanceClassifier;

pub struct AtriumApp {
    pub page: Page,
    pub config: AtriumConfig,
    pub classifier: ImportanceClassifier,
    pub env: EnvironmentReport,
    pub tidy: TidyState,
    pub new_protected_input: String,
    pub system_prefers_dark: bool,
    pub resolved_theme: Resolved,
    pub last_applied_theme: Option<Resolved>,
}

impl AtriumApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config = AtriumConfig::load();
        let classifier = settings::rebuild_classifier(&config);
        let system_prefers_dark = cc.egui_ctx.style().visuals.dark_mode;
        let resolved = theme::resolve(config.theme, system_prefers_dark);
        theme::apply(&cc.egui_ctx, resolved);
        Self {
            page: Page::Home,
            config,
            classifier,
            env: environment::detect(),
            tidy: TidyState::default(),
            new_protected_input: String::new(),
            system_prefers_dark,
            resolved_theme: resolved,
            last_applied_theme: Some(resolved),
        }
    }

    fn palette(&self) -> &'static Palette {
        Palette::for_resolved(self.resolved_theme)
    }

    fn sync_theme(&mut self, ctx: &egui::Context) {
        let resolved = theme::resolve(self.config.theme, self.system_prefers_dark);
        if self.last_applied_theme != Some(resolved) {
            theme::apply(ctx, resolved);
            self.last_applied_theme = Some(resolved);
        }
        self.resolved_theme = resolved;
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        ui.label(
            RichText::new("PlausiDen")
                .color(self.palette().text)
                .size(18.0)
                .strong(),
        );
        ui.label(
            RichText::new("Atrium")
                .color(self.palette().text_dim)
                .italics(),
        );
        ui.add_space(10.0);

        for page in Page::ALL {
            let selected = self.page == page;
            let text = RichText::new(format!("  {}  {}", page.icon(), page.label()))
                .color(if selected {
                    self.palette().accent
                } else {
                    self.palette().text
                })
                .size(15.0);
            let btn = ui.add_sized([180.0, 34.0], egui::SelectableLabel::new(selected, text));
            if btn.clicked() {
                self.page = page;
            }
        }

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(8.0);

        ui.label(
            RichText::new("Plan summary")
                .color(self.palette().text_dim)
                .small(),
        );
        ui.label(format!("  items: {}", self.tidy.plan.len()));
        ui.label(format!(
            "  approved: {}",
            self.tidy.plan.approved_count()
        ));

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        let lock_label = if self.config.dry_run_locked {
            RichText::new("🔒 dry-run locked").color(self.palette().ok)
        } else {
            RichText::new("⚠ live mode").color(self.palette().critical)
        };
        ui.label(lock_label);
    }

    fn header(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(self.page.label())
                    .color(self.palette().text)
                    .size(22.0)
                    .strong(),
            );
            ui.label(
                RichText::new(self.page.description())
                    .color(self.palette().text_dim)
                    .italics(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                egui::ComboBox::from_id_salt("theme-picker")
                    .selected_text(self.config.theme.label())
                    .show_ui(ui, |ui| {
                        for mode in ThemeMode::ALL {
                            if ui
                                .selectable_value(&mut self.config.theme, mode, mode.label())
                                .changed()
                            {
                                let _ = self.config.save();
                            }
                        }
                    });
            });
        });
        ui.separator();
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} · {} · overwrite effective: {}",
                    self.env.virtualization.label(),
                    self.env.storage_class.label(),
                    if self.env.overwrite_effective { "yes" } else { "no" }
                ))
                .color(self.palette().text_dim)
                .small(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(&self.tidy.status)
                        .color(self.palette().text_dim)
                        .small(),
                );
            });
        });
    }
}

impl eframe::App for AtriumApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sync_theme(ctx);

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(210.0)
            .show(ctx, |ui| self.sidebar(ui));

        egui::TopBottomPanel::top("header").show(ctx, |ui| self.header(ui));

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));

        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Home => {
                let cx = HomeContext {
                    palette: self.palette(),
                    env: &self.env,
                    last_scan_files: self
                        .tidy
                        .last_scan
                        .as_ref()
                        .map(|s| s.report.files_scanned)
                        .unwrap_or(0),
                    last_scan_bytes: self
                        .tidy
                        .last_scan
                        .as_ref()
                        .map(|s| s.report.total_bytes)
                        .unwrap_or(0),
                    plan_items: self.tidy.plan.len(),
                    plan_bytes: self.tidy.plan.total_bytes(),
                };
                match home::show(ui, &cx) {
                    HomeIntent::OpenTidy => self.page = Page::Tidy,
                    HomeIntent::OpenPurge => self.page = Page::Purge,
                    HomeIntent::OpenDocs => self.page = Page::Docs,
                    HomeIntent::OpenSettings => self.page = Page::Settings,
                    HomeIntent::None => {}
                }
            }
            Page::Tidy => {
                let cx = TidyContext {
                    palette: self.palette(),
                    config: &self.config,
                    classifier: &self.classifier,
                };
                tidy::show(ui, &mut self.tidy, &cx, ctx);
            }
            Page::Purge => {
                purge_page::show(ui, self.palette(), &self.env);
            }
            Page::Docs => {
                docs_page::show(ui, self.palette());
            }
            Page::Settings => {
                let mut cx = SettingsContext {
                    palette: self.palette(),
                    config: &mut self.config,
                    new_protected: &mut self.new_protected_input,
                    env: &self.env,
                };
                match settings::show(ui, &mut cx) {
                    SettingsIntent::ProtectedChanged => {
                        self.classifier = settings::rebuild_classifier(&self.config);
                        let _ = self.config.save();
                    }
                    SettingsIntent::ThemeChanged
                    | SettingsIntent::LockChanged
                    | SettingsIntent::Save => {
                        let _ = self.config.save();
                    }
                    SettingsIntent::None => {}
                }
            }
        });
    }
}
