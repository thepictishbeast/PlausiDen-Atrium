//! Tidy page — the core cleanup interface.
//!
//! This is the busiest part of Atrium. A single scan feeds several
//! views (All Files / Duplicates / Old / Large / Plan), all of which
//! share a virtualized sortable table, per-row context menus, and
//! live filters. The Plan sub-view is where per-item action kinds
//! are assigned and the final confirmation token is entered.

use crate::config::AtriumConfig;
use crate::file_manager;
use crate::formats::{
    format_bytes, format_count, relative_to_root, split_dir_and_name, TypedDuration,
};
use crate::theme::Palette;
use crate::widgets::{duration_input, importance_badge, size_bar};
use chrono::{DateTime, Utc};
use egui::{Align, Layout, RichText, ScrollArea, TextEdit, Ui};
use egui_extras::{Column, TableBuilder};
use plausiden_tidy::action::{ActionKind, FsExecutor, PlanAction};
use plausiden_tidy::age_analyzer::AgeAnalyzer;
use plausiden_tidy::dedup::{DedupReport, Deduplicator};
use plausiden_tidy::importance::{Importance, ImportanceClassifier};
use plausiden_tidy::plan::CleanupPlan;
use plausiden_tidy::scanner::{FileEntry, ScanOptions, ScanReport, Scanner};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Sub-view inside the Tidy page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TidyView {
    AllFiles,
    Duplicates,
    Old,
    Large,
    Plan,
}

impl TidyView {
    pub const ALL: [TidyView; 5] = [
        TidyView::AllFiles,
        TidyView::Duplicates,
        TidyView::Old,
        TidyView::Large,
        TidyView::Plan,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            TidyView::AllFiles => "All files",
            TidyView::Duplicates => "Duplicates",
            TidyView::Old => "Old files",
            TidyView::Large => "Large files",
            TidyView::Plan => "Plan",
        }
    }
}

/// Column that the results table is sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Size,
    Name,
    Directory,
    Modified,
    Importance,
}

/// Background scan progress state shared with the worker thread.
pub struct ScanInFlight {
    pub root: PathBuf,
    pub result: Option<Result<(Vec<FileEntry>, ScanReport), String>>,
}

pub struct ScanResult {
    pub root: PathBuf,
    pub entries: Vec<FileEntry>,
    pub report: ScanReport,
}

pub struct TidyState {
    pub view: TidyView,

    // Scan inputs
    pub scan_path: String,
    pub scan_options: ScanOptions,

    // Scan state
    pub scan_in_flight: Option<Arc<Mutex<ScanInFlight>>>,
    pub last_scan: Option<ScanResult>,

    // Filters
    pub filter_text: String,
    pub age_threshold: TypedDuration,
    pub min_size_filter_bytes: u64,
    pub importance_filter: Option<Importance>,
    pub sort_by: SortBy,
    pub sort_desc: bool,

    // Dedup
    pub dedup_report: Option<DedupReport>,
    pub dedup_min_size: u64,

    // Selection (by path so it is stable across filter changes)
    pub selected: HashSet<PathBuf>,
    pub focus_path: Option<PathBuf>,

    // Plan assembly
    pub plan: CleanupPlan,
    pub default_action_kind: ActionKind,
    pub confirmation_input: String,
    pub last_commit_status: Option<String>,

    // Status
    pub status: String,
}

impl Default for TidyState {
    fn default() -> Self {
        let default_path = std::env::var("HOME")
            .map(|h| format!("{}/Downloads", h))
            .unwrap_or_else(|_| "/tmp".to_string());
        Self {
            view: TidyView::AllFiles,
            scan_path: default_path,
            scan_options: ScanOptions::default(),
            scan_in_flight: None,
            last_scan: None,
            filter_text: String::new(),
            age_threshold: TypedDuration::default(),
            min_size_filter_bytes: 0,
            importance_filter: None,
            sort_by: SortBy::Size,
            sort_desc: true,
            dedup_report: None,
            dedup_min_size: 65536,
            selected: HashSet::new(),
            focus_path: None,
            plan: CleanupPlan::new("Atrium session"),
            default_action_kind: ActionKind::Review,
            confirmation_input: String::new(),
            last_commit_status: None,
            status: "Ready. Nothing is deleted until you approve and confirm.".into(),
        }
    }
}

pub struct TidyContext<'a> {
    pub palette: &'a Palette,
    pub config: &'a AtriumConfig,
    pub classifier: &'a ImportanceClassifier,
}

impl TidyState {
    pub fn start_scan(&mut self, ctx: &egui::Context) {
        let path = PathBuf::from(self.scan_path.trim());
        if !path.exists() {
            self.status = format!("Path does not exist: {}", path.display());
            return;
        }
        let options = self.scan_options.clone();
        let shared = Arc::new(Mutex::new(ScanInFlight {
            root: path.clone(),
            result: None,
        }));
        let shared_clone = shared.clone();
        let ctx_clone = ctx.clone();
        self.scan_in_flight = Some(shared);
        self.status = format!("Scanning {}…", path.display());
        self.selected.clear();
        self.focus_path = None;
        // Clear stale state so the user never sees old results
        // labelled with a new root.
        self.last_scan = None;
        self.dedup_report = None;
        std::thread::spawn(move || {
            let mut scanner = Scanner::new(options);
            let outcome = scanner.scan(&path).map_err(|e| e.to_string()).map(|_| {
                let report = scanner.report().clone();
                (scanner.into_entries(), report)
            });
            if let Ok(mut s) = shared_clone.lock() {
                s.result = Some(outcome);
            }
            ctx_clone.request_repaint();
        });
    }

    pub fn poll_scan(&mut self) {
        let Some(shared) = self.scan_in_flight.clone() else { return };
        let Ok(mut guard) = shared.lock() else { return };
        let Some(outcome) = guard.result.take() else { return };
        let root = guard.root.clone();
        drop(guard);
        self.scan_in_flight = None;
        match outcome {
            Ok((entries, report)) => {
                self.status = format!(
                    "Scanned {} files ({}) in {} directories",
                    report.files_scanned,
                    format_bytes(report.total_bytes),
                    report.dirs_scanned
                );
                self.last_scan = Some(ScanResult { root, entries, report });
                self.dedup_report = None;
            }
            Err(e) => self.status = format!("Scan failed: {}", e),
        }
    }

    fn run_dedup(&mut self) {
        let Some(scan) = &self.last_scan else { return };
        let report = Deduplicator::new()
            .with_min_size(self.dedup_min_size)
            .find(&scan.entries);
        self.status = format!(
            "Found {} duplicate groups ({} reclaimable)",
            report.groups_found,
            format_bytes(report.total_wasted_bytes)
        );
        self.dedup_report = Some(report);
    }

    pub fn filtered_rows(
        &self,
        classifier: &ImportanceClassifier,
    ) -> Vec<&FileEntry> {
        let Some(scan) = &self.last_scan else { return Vec::new() };

        let now = Utc::now();
        let age_days = self.age_threshold.to_days();

        // Pre-compute the set of paths in any duplicate group if
        // the Duplicates view is active.
        let dup_paths: Option<HashSet<PathBuf>> = match self.view {
            TidyView::Duplicates => self.dedup_report.as_ref().map(|r| {
                r.groups
                    .iter()
                    .flat_map(|g| g.paths.iter().cloned())
                    .collect()
            }),
            _ => None,
        };

        let filter_lower = self.filter_text.to_lowercase();
        let importance_wanted = self.importance_filter;

        let mut rows: Vec<&FileEntry> = scan
            .entries
            .iter()
            .filter(|e| !e.is_dir)
            .filter(|e| match self.view {
                TidyView::Old => {
                    let reference = e.accessed.max(e.modified);
                    (now - reference).num_days() >= age_days
                }
                TidyView::Large => e.size >= self.min_size_filter_bytes,
                TidyView::Duplicates => dup_paths
                    .as_ref()
                    .map(|set| set.contains(&e.path))
                    .unwrap_or(false),
                TidyView::AllFiles => true,
                TidyView::Plan => false, // Plan uses its own list
            })
            .filter(|e| {
                if filter_lower.is_empty() {
                    return true;
                }
                e.path.to_string_lossy().to_lowercase().contains(&filter_lower)
            })
            .filter(|e| {
                if let Some(wanted) = importance_wanted {
                    classifier.classify(&e.path).importance == wanted
                } else {
                    true
                }
            })
            .collect();

        rows.sort_by(|a, b| {
            let ord = match self.sort_by {
                SortBy::Size => a.size.cmp(&b.size),
                SortBy::Name => {
                    let na = a.path.file_name().unwrap_or_default();
                    let nb = b.path.file_name().unwrap_or_default();
                    na.cmp(nb)
                }
                SortBy::Directory => {
                    let da = a.path.parent().unwrap_or(Path::new(""));
                    let db = b.path.parent().unwrap_or(Path::new(""));
                    da.cmp(db)
                }
                SortBy::Modified => a.modified.cmp(&b.modified),
                SortBy::Importance => {
                    let ia = classifier.classify(&a.path).importance as i32;
                    let ib = classifier.classify(&b.path).importance as i32;
                    ia.cmp(&ib)
                }
            };
            if self.sort_desc { ord.reverse() } else { ord }
        });
        rows
    }

    fn add_paths_to_plan(
        &mut self,
        classifier: &ImportanceClassifier,
        paths: &[PathBuf],
        sizes: &[u64],
        kind: ActionKind,
    ) -> usize {
        let mut added = 0;
        for (path, size) in paths.iter().zip(sizes.iter()) {
            let verdict = classifier.classify(path);
            if !verdict.importance.is_deletable() {
                continue;
            }
            self.plan.add(
                PlanAction::new(path.clone(), *size, kind, verdict)
                    .with_note("added from Tidy".to_string()),
            );
            added += 1;
        }
        added
    }

    fn commit_plan(&mut self, classifier: &ImportanceClassifier, allow_live: bool) {
        let confirmation = self.confirmation_input.trim().to_string();
        let mut exec = FsExecutor::dry();
        // Even if allow_live is true, we keep FsExecutor::dry() for
        // now: real deletion will be enabled in a subsequent release
        // after end-to-end UI review. This is intentional.
        let _ = allow_live;
        match self.plan.commit(&mut exec, classifier, &confirmation) {
            Ok(results) => {
                let ok = results.iter().filter(|r| r.success).count();
                self.last_commit_status = Some(format!(
                    "DRY-RUN: {}/{} actions would succeed",
                    ok,
                    results.len()
                ));
            }
            Err(e) => {
                self.last_commit_status = Some(format!("Commit refused: {}", e));
            }
        }
    }
}

pub fn show(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext, ctx: &egui::Context) {
    state.poll_scan();

    header(ui, state, cx, ctx);

    ui.horizontal(|ui| {
        for view in TidyView::ALL {
            let selected = state.view == view;
            if ui
                .selectable_label(selected, RichText::new(view.label()).size(14.0))
                .clicked()
            {
                state.view = view;
                if view == TidyView::Duplicates && state.dedup_report.is_none() {
                    state.run_dedup();
                }
            }
        }
    });
    ui.separator();

    match state.view {
        TidyView::AllFiles => table_view(ui, state, cx, None),
        TidyView::Duplicates => dedup_view(ui, state, cx),
        TidyView::Old => old_view(ui, state, cx),
        TidyView::Large => large_view(ui, state, cx),
        TidyView::Plan => plan_view(ui, state, cx),
    }

    ui.add_space(6.0);
    ui.separator();
    ui.label(RichText::new(&state.status).color(cx.palette.text_dim).small());
}

fn header(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext, ctx: &egui::Context) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Path:").color(cx.palette.text));
        let path_edit = ui.add(
            TextEdit::singleline(&mut state.scan_path)
                .hint_text("/home/user/Downloads")
                .desired_width(460.0),
        );
        let _ = path_edit;
        if ui.button("Pick…").clicked()
            && let Some(dir) = rfd::FileDialog::new().pick_folder()
        {
            state.scan_path = dir.to_string_lossy().into_owned();
        }
        let running = state.scan_in_flight.is_some();
        if ui
            .add_enabled(!running, egui::Button::new("Start scan"))
            .clicked()
        {
            state.start_scan(ctx);
        }
        if running {
            ui.spinner();
            ui.label(RichText::new("scanning…").color(cx.palette.text_dim));
        }
    });

    ui.horizontal_wrapped(|ui| {
        ui.checkbox(
            &mut state.scan_options.include_hidden,
            "Hidden files",
        );
        ui.checkbox(
            &mut state.scan_options.follow_symlinks,
            "Follow symlinks",
        );
        ui.checkbox(
            &mut state.scan_options.skip_mounts,
            "Stay on one filesystem",
        );
        let mut depth = state.scan_options.max_depth.unwrap_or(0) as i64;
        if ui
            .add(
                egui::DragValue::new(&mut depth)
                    .prefix("Max depth: ")
                    .range(0..=64),
            )
            .changed()
        {
            state.scan_options.max_depth = if depth == 0 { None } else { Some(depth as usize) };
        }
    });

    if let Some(scan) = &state.last_scan {
        ui.label(
            RichText::new(format!(
                "Scanned {} files · {} · {} errors · root: {}",
                scan.report.files_scanned,
                format_bytes(scan.report.total_bytes),
                scan.report.io_errors,
                scan.root.display()
            ))
            .color(cx.palette.text_dim)
            .small(),
        );
    }
}

fn filter_bar(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext) {
    ui.horizontal_wrapped(|ui| {
        ui.label("Filter:");
        ui.add(
            TextEdit::singleline(&mut state.filter_text)
                .hint_text("name or path…")
                .desired_width(260.0),
        );

        ui.separator();

        ui.label("Importance:");
        let label = match state.importance_filter {
            Some(i) => format!("{:?}", i),
            None => "any".into(),
        };
        egui::ComboBox::from_id_salt("importance-filter")
            .selected_text(label)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.importance_filter, None, "any");
                for imp in [
                    Importance::Trash,
                    Importance::Low,
                    Importance::Medium,
                    Importance::High,
                    Importance::Critical,
                ] {
                    ui.selectable_value(
                        &mut state.importance_filter,
                        Some(imp),
                        format!("{:?}", imp),
                    );
                }
            });

        ui.separator();

        if ui.button("Clear filters").clicked() {
            state.filter_text.clear();
            state.importance_filter = None;
            state.selected.clear();
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{} selected", state.selected.len()))
                    .color(cx.palette.text_dim),
            );
        });
    });
}

fn table_view(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext, note: Option<&str>) {
    if state.last_scan.is_none() {
        ui.add_space(8.0);
        ui.label(
            RichText::new("Pick a directory above and start a scan.")
                .color(cx.palette.text_dim),
        );
        return;
    }

    filter_bar(ui, state, cx);

    if let Some(n) = note {
        ui.label(RichText::new(n).color(cx.palette.text_dim).small());
    }

    let root = state.last_scan.as_ref().unwrap().root.clone();

    // Snapshot rows for this frame.
    let rows: Vec<FileEntry> = state
        .filtered_rows(cx.classifier)
        .into_iter()
        .cloned()
        .collect();

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "Showing {} of {} files · root: {}",
                format_count(rows.len() as u64),
                format_count(
                    state
                        .last_scan
                        .as_ref()
                        .map(|s| s.report.files_scanned)
                        .unwrap_or(0)
                ),
                root.display()
            ))
            .color(cx.palette.text_dim)
            .small(),
        );
    });

    ui.add_space(4.0);

    let max_size = rows.iter().map(|e| e.size).max().unwrap_or(1);

    // Selected paths to mutate during render.
    let mut toggle_select: Option<PathBuf> = None;
    let mut open_parent_of: Option<PathBuf> = None;
    let mut focus_row: Option<PathBuf> = None;
    let mut context_action: Option<(PathBuf, ContextAction)> = None;

    let available_height = ui.available_height().max(300.0) - 180.0;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(26.0))
        .column(Column::exact(78.0))
        .column(Column::initial(240.0).at_least(140.0).resizable(true))
        .column(Column::initial(240.0).at_least(140.0).resizable(true))
        .column(Column::exact(108.0))
        .column(Column::exact(140.0))
        .column(Column::remainder().at_least(120.0).resizable(true))
        .min_scrolled_height(available_height)
        .header(26.0, |mut header| {
            header.col(|ui| { let _ = ui.label(""); });
            header.col(|ui| {
                sort_header(ui, state, SortBy::Importance, "Importance");
            });
            header.col(|ui| {
                sort_header(ui, state, SortBy::Name, "Name");
            });
            header.col(|ui| {
                sort_header(ui, state, SortBy::Directory, "Directory");
            });
            header.col(|ui| {
                sort_header(ui, state, SortBy::Size, "Size");
            });
            header.col(|ui| {
                sort_header(ui, state, SortBy::Modified, "Modified");
            });
            header.col(|ui| {
                let _ = ui.label("");
            });
        })
        .body(|body| {
            let row_height = 26.0;
            body.rows(row_height, rows.len(), |mut row| {
                let i = row.index();
                let entry = &rows[i];
                let verdict = cx.classifier.classify(&entry.path);
                let is_selected = state.selected.contains(&entry.path);

                row.col(|ui| {
                    let mut checked = is_selected;
                    if ui.checkbox(&mut checked, "").changed() {
                        toggle_select = Some(entry.path.clone());
                    }
                });

                row.col(|ui| {
                    importance_badge(ui, cx.palette, verdict.importance);
                });

                row.col(|ui| {
                    let rel = relative_to_root(&entry.path, &root);
                    let (_, name) = split_dir_and_name(&rel);
                    let name_display = if name.is_empty() { rel.clone() } else { name };
                    let resp = ui.add(
                        egui::Label::new(
                            RichText::new(name_display)
                                .color(cx.palette.text)
                                .monospace(),
                        )
                        .sense(egui::Sense::click()),
                    );
                    if resp.clicked() {
                        focus_row = Some(entry.path.clone());
                    }
                    if resp.double_clicked() {
                        open_parent_of = Some(entry.path.clone());
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Open file").clicked() {
                            context_action = Some((entry.path.clone(), ContextAction::Open));
                            ui.close_menu();
                        }
                        if ui.button("Reveal in file manager").clicked() {
                            context_action = Some((entry.path.clone(), ContextAction::Reveal));
                            ui.close_menu();
                        }
                        if ui.button("Copy full path").clicked() {
                            context_action = Some((entry.path.clone(), ContextAction::CopyPath));
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Add to plan (as default)").clicked() {
                            context_action = Some((entry.path.clone(), ContextAction::AddToPlan));
                            ui.close_menu();
                        }
                        if ui.button("Protect this path").clicked() {
                            context_action = Some((entry.path.clone(), ContextAction::Protect));
                            ui.close_menu();
                        }
                    });
                });

                row.col(|ui| {
                    let rel = relative_to_root(&entry.path, &root);
                    let (dir, _) = split_dir_and_name(&rel);
                    ui.label(
                        RichText::new(dir).color(cx.palette.text_dim).small(),
                    );
                });

                row.col(|ui| {
                    ui.label(
                        RichText::new(format_bytes(entry.size))
                            .color(cx.palette.text)
                            .monospace(),
                    );
                });

                row.col(|ui| {
                    ui.label(
                        RichText::new(format_mtime(entry.modified))
                            .color(cx.palette.text_dim)
                            .monospace()
                            .small(),
                    );
                });

                row.col(|ui| {
                    let color = match verdict.importance {
                        Importance::Critical => cx.palette.tier_critical,
                        Importance::High => cx.palette.tier_high,
                        Importance::Medium => cx.palette.tier_medium,
                        Importance::Low => cx.palette.tier_low,
                        Importance::Trash => cx.palette.tier_trash,
                    };
                    size_bar(ui, entry.size, max_size, color);
                });
            });
        });

    // Apply deferred mutations.
    if let Some(path) = toggle_select {
        if state.selected.contains(&path) {
            state.selected.remove(&path);
        } else {
            state.selected.insert(path.clone());
            state.focus_path = Some(path);
        }
    }
    if let Some(path) = focus_row {
        state.focus_path = Some(path);
    }
    if let Some(path) = open_parent_of
        && let Err(e) = file_manager::reveal_parent(&path)
    {
        state.status = format!("Open failed: {}", e);
    }
    if let Some((path, action)) = context_action {
        handle_context_action(state, cx, &path, action);
    }

    ui.add_space(8.0);
    action_bar(ui, state, cx, &rows);
}

#[derive(Debug, Clone, Copy)]
enum ContextAction {
    Open,
    Reveal,
    CopyPath,
    AddToPlan,
    Protect,
}

fn handle_context_action(
    state: &mut TidyState,
    cx: &TidyContext,
    path: &Path,
    action: ContextAction,
) {
    match action {
        ContextAction::Open => {
            if let Err(e) = file_manager::open_file(path) {
                state.status = format!("Open failed: {}", e);
            }
        }
        ContextAction::Reveal => {
            if let Err(e) = file_manager::reveal_parent(path) {
                state.status = format!("Reveal failed: {}", e);
            }
        }
        ContextAction::CopyPath => {
            if let Err(e) = file_manager::copy_to_clipboard(&path.to_string_lossy()) {
                state.status = format!("Copy failed: {}", e);
            } else {
                state.status = format!("Copied path: {}", path.display());
            }
        }
        ContextAction::AddToPlan => {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let added = state.add_paths_to_plan(
                cx.classifier,
                &[path.to_path_buf()],
                &[size],
                state.default_action_kind,
            );
            state.status = if added > 0 {
                format!("Added 1 item to plan")
            } else {
                format!(
                    "Skipped — path is classified {:?} and refused",
                    cx.classifier.classify(path).importance
                )
            };
        }
        ContextAction::Protect => {
            state.status = format!(
                "Tip: add {} to protected paths in Settings to make this permanent.",
                path.display()
            );
        }
    }
}

fn sort_header(ui: &mut Ui, state: &mut TidyState, column: SortBy, label: &str) {
    let active = state.sort_by == column;
    let arrow = if active {
        if state.sort_desc { " ↓" } else { " ↑" }
    } else {
        ""
    };
    let text = format!("{}{}", label, arrow);
    let resp = ui.add(
        egui::Label::new(RichText::new(text).strong())
            .sense(egui::Sense::click()),
    );
    if resp.clicked() {
        if active {
            state.sort_desc = !state.sort_desc;
        } else {
            state.sort_by = column;
            state.sort_desc = true;
        }
    }
}

fn action_bar(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext, rows: &[FileEntry]) {
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("default-action-kind")
            .selected_text(state.default_action_kind.description())
            .show_ui(ui, |ui| {
                for kind in [
                    ActionKind::Review,
                    ActionKind::MoveToTrash,
                    ActionKind::SimpleDelete,
                    ActionKind::SecurePurge,
                ] {
                    ui.selectable_value(
                        &mut state.default_action_kind,
                        kind,
                        kind.description(),
                    );
                }
            });

        if ui.button("Add selected to plan").clicked() {
            let paths: Vec<PathBuf> = state.selected.iter().cloned().collect();
            let sizes: Vec<u64> = paths
                .iter()
                .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
                .collect();
            let added = state.add_paths_to_plan(
                cx.classifier,
                &paths,
                &sizes,
                state.default_action_kind,
            );
            state.status = format!("Added {} / {} selected to plan", added, paths.len());
        }

        if ui.button("Add all deletable on this view").clicked() {
            let paths: Vec<PathBuf> = rows.iter().map(|e| e.path.clone()).collect();
            let sizes: Vec<u64> = rows.iter().map(|e| e.size).collect();
            let added = state.add_paths_to_plan(
                cx.classifier,
                &paths,
                &sizes,
                state.default_action_kind,
            );
            state.status = format!("Added {} deletable items to plan", added);
        }

        if ui.button("Deselect all").clicked() {
            state.selected.clear();
        }
    });
}

fn dedup_view(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext) {
    if state.last_scan.is_none() {
        ui.label(RichText::new("Scan a directory first.").color(cx.palette.text_dim));
        return;
    }

    ui.horizontal(|ui| {
        ui.label("Minimum duplicate size:");
        let mut v = state.dedup_min_size as i64;
        let changed = ui
            .add(
                egui::DragValue::new(&mut v)
                    .suffix(" bytes")
                    .speed(256.0)
                    .range(1..=i64::MAX),
            )
            .changed();
        if changed {
            state.dedup_min_size = v.max(1) as u64;
        }
        if ui.button("Re-scan for duplicates").clicked() {
            state.run_dedup();
        }
    });

    if state.dedup_report.is_none() {
        state.run_dedup();
    }

    ui.add_space(6.0);

    if let Some(report) = state.dedup_report.clone() {
        ui.label(
            RichText::new(format!(
                "{} duplicate group(s) · {} files · {} reclaimable",
                report.groups_found,
                report.files_in_groups,
                format_bytes(report.total_wasted_bytes)
            ))
            .color(cx.palette.text),
        );
        ui.add_space(4.0);
        table_view(
            ui,
            state,
            cx,
            Some("Rows below are files that appear in at least one duplicate group."),
        );
    }
}

fn old_view(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext) {
    if state.last_scan.is_none() {
        ui.label(RichText::new("Scan a directory first.").color(cx.palette.text_dim));
        return;
    }
    ui.horizontal_wrapped(|ui| {
        duration_input(
            ui,
            "Untouched for at least",
            &mut state.age_threshold,
            "tidy-age",
        );
        ui.label(
            RichText::new(format!("(= {} days)", state.age_threshold.to_days()))
                .color(cx.palette.text_dim)
                .small(),
        );
    });
    if let Some(scan) = &state.last_scan {
        let report = AgeAnalyzer::new(state.age_threshold.to_days()).analyze(&scan.entries);
        ui.label(
            RichText::new(format!(
                "{} files match · {} reclaimable",
                report.matched,
                format_bytes(report.total_bytes)
            ))
            .color(cx.palette.text),
        );
    }
    table_view(ui, state, cx, Some("Sorted by size; change the age threshold to refilter."));
}

fn large_view(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext) {
    if state.last_scan.is_none() {
        ui.label(RichText::new("Scan a directory first.").color(cx.palette.text_dim));
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.label("Minimum size:");
        let mut v = state.min_size_filter_bytes as i64;
        if ui
            .add(
                egui::DragValue::new(&mut v)
                    .suffix(" bytes")
                    .speed(1024.0)
                    .range(0..=i64::MAX),
            )
            .changed()
        {
            state.min_size_filter_bytes = v.max(0) as u64;
        }
        ui.label(
            RichText::new(format!("(= {})", format_bytes(state.min_size_filter_bytes)))
                .color(cx.palette.text_dim),
        );
    });
    table_view(ui, state, cx, None);
}

fn plan_view(ui: &mut Ui, state: &mut TidyState, cx: &TidyContext) {
    ui.label(
        RichText::new("Review plan")
            .color(cx.palette.text)
            .size(18.0)
            .strong(),
    );
    ui.label(
        RichText::new(
            "Nothing runs until you approve the items you want and type the confirmation token. The dry-run lock in Settings still applies.",
        )
        .color(cx.palette.text_dim),
    );
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button("Approve all").clicked() {
            state.plan.approve_all();
        }
        if ui.button("Unapprove all").clicked() {
            state.plan.unapprove_all();
        }
        if ui.button("Clear plan").clicked() {
            state.plan = CleanupPlan::new("Atrium session");
            state.confirmation_input.clear();
            state.last_commit_status = None;
        }
    });

    ui.add_space(6.0);

    ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
        let mut to_remove: Option<usize> = None;
        let mut approve_changes: Vec<(usize, bool)> = Vec::new();
        let mut kind_changes: Vec<(usize, ActionKind)> = Vec::new();
        for (i, action) in state.plan.actions.iter().enumerate() {
            ui.horizontal(|ui| {
                let mut approved = action.approved;
                if ui.checkbox(&mut approved, "").changed() {
                    approve_changes.push((i, approved));
                }
                importance_badge(ui, cx.palette, action.verdict.importance);
                let mut chosen = action.kind;
                egui::ComboBox::from_id_salt(format!("plan-kind-{}", i))
                    .selected_text(chosen.description())
                    .show_ui(ui, |ui| {
                        for k in [
                            ActionKind::Review,
                            ActionKind::MoveToTrash,
                            ActionKind::SimpleDelete,
                            ActionKind::SecurePurge,
                        ] {
                            if ui
                                .selectable_value(&mut chosen, k, k.description())
                                .changed()
                            {
                                kind_changes.push((i, k));
                            }
                        }
                    });
                ui.label(
                    RichText::new(format_bytes(action.size)).color(cx.palette.text_dim),
                );
                ui.label(action.path.to_string_lossy().into_owned());
                if ui.small_button("✕").clicked() {
                    to_remove = Some(i);
                }
            });
        }
        for (i, approved) in approve_changes {
            if approved {
                state.plan.approve_index(i);
            } else {
                state.plan.unapprove_index(i);
            }
        }
        for (i, k) in kind_changes {
            if let Some(a) = state.plan.actions.get_mut(i) {
                a.kind = k;
            }
        }
        if let Some(i) = to_remove {
            state.plan.remove_at(i);
        }
    });

    ui.add_space(6.0);
    ui.separator();

    let digest = state.plan.confirmation_digest();
    ui.label(
        RichText::new(format!(
            "Token: {}   ({} approved · {} to reclaim)",
            digest,
            state.plan.approved_count(),
            format_bytes(state.plan.total_bytes_approved())
        ))
        .color(cx.palette.text),
    );
    ui.horizontal(|ui| {
        ui.label("Type the token:");
        ui.add(TextEdit::singleline(&mut state.confirmation_input).desired_width(180.0));
        let matches = state.confirmation_input.trim() == digest;
        let live = !cx.config.dry_run_locked;
        let label = if live { "Commit (LIVE)" } else { "Commit (dry-run)" };
        let color = if live { cx.palette.critical } else { cx.palette.accent };
        if ui
            .add_enabled(
                matches && state.plan.approved_count() > 0,
                egui::Button::new(RichText::new(label).color(color)),
            )
            .clicked()
        {
            state.commit_plan(cx.classifier, live);
        }
    });
    if let Some(msg) = &state.last_commit_status {
        ui.label(RichText::new(msg).color(cx.palette.text));
    }
}

// ---- Helper: the for<'a> trick to satisfy filtered_rows lifetime ----
impl<'b> TidyState {
    #[allow(dead_code)]
    fn _unused(&'b self) {}
}

fn format_mtime(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let delta = now - dt;
    let days = delta.num_days();
    if days < 1 {
        dt.format("%H:%M").to_string()
    } else if days < 365 {
        dt.format("%b %d").to_string()
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}
