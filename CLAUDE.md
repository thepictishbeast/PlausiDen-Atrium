## Project: plausiden-atrium

Unified egui desktop frontend for the PlausiDen suite. Hosts Tidy, Purge, and disk analyzers.

## Architecture

- Pulls in `plausiden-tidy` as a path dependency. Future: `plausiden-purge` as well once its public API settles.
- Single binary `atrium`. Runs on X11 and Wayland via glow backend.
- Multi-page shell with sidebar navigation. Each page lives in `src/pages/`.
- Shared widgets in `src/widgets/` — duration input, byte formatter, importance badge, path cell.

## Safety-critical rules

- **Metadata-only scans.** Never read file contents for display. Hashes for dedup are computed locally and never surfaced as raw bytes.
- **Dry-run lock ON by default.** Every commit routes through `FsExecutor::dry()` unless the user explicitly releases the lock in Settings.
- **Per-item approval.** No "delete all" without a confirmation token that matches the plan's digest.
- **Relative paths in scan result lists.** Never repeat the scan root on every row. See `feedback_relative_path_display.md`.
- **No automatic destructive actions in tests.** Tests may use synthetic temp dirs only.

## UI rules

- Dark / light / automatic theme, persisted to `~/.config/plausiden/atrium.json`.
- Typed duration input (amount + unit) for age thresholds, not raw sliders.
- Auto-update analysis when inputs change — no explicit Analyze button required.
- Docs tab is not optional. Every new feature needs a docs entry.
- Runs as root with friendly error if DISPLAY/XAUTHORITY is missing.

## Code standards

Rust 2024, thiserror, serde. 8-12 tests per non-trivial module. No unwrap in library code (main.rs may unwrap on startup env vars only after a friendly message).
