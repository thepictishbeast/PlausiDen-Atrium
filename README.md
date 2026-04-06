# PlausiDen-Atrium

Unified desktop frontend for the [PlausiDen](https://github.com/redcaptian1917) civil rights toolkit. Atrium is the entry hall — the friendly, approachable front door to Tidy (everyday cleanup), Purge (antiforensic destruction), and the disk analyzers. One window, all the tools.

## Design principles

- **Approachable, not tactical.** PlausiDen is a civil rights tool. Atrium looks like a well-crafted consumer application, not a hacker console. Dark / light / automatic theme. Clear visual hierarchy. Per-item controls instead of bulk destructive buttons.
- **Safety is the default.** Dry-run lock is on by default. Every destructive action requires per-item approval *and* a plan-level confirmation token *and* an explicit unlock.
- **Relative paths in scans.** Never repeat the scan root on every row — the root is shown once, each row shows the relative subpath.
- **Typed durations.** Age thresholds are entered as an amount + unit (minutes, hours, days, weeks, months, years), not a raw day slider.
- **Auto-update analysis.** Changing a parameter re-runs the analyzer immediately — no separate "Analyze" button needed.
- **Backend ↔ UI parity.** Every Tidy capability and every Purge capability is reachable from the GUI. If it exists in the library, it has a UI affordance.
- **Runs as root.** Atrium makes the DISPLAY/XAUTHORITY handshake friendly when launched via sudo, and gives clear guidance if the environment is misconfigured.

## Structure

- **Home** — landing dashboard with environment summary
- **Tidy** — scan, duplicates, old files, large files, plan review
- **Purge** — antiforensic destruction (delegated from Tidy or invoked directly)
- **Disk** — disk usage visualization (treemap + per-dir breakdown)
- **Docs** — how-to guides, safety explanations, keyboard shortcuts
- **Settings** — theme, protected paths, defaults, installed tool versions

## Building

```bash
cargo build --release
./target/release/atrium
```

To run as root with display access:

```bash
sudo -E atrium   # preserves DISPLAY and XAUTHORITY
# or one-time setup:
xhost +si:localuser:root
sudo atrium
```

## License

AGPL-3.0-or-later.
