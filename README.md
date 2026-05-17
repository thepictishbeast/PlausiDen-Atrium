> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# PlausiDen-Atrium

Unified desktop frontend for the [PlausiDen](https://github.com/thepictishbeast) civil rights toolkit. Atrium is the entry hall — the friendly, approachable front door to Tidy (everyday cleanup), Purge (antiforensic destruction), and the disk analyzers. One window, all the tools.

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
