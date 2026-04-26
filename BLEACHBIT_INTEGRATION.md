# Atrium = BleachBit fork + DynamicCleaner extension

**Decision date:** 2026-04-26.

The current Atrium UI is being replaced by a **fork of BleachBit**
(GTK 3, Python, GPL-3.0+). BleachBit's UI + backend are both reused.
Atrium's added value: the `DynamicCleaner` class that consumes
JSON-based cleaner definitions emitted by sibling repos.

## Schema

[`PlausiDen-Meta/DYNAMIC_CLEANER_SCHEMA.md`](https://github.com/thepictishbeast/PlausiDen-Meta/blob/main/DYNAMIC_CLEANER_SCHEMA.md)
is the canonical contract. Atrium's `DynamicCleaner` parses it; Tidy
and AppGuard emit it.

## What Atrium adds to BleachBit

1. **`bleachbit/DynamicCleaner.py`** — a `Cleaner` subclass loaded by
   walking `/var/lib/atrium/dynamic-cleaners/*.json` (system) and
   `~/.local/share/atrium/dynamic-cleaners/*.json` (per-user).
2. **Inotify watcher** — refreshes the dynamic cleaners on file change.
3. **Two reserved tree-view categories**: `"PlausiDen Tidy"` and
   `"PlausiDen AppGuard"`.
4. **Disk-pressure trigger** — systemd path/timer unit that launches
   Atrium's GUI (or its CLI mode) when any volume crosses 80% used.
5. **Atrium chrome** — title bar, about dialog, theme.

## What Atrium does NOT change about BleachBit

- The 200+ stock cleaners stay verbatim.
- The action types (`delete`, `truncate`, `shred`, `wipe-free-space`)
  reuse BleachBit's existing implementations.
- The dry-run + preview flow is unchanged.
- Localization / i18n inheritance.

## License

BleachBit is GPL-3.0+. Atrium is therefore GPL-3.0+. Other PlausiDen
repos remain on their existing licenses (MIT/Apache); GPL doesn't
propagate beyond the linked unit.

## Implementation phases

1. Vendor BleachBit source as `vendor/bleachbit/` (specific commit pinned).
2. Add `DynamicCleaner` + tests against the schema.
3. Add inotify watcher + reserved categories.
4. Add disk-pressure trigger.
5. Rebrand chrome.
6. CI: build the GTK app + run BleachBit's existing test suite + new dynamic-cleaner tests on the self-hosted runner.

## Status

Planning. UI work is unfrozen with this decision (the previous "no UI
work" rule applied to the prior bespoke Atrium UI; that's being thrown
out and replaced by BleachBit's UI).
