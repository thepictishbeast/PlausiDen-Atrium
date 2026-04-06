//! Static how-to content rendered on the Docs tab.
//!
//! The docs live in code so they are always in sync with the binary
//! the user is actually running. Each section is a title + body pair.

pub struct Section {
    pub title: &'static str,
    pub body: &'static str,
}

pub const SECTIONS: &[Section] = &[
    Section {
        title: "Welcome",
        body: "\
PlausiDen-Atrium is the unified front door to the PlausiDen civil rights \
toolkit. It hosts two tools side by side:

  • Tidy — the everyday cleaner. Finds duplicates, old files, large files, \
    and lets you review everything before any change is committed.

  • Purge — the antiforensic engine. For the rare case when you need \
    forensic-grade destruction (not just deletion).

The safety model is simple: nothing on your disk changes until you \
explicitly review a plan, approve the items one by one, type a \
confirmation token, and release the dry-run lock in Settings."
    },
    Section {
        title: "How a cleanup flows",
        body: "\
1. Pick a directory on the Tidy page and start a scan. The scanner \
   reads file metadata — size, timestamps, inode — never the contents.

2. The scan fills a virtualized table sorted by size (largest first). \
   Every row is clickable: single click to select, double click to \
   open the folder in your file manager, right-click for a context menu.

3. Use the Age and Size filters to narrow the view. Changing the \
   threshold immediately re-runs the analysis — no Analyze button.

4. Add items to the cleanup plan with the + column or the context \
   menu. Each plan entry lets you pick the action kind per item: \
   Review (no-op), Move to Trash, Simple Delete, or Secure Purge \
   (delegates to PlausiDen-Purge).

5. Review the plan. The Commit button is disabled until (a) at least \
   one item is approved AND (b) you type the confirmation token that \
   matches the plan digest.

6. Commit is a dry run while the safety lock is on. Releasing the \
   lock in Settings lets destructive actions actually run."
    },
    Section {
        title: "Importance classifier",
        body: "\
Every file gets a colour-coded importance tier. The classifier refuses \
to add Critical and High items to the plan even when you bulk-add.

  • CRITICAL — SSH/GPG keys, source trees, package manifests, the \
    Git/Mercurial/Jujutsu metadata directories, user-supplied \
    protected paths.

  • HIGH — browser profile core files (places.sqlite, cookies.sqlite, \
    key databases).

  • MEDIUM — ordinary user data. Allowed into the plan, but each item \
    requires explicit approval.

  • LOW — caches, downloads, temporary directories. First-class \
    cleanup candidates.

  • TRASH — editor backups, core dumps, trash-bin entries. Most \
    permissive tier.

You can add your own paths to the protected list in Settings. Protected \
paths are refused at plan-build time AND re-checked at commit time."
    },
    Section {
        title: "Tidy vs Purge — when to use which",
        body: "\
  • Tidy's delete actions: Move to Trash (reversible), Simple Delete \
    (unlink, fast). Use these for everyday cleanup when you just want \
    to reclaim space and trust the filesystem/trash bin.

  • Purge's destruction actions: forensic_wipe (multi-pass overwrite), \
    crypto_shred (single-pass encryption of the file with an ephemeral \
    key that is destroyed the instant the write completes). Use these \
    only when the threat model actually calls for forensic resistance.

On VPS / SSD / copy-on-write filesystems, traditional multi-pass \
overwrite is not meaningful (wear-leveling, snapshots, thin \
provisioning break the assumption). Use crypto_shred instead on those \
targets. Atrium shows an environment banner that warns you when this \
applies."
    },
    Section {
        title: "Keyboard shortcuts",
        body: "\
  Ctrl+1 … Ctrl+6  Jump to page (Home, Tidy, Disk, Purge, Docs, Settings)
  Ctrl+O           Open directory picker on the Tidy page
  Ctrl+F           Focus the filter input
  Ctrl+A           Select all rows in the current filter
  Space            Toggle plan membership for the selected row(s)
  Enter            Open the selected file in the default handler
  Shift+Enter      Reveal the selected file in the file manager
  Delete           Remove selected plan items"
    },
    Section {
        title: "Running as root",
        body: "\
Some targets (system caches, /var/log, root-owned files) need root \
privileges. Atrium is designed to work when launched as root.

The easiest reliable recipe:

  sudo -E atrium

`-E` preserves your DISPLAY and XAUTHORITY variables so the GUI can \
connect to your existing desktop session. If that does not work, allow \
root to talk to your X server once:

  xhost +si:localuser:root
  sudo atrium

On Wayland, export the WAYLAND_DISPLAY variable or use `run0` (systemd \
256+) which sets it for you automatically."
    },
    Section {
        title: "Privacy",
        body: "\
Atrium does not send anything off the device. No telemetry, no crash \
reports, no remote hashes. The scanner reads metadata only. Duplicate \
detection computes BLAKE3 hashes locally; the hashes never leave the \
machine. Nothing in this toolkit phones home."
    },
];
