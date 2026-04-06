#![allow(dead_code)]
//! Forensic recovery verification — automate the well-known FOSS tools.
//!
//! After Purge destroys a file, Atrium can run one of the standard
//! DFIR recovery tools against the parent filesystem and count how
//! many files (if any) come back. If the recovery yield is non-zero,
//! Atrium re-runs the wipe on the recovered artefacts or on the free
//! space around them and repeats up to `max_iterations` times. This
//! is the "wipe-verify-rewipe" loop the user asked for.
//!
//! Tools supported (in preference order):
//!
//! 1. **photorec** (part of testdisk) — signature-based carving, very
//!    well regarded in DFIR, batch-friendly via `/log` and `/cmd`.
//! 2. **foremost** — header/footer carving, simple to drive.
//! 3. **scalpel** — a faster foremost fork.
//! 4. **extundelete** — ext3/ext4 journal recovery (not signature-based).
//! 5. **testdisk** — partition/boot sector recovery.
//! 6. **bulk_extractor** — regex-based artifact extraction.
//!
//! All tools require root privileges to scan raw devices. Atrium
//! detects which ones are installed and presents them as options.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Maximum recursion depth when counting recovered files. Forensic
/// tools never produce legitimate output trees deeper than a few
/// levels; anything beyond this is either pathological or a symlink
/// trap and must be cut off before it exhausts the stack / CPU.
const MAX_RECOVERY_DEPTH: usize = 32;

/// Forensic recovery tool that may be installed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForensicTool {
    PhotoRec,
    Foremost,
    Scalpel,
    ExtUndelete,
    TestDisk,
    BulkExtractor,
}

impl ForensicTool {
    pub const ALL: &'static [ForensicTool] = &[
        ForensicTool::PhotoRec,
        ForensicTool::Foremost,
        ForensicTool::Scalpel,
        ForensicTool::ExtUndelete,
        ForensicTool::TestDisk,
        ForensicTool::BulkExtractor,
    ];

    pub fn binary(&self) -> &'static str {
        match self {
            ForensicTool::PhotoRec => "photorec",
            ForensicTool::Foremost => "foremost",
            ForensicTool::Scalpel => "scalpel",
            ForensicTool::ExtUndelete => "extundelete",
            ForensicTool::TestDisk => "testdisk",
            ForensicTool::BulkExtractor => "bulk_extractor",
        }
    }

    pub fn package_hint(&self) -> &'static str {
        match self {
            ForensicTool::PhotoRec => "testdisk",
            ForensicTool::Foremost => "foremost",
            ForensicTool::Scalpel => "scalpel",
            ForensicTool::ExtUndelete => "extundelete",
            ForensicTool::TestDisk => "testdisk",
            ForensicTool::BulkExtractor => "bulk-extractor",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ForensicTool::PhotoRec => {
                "Signature-based file carving. Part of testdisk. Industry standard."
            }
            ForensicTool::Foremost => "Header/footer carving, originally by the US Air Force OSI.",
            ForensicTool::Scalpel => "Faster fork of foremost with a simpler config.",
            ForensicTool::ExtUndelete => "Journal-based recovery for ext3/ext4.",
            ForensicTool::TestDisk => "Partition table and boot sector recovery.",
            ForensicTool::BulkExtractor => {
                "Regex and feature extraction — pulls emails, URLs, credit cards, keys."
            }
        }
    }
}

/// Report on which forensic tools are available on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInventory {
    pub available: Vec<ForensicTool>,
    pub missing: Vec<ForensicTool>,
}

impl ToolInventory {
    pub fn is_any_available(&self) -> bool {
        !self.available.is_empty()
    }

    pub fn preferred(&self) -> Option<ForensicTool> {
        self.available.first().copied()
    }
}

/// Probe the system for installed forensic tools.
pub fn detect_tools() -> ToolInventory {
    let mut available = Vec::new();
    let mut missing = Vec::new();
    for tool in ForensicTool::ALL {
        if which(tool.binary()).is_some() {
            available.push(*tool);
        } else {
            missing.push(*tool);
        }
    }
    ToolInventory { available, missing }
}

fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Report of a single verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub tool: ForensicTool,
    pub target: PathBuf,
    pub files_recovered: usize,
    pub output_dir: PathBuf,
    pub raw_output: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Canonicalize a user-supplied forensic target so it cannot be
/// mistaken for a command-line flag.
///
/// BUG ASSUMPTION: the forensic CLIs we shell out to (photorec,
/// foremost, scalpel, …) all parse positional arguments through
/// getopt-style loops. A target like `-L` or `--version` looks
/// exactly like a flag to them and *will* be interpreted as such,
/// even though the caller intended it as a path. Canonicalizing
/// forces the path to be absolute (and therefore to start with `/`),
/// which sidesteps the ambiguity entirely.
///
/// Returns Err with a user-readable message if the path does not
/// exist, cannot be canonicalized, or (after canonicalization) still
/// somehow begins with `-` — any of which indicates we should refuse
/// to run the tool rather than pass a dangerous argument.
fn canonicalize_target(target: &Path) -> std::result::Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(target).map_err(|e| {
        format!(
            "target {} is not a canonicalizable path: {}",
            target.display(),
            e
        )
    })?;
    // Defence-in-depth: even after canonicalize, refuse anything that
    // could still be parsed as an option. On Unix all canonical paths
    // begin with `/`, so this is effectively unreachable — but it
    // costs nothing and keeps the safety invariant visible at the
    // call site.
    if let Some(first) = canonical.as_os_str().to_string_lossy().chars().next()
        && first == '-'
    {
        return Err(format!(
            "refusing suspicious target {}: looks like a CLI flag",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Run a verification pass against a filesystem or file. `target`
/// should usually be the block device (e.g. `/dev/sda1`) or a file
/// (e.g. a specific disk image).
pub fn run_verification(
    tool: ForensicTool,
    target: &Path,
    output_dir: &Path,
) -> VerificationReport {
    if which(tool.binary()).is_none() {
        return VerificationReport {
            tool,
            target: target.to_path_buf(),
            files_recovered: 0,
            output_dir: output_dir.to_path_buf(),
            raw_output: String::new(),
            success: false,
            error: Some(format!(
                "{} not installed (hint: apt install {})",
                tool.binary(),
                tool.package_hint()
            )),
        };
    }

    // Canonicalize the target BEFORE shelling out. See
    // `canonicalize_target` for the rationale — in short: a dash-
    // prefixed path would be parsed as a CLI flag by the downstream
    // tool and could turn a verify run into an arbitrary command.
    let canonical_target = match canonicalize_target(target) {
        Ok(p) => p,
        Err(e) => {
            return VerificationReport {
                tool,
                target: target.to_path_buf(),
                files_recovered: 0,
                output_dir: output_dir.to_path_buf(),
                raw_output: String::new(),
                success: false,
                error: Some(e),
            };
        }
    };

    if let Err(e) = std::fs::create_dir_all(output_dir) {
        return VerificationReport {
            tool,
            target: canonical_target.clone(),
            files_recovered: 0,
            output_dir: output_dir.to_path_buf(),
            raw_output: String::new(),
            success: false,
            error: Some(format!("could not create output dir: {}", e)),
        };
    }

    let output = match tool {
        ForensicTool::PhotoRec => Command::new("photorec")
            .arg("/log")
            .arg("/d")
            .arg(output_dir)
            .arg(&canonical_target)
            .arg("/cmd")
            .arg("options,paranoid,freespace,search")
            .output(),
        ForensicTool::Foremost => Command::new("foremost")
            .arg("-q")
            .arg("-t")
            .arg("all")
            .arg("-o")
            .arg(output_dir)
            .arg("-i")
            .arg(&canonical_target)
            .output(),
        ForensicTool::Scalpel => Command::new("scalpel")
            .arg("-o")
            .arg(output_dir)
            .arg(&canonical_target)
            .output(),
        ForensicTool::ExtUndelete => Command::new("extundelete")
            .arg("--restore-all")
            .arg("--output-dir")
            .arg(output_dir)
            .arg(&canonical_target)
            .output(),
        ForensicTool::TestDisk => {
            // testdisk is fully interactive; best-effort invoke with /log.
            Command::new("testdisk")
                .arg("/log")
                .arg(&canonical_target)
                .output()
        }
        ForensicTool::BulkExtractor => Command::new("bulk_extractor")
            .arg("-o")
            .arg(output_dir)
            .arg(&canonical_target)
            .output(),
    };

    let (raw_output, success, error) = match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let combined = format!("{}\n{}", stdout, stderr);
            (combined, out.status.success(), None)
        }
        Err(e) => (String::new(), false, Some(e.to_string())),
    };

    let files_recovered = count_recovered_files(output_dir);

    VerificationReport {
        tool,
        target: canonical_target,
        files_recovered,
        output_dir: output_dir.to_path_buf(),
        raw_output,
        success,
        error,
    }
}

/// Recursively count how many files a recovery tool dropped under
/// `output_dir`.
///
/// BUG ASSUMPTION: recovery tools can (and in the case of photorec's
/// carved-file mode actually do) produce symlinks. A naive recursive
/// walker that follows them will happily chase a cycle for ever. We
/// therefore:
///   1. Use `symlink_metadata` so we classify the entry itself, not
///      its target.
///   2. Never descend into symlinks.
///   3. Track visited canonical directory paths and refuse to re-
///      enter one we have already walked.
///   4. Cap the depth at `MAX_RECOVERY_DEPTH`, well above what any
///      real recovery tool produces.
pub fn count_recovered_files(output_dir: &Path) -> usize {
    let mut count = 0;
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let start = match std::fs::canonicalize(output_dir) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    visited.insert(start.clone());

    let mut stack: Vec<(PathBuf, usize)> = vec![(start, 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth >= MAX_RECOVERY_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // symlink_metadata does NOT follow symlinks — if the
            // entry is itself a symlink we classify it as such and
            // skip it, so a cycle or dangling link can never trap
            // the walker.
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if md.file_type().is_symlink() {
                continue;
            }
            if md.is_dir() {
                if let Ok(canon) = std::fs::canonicalize(&path)
                    && visited.insert(canon.clone())
                {
                    stack.push((canon, depth + 1));
                }
            } else if md.is_file() {
                count += 1;
            }
        }
    }
    count
}

/// Guidance text that the UI can show when no tools are installed.
pub const INSTALL_HINT: &str = "\
Install one or more forensic recovery tools to enable verification:

  Debian / Kali / Ubuntu:
    sudo apt install testdisk foremost scalpel extundelete bulk-extractor

  Arch:
    sudo pacman -S testdisk foremost scalpel extundelete bulk-extractor

  Fedora:
    sudo dnf install testdisk foremost scalpel extundelete bulk_extractor

These are standard DFIR tools and are safe to install on the laptop.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tools_have_binary_names() {
        for tool in ForensicTool::ALL {
            assert!(!tool.binary().is_empty());
            assert!(!tool.package_hint().is_empty());
            assert!(!tool.description().is_empty());
        }
    }

    #[test]
    fn test_detect_tools_runs() {
        let inv = detect_tools();
        assert_eq!(
            inv.available.len() + inv.missing.len(),
            ForensicTool::ALL.len()
        );
    }

    #[test]
    fn test_count_recovered_files_empty() {
        let dir = std::env::temp_dir().join(format!("atrium-count-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(count_recovered_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_count_recovered_files_nonempty() {
        let dir = std::env::temp_dir().join(format!("atrium-count-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"x").unwrap();
        std::fs::write(dir.join("b"), b"y").unwrap();
        assert_eq!(count_recovered_files(&dir), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_install_hint_nonempty() {
        assert!(INSTALL_HINT.contains("apt install"));
        assert!(INSTALL_HINT.contains("pacman"));
        assert!(INSTALL_HINT.contains("dnf"));
    }

    #[test]
    fn test_preferred_returns_first_available() {
        let inv = ToolInventory {
            available: vec![ForensicTool::Foremost, ForensicTool::PhotoRec],
            missing: vec![],
        };
        assert_eq!(inv.preferred(), Some(ForensicTool::Foremost));
    }

    #[test]
    fn test_which_finds_ls() {
        assert!(which("ls").is_some());
    }

    #[test]
    fn test_which_misses_garbage() {
        assert!(which("definitely-not-a-real-binary-xyz-12345").is_none());
    }

    #[test]
    fn test_canonicalize_target_accepts_real_file() {
        let dir = std::env::temp_dir().join(format!("atrium-canon-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("t.bin");
        std::fs::write(&file, b"x").unwrap();
        let canon = canonicalize_target(&file).expect("should canonicalize");
        assert!(canon.is_absolute());
        assert!(!canon.as_os_str().to_string_lossy().starts_with('-'));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_canonicalize_target_refuses_nonexistent() {
        // An attacker-controlled textbox value that happens to look
        // like a CLI flag. Canonicalize fails → we refuse to run.
        let target = PathBuf::from("-L");
        let err = canonicalize_target(&target)
            .expect_err("flag-shaped path must be rejected");
        assert!(err.contains("not a canonicalizable path") || err.contains("suspicious"));
    }

    #[test]
    fn test_run_verification_refuses_flag_shaped_target() {
        // End-to-end: even if the binary is somehow present, a flag-
        // shaped target must produce an error *before* the tool is
        // invoked.
        let out = std::env::temp_dir().join(format!("atrium-flag-{}", std::process::id()));
        let report = run_verification(ForensicTool::Foremost, &PathBuf::from("-L"), &out);
        assert!(!report.success);
        assert!(report.error.is_some());
    }

    #[test]
    #[cfg(unix)]
    fn test_count_recovered_files_survives_symlink_cycle() {
        // A symlink cycle inside the recovered-files tree must NOT
        // hang the walker. Regression guard for the old
        // `path.is_dir()` implementation which followed symlinks and
        // infinite-looped on the cycle.
        let dir = std::env::temp_dir().join(format!("atrium-cycle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("real.txt"), b"x").unwrap();
        let inner = dir.join("inner");
        std::fs::create_dir(&inner).unwrap();
        // inner/cycle -> dir, which already contains inner. Classic trap.
        std::os::unix::fs::symlink(&dir, inner.join("cycle")).unwrap();

        // Count with a hard wall-clock bound so test failure is fast.
        use std::sync::mpsc;
        use std::time::Duration;
        let (tx, rx) = mpsc::channel();
        let dir_clone = dir.clone();
        std::thread::spawn(move || {
            let n = count_recovered_files(&dir_clone);
            let _ = tx.send(n);
        });
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("count_recovered_files must terminate on a symlink cycle");
        assert_eq!(got, 1, "only real.txt should count, symlinks skipped");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_count_recovered_files_bounded_depth() {
        // Build a 40-level nested directory tree (deeper than
        // MAX_RECOVERY_DEPTH = 32) and confirm the walker returns
        // without running past the cap. We don't test the exact
        // count — just that we terminate and stay finite.
        let dir =
            std::env::temp_dir().join(format!("atrium-depth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cur = dir.clone();
        for i in 0..40 {
            cur = cur.join(format!("l{}", i));
            std::fs::create_dir(&cur).unwrap();
            std::fs::write(cur.join("leaf"), b"x").unwrap();
        }
        let n = count_recovered_files(&dir);
        // We should have seen *some* leaves but not crashed. The
        // exact count depends on MAX_RECOVERY_DEPTH.
        assert!(n > 0);
        assert!(n <= 40);
        std::fs::remove_dir_all(&dir).ok();
    }
}
