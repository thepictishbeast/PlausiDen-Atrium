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
use std::path::{Path, PathBuf};
use std::process::Command;

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

    if let Err(e) = std::fs::create_dir_all(output_dir) {
        return VerificationReport {
            tool,
            target: target.to_path_buf(),
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
            .arg(target)
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
            .arg(target)
            .output(),
        ForensicTool::Scalpel => Command::new("scalpel")
            .arg("-o")
            .arg(output_dir)
            .arg(target)
            .output(),
        ForensicTool::ExtUndelete => Command::new("extundelete")
            .arg("--restore-all")
            .arg("--output-dir")
            .arg(output_dir)
            .arg(target)
            .output(),
        ForensicTool::TestDisk => {
            // testdisk is fully interactive; best-effort invoke with /log.
            Command::new("testdisk").arg("/log").arg(target).output()
        }
        ForensicTool::BulkExtractor => Command::new("bulk_extractor")
            .arg("-o")
            .arg(output_dir)
            .arg(target)
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
        target: target.to_path_buf(),
        files_recovered,
        output_dir: output_dir.to_path_buf(),
        raw_output,
        success,
        error,
    }
}

/// Recursively count how many files a recovery tool dropped under
/// `output_dir`.
pub fn count_recovered_files(output_dir: &Path) -> usize {
    let mut count = 0;
    let Ok(entries) = std::fs::read_dir(output_dir) else { return 0 };
    let mut stack: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                for e in entries.flatten() {
                    stack.push(e.path());
                }
            }
        } else if path.is_file() {
            count += 1;
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
}
