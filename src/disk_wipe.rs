#![allow(dead_code)]
//! Disk-range wiping — write overwrite patterns to a specific byte
//! range of a block device, the way `parted rescue` or `dd` would.
//!
//! This is a *very* destructive primitive and is gated behind the
//! same dry-run lock as every other commit path in Atrium. The
//! functions here take explicit (device, start, end) tuples and
//! refuse to operate without them.
//!
//! IMPORTANT: disk-range wiping can brick a system if pointed at
//! the wrong device or range. The caller is responsible for every
//! byte it passes in.

use crate::wipe_config::{WipeAlgorithm, WipeConfig};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

/// A byte range on a block device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskRange {
    pub device: PathBuf,
    /// Inclusive byte offset of the first byte to wipe.
    pub start: u64,
    /// Exclusive byte offset one past the last byte to wipe.
    pub end: u64,
    /// Human-readable label for logging (e.g. "sda3 – swap").
    pub label: String,
}

impl DiskRange {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.device.as_os_str().is_empty() {
            return Err("device path is empty".into());
        }
        if self.end <= self.start {
            return Err(format!(
                "end ({}) must be greater than start ({})",
                self.end, self.start
            ));
        }
        if !self.device.exists() {
            return Err(format!("device {} does not exist", self.device.display()));
        }
        Ok(())
    }
}

/// Report emitted after a disk-range wipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskWipeReport {
    pub range: DiskRange,
    pub passes_run: usize,
    pub bytes_written: u64,
    pub errors: Vec<String>,
    pub success: bool,
}

/// Execute a wipe config against a disk range. Does nothing on a
/// dry run — returns an empty report with the intended pass list.
pub fn wipe_range(
    range: &DiskRange,
    config: &WipeConfig,
    dry_run: bool,
) -> DiskWipeReport {
    if let Err(e) = range.validate() {
        return DiskWipeReport {
            range: range.clone(),
            passes_run: 0,
            bytes_written: 0,
            errors: vec![e],
            success: false,
        };
    }

    if dry_run {
        return DiskWipeReport {
            range: range.clone(),
            passes_run: config.total_passes(),
            bytes_written: 0,
            errors: vec!["dry-run".into()],
            success: true,
        };
    }

    let mut errors = Vec::new();
    let mut bytes_written = 0u64;
    let mut passes_run = 0usize;

    let file_result = OpenOptions::new().write(true).open(&range.device);
    let mut file = match file_result {
        Ok(f) => f,
        Err(e) => {
            return DiskWipeReport {
                range: range.clone(),
                passes_run: 0,
                bytes_written: 0,
                errors: vec![format!("open failed: {}", e)],
                success: false,
            };
        }
    };

    let length = range.len();
    let chunk_size: usize = 1 << 20; // 1 MiB
    let mut buffer = vec![0u8; chunk_size];

    for pass in &config.passes {
        for _ in 0..pass.repeat {
            passes_run += 1;
            if let Err(e) = file.seek(SeekFrom::Start(range.start)) {
                errors.push(format!("seek failed: {}", e));
                return DiskWipeReport {
                    range: range.clone(),
                    passes_run,
                    bytes_written,
                    errors,
                    success: false,
                };
            }

            let mut remaining = length;

            // For ChaCha20 we need a fresh key per pass.
            let mut key_bytes = [0u8; 32];
            let mut nonce_bytes = [0u8; 12];
            if pass.algorithm == WipeAlgorithm::ChaCha20Stream {
                rand::thread_rng().fill_bytes(&mut key_bytes);
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
            }

            while remaining > 0 {
                let to_write = (chunk_size as u64).min(remaining) as usize;
                fill_buffer(&mut buffer[..to_write], pass.algorithm, &key_bytes, &nonce_bytes);
                if let Err(e) = file.write_all(&buffer[..to_write]) {
                    errors.push(format!("write failed: {}", e));
                    key_bytes.zeroize();
                    nonce_bytes.zeroize();
                    buffer.zeroize();
                    return DiskWipeReport {
                        range: range.clone(),
                        passes_run,
                        bytes_written,
                        errors,
                        success: false,
                    };
                }
                bytes_written += to_write as u64;
                remaining -= to_write as u64;
            }

            key_bytes.zeroize();
            nonce_bytes.zeroize();

            if config.fsync_between_passes {
                let _ = file.sync_data();
            }
        }
    }

    buffer.zeroize();
    let _ = file.sync_all();

    DiskWipeReport {
        range: range.clone(),
        passes_run,
        bytes_written,
        errors,
        success: true,
    }
}

fn fill_buffer(
    buf: &mut [u8],
    algorithm: WipeAlgorithm,
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
) {
    match algorithm {
        WipeAlgorithm::Zeros => buf.fill(0x00),
        WipeAlgorithm::Ones => buf.fill(0xFF),
        WipeAlgorithm::Pattern(b) => buf.fill(b),
        WipeAlgorithm::Random => rand::thread_rng().fill_bytes(buf),
        WipeAlgorithm::Complement => {
            // Flip existing bits in-place. The caller must have
            // primed `buf` with the last pass before calling — for
            // disk ranges we approximate with all-ones then flip,
            // which becomes all-zeros. Kept simple: fill 0x55 which
            // is the binary complement of 0xAA.
            for b in buf.iter_mut() {
                *b = !*b;
            }
        }
        WipeAlgorithm::ChaCha20Stream => {
            rand::thread_rng().fill_bytes(buf);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
            let _ = cipher.encrypt_in_place_detached(Nonce::from_slice(nonce_bytes), &[], buf);
        }
        WipeAlgorithm::Verify => {
            // Verify passes are no-ops for the disk writer.
        }
    }
}

/// List the mounted block devices (stat-based, no content reads).
pub fn list_block_devices() -> Vec<DeviceInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else { return out };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let device_path = PathBuf::from(format!("/dev/{}", name));
        if !device_path.exists() {
            continue;
        }
        let size = std::fs::read_to_string(entry.path().join("size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors * 512)
            .unwrap_or(0);
        let rotational = std::fs::read_to_string(entry.path().join("queue").join("rotational"))
            .ok()
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        out.push(DeviceInfo {
            name: name.clone(),
            path: device_path,
            size_bytes: size,
            rotational,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Information about a block device surfaced in the disk-wipe UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub rotational: bool,
}

impl DeviceInfo {
    pub fn storage_label(&self) -> &'static str {
        if self.rotational { "HDD" } else { "SSD" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_range_len() {
        let r = DiskRange {
            device: PathBuf::from("/dev/null"),
            start: 100,
            end: 200,
            label: "t".into(),
        };
        assert_eq!(r.len(), 100);
    }

    #[test]
    fn test_disk_range_empty() {
        let r = DiskRange {
            device: PathBuf::from("/dev/null"),
            start: 200,
            end: 100,
            label: "t".into(),
        };
        assert!(r.is_empty());
    }

    #[test]
    fn test_validate_end_before_start() {
        let r = DiskRange {
            device: PathBuf::from("/dev/null"),
            start: 200,
            end: 100,
            label: "t".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_validate_missing_device() {
        let r = DiskRange {
            device: PathBuf::from("/definitely/not/a/device/xyz"),
            start: 0,
            end: 100,
            label: "t".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_dry_run_no_writes() {
        let r = DiskRange {
            device: PathBuf::from("/dev/null"),
            start: 0,
            end: 4096,
            label: "t".into(),
        };
        let config = WipeConfig::default();
        let report = wipe_range(&r, &config, true);
        assert_eq!(report.bytes_written, 0);
        assert!(report.success);
    }

    #[test]
    fn test_list_block_devices_runs() {
        let devs = list_block_devices();
        // On a typical host there is at least one block device.
        // Don't assert non-empty because CI sandboxes may have none.
        let _ = devs;
    }

    #[test]
    fn test_device_info_storage_label() {
        let d = DeviceInfo {
            name: "sda".into(),
            path: PathBuf::from("/dev/sda"),
            size_bytes: 1000,
            rotational: true,
        };
        assert_eq!(d.storage_label(), "HDD");
    }

    #[test]
    fn test_device_info_ssd_label() {
        let d = DeviceInfo {
            name: "nvme0n1".into(),
            path: PathBuf::from("/dev/nvme0n1"),
            size_bytes: 0,
            rotational: false,
        };
        assert_eq!(d.storage_label(), "SSD");
    }
}
