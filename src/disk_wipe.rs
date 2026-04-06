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
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
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

    /// Validate the range is structurally sound AND that the target
    /// is actually a block device and is not currently mounted.
    ///
    /// BUG ASSUMPTION (AVP-2): the caller may pass a regular file,
    /// a device that is currently mounted as the root filesystem, a
    /// device-mapper volume holding active LUKS contents, or a range
    /// that extends past the end of the device. Every one of these
    /// is a way to brick the system.
    ///
    /// REGRESSION-GUARD: an earlier version of this function only
    /// checked `device.exists()`, which accepted regular files under
    /// `/tmp/*`. A caller that forgot to set up a real block device
    /// would silently destroy a regular file. Fixed in AVP-2 audit.
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
        let meta = std::fs::metadata(&self.device)
            .map_err(|e| format!("stat {}: {}", self.device.display(), e))?;
        if !meta.file_type().is_block_device() {
            return Err(format!(
                "{} is not a block device (safety refusal)",
                self.device.display()
            ));
        }
        if is_device_mounted(&self.device) {
            return Err(format!(
                "{} is currently mounted — refusing to wipe",
                self.device.display()
            ));
        }
        Ok(())
    }
}

/// Parse `/proc/mounts` and return true if the given device path
/// appears in any mount line. Also checks the canonical path (in
/// case the caller passed a symlink like `/dev/disk/by-label/foo`).
///
/// BUG ASSUMPTION: /proc/mounts may be unreadable in weird sandboxes;
/// the answer in that case is "unknown", which we treat as "possibly
/// mounted" to stay on the safe side and refuse the wipe.
pub fn is_device_mounted(device: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return true; // fail closed: assume mounted
    };
    let canonical = std::fs::canonicalize(device).ok();
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        if let Some(dev) = fields.next() {
            if dev == device.to_string_lossy() {
                return true;
            }
            if let Some(canon) = &canonical
                && dev == canon.to_string_lossy()
            {
                return true;
            }
        }
    }
    false
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

    // Open read+write. Read access is required for correct Complement
    // semantics (read-back, invert, write-back). REGRESSION-GUARD:
    // an earlier version opened write-only, which made multi-chunk
    // Complement passes produce alternating 0xAA/0x55 garbage.
    let file_result = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&range.device);
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
    // Scratch buffer for Complement read-back. Zeroized on every
    // exit path so disk contents never linger in RAM longer than
    // they need to.
    let mut readback = vec![0u8; chunk_size];

    for pass in &config.passes {
        for _ in 0..pass.repeat {
            passes_run += 1;
            if let Err(e) = file.seek(SeekFrom::Start(range.start)) {
                errors.push(format!("seek failed: {}", e));
                buffer.zeroize();
                readback.zeroize();
                return DiskWipeReport {
                    range: range.clone(),
                    passes_run,
                    bytes_written,
                    errors,
                    success: false,
                };
            }

            let mut remaining = length;
            let mut chunk_offset = range.start;

            // For ChaCha20 we need a fresh key per pass.
            let mut key_bytes = [0u8; 32];
            let mut nonce_bytes = [0u8; 12];
            if pass.algorithm == WipeAlgorithm::ChaCha20Stream {
                rand::thread_rng().fill_bytes(&mut key_bytes);
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
            }

            while remaining > 0 {
                let to_write = (chunk_size as u64).min(remaining) as usize;

                // Complement: read current contents first, then flip.
                // Every other algorithm fills the buffer blind.
                if pass.algorithm == WipeAlgorithm::Complement {
                    if let Err(e) = file.seek(SeekFrom::Start(chunk_offset)) {
                        errors.push(format!("seek failed: {}", e));
                        key_bytes.zeroize();
                        nonce_bytes.zeroize();
                        buffer.zeroize();
                        readback.zeroize();
                        return DiskWipeReport {
                            range: range.clone(),
                            passes_run,
                            bytes_written,
                            errors,
                            success: false,
                        };
                    }
                    if let Err(e) = file.read_exact(&mut readback[..to_write]) {
                        errors.push(format!("readback failed: {}", e));
                        key_bytes.zeroize();
                        nonce_bytes.zeroize();
                        buffer.zeroize();
                        readback.zeroize();
                        return DiskWipeReport {
                            range: range.clone(),
                            passes_run,
                            bytes_written,
                            errors,
                            success: false,
                        };
                    }
                    for i in 0..to_write {
                        buffer[i] = !readback[i];
                    }
                    // Seek back to the chunk start so write_all lands
                    // at the right offset after the read_exact advance.
                    if let Err(e) = file.seek(SeekFrom::Start(chunk_offset)) {
                        errors.push(format!("seek failed: {}", e));
                        key_bytes.zeroize();
                        nonce_bytes.zeroize();
                        buffer.zeroize();
                        readback.zeroize();
                        return DiskWipeReport {
                            range: range.clone(),
                            passes_run,
                            bytes_written,
                            errors,
                            success: false,
                        };
                    }
                } else {
                    fill_buffer(
                        &mut buffer[..to_write],
                        pass.algorithm,
                        &key_bytes,
                        &nonce_bytes,
                    );
                }

                if let Err(e) = file.write_all(&buffer[..to_write]) {
                    errors.push(format!("write failed: {}", e));
                    key_bytes.zeroize();
                    nonce_bytes.zeroize();
                    buffer.zeroize();
                    readback.zeroize();
                    return DiskWipeReport {
                        range: range.clone(),
                        passes_run,
                        bytes_written,
                        errors,
                        success: false,
                    };
                }
                bytes_written += to_write as u64;
                chunk_offset += to_write as u64;
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
    readback.zeroize();
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
            // UNREACHABLE: Complement is handled in wipe_range's
            // main loop where the caller reads the current contents
            // from disk before inverting. fill_buffer is only called
            // for non-Complement algorithms now.
            debug_assert!(
                false,
                "Complement must be handled in wipe_range, not fill_buffer"
            );
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

/// List safe-to-show physical block devices (stat-based, no content reads).
///
/// SECURITY: this function deliberately filters out dangerous
/// entries from /sys/block before surfacing them to the wipe UI:
///
/// - `dm-*`          — device-mapper volumes (LVM, LUKS). Wiping a
///                     live LUKS container destroys the unlocked
///                     data AND the key slots.
/// - `loop*`         — loop-mounted image files, almost never the
///                     user's intended wipe target.
/// - `zram*`/`ram*`  — in-memory block devices. Irrelevant.
/// - `md*`           — mdraid arrays. Wiping a member underneath
///                     the array head is catastrophic.
///
/// The physical backing devices (sdX, nvmeXnY, vdX, mmcblkX) are
/// kept. Partitions are not in /sys/block at the top level so they
/// don't appear here in any case.
///
/// Devices currently listed in /proc/mounts are also filtered out,
/// so the user cannot accidentally select their live root disk.
pub fn list_block_devices() -> Vec<DeviceInfo> {
    list_block_devices_filtered(true)
}

/// Unfiltered variant for diagnostics. Only use when you explicitly
/// want to see everything in /sys/block, including the dangerous
/// entries. Not called by the UI.
pub fn list_block_devices_all() -> Vec<DeviceInfo> {
    list_block_devices_filtered(false)
}

fn list_block_devices_filtered(filter_dangerous: bool) -> Vec<DeviceInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else { return out };
    let mounted = mounted_devices();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if filter_dangerous && is_dangerous_device_name(&name) {
            continue;
        }
        let device_path = PathBuf::from(format!("/dev/{}", name));
        if !device_path.exists() {
            continue;
        }
        if filter_dangerous && mounted.contains(&device_path.to_string_lossy().to_string()) {
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

/// Return true if a /sys/block entry name should be hidden from the
/// wipe picker because targeting it is almost always a mistake.
pub fn is_dangerous_device_name(name: &str) -> bool {
    name.starts_with("dm-")
        || name.starts_with("loop")
        || name.starts_with("zram")
        || name.starts_with("ram")
        || name.starts_with("md")
        || name.starts_with("sr") // optical drives
        || name.starts_with("fd") // legacy floppy
}

/// Snapshot of the first column of /proc/mounts.
fn mounted_devices() -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else { return out };
    for line in mounts.lines() {
        if let Some(dev) = line.split_whitespace().next() {
            out.insert(dev.to_string());
        }
    }
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

    // REGRESSION-GUARD: Bug 3 — validate() used to accept any path
    // that existed, including regular files. wipe_range would then
    // happily overwrite them. Fixed in AVP-2 audit.
    #[test]
    fn test_validate_rejects_regular_file() {
        let path = std::env::temp_dir().join(format!(
            "atrium-disk-wipe-regfile-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a block device").unwrap();
        let r = DiskRange {
            device: path.clone(),
            start: 0,
            end: 8,
            label: "t".into(),
        };
        let err = r.validate().unwrap_err();
        assert!(
            err.contains("not a block device"),
            "expected block-device refusal, got: {}",
            err
        );
        // And the file must be untouched by the failed validation.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"not a block device");
        std::fs::remove_file(&path).ok();
    }

    // REGRESSION-GUARD: Bug 3 confirmation — even when passed to
    // wipe_range with dry_run=false, a regular file target must
    // produce a hard failure before any write happens.
    #[test]
    fn test_wipe_range_refuses_regular_file_target() {
        let path = std::env::temp_dir().join(format!(
            "atrium-disk-wipe-regfile-live-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"sentinel-bytes-0123456789").unwrap();
        let r = DiskRange {
            device: path.clone(),
            start: 0,
            end: 25,
            label: "t".into(),
        };
        let config = WipeConfig::default();
        let report = wipe_range(&r, &config, false);
        assert!(!report.success);
        assert_eq!(report.bytes_written, 0);
        // Sentinel bytes survive unchanged.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"sentinel-bytes-0123456789");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_dry_run_no_writes() {
        // /dev/null is a character device so it will fail the new
        // block-device check. Use a range that won't validate
        // regardless and confirm dry-run takes the validate-first
        // path.
        let r = DiskRange {
            device: PathBuf::from("/dev/null"),
            start: 0,
            end: 4096,
            label: "t".into(),
        };
        let config = WipeConfig::default();
        let report = wipe_range(&r, &config, true);
        // Dry-run still goes through validate(). /dev/null is not
        // a block device, so this must fail fast rather than report
        // "dry run success".
        assert!(!report.success);
        assert_eq!(report.bytes_written, 0);
    }

    #[test]
    fn test_is_dangerous_device_name() {
        assert!(is_dangerous_device_name("dm-0"));
        assert!(is_dangerous_device_name("dm-7"));
        assert!(is_dangerous_device_name("loop0"));
        assert!(is_dangerous_device_name("loop12"));
        assert!(is_dangerous_device_name("zram0"));
        assert!(is_dangerous_device_name("ram1"));
        assert!(is_dangerous_device_name("md0"));
        assert!(is_dangerous_device_name("sr0"));
        assert!(is_dangerous_device_name("fd0"));
        // Real physical devices should NOT be filtered.
        assert!(!is_dangerous_device_name("sda"));
        assert!(!is_dangerous_device_name("sdb"));
        assert!(!is_dangerous_device_name("nvme0n1"));
        assert!(!is_dangerous_device_name("mmcblk0"));
        assert!(!is_dangerous_device_name("vda"));
    }

    #[test]
    fn test_list_block_devices_filters_dangerous() {
        // The default listing must not contain dm-/loop/etc entries
        // even if they exist on the host. This is the user-facing
        // guarantee: anything that comes out of this function is
        // something the UI can safely show as a wipe target.
        let devs = list_block_devices();
        for dev in &devs {
            assert!(
                !is_dangerous_device_name(&dev.name),
                "dangerous device leaked into filtered list: {}",
                dev.name
            );
        }
    }

    #[test]
    fn test_mounted_devices_returns_populated_set() {
        // On any running Linux system /proc/mounts has at least one
        // entry (the root mount). Not all test hosts will — just
        // verify the function returns without panicking.
        let _ = mounted_devices();
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
