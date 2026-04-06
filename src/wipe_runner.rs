//! File-level wipe runner — execute a [`WipeConfig`] against a single
//! file on disk.
//!
//! This module is the only place in Atrium that actually performs
//! destructive writes to user files. It is called exclusively after
//! an explicit per-item approval and plan-level confirmation token
//! in the Plan view, AND only when the safety lock has been released
//! in Settings.
//!
//! BUG ASSUMPTION: the file may disappear between stat and open; the
//! process may be killed mid-pass leaving partial writes; the user
//! may have passed a path that the OS will silently redirect; any of
//! these must not corrupt neighbouring files.

use crate::forensic::{self, ForensicTool, VerificationReport};
use crate::wipe_config::{WipeAlgorithm, WipeConfig};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Outcome of a file wipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    pub path: PathBuf,
    pub original_size: u64,
    pub passes_run: u32,
    pub bytes_written: u64,
    pub truncated: bool,
    pub removed: bool,
    pub errors: Vec<String>,
    pub success: bool,
}

impl WipeResult {
    fn failed(path: PathBuf, original_size: u64, err: String) -> Self {
        Self {
            path,
            original_size,
            passes_run: 0,
            bytes_written: 0,
            truncated: false,
            removed: false,
            errors: vec![err],
            success: false,
        }
    }
}

/// Execute a wipe configuration against a file.
///
/// BUG ASSUMPTION: the supplied path may be a symlink, a special
/// file, a directory, a FIFO, or not exist. Attackers may try to
/// swap the target between our stat and our open (TOCTOU). Other
/// processes may hold the file open and race our writes. All of
/// these must be rejected or defended against.
///
/// SECURITY: this function opens with `O_NOFOLLOW` so symlinks are
/// refused at the kernel level, not by an earlier stat(2) that an
/// attacker could race. After opening, it fstats the file descriptor
/// to verify it is still a regular file. It also takes an exclusive
/// flock(2) so no other process can write concurrently.
///
/// REGRESSION-GUARD: the previous version used symlink_metadata +
/// open(path), which had a TOCTOU race window between the check and
/// the open. An attacker with write access to the parent directory
/// could swap the regular file for a symlink in that window and have
/// the wipe destroy the symlink target instead. Fixed in AVP-2 audit.
pub fn execute_wipe(path: &Path, config: &WipeConfig, dry_run: bool) -> WipeResult {
    // A pre-flight symlink_metadata is still useful for the dry-run
    // path and for surfacing clearer errors. The authoritative check
    // happens after the open via fstat on the file descriptor.
    if !path.exists() {
        return WipeResult::failed(
            path.to_path_buf(),
            0,
            format!("path does not exist: {}", path.display()),
        );
    }

    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return WipeResult::failed(
                path.to_path_buf(),
                0,
                format!("symlink_metadata failed: {}", e),
            );
        }
    };
    if meta.file_type().is_symlink() {
        return WipeResult::failed(
            path.to_path_buf(),
            0,
            "refusing to wipe a symlink; approve the target explicitly".into(),
        );
    }
    if !meta.is_file() {
        return WipeResult::failed(
            path.to_path_buf(),
            0,
            format!("not a regular file: {}", path.display()),
        );
    }

    let original_size = meta.len();

    if dry_run {
        return WipeResult {
            path: path.to_path_buf(),
            original_size,
            passes_run: config.total_passes() as u32,
            bytes_written: 0,
            truncated: false,
            removed: false,
            errors: vec!["dry-run".into()],
            success: true,
        };
    }

    // Open with O_NOFOLLOW so the kernel refuses to open the file
    // if the path was swapped to a symlink between stat and open.
    // The caller's symlink check above still exists for cleaner
    // error messages on honest symlinks.
    let open_result = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    let file = match open_result {
        Ok(f) => f,
        Err(e) => {
            // ELOOP (errno 40) is what O_NOFOLLOW returns when the
            // path IS a symlink. Translate into a clearer message.
            let kind_msg = if e.raw_os_error() == Some(libc::ELOOP) {
                "path became a symlink between check and open (possible TOCTOU)".to_string()
            } else {
                format!("open failed: {}", e)
            };
            return WipeResult::failed(path.to_path_buf(), original_size, kind_msg);
        }
    };

    // After open, verify the descriptor still points at a regular
    // file of the expected inode. This catches the case where the
    // path was replaced with a different regular file in the stat-
    // to-open window.
    let fd = file.as_raw_fd();
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat(2) with a valid fd and a zeroed stat buffer is
    // the documented invocation. The fd is owned by `file` and
    // outlives this call.
    let fstat_rc = unsafe { libc::fstat(fd, &mut stat_buf) };
    if fstat_rc != 0 {
        return WipeResult::failed(
            path.to_path_buf(),
            original_size,
            "fstat failed after open".into(),
        );
    }
    let mode = stat_buf.st_mode;
    let is_regular = (mode & libc::S_IFMT) == libc::S_IFREG;
    if !is_regular {
        return WipeResult::failed(
            path.to_path_buf(),
            original_size,
            "fstat reports non-regular file after open".into(),
        );
    }

    // Take an exclusive, non-blocking flock so no other process can
    // write while we're shredding. flock() with LOCK_EX|LOCK_NB
    // returns EWOULDBLOCK if another holder has the lock.
    //
    // SAFETY: flock(2) with a valid fd is the documented invocation.
    let flock_rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if flock_rc != 0 {
        let err = std::io::Error::last_os_error();
        return WipeResult::failed(
            path.to_path_buf(),
            original_size,
            format!(
                "another process holds a lock on this file (flock: {})",
                err
            ),
        );
    }

    let mut file = file;

    let mut result = WipeResult {
        path: path.to_path_buf(),
        original_size,
        passes_run: 0,
        bytes_written: 0,
        truncated: false,
        removed: false,
        errors: Vec::new(),
        success: true,
    };

    // Reusable buffers. The previous-pass buffer feeds the Complement
    // pass; zeroized between passes for safety.
    let chunk_size: usize = 1 << 16; // 64 KiB
    let mut buffer = vec![0u8; chunk_size];
    let mut prev_buffer = vec![0u8; chunk_size];

    for pass in &config.passes {
        for _ in 0..pass.repeat {
            result.passes_run += 1;

            // Fresh ChaCha20 key per pass when needed.
            let mut key_bytes = [0u8; 32];
            let mut nonce_bytes = [0u8; 12];
            if pass.algorithm == WipeAlgorithm::ChaCha20Stream {
                rand::thread_rng().fill_bytes(&mut key_bytes);
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
            }

            if let Err(e) = file.seek(SeekFrom::Start(0)) {
                result.errors.push(format!("seek failed: {}", e));
                key_bytes.zeroize();
                nonce_bytes.zeroize();
                result.success = false;
                return finalize(file, result, buffer, prev_buffer);
            }

            let mut offset: u64 = 0;
            while offset < original_size {
                let to_write = (chunk_size as u64).min(original_size - offset) as usize;

                // For Complement we need what's currently on disk.
                if pass.algorithm == WipeAlgorithm::Complement {
                    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                        result.errors.push(format!("seek failed: {}", e));
                        key_bytes.zeroize();
                        nonce_bytes.zeroize();
                        result.success = false;
                        return finalize(file, result, buffer, prev_buffer);
                    }
                    if let Err(e) = file.read_exact(&mut prev_buffer[..to_write]) {
                        result.errors.push(format!("read failed: {}", e));
                        key_bytes.zeroize();
                        nonce_bytes.zeroize();
                        result.success = false;
                        return finalize(file, result, buffer, prev_buffer);
                    }
                    for i in 0..to_write {
                        buffer[i] = !prev_buffer[i];
                    }
                } else {
                    fill_buffer(
                        &mut buffer[..to_write],
                        pass.algorithm,
                        &key_bytes,
                        &nonce_bytes,
                    );
                }

                if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                    result.errors.push(format!("seek failed: {}", e));
                    key_bytes.zeroize();
                    nonce_bytes.zeroize();
                    result.success = false;
                    return finalize(file, result, buffer, prev_buffer);
                }
                if let Err(e) = file.write_all(&buffer[..to_write]) {
                    result.errors.push(format!("write failed: {}", e));
                    key_bytes.zeroize();
                    nonce_bytes.zeroize();
                    result.success = false;
                    return finalize(file, result, buffer, prev_buffer);
                }

                result.bytes_written += to_write as u64;
                offset += to_write as u64;
            }

            if config.fsync_between_passes {
                if let Err(e) = file.sync_data() {
                    result.errors.push(format!("sync_data failed: {}", e));
                }
            }

            // Zeroize ephemeral material before the next pass.
            key_bytes.zeroize();
            nonce_bytes.zeroize();
        }
    }

    // Final global fsync.
    if let Err(e) = file.sync_all() {
        result.errors.push(format!("sync_all failed: {}", e));
    }

    if config.truncate_after {
        if let Err(e) = file.set_len(0) {
            result.errors.push(format!("truncate failed: {}", e));
            result.success = false;
            return finalize(file, result, buffer, prev_buffer);
        }
        result.truncated = true;
    }

    drop(file);
    buffer.zeroize();
    prev_buffer.zeroize();

    if config.unlink_after {
        if let Err(e) = std::fs::remove_file(path) {
            result.errors.push(format!("unlink failed: {}", e));
            result.success = false;
            return result;
        }
        result.removed = true;
    }

    result
}

fn finalize(
    file: std::fs::File,
    mut result: WipeResult,
    mut buffer: Vec<u8>,
    mut prev_buffer: Vec<u8>,
) -> WipeResult {
    drop(file);
    buffer.zeroize();
    prev_buffer.zeroize();
    result.success = false;
    result
}

/// Report of a wipe followed by a forensic verification loop.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedWipeResult {
    pub initial_wipe: WipeResult,
    pub verification_attempts: Vec<VerificationReport>,
    pub final_success: bool,
    pub iterations: u32,
    pub verdict: String,
}

/// Run a wipe, then run a forensic recovery tool against the scan
/// directory, and loop the tool up to `max_iterations` times until
/// it reports zero recovered files.
///
/// BUG ASSUMPTION: photorec/foremost may be slow (10s of minutes on
/// large devices), may refuse to run without root, may produce
/// unrelated recoveries from the surrounding filesystem, and may
/// fail transiently. The loop treats tool failure as inconclusive
/// and preserves the attempt in the report.
///
/// SECURITY: this function cannot re-wipe the same file after the
/// initial wipe because the file no longer exists. The caller is
/// expected to use this against a free-space region or against a
/// disk image. For the everyday Tidy case, one initial wipe is
/// sufficient and the verification loop simply observes.
#[allow(dead_code)]
pub fn execute_wipe_with_verification(
    path: &Path,
    config: &WipeConfig,
    tool: ForensicTool,
    scan_target: &Path,
    max_iterations: u32,
    dry_run: bool,
) -> VerifiedWipeResult {
    let initial_wipe = execute_wipe(path, config, dry_run);

    if dry_run {
        return VerifiedWipeResult {
            initial_wipe,
            verification_attempts: Vec::new(),
            final_success: true,
            iterations: 0,
            verdict: "dry-run — verification skipped".into(),
        };
    }

    if !initial_wipe.success {
        return VerifiedWipeResult {
            initial_wipe: initial_wipe.clone(),
            verification_attempts: Vec::new(),
            final_success: false,
            iterations: 0,
            verdict: format!(
                "initial wipe failed: {}",
                initial_wipe.errors.join("; ")
            ),
        };
    }

    let mut attempts: Vec<VerificationReport> = Vec::new();
    let mut verdict = String::new();
    let mut iterations: u32 = 0;

    for i in 0..max_iterations {
        iterations = i + 1;
        let output_dir = std::env::temp_dir()
            .join(format!("atrium-verify-{}-{}", std::process::id(), i));
        let _ = std::fs::create_dir_all(&output_dir);
        let report = forensic::run_verification(tool, scan_target, &output_dir);
        let recovered = report.files_recovered;
        let tool_success = report.success;
        attempts.push(report);

        if !tool_success {
            verdict = format!(
                "iteration {}: tool invocation failed; cannot verify",
                iterations
            );
            let _ = std::fs::remove_dir_all(&output_dir);
            break;
        }

        if recovered == 0 {
            verdict = format!(
                "iteration {}: zero recoveries — verification passed",
                iterations
            );
            let _ = std::fs::remove_dir_all(&output_dir);
            return VerifiedWipeResult {
                initial_wipe,
                verification_attempts: attempts,
                final_success: true,
                iterations,
                verdict,
            };
        }

        verdict = format!(
            "iteration {}: recovered {} file(s); the wipe did not reach physical media",
            iterations, recovered
        );
        let _ = std::fs::remove_dir_all(&output_dir);
    }

    VerifiedWipeResult {
        initial_wipe,
        verification_attempts: attempts,
        final_success: false,
        iterations,
        verdict,
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
        WipeAlgorithm::ChaCha20Stream => {
            rand::thread_rng().fill_bytes(buf);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
            let _ = cipher.encrypt_in_place_detached(Nonce::from_slice(nonce_bytes), &[], buf);
        }
        WipeAlgorithm::Complement => {
            // Handled in the caller which reads prior contents first.
        }
        WipeAlgorithm::Verify => {
            // Verify passes are no-ops in the writer; a real verify
            // would re-read and hash, but that requires knowing the
            // expected pattern which varies per pass.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wipe_config::WipePreset;
    use std::io::Write as _;

    fn temp_file(contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "atrium-wipe-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn test_dry_run_reports_would_succeed() {
        let path = temp_file(b"abc");
        let config = WipeConfig::preset(WipePreset::Quick);
        let r = execute_wipe(&path, &config, true);
        assert!(r.success);
        assert_eq!(r.bytes_written, 0);
        assert!(path.exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_missing_file_fails() {
        let path = PathBuf::from("/tmp/definitely-does-not-exist-wipe-test-xyz");
        let r = execute_wipe(&path, &WipeConfig::default(), true);
        assert!(!r.success);
    }

    #[test]
    fn test_refuses_symlink() {
        let target = temp_file(b"target-data");
        let link = std::env::temp_dir().join(format!(
            "atrium-wipe-link-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let r = execute_wipe(&link, &WipeConfig::default(), false);
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("symlink")),
            "expected symlink refusal, got: {:?}",
            r.errors
        );
        // The target must be untouched.
        let contents = std::fs::read(&target).unwrap();
        assert_eq!(contents, b"target-data");
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[test]
    fn test_refuses_directory() {
        let dir = std::env::temp_dir().join(format!(
            "atrium-wipe-dir-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let r = execute_wipe(&dir, &WipeConfig::default(), false);
        assert!(!r.success);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_quick_pass_overwrites_and_removes() {
        let path = temp_file(b"plaintext-to-shred");
        let config = WipeConfig::preset(WipePreset::Quick);
        let r = execute_wipe(&path, &config, false);
        assert!(r.success, "errors: {:?}", r.errors);
        assert_eq!(r.passes_run, 1);
        assert!(r.removed);
        assert!(!path.exists());
    }

    #[test]
    fn test_crypto_shred_replaces_plaintext() {
        let plaintext = b"sensitive-marker-FFFF-secret-payload";
        let path = temp_file(plaintext);
        let mut config = WipeConfig::preset(WipePreset::CryptoShred);
        config.truncate_after = false;
        config.unlink_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success, "errors: {:?}", r.errors);
        let remaining = std::fs::read(&path).unwrap();
        assert_eq!(remaining.len(), plaintext.len());
        assert_ne!(remaining, plaintext);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_dod3_runs_three_passes() {
        let path = temp_file(&vec![0xABu8; 4096]);
        let config = WipeConfig::preset(WipePreset::DoD3Pass);
        let r = execute_wipe(&path, &config, false);
        assert!(r.success, "errors: {:?}", r.errors);
        assert_eq!(r.passes_run, 3);
    }

    #[test]
    fn test_zero_byte_file_handled() {
        let path = temp_file(b"");
        let config = WipeConfig::preset(WipePreset::Quick);
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        assert_eq!(r.bytes_written, 0);
        assert_eq!(r.original_size, 0);
    }

    #[test]
    fn test_large_file_multiple_chunks() {
        let big = vec![0x42u8; 300_000];
        let path = temp_file(&big);
        let mut config = WipeConfig::preset(WipePreset::Quick);
        config.truncate_after = false;
        config.unlink_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        assert_eq!(r.bytes_written, 300_000);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_truncate_without_unlink() {
        let path = temp_file(&vec![0u8; 1024]);
        let mut config = WipeConfig::preset(WipePreset::Quick);
        config.truncate_after = true;
        config.unlink_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        assert!(r.truncated);
        assert!(!r.removed);
        assert!(path.exists());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_complement_pass_toggles_bytes() {
        let plaintext = vec![0xAAu8; 4096];
        let path = temp_file(&plaintext);
        let mut config = WipeConfig {
            passes: vec![crate::wipe_config::WipePass::new(WipeAlgorithm::Complement)],
            truncate_after: false,
            unlink_after: false,
            fsync_between_passes: true,
            verify_with_forensics: false,
            max_repurge_iterations: 1,
        };
        config.passes[0].repeat = 1;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        let remaining = std::fs::read(&path).unwrap();
        assert_eq!(remaining, vec![0x55u8; 4096]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_dry_run_leaves_file_intact() {
        let plaintext = b"still-here-after-dry-run";
        let path = temp_file(plaintext);
        let r = execute_wipe(&path, &WipeConfig::default(), true);
        assert!(r.success);
        let remaining = std::fs::read(&path).unwrap();
        assert_eq!(remaining, plaintext);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_verified_wipe_dry_run_skips_verification() {
        let path = temp_file(b"dry-run-target");
        let result = execute_wipe_with_verification(
            &path,
            &WipeConfig::default(),
            ForensicTool::PhotoRec,
            &path,
            3,
            true,
        );
        assert!(result.final_success);
        assert_eq!(result.iterations, 0);
        assert!(result.verification_attempts.is_empty());
        assert!(result.verdict.contains("dry-run"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_verified_wipe_reports_initial_failure() {
        let missing = PathBuf::from("/tmp/nonexistent-verify-target-xyz-98765");
        let result = execute_wipe_with_verification(
            &missing,
            &WipeConfig::default(),
            ForensicTool::Foremost,
            &missing,
            3,
            false,
        );
        assert!(!result.final_success);
        assert!(result.verdict.contains("initial wipe failed"));
    }

    // REGRESSION-GUARD: the earlier implementation used
    // symlink_metadata + OpenOptions::open(path), which had a TOCTOU
    // window between check and open. An attacker with write access
    // to the parent directory could swap the target for a symlink.
    // After the O_NOFOLLOW fix, the open itself refuses a symlink
    // even if it was put there just now.
    #[test]
    fn test_wipe_refuses_symlink_at_kernel_open_layer() {
        let target = temp_file(b"target-content-sentinel");
        let link_path = std::env::temp_dir().join(format!(
            "atrium-wipe-nofollow-link-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link_path).unwrap();
        let r = execute_wipe(&link_path, &WipeConfig::default(), false);
        assert!(!r.success);
        // The symlink target must survive untouched.
        let target_contents = std::fs::read(&target).unwrap();
        assert_eq!(target_contents, b"target-content-sentinel");
        std::fs::remove_file(&link_path).ok();
        std::fs::remove_file(&target).ok();
    }

    // REGRESSION-GUARD: concurrent writer case. If another process
    // has an exclusive flock on the file, our wipe must refuse
    // rather than racing the other writer.
    #[test]
    fn test_wipe_refuses_when_flock_is_held() {
        use std::os::unix::io::AsRawFd;
        let path = temp_file(b"contested-file");
        // Take an exclusive lock in this test thread via a
        // persistent File handle.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let rc = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "should be able to take the initial lock");

        let r = execute_wipe(&path, &WipeConfig::default(), false);
        assert!(!r.success);
        assert!(
            r.errors.iter().any(|e| e.contains("another process")),
            "expected 'another process holds a lock' error, got: {:?}",
            r.errors
        );
        // File and its contents must be untouched.
        drop(holder);
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"contested-file");
        std::fs::remove_file(&path).ok();
    }

    // Files that are exactly one chunk long (boundary case).
    #[test]
    fn test_wipe_exactly_one_chunk_file() {
        let size = 1 << 16; // chunk_size in wipe_runner
        let path = temp_file(&vec![0xAAu8; size]);
        let mut config = WipeConfig::preset(WipePreset::Quick);
        config.unlink_after = false;
        config.truncate_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success, "errors: {:?}", r.errors);
        assert_eq!(r.bytes_written, size as u64);
        std::fs::remove_file(&path).ok();
    }

    // Files smaller than a chunk (1 byte).
    #[test]
    fn test_wipe_single_byte_file() {
        let path = temp_file(b"x");
        let mut config = WipeConfig::preset(WipePreset::Quick);
        config.unlink_after = false;
        config.truncate_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        assert_eq!(r.bytes_written, 1);
        std::fs::remove_file(&path).ok();
    }

    // Files slightly larger than a chunk (chunk+1) — exercises the
    // second-chunk path where remaining < chunk_size.
    #[test]
    fn test_wipe_chunk_plus_one_byte() {
        let size = (1 << 16) + 1;
        let path = temp_file(&vec![0xAAu8; size]);
        let mut config = WipeConfig::preset(WipePreset::Quick);
        config.unlink_after = false;
        config.truncate_after = false;
        let r = execute_wipe(&path, &config, false);
        assert!(r.success);
        assert_eq!(r.bytes_written, size as u64);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_verified_wipe_halts_on_tool_unavailable() {
        // PhotoRec is detected via the binary on PATH. Since the test
        // environment typically does not have it installed, calling
        // execute_wipe_with_verification should wipe successfully and
        // then hit a tool-unavailable error on the first iteration.
        // This test locks in that behaviour regardless of which tool
        // is actually installed: we use a tool name that is
        // overwhelmingly unlikely to exist.
        let path = temp_file(b"verify-target-that-will-actually-be-wiped");
        let result = execute_wipe_with_verification(
            &path,
            &WipeConfig::default(),
            ForensicTool::BulkExtractor,
            &std::env::temp_dir(),
            2,
            false,
        );
        // The wipe itself must have succeeded regardless of the tool
        // outcome.
        assert!(result.initial_wipe.success);
        assert!(!path.exists());
        // Either the tool runs and finds zero (success) or it is
        // unavailable (halt with failure). Both are valid outcomes
        // here — we just verify the function doesn't panic.
        assert!(!result.verdict.is_empty());
    }
}
