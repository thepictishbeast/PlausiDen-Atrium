//! File manager integration — reveal and open via xdg-open.
//!
//! All functions are best-effort. They log a warning and return if
//! the desktop environment doesn't support the operation.

use std::path::Path;
use std::process::Command;

/// Open the file's containing directory in the user's file manager.
pub fn reveal_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    Command::new("xdg-open")
        .arg(parent)
        .spawn()
        .map(|_| ())
}

/// Ask the desktop to open the file itself via its default handler.
pub fn open_file(path: &Path) -> std::io::Result<()> {
    Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map(|_| ())
}

/// Copy a string to the X11/Wayland clipboard via `wl-copy` or
/// `xclip`. Returns `Ok(())` on best-effort success.
pub fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    // Prefer wl-copy on Wayland sessions.
    if std::env::var("WAYLAND_DISPLAY").is_ok()
        && let Ok(mut child) = Command::new("wl-copy").stdin(std::process::Stdio::piped()).spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
        return Ok(());
    }

    // Fallback to xclip.
    if let Ok(mut child) = Command::new("xclip")
        .arg("-selection")
        .arg("clipboard")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
        return Ok(());
    }

    Err(std::io::Error::other(
        "no clipboard helper found (install wl-clipboard or xclip)",
    ))
}
