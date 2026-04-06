//! Formatting helpers — byte sizes, file counts, durations, relative paths.

use std::path::{Path, PathBuf};

/// Human-readable byte formatter.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// Short file-count formatter.
pub fn format_count(n: u64) -> String {
    if n < 1_000 {
        format!("{}", n)
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

/// Duration unit for typed duration inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DurationUnit {
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

impl DurationUnit {
    pub const ALL: [DurationUnit; 6] = [
        DurationUnit::Minutes,
        DurationUnit::Hours,
        DurationUnit::Days,
        DurationUnit::Weeks,
        DurationUnit::Months,
        DurationUnit::Years,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            DurationUnit::Minutes => "minutes",
            DurationUnit::Hours => "hours",
            DurationUnit::Days => "days",
            DurationUnit::Weeks => "weeks",
            DurationUnit::Months => "months",
            DurationUnit::Years => "years",
        }
    }

    pub fn days_per_unit(&self) -> f64 {
        match self {
            DurationUnit::Minutes => 1.0 / 1440.0,
            DurationUnit::Hours => 1.0 / 24.0,
            DurationUnit::Days => 1.0,
            DurationUnit::Weeks => 7.0,
            DurationUnit::Months => 30.4375,
            DurationUnit::Years => 365.25,
        }
    }
}

/// Typed duration — amount + unit, convertible to days for the analyzer.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TypedDuration {
    pub amount: i64,
    pub unit: DurationUnit,
}

impl TypedDuration {
    pub const fn new(amount: i64, unit: DurationUnit) -> Self {
        Self { amount, unit }
    }

    pub fn to_days(&self) -> i64 {
        (self.amount as f64 * self.unit.days_per_unit()).round() as i64
    }

    #[allow(dead_code)]
    pub fn describe(&self) -> String {
        format!("{} {}", self.amount, self.unit.label())
    }
}

impl Default for TypedDuration {
    fn default() -> Self {
        Self::new(1, DurationUnit::Years)
    }
}

/// Render a path relative to a known scan root. Returns the relative
/// portion if the path is inside the root, or a short pretty-print
/// of the full path otherwise.
pub fn relative_to_root<'a>(path: &'a Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => {
            let s = rel.to_string_lossy().to_string();
            if s.is_empty() { ".".into() } else { s }
        }
        Err(_) => path.to_string_lossy().to_string(),
    }
}

/// Split a path into a leading directory and a file name, both
/// pre-rendered. Used for two-column table displays.
pub fn split_dir_and_name(rel: &str) -> (String, String) {
    let pb = PathBuf::from(rel);
    let name = pb
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let dir = pb
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    (dir, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_1kb() {
        assert_eq!(format_bytes(1024), "1.00 KB");
    }

    #[test]
    fn test_format_bytes_1gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_count_small() {
        assert_eq!(format_count(7), "7");
    }

    #[test]
    fn test_format_count_thousands() {
        assert_eq!(format_count(2_500), "2.5K");
    }

    #[test]
    fn test_duration_years_to_days() {
        let d = TypedDuration::new(1, DurationUnit::Years);
        assert_eq!(d.to_days(), 365);
    }

    #[test]
    fn test_duration_minutes_to_days_floor() {
        let d = TypedDuration::new(30, DurationUnit::Minutes);
        assert_eq!(d.to_days(), 0);
    }

    #[test]
    fn test_duration_weeks() {
        let d = TypedDuration::new(4, DurationUnit::Weeks);
        assert_eq!(d.to_days(), 28);
    }

    #[test]
    fn test_duration_describe() {
        let d = TypedDuration::new(30, DurationUnit::Days);
        assert_eq!(d.describe(), "30 days");
    }

    #[test]
    fn test_relative_to_root_inside() {
        let rel = relative_to_root(
            Path::new("/home/u/Downloads/sub/file.iso"),
            Path::new("/home/u/Downloads"),
        );
        assert_eq!(rel, "sub/file.iso");
    }

    #[test]
    fn test_relative_to_root_outside() {
        let rel = relative_to_root(Path::new("/etc/passwd"), Path::new("/home/u"));
        assert_eq!(rel, "/etc/passwd");
    }

    #[test]
    fn test_relative_to_root_equal() {
        let rel = relative_to_root(Path::new("/a/b"), Path::new("/a/b"));
        assert_eq!(rel, ".");
    }

    #[test]
    fn test_split_dir_and_name() {
        let (dir, name) = split_dir_and_name("sub/path/file.txt");
        assert_eq!(dir, "sub/path");
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn test_split_dir_and_name_root_only() {
        let (dir, name) = split_dir_and_name("file.txt");
        assert_eq!(dir, "");
        assert_eq!(name, "file.txt");
    }
}
