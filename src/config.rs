//! Persistent configuration for Atrium.

use crate::theme::ThemeMode;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtriumConfig {
    #[serde(default)]
    pub theme: ThemeMode,
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default = "default_dry_run_locked")]
    pub dry_run_locked: bool,
}

fn default_dry_run_locked() -> bool {
    true
}

impl Default for AtriumConfig {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Auto,
            protected_paths: Vec::new(),
            dry_run_locked: true,
        }
    }
}

impl AtriumConfig {
    pub fn config_path() -> Option<PathBuf> {
        ProjectDirs::from("org", "plausiden", "atrium").map(|d| {
            let dir = d.config_dir().to_path_buf();
            let _ = std::fs::create_dir_all(&dir);
            dir.join("config.json")
        })
    }

    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| Self::default()),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = Self::config_path() else {
            return Err(std::io::Error::other("no config dir"));
        };
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_dry_run_locked() {
        let c = AtriumConfig::default();
        assert!(c.dry_run_locked);
    }

    #[test]
    fn test_default_theme_is_auto() {
        let c = AtriumConfig::default();
        assert_eq!(c.theme, ThemeMode::Auto);
    }

    #[test]
    fn test_serde_roundtrip() {
        let c = AtriumConfig {
            theme: ThemeMode::Dark,
            protected_paths: vec!["/a".into(), "/b".into()],
            dry_run_locked: false,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: AtriumConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.theme, ThemeMode::Dark);
        assert_eq!(back.protected_paths.len(), 2);
        assert!(!back.dry_run_locked);
    }
}
