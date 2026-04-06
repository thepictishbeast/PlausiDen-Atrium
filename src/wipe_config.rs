#![allow(dead_code)]
//! Wipe configuration — composable overwrite algorithms and presets.
//!
//! Tidy's `ActionKind::SecurePurge` is only a tag; the actual
//! destruction logic lives here and is executed by a Purge-aware
//! runner that Atrium builds. A `WipeConfig` is an ordered list of
//! `WipePass`es, each selecting an algorithm and (optionally) a
//! repeat count. This lets users compose arbitrary multi-pass wipes
//! out of the standard primitives — for example, a Gutmann pass
//! followed by a ChaCha20 stream overwrite followed by an
//! all-zeros verify pass.

use serde::{Deserialize, Serialize};

/// Individual overwrite algorithm, applied once per pass. Verified
/// presets (DoD, Gutmann, Schneier) are represented as *sequences*
/// of these primitives in `WipePreset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeAlgorithm {
    /// Single pass of all-zero bytes.
    Zeros,
    /// Single pass of all-one bytes (0xFF).
    Ones,
    /// Single pass of a fixed repeating byte (`Pattern(value)`).
    Pattern(u8),
    /// Single pass of cryptographic random bytes.
    Random,
    /// Single pass of a ChaCha20 keystream derived from an ephemeral
    /// key that is zeroized as soon as the write completes.
    ChaCha20Stream,
    /// Single pass with the bitwise complement of whatever was read.
    Complement,
    /// Verify pass — re-read the file and check it still contains
    /// only the last-written pattern (best-effort on SSD).
    Verify,
}

impl WipeAlgorithm {
    pub fn name(&self) -> String {
        match self {
            WipeAlgorithm::Zeros => "Zeros".into(),
            WipeAlgorithm::Ones => "Ones".into(),
            WipeAlgorithm::Pattern(b) => format!("Pattern 0x{:02X}", b),
            WipeAlgorithm::Random => "Random".into(),
            WipeAlgorithm::ChaCha20Stream => "ChaCha20 stream".into(),
            WipeAlgorithm::Complement => "Complement".into(),
            WipeAlgorithm::Verify => "Verify".into(),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            WipeAlgorithm::Zeros => "Write 0x00 over every byte.",
            WipeAlgorithm::Ones => "Write 0xFF over every byte.",
            WipeAlgorithm::Pattern(_) => "Write a fixed repeating byte value.",
            WipeAlgorithm::Random => "Write cryptographic random bytes (getrandom).",
            WipeAlgorithm::ChaCha20Stream => {
                "Write ChaCha20 keystream; key is zeroized the instant the pass finishes."
            }
            WipeAlgorithm::Complement => "Write the bitwise complement of the prior contents.",
            WipeAlgorithm::Verify => {
                "Re-read the file and confirm the previous pass is in place."
            }
        }
    }

    pub const ALL: &'static [WipeAlgorithm] = &[
        WipeAlgorithm::Zeros,
        WipeAlgorithm::Ones,
        WipeAlgorithm::Random,
        WipeAlgorithm::ChaCha20Stream,
        WipeAlgorithm::Complement,
        WipeAlgorithm::Verify,
    ];
}

/// One pass in a wipe configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipePass {
    pub algorithm: WipeAlgorithm,
    /// How many times to repeat this exact pass before moving on.
    pub repeat: u32,
}

impl WipePass {
    pub fn new(algorithm: WipeAlgorithm) -> Self {
        Self {
            algorithm,
            repeat: 1,
        }
    }
}

/// An ordered wipe recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeConfig {
    pub passes: Vec<WipePass>,
    pub truncate_after: bool,
    pub unlink_after: bool,
    pub fsync_between_passes: bool,
    pub verify_with_forensics: bool,
    pub max_repurge_iterations: u32,
}

impl Default for WipeConfig {
    fn default() -> Self {
        Self::preset(WipePreset::CryptoShred)
    }
}

impl WipeConfig {
    pub fn preset(preset: WipePreset) -> Self {
        let passes = match preset {
            WipePreset::Quick => vec![WipePass::new(WipeAlgorithm::Random)],
            WipePreset::DoD3Pass => vec![
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Complement),
                WipePass::new(WipeAlgorithm::Random),
            ],
            WipePreset::DoD7Pass => vec![
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Complement),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Zeros),
                WipePass::new(WipeAlgorithm::Ones),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Verify),
            ],
            WipePreset::Gutmann => {
                // Gutmann's classic 35-pass sequence for old magnetic media.
                // For most modern drives this is overkill; included for completeness.
                let mut v = Vec::new();
                // 4 passes of random
                for _ in 0..4 {
                    v.push(WipePass::new(WipeAlgorithm::Random));
                }
                // 27 fixed patterns chosen against MFM/RLL encodings
                let patterns: [u8; 27] = [
                    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                    0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB,
                ];
                for p in patterns {
                    v.push(WipePass::new(WipeAlgorithm::Pattern(p)));
                }
                // 4 passes of random
                for _ in 0..4 {
                    v.push(WipePass::new(WipeAlgorithm::Random));
                }
                v
            }
            WipePreset::Schneier7Pass => vec![
                WipePass::new(WipeAlgorithm::Zeros),
                WipePass::new(WipeAlgorithm::Ones),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Random),
            ],
            WipePreset::CryptoShred => vec![WipePass::new(WipeAlgorithm::ChaCha20Stream)],
            WipePreset::Paranoid => vec![
                // Composition: DoD-3 followed by a ChaCha20 pass and a
                // final zero pass. This is the "belt and suspenders"
                // option — overkill, but available.
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::Complement),
                WipePass::new(WipeAlgorithm::Random),
                WipePass::new(WipeAlgorithm::ChaCha20Stream),
                WipePass::new(WipeAlgorithm::Zeros),
                WipePass::new(WipeAlgorithm::Verify),
            ],
            WipePreset::Custom => vec![WipePass::new(WipeAlgorithm::Random)],
        };
        Self {
            passes,
            truncate_after: true,
            unlink_after: true,
            fsync_between_passes: true,
            verify_with_forensics: false,
            max_repurge_iterations: 3,
        }
    }

    pub fn total_passes(&self) -> usize {
        self.passes.iter().map(|p| p.repeat as usize).sum()
    }

    pub fn add_pass(&mut self, algorithm: WipeAlgorithm) {
        self.passes.push(WipePass::new(algorithm));
    }

    pub fn remove_pass(&mut self, idx: usize) {
        if idx < self.passes.len() {
            self.passes.remove(idx);
        }
    }

    pub fn move_pass_up(&mut self, idx: usize) {
        if idx > 0 && idx < self.passes.len() {
            self.passes.swap(idx, idx - 1);
        }
    }

    pub fn move_pass_down(&mut self, idx: usize) {
        if idx + 1 < self.passes.len() {
            self.passes.swap(idx, idx + 1);
        }
    }
}

/// Well-known preset recipes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipePreset {
    Quick,
    DoD3Pass,
    DoD7Pass,
    Gutmann,
    Schneier7Pass,
    CryptoShred,
    Paranoid,
    Custom,
}

impl WipePreset {
    pub const ALL: &'static [WipePreset] = &[
        WipePreset::Quick,
        WipePreset::CryptoShred,
        WipePreset::DoD3Pass,
        WipePreset::DoD7Pass,
        WipePreset::Schneier7Pass,
        WipePreset::Gutmann,
        WipePreset::Paranoid,
        WipePreset::Custom,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            WipePreset::Quick => "Quick (1 pass random)",
            WipePreset::DoD3Pass => "DoD 5220.22-M (3 pass)",
            WipePreset::DoD7Pass => "DoD ECE (7 pass)",
            WipePreset::Gutmann => "Gutmann (35 pass)",
            WipePreset::Schneier7Pass => "Schneier (7 pass)",
            WipePreset::CryptoShred => "Crypto-shred (1 pass + key destroy)",
            WipePreset::Paranoid => "Paranoid (DoD3 + crypto + zero + verify)",
            WipePreset::Custom => "Custom",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            WipePreset::Quick => "A single cryptographic random overwrite. Fastest option.",
            WipePreset::DoD3Pass => {
                "Department of Defense 5220.22-M: random / complement / random."
            }
            WipePreset::DoD7Pass => {
                "DoD ECE extended clear and erase, seven passes with verification."
            }
            WipePreset::Gutmann => {
                "Peter Gutmann's 35-pass sequence. Historical; overkill for modern drives."
            }
            WipePreset::Schneier7Pass => "Bruce Schneier's 7-pass sequence, simple and well-known.",
            WipePreset::CryptoShred => {
                "Single pass of ChaCha20 ciphertext with a key destroyed on completion. The right choice on SSD/VPS/COW."
            }
            WipePreset::Paranoid => {
                "Compose everything: DoD-3, ChaCha20 stream, zero pass, final verify. Defense in depth."
            }
            WipePreset::Custom => "Build your own sequence pass by pass.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_have_labels() {
        for preset in WipePreset::ALL {
            assert!(!preset.label().is_empty());
            assert!(!preset.description().is_empty());
        }
    }

    #[test]
    fn test_quick_preset_one_pass() {
        let c = WipeConfig::preset(WipePreset::Quick);
        assert_eq!(c.passes.len(), 1);
    }

    #[test]
    fn test_dod3_preset_three_passes() {
        let c = WipeConfig::preset(WipePreset::DoD3Pass);
        assert_eq!(c.passes.len(), 3);
    }

    #[test]
    fn test_gutmann_is_35_passes() {
        let c = WipeConfig::preset(WipePreset::Gutmann);
        assert_eq!(c.passes.len(), 35);
    }

    #[test]
    fn test_schneier_is_7_passes() {
        let c = WipeConfig::preset(WipePreset::Schneier7Pass);
        assert_eq!(c.passes.len(), 7);
    }

    #[test]
    fn test_add_pass() {
        let mut c = WipeConfig::preset(WipePreset::Quick);
        c.add_pass(WipeAlgorithm::Zeros);
        assert_eq!(c.passes.len(), 2);
    }

    #[test]
    fn test_remove_pass() {
        let mut c = WipeConfig::preset(WipePreset::DoD3Pass);
        c.remove_pass(0);
        assert_eq!(c.passes.len(), 2);
    }

    #[test]
    fn test_move_pass_up_and_down() {
        let mut c = WipeConfig::preset(WipePreset::DoD3Pass);
        let first = c.passes[0].algorithm;
        c.move_pass_down(0);
        assert_eq!(c.passes[1].algorithm, first);
        c.move_pass_up(1);
        assert_eq!(c.passes[0].algorithm, first);
    }

    #[test]
    fn test_total_passes_honours_repeat() {
        let mut c = WipeConfig::preset(WipePreset::Quick);
        c.passes[0].repeat = 5;
        assert_eq!(c.total_passes(), 5);
    }

    #[test]
    fn test_default_is_crypto_shred() {
        let c = WipeConfig::default();
        assert_eq!(c.passes[0].algorithm, WipeAlgorithm::ChaCha20Stream);
    }

    #[test]
    fn test_algorithm_descriptions_nonempty() {
        for algo in WipeAlgorithm::ALL {
            assert!(!algo.name().is_empty());
            assert!(!algo.description().is_empty());
        }
    }

    #[test]
    fn test_paranoid_has_verify() {
        let c = WipeConfig::preset(WipePreset::Paranoid);
        assert!(c.passes.iter().any(|p| p.algorithm == WipeAlgorithm::Verify));
    }

    #[test]
    fn test_serde_roundtrip() {
        let c = WipeConfig::preset(WipePreset::DoD7Pass);
        let s = serde_json::to_string(&c).unwrap();
        let back: WipeConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.passes.len(), c.passes.len());
    }
}
