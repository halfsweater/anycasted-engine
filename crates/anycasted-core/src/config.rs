//! Engine configuration and resource limits.

use serde::{Deserialize, Serialize};

use crate::errors::{EngineError, Result};

const MIB: u64 = 1024 * 1024;

/// Resource limits that protect the engine against hostile or pathological input.
///
/// All limits are enforced while streaming; none of them require the input to be
/// loaded into memory first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Maximum size of the input file as stored on disk (compressed size for `.gz`).
    /// Larger files are rejected before reading.
    pub max_file_bytes: u64,
    /// Maximum number of decompressed bytes analyzed. When reached, analysis stops and
    /// the report is marked incomplete (this is the decompression-bomb guard).
    pub max_decompressed_bytes: u64,
    /// Maximum bytes retained per physical line. Longer lines are cut and counted.
    pub max_line_bytes: usize,
    /// Maximum physical lines retained per log event (e.g. huge stack traces or thread
    /// dumps). Additional lines are counted but not stored.
    pub max_event_lines: usize,
    /// Maximum stack frames retained per exception.
    pub max_frames_per_exception: usize,
    /// Maximum number of distinct finding groups. Hits that would create more groups are
    /// counted and reported as dropped.
    pub max_finding_groups: usize,
    /// Maximum evidence entries stored per finding.
    pub max_evidence_per_finding: usize,
    /// Maximum additional occurrence line numbers stored per finding.
    pub max_sample_lines: usize,
    /// Maximum characters of a source line copied into an evidence entry.
    pub max_evidence_chars: usize,
    /// Maximum lines buffered when the input is a crash report (crash reports are
    /// parsed as a whole document).
    pub max_crash_report_lines: usize,
    /// Maximum number of plugins recorded in the server inventory.
    pub max_inventory_plugins: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * MIB,
            max_decompressed_bytes: 2048 * MIB,
            max_line_bytes: 64 * 1024,
            max_event_lines: 2_000,
            max_frames_per_exception: 256,
            max_finding_groups: 5_000,
            max_evidence_per_finding: 8,
            max_sample_lines: 20,
            max_evidence_chars: 600,
            max_crash_report_lines: 200_000,
            max_inventory_plugins: 1_024,
        }
    }
}

/// Tuning parameters for grouping and correlation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    /// A finding group with at least this many occurrences additionally produces a
    /// `PATTERN-REPEATED-ERROR` finding.
    pub repeated_error_threshold: u64,
    /// Error-level hits closer together than this (in seconds) form a temporal cluster.
    pub temporal_window_secs: u32,
    /// Errors within this many seconds before a shutdown marker are linked to it.
    pub shutdown_window_secs: u32,
    /// Fallback proximity, in lines, when timestamps are unavailable.
    pub proximity_window_lines: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            repeated_error_threshold: 25,
            temporal_window_secs: 5,
            shutdown_window_secs: 60,
            proximity_window_lines: 150,
        }
    }
}

/// Complete engine configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EngineConfig {
    /// Resource limits.
    pub limits: Limits,
    /// Grouping and correlation parameters.
    pub analysis: AnalysisConfig,
    /// Accept files whose extension is not in the allow-list (`.log`, `.txt`, `.gz`, or
    /// none). Content sniffing for binary data still applies.
    pub allow_any_extension: bool,
}

impl EngineConfig {
    /// Validates that limits are internally consistent and non-zero.
    pub fn validate(&self) -> Result<()> {
        let l = &self.limits;
        let checks: [(&str, u64); 8] = [
            ("max_file_bytes", l.max_file_bytes),
            ("max_decompressed_bytes", l.max_decompressed_bytes),
            ("max_line_bytes", l.max_line_bytes as u64),
            ("max_event_lines", l.max_event_lines as u64),
            ("max_finding_groups", l.max_finding_groups as u64),
            (
                "max_evidence_per_finding",
                l.max_evidence_per_finding as u64,
            ),
            ("max_evidence_chars", l.max_evidence_chars as u64),
            ("max_crash_report_lines", l.max_crash_report_lines as u64),
        ];
        if let Some((name, _)) = checks.iter().find(|(_, v)| *v == 0) {
            return Err(EngineError::InvalidConfig(format!(
                "{name} must be greater than zero"
            )));
        }
        if self.analysis.repeated_error_threshold < 2 {
            return Err(EngineError::InvalidConfig(
                "repeated_error_threshold must be at least 2".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        EngineConfig::default().validate().unwrap();
    }

    #[test]
    fn zero_limits_are_rejected() {
        let mut cfg = EngineConfig::default();
        cfg.limits.max_line_bytes = 0;
        assert!(cfg.validate().is_err());
    }
}
