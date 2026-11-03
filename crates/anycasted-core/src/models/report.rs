//! The versioned diagnostic report.

use serde::Serialize;

use super::crash::{Located, MemoryInfo};
use super::finding::{Evidence, Finding, Severity};
use super::format::{FormatConfidence, LogFormat};

/// Engine identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineInfo {
    /// Engine name.
    pub name: String,
    /// Engine version.
    pub version: String,
}

/// Facts about the analyzed input.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputInfo {
    /// File name (no directory components).
    pub filename: String,
    /// Identified format.
    pub format: LogFormat,
    /// Confidence of the identification.
    pub format_confidence: FormatConfidence,
    /// `true` when the format could not be identified with high confidence.
    pub format_uncertain: bool,
    /// Lines that identified the format.
    pub format_indicators: Vec<Evidence>,
    /// Compression of the input (`none`, `gzip`).
    pub compression: String,
    /// Bytes analyzed (after decompression).
    pub bytes_processed: u64,
    /// Physical lines analyzed.
    pub lines_processed: u64,
    /// Log events built from the lines.
    pub events_parsed: u64,
    /// Lines that did not match a known log line format.
    pub unstructured_lines: u64,
    /// Lines containing invalid UTF-8 (decoded lossily).
    pub invalid_utf8_lines: u64,
    /// Lines longer than the configured limit (cut).
    pub overlong_lines: u64,
    /// `false` if analysis stopped early (size limit, read error); findings then cover
    /// only the analyzed prefix.
    pub complete: bool,
    /// Non-fatal problems encountered while reading the input.
    pub warnings: Vec<String>,
}

/// A plugin seen loading in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginRecord {
    /// Plugin name.
    pub name: String,
    /// Version, when printed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Line where the plugin was first seen loading.
    pub line: u64,
}

/// Server facts extracted from a log.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ServerInfo {
    /// Server software name as printed (`Paper`, `Purpur`, `Velocity`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Located<String>>,
    /// Server software version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// Minecraft version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_version: Option<Located<String>>,
    /// Java runtime description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<Located<String>>,
    /// Operating system description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<Located<String>>,
    /// Address the server listens on (`Starting Minecraft server on ...`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<Located<String>>,
    /// Line where startup began, when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_started_line: Option<u64>,
    /// Whether the startup completion marker (`Done (...)!`) was observed. `None` when
    /// the log does not contain a startup sequence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_completed: Option<bool>,
    /// Startup duration reported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_seconds: Option<f64>,
    /// Lines of shutdown markers (`Stopping server`, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shutdown_lines: Vec<u64>,
    /// Plugins seen loading.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<PluginRecord>,
}

/// Exception summary used in crash report info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExceptionInfo {
    /// Outermost exception class.
    pub class: String,
    /// Outermost exception message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Line of the outermost exception.
    pub line: u64,
    /// Root cause class, when different from `class`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<String>,
}

/// Crash report facts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CrashReportInfo {
    /// `Description:`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Located<String>>,
    /// `Time:`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<Located<String>>,
    /// `Minecraft Version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_version: Option<Located<String>>,
    /// `Java Version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<Located<String>>,
    /// `Operating System`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<Located<String>>,
    /// Server brand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_brand: Option<Located<String>>,
    /// JVM flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jvm_flags: Option<Located<String>>,
    /// Heap figures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryInfo>,
    /// Main exception.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<ExceptionInfo>,
    /// Suspected mods as listed by the crash report (unconfirmed by definition).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suspected_mods: Vec<Located<String>>,
    /// Plugins listed in the crash report.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<String>,
    /// Section names with their header lines.
    pub sections: Vec<Located<String>>,
}

/// Overall health classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// No findings above `info`.
    Healthy,
    /// Highest severity is `warning`.
    Degraded,
    /// Highest severity is `error`.
    Failing,
    /// At least one `critical` finding.
    Critical,
}

/// Finding counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Overall status.
    pub status: HealthStatus,
    /// Highest severity, or `null` when there are no findings.
    pub highest_severity: Option<Severity>,
    /// Number of findings.
    pub total_findings: usize,
    /// Critical findings.
    pub critical: usize,
    /// Error findings.
    pub error: usize,
    /// Warning findings.
    pub warning: usize,
    /// Info findings.
    pub info: usize,
    /// Detection hits that could not be stored because the group limit was reached.
    pub dropped_hits: u64,
}

/// Kind of correlation between findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    /// Detected in the same log event (e.g. a plugin enable failure and the exception it
    /// printed).
    SameEvent,
    /// Error-level findings occurring within a short time window.
    TemporalCluster,
    /// Error-level findings occurring shortly before a shutdown marker.
    PrecededShutdown,
    /// Critical findings close to the end of the log.
    NearEndOfLog,
    /// Findings explicitly attributed to the same plugin.
    SamePlugin,
}

impl CorrelationKind {
    /// snake_case name (as serialized).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameEvent => "same_event",
            Self::TemporalCluster => "temporal_cluster",
            Self::PrecededShutdown => "preceded_shutdown",
            Self::NearEndOfLog => "near_end_of_log",
            Self::SamePlugin => "same_plugin",
        }
    }
}

/// A relationship between findings.
///
/// Correlations record co-occurrence. Except for `same_event`, they do not establish
/// causation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Correlation {
    /// Report-unique id.
    pub id: String,
    /// Kind.
    pub kind: CorrelationKind,
    /// Finding ids involved.
    pub findings: Vec<String>,
    /// Explanation.
    pub description: String,
    /// Supporting lines.
    pub evidence: Vec<Evidence>,
}

/// A complete diagnostic report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// Report schema version (see `REPORT_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Engine identification.
    pub engine: EngineInfo,
    /// Input facts.
    pub input: InputInfo,
    /// Server facts (log inputs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerInfo>,
    /// Crash report facts (crash report inputs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_report: Option<CrashReportInfo>,
    /// Counts.
    pub summary: Summary,
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
    /// Relationships between findings.
    pub correlations: Vec<Correlation>,
}
