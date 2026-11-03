//! Findings and evidence.

use std::fmt;

use serde::Serialize;

use super::event::Timestamp;

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no action required.
    Info,
    /// Degraded behavior or a problem that may become serious.
    Warning,
    /// A component failed; functionality is likely broken.
    Error,
    /// The server crashed, could not start, or is about to fail.
    Critical,
}

impl Severity {
    /// All severities from most to least severe.
    pub const DESCENDING: [Severity; 4] = [Self::Critical, Self::Error, Self::Warning, Self::Info];

    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// One level lower (saturating at `Info`).
    pub fn downgrade(self) -> Self {
        match self {
            Self::Critical => Self::Error,
            Self::Error => Self::Warning,
            Self::Warning | Self::Info => Self::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Diagnostic category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Java runtime exceptions.
    Exception,
    /// Heap / native memory exhaustion.
    Memory,
    /// Class-loading and linkage failures (missing or incompatible libraries/plugins).
    Dependency,
    /// Plugin lifecycle and plugin-reported failures.
    Plugin,
    /// Server startup failures.
    Startup,
    /// Invalid or corrupted configuration.
    Configuration,
    /// Network and proxy communication.
    Networking,
    /// Database connectivity and credentials.
    Database,
    /// Tick lag, watchdog and other performance problems.
    Performance,
    /// Shutdown failures.
    Shutdown,
    /// World, chunk and data pack loading/saving.
    Resource,
    /// Server crashes and crash reports.
    Crash,
    /// Cross-event patterns (repetition).
    Pattern,
}

impl Category {
    /// snake_case name, used as the finding id prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exception => "exception",
            Self::Memory => "memory",
            Self::Dependency => "dependency",
            Self::Plugin => "plugin",
            Self::Startup => "startup",
            Self::Configuration => "configuration",
            Self::Networking => "networking",
            Self::Database => "database",
            Self::Performance => "performance",
            Self::Shutdown => "shutdown",
            Self::Resource => "resource",
            Self::Crash => "crash",
            Self::Pattern => "pattern",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Epistemic status of a finding or implication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// The condition is directly visible in the input (an exception was thrown, the
    /// server printed a failure message).
    Observed,
    /// Evidence suggests the condition contributed to a problem, but the input does not
    /// prove it (e.g. a nearly full heap at the time of a crash).
    LikelyContributing,
    /// A plausible explanation that the input does not confirm (e.g. a plugin appears
    /// in a stack trace).
    Hypothesis,
}

/// Plain-language rendering of a confidence value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLabel {
    /// Confidence below 0.5: offered for investigation.
    Speculative,
    /// 0.5 to below 0.75.
    Possible,
    /// 0.75 to below 0.95.
    Likely,
    /// 0.95 and above: an unambiguous signature.
    Certain,
}

impl ConfidenceLabel {
    /// Maps a confidence value to its label.
    pub fn from_confidence(confidence: f32) -> Self {
        match confidence {
            c if c >= 0.95 => Self::Certain,
            c if c >= 0.75 => Self::Likely,
            c if c >= 0.5 => Self::Possible,
            _ => Self::Speculative,
        }
    }

    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Speculative => "speculative",
            Self::Possible => "possible",
            Self::Likely => "likely",
            Self::Certain => "certain",
        }
    }
}

/// Role of an evidence line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    /// The log line on which the condition was detected.
    Match,
    /// The header line of the event that contains the match.
    LogEntry,
    /// The outermost exception of a chain.
    Exception,
    /// The innermost cause of a chain.
    RootCause,
    /// A representative stack frame.
    StackFrame,
    /// A crash report field.
    CrashDetail,
    /// A later occurrence of the same finding.
    LastOccurrence,
    /// A later line showing the problem resolved itself.
    Recovery,
    /// Surrounding context (e.g. a shutdown marker, a format indicator).
    Context,
}

/// A verbatim excerpt from the input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// 1-based line number in the (decompressed) input.
    pub line: u64,
    /// Line text as decoded (see [`super::SourceLine`]), possibly shortened with `…`.
    pub text: String,
    /// Role of this line.
    pub role: EvidenceRole,
    /// Timestamp of the event the line belongs to, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

/// Where and when a finding occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Occurrence {
    /// First line of the event in which the finding was detected.
    pub line: u64,
    /// Event timestamp, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

/// What a finding is about, as stated explicitly by the input.
///
/// `plugin` is only set when the log itself names the plugin (its logger tag, or a
/// server message such as `Error occurred while enabling Foo`). It is never inferred
/// from stack frames; see [`Implication`] for that.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Subject {
    /// Plugin explicitly named by the log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Logger name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// Thread name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// Exception class most relevant to the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_class: Option<String>,
    /// Rule-specific detail (missing class, port, config file, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Subject {
    /// Whether no field is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Why a component is implicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplicationBasis {
    /// The component's archive appears in stack frames.
    StackFrame,
    /// A missing/affected class belongs to a package known to ship with the component.
    ClassPackage,
    /// The log message names the component explicitly.
    LogMessage,
    /// The crash report lists the component under "Suspected Mods".
    CrashReportSuspect,
}

/// A component (plugin, mod, jar) related to a finding, with the basis for the link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Implication {
    /// Component name.
    pub name: String,
    /// Basis for the link.
    pub basis: ImplicationBasis,
    /// Observed (named by the log) or hypothesis (inferred).
    pub classification: Classification,
    /// Whether the component was seen loading in the same log; `None` when the log has
    /// no plugin inventory to compare against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_loading: Option<bool>,
}

/// Repetition statistics for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Repetition {
    /// Seconds between first and last occurrence, when timestamps are available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_seconds: Option<f64>,
    /// Average occurrences per minute over the span.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_minute: Option<f64>,
}

/// A grouped, evidence-backed diagnostic finding.
///
/// User-facing fields (`title`, `explanation`, `recommendations`) are written for
/// server owners and filled with names from the log. Technical fields
/// (`technical_title`, `description`, `rule_id`, `subject`, `evidence`) are for support
/// staff and integrations.
///
/// ## Confidence
///
/// `confidence` (0.0-1.0) is the engine's confidence that the condition described by
/// the finding is present in the input. It is **not** a probability that the finding
/// caused an outage. `confidence_label` is its plain-language form:
///
/// * `certain` (≥ 0.95) — an unambiguous signature (exception class, exact server message).
/// * `likely` (≥ 0.75) — a strong but not exclusive textual signature.
/// * `possible` (≥ 0.5) — a heuristic (e.g. a missing completion marker; a nearly full heap).
/// * `speculative` (< 0.5) — a hypothesis offered for investigation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Report-unique id, `<category>-<nnn>`.
    pub id: String,
    /// Id of the rule that produced the finding.
    pub rule_id: String,
    /// Category.
    pub category: Category,
    /// Severity.
    pub severity: Severity,
    /// Observed / likely contributing / hypothesis.
    pub classification: Classification,
    /// Plain-language title naming the affected component.
    pub title: String,
    /// Plain-language explanation of what happened and what it affects.
    pub explanation: String,
    /// Plain-language, ordered fix steps.
    pub recommendations: Vec<String>,
    /// Technical title (rule title plus subject).
    pub technical_title: String,
    /// Technical description of the rule.
    pub description: String,
    /// See the type-level documentation.
    pub confidence: f32,
    /// Plain-language confidence.
    pub confidence_label: ConfidenceLabel,
    /// Number of log entries in which the finding was detected.
    pub occurrences: u64,
    /// First occurrence.
    pub first_seen: Occurrence,
    /// Last occurrence.
    pub last_seen: Occurrence,
    /// Repetition statistics (only when `occurrences > 1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<Repetition>,
    /// A later line showing the problem resolved itself (severity is then lowered by
    /// one level).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered: Option<Evidence>,
    /// Verbatim evidence lines, starting with the first occurrence.
    pub evidence: Vec<Evidence>,
    /// Line numbers of further occurrences (bounded sample).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other_occurrence_lines: Vec<u64>,
    /// What the finding is about, as stated by the input.
    #[serde(skip_serializing_if = "Subject::is_empty")]
    pub subject: Subject,
    /// Components linked to the finding, with the basis for each link.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub implicated: Vec<Implication>,
    /// Stable fingerprint of the rule + grouping key.
    pub fingerprint: String,
    /// Technical notes produced during detection/analysis.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Ids of correlated findings (see `correlations`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}
