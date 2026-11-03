//! Normalized data models.

mod crash;
mod event;
mod finding;
mod format;
mod java;
mod report;
mod rule;

pub use crash::{CrashDetail, CrashReport, CrashSection, Located, MemoryInfo};
pub use event::{
    CalendarDate, ContentKind, LogEvent, LogHeader, LogLevel, SourceLine, TimeOfDay, Timestamp,
};
pub use finding::{
    Category, Classification, ConfidenceLabel, Evidence, EvidenceRole, Finding, Implication,
    ImplicationBasis, Occurrence, Repetition, Severity, Subject,
};
pub use format::{FormatConfidence, FormatDetection, LogFormat};
pub use java::{ExceptionChain, StackFrame, ThrowableRelation, ThrownException, simple_class_name};
pub use report::{
    Correlation, CorrelationKind, CrashReportInfo, EngineInfo, ExceptionInfo, HealthStatus,
    InputInfo, PluginRecord, Report, ServerInfo, Summary,
};
pub use rule::{Hit, RuleMeta, RuleRole, TemplateVars};
