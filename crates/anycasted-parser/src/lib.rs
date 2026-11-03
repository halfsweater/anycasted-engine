//! Parsing pipeline: physical lines → normalized [`LogEvent`]s / [`CrashReport`]s.
//!
//! * [`minecraft`] — log line header parsing (timestamp, level, thread, logger).
//! * [`java`] — exception headers, stack frames and `Caused by:` chains.
//! * [`EventBuilder`] — multi-line grouping into events.
//! * [`FormatDetector`] — server software identification.
//! * [`ServerProfiler`] — versions, plugin inventory, lifecycle markers.
//! * [`velocity`] — Velocity proxy specifics.
//! * [`crash_report`] — Minecraft crash report parsing.
//!
//! [`LogEvent`]: anycasted_core::models::LogEvent
//! [`CrashReport`]: anycasted_core::models::CrashReport

pub mod crash_report;
mod event_builder;
mod format;
pub mod java;
mod metadata;
pub mod minecraft;
pub mod velocity;

pub use crash_report::{CRASH_REPORT_MARKER, looks_like_crash_report, parse_crash_report};
pub use event_builder::{EventBuilder, ParseStats};
pub use format::FormatDetector;
pub use metadata::{LifecycleSignal, ServerProfiler};
