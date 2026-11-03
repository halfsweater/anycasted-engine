//! Core types shared by every stage of the Anycasted Diagnostics Engine.
//!
//! This crate deliberately contains no I/O and no detection logic. It defines:
//!
//! * the normalized event model produced by the parser ([`models::LogEvent`],
//!   [`models::ExceptionChain`], [`models::CrashReport`]),
//! * the detection vocabulary ([`models::RuleMeta`], [`models::Hit`]),
//! * the versioned report schema ([`models::Report`]),
//! * resource limits and configuration ([`EngineConfig`], [`Limits`]),
//! * the error type ([`EngineError`]),
//! * small text utilities used for stable fingerprints ([`text`]).

pub mod config;
pub mod errors;
pub mod models;
pub mod text;

pub use config::{AnalysisConfig, EngineConfig, Limits};
pub use errors::{EngineError, Result};

/// Human-readable engine name, embedded in every report.
pub const ENGINE_NAME: &str = "Anycasted Diagnostics Engine";

/// Engine version, embedded in every report.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the JSON report schema.
///
/// Bump the major component for breaking changes (removed/renamed fields or changed
/// semantics), the minor component for additive changes.
pub const REPORT_SCHEMA_VERSION: &str = "2.0.0";
