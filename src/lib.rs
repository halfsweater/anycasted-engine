//! # Anycasted Diagnostics Engine
//!
//! Evidence-backed diagnostics for Minecraft server logs and crash reports.
//!
//! ```no_run
//! use anycasted_engine::{Engine, EngineConfig};
//!
//! let engine = Engine::new(EngineConfig::default())?;
//! let report = engine.analyze_path("logs/latest.log".as_ref())?;
//! for finding in &report.findings {
//!     println!("{} {} ({} occurrences)", finding.severity, finding.title, finding.occurrences);
//! }
//! # Ok::<(), anycasted_engine::EngineError>(())
//! ```
//!
//! The pipeline is single-pass and streaming:
//!
//! ```text
//! ingestion ──▶ parser ──▶ detection ──▶ analysis ──▶ report
//! (bounded      (headers,   (rules →      (grouping,
//!  lines, gzip)  stack       hits with     correlation,
//!                traces)     evidence)     scoring)
//! ```
//!
//! Memory use is bounded by the configured [`Limits`], not by input size.

mod pipeline;

pub use anycasted_analysis as analysis;
pub use anycasted_core as core;
pub use anycasted_core::models::Report;
pub use anycasted_core::{EngineConfig, EngineError, Limits, Result};
pub use anycasted_detection as detection;
pub use anycasted_ingestion as ingestion;
pub use anycasted_parser as parser;
pub use anycasted_reports as reports;
pub use pipeline::Engine;
