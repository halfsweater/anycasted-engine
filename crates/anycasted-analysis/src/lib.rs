//! Analysis: turns a stream of detection hits into grouped, correlated, ranked findings.
//!
//! * [`patterns`] — grouping by rule + fingerprint, repetition detection.
//! * [`correlation`] — same-event, temporal, shutdown-proximity and same-plugin links.
//! * [`scoring`] — severity aggregation, ordering, ids and final [`Finding`]s.
//!
//! [`Finding`]: anycasted_core::models::Finding

pub mod correlation;
pub mod patterns;
pub mod scoring;

pub use correlation::{CorrelationDraft, Correlator};
pub use patterns::{Aggregation, Aggregator, Group, REPEATED_ERROR_ID};
pub use scoring::{assemble, summarize};
