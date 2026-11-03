//! Error type for engine operations.
//!
//! Only conditions that prevent an analysis from producing a report are errors.
//! Recoverable input problems (invalid UTF-8, truncated streams, malformed lines)
//! are recorded as report warnings instead.

use std::path::PathBuf;

/// Errors that prevent the engine from producing a report.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The input path does not exist.
    #[error("input file not found: {0}")]
    NotFound(PathBuf),

    /// The input path exists but is not a regular file (directory, device, FIFO, ...).
    #[error("input path is not a regular file: {0}")]
    NotAFile(PathBuf),

    /// The input file exceeds the configured on-disk size limit.
    #[error("input is {size} bytes, which exceeds the configured limit of {limit} bytes")]
    FileTooLarge {
        /// Actual size in bytes.
        size: u64,
        /// Configured limit in bytes.
        limit: u64,
    },

    /// The input is not a supported type (binary content, disallowed extension, ...).
    #[error("unsupported input: {0}")]
    UnsupportedInput(String),

    /// An I/O error occurred before any content could be analyzed.
    #[error("I/O error while {context}: {source}")]
    Io {
        /// What the engine was doing.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The engine configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl EngineError {
    /// Convenience constructor for [`EngineError::Io`].
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// Result alias using [`EngineError`].
pub type Result<T, E = EngineError> = std::result::Result<T, E>;
