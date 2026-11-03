//! File path validation and opening.

use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::path::Path;

use anycasted_core::{EngineConfig, EngineError, Result};

use crate::OpenedInput;

/// Extensions accepted unless `allow_any_extension` is set. Files without an extension
/// are also accepted. Matching is case-insensitive and applies to the last extension,
/// so `latest.log.gz` and `2024-01-01-1.log.gz` are accepted via `gz`.
pub const ALLOWED_EXTENSIONS: &[&str] = &["log", "txt", "gz"];

/// Validates that `path` names a regular, readable-size file with an accepted extension.
///
/// Returns the file size.
pub fn validate_path(path: &Path, config: &EngineConfig) -> Result<u64> {
    let metadata = std::fs::metadata(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => EngineError::NotFound(path.to_path_buf()),
        _ => EngineError::io(format!("reading metadata of {}", path.display()), e),
    })?;
    if !metadata.is_file() {
        return Err(EngineError::NotAFile(path.to_path_buf()));
    }
    let size = metadata.len();
    if size > config.limits.max_file_bytes {
        return Err(EngineError::FileTooLarge {
            size,
            limit: config.limits.max_file_bytes,
        });
    }
    if !config.allow_any_extension {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if !ALLOWED_EXTENSIONS
                .iter()
                .any(|a| a.eq_ignore_ascii_case(ext))
            {
                return Err(EngineError::UnsupportedInput(format!(
                    "file extension `.{ext}` is not a supported log type (expected one of: {})",
                    ALLOWED_EXTENSIONS.join(", ")
                )));
            }
        }
    }
    Ok(size)
}

/// Validates and opens a file for streaming.
pub fn open_path(path: &Path, config: &EngineConfig) -> Result<OpenedInput> {
    let size = validate_path(path, config)?;
    let file = File::open(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => EngineError::NotFound(path.to_path_buf()),
        _ => EngineError::io(format!("opening {}", path.display()), e),
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    crate::open_buffered(
        &name,
        BufReader::with_capacity(crate::READ_BUFFER_BYTES, file),
        Some(size),
        config,
    )
}
