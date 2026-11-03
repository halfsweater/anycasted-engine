//! Bounded, streaming input ingestion.
//!
//! The ingestion layer turns a file or reader into a stream of decoded [`RawLine`]s
//! without ever buffering the whole input:
//!
//! * gzip is detected by magic bytes (not by extension) and decompressed on the fly;
//! * every line is capped at [`Limits::max_line_bytes`](anycasted_core::Limits);
//! * the total number of decompressed bytes is capped (decompression-bomb guard);
//! * invalid UTF-8 is decoded lossily, NUL bytes and ANSI escapes are removed;
//! * mid-stream read errors (e.g. a truncated `.gz`) end the stream gracefully and are
//!   reported through [`IngestStats`] instead of aborting the analysis.

mod compression;
mod file;
mod reader;

use std::io::{BufRead, BufReader, Read};

use anycasted_core::{EngineConfig, EngineError, Result};

pub use compression::Compression;
pub use file::{ALLOWED_EXTENSIONS, open_path, validate_path};
pub use reader::{IngestStats, LineReader, RawLine, strip_control_sequences};

/// Size of the read buffer used for inputs.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Descriptive information about an opened input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMeta {
    /// Display name (file name without directories).
    pub name: String,
    /// Detected compression.
    pub compression: Compression,
    /// Size of the input as stored, when known.
    pub stored_bytes: Option<u64>,
}

/// An opened input: metadata plus a line stream.
pub struct OpenedInput {
    /// Metadata.
    pub meta: InputMeta,
    /// Decoded line stream.
    pub lines: LineReader,
}

impl std::fmt::Debug for OpenedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedInput")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// Opens an arbitrary reader (e.g. an upload body).
///
/// `name` is used for display only. Compression is detected from content.
pub fn open_reader<R>(name: &str, reader: R, config: &EngineConfig) -> Result<OpenedInput>
where
    R: Read + Send + 'static,
{
    open_buffered(
        name,
        BufReader::with_capacity(READ_BUFFER_BYTES, reader),
        None,
        config,
    )
}

pub(crate) fn open_buffered<R>(
    name: &str,
    mut reader: BufReader<R>,
    stored_bytes: Option<u64>,
    config: &EngineConfig,
) -> Result<OpenedInput>
where
    R: Read + Send + 'static,
{
    let prefix = reader
        .fill_buf()
        .map_err(|e| EngineError::io(format!("reading {name}"), e))?;
    let compression = Compression::detect(prefix);
    let decoded: Box<dyn BufRead + Send> = compression.wrap(reader);
    let lines = LineReader::new(decoded, &config.limits)?;
    tracing::debug!(input = name, ?compression, "input opened");
    Ok(OpenedInput {
        meta: InputMeta {
            name: name.to_owned(),
            compression,
            stored_bytes,
        },
        lines,
    })
}
