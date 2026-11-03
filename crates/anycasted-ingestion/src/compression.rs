//! Compression detection and transparent decompression.

use std::fmt;
use std::io::{BufRead, BufReader, Read};

use flate2::bufread::MultiGzDecoder;

/// gzip magic bytes (RFC 1952).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Compression applied to an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Plain text.
    None,
    /// gzip (`.gz`, including concatenated members as written by log rotation).
    Gzip,
}

impl Compression {
    /// Detects compression from the first bytes of the input.
    pub fn detect(prefix: &[u8]) -> Self {
        if prefix.starts_with(&GZIP_MAGIC) {
            Self::Gzip
        } else {
            Self::None
        }
    }

    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
        }
    }

    /// Wraps a buffered reader with the matching decoder.
    pub(crate) fn wrap<R>(self, reader: BufReader<R>) -> Box<dyn BufRead + Send>
    where
        R: Read + Send + 'static,
    {
        match self {
            Self::None => Box::new(reader),
            Self::Gzip => Box::new(BufReader::with_capacity(
                super::READ_BUFFER_BYTES,
                MultiGzDecoder::new(reader),
            )),
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gzip_magic() {
        assert_eq!(Compression::detect(&[0x1f, 0x8b, 8, 0]), Compression::Gzip);
        assert_eq!(Compression::detect(b"[12:00:00 INFO]"), Compression::None);
        assert_eq!(Compression::detect(b""), Compression::None);
    }
}
