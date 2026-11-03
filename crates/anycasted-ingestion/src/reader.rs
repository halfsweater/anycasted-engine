//! Bounded line reader with lossy decoding.

use std::borrow::Cow;
use std::io::{BufRead, ErrorKind};

use anycasted_core::{EngineError, Limits, Result};

/// A decoded physical line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    /// 1-based line number in the decoded stream.
    pub number: u64,
    /// Decoded text (see [`anycasted_core::models::SourceLine`]).
    pub text: String,
    /// The line contained invalid UTF-8.
    pub invalid_utf8: bool,
    /// The line exceeded `max_line_bytes` and was cut.
    pub overlong: bool,
}

/// Counters describing what the reader saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// Decoded bytes consumed (including line terminators).
    pub bytes_read: u64,
    /// Lines produced.
    pub lines: u64,
    /// Lines containing invalid UTF-8.
    pub invalid_utf8_lines: u64,
    /// Lines cut at `max_line_bytes`.
    pub overlong_lines: u64,
    /// NUL bytes removed (typical of logs truncated by a crash or power loss).
    pub nul_bytes_removed: u64,
    /// The input did not end with a newline (the last line may be truncated).
    pub ended_without_newline: bool,
    /// Reading stopped because `max_decompressed_bytes` was reached.
    pub limit_reached: bool,
    /// Reading stopped because of an I/O or decoding error.
    pub read_error: Option<String>,
}

impl IngestStats {
    /// Whether the entire input was read.
    pub fn complete(&self) -> bool {
        !self.limit_reached && self.read_error.is_none()
    }
}

/// Streams decoded lines from a buffered reader, enforcing limits.
pub struct LineReader {
    inner: Box<dyn BufRead + Send>,
    max_line_bytes: usize,
    max_total_bytes: u64,
    buf: Vec<u8>,
    stats: IngestStats,
    done: bool,
}

/// Bytes inspected to decide whether the input is binary.
const SNIFF_BYTES: usize = 8 * 1024;

impl LineReader {
    /// Creates a reader; fails if the content is clearly binary or undecodable.
    pub fn new(mut inner: Box<dyn BufRead + Send>, limits: &Limits) -> Result<Self> {
        let prefix = loop {
            match inner.fill_buf() {
                Ok(buf) => break buf,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(EngineError::UnsupportedInput(format!(
                        "input could not be decoded: {e}"
                    )));
                }
            }
        };
        if looks_binary(&prefix[..prefix.len().min(SNIFF_BYTES)]) {
            return Err(EngineError::UnsupportedInput(
                "input appears to be binary data, not a text log".into(),
            ));
        }
        Ok(Self {
            inner,
            max_line_bytes: limits.max_line_bytes,
            max_total_bytes: limits.max_decompressed_bytes,
            buf: Vec::with_capacity(512),
            stats: IngestStats::default(),
            done: false,
        })
    }

    /// Statistics so far.
    pub fn stats(&self) -> &IngestStats {
        &self.stats
    }

    /// Reads raw bytes of the next line into `self.buf`. Returns `false` at end of input.
    fn fill_line(&mut self) -> (bool, bool) {
        self.buf.clear();
        let mut got_any = false;
        let mut overlong = false;
        loop {
            if self.stats.bytes_read >= self.max_total_bytes {
                self.stats.limit_reached = true;
                self.done = true;
                break;
            }
            let available = match self.inner.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.stats.read_error = Some(e.to_string());
                    self.done = true;
                    break;
                }
            };
            if available.is_empty() {
                self.done = true;
                if got_any {
                    self.stats.ended_without_newline = true;
                }
                break;
            }
            let budget = usize::try_from(self.max_total_bytes - self.stats.bytes_read)
                .unwrap_or(usize::MAX)
                .min(available.len());
            let window = &available[..budget];
            let (chunk_len, found_newline) = match window.iter().position(|&b| b == b'\n') {
                Some(i) => (i, true),
                None => (window.len(), false),
            };
            got_any = true;
            let room = self.max_line_bytes.saturating_sub(self.buf.len());
            if chunk_len > room {
                overlong = true;
                self.buf.extend_from_slice(&window[..room]);
            } else {
                self.buf.extend_from_slice(&window[..chunk_len]);
            }
            let consumed = chunk_len + usize::from(found_newline);
            self.inner.consume(consumed);
            self.stats.bytes_read += consumed as u64;
            if found_newline {
                break;
            }
        }
        (got_any, overlong)
    }

    fn decode(&mut self, overlong: bool) -> RawLine {
        if self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        let nuls = self.buf.iter().filter(|&&b| b == 0).count();
        if nuls > 0 {
            self.buf.retain(|&b| b != 0);
            self.stats.nul_bytes_removed += nuls as u64;
        }
        let (text, invalid_utf8) = match std::str::from_utf8(&self.buf) {
            Ok(s) => (s.to_owned(), false),
            Err(_) => (String::from_utf8_lossy(&self.buf).into_owned(), true),
        };
        let text = match strip_control_sequences(&text) {
            Cow::Borrowed(_) => text,
            Cow::Owned(s) => s,
        };
        self.stats.lines += 1;
        self.stats.invalid_utf8_lines += u64::from(invalid_utf8);
        self.stats.overlong_lines += u64::from(overlong);
        RawLine {
            number: self.stats.lines,
            text,
            invalid_utf8,
            overlong,
        }
    }
}

impl Iterator for LineReader {
    type Item = RawLine;

    fn next(&mut self) -> Option<RawLine> {
        if self.done {
            return None;
        }
        let (got_any, overlong) = self.fill_line();
        got_any.then(|| self.decode(overlong))
    }
}

/// Removes ANSI escape sequences (console colors captured by hosting panels) and ASCII
/// control characters other than tab.
pub fn strip_control_sequences(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(is_ascii_control) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                // CSI: ESC [ params... final byte (0x40-0x7e)
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] ... BEL or ESC \
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' || (c == '\u{1b}' && chars.peek() == Some(&'\\')) {
                            if c == '\u{1b}' {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
        } else if !c.is_ascii() || !is_ascii_control(c as u8) {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn is_ascii_control(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

/// Heuristic: a prefix is binary if more than 10% of its bytes are control bytes that
/// never appear in text logs. NUL runs are tolerated only when the prefix also contains
/// substantial text (logs truncated by a crash can contain NUL padding).
fn looks_binary(prefix: &[u8]) -> bool {
    if prefix.len() < 16 {
        return prefix.contains(&0) && !prefix.iter().any(u8::is_ascii_graphic);
    }
    let suspicious = prefix
        .iter()
        .filter(|&&b| matches!(b, 0x01..=0x08 | 0x0e..=0x1a | 0x1c..=0x1f | 0x7f))
        .count();
    let nul = prefix.iter().filter(|&&b| b == 0).count();
    let printable = prefix
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    suspicious * 10 > prefix.len() || (nul * 2 > prefix.len() && printable * 4 < prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(data: &[u8], limits: &Limits) -> Result<LineReader> {
        LineReader::new(Box::new(Cursor::new(data.to_vec())), limits)
    }

    fn lines(data: &[u8]) -> (Vec<RawLine>, IngestStats) {
        let mut r = reader(data, &Limits::default()).unwrap();
        let v: Vec<_> = r.by_ref().collect();
        (v, r.stats().clone())
    }

    #[test]
    fn numbers_lines_and_handles_crlf() {
        let (v, s) = lines(b"a\r\nb\n\nc");
        assert_eq!(
            v.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            ["a", "b", "", "c"]
        );
        assert_eq!(v[3].number, 4);
        assert!(s.ended_without_newline);
        assert!(s.complete());
    }

    #[test]
    fn trailing_newline_does_not_add_line() {
        let (v, s) = lines(b"a\nb\n");
        assert_eq!(v.len(), 2);
        assert!(!s.ended_without_newline);
    }

    #[test]
    fn empty_input_has_no_lines() {
        let (v, s) = lines(b"");
        assert!(v.is_empty());
        assert_eq!(s.lines, 0);
    }

    #[test]
    fn invalid_utf8_is_lossy() {
        let (v, s) = lines(b"ok\nbad \xff\xfe here\n");
        assert!(v[1].invalid_utf8);
        assert!(v[1].text.contains('\u{fffd}'));
        assert_eq!(s.invalid_utf8_lines, 1);
    }

    #[test]
    fn overlong_lines_are_cut_but_numbering_stays_correct() {
        let limits = Limits {
            max_line_bytes: 8,
            ..Limits::default()
        };
        let mut r = reader(b"0123456789abcdef\nnext\n", &limits).unwrap();
        let v: Vec<_> = r.by_ref().collect();
        assert_eq!(v[0].text, "01234567");
        assert!(v[0].overlong);
        assert_eq!(v[1].text, "next");
        assert_eq!(v[1].number, 2);
    }

    #[test]
    fn total_limit_stops_reading() {
        let limits = Limits {
            max_decompressed_bytes: 10,
            ..Limits::default()
        };
        let mut r = reader(b"aaaa\nbbbb\ncccc\ndddd\n", &limits).unwrap();
        let v: Vec<_> = r.by_ref().collect();
        assert_eq!(v.len(), 2);
        assert!(r.stats().limit_reached);
        assert!(!r.stats().complete());
    }

    #[test]
    fn strips_ansi_and_nul() {
        let (v, s) = lines(b"\x1b[0;31mred\x1b[m text\x00\x00\n");
        assert_eq!(v[0].text, "red text");
        assert_eq!(s.nul_bytes_removed, 2);
    }

    #[test]
    fn rejects_binary() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert!(reader(&data, &Limits::default()).is_err());
    }
}
