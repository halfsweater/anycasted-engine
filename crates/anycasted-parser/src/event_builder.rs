//! Groups physical lines into [`LogEvent`]s (multi-line messages and stack traces).

use anycasted_core::Limits;
use anycasted_core::models::{LogEvent, SourceLine, Timestamp};

use crate::java::{self, is_stack_line};
use crate::minecraft::parse_header;

/// Counters describing the parse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Events emitted.
    pub events: u64,
    /// Lines that started an event with a recognized header.
    pub header_lines: u64,
    /// Lines without a recognized header (continuations and unstructured output).
    pub unstructured_lines: u64,
    /// Lines belonging to events but not retained due to `max_event_lines`.
    pub omitted_lines: u64,
}

/// Tracks midnight roll-overs for logs whose timestamps lack a date.
#[derive(Debug, Default)]
struct DayTracker {
    last_millis: Option<u32>,
    offset: u32,
}

impl DayTracker {
    /// A backwards jump of more than this is treated as crossing midnight; smaller
    /// jumps are normal interleaving of multi-threaded output.
    const ROLLOVER_THRESHOLD_MS: u32 = 3 * 3600 * 1000;

    fn adjust(&mut self, ts: &mut Timestamp) {
        if ts.date.is_some() {
            return;
        }
        let now = ts.time.millis_of_day();
        if let Some(last) = self.last_millis {
            if now + Self::ROLLOVER_THRESHOLD_MS < last {
                self.offset += 1;
            }
        }
        self.last_millis = Some(now);
        ts.day_offset = self.offset;
    }
}

/// Incremental event builder. Feed lines with [`EventBuilder::push`]; completed events
/// are returned as soon as the next event starts. Call [`EventBuilder::finish`] at the
/// end of input.
#[derive(Debug)]
pub struct EventBuilder {
    current: Option<LogEvent>,
    max_event_lines: usize,
    max_frames: usize,
    days: DayTracker,
    stats: ParseStats,
}

impl EventBuilder {
    /// Creates a builder.
    pub fn new(limits: &Limits) -> Self {
        Self {
            current: None,
            max_event_lines: limits.max_event_lines,
            max_frames: limits.max_frames_per_exception,
            days: DayTracker::default(),
            stats: ParseStats::default(),
        }
    }

    /// Parse statistics so far.
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Adds a line; returns the previous event if this line completed it.
    pub fn push(&mut self, line: SourceLine) -> Option<LogEvent> {
        if let Some(mut header) = parse_header(&line.text) {
            self.stats.header_lines += 1;
            if let Some(ts) = header.timestamp.as_mut() {
                self.days.adjust(ts);
            }
            return self.start(LogEvent::new(Some(header), line));
        }
        self.stats.unstructured_lines += 1;

        let blank = line.text.trim().is_empty();
        match self.current.as_mut() {
            Some(ev) if ev.header.is_some() && !starts_unstructured_event(&line.text) => {
                append(ev, line, self.max_event_lines, &mut self.stats);
                None
            }
            Some(ev) if ev.header.is_none() && !blank && is_continuation(&line.text) => {
                append(ev, line, self.max_event_lines, &mut self.stats);
                None
            }
            _ if blank => self.current.take().map(|ev| self.finalize(ev)),
            _ => self.start(LogEvent::new(None, line)),
        }
    }

    /// Completes the last event.
    pub fn finish(&mut self) -> Option<LogEvent> {
        self.current.take().map(|ev| self.finalize(ev))
    }

    fn start(&mut self, event: LogEvent) -> Option<LogEvent> {
        let done = self.current.take().map(|ev| self.finalize(ev));
        self.current = Some(event);
        done
    }

    fn finalize(&mut self, mut event: LogEvent) -> LogEvent {
        self.stats.events += 1;
        if !event.is_user_content() {
            let first = std::iter::once((event.start_line(), event.message()));
            let rest = event
                .continuation()
                .iter()
                .map(|l| (l.number, l.text.as_str()));
            event.exceptions = java::extract_chains(first.chain(rest), self.max_frames);
        }
        event
    }
}

fn append(event: &mut LogEvent, line: SourceLine, max_lines: usize, stats: &mut ParseStats) {
    event.last_line = line.number;
    if event.lines.len() < max_lines {
        event.lines.push(line);
    } else {
        event.omitted_lines = event.omitted_lines.saturating_add(1);
        stats.omitted_lines += 1;
    }
}

/// Lines that belong to the preceding header-less line (stack trace bodies).
fn is_continuation(text: &str) -> bool {
    text.starts_with([' ', '\t'])
        || is_stack_line(text)
        || text.starts_with("Caused by: ")
        || text.starts_with("Suppressed: ")
}

/// Header-less lines that must not be swallowed by a preceding header event: an
/// uncaught exception printed directly by the JVM to stderr.
fn starts_unstructured_event(text: &str) -> bool {
    text.starts_with("Exception in thread \"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(text: &str) -> Vec<LogEvent> {
        let mut b = EventBuilder::new(&Limits::default());
        let mut out = Vec::new();
        for (i, l) in text.lines().enumerate() {
            out.extend(b.push(SourceLine {
                number: i as u64 + 1,
                text: l.to_owned(),
            }));
        }
        out.extend(b.finish());
        out
    }

    #[test]
    fn groups_stack_traces_with_header() {
        let events = build(
            "[12:00:00] [Server thread/INFO]: Starting\n\
             [12:00:01] [Server thread/ERROR]: Could not pass event PlayerJoinEvent to Foo v1.0\n\
             java.lang.NullPointerException: null\n\
             \tat com.foo.Listener.onJoin(Listener.java:5) ~[Foo-1.0.jar:?]\n\
             [12:00:02] [Server thread/INFO]: Next",
        );
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].lines.len(), 3);
        assert_eq!(events[1].last_line, 4);
        assert_eq!(events[1].exceptions.len(), 1);
        assert_eq!(events[1].exceptions[0].top().unwrap().line, 3);
    }

    #[test]
    fn headerless_stderr_traces() {
        let events = build(
            "Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space\n\
             \tat java.util.Arrays.copyOf(Arrays.java:3512)\n\
             \n\
             some other output\n\
             more output",
        );
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].exceptions[0].top().unwrap().simple_name(),
            "OutOfMemoryError"
        );
    }

    #[test]
    fn rollover_increments_day() {
        let events =
            build("[23:59:59] [Server thread/INFO]: a\n[00:00:01] [Server thread/INFO]: b");
        assert_eq!(events[1].timestamp().unwrap().day_offset, 1);
        assert!(
            events[0].timestamp().unwrap().ordinal_millis()
                < events[1].timestamp().unwrap().ordinal_millis()
        );
    }

    #[test]
    fn event_line_cap() {
        let limits = Limits {
            max_event_lines: 2,
            ..Limits::default()
        };
        let mut b = EventBuilder::new(&limits);
        for (i, t) in ["[12:00:00 ERROR]: x", "a", "b", "c"].iter().enumerate() {
            b.push(SourceLine {
                number: i as u64 + 1,
                text: (*t).to_owned(),
            });
        }
        let ev = b.finish().unwrap();
        assert_eq!(ev.lines.len(), 2);
        assert_eq!(ev.omitted_lines, 2);
        assert_eq!(ev.last_line, 4);
    }

    #[test]
    fn chat_is_not_parsed_for_exceptions() {
        let events =
            build("[12:00:00] [Server thread/INFO]: <Steve> java.lang.OutOfMemoryError: lol");
        assert!(events[0].exceptions.is_empty());
        assert!(events[0].is_user_content());
    }
}
