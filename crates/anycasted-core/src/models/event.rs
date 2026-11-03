//! Log events: the normalized unit that detection rules operate on.

use std::fmt;

use serde::{Serialize, Serializer};

use super::java::ExceptionChain;

/// Severity level as written by the logging framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// TRACE / FINEST / FINER.
    Trace,
    /// DEBUG / FINE / CONFIG.
    Debug,
    /// INFO.
    Info,
    /// WARN / WARNING.
    Warn,
    /// ERROR / SEVERE.
    Error,
    /// FATAL.
    Fatal,
}

impl LogLevel {
    /// Parses a level token case-insensitively, including legacy `java.util.logging`
    /// names used by old Bukkit servers (`SEVERE`, `WARNING`, `FINE`, ...).
    pub fn parse(token: &str) -> Option<Self> {
        const TABLE: &[(&str, LogLevel)] = &[
            ("INFO", LogLevel::Info),
            ("WARN", LogLevel::Warn),
            ("ERROR", LogLevel::Error),
            ("WARNING", LogLevel::Warn),
            ("SEVERE", LogLevel::Error),
            ("DEBUG", LogLevel::Debug),
            ("FATAL", LogLevel::Fatal),
            ("TRACE", LogLevel::Trace),
            ("FINE", LogLevel::Debug),
            ("CONFIG", LogLevel::Debug),
            ("FINER", LogLevel::Trace),
            ("FINEST", LogLevel::Trace),
        ];
        let token = token.trim();
        TABLE
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(token))
            .map(|(_, level)| *level)
    }

    /// Canonical upper-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }
}

/// A calendar date (proleptic Gregorian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CalendarDate {
    /// Year.
    pub year: u16,
    /// Month, 1-12.
    pub month: u8,
    /// Day of month, 1-31.
    pub day: u8,
}

impl CalendarDate {
    /// Creates a date if the components are in range.
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        ((1..=12).contains(&month) && (1..=31).contains(&day)).then_some(Self { year, month, day })
    }

    /// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    pub fn days_since_epoch(self) -> i64 {
        let (m, d) = (i64::from(self.month), i64::from(self.day));
        let y = i64::from(self.year) - i64::from(m <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}

/// A wall-clock time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeOfDay {
    /// Hour, 0-23.
    pub hour: u8,
    /// Minute, 0-59.
    pub minute: u8,
    /// Second, 0-60 (leap second tolerated).
    pub second: u8,
    /// Milliseconds when the log format includes them.
    pub millis: Option<u16>,
}

impl TimeOfDay {
    /// Creates a time if the components are in range.
    pub fn new(hour: u8, minute: u8, second: u8, millis: Option<u16>) -> Option<Self> {
        (hour < 24 && minute < 60 && second <= 60 && millis.is_none_or(|m| m < 1000)).then_some(
            Self {
                hour,
                minute,
                second,
                millis,
            },
        )
    }

    /// Milliseconds since midnight.
    pub fn millis_of_day(self) -> u32 {
        (u32::from(self.hour) * 3600 + u32::from(self.minute) * 60 + u32::from(self.second)) * 1000
            + u32::from(self.millis.unwrap_or(0))
    }
}

/// A timestamp extracted from a log line.
///
/// Most Minecraft logs only record the time of day. For those, the parser tracks
/// midnight roll-overs and records them in `day_offset` so timestamps within one log
/// remain monotonic and comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Calendar date, when the format includes one.
    pub date: Option<CalendarDate>,
    /// Time of day.
    pub time: TimeOfDay,
    /// Number of midnight roll-overs observed since the start of the log (only
    /// meaningful when `date` is `None`).
    pub day_offset: u32,
}

impl Timestamp {
    /// A monotonic millisecond value for ordering within one log.
    pub fn ordinal_millis(&self) -> i64 {
        let days = match self.date {
            Some(d) => d.days_since_epoch(),
            None => i64::from(self.day_offset),
        };
        days * 86_400_000 + i64::from(self.time.millis_of_day())
    }

    /// Milliseconds from `self` to `later`, or `None` when the two timestamps are not
    /// comparable (one has a date and the other does not).
    pub fn millis_until(&self, later: &Timestamp) -> Option<i64> {
        (self.date.is_some() == later.date.is_some())
            .then(|| later.ordinal_millis() - self.ordinal_millis())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = self.date {
            write!(f, "{:04}-{:02}-{:02} ", d.year, d.month, d.day)?;
        }
        let t = self.time;
        write!(f, "{:02}:{:02}:{:02}", t.hour, t.minute, t.second)?;
        if let Some(ms) = t.millis {
            write!(f, ".{ms:03}")?;
        }
        if self.date.is_none() && self.day_offset > 0 {
            write!(f, " (+{}d)", self.day_offset)?;
        }
        Ok(())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// One physical line of input, with its 1-based line number.
///
/// `text` is the decoded line: invalid UTF-8 is replaced with U+FFFD, and NUL bytes,
/// ANSI escape sequences and the trailing `\r` are removed. It is otherwise verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceLine {
    /// 1-based physical line number in the (decompressed) input.
    pub number: u64,
    /// Decoded line content.
    pub text: String,
}

/// What kind of content a log message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Output from the server, plugins or the JVM.
    #[default]
    System,
    /// A player chat message. Never used as diagnostic evidence.
    Chat,
    /// A player-issued command echo. Never used as diagnostic evidence.
    PlayerCommand,
}

/// Structured header fields parsed from the first line of a log event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHeader {
    /// Timestamp, when present.
    pub timestamp: Option<Timestamp>,
    /// Level, when present.
    pub level: Option<LogLevel>,
    /// Thread name (`Server thread`, `Craft Scheduler Thread - 3`, ...).
    pub thread: Option<String>,
    /// Logger name when the format includes one (`minecraft/DedicatedServer`,
    /// `luckperms`, ...).
    pub logger: Option<String>,
    /// Bracketed tag at the start of the message (`[LuckPerms] ...`), usually the name
    /// of the plugin logger that produced the message.
    pub tag: Option<String>,
    /// Byte offset of the message within the header line text.
    pub message_start: usize,
    /// Whether the message is player content (chat, commands).
    pub content: ContentKind,
}

/// A normalized log event: a header line plus its continuation lines (multi-line
/// messages, stack traces), or a group of header-less lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// Parsed header, or `None` for lines that do not follow a recognized log format.
    pub header: Option<LogHeader>,
    /// Retained source lines; `lines[0]` is the first line of the event. Never empty.
    pub lines: Vec<SourceLine>,
    /// Number of lines belonging to this event that were not retained due to limits.
    pub omitted_lines: u32,
    /// Line number of the last line belonging to this event (retained or not).
    pub last_line: u64,
    /// Java exceptions found in this event.
    pub exceptions: Vec<ExceptionChain>,
}

impl LogEvent {
    /// Creates an event from its first line.
    pub fn new(header: Option<LogHeader>, first: SourceLine) -> Self {
        Self {
            header,
            last_line: first.number,
            lines: vec![first],
            omitted_lines: 0,
            exceptions: Vec::new(),
        }
    }

    /// Line number of the first line.
    pub fn start_line(&self) -> u64 {
        self.lines[0].number
    }

    /// The first line of the event.
    pub fn first_line(&self) -> &SourceLine {
        &self.lines[0]
    }

    /// The message portion of the first line (the whole line for header-less events).
    pub fn message(&self) -> &str {
        let text = &self.lines[0].text;
        match &self.header {
            Some(h) => text.get(h.message_start..).unwrap_or(""),
            None => text,
        }
    }

    /// Lines after the first.
    pub fn continuation(&self) -> &[SourceLine] {
        &self.lines[1..]
    }

    /// Timestamp, when present.
    pub fn timestamp(&self) -> Option<Timestamp> {
        self.header.as_ref().and_then(|h| h.timestamp)
    }

    /// Level, when present.
    pub fn level(&self) -> Option<LogLevel> {
        self.header.as_ref().and_then(|h| h.level)
    }

    /// Whether this event is player-generated content.
    pub fn is_user_content(&self) -> bool {
        self.header
            .as_ref()
            .is_some_and(|h| h.content != ContentKind::System)
    }

    /// Finds a retained line by number.
    pub fn line(&self, number: u64) -> Option<&SourceLine> {
        self.lines.iter().find(|l| l.number == number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_days() {
        assert_eq!(CalendarDate::new(1970, 1, 1).unwrap().days_since_epoch(), 0);
        assert_eq!(
            CalendarDate::new(2024, 3, 1).unwrap().days_since_epoch(),
            19_783
        );
    }

    #[test]
    fn timestamp_display() {
        let ts = Timestamp {
            date: None,
            time: TimeOfDay::new(1, 2, 3, None).unwrap(),
            day_offset: 1,
        };
        assert_eq!(ts.to_string(), "01:02:03 (+1d)");
    }

    #[test]
    fn level_parse() {
        assert_eq!(LogLevel::parse("severe"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse("Warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("nope"), None);
    }
}
