//! Log line header parsing for Minecraft server and proxy logs.
//!
//! Supported header layouts (all produced by log4j or `java.util.logging` configs that
//! ship with Minecraft server software):
//!
//! | Layout | Example | Used by |
//! |---|---|---|
//! | `[T] [thread/LEVEL]: msg` | `[12:00:01] [Server thread/INFO]: Done` | Vanilla, Paper, Purpur, Spigot `latest.log` |
//! | `[T] [thread/LEVEL] [logger]: msg` | `[12:00:01] [main/INFO] [minecraft/Main]: ...` | modern Vanilla, Velocity, Fabric |
//! | `[T LEVEL]: msg` | `[12:00:01 INFO]: Done` | Paper/Spigot/Velocity console |
//! | `[T LEVEL] [logger]: msg` | `[12:00:01 INFO] [luckperms]: ...` | Velocity console |
//! | `[ddMMMyyyy T] [thread/LEVEL] [logger/]: msg` | `[02Jan2024 12:00:01.123] [main/INFO] [...]` | Forge |
//! | `YYYY-MM-DD T [LEVEL] msg` | `2013-01-01 12:00:01 [SEVERE] ...` | legacy Bukkit |
//!
//! `T` may be `HH:MM:SS`, `HH:MM:SS.mmm` or prefixed with an ISO date. Parsing is
//! hand-written (no regex) and runs in linear time over a bounded prefix of the line.

use anycasted_core::models::{
    CalendarDate, ContentKind, LogHeader, LogLevel, TimeOfDay, Timestamp,
};

/// Maximum length of a bracketed header group.
const MAX_GROUP_LEN: usize = 160;
/// Maximum length of a plugin tag at the start of a message.
const MAX_TAG_LEN: usize = 48;

/// Parses the header of a log line. Returns `None` if the line does not start with a
/// recognized header (continuation lines, stack frames, raw stdout, ...).
pub fn parse_header(line: &str) -> Option<LogHeader> {
    let start = prompt_prefix_len(line);
    let s = &line[start..];
    let mut h = PartialHeader::default();
    let rest = if s.starts_with('[') {
        parse_bracketed(s, &mut h)?
    } else if s.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        parse_legacy(s, &mut h)?
    } else {
        return None;
    };
    let message_start = line.len() - rest.len();
    let message = rest;
    let (tag, content) = classify_message(message);
    Some(LogHeader {
        timestamp: h.timestamp,
        level: h.level,
        thread: h.thread.map(str::to_owned),
        logger: h.logger.map(str::to_owned),
        tag: tag.map(str::to_owned),
        message_start,
        content,
    })
}

#[derive(Default)]
struct PartialHeader<'a> {
    timestamp: Option<Timestamp>,
    level: Option<LogLevel>,
    thread: Option<&'a str>,
    logger: Option<&'a str>,
}

/// Console captures from hosting panels may prefix lines with `> `.
fn prompt_prefix_len(line: &str) -> usize {
    let trimmed = line.trim_start_matches(['>', ' ']);
    if trimmed.len() != line.len() && trimmed.starts_with('[') {
        line.len() - trimmed.len()
    } else {
        0
    }
}

/// Splits `[content]rest` into `(content, rest)`.
fn bracket(s: &str) -> Option<(&str, &str)> {
    let inner = s.strip_prefix('[')?;
    let end = inner
        .as_bytes()
        .iter()
        .take(MAX_GROUP_LEN)
        .position(|&b| b == b']')?;
    Some((&inner[..end], &inner[end + 1..]))
}

fn parse_bracketed<'a>(s: &'a str, h: &mut PartialHeader<'a>) -> Option<&'a str> {
    let (first, mut rest) = bracket(s)?;
    parse_first_group(first, h)?;

    if h.level.is_none() {
        let (group, after) = bracket(rest.strip_prefix(' ').unwrap_or(rest))?;
        match group.rsplit_once('/') {
            Some((thread, level)) => {
                h.level = Some(LogLevel::parse(level)?);
                h.thread = Some(thread);
            }
            None => h.level = Some(LogLevel::parse(group)?),
        }
        rest = after;
    }

    // Optional logger group, only if directly followed by the `:` separator.
    if let Some(candidate) = rest.strip_prefix(' ') {
        if let Some((logger, after)) = bracket(candidate) {
            if after.starts_with(':') {
                h.logger = Some(logger.trim_end_matches('/'));
                rest = after;
            }
        }
    }

    Some(
        rest.strip_prefix(": ")
            .or_else(|| rest.strip_prefix(':'))
            .or_else(|| rest.strip_prefix(' '))
            .unwrap_or(rest),
    )
}

/// Parses the first bracket group: a timestamp, optionally followed by a level.
fn parse_first_group(group: &str, h: &mut PartialHeader<'_>) -> Option<()> {
    let mut tokens = group.split_ascii_whitespace();
    let first = tokens.next()?;
    let (date, time) = if let Some(time) = parse_time(first) {
        (None, time)
    } else if let Some((d, t)) = first.split_once('T') {
        (
            Some(parse_iso_date(d)?),
            parse_time(t.trim_end_matches('Z'))?,
        )
    } else {
        let date = parse_iso_date(first).or_else(|| parse_forge_date(first))?;
        (Some(date), parse_time(tokens.next()?)?)
    };
    h.timestamp = Some(Timestamp {
        date,
        time,
        day_offset: 0,
    });
    if let Some(level) = tokens.next() {
        h.level = Some(LogLevel::parse(level)?);
    }
    tokens.next().is_none().then_some(())
}

/// Legacy Bukkit: `2013-01-01 12:00:01 [INFO] message`.
fn parse_legacy<'a>(s: &'a str, h: &mut PartialHeader<'a>) -> Option<&'a str> {
    let (date, rest) = s.split_once(' ')?;
    let (time, rest) = rest.split_once(' ')?;
    h.timestamp = Some(Timestamp {
        date: Some(parse_iso_date(date)?),
        time: parse_time(time)?,
        day_offset: 0,
    });
    let (level, rest) = bracket(rest)?;
    h.level = Some(LogLevel::parse(level)?);
    Some(rest.strip_prefix(' ').unwrap_or(rest))
}

fn two_digits(s: &str) -> Option<u8> {
    (s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
}

/// `HH:MM:SS`, `HH:MM:SS.mmm`, `HH:MM:SS,mmm`.
fn parse_time(s: &str) -> Option<TimeOfDay> {
    let (hms, millis) = match s.find(['.', ',']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut parts = hms.split(':');
    let (h, m, sec) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let millis = match millis {
        Some(ms) if (1..=9).contains(&ms.len()) && ms.bytes().all(|b| b.is_ascii_digit()) => {
            let first3 = &ms[..ms.len().min(3)];
            let scale = 10u16.pow(3 - first3.len() as u32);
            Some(first3.parse::<u16>().ok()? * scale)
        }
        Some(_) => return None,
        None => None,
    };
    TimeOfDay::new(two_digits(h)?, two_digits(m)?, two_digits(sec)?, millis)
}

/// `YYYY-MM-DD`.
fn parse_iso_date(s: &str) -> Option<CalendarDate> {
    let mut parts = s.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || !y.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    CalendarDate::new(y.parse().ok()?, two_digits(m)?, two_digits(d)?)
}

/// `02Jan2024` (Forge).
fn parse_forge_date(s: &str) -> Option<CalendarDate> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if s.len() != 9 || !s.is_ascii() {
        return None;
    }
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(&s[2..5]))? as u8
        + 1;
    let year = &s[5..];
    if !year.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    CalendarDate::new(year.parse().ok()?, month, two_digits(&s[..2])?)
}

/// Extracts a leading `[Tag]` (plugin logger) and classifies player content.
fn classify_message(message: &str) -> (Option<&str>, ContentKind) {
    let tag = message.strip_prefix('[').and_then(|inner| {
        let end = inner.find(']')?;
        let tag = &inner[..end];
        (end > 0
            && end <= MAX_TAG_LEN
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .then_some(tag)
    });

    // Chat: `<Name> text`, `[Not Secure] <Name> text`. `[Server] text` (from /say) is not
    // treated as chat: some hosts prefix genuine server lines the same way.
    let body = message.strip_prefix("[Not Secure] ").unwrap_or(message);
    let is_chat = body
        .strip_prefix('<')
        .and_then(|b| b.find("> "))
        .is_some_and(|end| end <= 40);
    let content = if is_chat {
        ContentKind::Chat
    } else if message.contains(" issued server command: ")
        || message.contains(" executed command: ")
        || message.contains(" -> executed command ")
    {
        ContentKind::PlayerCommand
    } else {
        ContentKind::System
    };
    (tag, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg<'a>(line: &'a str, h: &LogHeader) -> &'a str {
        &line[h.message_start..]
    }

    #[test]
    fn paper_latest_log() {
        let line = "[12:34:56] [Server thread/INFO]: [LuckPerms] Enabling LuckPerms v5.4.102";
        let h = parse_header(line).unwrap();
        assert_eq!(h.level, Some(LogLevel::Info));
        assert_eq!(h.thread.as_deref(), Some("Server thread"));
        assert_eq!(h.tag.as_deref(), Some("LuckPerms"));
        assert_eq!(msg(line, &h), "[LuckPerms] Enabling LuckPerms v5.4.102");
        assert_eq!(h.timestamp.unwrap().to_string(), "12:34:56");
    }

    #[test]
    fn console_format() {
        let line = "[12:34:56 WARN]: Can't keep up!";
        let h = parse_header(line).unwrap();
        assert_eq!(h.level, Some(LogLevel::Warn));
        assert_eq!(h.thread, None);
        assert_eq!(msg(line, &h), "Can't keep up!");
    }

    #[test]
    fn velocity_plugin_logger() {
        let line = "[12:34:56 INFO] [luckperms]: Loading configuration...";
        let h = parse_header(line).unwrap();
        assert_eq!(h.logger.as_deref(), Some("luckperms"));
        assert_eq!(msg(line, &h), "Loading configuration...");
    }

    #[test]
    fn vanilla_with_logger_and_millis() {
        let line = "[12:34:56.789] [Server thread/INFO] [minecraft/DedicatedServer]: Done (3.1s)!";
        let h = parse_header(line).unwrap();
        assert_eq!(h.logger.as_deref(), Some("minecraft/DedicatedServer"));
        assert_eq!(h.timestamp.unwrap().time.millis, Some(789));
        assert_eq!(msg(line, &h), "Done (3.1s)!");
    }

    #[test]
    fn forge_format() {
        let line = "[02Jan2024 12:00:01.123] [main/INFO] [cpw.mods.modlauncher.Launcher/MODLAUNCHER]: ModLauncher running";
        let h = parse_header(line).unwrap();
        let ts = h.timestamp.unwrap();
        assert_eq!(ts.date, CalendarDate::new(2024, 1, 2));
        assert_eq!(
            h.logger.as_deref(),
            Some("cpw.mods.modlauncher.Launcher/MODLAUNCHER")
        );
    }

    #[test]
    fn legacy_bukkit() {
        let line = "2013-01-01 12:00:01 [SEVERE] Could not load 'plugins/Foo.jar'";
        let h = parse_header(line).unwrap();
        assert_eq!(h.level, Some(LogLevel::Error));
        assert_eq!(msg(line, &h), "Could not load 'plugins/Foo.jar'");
    }

    #[test]
    fn iso_date_group() {
        let h = parse_header("[2024-05-01 23:59:59] [Server thread/ERROR]: boom").unwrap();
        assert_eq!(h.timestamp.unwrap().to_string(), "2024-05-01 23:59:59");
    }

    #[test]
    fn panel_prompt_prefix() {
        let line = "> [12:00:00 INFO]: Done";
        let h = parse_header(line).unwrap();
        assert_eq!(msg(line, &h), "Done");
    }

    #[test]
    fn chat_and_commands_are_user_content() {
        let chat =
            parse_header("[12:00:00] [Server thread/INFO]: <Steve> I got an error lol").unwrap();
        assert_eq!(chat.content, ContentKind::Chat);
        let secure =
            parse_header("[12:00:00 INFO]: [Not Secure] <Alex> OutOfMemoryError haha").unwrap();
        assert_eq!(secure.content, ContentKind::Chat);
        assert_eq!(secure.tag, None);
        let cmd = parse_header("[12:00:00 INFO]: Steve issued server command: /crash").unwrap();
        assert_eq!(cmd.content, ContentKind::PlayerCommand);
    }

    #[test]
    fn non_headers() {
        for line in [
            "\tat java.lang.Thread.run(Thread.java:833)",
            "java.lang.NullPointerException",
            "[Foo] not a header",
            "",
            "[99:99:99 INFO]: bad time",
            "[12:00:00] [Server thread/NOTALEVEL]: x",
        ] {
            assert!(parse_header(line).is_none(), "{line}");
        }
    }
}
