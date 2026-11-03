//! Java throwable and stack trace parsing.
//!
//! Recognizes the formats printed by `Throwable.printStackTrace()` and by log4j's
//! extended throwable pattern (which appends `~[archive.jar:version]` to frames).

use anycasted_core::models::{ExceptionChain, StackFrame, ThrowableRelation, ThrownException};

/// A parsed throwable header line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHeader<'a> {
    /// Relation to the previous throwable.
    pub relation: ThrowableRelation,
    /// Class name.
    pub class: &'a str,
    /// Message, if any.
    pub message: Option<&'a str>,
}

const THROWABLE_SUFFIXES: &[&str] = &["Exception", "Error", "Throwable"];

/// Parses a throwable header such as `java.lang.IllegalStateException: msg`,
/// `Caused by: java.io.IOException`, `Suppressed: ...` or
/// `Exception in thread "main" java.lang.OutOfMemoryError: Java heap space`.
pub fn parse_exception_header(line: &str) -> Option<ExceptionHeader<'_>> {
    let t = line.trim_start();
    let (relation, body) = if let Some(rest) = t.strip_prefix("Caused by: ") {
        (ThrowableRelation::CausedBy, rest)
    } else if let Some(rest) = t.strip_prefix("Suppressed: ") {
        (ThrowableRelation::Suppressed, rest)
    } else if let Some(rest) = t.strip_prefix("Exception in thread \"") {
        let end = rest.find("\" ")?;
        (ThrowableRelation::Thrown, &rest[end + 2..])
    } else {
        (ThrowableRelation::Thrown, t)
    };

    let class_end = body.find([':', ' ']).unwrap_or(body.len());
    let class = &body[..class_end];
    if !is_qualified_class_name(class) {
        return None;
    }
    let simple = class.rsplit('.').next().unwrap_or(class);
    let nested = simple.rsplit('$').next().unwrap_or(simple);
    if relation == ThrowableRelation::Thrown
        && !THROWABLE_SUFFIXES.iter().any(|s| nested.ends_with(s))
    {
        return None;
    }
    let rest = &body[class_end..];
    let message = if rest.is_empty() {
        None
    } else {
        // Trailing text must be introduced by a colon (`java.lang.Foo is bad` is prose).
        let m = rest.strip_prefix(':')?.trim();
        (!m.is_empty()).then_some(m)
    };
    Some(ExceptionHeader {
        relation,
        class,
        message,
    })
}

/// `pkg.sub.ClassName` with at least two segments, the last starting upper-case.
fn is_qualified_class_name(s: &str) -> bool {
    let mut segments = 0;
    let mut last = "";
    for seg in s.split('.') {
        let mut chars = seg.chars();
        let valid_start = chars
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$');
        if !valid_start || !chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$') {
            return false;
        }
        segments += 1;
        last = seg;
    }
    segments >= 2 && last.starts_with(|c: char| c.is_uppercase())
}

/// Parses `at pkg.Class.method(File.java:12) ~[archive.jar:?]`.
pub fn parse_frame(line: &str, number: u64) -> Option<StackFrame> {
    let rest = line.trim_start().strip_prefix("at ")?;
    let open = rest.find('(')?;
    let close = open + rest[open..].find(')')?;
    let target = &rest[..open];
    let location = &rest[open + 1..close];
    let suffix = rest[close + 1..].trim();

    let (module, qualified) = match target.rfind('/') {
        Some(i) => (Some(target[..i].trim_end_matches('/')), &target[i + 1..]),
        None => (None, target),
    };
    let (class, method) = qualified.rsplit_once('.')?;
    if class.is_empty() || method.is_empty() || class.contains(' ') || method.contains(' ') {
        return None;
    }

    let native = location == "Native Method";
    let (file, line_number) = match location.rsplit_once(':') {
        Some((file, n)) => (Some(file), n.parse().ok()),
        None if native || location == "Unknown Source" || location.is_empty() => (None, None),
        None => (Some(location), None),
    };

    let jar = suffix
        .trim_start_matches('~')
        .strip_prefix('[')
        .and_then(|s| s.split([':', ']']).next())
        .filter(|j| !j.is_empty() && *j != "?");

    Some(StackFrame {
        line: number,
        module: module.filter(|m| !m.is_empty()).map(str::to_owned),
        class: class.to_owned(),
        method: method.to_owned(),
        file: file.map(str::to_owned),
        line_number,
        native,
        jar: jar.map(str::to_owned),
    })
}

/// Parses `... 12 more` and returns the count.
pub fn parse_elided_frames(line: &str) -> Option<u32> {
    line.trim_start()
        .strip_prefix("... ")?
        .strip_suffix(" more")?
        .trim()
        .parse()
        .ok()
}

/// Whether a line is part of a stack trace body (frame or elision marker).
pub fn is_stack_line(line: &str) -> bool {
    let t = line.trim_start();
    (t.starts_with("at ") && t.contains('(')) || t.starts_with("... ")
}

/// Extracts exception chains from a sequence of `(line number, text)` pairs.
///
/// A new chain starts at every top-level throwable header; `Caused by:` and
/// `Suppressed:` headers extend the current chain; frames attach to the most recent
/// throwable. Lines that are neither are ignored (multi-line exception messages).
pub fn extract_chains<'a, I>(lines: I, max_frames: usize) -> Vec<ExceptionChain>
where
    I: IntoIterator<Item = (u64, &'a str)>,
{
    let mut chains = Vec::new();
    let mut current: Option<ExceptionChain> = None;

    for (number, text) in lines {
        let last = current.as_mut().and_then(|c| c.exceptions.last_mut());
        if let Some(exc) = last {
            if let Some(frame) = parse_frame(text, number) {
                if exc.frames.len() < max_frames {
                    exc.frames.push(frame);
                } else {
                    exc.omitted_frames += 1;
                }
                continue;
            }
            if let Some(n) = parse_elided_frames(text) {
                exc.omitted_frames = exc.omitted_frames.saturating_add(n);
                continue;
            }
        }
        let Some(header) = parse_exception_header(text) else {
            continue;
        };
        let exc = ThrownException {
            line: number,
            relation: header.relation,
            class: header.class.to_owned(),
            message: header.message.map(str::to_owned),
            frames: Vec::new(),
            omitted_frames: 0,
        };
        match (header.relation, current.as_mut()) {
            (ThrowableRelation::Thrown, _) | (_, None) => {
                chains.extend(current.take());
                current = Some(ExceptionChain {
                    exceptions: vec![exc],
                });
            }
            (_, Some(chain)) => chain.exceptions.push(exc),
        }
    }
    chains.extend(current);
    chains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let h =
            parse_exception_header("java.lang.NullPointerException: Cannot invoke \"x\"").unwrap();
        assert_eq!(h.class, "java.lang.NullPointerException");
        assert_eq!(h.message, Some("Cannot invoke \"x\""));

        let h = parse_exception_header(
            "Caused by: java.lang.ClassNotFoundException: net.milkbowl.vault.economy.Economy",
        )
        .unwrap();
        assert_eq!(h.relation, ThrowableRelation::CausedBy);

        let h = parse_exception_header(
            "Exception in thread \"Server thread\" java.lang.OutOfMemoryError: Java heap space",
        )
        .unwrap();
        assert_eq!(h.class, "java.lang.OutOfMemoryError");
        assert_eq!(h.message, Some("Java heap space"));

        let h = parse_exception_header("io.netty.channel.AbstractChannel$AnnotatedConnectException: Connection refused: /127.0.0.1:25566").unwrap();
        assert_eq!(
            h.class,
            "io.netty.channel.AbstractChannel$AnnotatedConnectException"
        );

        assert!(
            parse_exception_header("Caused by: org.bukkit.plugin.UnknownDependencyException")
                .is_some()
        );
        assert!(parse_exception_header("java.lang.String is great").is_none());
        assert!(parse_exception_header("Error occurred while enabling Foo").is_none());
        assert!(parse_exception_header("com.example.Widget: hi").is_none());
        assert!(parse_exception_header("Done (12.3s)! For help").is_none());
    }

    #[test]
    fn frames() {
        let f = parse_frame(
            "\tat com.earth2me.essentials.Essentials.onEnable(Essentials.java:123) ~[EssentialsX-2.20.1.jar:?]",
            7,
        )
        .unwrap();
        assert_eq!(f.class, "com.earth2me.essentials.Essentials");
        assert_eq!(f.method, "onEnable");
        assert_eq!(f.line_number, Some(123));
        assert_eq!(f.jar.as_deref(), Some("EssentialsX-2.20.1.jar"));
        assert_eq!(f.line, 7);

        let f = parse_frame(
            "\tat java.base/java.lang.Thread.run(Thread.java:840) [?:?]",
            1,
        )
        .unwrap();
        assert_eq!(f.module.as_deref(), Some("java.base"));
        assert_eq!(f.jar, None);

        let f = parse_frame("at sun.misc.Unsafe.park(Native Method)", 1).unwrap();
        assert!(f.native);

        assert!(parse_frame("at least one player joined (yay)", 1).is_none());
        assert_eq!(parse_elided_frames("\t... 12 more"), Some(12));
    }

    #[test]
    fn chain_extraction() {
        let text = [
            "Error occurred while enabling Foo v1.0 (Is it up to date?)",
            "java.lang.NoClassDefFoundError: net/milkbowl/vault/economy/Economy",
            "\tat com.example.foo.Foo.onEnable(Foo.java:10) ~[Foo-1.0.jar:?]",
            "Caused by: java.lang.ClassNotFoundException: net.milkbowl.vault.economy.Economy",
            "\tat java.base/java.net.URLClassLoader.findClass(URLClassLoader.java:445) ~[?:?]",
            "\t... 3 more",
        ];
        let chains = extract_chains(text.iter().enumerate().map(|(i, t)| (i as u64 + 1, *t)), 64);
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.exceptions.len(), 2);
        assert_eq!(c.top().unwrap().line, 2);
        assert_eq!(
            c.root_cause().unwrap().simple_name(),
            "ClassNotFoundException"
        );
        assert_eq!(c.root_cause().unwrap().omitted_frames, 3);
        assert_eq!(c.top().unwrap().frames.len(), 1);
    }
}
