//! Parser tests: line formats, multi-line grouping, line numbers, crash reports and
//! robustness against malformed input.

mod common;

use anycasted_engine::Limits;
use anycasted_engine::core::models::{LogEvent, LogLevel, SourceLine, ThrowableRelation};
use anycasted_engine::parser::{EventBuilder, minecraft::parse_header, parse_crash_report};
use common::*;

fn events(text: &str) -> Vec<LogEvent> {
    let mut builder = EventBuilder::new(&Limits::default());
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        out.extend(builder.push(SourceLine {
            number: i as u64 + 1,
            text: line.to_owned(),
        }));
    }
    out.extend(builder.finish());
    out
}

fn fixture_events(name: &str) -> Vec<LogEvent> {
    events(&std::fs::read_to_string(fixture(name)).unwrap())
}

#[test]
fn header_formats_of_supported_software() {
    let cases: &[(&str, Option<&str>, Option<&str>, &str)] = &[
        // (line, thread, logger, message)
        (
            "[10:00:03] [Server thread/INFO]: Starting minecraft server version 1.20.4",
            Some("Server thread"),
            None,
            "Starting minecraft server version 1.20.4",
        ),
        (
            "[08:00:04 ERROR]: Cannot load plugins/Shop/config.yml",
            None,
            None,
            "Cannot load plugins/Shop/config.yml",
        ),
        (
            "[12:00:00] [main/INFO] [com.velocitypowered.proxy.VelocityServer]: Booting up Velocity 3.3.0",
            Some("main"),
            Some("com.velocitypowered.proxy.VelocityServer"),
            "Booting up Velocity 3.3.0",
        ),
        (
            "[12:00:00 INFO] [luckperms]: Loading configuration...",
            None,
            Some("luckperms"),
            "Loading configuration...",
        ),
        (
            "[02Jan2024 12:00:01.123] [main/INFO] [cpw.mods.modlauncher.Launcher/MODLAUNCHER]: ModLauncher running",
            Some("main"),
            Some("cpw.mods.modlauncher.Launcher/MODLAUNCHER"),
            "ModLauncher running",
        ),
        (
            "2015-06-01 18:00:01 [SEVERE] Could not load 'plugins/OldWarps.jar'",
            None,
            None,
            "Could not load 'plugins/OldWarps.jar'",
        ),
        (
            "[10:20:00] [Craft Scheduler Thread - 7 - TreeFeller/WARN]: [TreeFeller] Task failed",
            Some("Craft Scheduler Thread - 7 - TreeFeller"),
            None,
            "[TreeFeller] Task failed",
        ),
    ];
    for (line, thread, logger, message) in cases {
        let h = parse_header(line).unwrap_or_else(|| panic!("no header: {line}"));
        assert_eq!(h.thread.as_deref(), *thread, "{line}");
        assert_eq!(h.logger.as_deref(), *logger, "{line}");
        assert_eq!(&line[h.message_start..], *message, "{line}");
        assert!(h.timestamp.is_some() && h.level.is_some(), "{line}");
    }
}

#[test]
fn multiline_events_preserve_line_numbers() {
    let evs = fixture_events("paper_plugin_errors.log");
    let enable = evs
        .iter()
        .find(|e| e.message().starts_with("Error occurred while enabling"))
        .unwrap();
    assert_eq!(enable.start_line(), 26);
    assert_eq!(enable.last_line, 34);
    assert_eq!(enable.level(), Some(LogLevel::Error));
    let chain = &enable.exceptions[0];
    assert_eq!(chain.exceptions.len(), 2);
    let (top, root) = (chain.top().unwrap(), chain.root_cause().unwrap());
    assert_eq!(
        (top.line, top.class.as_str()),
        (27, "java.lang.NoClassDefFoundError")
    );
    assert_eq!(top.frames.len(), 3);
    assert_eq!(top.frames[0].line, 28);
    assert_eq!(top.frames[0].jar.as_deref(), Some("WelcomePlus-1.4.2.jar"));
    assert_eq!(top.frames[0].line_number, Some(58));
    assert_eq!(
        (root.line, root.relation),
        (31, ThrowableRelation::CausedBy)
    );
    assert_eq!(root.omitted_frames, 3);
    // Every line belongs to exactly one event, in order.
    let mut expected = 1;
    for e in &evs {
        assert_eq!(e.start_line(), expected);
        expected = e.last_line + 1;
    }
    assert_eq!(expected - 1, 79);
}

#[test]
fn missing_timestamps_and_headerless_output() {
    let evs = fixture_events("paper_oom.log");
    let stderr: Vec<_> = evs.iter().filter(|e| e.header.is_none()).collect();
    assert_eq!(stderr.len(), 2);
    assert_eq!(stderr[0].start_line(), 22);
    assert_eq!(stderr[0].timestamp(), None);
    assert_eq!(
        stderr[0].exceptions[0].top().unwrap().simple_name(),
        "OutOfMemoryError"
    );
}

#[test]
fn thread_dump_lines_stay_with_their_header() {
    let evs = fixture_events("purpur_server.log");
    let yaml = evs
        .iter()
        .find(|e| e.message().starts_with("Cannot load"))
        .unwrap();
    assert_eq!((yaml.start_line(), yaml.last_line), (6, 17));
    let chain = &yaml.exceptions[0];
    assert_eq!(
        chain.root_cause().unwrap().class,
        "org.yaml.snakeyaml.scanner.ScannerException"
    );
}

#[test]
fn crash_report_sections() {
    let text = std::fs::read_to_string(fixture("crash-2024-04-21_18.03.11-server.txt")).unwrap();
    let lines: Vec<SourceLine> = text
        .lines()
        .enumerate()
        .map(|(i, t)| SourceLine {
            number: i as u64 + 1,
            text: t.to_owned(),
        })
        .collect();
    let report = parse_crash_report(&lines, 64);
    assert_eq!(report.time.as_ref().unwrap().value, "2024-04-21 18:03:11");
    assert_eq!(report.description.as_ref().unwrap().line, 5);
    let names: Vec<_> = report.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["Head", "Entity being ticked", "System Details"]);
    let entity = report.section("Entity being ticked").unwrap();
    assert_eq!(
        entity.detail("Entity's Exact location").unwrap().value,
        "104.50, 71.00, -233.18"
    );
    assert!(report.jvm_flags.as_ref().unwrap().value.contains("-Xmx4G"));
    assert!(report.suspected_mods.is_empty());
    let mem = report.memory.unwrap();
    assert!(mem.used_fraction_of_max() > 0.95);
}

#[test]
fn timestamps_roll_over_midnight() {
    let evs = events("[23:59:58] [Server thread/INFO]: a\n[00:00:02] [Server thread/ERROR]: b");
    let (a, b) = (evs[0].timestamp().unwrap(), evs[1].timestamp().unwrap());
    assert_eq!(a.millis_until(&b), Some(4_000));
}

/// Deterministic pseudo-random generator (no external dependency needed).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

#[test]
fn malformed_input_never_panics() {
    const ALPHABET: &[&str] = &[
        "[",
        "]",
        ":",
        " ",
        "/",
        "INFO",
        "ERROR",
        "12:00:00",
        "99:99:99",
        "at ",
        "(",
        ")",
        "Caused by: ",
        "java.lang.",
        "Exception",
        "\t",
        "...",
        " more",
        "é",
        "\u{fffd}",
        "[Not Secure] ",
        "<",
        ">",
        "---- Minecraft Crash Report ----",
        "-- ",
        " --",
        "Memory: ",
        " bytes",
        "Description: ",
        "~[",
        ".jar:?]",
    ];
    let mut rng = Lcg(42);
    let mut text = String::new();
    for _ in 0..3_000 {
        let tokens = rng.next() % 12;
        for _ in 0..tokens {
            text.push_str(ALPHABET[(rng.next() as usize) % ALPHABET.len()]);
        }
        text.push('\n');
    }
    for line in text.lines() {
        let _ = parse_header(line);
    }
    let report = engine()
        .analyze_bytes("fuzz.log", text.clone().into_bytes())
        .unwrap();
    assert_evidence_matches_input(&report, text.as_bytes());
    // Same content presented as a crash report.
    let crash = format!("---- Minecraft Crash Report ----\n{text}");
    let report = engine()
        .analyze_bytes("fuzz-crash.txt", crash.clone().into_bytes())
        .unwrap();
    assert_evidence_matches_input(&report, crash.as_bytes());
}
