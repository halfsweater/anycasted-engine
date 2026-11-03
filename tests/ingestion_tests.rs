//! Ingestion robustness: compression, limits, corrupted and hostile input.

mod common;

use std::time::Instant;

use anycasted_engine::{Engine, EngineConfig, EngineError};
use common::*;

#[test]
fn gzip_logs_match_plain_analysis() {
    let plain_bytes = std::fs::read(fixture("paper_plugin_errors.log")).unwrap();
    let gz = temp_path("latest.log.gz");
    write_gzip(&gz, &[&plain_bytes]);
    let plain = analyze("paper_plugin_errors.log");
    let compressed = engine().analyze_path(&gz).unwrap();
    assert_evidence_matches_input(&compressed, &std::fs::read(&gz).unwrap());
    assert_eq!(compressed.input.compression, "gzip");
    assert_eq!(
        compressed.input.lines_processed,
        plain.input.lines_processed
    );
    let key = |r: &anycasted_engine::Report| -> Vec<(String, u64, u64)> {
        r.findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.first_seen.line, f.occurrences))
            .collect()
    };
    assert_eq!(key(&compressed), key(&plain));
}

#[test]
fn concatenated_gzip_members_are_read_fully() {
    let gz = temp_path("rotated.log.gz");
    write_gzip(&gz, &[b"[10:00:00 INFO]: first\n", b"[10:00:01 WARN]: Can't keep up! Is the server overloaded? Running 3000ms or 60 ticks behind\n"]);
    let report = engine().analyze_path(&gz).unwrap();
    assert_eq!(report.input.lines_processed, 2);
    assert_eq!(finding(&report, "PERF-SERVER-LAG").first_seen.line, 2);
}

#[test]
fn truncated_gzip_reports_partial_results() {
    let mut log = String::new();
    log.push_str("[10:00:00] [Server thread/ERROR]: **** FAILED TO BIND TO PORT!\n");
    for i in 0..5_000 {
        log.push_str(&format!(
            "[10:00:01] [Server thread/INFO]: filler line {i} with some entropy {}\n",
            i * 7919 % 104_729
        ));
    }
    let full = temp_path("full.log.gz");
    write_gzip(&full, &[log.as_bytes()]);
    let bytes = std::fs::read(&full).unwrap();
    let cut = temp_path("truncated.log.gz");
    std::fs::write(&cut, &bytes[..bytes.len() / 2]).unwrap();

    let report = engine().analyze_path(&cut).unwrap();
    assert!(!report.input.complete);
    assert!(
        report
            .input
            .warnings
            .iter()
            .any(|w| w.contains("Reading stopped early"))
    );
    assert!(report.input.lines_processed > 0 && report.input.lines_processed < 5_001);
    finding(&report, "STARTUP-PORT-BIND");
}

#[test]
fn decompression_limit_stops_gzip_bombs() {
    let zeros = "A".repeat(4 * 1024 * 1024) + "\n";
    let gz = temp_path("bomb.log.gz");
    write_gzip(&gz, &[zeros.repeat(4).as_bytes()]);
    assert!(
        std::fs::metadata(&gz).unwrap().len() < 200 * 1024,
        "test input should compress well"
    );
    let mut config = EngineConfig::default();
    config.limits.max_decompressed_bytes = 1024 * 1024;
    let report = Engine::new(config).unwrap().analyze_path(&gz).unwrap();
    assert!(!report.input.complete);
    assert!(report.input.bytes_processed <= 1024 * 1024);
    assert!(
        report
            .input
            .warnings
            .iter()
            .any(|w| w.contains("decompressed-size limit"))
    );
}

#[test]
fn corrupted_text_is_decoded_with_accurate_line_numbers() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        b"[10:00:00] [Server thread/INFO]: Starting minecraft server version 1.20.4\r\n",
    );
    bytes.extend_from_slice(b"[10:00:01] [Server thread/INFO]: garbage \xff\xfe\xfd here\r\n");
    bytes.extend_from_slice(b"\x1b[0;31m[10:00:02] [Server thread/ERROR]: Encountered an unexpected exception\x1b[m\r\n");
    bytes.extend_from_slice(b"java.lang.StackOverflowError\r\n");
    bytes.extend_from_slice(b"\tat com.example.Loop.recurse(Loop.java:5) ~[Loopy-1.0.jar:?]\r\n");
    bytes.extend_from_slice(&[0u8; 64]);
    bytes.extend_from_slice(b"\n[10:00:03] [Server thread/INFO]: after the NUL padding");
    let report = engine()
        .analyze_bytes("corrupt.log", bytes.clone())
        .unwrap();
    assert_evidence_matches_input(&report, &bytes);
    assert_eq!(report.input.invalid_utf8_lines, 1);
    assert!(report.input.warnings.iter().any(|w| w.contains("NUL")));
    assert!(
        report
            .input
            .warnings
            .iter()
            .any(|w| w.contains("does not end with a newline"))
    );
    let so = finding(&report, "JAVA-STACK-OVERFLOW");
    assert_eq!(so.first_seen.line, 3);
    assert!(
        so.evidence
            .iter()
            .any(|e| e.line == 4 && e.text == "java.lang.StackOverflowError")
    );
    // The crash message is merged into the stack overflow it printed.
    assert!(so.explanation.contains("This error crashed the server."));
}

#[test]
fn truncated_log_mid_stack_trace() {
    let log = "[10:00:00] [Server thread/ERROR]: Could not pass event BlockBreakEvent to Miner v2.0\n\
               java.lang.IllegalStateException: Block is not loaded\n\
               \tat com.example.miner.Listener.onBreak(Listener.java:1";
    let report = engine()
        .analyze_bytes("cut.log", log.as_bytes().to_vec())
        .unwrap();
    assert_evidence_matches_input(&report, log.as_bytes());
    let f = finding(&report, "PLUGIN-EVENT-EXCEPTION");
    assert!(
        f.explanation.contains("Block is not loaded"),
        "{}",
        f.explanation
    );
    assert!(f.title.contains("a block was broken"));
}

#[test]
fn binary_and_disallowed_inputs_are_rejected() {
    let bin = temp_path("random.log");
    let data: Vec<u8> = (0u32..20_000)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(&bin, &data).unwrap();
    assert!(matches!(
        engine().analyze_path(&bin),
        Err(EngineError::UnsupportedInput(_))
    ));

    let jar = temp_path("plugin.jar");
    std::fs::write(&jar, b"[10:00:00 INFO]: hi\n").unwrap();
    assert!(matches!(
        engine().analyze_path(&jar),
        Err(EngineError::UnsupportedInput(_))
    ));

    let dir = temp_path("a-directory.log");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(matches!(
        engine().analyze_path(&dir),
        Err(EngineError::NotAFile(_))
    ));

    assert!(matches!(
        engine().analyze_path(&temp_path("missing.log")),
        Err(EngineError::NotFound(_))
    ));

    let mut config = EngineConfig::default();
    config.limits.max_file_bytes = 100;
    let big = temp_path("big.log");
    std::fs::write(&big, "x".repeat(101)).unwrap();
    assert!(matches!(
        Engine::new(config).unwrap().analyze_path(&big),
        Err(EngineError::FileTooLarge {
            size: 101,
            limit: 100
        })
    ));
}

#[test]
fn overlong_lines_are_cut() {
    let mut config = EngineConfig::default();
    config.limits.max_line_bytes = 1024;
    let log = format!(
        "[10:00:00 INFO]: {}\n[10:00:01 WARN]: Can't keep up! Is the server overloaded? Running 2500ms or 50 ticks behind\n",
        "z".repeat(100_000)
    );
    let report = Engine::new(config)
        .unwrap()
        .analyze_bytes("long.log", log.into_bytes())
        .unwrap();
    assert_eq!(report.input.overlong_lines, 1);
    assert_eq!(finding(&report, "PERF-SERVER-LAG").first_seen.line, 2);
}

#[test]
fn large_logs_stream_with_accurate_line_numbers() {
    const LINES: u64 = 250_000;
    let path = temp_path("large.log");
    let mut log = String::with_capacity(LINES as usize * 90);
    log.push_str("[00:00:00] [Server thread/INFO]: Starting minecraft server version 1.20.4\n");
    log.push_str("[00:00:05] [Server thread/INFO]: Done (5.0s)! For help, type \"help\"\n");
    let error_line = LINES - 10;
    let mut n = 2;
    while n < LINES {
        n += 1;
        let secs = n / 10;
        let ts = format!(
            "[{:02}:{:02}:{:02}]",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60
        );
        if n == error_line {
            log.push_str(&format!("{ts} [Server thread/ERROR]: java.lang.OutOfMemoryError: GC overhead limit exceeded\n"));
        } else {
            log.push_str(&format!(
                "{ts} [Server thread/INFO]: Player{} moved to chunk {} {}\n",
                n % 97,
                n % 1000,
                n % 777
            ));
        }
    }
    std::fs::write(&path, &log).unwrap();

    let started = Instant::now();
    let report = engine().analyze_path(&path).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(report.input.lines_processed, LINES);
    assert!(report.input.complete);
    let gc = finding(&report, "MEM-GC-OVERHEAD");
    assert_eq!(gc.first_seen.line, error_line);
    assert_evidence_matches_input(&report, log.as_bytes());
    eprintln!("analyzed {LINES} lines in {elapsed:?}");
}

#[cfg(feature = "async")]
#[tokio::test(flavor = "multi_thread")]
async fn async_wrapper_matches_sync() {
    let sync = analyze("paper_oom.log");
    let report = engine()
        .analyze_path_async(fixture("paper_oom.log"))
        .await
        .unwrap();
    assert_eq!(report.findings.len(), sync.findings.len());
}
