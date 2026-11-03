//! Shared helpers for integration tests.
#![allow(dead_code, missing_docs)]

use std::io::Read;
use std::path::{Path, PathBuf};

use anycasted_engine::core::models::{Evidence, Finding, Report};
use anycasted_engine::{Engine, EngineConfig};

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A unique path in Cargo's per-test temporary directory.
pub fn temp_path(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("anycasted-tests");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

pub fn engine() -> Engine {
    Engine::new(EngineConfig::default()).unwrap()
}

pub fn analyze(name: &str) -> Report {
    let report = engine().analyze_path(&fixture(name)).unwrap();
    let bytes = std::fs::read(fixture(name)).unwrap();
    assert_evidence_matches_input(&report, &bytes);
    report
}

/// Decodes input the same way the ingestion layer does, so line numbers and texts can
/// be compared: split on `\n`, drop a trailing `\r`, remove NUL bytes, decode UTF-8
/// lossily, strip ANSI/control sequences. gzip input is decompressed first.
pub fn decoded_lines(bytes: &[u8]) -> Vec<String> {
    let mut data = bytes.to_vec();
    if data.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        let _ = flate2::read::MultiGzDecoder::new(bytes).read_to_end(&mut out);
        data = out;
    }
    if data.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = data
        .split(|&b| b == b'\n')
        .map(|raw| {
            let mut raw: Vec<u8> = raw.to_vec();
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }
            raw.retain(|&b| b != 0);
            let text = String::from_utf8_lossy(&raw).into_owned();
            anycasted_engine::ingestion::strip_control_sequences(&text).into_owned()
        })
        .collect();
    if data.last() == Some(&b'\n') {
        lines.pop();
    }
    lines
}

fn check_evidence(e: &Evidence, lines: &[String], context: &str) {
    assert!(
        e.line >= 1 && (e.line as usize) <= lines.len(),
        "{context}: evidence line {} out of range (input has {} lines)",
        e.line,
        lines.len()
    );
    let actual = &lines[e.line as usize - 1];
    match e.text.strip_suffix('…') {
        Some(prefix) if actual != &e.text => assert!(
            actual.starts_with(prefix),
            "{context}: shortened evidence at line {} is not a prefix of the input line\n  evidence: {:?}\n  input:    {:?}",
            e.line,
            e.text,
            actual
        ),
        _ => assert_eq!(
            &e.text, actual,
            "{context}: evidence text differs from input line {}",
            e.line
        ),
    }
}

/// Asserts that every line reference in the report points at real input and that every
/// evidence text is the verbatim input line.
pub fn assert_evidence_matches_input(report: &Report, bytes: &[u8]) {
    let lines = decoded_lines(bytes);
    assert_eq!(
        report.input.lines_processed as usize,
        lines.len(),
        "lines_processed mismatch"
    );
    for f in &report.findings {
        assert!(!f.evidence.is_empty(), "{} has no evidence", f.id);
        for e in &f.evidence {
            check_evidence(e, &lines, &f.id);
        }
        for line in [f.first_seen.line, f.last_seen.line]
            .iter()
            .chain(&f.other_occurrence_lines)
        {
            assert!(
                *line >= 1 && (*line as usize) <= lines.len(),
                "{}: occurrence line {line} out of range",
                f.id
            );
        }
        assert!(
            f.first_seen.line <= f.last_seen.line,
            "{}: first after last",
            f.id
        );
        assert!((0.0..=1.0).contains(&f.confidence));
    }
    for c in &report.correlations {
        for e in &c.evidence {
            check_evidence(e, &lines, &c.id);
        }
        for id in &c.findings {
            assert!(
                report.findings.iter().any(|f| &f.id == id),
                "{} references unknown {id}",
                c.id
            );
        }
    }
    for e in &report.input.format_indicators {
        check_evidence(e, &lines, "format indicator");
    }
}

pub fn rule_ids(report: &Report) -> Vec<&str> {
    report.findings.iter().map(|f| f.rule_id.as_str()).collect()
}

pub fn findings<'a>(report: &'a Report, rule_id: &str) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|f| f.rule_id == rule_id)
        .collect()
}

pub fn finding<'a>(report: &'a Report, rule_id: &str) -> &'a Finding {
    let found = findings(report, rule_id);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one {rule_id}, found {} (all: {:?})",
        found.len(),
        rule_ids(report)
    );
    found[0]
}

pub fn write_gzip(path: &Path, members: &[&[u8]]) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    for m in members {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(m).unwrap();
        file.write_all(&enc.finish().unwrap()).unwrap();
    }
}
