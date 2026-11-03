//! Library usage: analyze a file and print evidence-backed findings.
//!
//! ```text
//! cargo run --example analyze_file -- tests/fixtures/paper_plugin_errors.log
//! ```

use anycasted_engine::{Engine, EngineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: analyze_file <path-to-log-or-crash-report>")?;

    let mut config = EngineConfig::default();
    config.limits.max_file_bytes = 256 * 1024 * 1024;
    let engine = Engine::new(config)?;
    let report = engine.analyze_path(path.as_ref())?;

    println!(
        "{} ({}), {} lines, status {:?}",
        report.input.filename,
        report.input.format,
        report.input.lines_processed,
        report.summary.status
    );
    for finding in &report.findings {
        println!(
            "\n[{}] {} — {} ×{} (confidence {:.2}, {:?})",
            finding.severity,
            finding.id,
            finding.title,
            finding.occurrences,
            finding.confidence,
            finding.classification
        );
        for evidence in &finding.evidence {
            println!("  line {:>6}: {}", evidence.line, evidence.text);
        }
    }
    Ok(())
}
