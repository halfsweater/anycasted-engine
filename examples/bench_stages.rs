//! Times each pipeline stage separately on one input (development aid).
//!
//! `cargo run --release --example bench_stages -- path/to/latest.log`
use std::time::Instant;

use anycasted_engine::core::models::SourceLine;
use anycasted_engine::detection::DetectionEngine;
use anycasted_engine::parser::{EventBuilder, FormatDetector, ServerProfiler};
use anycasted_engine::{EngineConfig, ingestion};

fn main() {
    let path = std::env::args().nth(1).expect("usage: bench_stages <file>");
    let cfg = EngineConfig::default();

    let t = Instant::now();
    let lines: Vec<_> = ingestion::open_path(path.as_ref(), &cfg)
        .unwrap()
        .lines
        .collect();
    println!("ingest:     {:?} ({} lines)", t.elapsed(), lines.len());

    let t = Instant::now();
    let mut b = EventBuilder::new(&cfg.limits);
    let mut events = Vec::new();
    for l in lines {
        events.extend(b.push(SourceLine {
            number: l.number,
            text: l.text,
        }));
    }
    events.extend(b.finish());
    println!("parse:      {:?} ({} events)", t.elapsed(), events.len());

    let t = Instant::now();
    let mut f = FormatDetector::new();
    events.iter().for_each(|e| f.observe(e));
    println!("format:     {:?}", t.elapsed());

    let t = Instant::now();
    let mut p = ServerProfiler::new(1024);
    events.iter().for_each(|e| {
        p.observe(e);
    });
    println!("profile:    {:?}", t.elapsed());

    let t = Instant::now();
    let d = DetectionEngine::builtin(&cfg.limits).unwrap();
    let mut hits = Vec::new();
    events.iter().for_each(|e| d.detect_event(e, &mut hits));
    println!("detect:     {:?} ({} hits)", t.elapsed(), hits.len());
}
