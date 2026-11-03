//! The analysis pipeline.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anycasted_analysis::{Aggregator, Correlator, assemble, summarize};
use anycasted_core::models::{
    CrashReport, CrashReportInfo, EngineInfo, Evidence, EvidenceRole, ExceptionInfo,
    FormatConfidence, FormatDetection, Hit, InputInfo, LogEvent, LogFormat, Occurrence, Report,
    RuleMeta, ServerInfo, Severity, SourceLine, TemplateVars,
};
use anycasted_core::text::excerpt;
use anycasted_core::{ENGINE_NAME, ENGINE_VERSION, EngineConfig, REPORT_SCHEMA_VERSION, Result};
use anycasted_detection::{DetectionEngine, RuleSet};
use anycasted_ingestion::{IngestStats, InputMeta, LineReader, OpenedInput, RawLine};
use anycasted_parser::{
    EventBuilder, FormatDetector, LifecycleSignal, ParseStats, ServerProfiler,
    looks_like_crash_report, parse_crash_report,
};

/// Non-blank lines inspected to recognize a crash report.
const CRASH_SNIFF_LINES: usize = 8;
/// Maximum lines buffered while sniffing (protects against long blank prefixes).
const SNIFF_BUFFER_LINES: usize = 256;

/// The diagnostics engine. Cheap to clone; safe to share across threads.
#[derive(Debug, Clone)]
pub struct Engine {
    config: Arc<EngineConfig>,
    detection: Arc<DetectionEngine>,
}

impl Engine {
    /// Creates an engine with the built-in rules.
    pub fn new(config: EngineConfig) -> Result<Self> {
        Self::with_rules(config, RuleSet::builtin())
    }

    /// Creates an engine with a custom rule set.
    pub fn with_rules(config: EngineConfig, rules: RuleSet) -> Result<Self> {
        config.validate()?;
        let detection = DetectionEngine::new(rules, &config.limits)?;
        Ok(Self {
            config: Arc::new(config),
            detection: Arc::new(detection),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Metadata of all rules, sorted by id.
    pub fn rule_catalog(&self) -> Vec<Arc<RuleMeta>> {
        let mut catalog = self.detection.rules().catalog();
        catalog.push(anycasted_analysis::patterns::repeated_error_meta());
        catalog.sort_by(|a, b| a.id.cmp(&b.id));
        catalog
    }

    /// Analyzes a file (plain text or gzip).
    pub fn analyze_path(&self, path: &Path) -> Result<Report> {
        let input = anycasted_ingestion::open_path(path, &self.config)?;
        Ok(self.run(input))
    }

    /// Analyzes an arbitrary reader (e.g. an upload stream). `name` is used for display.
    pub fn analyze_reader<R: Read + Send + 'static>(
        &self,
        name: &str,
        reader: R,
    ) -> Result<Report> {
        let input = anycasted_ingestion::open_reader(name, reader, &self.config)?;
        Ok(self.run(input))
    }

    /// Analyzes in-memory content.
    pub fn analyze_bytes(&self, name: &str, bytes: Vec<u8>) -> Result<Report> {
        if bytes.len() as u64 > self.config.limits.max_file_bytes {
            return Err(anycasted_core::EngineError::FileTooLarge {
                size: bytes.len() as u64,
                limit: self.config.limits.max_file_bytes,
            });
        }
        self.analyze_reader(name, std::io::Cursor::new(bytes))
    }

    /// Async wrapper around [`Engine::analyze_path`] that runs the CPU-bound analysis
    /// on Tokio's blocking thread pool.
    #[cfg(feature = "async")]
    pub async fn analyze_path_async(&self, path: std::path::PathBuf) -> Result<Report> {
        let engine = self.clone();
        tokio::task::spawn_blocking(move || engine.analyze_path(&path))
            .await
            .map_err(|e| {
                anycasted_core::EngineError::io("joining analysis task", std::io::Error::other(e))
            })?
    }

    fn run(&self, input: OpenedInput) -> Report {
        let OpenedInput { meta, mut lines } = input;
        let mut prefix = Vec::new();
        let mut non_blank = 0;
        while non_blank < CRASH_SNIFF_LINES && prefix.len() < SNIFF_BUFFER_LINES {
            let Some(line) = lines.next() else { break };
            non_blank += usize::from(!line.text.trim().is_empty());
            prefix.push(line);
        }
        let crash =
            looks_like_crash_report(prefix.iter().map(|l| l.text.as_str()), CRASH_SNIFF_LINES);
        tracing::debug!(input = %meta.name, crash, "analysis started");
        if crash {
            self.analyze_crash(meta, prefix, lines)
        } else {
            self.analyze_log(meta, prefix, lines)
        }
    }

    fn analyze_log(&self, meta: InputMeta, prefix: Vec<RawLine>, mut lines: LineReader) -> Report {
        let mut pipeline = LogPipeline::new(self);
        for raw in prefix.into_iter().chain(lines.by_ref()) {
            pipeline.feed(raw);
        }
        pipeline.finish(meta, lines.stats())
    }

    fn analyze_crash(
        &self,
        meta: InputMeta,
        prefix: Vec<RawLine>,
        mut lines: LineReader,
    ) -> Report {
        let limits = &self.config.limits;
        let mut source: Vec<SourceLine> = Vec::new();
        let mut truncated = false;
        for raw in prefix.into_iter().chain(lines.by_ref()) {
            if source.len() >= limits.max_crash_report_lines {
                truncated = true;
                break;
            }
            source.push(SourceLine {
                number: raw.number,
                text: raw.text,
            });
        }
        let report = parse_crash_report(&source, limits.max_frames_per_exception);
        let mut hits = Vec::new();
        self.detection.detect_crash(&report, &source, &mut hits);

        // All findings of a crash report describe the same crash, so no correlations
        // are derived; the `crash_report` section ties them together.
        let mut aggregator = Aggregator::new(limits);
        for hit in hits {
            aggregator.add(hit);
        }
        let dropped = aggregator.dropped_hits();
        let aggregation = aggregator.finish(&self.config.analysis);
        let drafts = Vec::new();
        let plugins = report.plugins.clone();
        let loaded = |name: &str| plugins.iter().any(|p| names_match(p, name));
        let inventory: Option<&dyn Fn(&str) -> bool> = (!plugins.is_empty()).then_some(&loaded);
        let mut globals = TemplateVars::new();
        if let Some(v) = &report.minecraft_version {
            globals.insert("minecraft_version".into(), v.value.clone());
        }
        let (findings, correlations) = assemble(aggregation, drafts, inventory, &globals);

        let stats = lines.stats();
        let mut warnings = ingest_warnings(stats, &self.config);
        if truncated {
            warnings.push(format!(
                "The crash report exceeds {} lines; only the first {} lines were analyzed.",
                limits.max_crash_report_lines, limits.max_crash_report_lines
            ));
        }
        if report.description.is_none() {
            warnings
                .push("The crash report has no `Description:` line; it may be truncated.".into());
        }
        let format = FormatDetection {
            format: LogFormat::CrashReport,
            confidence: FormatConfidence::High,
            uncertain: false,
            indicators: source
                .iter()
                .find(|l| l.number == report.header_line)
                .map(|l| Evidence {
                    line: l.number,
                    text: l.text.clone(),
                    role: EvidenceRole::Context,
                    timestamp: None,
                })
                .into_iter()
                .collect(),
        };
        let parse = ParseStats {
            events: 1,
            ..ParseStats::default()
        };
        let input = input_info(&meta, stats, &parse, format, warnings, truncated);
        Report {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            engine: engine_info(),
            input,
            server: None,
            crash_report: Some(crash_info(&report)),
            summary: summarize(&findings, dropped),
            findings,
            correlations,
        }
    }
}

/// Streaming state for log analysis.
struct LogPipeline<'a> {
    engine: &'a Engine,
    builder: EventBuilder,
    format: FormatDetector,
    profiler: ServerProfiler,
    aggregator: Aggregator,
    correlator: Correlator,
    hits: Vec<Hit>,
    startup_marker: Option<Evidence>,
    first_error_after_startup: Option<(Occurrence, Option<Evidence>)>,
    had_shutdown: bool,
    last_line: u64,
}

impl<'a> LogPipeline<'a> {
    fn new(engine: &'a Engine) -> Self {
        let cfg = &engine.config;
        Self {
            engine,
            builder: EventBuilder::new(&cfg.limits),
            format: FormatDetector::new(),
            profiler: ServerProfiler::new(cfg.limits.max_inventory_plugins),
            aggregator: Aggregator::new(&cfg.limits),
            correlator: Correlator::new(&cfg.analysis),
            hits: Vec::new(),
            startup_marker: None,
            first_error_after_startup: None,
            had_shutdown: false,
            last_line: 0,
        }
    }

    fn feed(&mut self, raw: RawLine) {
        self.last_line = raw.number;
        if let Some(event) = self.builder.push(SourceLine {
            number: raw.number,
            text: raw.text,
        }) {
            self.process(&event);
        }
    }

    fn process(&mut self, event: &LogEvent) {
        self.format.observe(event);
        self.aggregator.observe_recovery(event);
        let signal = self.profiler.observe(event);

        self.engine.detection.detect_event(event, &mut self.hits);
        for hit in self.hits.drain(..) {
            let (severity, occurrence) = (hit.severity, hit.occurrence);
            let tracking_startup = self.startup_marker.is_some()
                && self.profiler.info().startup_completed == Some(false)
                && self.first_error_after_startup.is_none()
                && severity >= Severity::Error;
            if tracking_startup {
                let main = hit
                    .evidence
                    .iter()
                    .find(|e| e.role == EvidenceRole::Match)
                    .or_else(|| hit.evidence.first())
                    .cloned();
                self.first_error_after_startup = Some((occurrence, main));
            }
            if let Some(idx) = self.aggregator.add(hit) {
                self.correlator.observe_hit(idx, severity, occurrence);
            }
        }

        match signal {
            LifecycleSignal::StartupBegan if self.startup_marker.is_none() => {
                self.startup_marker = Some(marker(event));
            }
            LifecycleSignal::Shutdown => {
                self.had_shutdown = true;
                self.correlator
                    .observe_shutdown(marker(event), self.aggregator.groups());
            }
            _ => {}
        }
    }

    fn finish(mut self, meta: InputMeta, stats: &IngestStats) -> Report {
        if let Some(event) = self.builder.finish() {
            self.process(&event);
        }
        self.check_startup();

        let cfg = &self.engine.config;
        let dropped = self.aggregator.dropped_hits();
        let aggregation = self.aggregator.finish(&cfg.analysis);
        let drafts = self
            .correlator
            .finish(&aggregation.groups, self.last_line, self.had_shutdown);
        let server = self.profiler.finish();
        let plugins: Vec<String> = server.plugins.iter().map(|p| p.name.clone()).collect();
        let loaded = |name: &str| plugins.iter().any(|p| names_match(p, name));
        let inventory: Option<&dyn Fn(&str) -> bool> = (!plugins.is_empty()).then_some(&loaded);
        let globals = global_vars(&server);
        let (findings, correlations) = assemble(aggregation, drafts, inventory, &globals);

        let parse = self.builder.stats().clone();
        let mut warnings = ingest_warnings(stats, cfg);
        if parse.omitted_lines > 0 {
            warnings.push(format!(
                "{} line(s) inside very large log entries were not retained (limit: {} lines per entry); findings in those lines may be missed.",
                parse.omitted_lines, cfg.limits.max_event_lines
            ));
        }
        if dropped > 0 {
            warnings.push(format!(
                "{dropped} detection(s) were dropped because the limit of {} distinct findings was reached.",
                cfg.limits.max_finding_groups
            ));
        }
        let input = input_info(&meta, stats, &parse, self.format.finish(), warnings, false);
        Report {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            engine: engine_info(),
            input,
            server: Some(server).filter(|s| *s != ServerInfo::default()),
            crash_report: None,
            summary: summarize(&findings, dropped),
            findings,
            correlations,
        }
    }

    /// Emits `STARTUP-INCOMPLETE` when startup began, never completed, and errors
    /// were logged after it began.
    fn check_startup(&mut self) {
        if self.profiler.info().startup_completed != Some(false) {
            return;
        }
        let (Some(start), Some((first_error, error_evidence))) = (
            self.startup_marker.clone(),
            self.first_error_after_startup.clone(),
        ) else {
            return;
        };
        let meta = Arc::clone(self.engine.detection.startup_incomplete_meta());
        let mut hit = Hit::new(
            meta,
            String::new(),
            Occurrence {
                line: start.line,
                timestamp: start.timestamp,
            },
        );
        hit.notes.push(format!(
            "Startup began at line {}; the first error-level finding after it is at line {}; the log ends at line {} without a completion message.",
            start.line, first_error.line, self.last_line
        ));
        hit.evidence.push(start);
        hit.evidence.extend(error_evidence);
        if let Some(idx) = self.aggregator.add(hit) {
            let g = &self.aggregator.groups()[idx];
            self.correlator.observe_hit(idx, g.severity, g.first);
        }
    }
}

/// Template variables known for the whole log.
fn global_vars(server: &ServerInfo) -> TemplateVars {
    let mut vars = TemplateVars::new();
    if let Some(v) = &server.minecraft_version {
        vars.insert("minecraft_version".into(), v.value.clone());
    }
    if let Some(port) = server
        .bind_address
        .as_ref()
        .and_then(|a| a.value.rsplit_once(':'))
    {
        if port.1.bytes().all(|b| b.is_ascii_digit()) {
            vars.insert("port".into(), port.1.to_owned());
        }
    }
    if let Some(sw) = &server.software {
        vars.insert("software".into(), sw.value.clone());
    }
    vars
}

fn marker(event: &LogEvent) -> Evidence {
    let line = event.first_line();
    Evidence {
        line: line.number,
        text: excerpt(&line.text, 600).into_owned(),
        role: EvidenceRole::Context,
        timestamp: event.timestamp(),
    }
}

/// Plugin name comparison tolerant of jar-derived names (`LuckPerms-Bukkit` vs
/// `LuckPerms`).
fn names_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    a == b || a.starts_with(&format!("{b}-")) || b.starts_with(&format!("{a}-"))
}

fn engine_info() -> EngineInfo {
    EngineInfo {
        name: ENGINE_NAME.into(),
        version: ENGINE_VERSION.into(),
    }
}

fn ingest_warnings(stats: &IngestStats, cfg: &EngineConfig) -> Vec<String> {
    let mut w = Vec::new();
    if stats.lines == 0 {
        w.push("The input is empty.".into());
    }
    if stats.limit_reached {
        w.push(format!(
            "Analysis stopped after {} bytes because the decompressed-size limit was reached; findings cover only the analyzed part.",
            stats.bytes_read
        ));
    }
    if let Some(err) = &stats.read_error {
        w.push(format!(
            "Reading stopped early after line {} ({err}); the input may be truncated or corrupted. Findings cover only the readable part.",
            stats.lines
        ));
    }
    if stats.ended_without_newline && stats.lines > 0 {
        w.push("The input does not end with a newline; the last line may be truncated.".into());
    }
    if stats.invalid_utf8_lines > 0 {
        w.push(format!(
            "{} line(s) contained invalid UTF-8 and were decoded with replacement characters.",
            stats.invalid_utf8_lines
        ));
    }
    if stats.overlong_lines > 0 {
        w.push(format!(
            "{} line(s) exceeded {} bytes and were cut.",
            stats.overlong_lines, cfg.limits.max_line_bytes
        ));
    }
    if stats.nul_bytes_removed > 0 {
        w.push(format!(
            "{} NUL byte(s) were removed (typical of a log file truncated by a crash or power loss).",
            stats.nul_bytes_removed
        ));
    }
    w
}

fn input_info(
    meta: &InputMeta,
    stats: &IngestStats,
    parse: &ParseStats,
    format: FormatDetection,
    warnings: Vec<String>,
    truncated: bool,
) -> InputInfo {
    InputInfo {
        filename: meta.name.clone(),
        format: format.format,
        format_confidence: format.confidence,
        format_uncertain: format.uncertain,
        format_indicators: format.indicators,
        compression: meta.compression.as_str().into(),
        bytes_processed: stats.bytes_read,
        lines_processed: stats.lines,
        events_parsed: parse.events,
        unstructured_lines: parse.unstructured_lines,
        invalid_utf8_lines: stats.invalid_utf8_lines,
        overlong_lines: stats.overlong_lines,
        complete: stats.complete() && !truncated,
        warnings,
    }
}

fn crash_info(report: &CrashReport) -> CrashReportInfo {
    let exception = report.exception.as_ref().and_then(|chain| {
        let top = chain.top()?;
        let root = chain.root_cause().filter(|r| r.class != top.class);
        Some(ExceptionInfo {
            class: top.class.clone(),
            message: top.message.clone(),
            line: top.line,
            root_cause: root.map(|r| r.class.clone()),
        })
    });
    CrashReportInfo {
        description: report.description.clone(),
        time: report.time.clone(),
        minecraft_version: report.minecraft_version.clone(),
        java_version: report.java_version.clone(),
        operating_system: report.operating_system.clone(),
        server_brand: report.server_brand.clone(),
        jvm_flags: report.jvm_flags.clone(),
        memory: report.memory,
        exception,
        suspected_mods: report.suspected_mods.clone(),
        plugins: report.plugins.clone(),
        sections: report
            .sections
            .iter()
            .map(|s| anycasted_core::models::Located::new(s.name.clone(), s.line))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_name_matching() {
        assert!(names_match("LuckPerms", "luckperms"));
        assert!(names_match("LuckPerms", "LuckPerms-Bukkit"));
        assert!(!names_match("Luck", "LuckPerms"));
    }

    #[test]
    fn empty_input_produces_valid_report() {
        let engine = Engine::new(EngineConfig::default()).unwrap();
        let report = engine.analyze_bytes("empty.log", Vec::new()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.input.lines_processed, 0);
        assert_eq!(report.input.format, LogFormat::Unknown);
        assert_eq!(report.summary.total_findings, 0);
    }
}
