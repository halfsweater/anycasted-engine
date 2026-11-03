//! Deterministic, rule-based detection.
//!
//! The [`DetectionEngine`] evaluates a [`RuleSet`] against normalized events and crash
//! reports and emits [`Hit`]s. Every hit carries verbatim evidence copied from the
//! event's source lines, so findings can always be traced back to the input.
//!
//! Rules are grouped by domain:
//! [`exceptions`], [`memory`], [`dependencies`], [`plugins`], [`startup`],
//! [`networking`], [`performance`], [`shutdown`], [`crash`].
//!
//! To add a rule, implement [`LogRule`]/[`CrashRule`] or build a [`TextRule`] /
//! [`ExceptionRule`], and register it with [`RuleSet::with_log_rule`] (etc.). The
//! engine does not need to change.

pub mod attribution;
pub mod crash;
pub mod database;
pub mod dependencies;
pub mod exceptions;
mod hints;
pub mod memory;
pub mod networking;
pub mod performance;
pub mod plugins;
mod rule;
pub mod shutdown;
pub mod startup;

use std::collections::BTreeMap;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};

use anycasted_core::models::{
    CrashReport, Evidence, EvidenceRole, ExceptionChain, Hit, Implication, LogEvent, LogLevel,
    Occurrence, RuleMeta, RuleRole, Severity, SourceLine, Subject, ThrownException,
};
use anycasted_core::text::{Fingerprinter, excerpt, normalize_message};
use anycasted_core::{EngineError, Limits};

pub use rule::{
    CrashMatch, CrashRule, EventView, ExceptionExtractor, ExceptionRule, Extraction, LogMatch,
    LogRule, TextExtractor, TextLine, TextRule,
};

/// Frames used for stack trace fingerprints.
const SIGNATURE_FRAMES: usize = 5;
/// Maximum plugins implicated from stack frames per hit.
const MAX_FRAME_IMPLICATIONS: usize = 5;

/// A collection of rules.
pub struct RuleSet {
    log_rules: Vec<Box<dyn LogRule>>,
    exception_rules: Vec<ExceptionRule>,
    crash_rules: Vec<Box<dyn CrashRule>>,
    fallback: Arc<RuleMeta>,
    startup_incomplete: Arc<RuleMeta>,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("log_rules", &self.log_rules.len())
            .field("exception_rules", &self.exception_rules.len())
            .field("crash_rules", &self.crash_rules.len())
            .finish()
    }
}

impl RuleSet {
    /// An empty rule set (the fallback and end-of-input rules are always present).
    pub fn empty() -> Self {
        Self {
            log_rules: Vec::new(),
            exception_rules: Vec::new(),
            crash_rules: Vec::new(),
            fallback: exceptions::unclassified_meta(),
            startup_incomplete: startup::startup_incomplete_meta(),
        }
    }

    /// All built-in rules.
    pub fn builtin() -> Self {
        let mut set = Self::empty();
        set.exception_rules.extend(exceptions::exception_rules());
        set.exception_rules.extend(memory::exception_rules());
        set.exception_rules.extend(dependencies::exception_rules());
        set.exception_rules.extend(plugins::exception_rules());
        set.exception_rules.extend(startup::exception_rules());
        set.exception_rules.extend(networking::exception_rules());
        set.exception_rules.extend(database::exception_rules());
        set.exception_rules.extend(shutdown::exception_rules());
        set.log_rules.extend(memory::log_rules());
        set.log_rules.extend(plugins::log_rules());
        set.log_rules.extend(startup::log_rules());
        set.log_rules.extend(networking::log_rules());
        set.log_rules.extend(performance::log_rules());
        set.log_rules.extend(shutdown::log_rules());
        set.log_rules.extend(database::log_rules());
        set.crash_rules.extend(crash::crash_rules());
        set
    }

    /// Adds a log rule.
    pub fn with_log_rule(mut self, rule: Box<dyn LogRule>) -> Self {
        self.log_rules.push(rule);
        self
    }

    /// Adds an exception rule.
    pub fn with_exception_rule(mut self, rule: ExceptionRule) -> Self {
        self.exception_rules.push(rule);
        self
    }

    /// Adds a crash rule.
    pub fn with_crash_rule(mut self, rule: Box<dyn CrashRule>) -> Self {
        self.crash_rules.push(rule);
        self
    }

    /// Metadata of every rule, unique by id, sorted by id.
    pub fn catalog(&self) -> Vec<Arc<RuleMeta>> {
        let mut map: BTreeMap<String, Arc<RuleMeta>> = BTreeMap::new();
        for meta in self.metas() {
            map.entry(meta.id.clone())
                .or_insert_with(|| Arc::clone(meta));
        }
        map.into_values().collect()
    }

    fn metas(&self) -> impl Iterator<Item = &Arc<RuleMeta>> {
        self.log_rules
            .iter()
            .map(|r| r.meta())
            .chain(self.exception_rules.iter().map(ExceptionRule::meta))
            .chain(self.crash_rules.iter().map(|r| r.meta()))
            .chain([&self.fallback, &self.startup_incomplete])
    }

    /// Checks that rule ids are well-formed and that rules sharing an id share
    /// identical metadata.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen: BTreeMap<&str, &RuleMeta> = BTreeMap::new();
        for meta in self.metas() {
            let valid_id = !meta.id.is_empty()
                && meta
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
            if !valid_id {
                return Err(format!(
                    "invalid rule id `{}` (expected UPPER-KEBAB-CASE)",
                    meta.id
                ));
            }
            if meta.title.is_empty()
                || meta.description.is_empty()
                || meta.user_title.is_empty()
                || meta.explanation.is_empty()
                || meta.recommendations.is_empty()
            {
                return Err(format!(
                    "rule `{}` lacks a title, description, user title, explanation or fix steps",
                    meta.id
                ));
            }
            if (meta.role == RuleRole::Context) != meta.context_note.is_some() {
                return Err(format!(
                    "rule `{}`: context rules (and only they) need a context note",
                    meta.id
                ));
            }
            for t in meta.templates() {
                if let Some(issue) = anycasted_core::text::template_issues(t).into_iter().next() {
                    return Err(format!("rule `{}`: template {t:?}: {issue}", meta.id));
                }
            }
            match seen.get(meta.id.as_str()) {
                Some(existing) if **existing != **meta => {
                    return Err(format!(
                        "rule id `{}` is used by rules with different metadata",
                        meta.id
                    ));
                }
                _ => {
                    seen.insert(&meta.id, meta);
                }
            }
        }
        Ok(())
    }
}

/// Multi-pattern prefilter over the needles of all log rules.
#[derive(Debug)]
struct Prefilter {
    automaton: AhoCorasick,
    /// Pattern id → log rule index.
    pattern_rule: Vec<usize>,
    /// Log rules without needles (always evaluated).
    unfiltered: Vec<usize>,
}

impl Prefilter {
    fn new(rules: &[Box<dyn LogRule>]) -> Result<Self, EngineError> {
        let mut patterns = Vec::new();
        let mut pattern_rule = Vec::new();
        let mut unfiltered = Vec::new();
        for (idx, rule) in rules.iter().enumerate() {
            match rule.prefilter() {
                Some(needles) if !needles.is_empty() => {
                    for n in needles {
                        patterns.push(n.as_str());
                        pattern_rule.push(idx);
                    }
                }
                _ => unfiltered.push(idx),
            }
        }
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| EngineError::InvalidConfig(format!("rule needles: {e}")))?;
        Ok(Self {
            automaton,
            pattern_rule,
            unfiltered,
        })
    }

    /// Indices of rules that may match the view, in registration order.
    fn candidates(&self, view: &EventView<'_>, rule_count: usize) -> Vec<usize> {
        let mut flags = vec![false; rule_count];
        for idx in &self.unfiltered {
            flags[*idx] = true;
        }
        for line in view.text_lines() {
            for m in self.automaton.find_overlapping_iter(line.text) {
                flags[self.pattern_rule[m.pattern().as_usize()]] = true;
            }
        }
        flags
            .iter()
            .enumerate()
            .filter(|(_, f)| **f)
            .map(|(i, _)| i)
            .collect()
    }
}

/// Evaluates rules and builds hits with verbatim evidence.
#[derive(Debug)]
pub struct DetectionEngine {
    rules: RuleSet,
    prefilter: Prefilter,
    max_evidence: usize,
    max_evidence_chars: usize,
}

impl DetectionEngine {
    /// Creates an engine; fails if the rule set is invalid.
    pub fn new(rules: RuleSet, limits: &Limits) -> Result<Self, EngineError> {
        rules.validate().map_err(EngineError::InvalidConfig)?;
        Ok(Self {
            prefilter: Prefilter::new(&rules.log_rules)?,
            rules,
            max_evidence: limits.max_evidence_per_finding,
            max_evidence_chars: limits.max_evidence_chars,
        })
    }

    /// Creates an engine with the built-in rules.
    pub fn builtin(limits: &Limits) -> Result<Self, EngineError> {
        Self::new(RuleSet::builtin(), limits)
    }

    /// The rule set.
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Metadata of the end-of-input `STARTUP-INCOMPLETE` rule.
    pub fn startup_incomplete_meta(&self) -> &Arc<RuleMeta> {
        &self.rules.startup_incomplete
    }

    /// Detects findings in one log event, appending hits to `out`.
    pub fn detect_event(&self, event: &LogEvent, out: &mut Vec<Hit>) {
        if event.is_user_content() {
            return;
        }
        let start = out.len();
        let view = EventView::new(event);
        let text_matches: Vec<(&dyn LogRule, LogMatch)> = self
            .prefilter
            .candidates(&view, self.rules.log_rules.len())
            .into_iter()
            .map(|i| self.rules.log_rules[i].as_ref())
            .filter_map(|r| r.evaluate(&view).map(|m| (r, m)))
            .collect();

        let first_lower = if event.exceptions.is_empty() {
            String::new()
        } else {
            event.first_line().text.to_ascii_lowercase()
        };
        let exception_matches: Vec<ExceptionMatch<'_>> = event
            .exceptions
            .iter()
            .filter_map(|chain| self.match_chain(event, chain, &first_lower))
            .collect();

        let fired: Vec<&str> = text_matches
            .iter()
            .map(|(r, _)| r.meta().id.as_str())
            .chain(exception_matches.iter().map(|m| m.meta.id.as_str()))
            .collect();

        let tag_plugin = event
            .header
            .as_ref()
            .and_then(|h| h.tag.as_deref())
            .filter(|t| attribution::is_plugin_tag(t));
        let event_plugin = text_matches
            .iter()
            .find_map(|(_, m)| m.extraction.plugin.as_deref())
            .or(tag_plugin)
            .map(str::to_owned);

        let mut emitted: Vec<String> = Vec::new();
        for (rule, m) in text_matches {
            let meta = rule.meta();
            if rule.superseded_by().iter().any(|id| fired.contains(id))
                || emitted.contains(&meta.id)
            {
                continue;
            }
            emitted.push(meta.id.clone());
            out.push(self.text_hit(event, meta, m, tag_plugin));
        }
        for m in exception_matches {
            if emitted.contains(&m.meta.id) {
                continue;
            }
            emitted.push(m.meta.id.clone());
            out.push(self.exception_hit(event, m, event_plugin.as_deref()));
        }
        merge_event_hits(out, start, self.max_evidence);
    }

    /// Detects findings in a crash report. `lines` are the report's source lines.
    ///
    /// The main exception is run through the exception rules. If it only matches the
    /// generic fallback and a crash rule describes the crash, the fallback is omitted as
    /// redundant.
    pub fn detect_crash(&self, report: &CrashReport, lines: &[SourceLine], out: &mut Vec<Hit>) {
        let mut exception_hits = Vec::new();
        if let (Some(chain), false) = (&report.exception, report.exception_lines.is_empty()) {
            let event = LogEvent {
                header: None,
                lines: report.exception_lines.clone(),
                omitted_lines: 0,
                last_line: report.exception_lines.last().map_or(0, |l| l.number),
                exceptions: vec![chain.clone()],
            };
            self.detect_event(&event, &mut exception_hits);
        }

        let matches: Vec<(&dyn CrashRule, CrashMatch)> = self
            .rules
            .crash_rules
            .iter()
            .filter_map(|r| r.evaluate(report).map(|m| (r.as_ref(), m)))
            .collect();
        let signature = matches.iter().any(|(r, _)| r.is_signature());
        let crash_described = !matches.is_empty();
        out.extend(
            exception_hits
                .into_iter()
                .filter(|h| !(crash_described && h.rule.id == exceptions::UNCLASSIFIED_ID)),
        );
        let anchor = report
            .description
            .as_ref()
            .map_or(report.header_line, |d| d.line);
        for (rule, m) in matches {
            if signature && rule.meta().id == crash::GENERIC_CRASH_ID {
                continue;
            }
            let meta = Arc::clone(rule.meta());
            let group = m.extraction.group.clone().unwrap_or_default();
            let mut hit = Hit::new(
                meta,
                group,
                Occurrence {
                    line: anchor,
                    timestamp: None,
                },
            );
            let mut evidence: Vec<Evidence> = m
                .lines
                .iter()
                .filter_map(|&(n, role)| {
                    let idx = lines.binary_search_by_key(&n, |l| l.number).ok()?;
                    Some(self.evidence(&lines[idx], role, None))
                })
                .collect();
            self.finish_evidence(&mut evidence);
            hit.evidence = evidence;
            apply_extraction(&mut hit, m.extraction);
            standard_vars(
                &mut hit,
                report.exception.as_ref(),
                report.exception.as_ref().and_then(|c| c.root_cause()),
            );
            out.push(hit);
        }
    }

    /// Selects the best exception rule for a chain (closest to the root cause, then
    /// highest priority), or the fallback.
    fn match_chain<'a>(
        &'a self,
        event: &LogEvent,
        chain: &'a ExceptionChain,
        first_line_lower: &str,
    ) -> Option<ExceptionMatch<'a>> {
        let mut best: Option<(usize, u8, &ExceptionRule, &ThrownException)> = None;
        for (depth, exc) in chain.causal().enumerate() {
            for rule in &self.rules.exception_rules {
                if !rule.matches(exc) || !rule.context_matches(first_line_lower) {
                    continue;
                }
                let key = (depth, rule.priority_value());
                if best.is_none_or(|(d, p, _, _)| key > (d, p)) {
                    best = Some((depth, rule.priority_value(), rule, exc));
                }
            }
        }
        if let Some((_, _, rule, exc)) = best {
            return Some(ExceptionMatch {
                meta: rule.meta(),
                chain,
                matched: exc,
                extraction: rule.extract_from(chain, exc),
                severity: adjust_for_level(rule.meta().severity, event.level()),
                fallback: false,
            });
        }

        let level = event.level();
        let qualifies =
            chain.has_frames() || event.header.is_none() || level >= Some(LogLevel::Warn);
        let root = chain.root_cause()?;
        qualifies.then(|| {
            let top = chain.top().unwrap_or(root);
            let headline = if top.class == root.class {
                root.simple_name().to_owned()
            } else {
                format!("{} (wrapped in {})", root.simple_name(), top.simple_name())
            };
            let severity = match level {
                None | Some(LogLevel::Error | LogLevel::Fatal) => Severity::Error,
                Some(_) => Severity::Warning,
            };
            ExceptionMatch {
                meta: &self.rules.fallback,
                chain,
                matched: root,
                extraction: Extraction {
                    headline: Some(headline),
                    ..Extraction::default()
                },
                severity,
                fallback: true,
            }
        })
    }

    fn text_hit(
        &self,
        event: &LogEvent,
        meta: &Arc<RuleMeta>,
        m: LogMatch,
        tag_plugin: Option<&str>,
    ) -> Hit {
        let group = m.extraction.group.clone().unwrap_or_default();
        let mut hit = Hit::new(Arc::clone(meta), group, occurrence(event));
        let mut evidence = Vec::new();
        self.push_line(&mut evidence, event, m.line, EvidenceRole::Match);
        self.push_line(
            &mut evidence,
            event,
            event.start_line(),
            EvidenceRole::LogEntry,
        );
        if let Some(chain) = event.exceptions.first() {
            if let Some(top) = chain.top() {
                self.push_line(&mut evidence, event, top.line, EvidenceRole::Exception);
            }
            if let Some(root) = chain.root_cause() {
                self.push_line(&mut evidence, event, root.line, EvidenceRole::RootCause);
            }
        }
        self.finish_evidence(&mut evidence);
        hit.evidence = evidence;
        hit.subject = base_subject(event);
        if meta.attribute_logger_tag {
            hit.subject.plugin = tag_plugin.map(str::to_owned);
        }
        apply_extraction(&mut hit, m.extraction);
        let chain = event.exceptions.first();
        standard_vars(&mut hit, chain, chain.and_then(ExceptionChain::root_cause));
        hit
    }

    fn exception_hit(
        &self,
        event: &LogEvent,
        m: ExceptionMatch<'_>,
        event_plugin: Option<&str>,
    ) -> Hit {
        let group = match &m.extraction.group {
            Some(g) => g.clone(),
            None => stack_signature(m.chain, m.matched),
        };
        let mut hit = Hit::new(Arc::clone(m.meta), group, occurrence(event));
        hit.severity = m.severity;

        let mut evidence = Vec::new();
        self.push_line(&mut evidence, event, m.matched.line, EvidenceRole::Match);
        self.push_line(
            &mut evidence,
            event,
            event.start_line(),
            EvidenceRole::LogEntry,
        );
        if let Some(top) = m.chain.top() {
            self.push_line(&mut evidence, event, top.line, EvidenceRole::Exception);
        }
        if let Some(root) = m.chain.root_cause() {
            self.push_line(&mut evidence, event, root.line, EvidenceRole::RootCause);
        }
        let frame = m.matched.frames.first().or_else(|| m.chain.frames().next());
        if let Some(f) = frame {
            self.push_line(&mut evidence, event, f.line, EvidenceRole::StackFrame);
        }
        self.finish_evidence(&mut evidence);
        hit.evidence = evidence;

        hit.subject = base_subject(event);
        hit.subject.plugin = event_plugin.map(str::to_owned);
        hit.subject.exception_class = Some(m.matched.class.clone());
        for implication in attribution::implicated_from_frames(m.chain, MAX_FRAME_IMPLICATIONS) {
            let explicit = hit
                .subject
                .plugin
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(&implication.name));
            if !explicit {
                hit.implicated.push(implication);
            }
        }
        if m.fallback {
            if let Some(msg) = m.matched.message.as_deref() {
                hit.subject.detail = Some(excerpt(msg, 200).into_owned());
            }
        }
        apply_extraction(&mut hit, m.extraction);
        standard_vars(&mut hit, Some(m.chain), Some(m.matched));
        hit
    }

    fn evidence(
        &self,
        line: &SourceLine,
        role: EvidenceRole,
        timestamp: Option<anycasted_core::models::Timestamp>,
    ) -> Evidence {
        Evidence {
            line: line.number,
            text: excerpt(&line.text, self.max_evidence_chars).into_owned(),
            role,
            timestamp,
        }
    }

    /// Adds the event line `number` as evidence unless it is already present.
    fn push_line(
        &self,
        evidence: &mut Vec<Evidence>,
        event: &LogEvent,
        number: u64,
        role: EvidenceRole,
    ) {
        if evidence.iter().any(|e| e.line == number) {
            return;
        }
        if let Some(line) = event.line(number) {
            evidence.push(self.evidence(line, role, event.timestamp()));
        }
    }

    fn finish_evidence(&self, evidence: &mut Vec<Evidence>) {
        evidence.sort_by_key(|e| e.line);
        evidence.dedup_by_key(|e| e.line);
        evidence.truncate(self.max_evidence);
    }
}

struct ExceptionMatch<'a> {
    meta: &'a Arc<RuleMeta>,
    chain: &'a ExceptionChain,
    matched: &'a ThrownException,
    extraction: Extraction,
    severity: Severity,
    fallback: bool,
}

fn occurrence(event: &LogEvent) -> Occurrence {
    Occurrence {
        line: event.start_line(),
        timestamp: event.timestamp(),
    }
}

fn base_subject(event: &LogEvent) -> Subject {
    let header = event.header.as_ref();
    Subject {
        logger: header.and_then(|h| h.logger.clone()),
        thread: header.and_then(|h| h.thread.clone()),
        ..Subject::default()
    }
}

/// Exceptions logged below ERROR level are reported one severity lower (but never
/// below the rule's intent for critical conditions).
fn adjust_for_level(severity: Severity, level: Option<LogLevel>) -> Severity {
    match (severity, level) {
        (Severity::Error, Some(l)) if l <= LogLevel::Warn => Severity::Warning,
        (s, _) => s,
    }
}

fn apply_extraction(hit: &mut Hit, extraction: Extraction) {
    for (name, value) in extraction.vars {
        if !value.trim().is_empty() {
            hit.vars.insert(name.to_owned(), value);
        }
    }
    if extraction.plugin.is_some() {
        hit.subject.plugin = extraction.plugin;
    }
    if extraction.detail.is_some() {
        hit.subject.detail = extraction.detail;
    }
    hit.headline = extraction.headline.or(hit.headline.take());
    hit.notes.extend(extraction.notes);
    for implication in extraction.implicated {
        if !hit
            .implicated
            .iter()
            .any(|i: &Implication| i.name.eq_ignore_ascii_case(&implication.name))
        {
            hit.implicated.push(implication);
        }
    }
}

/// Fills variables every template may use: `plugin`, `detail`, `exception`,
/// `exception_message`, `error_hint`, `null_ref`. Rule-extracted variables win.
fn standard_vars(hit: &mut Hit, chain: Option<&ExceptionChain>, exc: Option<&ThrownException>) {
    if let Some(p) = hit.subject.plugin.clone() {
        hit.set_var_default("plugin", p);
    }
    if let Some(d) = hit.subject.detail.clone() {
        hit.set_var_default("detail", d);
    }
    if let Some(h) = hit.headline.clone() {
        hit.set_var_default("headline", h);
    }
    let suspect = hit
        .implicated
        .iter()
        .find(|i| i.basis == anycasted_core::models::ImplicationBasis::StackFrame)
        .map(|i| i.name.clone());
    if let Some(s) = suspect {
        hit.set_var_default("suspect", s);
    }
    let Some(exc) = exc.or_else(|| chain.and_then(ExceptionChain::root_cause)) else {
        return;
    };
    let simple = exc
        .simple_name()
        .rsplit('$')
        .next()
        .unwrap_or(exc.simple_name())
        .to_owned();
    hit.set_var_default("exception", simple);
    if let Some(msg) = exc.message.as_deref() {
        let msg = excerpt(msg.trim().trim_end_matches('.'), 160).into_owned();
        hit.set_var_default("exception_message", msg);
    }
    if let Some(r) = hints::null_reference(exc) {
        hit.set_var_default("null_ref", r);
    }
    hit.set_var_default("error_hint", hints::error_hint(exc));
}

/// Merges hits from one log entry (see [`RuleRole`]).
fn merge_event_hits(out: &mut Vec<Hit>, start: usize, max_evidence: usize) {
    if out.len() - start < 2 {
        return;
    }
    let hits = out.split_off(start);
    let (contexts, rest): (Vec<Hit>, Vec<Hit>) = hits
        .into_iter()
        .partition(|h| h.rule.role == RuleRole::Context);
    if contexts.is_empty() {
        out.extend(rest);
        return;
    }
    let (generics, specifics): (Vec<Hit>, Vec<Hit>) = rest
        .into_iter()
        .partition(|h| h.rule.role == RuleRole::GenericCause);
    if specifics.is_empty() {
        for mut context in contexts {
            for generic in &generics {
                absorb(&mut context, generic, None, max_evidence);
            }
            out.push(context);
        }
        return;
    }
    for mut specific in specifics {
        for context in &contexts {
            absorb(
                &mut specific,
                context,
                context.rule.context_note.as_deref(),
                max_evidence,
            );
        }
        out.push(specific);
    }
}

/// Folds `other` into `into`: variables, evidence, subject gaps, severity, notes.
fn absorb(into: &mut Hit, other: &Hit, note: Option<&str>, max_evidence: usize) {
    for (k, v) in &other.vars {
        into.vars.entry(k.clone()).or_insert_with(|| v.clone());
    }
    for e in &other.evidence {
        if !into.evidence.iter().any(|x| x.line == e.line) {
            into.evidence.push(e.clone());
        }
    }
    into.evidence.sort_by_key(|e| e.line);
    into.evidence.truncate(max_evidence);
    if into.subject.plugin.is_none() {
        into.subject.plugin.clone_from(&other.subject.plugin);
    }
    if into.subject.exception_class.is_none() {
        into.subject
            .exception_class
            .clone_from(&other.subject.exception_class);
    }
    into.severity = into.severity.max(other.severity);
    for i in &other.implicated {
        if !into
            .implicated
            .iter()
            .any(|x| x.name.eq_ignore_ascii_case(&i.name))
        {
            into.implicated.push(i.clone());
        }
    }
    into.notes.extend(other.notes.iter().cloned());
    into.context_notes
        .extend(other.context_notes.iter().cloned());
    if let Some(n) = note {
        into.context_notes.push(n.to_owned());
    }
}

/// Stable signature of a stack trace: the chain's class sequence plus the top frames of
/// the matched throwable (or of the first throwable with frames). Line numbers are
/// excluded so that the same failure groups across plugin builds; digits in class and
/// method names (lambdas, generated accessors) are normalized. Without frames, the
/// normalized message is used.
pub fn stack_signature(chain: &ExceptionChain, matched: &ThrownException) -> String {
    let mut fp = Fingerprinter::new();
    for exc in chain.causal() {
        fp.write(&exc.class);
    }
    let frames = if matched.frames.is_empty() {
        chain
            .exceptions
            .iter()
            .find(|e| !e.frames.is_empty())
            .map_or(&[][..], |e| &e.frames[..])
    } else {
        &matched.frames[..]
    };
    if frames.is_empty() {
        fp.write(&normalize_message(
            matched.message.as_deref().unwrap_or(""),
            160,
        ));
    }
    for frame in frames.iter().take(SIGNATURE_FRAMES) {
        fp.write(&normalize_message(&frame.qualified_method(), 200));
    }
    fp.finish_hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_are_valid() {
        let set = RuleSet::builtin();
        set.validate().unwrap();
        assert!(set.catalog().len() > 40);
    }

    #[test]
    fn duplicate_ids_with_different_metadata_are_rejected() {
        use anycasted_core::models::Category;
        let a = RuleMeta::new("X-RULE", Category::Plugin, Severity::Info)
            .title("a")
            .description("d")
            .user_title("t")
            .explain("e")
            .fix(&["r"])
            .shared();
        let b = RuleMeta::new("X-RULE", Category::Plugin, Severity::Error)
            .title("b")
            .description("d")
            .user_title("t")
            .explain("e")
            .fix(&["r"])
            .shared();
        let set = RuleSet::empty()
            .with_log_rule(TextRule::new(a, &["x"]).boxed())
            .with_log_rule(TextRule::new(b, &["y"]).boxed());
        assert!(set.validate().is_err());
    }
}
