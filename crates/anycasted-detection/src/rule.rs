//! Rule abstractions.
//!
//! Three kinds of rules exist:
//!
//! * [`ExceptionRule`] — matches a throwable in an exception chain by class (and
//!   optionally message). For each chain, only the best exception rule fires: the one
//!   matching the throwable closest to the root cause, ties broken by priority. A
//!   chain without a matching rule produces a generic `JAVA-UNCLASSIFIED-EXCEPTION`.
//! * [`LogRule`] — inspects the textual lines of an event (log messages; never stack
//!   frames, exception headers or player chat). [`TextRule`] is the declarative
//!   implementation used by most built-in rules; custom logic can implement the trait.
//! * [`CrashRule`] — inspects a parsed crash report.
//!
//! Rules only *find* conditions and extract details; the engine turns matches into
//! [`Hit`](anycasted_core::models::Hit)s with uniformly built, verbatim evidence.

use std::cell::OnceCell;
use std::sync::Arc;

use anycasted_core::models::{
    CrashReport, EvidenceRole, ExceptionChain, Implication, LogEvent, LogLevel, RuleMeta,
    ThrownException,
};

/// Details extracted by a rule from the matched text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extraction {
    /// Plugin explicitly named by the matched text.
    pub plugin: Option<String>,
    /// Title suffix.
    pub headline: Option<String>,
    /// Rule-specific detail (port, file, missing class, ...).
    pub detail: Option<String>,
    /// Grouping key override.
    pub group: Option<String>,
    /// Notes to attach.
    pub notes: Vec<String>,
    /// Implicated components.
    pub implicated: Vec<Implication>,
    /// Template variables for the user-facing texts.
    pub vars: Vec<(&'static str, String)>,
}

impl Extraction {
    /// Adds a template variable (builder style).
    pub fn var(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.vars.push((name, value.into()));
        self
    }
}

/// A textual line of an event, as seen by [`LogRule`]s.
#[derive(Debug)]
pub struct TextLine<'a> {
    /// Source line number.
    pub number: u64,
    /// Text: the message for the event's first line, the full line otherwise.
    pub text: &'a str,
    lower: OnceCell<String>,
}

impl TextLine<'_> {
    /// ASCII-lowercased text (computed on first use).
    pub fn lower(&self) -> &str {
        self.lower.get_or_init(|| self.text.to_ascii_lowercase())
    }
}

/// Maximum textual lines of one event inspected by text rules.
const MAX_TEXT_LINES: usize = 64;

/// Read-only view of an event prepared for rule evaluation.
#[derive(Debug)]
pub struct EventView<'a> {
    /// The event.
    pub event: &'a LogEvent,
    lines: Vec<TextLine<'a>>,
}

impl<'a> EventView<'a> {
    /// Prepares the textual lines of `event`. Player content yields no lines.
    pub fn new(event: &'a LogEvent) -> Self {
        let mut lines = Vec::new();
        if !event.is_user_content() {
            let exception_lines: Vec<u64> = event
                .exceptions
                .iter()
                .flat_map(|c| c.exceptions.iter().map(|e| e.line))
                .collect();
            let first = std::iter::once((event.start_line(), event.message()));
            let rest = event
                .continuation()
                .iter()
                .map(|l| (l.number, l.text.as_str()));
            for (number, text) in first.chain(rest) {
                if lines.len() >= MAX_TEXT_LINES {
                    break;
                }
                let t = text.trim_start();
                if t.is_empty()
                    || exception_lines.contains(&number)
                    || (t.starts_with("at ") && t.contains('('))
                    || t.starts_with("... ")
                {
                    continue;
                }
                lines.push(TextLine {
                    number,
                    text,
                    lower: OnceCell::new(),
                });
            }
        }
        Self { event, lines }
    }

    /// Textual lines (see [`TextLine`]).
    pub fn text_lines(&self) -> &[TextLine<'a>] {
        &self.lines
    }

    /// Event level, if known.
    pub fn level(&self) -> Option<LogLevel> {
        self.event.level()
    }
}

/// A [`LogRule`] match.
#[derive(Debug, Clone, PartialEq)]
pub struct LogMatch {
    /// Line on which the condition was found.
    pub line: u64,
    /// Extracted details.
    pub extraction: Extraction,
}

/// A rule over log event text.
pub trait LogRule: Send + Sync {
    /// Rule metadata.
    fn meta(&self) -> &Arc<RuleMeta>;
    /// Evaluates the rule against one event.
    fn evaluate(&self, view: &EventView<'_>) -> Option<LogMatch>;
    /// Rule ids that, when they fire on the same event, make this rule's hit redundant.
    fn superseded_by(&self) -> &[&'static str] {
        &[]
    }
    /// Lower-case substrings of which at least one must occur in a textual line for the
    /// rule to possibly match. The engine uses them to skip rules cheaply with a single
    /// multi-pattern scan per line. `None` means the rule is evaluated on every event.
    fn prefilter(&self) -> Option<&[String]> {
        None
    }
}

/// Extractor callback for [`TextRule`]: receives the matched line's original text.
pub type TextExtractor = fn(&str) -> Option<Extraction>;

/// Enrichment callback: adds details found elsewhere in the event (e.g. the line and
/// column printed below a YAML error).
pub type EventEnricher = fn(&LogEvent, &mut Extraction);

/// Declarative text rule: case-insensitive substring matching on one line.
pub struct TextRule {
    meta: Arc<RuleMeta>,
    any: Vec<String>,
    all: Vec<String>,
    none: Vec<String>,
    first_line_only: bool,
    min_level: Option<LogLevel>,
    extractor: Option<TextExtractor>,
    require_extraction: bool,
    superseded_by: &'static [&'static str],
    enricher: Option<EventEnricher>,
}

impl TextRule {
    /// Creates a rule that fires when a line contains any of `needles`
    /// (case-insensitive).
    pub fn new(meta: Arc<RuleMeta>, needles: &[&str]) -> Self {
        Self {
            meta,
            any: lower_all(needles),
            all: Vec::new(),
            none: Vec::new(),
            first_line_only: false,
            min_level: None,
            extractor: None,
            require_extraction: false,
            superseded_by: &[],
            enricher: None,
        }
    }

    /// Adds event-level enrichment of the extraction.
    pub fn enrich(mut self, enricher: EventEnricher) -> Self {
        self.enricher = Some(enricher);
        self
    }

    /// The line must additionally contain all of these.
    pub fn and_all(mut self, needles: &[&str]) -> Self {
        self.all = lower_all(needles);
        self
    }

    /// The line must contain none of these.
    pub fn excluding(mut self, needles: &[&str]) -> Self {
        self.none = lower_all(needles);
        self
    }

    /// Only match the event's first (header) line.
    pub fn first_line_only(mut self) -> Self {
        self.first_line_only = true;
        self
    }

    /// Skip events whose known level is below `level`.
    pub fn min_level(mut self, level: LogLevel) -> Self {
        self.min_level = Some(level);
        self
    }

    /// Extracts details from the matched line.
    pub fn extract(mut self, extractor: TextExtractor) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Like [`Self::extract`], but the rule only fires if extraction succeeds.
    pub fn extract_required(mut self, extractor: TextExtractor) -> Self {
        self.extractor = Some(extractor);
        self.require_extraction = true;
        self
    }

    /// Suppress this rule when any of the given rules fire on the same event.
    pub fn superseded_by(mut self, ids: &'static [&'static str]) -> Self {
        self.superseded_by = ids;
        self
    }

    fn line_matches(&self, lower: &str) -> bool {
        self.any.iter().any(|n| lower.contains(n.as_str()))
            && self.all.iter().all(|n| lower.contains(n.as_str()))
            && !self.none.iter().any(|n| lower.contains(n.as_str()))
    }

    /// Boxes the rule.
    pub fn boxed(self) -> Box<dyn LogRule> {
        Box::new(self)
    }
}

impl LogRule for TextRule {
    fn meta(&self) -> &Arc<RuleMeta> {
        &self.meta
    }

    fn evaluate(&self, view: &EventView<'_>) -> Option<LogMatch> {
        if let (Some(min), Some(level)) = (self.min_level, view.level()) {
            if level < min {
                return None;
            }
        }
        let lines = view.text_lines();
        let candidates = if self.first_line_only {
            lines
                .iter()
                .take_while(|l| l.number == view.event.start_line())
                .collect::<Vec<_>>()
        } else {
            lines.iter().collect()
        };
        candidates.into_iter().find_map(|line| {
            if !self.line_matches(line.lower()) {
                return None;
            }
            let mut extraction = match self.extractor {
                Some(f) => match f(line.text) {
                    Some(e) => e,
                    None if self.require_extraction => return None,
                    None => Extraction::default(),
                },
                None => Extraction::default(),
            };
            if let Some(enrich) = self.enricher {
                enrich(view.event, &mut extraction);
            }
            Some(LogMatch {
                line: line.number,
                extraction,
            })
        })
    }

    fn superseded_by(&self) -> &[&'static str] {
        self.superseded_by
    }

    fn prefilter(&self) -> Option<&[String]> {
        Some(&self.any)
    }
}

/// Extractor callback for [`ExceptionRule`]: receives the whole chain and the matched
/// throwable.
pub type ExceptionExtractor = fn(&ExceptionChain, &ThrownException) -> Option<Extraction>;

/// Matches throwables by class and message.
pub struct ExceptionRule {
    meta: Arc<RuleMeta>,
    classes: Vec<String>,
    context_any: Vec<String>,
    message_any: Vec<String>,
    message_none: Vec<String>,
    priority: u8,
    extractor: Option<ExceptionExtractor>,
}

impl ExceptionRule {
    /// Creates a rule matching any of `classes` (fully qualified or simple names).
    pub fn new(meta: Arc<RuleMeta>, classes: &[&str]) -> Self {
        Self {
            meta,
            classes: classes.iter().map(|c| (*c).to_owned()).collect(),
            context_any: Vec::new(),
            message_any: Vec::new(),
            message_none: Vec::new(),
            priority: 10,
            extractor: None,
        }
    }

    /// Creates a rule matching throwables of any class (use with
    /// [`Self::message_any`]).
    pub fn any_class(meta: Arc<RuleMeta>) -> Self {
        Self::new(meta, &["*"])
    }

    /// The log entry's first line must contain one of these (case-insensitive), e.g.
    /// `chunk` for a decompression error that only means corruption in that context.
    pub fn context_any(mut self, needles: &[&str]) -> Self {
        self.context_any = lower_all(needles);
        self
    }

    /// Whether the log entry satisfies the context requirement.
    pub fn context_matches(&self, first_line_lower: &str) -> bool {
        self.context_any.is_empty()
            || self
                .context_any
                .iter()
                .any(|n| first_line_lower.contains(n.as_str()))
    }

    /// The message must contain one of these (case-insensitive).
    pub fn message_any(mut self, needles: &[&str]) -> Self {
        self.message_any = lower_all(needles);
        self
    }

    /// The message must contain none of these (case-insensitive).
    pub fn message_none(mut self, needles: &[&str]) -> Self {
        self.message_none = lower_all(needles);
        self
    }

    /// Priority among rules matching the same throwable (higher wins). Rules with a
    /// message constraint should use a higher priority than class-only rules.
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Extracts details from the matched throwable.
    pub fn extract(mut self, extractor: ExceptionExtractor) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Rule metadata.
    pub fn meta(&self) -> &Arc<RuleMeta> {
        &self.meta
    }

    /// Priority.
    pub fn priority_value(&self) -> u8 {
        self.priority
    }

    /// Whether the rule matches `exc`.
    pub fn matches(&self, exc: &ThrownException) -> bool {
        if !self.classes.iter().any(|c| c == "*" || exc.is(c)) {
            return false;
        }
        if self.message_any.is_empty() && self.message_none.is_empty() {
            return true;
        }
        let msg = exc.message_lower();
        (self.message_any.is_empty() || self.message_any.iter().any(|n| msg.contains(n.as_str())))
            && !self.message_none.iter().any(|n| msg.contains(n.as_str()))
    }

    /// Runs the extractor.
    pub fn extract_from(&self, chain: &ExceptionChain, exc: &ThrownException) -> Extraction {
        self.extractor
            .and_then(|f| f(chain, exc))
            .unwrap_or_default()
    }
}

/// A [`CrashRule`] match.
#[derive(Debug, Clone, PartialEq)]
pub struct CrashMatch {
    /// Evidence lines with their roles (texts are resolved by the engine).
    pub lines: Vec<(u64, EvidenceRole)>,
    /// Extracted details.
    pub extraction: Extraction,
}

/// A rule over a parsed crash report.
pub trait CrashRule: Send + Sync {
    /// Rule metadata.
    fn meta(&self) -> &Arc<RuleMeta>;
    /// Evaluates the rule.
    fn evaluate(&self, report: &CrashReport) -> Option<CrashMatch>;
    /// Whether this rule identifies a specific crash signature. When any signature rule
    /// fires, the generic crash rule is not reported.
    fn is_signature(&self) -> bool {
        false
    }
}

fn lower_all(needles: &[&str]) -> Vec<String> {
    needles.iter().map(|n| n.to_ascii_lowercase()).collect()
}
