//! Grouping of hits into finding groups, and repetition detection.
//!
//! Hits with the same rule id and grouping key (stack signature, plugin, ...) are
//! merged into one [`Group`] with occurrence counts, first/last occurrence and bounded
//! representative evidence. Memory use is bounded by the number of distinct groups,
//! not by the number of hits.

use std::collections::HashMap;
use std::sync::Arc;

use anycasted_core::models::{
    Category, Classification, Evidence, EvidenceRole, Hit, Implication, LogEvent, Occurrence,
    RuleMeta, Severity, Subject, TemplateVars,
};
use anycasted_core::text::Fingerprinter;
use anycasted_core::{AnalysisConfig, Limits};

/// Id of the repetition rule.
pub const REPEATED_ERROR_ID: &str = "PATTERN-REPEATED-ERROR";

const MAX_IMPLICATIONS: usize = 10;
const MAX_NOTES: usize = 10;
const MAX_VARS: usize = 48;

/// Metadata of the repetition rule.
pub fn repeated_error_meta() -> Arc<RuleMeta> {
    RuleMeta::new(REPEATED_ERROR_ID, Category::Pattern, Severity::Warning)
        .title("Repeated error")
        .user_title("This keeps happening: {source_title|the same problem} ({count|many} times)")
        .explain("The same problem was logged {count|many} times. Problems that repeat this often fill up the log, can hide other errors and cost server performance. Fixing the related problem below will stop it.")
        .fix(&["Fix the related problem: {source_title|see the related finding}.", "Use the first and last time it was seen to tell whether it's still happening."])
        .description("The same problem signature was logged many times. Persistent repetition usually means a recurring task, listener or connection keeps failing; it floods the log, can hide other problems and costs server performance.")
        .evidence("A finding whose occurrence count reaches the configured repetition threshold.")
        .shared()
}

/// A group of hits sharing rule and grouping key.
#[derive(Debug, Clone)]
pub struct Group {
    /// Rule metadata.
    pub rule: Arc<RuleMeta>,
    /// Grouping key from the rule.
    pub key: String,
    /// Stable fingerprint of rule id + key.
    pub fingerprint: String,
    /// Title suffix.
    pub headline: Option<String>,
    /// Highest severity among hits.
    pub severity: Severity,
    /// Highest confidence among hits.
    pub confidence: f32,
    /// Strongest classification among hits.
    pub classification: Classification,
    /// Number of hits.
    pub occurrences: u64,
    /// First occurrence.
    pub first: Occurrence,
    /// Last occurrence.
    pub last: Occurrence,
    /// Evidence of the first occurrence.
    pub evidence: Vec<Evidence>,
    /// Main evidence line of the last occurrence (when there are several).
    pub last_evidence: Option<Evidence>,
    /// Line numbers of further occurrences (bounded).
    pub sample_lines: Vec<u64>,
    /// Subject of the first occurrence.
    pub subject: Subject,
    /// Merged implications.
    pub implicated: Vec<Implication>,
    /// Merged notes.
    pub notes: Vec<String>,
    /// Template variables (first value seen wins).
    pub vars: TemplateVars,
    /// Context-note templates absorbed during detection.
    pub context_notes: Vec<String>,
    /// A later log line showing the problem resolved itself.
    pub recovered: Option<Evidence>,
}

impl Group {
    fn from_hit(hit: Hit, fingerprint: String) -> Self {
        Self {
            fingerprint,
            key: hit.group_key,
            headline: hit.headline,
            severity: hit.severity,
            confidence: hit.confidence,
            classification: hit.classification,
            occurrences: 1,
            first: hit.occurrence,
            last: hit.occurrence,
            evidence: hit.evidence,
            last_evidence: None,
            sample_lines: Vec::new(),
            subject: hit.subject,
            implicated: hit.implicated,
            notes: hit.notes,
            vars: hit.vars,
            context_notes: hit.context_notes,
            recovered: None,
            rule: hit.rule,
        }
    }

    fn merge(&mut self, hit: Hit, max_samples: usize) {
        self.occurrences += 1;
        // A new occurrence after a recovery means the problem came back.
        if self
            .recovered
            .as_ref()
            .is_some_and(|r| hit.occurrence.line > r.line)
        {
            self.recovered = None;
        }
        for (k, v) in hit.vars {
            if self.vars.len() < MAX_VARS {
                self.vars.entry(k).or_insert(v);
            }
        }
        for n in hit.context_notes {
            if self.context_notes.len() < MAX_NOTES && !self.context_notes.contains(&n) {
                self.context_notes.push(n);
            }
        }
        self.last = hit.occurrence;
        self.severity = self.severity.max(hit.severity);
        self.confidence = self.confidence.max(hit.confidence);
        self.classification = self.classification.min(hit.classification);
        if self.sample_lines.len() < max_samples {
            self.sample_lines.push(hit.occurrence.line);
        }
        let main = hit
            .evidence
            .iter()
            .find(|e| e.role == EvidenceRole::Match)
            .or_else(|| hit.evidence.first());
        if let Some(e) = main {
            self.last_evidence = Some(Evidence {
                role: EvidenceRole::LastOccurrence,
                ..e.clone()
            });
        }
        for implication in hit.implicated {
            if self.implicated.len() < MAX_IMPLICATIONS
                && !self
                    .implicated
                    .iter()
                    .any(|i| i.name.eq_ignore_ascii_case(&implication.name))
            {
                self.implicated.push(implication);
            }
        }
        for note in hit.notes {
            if self.notes.len() < MAX_NOTES && !self.notes.contains(&note) {
                self.notes.push(note);
            }
        }
    }
}

/// Streaming aggregator of hits.
#[derive(Debug)]
pub struct Aggregator {
    groups: Vec<Group>,
    index: HashMap<String, usize>,
    max_groups: usize,
    max_samples: usize,
    dropped_hits: u64,
}

impl Aggregator {
    /// Creates an aggregator bounded by `limits`.
    pub fn new(limits: &Limits) -> Self {
        Self {
            groups: Vec::new(),
            index: HashMap::new(),
            max_groups: limits.max_finding_groups,
            max_samples: limits.max_sample_lines,
            dropped_hits: 0,
        }
    }

    /// Adds a hit; returns its group index, or `None` if the group limit was reached.
    pub fn add(&mut self, hit: Hit) -> Option<usize> {
        // Same rule and key but different plugins are different problems.
        let plugin = hit
            .subject
            .plugin
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let fingerprint = Fingerprinter::new()
            .write(&hit.rule.id)
            .write(&hit.group_key)
            .write(&plugin)
            .finish_hex();
        if let Some(&idx) = self.index.get(&fingerprint) {
            self.groups[idx].merge(hit, self.max_samples);
            return Some(idx);
        }
        if self.groups.len() >= self.max_groups {
            self.dropped_hits += 1;
            return None;
        }
        let idx = self.groups.len();
        self.index.insert(fingerprint.clone(), idx);
        self.groups.push(Group::from_hit(hit, fingerprint));
        Some(idx)
    }

    /// Checks whether `event` shows that an earlier problem resolved itself (e.g. a
    /// plugin reporting a successful database connection after failures). Only rules
    /// with recovery markers are considered, and only events from the same plugin.
    pub fn observe_recovery(&mut self, event: &LogEvent) {
        if !self
            .groups
            .iter()
            .any(|g| !g.rule.recovery_markers.is_empty())
        {
            return;
        }
        let tag = event.header.as_ref().and_then(|h| h.tag.as_deref());
        let message = event.message().to_ascii_lowercase();
        for g in &mut self.groups {
            let same_plugin = match (&g.subject.plugin, tag) {
                (Some(p), Some(t)) => p.eq_ignore_ascii_case(t),
                (None, _) => true,
                (Some(_), None) => false,
            };
            if g.last.line < event.start_line()
                && same_plugin
                && g.rule
                    .recovery_markers
                    .iter()
                    .any(|m| message.contains(m.as_str()))
            {
                let line = event.first_line();
                g.recovered = Some(Evidence {
                    line: line.number,
                    text: anycasted_core::text::excerpt(&line.text, 600).into_owned(),
                    role: EvidenceRole::Recovery,
                    timestamp: event.timestamp(),
                });
            }
        }
    }

    /// Current groups.
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// Hits dropped because of the group limit.
    pub fn dropped_hits(&self) -> u64 {
        self.dropped_hits
    }

    /// Adds `PATTERN-REPEATED-ERROR` groups for groups at or above the repetition
    /// threshold and returns the aggregated result.
    pub fn finish(mut self, config: &AnalysisConfig) -> Aggregation {
        let meta = repeated_error_meta();
        let mut links = Vec::new();
        let candidates: Vec<usize> = (0..self.groups.len())
            .filter(|&i| {
                let g = &self.groups[i];
                g.occurrences >= config.repeated_error_threshold
                    && g.severity >= Severity::Warning
                    && g.rule.category != Category::Pattern
            })
            .collect();
        for source in candidates {
            if let Some(hit) = repeated_hit(&meta, &self.groups[source]) {
                // Pattern groups are created even at the group limit: they summarize
                // existing groups rather than adding new information.
                let fingerprint = Fingerprinter::new()
                    .write(&meta.id)
                    .write(&hit.group_key)
                    .finish_hex();
                let idx = self.groups.len();
                self.groups.push(Group::from_hit(hit, fingerprint));
                links.push((idx, source));
            }
        }
        Aggregation {
            groups: self.groups,
            pattern_links: links,
            dropped_hits: self.dropped_hits,
        }
    }
}

/// Result of aggregation.
#[derive(Debug)]
pub struct Aggregation {
    /// All groups (pattern groups last).
    pub groups: Vec<Group>,
    /// `(pattern group, source group)` pairs.
    pub pattern_links: Vec<(usize, usize)>,
    /// Hits dropped because of the group limit.
    pub dropped_hits: u64,
}

fn repeated_hit(meta: &Arc<RuleMeta>, source: &Group) -> Option<Hit> {
    let first = source
        .evidence
        .iter()
        .find(|e| e.role == EvidenceRole::Match)
        .or_else(|| source.evidence.first())?
        .clone();
    let mut hit = Hit::new(Arc::clone(meta), source.fingerprint.clone(), source.first);
    hit.headline = Some(match &source.headline {
        Some(h) => format!("{} — {h} ×{}", source.rule.title, source.occurrences),
        None => format!("{} ×{}", source.rule.title, source.occurrences),
    });
    hit.evidence.push(first);
    hit.evidence.extend(source.last_evidence.clone());
    hit.subject = source.subject.clone();
    hit.vars
        .insert("count".into(), source.occurrences.to_string());
    hit.vars.insert(
        "source_title".into(),
        anycasted_core::text::render_template(&source.rule.user_title, &source.vars),
    );
    let mut note = format!(
        "{} occurrences of {} between line {} and line {}",
        source.occurrences, source.rule.id, source.first.line, source.last.line
    );
    if let Some(rep) = repetition(source.occurrences, &source.first, &source.last) {
        if let (Some(span), Some(rate)) = (rep.span_seconds, rep.per_minute) {
            note.push_str(&format!(" ({span:.0} s, {rate:.1} per minute)"));
        }
    }
    note.push('.');
    hit.notes.push(note);
    Some(hit)
}

/// Repetition statistics from first/last occurrence.
pub fn repetition(
    occurrences: u64,
    first: &Occurrence,
    last: &Occurrence,
) -> Option<anycasted_core::models::Repetition> {
    if occurrences < 2 {
        return None;
    }
    let span_ms = match (first.timestamp, last.timestamp) {
        (Some(a), Some(b)) => a.millis_until(&b).filter(|ms| *ms >= 0),
        _ => None,
    };
    let span_seconds = span_ms.map(|ms| ms as f64 / 1000.0);
    let per_minute = span_seconds
        .filter(|s| *s >= 1.0)
        .map(|s| (occurrences as f64 / (s / 60.0) * 10.0).round() / 10.0);
    Some(anycasted_core::models::Repetition {
        span_seconds,
        per_minute,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anycasted_core::models::{Category, RuleMeta};

    fn hit(meta: &Arc<RuleMeta>, key: &str, line: u64) -> Hit {
        let mut h = Hit::new(
            Arc::clone(meta),
            key.into(),
            Occurrence {
                line,
                timestamp: None,
            },
        );
        h.evidence.push(Evidence {
            line,
            text: format!("line {line}"),
            role: EvidenceRole::Match,
            timestamp: None,
        });
        h
    }

    #[test]
    fn groups_identical_hits() {
        let meta = RuleMeta::new("T-RULE", Category::Exception, Severity::Error)
            .title("T")
            .shared();
        let mut agg = Aggregator::new(&Limits::default());
        for line in 1..=400 {
            agg.add(hit(&meta, "sig", line));
        }
        agg.add(hit(&meta, "other", 500));
        let result = agg.finish(&AnalysisConfig::default());
        let g = &result.groups[0];
        assert_eq!(g.occurrences, 400);
        assert_eq!(g.first.line, 1);
        assert_eq!(g.last.line, 400);
        assert_eq!(g.evidence[0].line, 1);
        assert_eq!(g.last_evidence.as_ref().unwrap().line, 400);
        assert_eq!(g.sample_lines.len(), Limits::default().max_sample_lines);
        // One repetition finding for the 400× group only.
        assert_eq!(result.pattern_links, vec![(2, 0)]);
        assert_eq!(result.groups[2].evidence.len(), 2);
    }

    #[test]
    fn group_limit_is_enforced() {
        let meta = RuleMeta::new("T-RULE", Category::Exception, Severity::Error)
            .title("T")
            .shared();
        let limits = Limits {
            max_finding_groups: 2,
            ..Limits::default()
        };
        let mut agg = Aggregator::new(&limits);
        for i in 0..5 {
            agg.add(hit(&meta, &i.to_string(), i));
        }
        assert_eq!(agg.groups().len(), 2);
        assert_eq!(agg.dropped_hits(), 3);
    }
}
