//! Severity aggregation, ordering, id assignment and finding assembly.

use std::collections::{BTreeMap, BTreeSet};

use anycasted_core::models::{
    ConfidenceLabel, Correlation, Finding, HealthStatus, ImplicationBasis, Severity, Summary,
    TemplateVars,
};
use anycasted_core::text::render_template;

use crate::correlation::CorrelationDraft;
use crate::patterns::{Aggregation, Group, repetition};

/// Ordering key: most severe first, then observed before hypotheses, then most frequent,
/// then earliest.
fn rank(
    g: &Group,
) -> (
    std::cmp::Reverse<Severity>,
    anycasted_core::models::Classification,
    std::cmp::Reverse<u64>,
    u64,
) {
    (
        std::cmp::Reverse(g.severity),
        g.classification,
        std::cmp::Reverse(g.occurrences),
        g.first.line,
    )
}

/// Builds the report summary from findings.
pub fn summarize(findings: &[Finding], dropped_hits: u64) -> Summary {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    let highest = findings.iter().map(|f| f.severity).max();
    let status = match highest {
        Some(Severity::Critical) => HealthStatus::Critical,
        Some(Severity::Error) => HealthStatus::Failing,
        Some(Severity::Warning) => HealthStatus::Degraded,
        Some(Severity::Info) | None => HealthStatus::Healthy,
    };
    Summary {
        status,
        highest_severity: highest,
        total_findings: findings.len(),
        critical: count(Severity::Critical),
        error: count(Severity::Error),
        warning: count(Severity::Warning),
        info: count(Severity::Info),
        dropped_hits,
    }
}

/// Converts groups and correlation drafts into ordered findings with ids, and
/// correlations referencing those ids.
///
/// `plugin_loaded` answers whether a plugin name was seen loading in the input; pass
/// `None` when the input has no plugin inventory. `globals` are template variables
/// known for the whole input (e.g. `port`, `minecraft_version`); a group's own
/// variables take precedence.
pub fn assemble(
    aggregation: Aggregation,
    drafts: Vec<CorrelationDraft>,
    plugin_loaded: Option<&dyn Fn(&str) -> bool>,
    globals: &TemplateVars,
) -> (Vec<Finding>, Vec<Correlation>) {
    let Aggregation {
        mut groups,
        pattern_links,
        ..
    } = aggregation;
    // A problem that resolved itself is reported one level lower.
    for g in &mut groups {
        if g.recovered.is_some() {
            g.severity = g.severity.downgrade();
        }
    }

    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by_key(|&i| rank(&groups[i]));

    let mut ids = vec![String::new(); groups.len()];
    let mut per_category: BTreeMap<&str, u32> = BTreeMap::new();
    for &i in &order {
        let cat = groups[i].rule.category.as_str();
        let n = per_category.entry(cat).or_default();
        *n += 1;
        ids[i] = format!("{cat}-{n:03}");
    }

    let mut related: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); groups.len()];
    let mut correlations = Vec::with_capacity(drafts.len());
    for (n, draft) in drafts.into_iter().enumerate() {
        for &a in &draft.groups {
            related[a].extend(draft.groups.iter().copied().filter(|&b| b != a));
        }
        let mut members = draft.groups.clone();
        members.sort_by_key(|&i| rank(&groups[i]));
        correlations.push(Correlation {
            id: format!("correlation-{:03}", n + 1),
            kind: draft.kind,
            findings: members.iter().map(|&i| ids[i].clone()).collect(),
            description: draft.description,
            evidence: draft.evidence,
        });
    }
    for (pattern, source) in pattern_links {
        related[pattern].insert(source);
        related[source].insert(pattern);
    }

    let mut groups: Vec<Option<Group>> = groups.into_iter().map(Some).collect();
    let findings = order
        .iter()
        .filter_map(|&i| {
            let group = groups[i].take()?;
            let mut rel: Vec<usize> = related[i].iter().copied().collect();
            rel.sort_by_key(|&j| ids[j].clone());
            Some(to_finding(
                group,
                ids[i].clone(),
                rel.iter().map(|&j| ids[j].clone()).collect(),
                plugin_loaded,
                globals,
            ))
        })
        .collect();
    (findings, correlations)
}

fn to_finding(
    group: Group,
    id: String,
    related: Vec<String>,
    plugin_loaded: Option<&dyn Fn(&str) -> bool>,
    globals: &TemplateVars,
) -> Finding {
    let technical_title = match &group.headline {
        Some(h) => format!("{}: {h}", group.rule.title),
        None => group.rule.title.clone(),
    };
    let mut evidence = group.evidence;
    evidence.extend(
        group
            .last_evidence
            .filter(|e| !evidence.iter().any(|x| x.line == e.line)),
    );

    let mut notes = group.notes;
    let mut implicated = group.implicated;
    let mut confirmations = Vec::new();
    if let Some(loaded) = plugin_loaded {
        for i in &mut implicated {
            let seen = loaded(&i.name);
            i.seen_loading = Some(seen);
            if !seen && i.basis == ImplicationBasis::LogMessage {
                notes.push(format!(
                    "{} was not seen loading anywhere in this log.",
                    i.name
                ));
                confirmations.push(format!(
                    "{} doesn't appear among the plugins loaded in this log, which confirms it isn't installed.",
                    i.name
                ));
            }
        }
    }

    let mut vars = group.vars;
    for (k, v) in globals {
        vars.entry(k.clone()).or_insert_with(|| v.clone());
    }
    let title = render_template(&group.rule.user_title, &vars);
    let mut explanation = render_template(&group.rule.explanation, &vars);
    for note in group.context_notes.iter().filter(|n| !n.is_empty()) {
        push_sentence(&mut explanation, &render_template(note, &vars));
    }
    for c in &confirmations {
        push_sentence(&mut explanation, c);
    }
    let mut recommendations: Vec<String> = group
        .rule
        .recommendations
        .iter()
        .map(|t| render_template(t, &vars))
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(r) = &group.recovered {
        push_sentence(
            &mut explanation,
            &format!(
                "It recovered on its own afterwards (line {}), so it may already be fine.",
                r.line
            ),
        );
        recommendations.insert(
            0,
            "It recovered by itself. If it doesn't come back, no action is needed; if it keeps happening, follow the steps below.".into(),
        );
    }

    Finding {
        id,
        rule_id: group.rule.id.clone(),
        category: group.rule.category,
        severity: group.severity,
        classification: group.classification,
        title,
        explanation,
        recommendations,
        technical_title,
        description: group.rule.description.clone(),
        confidence: (group.confidence * 100.0).round() / 100.0,
        confidence_label: ConfidenceLabel::from_confidence(group.confidence),
        occurrences: group.occurrences,
        first_seen: group.first,
        last_seen: group.last,
        repetition: repetition(group.occurrences, &group.first, &group.last),
        recovered: group.recovered,
        evidence,
        other_occurrence_lines: group.sample_lines,
        subject: group.subject,
        implicated,
        fingerprint: group.fingerprint,
        notes,
        related,
    }
}

fn push_sentence(text: &mut String, sentence: &str) {
    if sentence.is_empty() || text.contains(sentence) {
        return;
    }
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(sentence);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summary_is_healthy() {
        let s = summarize(&[], 0);
        assert_eq!(s.status, HealthStatus::Healthy);
        assert_eq!(s.highest_severity, None);
        assert_eq!(s.total_findings, 0);
    }
}
