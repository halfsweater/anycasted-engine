//! Streaming correlation of finding groups.
//!
//! Correlations describe *co-occurrence*. Only `same_event` reflects a structural link
//! (the server printed both in one log entry); all other kinds are proximity in time,
//! position or attribution, and their descriptions say so explicitly.

use std::collections::{BTreeMap, BTreeSet};

use anycasted_core::AnalysisConfig;
use anycasted_core::models::{Category, CorrelationKind, Evidence, Occurrence, Severity};

use crate::patterns::Group;

const MAX_PAIRS: usize = 256;
const MAX_CLUSTERS: usize = 50;
const MAX_CLUSTER_GROUPS: usize = 32;
const MAX_SHUTDOWN_MARKERS: usize = 16;

/// A correlation before finding ids are assigned (group indices instead of ids).
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationDraft {
    /// Kind.
    pub kind: CorrelationKind,
    /// Group indices.
    pub groups: Vec<usize>,
    /// Explanation.
    pub description: String,
    /// Supporting evidence.
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy)]
struct PairStat {
    count: u64,
    first_line: u64,
}

#[derive(Debug, Clone)]
struct Cluster {
    start: Occurrence,
    end: Occurrence,
    groups: BTreeSet<usize>,
}

#[derive(Debug, Clone)]
struct ShutdownLink {
    marker: Evidence,
    groups: Vec<usize>,
}

/// Observes hits as they are aggregated and derives correlations.
#[derive(Debug)]
pub struct Correlator {
    config: AnalysisConfig,
    current_event: Option<u64>,
    event_groups: Vec<usize>,
    pairs: BTreeMap<(usize, usize), PairStat>,
    cluster: Option<Cluster>,
    clusters: Vec<Cluster>,
    shutdowns: Vec<ShutdownLink>,
    last_marker_line: Option<u64>,
}

impl Correlator {
    /// Creates a correlator.
    pub fn new(config: &AnalysisConfig) -> Self {
        Self {
            config: config.clone(),
            current_event: None,
            event_groups: Vec::new(),
            pairs: BTreeMap::new(),
            cluster: None,
            clusters: Vec::new(),
            shutdowns: Vec::new(),
            last_marker_line: None,
        }
    }

    /// Records that a hit for `group` occurred (in event order).
    pub fn observe_hit(&mut self, group: usize, severity: Severity, occurrence: Occurrence) {
        if self.current_event != Some(occurrence.line) {
            self.flush_event();
            self.current_event = Some(occurrence.line);
        }
        if !self.event_groups.contains(&group) {
            self.event_groups.push(group);
        }
        if severity >= Severity::Error {
            self.observe_cluster(group, occurrence);
        }
    }

    fn flush_event(&mut self) {
        let line = self.current_event.unwrap_or(0);
        let groups = std::mem::take(&mut self.event_groups);
        for (i, &a) in groups.iter().enumerate() {
            for &b in &groups[i + 1..] {
                let key = (a.min(b), a.max(b));
                if let Some(stat) = self.pairs.get_mut(&key) {
                    stat.count += 1;
                } else if self.pairs.len() < MAX_PAIRS {
                    self.pairs.insert(
                        key,
                        PairStat {
                            count: 1,
                            first_line: line,
                        },
                    );
                }
            }
        }
    }

    fn observe_cluster(&mut self, group: usize, occurrence: Occurrence) {
        let Some(ts) = occurrence.timestamp else {
            return;
        };
        let window_ms = i64::from(self.config.temporal_window_secs) * 1000;
        if let Some(cluster) = self.cluster.as_mut() {
            let gap = cluster.end.timestamp.and_then(|end| end.millis_until(&ts));
            if gap.is_some_and(|g| (0..=window_ms).contains(&g)) {
                cluster.end = occurrence;
                if cluster.groups.len() < MAX_CLUSTER_GROUPS {
                    cluster.groups.insert(group);
                }
                return;
            }
        }
        self.close_cluster();
        self.cluster = Some(Cluster {
            start: occurrence,
            end: occurrence,
            groups: BTreeSet::from([group]),
        });
    }

    fn close_cluster(&mut self) {
        if let Some(c) = self.cluster.take() {
            if c.groups.len() >= 2 && self.clusters.len() < MAX_CLUSTERS {
                self.clusters.push(c);
            }
        }
    }

    /// Records a shutdown marker; links error-level groups whose last occurrence is
    /// shortly before it.
    pub fn observe_shutdown(&mut self, marker: Evidence, groups: &[Group]) {
        if self.shutdowns.len() >= MAX_SHUTDOWN_MARKERS
            || self.last_marker_line.is_some_and(|l| {
                marker.line.saturating_sub(l) <= self.config.proximity_window_lines
            })
        {
            return;
        }
        self.last_marker_line = Some(marker.line);
        let linked: Vec<usize> = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| g.severity >= Severity::Error && self.precedes(&g.last, &marker))
            .map(|(i, _)| i)
            .collect();
        if !linked.is_empty() {
            self.shutdowns.push(ShutdownLink {
                marker,
                groups: linked,
            });
        }
    }

    fn precedes(&self, occurrence: &Occurrence, marker: &Evidence) -> bool {
        if occurrence.line >= marker.line {
            return false;
        }
        match (occurrence.timestamp, marker.timestamp) {
            (Some(a), Some(b)) => a.millis_until(&b).is_some_and(|ms| {
                (0..=i64::from(self.config.shutdown_window_secs) * 1000).contains(&ms)
            }),
            _ => marker.line - occurrence.line <= self.config.proximity_window_lines,
        }
    }

    /// Produces correlation drafts.
    ///
    /// `last_line` is the last line of the input; `had_shutdown` whether any shutdown
    /// marker was seen.
    pub fn finish(
        mut self,
        groups: &[Group],
        last_line: u64,
        had_shutdown: bool,
    ) -> Vec<CorrelationDraft> {
        self.flush_event();
        self.close_cluster();
        let mut drafts = Vec::new();
        self.same_event_drafts(groups, &mut drafts);
        self.cluster_drafts(&mut drafts);
        self.shutdown_drafts(&mut drafts);
        if !had_shutdown {
            near_end_draft(
                groups,
                last_line,
                self.config.proximity_window_lines,
                &mut drafts,
            );
        }
        same_plugin_drafts(groups, &self.pairs, &mut drafts);
        drafts
    }

    fn same_event_drafts(&self, groups: &[Group], drafts: &mut Vec<CorrelationDraft>) {
        for (&(a, b), stat) in &self.pairs {
            let mut evidence: Vec<Evidence> = [a, b]
                .iter()
                .filter_map(|&g| groups.get(g))
                .flat_map(|g| {
                    g.evidence
                        .iter()
                        .filter(|e| e.line >= stat.first_line)
                        .take(1)
                })
                .cloned()
                .collect();
            evidence.sort_by_key(|e| e.line);
            evidence.dedup_by_key(|e| e.line);
            drafts.push(CorrelationDraft {
                kind: CorrelationKind::SameEvent,
                groups: vec![a, b],
                description: format!(
                    "Both findings were detected in the same log entry {} time(s), first in the entry starting at line {}. The server printed them together, so they describe the same incident.",
                    stat.count, stat.first_line
                ),
                evidence,
            });
        }
    }

    fn cluster_drafts(&self, drafts: &mut Vec<CorrelationDraft>) {
        for c in &self.clusters {
            let groups: Vec<usize> = c.groups.iter().copied().collect();
            if groups.len() == 2 && self.pairs.contains_key(&(groups[0], groups[1])) {
                continue;
            }
            let (start, end) = (
                c.start.timestamp.map(|t| t.to_string()),
                c.end.timestamp.map(|t| t.to_string()),
            );
            drafts.push(CorrelationDraft {
                kind: CorrelationKind::TemporalCluster,
                description: format!(
                    "{} distinct error-level findings occurred with gaps of at most {} s between {} and {} (lines {}-{}). Proximity in time does not by itself establish that one caused another.",
                    groups.len(),
                    self.config.temporal_window_secs,
                    start.unwrap_or_default(),
                    end.unwrap_or_default(),
                    c.start.line,
                    c.end.line
                ),
                groups,
                evidence: Vec::new(),
            });
        }
    }

    fn shutdown_drafts(&self, drafts: &mut Vec<CorrelationDraft>) {
        for s in &self.shutdowns {
            let window = if s.marker.timestamp.is_some() {
                format!("{} s", self.config.shutdown_window_secs)
            } else {
                format!("{} lines", self.config.proximity_window_lines)
            };
            drafts.push(CorrelationDraft {
                kind: CorrelationKind::PrecededShutdown,
                groups: s.groups.clone(),
                description: format!(
                    "These error-level findings last occurred within {window} before the shutdown that began at line {}. They may be related to the shutdown, or the shutdown may have been routine.",
                    s.marker.line
                ),
                evidence: vec![s.marker.clone()],
            });
        }
    }
}

fn near_end_draft(
    groups: &[Group],
    last_line: u64,
    window: u64,
    drafts: &mut Vec<CorrelationDraft>,
) {
    let near: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.severity == Severity::Critical && g.last.line + window >= last_line)
        .map(|(i, _)| i)
        .collect();
    if !near.is_empty() {
        drafts.push(CorrelationDraft {
            kind: CorrelationKind::NearEndOfLog,
            groups: near,
            description: format!(
                "These critical findings occurred within the last {window} lines of the log (which ends at line {last_line}) and no shutdown message follows. The process may have terminated abnormally, or the log may have been captured early."
            ),
            evidence: Vec::new(),
        });
    }
}

fn same_plugin_drafts(
    groups: &[Group],
    pairs: &BTreeMap<(usize, usize), PairStat>,
    drafts: &mut Vec<CorrelationDraft>,
) {
    let mut by_plugin: BTreeMap<String, (String, Vec<usize>)> = BTreeMap::new();
    // Pattern groups restate their source group and are linked to it directly.
    for (i, g) in groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.rule.category != Category::Pattern)
    {
        if let Some(p) = &g.subject.plugin {
            by_plugin
                .entry(p.to_ascii_lowercase())
                .or_insert_with(|| (p.clone(), Vec::new()))
                .1
                .push(i);
        }
    }
    for (_, (name, members)) in by_plugin {
        let restates_pair = members.len() == 2 && pairs.contains_key(&(members[0], members[1]));
        if members.len() >= 2 && !restates_pair {
            drafts.push(CorrelationDraft {
                kind: CorrelationKind::SamePlugin,
                groups: members,
                description: format!(
                    "The log explicitly attributes each of these findings to the plugin {name}."
                ),
                evidence: Vec::new(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anycasted_core::models::{EvidenceRole, TimeOfDay, Timestamp};

    fn ts(s: u8) -> Option<Timestamp> {
        Some(Timestamp {
            date: None,
            time: TimeOfDay::new(12, 0, s, None).unwrap(),
            day_offset: 0,
        })
    }

    fn occ(line: u64, s: u8) -> Occurrence {
        Occurrence {
            line,
            timestamp: ts(s),
        }
    }

    #[test]
    fn same_event_and_clusters() {
        let mut c = Correlator::new(&AnalysisConfig::default());
        c.observe_hit(0, Severity::Error, occ(10, 1));
        c.observe_hit(1, Severity::Error, occ(10, 1));
        c.observe_hit(2, Severity::Error, occ(20, 3));
        c.observe_hit(3, Severity::Error, occ(30, 50));
        let drafts = c.finish(&[], 100, true);
        let same: Vec<_> = drafts
            .iter()
            .filter(|d| d.kind == CorrelationKind::SameEvent)
            .collect();
        assert_eq!(same.len(), 1);
        assert_eq!(same[0].groups, vec![0, 1]);
        let clusters: Vec<_> = drafts
            .iter()
            .filter(|d| d.kind == CorrelationKind::TemporalCluster)
            .collect();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].groups, vec![0, 1, 2]);
    }

    #[test]
    fn shutdown_proximity_uses_time() {
        use crate::patterns::Aggregator;
        use anycasted_core::Limits;
        use anycasted_core::models::{Category, Hit, RuleMeta};
        let meta = RuleMeta::new("T", Category::Exception, Severity::Error)
            .title("t")
            .shared();
        let mut agg = Aggregator::new(&Limits::default());
        agg.add(Hit::new(meta.clone(), "a".into(), occ(5, 0)));
        let mut late = Hit::new(meta, "b".into(), occ(6, 0));
        late.severity = Severity::Info;
        agg.add(late);
        let mut c = Correlator::new(&AnalysisConfig::default());
        let marker = Evidence {
            line: 50,
            text: "Stopping server".into(),
            role: EvidenceRole::Context,
            timestamp: ts(30),
        };
        c.observe_shutdown(marker, agg.groups());
        let drafts = c.finish(agg.groups(), 60, true);
        let s: Vec<_> = drafts
            .iter()
            .filter(|d| d.kind == CorrelationKind::PrecededShutdown)
            .collect();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].groups, vec![0]);
    }
}
