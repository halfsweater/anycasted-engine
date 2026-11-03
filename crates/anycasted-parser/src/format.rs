//! Streaming server software / log format identification.
//!
//! Identification is based on explicit self-identification lines (high confidence),
//! secondary markers (medium confidence), or only the generic line syntax (low
//! confidence, reported as uncertain). Vanilla is identified by the *absence* of any
//! modified-server markers and is therefore never reported with high confidence.

use anycasted_core::models::{
    Evidence, EvidenceRole, FormatConfidence, FormatDetection, LogEvent, LogFormat,
};
use anycasted_core::text::excerpt;
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;

use crate::velocity;

/// A marker: substring of a log message → (format, strength).
struct Marker {
    needle: &'static str,
    format: LogFormat,
    strength: FormatConfidence,
}

const fn m(needle: &'static str, format: LogFormat, strength: FormatConfidence) -> Marker {
    Marker {
        needle,
        format,
        strength,
    }
}

use FormatConfidence::{High, Medium};
use LogFormat::{Fabric, Forge, Paper, Purpur, Spigot, Velocity};

const MARKERS: &[Marker] = &[
    m("This server is running Purpur version", Purpur, High),
    m("This server is running Paper version", Paper, High),
    m("This server is running CraftBukkit version", Spigot, Medium),
    m("Booting up Velocity", Velocity, High),
    m("with Fabric Loader", Fabric, High),
    m("ModLauncher running", Forge, High),
    m("MinecraftForge v", Forge, High),
    m("NeoForge", Forge, Medium),
    m("[bootstrap] Running Java", Paper, Medium),
    m("Paper: Using", Paper, Medium),
    m("Loading Paper", Paper, Medium),
    m("Purpur config", Purpur, Medium),
    m("Loading server plugin", Spigot, Medium),
    m("Server permissions file permissions.yml", Spigot, Medium),
    m("[connected player] ", Velocity, Medium),
    m("[server connection] ", Velocity, Medium),
];

/// One automaton over all marker needles: a single scan per message.
static MARKER_AUTOMATON: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(MARKERS.iter().map(|m| m.needle)).expect("valid marker needles")
});

/// Priority when two formats have the same strength: forks before their upstream.
const PRIORITY: &[LogFormat] = &[Velocity, Purpur, Paper, Spigot, Forge, Fabric];

/// Maximum indicator lines kept per format.
const MAX_INDICATORS: usize = 3;
/// Maximum characters per indicator excerpt.
const INDICATOR_CHARS: usize = 200;

#[derive(Debug, Default)]
struct Candidate {
    strength: Option<FormatConfidence>,
    indicators: Vec<Evidence>,
}

/// Observes events and identifies the format.
#[derive(Debug, Default)]
pub struct FormatDetector {
    candidates: Vec<(LogFormat, Candidate)>,
    vanilla_marker: Option<Evidence>,
    header_events: u64,
    events: u64,
}

impl FormatDetector {
    /// Creates a detector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes one event.
    pub fn observe(&mut self, event: &LogEvent) {
        self.events += 1;
        let Some(header) = &event.header else {
            return;
        };
        self.header_events += 1;
        if event.is_user_content() {
            return;
        }
        let message = event.message();
        for m in MARKER_AUTOMATON.find_overlapping_iter(message) {
            let marker = &MARKERS[m.pattern().as_usize()];
            // `This server is running CraftBukkit version ...-Spigot-...` identifies a
            // Spigot build explicitly.
            let spigot_build = marker.needle == "This server is running CraftBukkit version"
                && message.contains("-Spigot-");
            let strength = if spigot_build { High } else { marker.strength };
            self.record(marker.format, strength, event);
        }
        if header
            .logger
            .as_deref()
            .is_some_and(velocity::is_velocity_logger)
        {
            self.record(Velocity, Medium, event);
        }
        if self.vanilla_marker.is_none() && message.starts_with("Starting minecraft server version")
        {
            self.vanilla_marker = Some(indicator(event));
        }
    }

    fn record(&mut self, format: LogFormat, strength: FormatConfidence, event: &LogEvent) {
        let idx = match self.candidates.iter().position(|(f, _)| *f == format) {
            Some(i) => i,
            None => {
                self.candidates.push((format, Candidate::default()));
                self.candidates.len() - 1
            }
        };
        let c = &mut self.candidates[idx].1;
        c.strength = c.strength.max(Some(strength));
        if c.indicators.len() < MAX_INDICATORS
            && !c.indicators.iter().any(|e| e.line == event.start_line())
        {
            c.indicators.push(indicator(event));
        }
    }

    /// Final identification.
    pub fn finish(self) -> FormatDetection {
        let best = self
            .candidates
            .into_iter()
            .filter_map(|(f, c)| c.strength.map(|s| (f, s, c.indicators)))
            .max_by_key(|(f, s, _)| {
                let prio = PRIORITY.iter().rev().position(|p| p == f).unwrap_or(0);
                (*s, prio)
            });
        let (format, confidence, indicators) = match (best, self.vanilla_marker) {
            (Some(best), _) => best,
            (None, Some(v)) => (LogFormat::Vanilla, Medium, vec![v]),
            (None, None) if self.header_events > 0 => (
                LogFormat::GenericMinecraft,
                FormatConfidence::Low,
                Vec::new(),
            ),
            (None, None) => (LogFormat::Unknown, FormatConfidence::Low, Vec::new()),
        };
        FormatDetection {
            format,
            confidence,
            uncertain: confidence != High,
            indicators,
        }
    }
}

fn indicator(event: &LogEvent) -> Evidence {
    let line = event.first_line();
    Evidence {
        line: line.number,
        text: excerpt(&line.text, INDICATOR_CHARS).into_owned(),
        role: EvidenceRole::Context,
        timestamp: event.timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventBuilder;
    use anycasted_core::{Limits, models::SourceLine};

    fn detect(text: &str) -> FormatDetection {
        let mut b = EventBuilder::new(&Limits::default());
        let mut d = FormatDetector::new();
        for (i, l) in text.lines().enumerate() {
            if let Some(ev) = b.push(SourceLine {
                number: i as u64 + 1,
                text: l.to_owned(),
            }) {
                d.observe(&ev);
            }
        }
        if let Some(ev) = b.finish() {
            d.observe(&ev);
        }
        d.finish()
    }

    #[test]
    fn identifies_paper() {
        let d = detect(
            "[12:00:00 INFO]: Starting minecraft server version 1.20.4\n[12:00:00 INFO]: This server is running Paper version 1.20.4-496-master@abc (2024-04-21T00:00:00Z) (Implementing API version 1.20.4-R0.1-SNAPSHOT)",
        );
        assert_eq!(d.format, LogFormat::Paper);
        assert_eq!(d.confidence, High);
        assert_eq!(d.indicators[0].line, 2);
    }

    #[test]
    fn purpur_beats_paper() {
        let d = detect(
            "[12:00:00 INFO]: [bootstrap] Running Java 21\n[12:00:00 INFO]: This server is running Purpur version 1.20.4-2176",
        );
        assert_eq!(d.format, LogFormat::Purpur);
    }

    #[test]
    fn vanilla_is_medium_by_absence() {
        let d = detect("[12:00:00] [Server thread/INFO]: Starting minecraft server version 1.20.4");
        assert_eq!(d.format, LogFormat::Vanilla);
        assert!(d.uncertain);
    }

    #[test]
    fn generic_and_unknown() {
        assert_eq!(
            detect("[12:00:00 INFO]: hello").format,
            LogFormat::GenericMinecraft
        );
        assert_eq!(detect("hello world").format, LogFormat::Unknown);
        assert_eq!(detect("").format, LogFormat::Unknown);
    }
}
