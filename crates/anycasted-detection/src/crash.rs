//! Crash report rules.
//!
//! The crash report's main exception is additionally run through all exception rules
//! by the engine. The rules here add what only a crash report provides: the crash
//! description, the crashing entity/block, and system state at crash time.

use std::sync::Arc;

use anycasted_core::models::{
    Category, Classification, CrashReport, EvidenceRole, Implication, ImplicationBasis, RuleMeta,
    Severity,
};

use crate::rule::{CrashMatch, CrashRule, Extraction};

/// Id of the generic crash rule.
pub const GENERIC_CRASH_ID: &str = "CRASH-REPORT";

/// Heap usage (fraction of max heap) above which the heap is considered nearly full.
const LOW_MEMORY_THRESHOLD: f64 = 0.90;

const BACKUP_FIRST: &str = "Make a backup of your world before editing or deleting anything.";
const OTHER_PROBLEMS: &str = "Check the other problems listed in this report: they describe the error that caused the crash and the plugin or mod involved.";

fn base_lines(report: &CrashReport) -> Vec<(u64, EvidenceRole)> {
    let mut lines = Vec::new();
    if let Some(d) = &report.description {
        lines.push((d.line, EvidenceRole::Match));
    }
    if let Some(top) = report.exception.as_ref().and_then(|c| c.top()) {
        lines.push((top.line, EvidenceRole::Exception));
    }
    lines
}

/// Generic rule: every crash report with a description is an observed crash.
struct GenericCrash(Arc<RuleMeta>);

impl CrashRule for GenericCrash {
    fn meta(&self) -> &Arc<RuleMeta> {
        &self.0
    }

    fn evaluate(&self, report: &CrashReport) -> Option<CrashMatch> {
        let description = report.description.as_ref()?;
        let mut lines = vec![(report.header_line, EvidenceRole::Context)];
        lines.extend(base_lines(report));
        Some(CrashMatch {
            lines,
            extraction: Extraction {
                headline: Some(description.value.clone()),
                group: Some(description.value.to_ascii_lowercase()),
                ..Extraction::default()
            }
            .var("description", description.value.clone()),
        })
    }
}

/// A crash signature identified by the crash description. `details` maps crash report
/// detail keys of `section` to template variables.
struct DescriptionSignature {
    meta: Arc<RuleMeta>,
    needles: &'static [&'static str],
    section: Option<&'static str>,
    details: &'static [(&'static str, &'static str)],
}

impl CrashRule for DescriptionSignature {
    fn meta(&self) -> &Arc<RuleMeta> {
        &self.meta
    }

    fn is_signature(&self) -> bool {
        true
    }

    fn evaluate(&self, report: &CrashReport) -> Option<CrashMatch> {
        let description = report.description.as_ref()?.value.to_ascii_lowercase();
        if !self.needles.iter().any(|n| description.contains(n)) {
            return None;
        }
        let mut lines = base_lines(report);
        let mut extraction = Extraction::default();
        if let Some(section) = self.section.and_then(|name| report.section(name)) {
            for (key, var) in self.details {
                let Some(d) = section.detail(key) else {
                    continue;
                };
                lines.push((d.line, EvidenceRole::CrashDetail));
                // `minecraft:wolf (net.minecraft....Wolf)` → `minecraft:wolf`
                let value = d
                    .value
                    .split(" (")
                    .next()
                    .unwrap_or(&d.value)
                    .trim()
                    .to_owned();
                if extraction.headline.is_none() {
                    extraction.headline = Some(value.clone());
                    extraction.group = Some(value.clone());
                }
                extraction.vars.push((var, value));
            }
            let summary: Vec<String> = section
                .details
                .iter()
                .filter(|d| {
                    self.details
                        .iter()
                        .any(|(k, _)| d.key.eq_ignore_ascii_case(k))
                })
                .map(|d| format!("{}: {}", d.key, d.value))
                .collect();
            extraction.detail = (!summary.is_empty()).then(|| summary.join("; "));
        }
        Some(CrashMatch { lines, extraction })
    }
}

struct LowMemory(Arc<RuleMeta>);

impl CrashRule for LowMemory {
    fn meta(&self) -> &Arc<RuleMeta> {
        &self.0
    }

    fn evaluate(&self, report: &CrashReport) -> Option<CrashMatch> {
        let memory = report.memory?;
        let used = memory.used_fraction_of_max();
        if used < LOW_MEMORY_THRESHOLD {
            return None;
        }
        let used_mib = memory.total_bytes.saturating_sub(memory.free_bytes) / (1024 * 1024);
        let max_mib = memory.max_bytes / (1024 * 1024);
        Some(CrashMatch {
            lines: vec![(memory.line, EvidenceRole::CrashDetail)],
            extraction: Extraction {
                detail: Some(format!(
                    "{:.0}% of the maximum heap in use ({used_mib} MiB of {max_mib} MiB)",
                    used * 100.0
                )),
                ..Extraction::default()
            }
            .var("used_percent", format!("{:.0}", used * 100.0))
            .var("used_mib", used_mib.to_string())
            .var("max_mib", max_mib.to_string()),
        })
    }
}

struct SuspectedMods(Arc<RuleMeta>);

impl CrashRule for SuspectedMods {
    fn meta(&self) -> &Arc<RuleMeta> {
        &self.0
    }

    fn evaluate(&self, report: &CrashReport) -> Option<CrashMatch> {
        if report.suspected_mods.is_empty() {
            return None;
        }
        let names: Vec<&str> = report
            .suspected_mods
            .iter()
            .map(|m| m.value.as_str())
            .collect();
        Some(CrashMatch {
            lines: report
                .suspected_mods
                .iter()
                .map(|m| (m.line, EvidenceRole::CrashDetail))
                .collect(),
            extraction: Extraction {
                headline: Some(names.join(", ")),
                implicated: report
                    .suspected_mods
                    .iter()
                    .map(|m| Implication {
                        name: m.value.clone(),
                        basis: ImplicationBasis::CrashReportSuspect,
                        classification: Classification::Hypothesis,
                        seen_loading: None,
                    })
                    .collect(),
                ..Extraction::default()
            }
            .var("mods", names.join(", ")),
        })
    }
}

fn crash(id: &str, title: &str, description: &str, evidence: &str) -> RuleMeta {
    RuleMeta::new(id, Category::Crash, Severity::Critical)
        .title(title)
        .description(description)
        .evidence(evidence)
}

/// Built-in crash rules.
pub fn crash_rules() -> Vec<Box<dyn CrashRule>> {
    vec![
        Box::new(GenericCrash(
            crash(GENERIC_CRASH_ID, "Minecraft server crashed", "A Minecraft crash report was generated: the server stopped because of an unrecoverable error.", "A crash report with a `Description:` line.")
                .user_title("The server crashed: {description|reason not stated}")
                .explain("The server crashed and wrote this report. The reason it gives is \"{description|not stated}\".[[ The error was: {error_hint}.]]")
                .fix(&[OTHER_PROBLEMS, "Update the plugins or mods named in those problems, then start the server again."])
                .shared(),
        )),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-TICKING-ENTITY", "Crash while ticking an entity", "The server crashed while updating a specific entity; if it is saved in the world, the crash repeats whenever its chunk loads.", "Crash description `Ticking entity`, with the `Entity being ticked` section when present.")
                .user_title("The server crashed because of a broken entity[[ ({entity})]]")
                .explain("An entity[[ ({entity})]][[ at {location}]] caused an error every time the server updated it, which crashed the server.[[ The error: {error_hint}.]] Because the entity is saved in the world, the crash will probably happen again whenever that area is loaded.")
                .fix(&[
                    BACKUP_FIRST,
                    "Stop the server and remove that entity with a world editor such as MCA Selector or NBTExplorer[[ (it is at {location})]].",
                    "If a plugin adds this kind of mob or pet (check the error), update that plugin.",
                    "Start the server and check that it stays up.",
                ])
                .shared(),
            needles: &["ticking entity"],
            section: Some("Entity being ticked"),
            details: &[("Entity Type", "entity"), ("Entity's Exact location", "location")],
        }),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-TICKING-BLOCK-ENTITY", "Crash while ticking a block entity", "The server crashed while updating a block entity (chest, furnace, spawner, modded machine); the crash usually repeats whenever its chunk loads.", "Crash description `Ticking block entity`, with the `Block entity being ticked` section when present.")
                .user_title("The server crashed because of a broken block[[ ({block})]]")
                .explain("A special block[[ ({block})]][[ at {location}]] (like a chest, spawner, furnace or modded machine) caused an error every time the server updated it, which crashed the server. The crash will probably happen again whenever that area is loaded.")
                .fix(&[
                    BACKUP_FIRST,
                    "Stop the server and remove or replace that block with a world editor such as MCA Selector or NBTExplorer[[ (it is at {location})]].",
                    "Update the plugin or mod that adds this block.",
                ])
                .shared(),
            needles: &["ticking block entity", "ticking tile entity"],
            section: Some("Block entity being ticked"),
            details: &[("Name", "block"), ("Block location", "location")],
        }),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-WATCHDOG", "Server watchdog killed the server", "A single server tick took too long (by default 60 seconds) and the watchdog deliberately crashed the server.", "Crash description `Watching Server`.")
                .user_title("The server froze and the watchdog stopped it")
                .explain("A single server tick took far too long (usually more than 60 seconds), so Minecraft deliberately crashed the server instead of letting it hang forever. Something was blocking the main server thread, often a plugin waiting on a website or database, or stuck in a loop.")
                .fix(&[
                    "Look at the \"Server thread\" section of this crash report: plugin names there show what was running.",
                    "Use the spark plugin to profile the server and find long-running tasks.",
                    "Don't just raise max-tick-time in server.properties; that hides the freeze instead of fixing it.",
                ])
                .shared(),
            needles: &["watching server"],
            section: None,
            details: &[],
        }),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-WORLDGEN", "Crash during world generation", "The server crashed while generating terrain or placing features.", "Crash description mentioning chunk generation or feature placement.")
                .user_title("The server crashed while generating new terrain")
                .explain("The server crashed while creating new parts of the world. World-generation plugins, data packs or custom generator settings are the usual cause.")
                .fix(&[
                    "Update world-generation plugins and data packs.",
                    "If you recently changed generator settings or added a data pack, undo that change and test again.",
                    OTHER_PROBLEMS,
                ])
                .shared(),
            needles: &["exception generating new chunk", "exception generating chunk", "feature placement", "chunk generation"],
            section: None,
            details: &[],
        }),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-TICKING-WORLD", "Crash while ticking a world", "The server crashed during the world update step (outside a specific entity).", "Crash description `Exception ticking world`.")
                .user_title("The server crashed while updating the world")
                .explain("The server crashed during its regular world update.[[ The error was: {error_hint}.]]")
                .fix(&[OTHER_PROBLEMS, BACKUP_FIRST])
                .shared(),
            needles: &["exception ticking world"],
            section: None,
            details: &[],
        }),
        Box::new(DescriptionSignature {
            meta: crash("CRASH-NBT", "Crash while reading or writing saved data (NBT)", "The server crashed while loading or saving NBT data; the stored data is likely corrupted or written by an incompatible version/mod.", "Crash description mentioning NBT data.")
                .user_title("The server crashed while reading saved data")
                .explain("The server crashed while loading or saving stored data (chunks, entities or player data). That data is probably damaged, or was saved by a different (newer) version or by mods that are no longer installed.")
                .fix(&[
                    BACKUP_FIRST,
                    "Restore the affected world or player data file from a backup.",
                    "If the world was opened with a newer Minecraft version or with mods that were removed, go back to that setup.",
                ])
                .shared(),
            needles: &["nbt"],
            section: None,
            details: &[],
        }),
        Box::new(LowMemory(
            RuleMeta::new("CRASH-LOW-MEMORY", Category::Memory, Severity::Warning)
                .title("Heap nearly full at crash time")
                .description("The crash report shows more than 90% of the maximum heap in use at crash time. Memory pressure may have contributed, but uncollected garbage also counts, so this is not proof.")
                .evidence("The `Memory:` system detail with used heap ≥ 90% of the maximum heap.")
                .user_title("Memory was almost full when the server crashed")
                .explain("When it crashed, the server was using[[ {used_percent}% ({used_mib} MB of {max_mib} MB) of]] almost all the memory it is allowed to use. That may have contributed to the crash, but it isn't proof: Java often fills memory before cleaning it up.")
                .fix(&[
                    "Check whether the server's memory (RAM) allocation is enough for your player count and plugins.",
                    "Watch memory use with the spark plugin (`/spark health`) to see whether it keeps climbing.",
                ])
                .confidence(0.5)
                .classification(Classification::LikelyContributing)
                .shared(),
        )),
        Box::new(SuspectedMods(
            RuleMeta::new("CRASH-SUSPECTED-MODS", Category::Crash, Severity::Warning)
                .title("Crash report lists suspected mods")
                .description("The mod loader listed mods whose code appears in the crash stack trace; a heuristic, not a confirmed cause.")
                .evidence("A non-empty `Suspected Mods` entry in the crash report.")
                .user_title("The crash report suspects {mods|some mods}")
                .explain("The mod loader noticed {mods|some mods} in the error. This is the loader's best guess, not a confirmed cause.")
                .fix(&[
                    "Update {mods|the suspected mods} first, then try again.",
                    "If it still crashes, test without them to confirm or rule them out.",
                ])
                .confidence(0.4)
                .classification(Classification::Hypothesis)
                .shared(),
        )),
    ]
}
