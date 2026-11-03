//! Minecraft crash report parsing.
//!
//! Crash reports (`crash-reports/crash-<date>-server.txt`) have a fixed layout:
//!
//! ```text
//! ---- Minecraft Crash Report ----
//! // witty comment
//!
//! Time: 2024-04-21 18:03:11
//! Description: Exception in server tick loop
//!
//! java.lang.NullPointerException: ...
//!     at ...
//!
//!
//! A detailed walkthrough of the error, its code path and all known details is as follows:
//! ---------------------------------------------------------------------------------------
//!
//! -- Head --
//! Thread: Server thread
//! ...
//! -- System Details --
//! Details:
//!     Minecraft Version: 1.20.4
//!     Memory: 123 bytes (0 MiB) / 456 bytes (0 MiB) up to 789 bytes (0 MiB)
//! ```

use anycasted_core::models::{
    CrashDetail, CrashReport, CrashSection, Located, MemoryInfo, SourceLine,
};

use crate::java;

/// Marker line that identifies a crash report.
pub const CRASH_REPORT_MARKER: &str = "---- Minecraft Crash Report ----";
const WALKTHROUGH: &str = "A detailed walkthrough of the error";

/// Whether the given leading lines identify a crash report: the marker must appear
/// within the first `window` non-blank lines.
pub fn looks_like_crash_report<'a, I>(lines: I, window: usize) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    lines
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .take(window)
        .any(|l| l.contains(CRASH_REPORT_MARKER))
}

/// Parses a crash report from its lines.
pub fn parse_crash_report(lines: &[SourceLine], max_frames: usize) -> CrashReport {
    let mut report = CrashReport {
        total_lines: lines.last().map_or(0, |l| l.number),
        ..CrashReport::default()
    };
    let start = lines
        .iter()
        .position(|l| l.text.contains(CRASH_REPORT_MARKER))
        .unwrap_or(0);
    if let Some(l) = lines.get(start) {
        report.header_line = l.number;
    }

    let mut i = (start + 1).min(lines.len());
    // Preamble: comments, Time, Description.
    while i < lines.len() {
        let line = &lines[i];
        let t = line.text.trim();
        if let Some(v) = t.strip_prefix("Time:") {
            report.time = Some(Located::new(v.trim().to_owned(), line.number));
        } else if let Some(v) = t.strip_prefix("Description:") {
            report.description = Some(Located::new(v.trim().to_owned(), line.number));
            i += 1;
            break;
        } else if t.starts_with("-- ") || t.starts_with(WALKTHROUGH) {
            break;
        }
        i += 1;
    }

    // Main exception block: up to the walkthrough line or the first section.
    let block_start = i;
    while i < lines.len() {
        let t = lines[i].text.trim_start();
        if t.starts_with(WALKTHROUGH) || is_section_header(t).is_some() {
            break;
        }
        i += 1;
    }
    let block: Vec<SourceLine> = lines[block_start..i]
        .iter()
        .filter(|l| !l.text.trim().is_empty())
        .cloned()
        .collect();
    report.exception = java::extract_chains(
        block.iter().map(|l| (l.number, l.text.as_str())),
        max_frames,
    )
    .into_iter()
    .next();
    report.exception_lines = block;

    parse_sections(&lines[i..], &mut report);
    extract_known_details(&mut report);
    report
}

fn is_section_header(t: &str) -> Option<&str> {
    let name = t.trim_end().strip_prefix("-- ")?.strip_suffix(" --")?;
    (!name.is_empty() && name.len() <= 80).then_some(name)
}

fn parse_sections(lines: &[SourceLine], report: &mut CrashReport) {
    let mut current: Option<CrashSection> = None;
    for line in lines {
        if let Some(name) = is_section_header(line.text.trim()) {
            report.sections.extend(current.take());
            current = Some(CrashSection {
                name: name.to_owned(),
                line: line.number,
                details: Vec::new(),
            });
            continue;
        }
        let Some(section) = current.as_mut() else {
            continue;
        };
        if let Some(detail) = parse_detail(line) {
            section.details.push(detail);
        }
    }
    report.sections.extend(current);
}

/// Parses an indented `Key: Value` detail line. Stack frames are skipped.
fn parse_detail(line: &SourceLine) -> Option<CrashDetail> {
    let text = &line.text;
    let indent = text.len() - text.trim_start_matches(['\t', ' ']).len();
    let t = text.trim();
    if t.is_empty() || java::is_stack_line(t) {
        return None;
    }
    let tabs = text.bytes().take_while(|&b| b == b'\t').count();
    let depth = if tabs > 0 { tabs } else { indent.div_ceil(4) };
    let (key, value) = t.split_once(':')?;
    if key.is_empty() || key.len() > 64 {
        return None;
    }
    Some(CrashDetail {
        key: key.trim().to_owned(),
        value: value.trim().to_owned(),
        line: line.number,
        depth: u8::try_from(depth).unwrap_or(u8::MAX),
    })
}

fn located(detail: &CrashDetail) -> Located<String> {
    Located::new(detail.value.clone(), detail.line)
}

fn extract_known_details(report: &mut CrashReport) {
    report.minecraft_version = report.detail("Minecraft Version").map(located);
    report.java_version = report.detail("Java Version").map(located);
    report.operating_system = report.detail("Operating System").map(located);
    report.jvm_flags = report.detail("JVM Flags").map(located);
    report.memory = report
        .detail("Memory")
        .and_then(|d| parse_memory(&d.value, d.line));
    report.server_brand = report
        .detail("BrandInfo")
        .or_else(|| report.detail("Server Brand"))
        .or_else(|| report.detail("Is Modded"))
        .map(located);
    report.plugins = report
        .detail("Plugins")
        .map(|d| parse_plugin_list(&d.value))
        .unwrap_or_default();
    report.suspected_mods = suspected_mods(report);
}

/// `Memory: 12 bytes (0 MiB) / 34 bytes (0 MiB) up to 56 bytes (0 MiB)` → free/total/max.
fn parse_memory(value: &str, line: u64) -> Option<MemoryInfo> {
    let mut numbers = value.split(" bytes").filter_map(|part| {
        part.rsplit([' ', '/'])
            .find(|t| !t.is_empty())?
            .parse::<u64>()
            .ok()
    });
    Some(MemoryInfo {
        free_bytes: numbers.next()?,
        total_bytes: numbers.next()?,
        max_bytes: numbers.next()?,
        line,
    })
}

/// `{ LuckPerms v5.4.102 me.lucko.Loader [Luck], EssentialsX v2.20.1 com.Foo [a, b] }`.
fn parse_plugin_list(value: &str) -> Vec<String> {
    let inner = value.trim().trim_start_matches('{').trim_end_matches('}');
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in inner.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                items.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&inner[start..]);
    items
        .into_iter()
        .filter_map(|item| {
            let mut tokens = item.split_whitespace();
            let name = tokens.next()?;
            tokens.next().filter(|v| v.starts_with('v'))?;
            Some(name.to_owned())
        })
        .collect()
}

fn suspected_mods(report: &CrashReport) -> Vec<Located<String>> {
    let mut out = Vec::new();
    for section in &report.sections {
        let mut iter = section.details.iter().peekable();
        while let Some(d) = iter.next() {
            if !d.key.eq_ignore_ascii_case("Suspected Mods")
                && !d.key.eq_ignore_ascii_case("Suspected Mod")
            {
                continue;
            }
            for v in d.value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                if !v.eq_ignore_ascii_case("None") && !v.starts_with("Unknown") {
                    out.push(Located::new(v.to_owned(), d.line));
                }
            }
            // Forge prints suspects on nested lines.
            while let Some(child) = iter.peek().filter(|c| c.depth > d.depth) {
                out.push(Located::new(
                    format!("{}: {}", child.key, child.value),
                    child.line,
                ));
                iter.next();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "---- Minecraft Crash Report ----
// Who set us up the TNT?

Time: 2024-04-21 18:03:11
Description: Ticking entity

java.lang.NullPointerException: Cannot invoke \"net.minecraft.world.entity.Entity.getX()\" because \"target\" is null
\tat net.minecraft.world.entity.monster.Zombie.tick(Zombie.java:120)
\tat net.minecraft.server.level.ServerLevel.tickNonPassenger(ServerLevel.java:900)


A detailed walkthrough of the error, its code path and all known details is as follows:
---------------------------------------------------------------------------------------

-- Head --
Thread: Server thread
Stacktrace:
\tat net.minecraft.world.entity.monster.Zombie.tick(Zombie.java:120)

-- Entity being ticked --
Details:
\tEntity Type: minecraft:zombie (net.minecraft.world.entity.monster.Zombie)
\tEntity's Exact location: 10.50, 64.00, -3.20

-- System Details --
Details:
\tMinecraft Version: 1.20.4
\tOperating System: Linux (amd64) version 6.1.0
\tJava Version: 17.0.9, Eclipse Adoptium
\tMemory: 104857600 bytes (100 MiB) / 4294967296 bytes (4096 MiB) up to 4294967296 bytes (4096 MiB)
\tJVM Flags: 2 total; -Xms4G -Xmx4G
\tCraftBukkit Information:
\t\tBrandInfo: Paper (papermc:paper) version 1.20.4-496
\t\tPlugins: { LuckPerms v5.4.102 me.lucko.luckperms.bukkit.loader.BukkitLoaderPlugin [Luck], Foo v1.0 com.foo.Foo [A, B]}
\tSuspected Mods: None
";

    fn lines(s: &str) -> Vec<SourceLine> {
        s.lines()
            .enumerate()
            .map(|(i, t)| SourceLine {
                number: i as u64 + 1,
                text: t.to_owned(),
            })
            .collect()
    }

    #[test]
    fn detects_marker() {
        assert!(looks_like_crash_report(SAMPLE.lines(), 5));
        assert!(!looks_like_crash_report(["[12:00:00 INFO]: hi"], 5));
    }

    #[test]
    fn parses_sample() {
        let r = parse_crash_report(&lines(SAMPLE), 64);
        assert_eq!(r.header_line, 1);
        assert_eq!(r.description.as_ref().unwrap().value, "Ticking entity");
        assert_eq!(r.description.as_ref().unwrap().line, 5);
        let exc = r.exception.as_ref().unwrap();
        assert_eq!(exc.top().unwrap().line, 7);
        assert_eq!(exc.top().unwrap().frames.len(), 2);
        assert_eq!(r.minecraft_version.as_ref().unwrap().value, "1.20.4");
        assert_eq!(
            r.java_version.as_ref().unwrap().value,
            "17.0.9, Eclipse Adoptium"
        );
        let mem = r.memory.unwrap();
        assert_eq!(mem.free_bytes, 104_857_600);
        assert_eq!(mem.max_bytes, 4_294_967_296);
        assert_eq!(r.plugins, vec!["LuckPerms", "Foo"]);
        assert!(r.suspected_mods.is_empty());
        assert!(r.server_brand.as_ref().unwrap().value.starts_with("Paper"));
        let entity = r.section("Entity being ticked").unwrap();
        assert!(
            entity
                .detail("Entity Type")
                .unwrap()
                .value
                .starts_with("minecraft:zombie")
        );
    }

    #[test]
    fn truncated_report_does_not_panic() {
        let r = parse_crash_report(
            &lines("---- Minecraft Crash Report ----\nTime: x\nDescr"),
            64,
        );
        assert!(r.description.is_none());
        assert!(r.exception.is_none());
        let r = parse_crash_report(&[], 64);
        assert_eq!(r.header_line, 0);
    }
}
