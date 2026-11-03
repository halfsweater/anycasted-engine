//! Human-readable terminal rendering of reports.
//!
//! The default view is written for server owners: one block per problem with a plain
//! title, "What happened", numbered "How to fix" steps and the log line it is based on.
//! `verbose` adds the technical details (rule ids, all evidence, implicated components,
//! correlations) for support staff.

use std::fmt::Write as _;

use anycasted_core::models::{
    Classification, Evidence, Finding, FormatConfidence, LogFormat, Report, Severity,
};
use anycasted_core::text::excerpt;

/// Rendering options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextOptions {
    /// Use ANSI colors.
    pub color: bool,
    /// Add technical details.
    pub verbose: bool,
}

/// Maximum width of wrapped paragraphs.
const WIDTH: usize = 92;

struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn accent(&self, s: &str) -> String {
        self.paint("1;36", s)
    }
    fn good(&self, s: &str) -> String {
        self.paint("1;32", s)
    }
    fn severity(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::Critical => "1;31",
            Severity::Error => "31",
            Severity::Warning => "33",
            Severity::Info => "34",
        };
        self.paint(code, s)
    }
}

/// Formats an integer with thousands separators.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Word-wraps `text` to `WIDTH`, prefixing every line with `indent`.
fn wrap(text: &str, indent: &str) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.chars().count() > WIDTH {
            let _ = writeln!(out, "{indent}{line}");
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        let _ = writeln!(out, "{indent}{line}");
    }
    out
}

/// Wraps a numbered step with a hanging indent.
fn wrap_step(n: usize, text: &str, indent: &str) -> String {
    let label = format!("{n}. ");
    let hanging = format!("{indent}{}", " ".repeat(label.len()));
    let wrapped = wrap(text, &hanging);
    wrapped.replacen(&hanging, &format!("{indent}{label}"), 1)
}

/// Wraps a bullet with a hanging indent.
fn wrap_bullet(text: &str) -> String {
    wrap(text, "      ").replacen("      ", "    • ", 1)
}

/// The Anycasted banner.
pub fn banner(options: TextOptions) -> String {
    let st = Style {
        color: options.color,
    };
    format!(
        "\n  {} {}  {}\n  {}\n",
        st.accent("▲"),
        st.accent("ANYCASTED"),
        st.dim(&format!(
            "Diagnostics Engine v{}",
            anycasted_core::ENGINE_VERSION
        )),
        st.dim(&"─".repeat(44)),
    )
}

/// Renders the report body.
pub fn render(report: &Report, options: TextOptions) -> String {
    let st = Style {
        color: options.color,
    };
    let mut out = String::new();
    render_overview(report, &st, options.verbose, &mut out);

    if report.findings.is_empty() {
        let _ = writeln!(out, "\n  {}", st.good("✔ No problems found in this file."));
        if !report.input.complete || report.input.lines_processed == 0 {
            let _ = writeln!(
                out,
                "  {}",
                st.dim("(See the notes below: the file may be empty or incomplete.)")
            );
        }
    }
    for finding in &report.findings {
        render_finding(finding, &st, options.verbose, &mut out);
    }
    if options.verbose && !report.correlations.is_empty() {
        let _ = writeln!(out, "\n  {}", st.bold("Related problems"));
        for c in &report.correlations {
            let _ = writeln!(
                out,
                "  {} {} {}",
                st.dim("•"),
                st.bold(&c.findings.join(", ")),
                st.dim(&format!("[{}]", c.kind.as_str()))
            );
            out.push_str(&wrap(&c.description, "      "));
        }
    }
    if !report.input.warnings.is_empty() {
        let _ = writeln!(
            out,
            "\n  {}",
            st.severity(Severity::Warning, "Notes about this file")
        );
        for w in &report.input.warnings {
            out.push_str(&wrap_bullet(w));
        }
    }
    out
}

fn format_label(report: &Report) -> String {
    let input = &report.input;
    match (input.format, input.format_confidence) {
        (LogFormat::GenericMinecraft, _) => {
            "Minecraft server log (server software not identified)".into()
        }
        (LogFormat::Unknown, _) => "Not recognized as a Minecraft log".into(),
        (LogFormat::CrashReport, _) => "Minecraft crash report".into(),
        (f, FormatConfidence::High) => format!("{f} log"),
        (f, _) => format!("{f} log (probably)"),
    }
}

fn render_overview(report: &Report, st: &Style, verbose: bool, out: &mut String) {
    let input = &report.input;
    let row = |out: &mut String, label: &str, value: String| {
        let _ = writeln!(out, "  {}  {value}", st.dim(&format!("{label:<8}")));
    };
    let compressed = if input.compression == "none" {
        String::new()
    } else {
        st.dim(" (compressed)")
    };
    row(
        out,
        "File",
        format!("{}{compressed}", st.bold(&input.filename)),
    );
    row(out, "Type", format_label(report));

    if let Some(server) = &report.server {
        let mut parts = Vec::new();
        if let Some(sw) = &server.software {
            parts.push(
                format!(
                    "{} {}",
                    sw.value,
                    server.software_version.as_deref().unwrap_or("")
                )
                .trim_end()
                .to_owned(),
            );
        }
        if let Some(mc) = &server.minecraft_version {
            parts.push(format!("Minecraft {}", mc.value));
        }
        if let Some(java) = &server.java_version {
            parts.push(
                java.value
                    .split(" (")
                    .next()
                    .unwrap_or(&java.value)
                    .to_owned(),
            );
        }
        if !server.plugins.is_empty() {
            parts.push(format!("{} plugins", server.plugins.len()));
        }
        if !parts.is_empty() {
            row(out, "Server", parts.join(" · "));
        }
        match (server.startup_completed, server.startup_seconds) {
            (Some(true), Some(s)) => row(out, "Startup", format!("finished in {s:.1} s")),
            (Some(true), None) => row(out, "Startup", "finished".into()),
            (Some(false), _) => row(
                out,
                "Startup",
                st.severity(Severity::Warning, "never finished in this log"),
            ),
            (None, _) => {}
        }
    }
    if let Some(crash) = &report.crash_report {
        let mut parts = Vec::new();
        if let Some(mc) = &crash.minecraft_version {
            parts.push(format!("Minecraft {}", mc.value));
        }
        if let Some(j) = &crash.java_version {
            parts.push(format!(
                "Java {}",
                j.value.split(',').next().unwrap_or(&j.value)
            ));
        }
        if !parts.is_empty() {
            row(out, "Server", parts.join(" · "));
        }
        if let Some(d) = &crash.description {
            row(out, "Crash", st.bold(&d.value));
        }
    }
    let mut checked = format!("{} lines", thousands(input.lines_processed));
    if verbose {
        checked.push_str(&format!(
            " · {} log entries · {} unstructured lines",
            thousands(input.events_parsed),
            thousands(input.unstructured_lines)
        ));
    }
    if !input.complete {
        checked.push_str(&format!(
            " · {}",
            st.severity(Severity::Warning, "only part of the file could be read")
        ));
    }
    row(out, "Checked", checked);

    let s = &report.summary;
    let mut parts = Vec::new();
    for (n, sev, one, many) in [
        (s.critical, Severity::Critical, "critical", "critical"),
        (s.error, Severity::Error, "error", "errors"),
        (s.warning, Severity::Warning, "warning", "warnings"),
        (s.info, Severity::Info, "note", "notes"),
    ] {
        if n > 0 {
            parts.push(st.severity(sev, &format!("{n} {}", if n == 1 { one } else { many })));
        }
    }
    let result = if parts.is_empty() {
        st.good("no problems found")
    } else {
        let total = s.total_findings;
        format!(
            "{} {} found: {}",
            total,
            if total == 1 { "problem" } else { "problems" },
            parts.join(" · ")
        )
    };
    row(out, "Result", result);
}

fn badge(st: &Style, severity: Severity) -> String {
    let (icon, label) = match severity {
        Severity::Critical => ("✖", "CRITICAL"),
        Severity::Error => ("✖", "ERROR"),
        Severity::Warning => ("⚠", "WARNING"),
        Severity::Info => ("ℹ", "NOTE"),
    };
    st.severity(severity, &format!("{icon} {label}"))
}

/// The most informative evidence line to show users.
fn key_evidence(f: &Finding) -> Option<&Evidence> {
    use anycasted_core::models::EvidenceRole::{Exception, Match, RootCause};
    f.evidence
        .iter()
        .find(|e| e.role == Match)
        .or_else(|| {
            f.evidence
                .iter()
                .find(|e| matches!(e.role, Exception | RootCause))
        })
        .or_else(|| f.evidence.first())
}

fn render_finding(f: &Finding, st: &Style, verbose: bool, out: &mut String) {
    let _ = writeln!(
        out,
        "\n  {}  {}  {}",
        badge(st, f.severity),
        st.bold(&f.title),
        st.dim(&format!("[{}]", f.id))
    );

    let _ = writeln!(out, "\n    {}", st.bold("What happened"));
    out.push_str(&wrap(&f.explanation, "      "));

    if !f.recommendations.is_empty() {
        let _ = writeln!(out, "\n    {}", st.bold("How to fix"));
        for (i, step) in f.recommendations.iter().enumerate() {
            out.push_str(&wrap_step(i + 1, step, "      "));
        }
    }

    let mut facts = Vec::new();
    facts.push(if f.occurrences == 1 {
        format!("Seen once (line {})", f.first_seen.line)
    } else {
        format!(
            "Seen {}× (lines {}–{})",
            thousands(f.occurrences),
            f.first_seen.line,
            f.last_seen.line
        )
    });
    facts.push(format!("confidence: {}", f.confidence_label.as_str()));
    match f.classification {
        Classification::Observed => {}
        Classification::LikelyContributing => {
            facts.push("likely contributed, not confirmed".into())
        }
        Classification::Hypothesis => facts.push("unconfirmed guess".into()),
    }
    let _ = writeln!(out, "\n    {}", st.dim(&facts.join(" · ")));
    if let Some(r) = &f.recovered {
        let _ = writeln!(
            out,
            "    {} {}",
            st.good("✔ Recovered at line"),
            st.good(&r.line.to_string())
        );
    }
    if !verbose {
        if let Some(e) = key_evidence(f) {
            let _ = writeln!(
                out,
                "    {} {}",
                st.dim(&format!("Log line {}:", e.line)),
                excerpt(e.text.trim(), 110)
            );
        }
        return;
    }
    render_technical(f, st, out);
}

fn render_technical(f: &Finding, st: &Style, out: &mut String) {
    let _ = writeln!(out, "\n    {}", st.bold("Technical details"));
    let _ = writeln!(
        out,
        "      {}",
        st.dim(&format!(
            "{} · {} · {} · confidence {:.2}",
            f.rule_id, f.category, f.technical_title, f.confidence
        ))
    );
    out.push_str(&st.dim(&wrap(&f.description, "      ")));
    if let Some(p) = &f.subject.plugin {
        let _ = writeln!(out, "      plugin (named by the log): {p}");
    }
    if let Some(c) = &f.subject.exception_class {
        let _ = writeln!(out, "      exception: {c}");
    }
    if !f.implicated.is_empty() {
        let names: Vec<String> = f
            .implicated
            .iter()
            .map(|i| {
                let loaded = if i.seen_loading == Some(false) {
                    ", not loaded"
                } else {
                    ""
                };
                let kind = match i.classification {
                    Classification::Observed => "named by the log",
                    Classification::LikelyContributing => "likely",
                    Classification::Hypothesis => "possible",
                };
                format!("{} ({kind}{loaded})", i.name)
            })
            .collect();
        let _ = writeln!(out, "      involved: {}", names.join(", "));
    }
    for e in &f.evidence {
        let _ = writeln!(
            out,
            "      {} {}",
            st.dim(&format!("│ {:>6}", e.line)),
            excerpt(&e.text, 400)
        );
    }
    if let Some(r) = &f.recovered {
        let _ = writeln!(
            out,
            "      {} {}",
            st.dim(&format!("│ {:>6}", r.line)),
            excerpt(&r.text, 400)
        );
    }
    for n in &f.notes {
        let _ = writeln!(out, "      {} {n}", st.dim("note:"));
    }
    if !f.related.is_empty() {
        let _ = writeln!(out, "      {} {}", st.dim("related:"), f.related.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_separator() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(18_420), "18,420");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn wrapping() {
        let text = "one two three four five six seven eight nine ten ".repeat(5);
        for line in wrap(&text, "    ").lines() {
            assert!(line.chars().count() <= WIDTH);
        }
        let step = wrap_step(1, &text, "  ");
        assert!(step.starts_with("  1. one"));
        assert!(step.lines().nth(1).unwrap().starts_with("     "));
    }
}
