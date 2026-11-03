//! Detection, grouping and correlation tests against realistic fixtures.

mod common;

use anycasted_engine::core::models::{
    Category, Classification, CorrelationKind, HealthStatus, ImplicationBasis, LogFormat, RuleMeta,
    Severity,
};
use anycasted_engine::detection::{RuleSet, TextRule};
use anycasted_engine::{Engine, EngineConfig};
use common::*;

const ALL_FIXTURES: &[&str] = &[
    "paper_clean.log",
    "paper_plugin_errors.log",
    "paper_oom.log",
    "purpur_server.log",
    "velocity_proxy.log",
    "vanilla_bind_failure.log",
    "spigot_legacy.log",
    "unknown_format.txt",
    "empty.log",
    "crash-2024-04-21_18.03.11-server.txt",
    "crash-watchdog-server.txt",
];

#[test]
fn every_fixture_has_verifiable_evidence() {
    for name in ALL_FIXTURES {
        let report = analyze(name); // asserts evidence ↔ input consistency
        assert_eq!(
            report.summary.total_findings,
            report.findings.len(),
            "{name}"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], "2.0.0");
    }
}

// ---------------------------------------------------------------- negative tests

#[test]
fn clean_paper_log_has_no_findings() {
    // Contains chat mentioning exceptions, a /say echo of a plugin failure message,
    // player time-outs and a plugin named ErrorLogger. None of these are problems.
    let report = analyze("paper_clean.log");
    assert!(
        report.findings.is_empty(),
        "unexpected findings: {:?}",
        rule_ids(&report)
    );
    assert_eq!(report.summary.status, HealthStatus::Healthy);
    assert_eq!(report.input.format, LogFormat::Paper);
    let server = report.server.as_ref().unwrap();
    assert_eq!(server.startup_completed, Some(true));
    assert_eq!(server.plugins.len(), 3);
}

#[test]
fn unknown_text_is_not_diagnosed() {
    let report = analyze("unknown_format.txt");
    assert!(report.findings.is_empty());
    assert_eq!(report.input.format, LogFormat::Unknown);
    assert!(report.input.format_uncertain);
}

#[test]
fn chat_messages_never_become_evidence() {
    for name in ["paper_clean.log", "paper_plugin_errors.log"] {
        let report = analyze(name);
        for f in &report.findings {
            for e in &f.evidence {
                assert!(
                    !e.text.contains("<Steve>") && !e.text.contains("<Alex>"),
                    "{name}: chat used as evidence in {}",
                    f.id
                );
            }
        }
    }
}

// ---------------------------------------------------------------- plugins

#[test]
fn plugin_failures_are_attributed_explicitly() {
    let report = analyze("paper_plugin_errors.log");

    let dep = finding(&report, "PLUGIN-MISSING-DEPENDENCY");
    assert_eq!(dep.subject.plugin.as_deref(), Some("EconomyShop"));
    assert_eq!(dep.first_seen.line, 15);
    let vault = &dep.implicated[0];
    assert_eq!(vault.name, "Vault");
    assert_eq!(vault.basis, ImplicationBasis::LogMessage);
    assert_eq!(vault.seen_loading, Some(false));
    assert!(
        dep.notes
            .iter()
            .any(|n| n.contains("Vault was not seen loading"))
    );
    // The load-failure message is merged into the specific reason.
    assert!(findings(&report, "PLUGIN-LOAD-FAILED").is_empty());
    assert_eq!(dep.title, "EconomyShop needs Vault to be installed");
    assert!(dep.explanation.contains("confirms it isn't installed"));
    assert!(dep.recommendations[0].starts_with("Download Vault"));

    // "Error occurred while enabling" is merged into the missing-class diagnosis.
    assert!(findings(&report, "PLUGIN-ENABLE-FAILED").is_empty());

    // The root cause wins over the wrapping NoClassDefFoundError.
    let cnf = finding(&report, "JAVA-CLASS-NOT-FOUND");
    assert!(findings(&report, "JAVA-NO-CLASS-DEF-FOUND").is_empty());
    assert_eq!(cnf.subject.plugin.as_deref(), Some("WelcomePlus"));
    assert_eq!(cnf.first_seen.line, 26);
    assert_eq!(
        cnf.title,
        "WelcomePlus can't find something it needs: PlaceholderAPI"
    );
    assert!(cnf.explanation.contains("WelcomePlus is now disabled"));
    assert!(cnf.recommendations[0].contains("Install PlaceholderAPI"));
    assert!(
        cnf.evidence.iter().any(|e| e.line == 26),
        "context line kept as evidence"
    );
    assert_eq!(
        cnf.subject.detail.as_deref(),
        Some("me.clip.placeholderapi.PlaceholderAPI")
    );
    let papi = cnf
        .implicated
        .iter()
        .find(|i| i.name == "PlaceholderAPI")
        .unwrap();
    assert_eq!(papi.classification, Classification::Hypothesis);
    assert_eq!(papi.basis, ImplicationBasis::ClassPackage);
    assert!(
        cnf.evidence
            .iter()
            .any(|e| e.line == 31 && e.text.starts_with("Caused by:"))
    );
}

#[test]
fn stack_frames_only_produce_hypotheses() {
    let report = analyze("paper_oom.log");
    let oom = finding(&report, "MEM-HEAP-EXHAUSTED");
    let dyn_mapper = oom
        .implicated
        .iter()
        .find(|i| i.name == "DynMapper")
        .unwrap();
    assert_eq!(dyn_mapper.basis, ImplicationBasis::StackFrame);
    assert_eq!(dyn_mapper.classification, Classification::Hypothesis);
    assert_eq!(
        oom.subject.plugin, None,
        "a stack frame must not make a plugin the subject"
    );
    // Server and library jars are never implicated.
    for f in &report.findings {
        for i in &f.implicated {
            let lower = i.name.to_ascii_lowercase();
            assert!(
                !lower.starts_with("paper") && !lower.starts_with("netty"),
                "{} implicated {}",
                f.id,
                i.name
            );
        }
    }
}

#[test]
fn repeated_listener_failures_are_grouped() {
    let report = analyze("paper_plugin_errors.log");
    let event = finding(&report, "PLUGIN-EVENT-EXCEPTION");
    assert_eq!(event.occurrences, 3);
    assert_eq!((event.first_seen.line, event.last_seen.line), (37, 59));
    assert_eq!(event.other_occurrence_lines, vec![48, 59]);
    assert!(event.repetition.is_some());
    // The NullPointerException is a detail of the listener failure, not a second problem.
    assert!(findings(&report, "JAVA-NULL-POINTER").is_empty());
    assert_eq!(
        event.subject.exception_class.as_deref(),
        Some("java.lang.NullPointerException")
    );
    assert_eq!(event.title, "WelcomePlus hit an error when a player joined");
    assert!(
        event
            .explanation
            .contains("a value it needed (`section`) was missing"),
        "{}",
        event.explanation
    );
    assert!(
        event
            .recommendations
            .iter()
            .any(|r| r.contains("`section`"))
    );
    assert!(
        event
            .evidence
            .iter()
            .any(|e| e.text.starts_with("java.lang.NullPointerException"))
    );
}

#[test]
fn async_api_misuse_absorbs_task_context() {
    let report = analyze("paper_plugin_errors.log");
    let f = finding(&report, "PLUGIN-ASYNC-API-ACCESS");
    assert_eq!(f.subject.plugin.as_deref(), Some("TreeFeller"));
    assert!(findings(&report, "JAVA-ILLEGAL-STATE").is_empty());
    assert!(findings(&report, "PLUGIN-TASK-EXCEPTION").is_empty());
    assert!(
        f.explanation.contains("background task run by TreeFeller"),
        "{}",
        f.explanation
    );
}

// ---------------------------------------------------------------- memory & crashes

#[test]
fn out_of_memory_is_critical_and_grouped() {
    let report = analyze("paper_oom.log");
    let oom = finding(&report, "MEM-HEAP-EXHAUSTED");
    assert_eq!(oom.severity, Severity::Critical);
    assert_eq!(oom.occurrences, 3);
    assert_eq!(oom.category, Category::Memory);
    assert_eq!(oom.confidence, 1.0);
    // "Encountered an unexpected exception" becomes part of the memory finding.
    assert!(findings(&report, "CRASH-SERVER-THREAD").is_empty());
    assert!(oom.explanation.ends_with("This error crashed the server."));
    assert_eq!(oom.title, "The server ran out of memory");
    assert!(
        report
            .correlations
            .iter()
            .any(|c| c.kind == CorrelationKind::NearEndOfLog)
    );
    assert_eq!(report.summary.status, HealthStatus::Critical);
}

#[test]
fn crash_report_ticking_entity() {
    let report = analyze("crash-2024-04-21_18.03.11-server.txt");
    assert_eq!(report.input.format, LogFormat::CrashReport);
    let crash = report.crash_report.as_ref().unwrap();
    assert_eq!(crash.minecraft_version.as_ref().unwrap().value, "1.20.4");
    assert_eq!(
        crash.java_version.as_ref().unwrap().value,
        "21.0.2, Eclipse Adoptium"
    );
    assert!(
        crash
            .operating_system
            .as_ref()
            .unwrap()
            .value
            .starts_with("Linux")
    );
    assert_eq!(crash.plugins, vec!["LuckPerms", "PetsPlus"]);
    assert_eq!(crash.exception.as_ref().unwrap().line, 7);
    assert_eq!(crash.memory.unwrap().max_bytes, 4_294_967_296);

    let entity = finding(&report, "CRASH-TICKING-ENTITY");
    assert_eq!(entity.classification, Classification::Observed);
    assert_eq!(
        entity.title,
        "The server crashed because of a broken entity (minecraft:wolf)"
    );
    assert!(
        entity.explanation.contains("at 104.50, 71.00, -233.18"),
        "{}",
        entity.explanation
    );
    assert!(entity.evidence.iter().any(|e| e.line == 25));
    assert!(
        findings(&report, "CRASH-REPORT").is_empty(),
        "generic crash rule must yield to the signature"
    );
    finding(&report, "JAVA-NULL-POINTER");

    let memory = finding(&report, "CRASH-LOW-MEMORY");
    assert_eq!(memory.classification, Classification::LikelyContributing);
    assert!(memory.confidence < 1.0);
    assert!(
        findings(&report, "CRASH-SUSPECTED-MODS").is_empty(),
        "`Suspected Mod: NONE` is not a suspect"
    );
}

#[test]
fn crash_report_watchdog() {
    let report = analyze("crash-watchdog-server.txt");
    finding(&report, "CRASH-WATCHDOG");
    assert!(findings(&report, "JAVA-UNCLASSIFIED-EXCEPTION").is_empty());
    assert!(
        findings(&report, "CRASH-LOW-MEMORY").is_empty(),
        "25% heap use is not low memory"
    );
    assert!(findings(&report, "CRASH-SUSPECTED-MODS").is_empty());
}

// ---------------------------------------------------------------- startup, config, perf

#[test]
fn vanilla_port_bind_failure() {
    let report = analyze("vanilla_bind_failure.log");
    assert_eq!(report.input.format, LogFormat::Vanilla);
    assert!(report.input.format_uncertain);
    let bind = finding(&report, "STARTUP-PORT-BIND");
    assert_eq!(bind.severity, Severity::Critical);
    assert_eq!(
        bind.occurrences, 1,
        "one failure must not be counted per message line"
    );
    let incomplete = finding(&report, "STARTUP-INCOMPLETE");
    assert_eq!(
        incomplete.classification,
        Classification::LikelyContributing
    );
    assert!(incomplete.evidence.iter().any(|e| e.line == 9));
    assert!(
        report
            .correlations
            .iter()
            .any(|c| c.kind == CorrelationKind::PrecededShutdown)
    );
}

#[test]
fn purpur_config_and_performance() {
    let report = analyze("purpur_server.log");
    assert_eq!(report.input.format, LogFormat::Purpur);
    let yaml = finding(&report, "CONFIG-INVALID-YAML");
    assert_eq!(
        yaml.subject.detail.as_deref(),
        Some("plugins/Shop/config.yml")
    );
    assert_eq!(finding(&report, "PERF-SERVER-LAG").occurrences, 2);
    finding(&report, "PERF-WATCHDOG-STALL");
    // The ConcurrentModificationException is a detail of the failing task.
    assert!(findings(&report, "JAVA-CONCURRENT-MODIFICATION").is_empty());
    let task = finding(&report, "PLUGIN-TASK-EXCEPTION");
    assert_eq!(task.subject.plugin.as_deref(), Some("Shop"));
    assert!(
        task.explanation
            .contains("changed the same data at the same time")
    );
    assert_eq!(
        yaml.title,
        "A config file has a formatting mistake: plugins/Shop/config.yml"
    );
}

#[test]
fn legacy_spigot_invalid_plugin_yml() {
    let report = analyze("spigot_legacy.log");
    assert_eq!(report.input.format, LogFormat::Spigot);
    let f = finding(&report, "PLUGIN-INVALID-DESCRIPTION");
    assert_eq!(f.subject.plugin.as_deref(), Some("OldWarps"));
    assert_eq!(
        f.first_seen.timestamp.unwrap().to_string(),
        "2015-06-01 18:00:01"
    );
}

// ---------------------------------------------------------------- networking

#[test]
fn velocity_networking() {
    let report = analyze("velocity_proxy.log");
    assert_eq!(report.input.format, LogFormat::Velocity);
    // "unable to connect to server lobby" is merged into the refused connection.
    assert!(findings(&report, "NET-PROXY-BACKEND-UNREACHABLE").is_empty());
    let refused = finding(&report, "NET-CONNECTION-REFUSED");
    assert_eq!(refused.occurrences, 2);
    assert_eq!(refused.subject.detail.as_deref(), Some("10.0.0.5:25566"));
    assert_eq!(refused.severity, Severity::Error);
    assert_eq!(
        refused.title,
        "Nothing is accepting connections at 10.0.0.5:25566 (backend server 'lobby')"
    );
    assert!(
        refused
            .explanation
            .contains("Players trying to join the backend server 'lobby' couldn't connect.")
    );
    finding(&report, "NET-DNS-FAILURE");
    finding(&report, "NET-PROXY-FORWARDING");
    let dep = finding(&report, "PLUGIN-MISSING-DEPENDENCY");
    assert_eq!(dep.subject.plugin.as_deref(), Some("chatbridge"));
    // A player timing out is not a server networking problem.
    assert!(findings(&report, "NET-TIMEOUT").is_empty());
}

// ---------------------------------------------------------------- repetition

#[test]
fn four_hundred_identical_errors_become_one_finding() {
    let mut log = String::from(
        "[10:00:00] [Server thread/INFO]: Starting minecraft server version 1.20.4\n\
         [10:00:00] [Server thread/INFO]: Done (3.2s)! For help, type \"help\"\n",
    );
    for i in 0..400 {
        let (m, s) = (i / 60, i % 60);
        log.push_str(&format!(
            "[10:{m:02}:{s:02}] [Server thread/WARN]: [Holo] Plugin Holo v1.0 generated an exception while executing task {}\n\
             java.lang.IllegalArgumentException: Invalid sound: entity.foo.bar\n\
             \tat com.example.holo.SoundTask.run(SoundTask.java:{}) ~[Holo-1.0.jar:?]\n\
             \tat org.bukkit.craftbukkit.scheduler.CraftTask.run(CraftTask.java:101) ~[paper-1.20.4.jar:?]\n",
            1000 + i,
            20 + (i % 3) // line numbers vary; signatures must not
        ));
    }
    let path = temp_path("repeated.log");
    std::fs::write(&path, &log).unwrap();
    let report = engine().analyze_path(&path).unwrap();
    assert_evidence_matches_input(&report, log.as_bytes());

    let task = finding(&report, "PLUGIN-TASK-EXCEPTION");
    assert_eq!(task.occurrences, 400);
    assert_eq!(task.first_seen.line, 3);
    assert_eq!(task.last_seen.line, 3 + 399 * 4);
    // The IllegalArgumentException is a detail of the failing task, not a second problem.
    assert!(findings(&report, "JAVA-ILLEGAL-ARGUMENT").is_empty());
    assert!(
        task.explanation.contains("Invalid sound: entity.foo.bar"),
        "{}",
        task.explanation
    );
    let repeated = finding(&report, "PATTERN-REPEATED-ERROR");
    assert_eq!(repeated.related, vec![task.id.clone()]);
    assert_eq!(
        repeated.title,
        "This keeps happening: Holo's background task is failing (400 times)"
    );
    assert_eq!(report.findings.len(), 2, "{:?}", rule_ids(&report));
    let rep = task.repetition.unwrap();
    assert_eq!(rep.span_seconds, Some(399.0));
}

#[test]
fn duplicate_lines_are_counted_not_duplicated() {
    let line = "[10:00:00] [Server thread/WARN]: Can't keep up! Is the server overloaded? Running 2001ms or 40 ticks behind\n";
    let log = line.repeat(5);
    let report = engine()
        .analyze_bytes("dup.log", log.clone().into_bytes())
        .unwrap();
    assert_evidence_matches_input(&report, log.as_bytes());
    let f = finding(&report, "PERF-SERVER-LAG");
    assert_eq!(f.occurrences, 5);
}

// ---------------------------------------------------------------- report & rules

#[test]
fn json_report_shape() {
    let report = analyze("paper_plugin_errors.log");
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(v["engine"]["name"], "Anycasted Diagnostics Engine");
    assert_eq!(v["input"]["format"], "paper");
    assert_eq!(v["input"]["lines_processed"], 79);
    assert!(v["summary"]["error"].as_u64().unwrap() > 0);
    let f = &v["findings"][0];
    for key in [
        "id",
        "rule_id",
        "category",
        "severity",
        "classification",
        "title",
        "description",
        "confidence",
        "occurrences",
        "first_seen",
        "last_seen",
        "evidence",
        "fingerprint",
        "recommendations",
    ] {
        assert!(!f[key].is_null(), "finding lacks {key}");
    }
    assert!(f["evidence"][0]["line"].is_u64());
    // Ordered most severe first.
    let severities: Vec<Severity> = report.findings.iter().map(|f| f.severity).collect();
    assert!(severities.windows(2).all(|w| w[0] >= w[1]));
}

#[test]
fn empty_report_is_valid_json() {
    let report = analyze("empty.log");
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(v["findings"], serde_json::json!([]));
    assert_eq!(v["summary"]["status"], "healthy");
    assert!(v["summary"]["highest_severity"].is_null());
}

#[test]
fn fingerprints_are_stable_across_runs() {
    let a = analyze("paper_plugin_errors.log");
    let b = analyze("paper_plugin_errors.log");
    let fa: Vec<_> = a.findings.iter().map(|f| &f.fingerprint).collect();
    let fb: Vec<_> = b.findings.iter().map(|f| &f.fingerprint).collect();
    assert_eq!(fa, fb);
}

#[test]
fn rule_catalog_is_complete() {
    let catalog = engine().rule_catalog();
    let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
    let total = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), total, "duplicate rule ids");
    for required in [
        "JAVA-NULL-POINTER",
        "JAVA-ILLEGAL-STATE",
        "JAVA-ILLEGAL-ARGUMENT",
        "JAVA-CLASS-NOT-FOUND",
        "JAVA-NO-CLASS-DEF-FOUND",
        "JAVA-NO-SUCH-METHOD",
        "JAVA-NO-SUCH-FIELD",
        "JAVA-CONCURRENT-MODIFICATION",
        "JAVA-STACK-OVERFLOW",
        "MEM-HEAP-EXHAUSTED",
        "MEM-GC-OVERHEAD",
        "MEM-DIRECT-BUFFER",
        "PLUGIN-ENABLE-FAILED",
        "PLUGIN-MISSING-DEPENDENCY",
        "STARTUP-PORT-BIND",
        "CONFIG-INVALID-YAML",
        "NET-CONNECTION-REFUSED",
        "NET-TIMEOUT",
        "NET-DNS-FAILURE",
        "NET-CONNECTION-RESET",
        "NET-PROXY-FORWARDING",
        "SHUTDOWN-EXCEPTION",
        "PATTERN-REPEATED-ERROR",
    ] {
        assert!(ids.contains(&required), "missing {required}");
    }
    for m in &catalog {
        assert!(
            !m.recommendations.is_empty() && !m.evidence_requirement.is_empty(),
            "{} incomplete",
            m.id
        );
    }
}

#[test]
fn custom_rules_extend_the_engine() {
    let meta = RuleMeta::new("CUSTOM-HOST-MAINTENANCE", Category::Startup, Severity::Info)
        .title("Host maintenance notice")
        .description("The hosting panel announced maintenance.")
        .evidence("A line containing `scheduled maintenance`.")
        .user_title("Your host has scheduled maintenance")
        .explain("The hosting panel announced maintenance.")
        .fix(&["Plan around the maintenance window."])
        .shared();
    let rules =
        RuleSet::builtin().with_log_rule(TextRule::new(meta, &["scheduled maintenance"]).boxed());
    let engine = Engine::with_rules(EngineConfig::default(), rules).unwrap();
    let log = "[10:00:00 INFO]: Panel: scheduled maintenance at 02:00 UTC\n";
    let report = engine
        .analyze_bytes("m.log", log.as_bytes().to_vec())
        .unwrap();
    assert_eq!(rule_ids(&report), vec!["CUSTOM-HOST-MAINTENANCE"]);
}
