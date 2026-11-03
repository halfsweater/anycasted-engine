//! Regression tests for real-world-style scenarios (`tests/fixtures/scenarios`).
//!
//! Each scenario pins the exact set of problems reported and the plain-language title a
//! server owner sees, so wording or detection regressions are caught.

mod common;

use anycasted_engine::core::models::{Report, Severity};
use common::*;

fn scenario(name: &str) -> Report {
    analyze(&format!("scenarios/{name}"))
}

/// Asserts the exact (rule id, title) pairs, in report order.
fn expect(report: &Report, expected: &[(&str, &str)]) {
    let actual: Vec<(&str, &str)> = report
        .findings
        .iter()
        .map(|f| (f.rule_id.as_str(), f.title.as_str()))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn s01_missing_dependency() {
    let r = scenario("01-paper-missing-dependency.log");
    expect(
        &r,
        &[(
            "PLUGIN-MISSING-DEPENDENCY",
            "MyWarps needs Vault to be installed",
        )],
    );
    assert!(r.findings[0].recommendations[0].starts_with("Download Vault"));
}

#[test]
fn s02_vault_chat_provider() {
    let r = scenario("02-paper-nullpointer.log");
    expect(
        &r,
        &[(
            "PLUGIN-VAULT-SERVICE-MISSING",
            "WelcomePlus needs a Vault chat provider",
        )],
    );
    let f = &r.findings[0];
    assert!(f.explanation.contains("It happened when a player joined."));
    assert!(f.recommendations.iter().any(|s| s.contains("LuckPerms")));
}

#[test]
fn s03_plugin_does_not_support_version() {
    let r = scenario("03-paper-invalid-plugin-version.log");
    expect(
        &r,
        &[(
            "PLUGIN-UNSUPPORTED-SERVER-VERSION",
            "OldCombat doesn't support your server version",
        )],
    );
    assert_eq!(
        r.findings[0].occurrences, 1,
        "the follow-up 'Disabling' line is not a second problem"
    );
}

#[test]
fn s04_proxy_backend_timeout() {
    let r = scenario("04-velocity-forwarding-secret.log");
    expect(
        &r,
        &[(
            "NET-TIMEOUT",
            "Connection to 10.0.0.12:25566 timed out (backend server 'lobby')",
        )],
    );
    assert_eq!(r.findings[0].severity, Severity::Error);
}

#[test]
fn s05_modern_forwarding() {
    let r = scenario("05-velocity-modern-forwarding.log");
    expect(
        &r,
        &[(
            "NET-PROXY-FORWARDING",
            "The proxy and the backend server 'survival' disagree about player forwarding",
        )],
    );
    assert!(
        r.findings[0]
            .recommendations
            .iter()
            .any(|s| s.contains("paper-global.yml"))
    );
}

#[test]
fn s06_out_of_memory_crash() {
    let r = scenario("06-java-out-of-memory.log");
    expect(
        &r,
        &[
            ("MEM-HEAP-EXHAUSTED", "The server ran out of memory"),
            (
                "CRASH-REPORT-WRITTEN",
                "A crash report was saved: crash-2026-11-03_03.17.44-server.txt",
            ),
        ],
    );
    assert!(
        r.findings[0]
            .explanation
            .contains("This error crashed the server.")
    );
    assert!(
        r.findings[1].recommendations[0]
            .contains("./crash-reports/crash-2026-11-03_03.17.44-server.txt")
    );
}

#[test]
fn s07_database_pool() {
    let r = scenario("07-database-pool-exhausted.log");
    expect(
        &r,
        &[
            ("DB-UNREACHABLE", "Ranks can't connect to its database"),
            ("PLUGIN-DATA-SAVE-FAILED", "Ranks couldn't save its data"),
        ],
    );
    assert!(
        r.findings[0].related.contains(&r.findings[1].id),
        "same plugin → related"
    );
}

#[test]
fn s08_class_not_found() {
    let r = scenario("08-plugin-classnotfound.log");
    expect(
        &r,
        &[(
            "JAVA-CLASS-NOT-FOUND",
            "ScoreboardX can't find something it needs",
        )],
    );
    assert!(
        r.findings[0]
            .explanation
            .contains("com.example.api.PlaceholderBridge")
    );
    assert!(
        r.findings[0]
            .explanation
            .contains("ScoreboardX is now disabled")
    );
}

#[test]
fn s09_corrupted_chunk() {
    let r = scenario("09-world-chunk-error.log");
    expect(
        &r,
        &[(
            "RESOURCE-CHUNK-LOAD-FAILED",
            "Part of the world is damaged: chunk 12, -8 in 'survival'",
        )],
    );
    let f = &r.findings[0];
    assert_eq!(f.occurrences, 2);
    assert!(
        f.recommendations
            .iter()
            .any(|s| s.contains("region/r.0.-1.mca"))
    );
}

#[test]
fn s10_lag_and_tps() {
    let r = scenario("10-tick-lag.log");
    expect(
        &r,
        &[(
            "PERF-SERVER-LAG",
            "The server is lagging (TPS dropped to 8.7)",
        )],
    );
    assert_eq!(r.findings[0].occurrences, 3);
    assert_eq!(
        r.findings[0].subject.plugin, None,
        "spark only reported the TPS"
    );
}

#[test]
fn s11_port_in_use() {
    let r = scenario("11-port-in-use.log");
    expect(
        &r,
        &[
            ("STARTUP-PORT-BIND", "Port 25565 is already in use"),
            ("STARTUP-INCOMPLETE", "The server never finished starting"),
        ],
    );
}

#[test]
fn s12_yaml_config() {
    let r = scenario("12-plugin-config-parse.log");
    expect(
        &r,
        &[(
            "CONFIG-INVALID-YAML",
            "A config file has a formatting mistake: plugins/ChatControl/config.yml",
        )],
    );
    assert!(r.findings[0].recommendations[0].contains("go to line 14"));
}

#[test]
fn s15_recovered_database() {
    let r = scenario("15-contradictory-signal.log");
    expect(
        &r,
        &[(
            "DB-ACCESS-DENIED",
            "ExamplePlugin can't log in to its database",
        )],
    );
    let f = &r.findings[0];
    assert_eq!(
        f.severity,
        Severity::Warning,
        "lowered from error because it recovered"
    );
    assert_eq!(f.recovered.as_ref().map(|e| e.line), Some(4));
    assert!(
        f.explanation
            .contains("for user 'mc_user' connecting from 10.0.0.5")
    );
}

#[test]
fn user_facing_text_is_fully_rendered() {
    let names = std::fs::read_dir(fixture("scenarios"))
        .unwrap()
        .map(|e| format!("scenarios/{}", e.unwrap().file_name().to_string_lossy()))
        .chain(
            [
                "paper_plugin_errors.log",
                "paper_oom.log",
                "purpur_server.log",
                "velocity_proxy.log",
                "vanilla_bind_failure.log",
                "spigot_legacy.log",
                "crash-2024-04-21_18.03.11-server.txt",
                "crash-watchdog-server.txt",
            ]
            .map(String::from),
        );
    for name in names {
        let r = analyze(&name);
        for f in &r.findings {
            for text in [&f.title, &f.explanation]
                .into_iter()
                .chain(&f.recommendations)
            {
                assert!(!text.is_empty(), "{name} {}: empty text", f.rule_id);
                for token in ["{", "}", "[[", "]]", "  "] {
                    assert!(
                        !text.contains(token),
                        "{name} {}: leftover {token:?} in {text:?}",
                        f.rule_id
                    );
                }
            }
        }
    }
}
