//! Tick lag, TPS and watchdog detection.

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{Category, RuleMeta, Severity};
use regex::Regex;

use crate::rule::{Extraction, LogRule, TextRule};

static BEHIND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)running (\d+)ms or (\d+) ticks behind").expect("valid regex")
});
static TPS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)tps(?: from last 1m, 5m, 15m)?:\s*\*?(\d+(?:\.\d+)?)").expect("valid regex")
});
static NOT_RESPONDED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)not responded for (\d+) seconds").expect("valid regex"));

/// TPS below this is reported.
const LOW_TPS: f64 = 18.0;

const SPARK: &str = "Install the spark plugin and run `/spark profiler start --timeout 120` while the lag is happening; the report shows which plugin, mob or area is using the time.";
const REDUCE: &str = "Lower view-distance and simulation-distance in server.properties, and limit large farms, dropped items and mob counts.";
const CPU: &str = "Check that the server has enough CPU: on shared hosting, other servers on the same machine may be competing for it.";

fn behind(text: &str) -> Option<Extraction> {
    let c = BEHIND.captures(text)?;
    Some(
        Extraction {
            notes: vec![format!("Reported lag: {} ms ({} ticks).", &c[1], &c[2])],
            ..Extraction::default()
        }
        .var("lag_ms", c[1].to_owned())
        .var("lag_ticks", c[2].to_owned()),
    )
}

fn low_tps(text: &str) -> Option<Extraction> {
    let raw = TPS.captures(text)?.get(1)?.as_str();
    let tps: f64 = raw.parse().ok()?;
    (tps < LOW_TPS).then(|| Extraction::default().var("tps", raw.to_owned()))
}

fn not_responded(text: &str) -> Option<Extraction> {
    let seconds = NOT_RESPONDED.captures(text)?.get(1)?.as_str().to_owned();
    Some(Extraction::default().var("seconds", seconds))
}

fn lag_meta() -> Arc<RuleMeta> {
    RuleMeta::new("PERF-SERVER-LAG", Category::Performance, Severity::Warning)
        .title("Server tick loop falling behind / low TPS")
        .description("The main thread could not complete ticks within 50 ms (`Can't keep up!`) or a TPS report shows fewer than 18 ticks per second. Occasional occurrences during startup or world generation are normal.")
        .evidence("The server message `Can't keep up! Is the server overloaded?`, or a TPS report line (spark, /tps) with a value below 18.")
        .user_title("The server is lagging[[ (TPS dropped to {tps})]]")
        .explain("The server can't keep up with the game[[: it reported running {lag_ms} ms ({lag_ticks} ticks) behind]][[, and its TPS dropped to {tps} (a healthy server runs at 20)]]. Players see lag such as rubber-banding, slow block breaking and delayed mobs. A little of this while the server starts is normal; regular lag means the server is overloaded.")
        .fix(&[SPARK, REDUCE, CPU])
        .ignore_logger_tag()
        .shared()
}

/// Text rules.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(lag_meta(), &["can't keep up! is the server overloaded"])
            .extract(behind)
            .boxed(),
        TextRule::new(lag_meta(), &["tps:", "tps from last"])
            .extract_required(low_tps)
            .boxed(),
        TextRule::new(
            RuleMeta::new("PERF-WATCHDOG-STALL", Category::Performance, Severity::Error)
                .title("Main thread stalled (watchdog warning)")
                .description("The watchdog detected that the main server thread has not completed a tick for several seconds and printed a thread dump.")
                .evidence("Paper's watchdog message `The server has not responded for N seconds!`.")
                .user_title("The server froze[[ for {seconds} seconds]]")
                .explain("The server's main thread stopped responding[[ for {seconds} seconds]]. During that time nothing in the game moved. The log includes a \"thread dump\" showing what the server was stuck on.")
                .fix(&[
                    "Look at the \"Server thread\" part of the thread dump below this message: plugin names that appear there show what was running when it froze.",
                    SPARK,
                    "If one plugin keeps appearing in these dumps, update or remove it.",
                ])
                .shared(),
            &["the server has not responded for"],
        )
        .extract(not_responded)
        .boxed(),
        TextRule::new(
            RuleMeta::new("PERF-WATCHDOG-CRASH", Category::Performance, Severity::Critical)
                .title("Server stopped responding (watchdog)")
                .description("The watchdog determined that the main server thread was stuck long enough to consider the server crashed, and dumped threads or forcibly stopped the server.")
                .evidence("`The server has stopped responding!`, `A single server tick took ... seconds` or `Considering it to be crashed`.")
                .user_title("The server froze and was shut down")
                .explain("The server was frozen for so long that its watchdog decided it had crashed and stopped it, so it wouldn't hang forever. Something blocked the main server thread: usually a plugin waiting on a slow website or database, or stuck in a loop.")
                .fix(&[
                    "Read the \"Server thread\" section of the thread dump in the log: plugin names there show what was blocking the server.",
                    "Check the crash-reports folder for a crash report from the same time and analyze it with Anycasted.",
                    SPARK,
                ])
                .shared(),
            &["the server has stopped responding", "a single server tick took", "considering it to be crashed"],
        )
        .boxed(),
    ]
}
