//! Extraction of server facts (versions, plugins, lifecycle markers) from log events.

use std::sync::LazyLock;

use anycasted_core::models::Located;
use anycasted_core::models::{LogEvent, PluginRecord, ServerInfo};
use regex::Regex;

use crate::velocity;

static RUNNING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^This server is running ([A-Za-z][\w-]*) version (\S+)").expect("valid regex")
});
static MC_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Starting minecraft server version (\S+)").expect("valid regex"));
static JAVA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Running Java (\d+) \(([^)]*)\) on (.+)$").expect("valid regex"));
static DONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Done \(([0-9]+[.,]?[0-9]*)s\)!").expect("valid regex"));
static BIND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Starting Minecraft server on (\S+)").expect("valid regex"));
static BUKKIT_PLUGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Loading server plugin ([A-Za-z0-9_.\-]+) v(\S+)").expect("valid regex")
});

const SHUTDOWN_PREFIXES: &[&str] = &["Stopping server", "Stopping the server", "Closing Server"];

fn gated<'a>(text: &'a str, prefix: &str, regex: &Regex) -> Option<regex::Captures<'a>> {
    if text.starts_with(prefix) {
        regex.captures(text)
    } else {
        None
    }
}

/// Signals emitted while profiling that later stages care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleSignal {
    /// Nothing notable.
    None,
    /// Startup began.
    StartupBegan,
    /// Startup completed (`Done (...)!`).
    StartupCompleted,
    /// A shutdown began.
    Shutdown,
}

/// Collects [`ServerInfo`] from a stream of events.
#[derive(Debug)]
pub struct ServerProfiler {
    info: ServerInfo,
    max_plugins: usize,
}

impl ServerProfiler {
    /// Creates a profiler that records at most `max_plugins` plugins.
    pub fn new(max_plugins: usize) -> Self {
        Self {
            info: ServerInfo::default(),
            max_plugins,
        }
    }

    /// Observes one event and reports lifecycle transitions.
    pub fn observe(&mut self, event: &LogEvent) -> LifecycleSignal {
        let Some(header) = &event.header else {
            return LifecycleSignal::None;
        };
        if event.is_user_content() {
            return LifecycleSignal::None;
        }
        let line = event.start_line();
        let message = event.message();
        // Strip a leading `[Tag] ` so `[bootstrap] Running Java ...` and
        // `[Foo] Loading server plugin Foo v1` match.
        let body = header
            .tag
            .as_deref()
            .and_then(|t| {
                message
                    .strip_prefix('[')?
                    .strip_prefix(t)?
                    .strip_prefix("] ")
            })
            .unwrap_or(message);

        // Literal prefix checks gate every regex: almost no line is a lifecycle line.
        if let Some(c) = gated(body, "Starting minecraft server version", &MC_VERSION) {
            self.info
                .minecraft_version
                .get_or_insert(Located::new(c[1].to_owned(), line));
            return self.startup_began(line);
        }
        if let Some(version) = velocity::boot_version(body) {
            self.set_software("Velocity", version, line);
            return self.startup_began(line);
        }
        if let Some(c) = gated(body, "Starting Minecraft server on ", &BIND) {
            self.info
                .bind_address
                .get_or_insert(Located::new(c[1].to_owned(), line));
            return self.startup_began(line);
        }
        if body.starts_with("Loading libraries, please wait") {
            return self.startup_began(line);
        }
        if let Some(c) = gated(body, "This server is running ", &RUNNING) {
            self.set_software(&c[1], &c[2], line);
            return LifecycleSignal::None;
        }
        if let Some(c) = gated(body, "Running Java ", &JAVA) {
            self.info
                .java_version
                .get_or_insert(Located::new(format!("Java {} ({})", &c[1], &c[2]), line));
            self.info
                .operating_system
                .get_or_insert(Located::new(c[3].to_owned(), line));
            return LifecycleSignal::None;
        }
        if let Some(c) = gated(body, "Done (", &DONE) {
            self.info.startup_completed = Some(true);
            self.info.startup_seconds = c[1].replace(',', ".").parse().ok();
            return LifecycleSignal::StartupCompleted;
        }
        if SHUTDOWN_PREFIXES.iter().any(|p| body.starts_with(p))
            || velocity::is_shutdown_marker(body)
        {
            self.info.shutdown_lines.push(line);
            return LifecycleSignal::Shutdown;
        }
        let plugin = gated(body, "Loading server plugin ", &BUKKIT_PLUGIN)
            .map(|c| {
                (
                    c.get(1).map_or("", |m| m.as_str()),
                    c.get(2).map_or("", |m| m.as_str()),
                )
            })
            .or_else(|| velocity::loaded_plugin(body));
        if let Some((name, version)) = plugin {
            self.add_plugin(name, version, line);
        }
        LifecycleSignal::None
    }

    fn startup_began(&mut self, line: u64) -> LifecycleSignal {
        if self.info.startup_started_line.is_none() {
            self.info.startup_started_line = Some(line);
        }
        if self.info.startup_completed.is_none() {
            self.info.startup_completed = Some(false);
        }
        LifecycleSignal::StartupBegan
    }

    fn set_software(&mut self, name: &str, version: &str, line: u64) {
        if self.info.software.is_none() {
            self.info.software = Some(Located::new(name.to_owned(), line));
            self.info.software_version = Some(version.to_owned());
        }
    }

    fn add_plugin(&mut self, name: &str, version: &str, line: u64) {
        if self.info.plugins.len() >= self.max_plugins
            || self
                .info
                .plugins
                .iter()
                .any(|p| p.name.eq_ignore_ascii_case(name))
        {
            return;
        }
        self.info.plugins.push(PluginRecord {
            name: name.to_owned(),
            version: (!version.is_empty()).then(|| version.to_owned()),
            line,
        });
    }

    /// Current view of the collected facts.
    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Whether a plugin with this name (case-insensitive) was seen loading.
    pub fn has_plugin(&self, name: &str) -> bool {
        self.info
            .plugins
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// Consumes the profiler.
    pub fn finish(self) -> ServerInfo {
        self.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventBuilder;
    use anycasted_core::{Limits, models::SourceLine};

    fn profile(text: &str) -> (ServerInfo, Vec<LifecycleSignal>) {
        let mut b = EventBuilder::new(&Limits::default());
        let mut p = ServerProfiler::new(100);
        let mut signals = Vec::new();
        let mut events = Vec::new();
        for (i, l) in text.lines().enumerate() {
            events.extend(b.push(SourceLine {
                number: i as u64 + 1,
                text: l.to_owned(),
            }));
        }
        events.extend(b.finish());
        for e in &events {
            signals.push(p.observe(e));
        }
        (p.finish(), signals)
    }

    #[test]
    fn paper_startup() {
        let (info, signals) = profile(
            "[10:00:00 INFO]: [bootstrap] Running Java 21 (OpenJDK 64-Bit Server VM 21.0.2+13-LTS; Eclipse Adoptium Temurin-21.0.2+13) on Linux 6.1.0 (amd64)\n\
             [10:00:02 INFO]: Starting minecraft server version 1.20.4\n\
             [10:00:02 INFO]: This server is running Paper version 1.20.4-496-master@7ac24a1 (2024-04-21T00:00:00Z) (Implementing API version 1.20.4-R0.1-SNAPSHOT)\n\
             [10:00:03 INFO]: [LuckPerms] Loading server plugin LuckPerms v5.4.102\n\
             [10:00:09 INFO]: Done (7.712s)! For help, type \"help\"\n\
             [11:00:00 INFO]: Stopping the server",
        );
        assert_eq!(info.minecraft_version.unwrap().value, "1.20.4");
        assert_eq!(info.software.unwrap().value, "Paper");
        assert!(info.java_version.unwrap().value.starts_with("Java 21"));
        assert_eq!(info.plugins[0].name, "LuckPerms");
        assert_eq!(info.startup_completed, Some(true));
        assert_eq!(info.startup_seconds, Some(7.712));
        assert_eq!(info.shutdown_lines, vec![6]);
        assert_eq!(signals[5], LifecycleSignal::Shutdown);
    }

    #[test]
    fn velocity_plugins() {
        let (info, _) = profile(
            "[10:00:00 INFO]: Booting up Velocity 3.3.0-SNAPSHOT (git-71746fb2-b416)...\n\
             [10:00:01 INFO]: Loaded plugin luckperms 5.4.102 by Luck",
        );
        assert_eq!(info.software.unwrap().value, "Velocity");
        assert_eq!(info.software_version.as_deref(), Some("3.3.0-SNAPSHOT"));
        assert_eq!(info.plugins[0].name, "luckperms");
        assert_eq!(info.startup_completed, Some(false));
    }
}
