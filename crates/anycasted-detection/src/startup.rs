//! Startup failures and configuration problems.

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{
    Category, Classification, ExceptionChain, LogEvent, RuleMeta, Severity, ThrownException,
};
use regex::Regex;

use crate::plugins::leading_plugin_tag;
use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

/// Id of the startup-incomplete rule (evaluated by the engine at end of input).
pub const STARTUP_INCOMPLETE_ID: &str = "STARTUP-INCOMPLETE";

static CLASS_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"class file version (\d{2})(?:\.\d+)?\), this version of the Java Runtime only recognizes class file versions up to (\d{2})")
        .expect("valid regex")
});
static PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:port|:)\s?(\d{2,5})\b").expect("valid regex"));
static YML_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)([\w./\\-]+\.ya?ml)").expect("valid regex"));
static YAML_POSITION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"line (\d+), column (\d+)").expect("valid regex"));

fn port_bind_meta() -> Arc<RuleMeta> {
    RuleMeta::new("STARTUP-PORT-BIND", Category::Startup, Severity::Critical)
        .title("Failed to bind to network port")
        .description("The server could not listen on its configured address/port: another process (often a previous instance) holds the port, or the configured IP is not assigned to this machine.")
        .evidence("`FAILED TO BIND TO PORT`, `Can't bind to`, or a `java.net.BindException`/`Address already in use` exception.")
        .user_title("Port {port|the server's port} is already in use")
        .explain("The server couldn't open port {port|its network port}, so nobody can connect to it. Usually another copy of the server is still running (it didn't shut down properly), or another program is using the same port.")
        .fix(&[
            "Make sure the server isn't already running: stop every copy, wait a few seconds, then start it once.",
            "On a hosting panel, use the port your host assigned and restart the server from the panel (this clears leftover processes).",
            "In server.properties, leave server-ip empty unless your host tells you otherwise[[, and check that server-port is {port}]].",
        ])
        .shared()
}

fn java_version_meta() -> Arc<RuleMeta> {
    RuleMeta::new("STARTUP-JAVA-VERSION", Category::Startup, Severity::Critical)
        .title("Incompatible Java version")
        .description("Code was compiled for a newer Java version than the one running the server, or the server software rejected the Java version.")
        .evidence("A `java.lang.UnsupportedClassVersionError`, or the server's unsupported-Java message.")
        .user_title("The server is using the wrong Java version")
        .explain("[[Something on this server needs Java {needed_java}, but the server is running Java {running_java}.]] Code made for a newer Java version can't run on an older one. Minecraft 1.20.5 and newer need Java 21; Minecraft 1.18 to 1.20.4 need Java 17.")
        .fix(&[
            "Switch the server to the right Java version (most hosting panels have a \"Java version\" or \"Docker image\" setting).",
            "[[Use Java {needed_java} or newer.]]",
            "If only one plugin causes this, download a version of that plugin that supports your Java version.",
        ])
        .shared()
}

fn config_meta() -> Arc<RuleMeta> {
    RuleMeta::new("CONFIG-INVALID-YAML", Category::Configuration, Severity::Error)
        .title("Invalid YAML configuration")
        .description("A YAML configuration file could not be parsed; the owning component falls back to defaults, refuses to start, or may overwrite the file.")
        .evidence("An `InvalidConfigurationException` / SnakeYAML parser exception, or `Cannot load <file>.yml`.")
        .user_title("A config file has a formatting mistake[[: {file}]]")
        .explain("{file|A config file} can't be read because of a formatting mistake[[ around line {config_line}]]. {plugin|The plugin that owns it} will use default settings, refuse to start, or may overwrite the file.")
        .fix(&[
            "Open {file|the config file}[[ and go to line {config_line}]]. The mistake is usually on that line or just above it.",
            "Fix the formatting: indent with spaces (never tabs), keep the same indentation for items at the same level, and wrap text that has special characters (colons, #, & or quotes) in quotes.",
            "Paste the file into a YAML checker (for example yamllint.com) to see the exact problem.",
            "Or restore the file from a backup, or delete it so {plugin|the plugin} creates a fresh default.",
        ])
        .shared()
}

fn port_from_text(text: &str) -> Option<Extraction> {
    let port = PORT.captures_iter(text).last()?.get(1)?.as_str().to_owned();
    Some(
        Extraction {
            detail: Some(format!("port {port}")),
            ..Extraction::default()
        }
        .var("port", port),
    )
}

fn bind_from_exception(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    exc.message.as_deref().and_then(port_from_text)
}

fn class_version(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    let msg = exc.message.as_deref()?;
    let c = CLASS_VERSION.captures(msg)?;
    let needed: u32 = c[1].parse().ok()?;
    let supported: u32 = c[2].parse().ok()?;
    let (needed, supported) = (needed.checked_sub(44)?, supported.checked_sub(44)?);
    let class = msg
        .split_whitespace()
        .next()
        .unwrap_or("")
        .replace('/', ".");
    Some(
        Extraction {
            headline: Some(format!("requires Java {needed}, running Java {supported}")),
            detail: Some(format!(
                "{class} requires Java {needed}; the running JVM supports up to Java {supported}"
            )),
            group: Some(format!("{needed}|{supported}")),
            ..Extraction::default()
        }
        .var("needed_java", needed.to_string())
        .var("running_java", supported.to_string()),
    )
}

fn yml_path(text: &str) -> Option<Extraction> {
    let path = YML_PATH.captures(text)?.get(1)?.as_str().to_owned();
    let mut e = Extraction {
        headline: Some(path.clone()),
        detail: Some(path.clone()),
        group: Some(path.clone()),
        ..Extraction::default()
    };
    // `[ChatControl] Could not load config.yml` → plugins/ChatControl/config.yml
    let file = match leading_plugin_tag(text) {
        Some(tag) if !path.contains(['/', '\\']) => {
            e.plugin = Some(tag.to_owned());
            format!("plugins/{tag}/{path}")
        }
        _ => path,
    };
    Some(e.var("file", file))
}

/// Adds the line/column SnakeYAML prints below the error.
fn yaml_position(event: &LogEvent, extraction: &mut Extraction) {
    let found = event
        .lines
        .iter()
        .find_map(|l| YAML_POSITION.captures(&l.text));
    if let Some(c) = found {
        extraction.vars.push(("config_line", c[1].to_owned()));
        extraction.vars.push(("config_column", c[2].to_owned()));
    }
}

/// Exception rules.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(port_bind_meta(), &["java.net.BindException", "NativeIoException", "java.io.IOException"])
            .message_any(&["address already in use", "cannot assign requested address", "bind(..) failed"])
            .priority(40)
            .extract(bind_from_exception),
        ExceptionRule::new(java_version_meta(), &["java.lang.UnsupportedClassVersionError"])
            .priority(40)
            .extract(class_version),
        ExceptionRule::new(
            config_meta(),
            &[
                "org.bukkit.configuration.InvalidConfigurationException",
                "org.yaml.snakeyaml.scanner.ScannerException",
                "org.yaml.snakeyaml.parser.ParserException",
                "org.yaml.snakeyaml.error.YAMLException",
                "org.yaml.snakeyaml.error.MarkedYAMLException",
                "org.yaml.snakeyaml.constructor.ConstructorException",
                "org.spongepowered.configurate.serialize.SerializationException",
                "org.spongepowered.configurate.ConfigurateException",
            ],
        )
        .priority(20),
        ExceptionRule::new(
            RuleMeta::new("CONFIG-INVALID-JSON", Category::Configuration, Severity::Error)
                .title("Invalid JSON data file")
                .description("A JSON file could not be parsed; commonly a corrupted ops.json, whitelist.json, banned-players.json, usercache.json or plugin data file truncated by an unclean shutdown or full disk.")
                .evidence("A Gson `JsonSyntaxException`, `MalformedJsonException` or `JsonParseException` in an exception chain.")
                .user_title("A data file is damaged (invalid JSON)")
                .explain("A JSON file couldn't be read[[ ({exception_message})]]. Common ones are ops.json, whitelist.json, banned-players.json, usercache.json or a plugin's data file. They get damaged when the server is killed while saving, or when the disk is full.")
                .fix(&[
                    "Find the file mentioned near this error and check it with a JSON validator (for example jsonlint.com).",
                    "Restore the file from a backup. usercache.json can simply be deleted; the server recreates it.",
                    "Check that the disk isn't full.",
                ])
                .shared(),
            &[
                "com.google.gson.JsonSyntaxException",
                "com.google.gson.stream.MalformedJsonException",
                "com.google.gson.JsonParseException",
            ],
        )
        .priority(20),
    ]
}

/// Text rules.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(port_bind_meta(), &["failed to bind to port", "can't bind to ", "could not bind to "])
            .extract(port_from_text)
            .boxed(),
        TextRule::new(java_version_meta(), &["unsupported java detected", "requires running the server with java", "this version of minecraft requires java"])
            .boxed(),
        TextRule::new(
            RuleMeta::new("STARTUP-EULA", Category::Startup, Severity::Critical)
                .title("Minecraft EULA not accepted")
                .description("The server refuses to start until the Minecraft EULA is accepted in eula.txt.")
                .evidence("The server message `You need to agree to the EULA in order to run the server`.")
                .user_title("The Minecraft EULA hasn't been accepted")
                .explain("Minecraft servers won't start until you accept Mojang's End User License Agreement (EULA).")
                .fix(&[
                    "Open eula.txt in the server folder.",
                    "Read the EULA at https://aka.ms/MinecraftEULA, then change eula=false to eula=true.",
                    "Start the server again.",
                ])
                .shared(),
            &["you need to agree to the eula", "failed to load eula.txt"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("STARTUP-FAILED", Category::Startup, Severity::Critical)
                .title("Server failed to start")
                .description("The server reported that it could not start or initialize.")
                .evidence("A server message such as `Failed to start the minecraft server` or `Failed to initialize server`.")
                .user_title("The server failed to start")
                .explain("The server stopped during startup[[: {error_hint}]]. The reason is usually an error printed just before this message; see the other problems in this report.")
                .fix(&[
                    "Fix the other problems in this report that happened during startup, starting with the first one.",
                    "Start the server again and wait for the \"Done\" message.",
                ])
                .context("Because of this, the server failed to start.")
                .shared(),
            &["failed to start the minecraft server", "failed to initialize server", "failed to initialize the server", "error starting the proxy", "couldn't start the server"],
        )
        .boxed(),
        TextRule::new(config_meta(), &["cannot load ", "could not load ", "failed to load ", "error loading "])
            .and_all(&[".yml"])
            .extract(yml_path)
            .enrich(yaml_position)
            .boxed(),
        TextRule::new(
            RuleMeta::new("CONFIG-SERVER-PROPERTIES", Category::Configuration, Severity::Error)
                .title("server.properties could not be loaded")
                .description("The server could not read server.properties and is running with default settings.")
                .evidence("The server message `Failed to load properties from file: server.properties`.")
                .user_title("server.properties couldn't be read")
                .explain("The server couldn't read server.properties, so it's running with default settings. The port, world name, game mode and other settings may not be what you configured.")
                .fix(&[
                    "Check that server.properties exists in the server folder and that the server is allowed to read it.",
                    "Open it and check that every line looks like key=value (no stray characters), and save it as UTF-8.",
                    "Restart the server.",
                ])
                .shared(),
            &["failed to load properties from file"],
        )
        .boxed(),
    ]
}

/// Metadata of the end-of-input startup check (see `STARTUP_INCOMPLETE_ID`).
pub fn startup_incomplete_meta() -> Arc<RuleMeta> {
    RuleMeta::new(STARTUP_INCOMPLETE_ID, Category::Startup, Severity::Warning)
        .title("Startup did not complete in this log")
        .description("The log contains the beginning of a server startup but no completion message (`Done (...)!`), and errors were logged after startup began. The log could also simply end early.")
        .evidence("A startup marker, no `Done (...)!` afterwards, and at least one error-level finding after the startup marker.")
        .user_title("The server never finished starting")
        .explain("The log shows the server starting, but never the \"Done\" message that means it's ready, and errors were logged during startup. The server probably failed to start. (If the log was copied while the server was still starting, this can be a false alarm.)")
        .fix(&[
            "Fix the first error that appeared during startup (listed in this report).",
            "Start the server again and wait for the \"Done (...)! For help, type help\" message.",
        ])
        .confidence(0.6)
        .classification(Classification::LikelyContributing)
        .shared()
}
