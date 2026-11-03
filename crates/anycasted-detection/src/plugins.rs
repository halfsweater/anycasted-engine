//! Plugin lifecycle and plugin-reported failures (Bukkit/Paper/Velocity).

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{
    Category, Classification, ExceptionChain, Implication, ImplicationBasis, RuleMeta, Severity,
    ThrownException,
};
use regex::Regex;

use crate::attribution::{is_plugin_tag, plugin_from_jar};
use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

/// Id of the missing-dependency rule.
pub const MISSING_DEPENDENCY_ID: &str = "PLUGIN-MISSING-DEPENDENCY";
/// Id of the unsupported-API rule.
pub const UNSUPPORTED_API_ID: &str = "PLUGIN-UNSUPPORTED-API-VERSION";
/// Id of the invalid-description rule.
pub const INVALID_DESCRIPTION_ID: &str = "PLUGIN-INVALID-DESCRIPTION";
/// Id of the plugin data-save rule.
pub const DATA_SAVE_ID: &str = "PLUGIN-DATA-SAVE-FAILED";

const UPDATE: &str =
    "Update {plugin|the plugin} to the newest version that supports your Minecraft version.";
const REPORT: &str =
    "If it keeps happening, send the log lines shown below to the author of {plugin|the plugin}.";
const CHECK_CONFIG: &str = "Check {plugin|the plugin}'s config for missing or misspelled settings[[ (the missing value was `{null_ref}`)]], then restart the server.";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid built-in regex")
}

static ENABLING: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)while enabling (\S+?)(?: v(\S+))?(?: \(|$)"));
static DISABLING: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)while disabling (\S+?)(?: v(\S+))?(?: \(|$)"));
static LOAD_FILE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)could not load (?:plugin )?'([^']+)'"));
static PASS_EVENT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)could not pass event (\S+) to (\S+?)(?: v(\S+))?$"));
static TASK: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)plugin (\S+) v(\S+) generated an exception while executing task"));
static COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)unhandled exception executing (?:command )?'([^']*)' in (?:plugin )?(\S+?)(?: v(\S+))?$",
    )
});
static BRACKET_LIST: LazyLock<Regex> = LazyLock::new(|| re(r"\[([^\]]+)\]"));
static TO_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)to run '([^']+)'"));
static PLUGIN_QUOTED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)plugin '([^']+)'"));
static PLUGIN_DUE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)plugin (\S+) due to"));
static SINGLE_DEP: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(?:unknown|missing) dependency:? ([A-Za-z0-9_.\-]+)"));
static API_VERSION: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)unsupported api version:? ?(\S+)"));
static AMBIGUOUS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)ambiguous plugin name [`'](\S+?)'"));
static LEGACY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)legacy plugin (\S+) v(\S+) does not specify an api-version"));
static NAG: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)of '(\S+) v(\S+)' about the following: (.+)"));
static PLUGIN_VERSION: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)plugin (\S+) v(\S+)"));
static VAULT_SERVICE: LazyLock<Regex> =
    LazyLock::new(|| re(r"net\.milkbowl\.vault\.(chat|economy|permission)\."));

/// Plain-language phrases for common Bukkit/Paper events.
const EVENT_ACTIONS: &[(&str, &str)] = &[
    ("PlayerJoinEvent", "a player joined"),
    ("PlayerQuitEvent", "a player left"),
    ("PlayerKickEvent", "a player was kicked"),
    ("PlayerLoginEvent", "a player was logging in"),
    ("AsyncPlayerPreLoginEvent", "a player was logging in"),
    ("PlayerMoveEvent", "a player moved"),
    ("PlayerTeleportEvent", "a player teleported"),
    ("PlayerRespawnEvent", "a player respawned"),
    ("PlayerDeathEvent", "a player died"),
    ("AsyncPlayerChatEvent", "a player sent a chat message"),
    ("AsyncChatEvent", "a player sent a chat message"),
    ("PlayerCommandPreprocessEvent", "a player ran a command"),
    (
        "PlayerInteractEvent",
        "a player clicked or interacted with something",
    ),
    (
        "PlayerInteractEntityEvent",
        "a player interacted with a mob or entity",
    ),
    ("PlayerDropItemEvent", "a player dropped an item"),
    ("EntityPickupItemEvent", "something picked up an item"),
    ("InventoryClickEvent", "a player clicked in an inventory"),
    ("InventoryCloseEvent", "a player closed an inventory"),
    ("InventoryOpenEvent", "a player opened an inventory"),
    ("BlockBreakEvent", "a block was broken"),
    ("BlockPlaceEvent", "a block was placed"),
    ("SignChangeEvent", "a sign was edited"),
    ("EntityDamageEvent", "something took damage"),
    (
        "EntityDamageByEntityEvent",
        "something attacked something else",
    ),
    ("EntityDeathEvent", "a mob or player died"),
    ("CreatureSpawnEvent", "a mob spawned"),
    ("EntitySpawnEvent", "an entity spawned"),
    ("EntityExplodeEvent", "something exploded"),
    ("ChunkLoadEvent", "a chunk was loaded"),
    ("ChunkUnloadEvent", "a chunk was unloaded"),
    ("WorldLoadEvent", "a world was loaded"),
    ("ServerListPingEvent", "someone refreshed the server list"),
    (
        "PaperServerListPingEvent",
        "someone refreshed the server list",
    ),
    ("ServerLoadEvent", "the server finished loading"),
];

/// Phrase for an event class name.
pub fn event_action(event: &str) -> Option<&'static str> {
    let simple = event.rsplit('.').next().unwrap_or(event);
    EVENT_ACTIONS
        .iter()
        .find(|(e, _)| *e == simple)
        .map(|(_, a)| *a)
}

/// `[Tag] message` → `Tag`, if the tag names a plugin.
pub fn leading_plugin_tag(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('[')?;
    let tag = &inner[..inner.find(']')?];
    (!tag.is_empty()
        && tag.len() <= 48
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && is_plugin_tag(tag))
    .then_some(tag)
}

fn named(plugin: &str, headline: Option<String>) -> Extraction {
    Extraction {
        plugin: Some(plugin.to_owned()),
        group: Some(plugin.to_ascii_lowercase()),
        headline: headline.or_else(|| Some(plugin.to_owned())),
        ..Extraction::default()
    }
}

fn with_version(mut e: Extraction, version: Option<regex::Match<'_>>) -> Extraction {
    if let Some(v) = version {
        e.vars.push(("plugin_version", v.as_str().to_owned()));
    }
    e
}

fn extract_enabling(text: &str) -> Option<Extraction> {
    ENABLING
        .captures(text)
        .map(|c| with_version(named(&c[1], None), c.get(2)))
}

fn extract_disabling(text: &str) -> Option<Extraction> {
    DISABLING
        .captures(text)
        .map(|c| with_version(named(&c[1], None), c.get(2)))
}

/// `plugins/Foo-1.2.jar` → `Foo`.
fn plugin_from_path(path: &str) -> String {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    plugin_from_jar(file).unwrap_or_else(|| file.trim_end_matches(".jar").to_owned())
}

fn extract_load(text: &str) -> Option<Extraction> {
    LOAD_FILE.captures(text).map(|c| {
        let mut e = named(&plugin_from_path(&c[1]), None).var("file", c[1].to_owned());
        e.detail = Some(c[1].to_owned());
        e
    })
}

fn extract_pass_event(text: &str) -> Option<Extraction> {
    let c = PASS_EVENT.captures(text)?;
    let (event, plugin) = (&c[1], &c[2]);
    let mut e = with_version(named(plugin, Some(format!("{plugin} ({event})"))), c.get(3))
        .var("event", event.to_owned());
    if let Some(action) = event_action(event) {
        e.vars.push(("event_action", action.to_owned()));
    }
    e.detail = Some(event.to_owned());
    e.group = Some(format!("{}|{event}", plugin.to_ascii_lowercase()));
    Some(e)
}

fn extract_task(text: &str) -> Option<Extraction> {
    TASK.captures(text)
        .map(|c| with_version(named(&c[1], None), c.get(2)))
}

fn extract_command(text: &str) -> Option<Extraction> {
    let c = COMMAND.captures(text)?;
    let mut e =
        named(&c[2], Some(format!("{} (/{})", &c[2], &c[1]))).var("command", format!("/{}", &c[1]));
    e.detail = Some(format!("/{}", &c[1]));
    e.group = Some(format!("{}|{}", c[2].to_ascii_lowercase(), &c[1]));
    Some(e)
}

/// Parses dependency names and the dependent plugin from a missing-dependency message.
fn parse_missing_dependency(text: &str) -> Option<Extraction> {
    let deps: Vec<String> = match BRACKET_LIST.captures(text) {
        Some(c) => c[1]
            .split(',')
            .map(|d| d.trim().trim_matches(['\'', '"']).to_owned())
            .filter(|d| !d.is_empty())
            .collect(),
        None => SINGLE_DEP
            .captures(text)
            .map(|c| vec![c[1].trim_end_matches('.').to_owned()])
            .unwrap_or_default(),
    };
    if deps.is_empty() {
        return None;
    }
    let plugin = TO_RUN
        .captures(text)
        .or_else(|| PLUGIN_QUOTED.captures(text))
        .or_else(|| PLUGIN_DUE.captures(text))
        .map(|c| plugin_from_path(&c[1]));
    let dep_list = deps.join(", ");
    let mut e = Extraction {
        headline: Some(match &plugin {
            Some(p) => format!("{p} requires {dep_list}"),
            None => format!("requires {dep_list}"),
        }),
        detail: Some(dep_list.clone()),
        group: Some(format!(
            "{}|{}",
            plugin.as_deref().unwrap_or("").to_ascii_lowercase(),
            dep_list.to_ascii_lowercase()
        )),
        plugin,
        ..Extraction::default()
    }
    .var("dependency", dep_list);
    e.implicated = deps
        .into_iter()
        .map(|name| Implication {
            name,
            basis: ImplicationBasis::LogMessage,
            classification: Classification::Observed,
            seen_loading: None,
        })
        .collect();
    Some(e)
}

fn missing_dependency_from_exception(
    _: &ExceptionChain,
    exc: &ThrownException,
) -> Option<Extraction> {
    let msg = exc.message.as_deref()?;
    parse_missing_dependency(msg).or_else(|| {
        // Old Spigot: `UnknownDependencyException: Vault`
        let dep = msg.trim().trim_end_matches('.');
        (!dep.is_empty() && !dep.contains(' '))
            .then(|| parse_missing_dependency(&format!("[{dep}]")))
            .flatten()
    })
}

fn extract_api_version(text: &str) -> Option<Extraction> {
    let mut e = Extraction::default();
    if let Some(c) = API_VERSION.captures(text) {
        let v = c[1].trim_end_matches(['.', ')']).to_owned();
        e.detail = Some(v.clone());
        e.vars.push(("api_version", v));
    }
    if let Some(c) = PLUGIN_QUOTED
        .captures(text)
        .or_else(|| LOAD_FILE.captures(text))
    {
        let p = plugin_from_path(&c[1]);
        e.group = Some(p.to_ascii_lowercase());
        e.headline = Some(p.clone());
        e.plugin = Some(p);
    }
    Some(e)
}

fn api_version_from_exception(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    extract_api_version(exc.message.as_deref()?)
}

fn extract_ambiguous(text: &str) -> Option<Extraction> {
    AMBIGUOUS.captures(text).map(|c| named(&c[1], None))
}

fn extract_legacy(text: &str) -> Option<Extraction> {
    LEGACY
        .captures(text)
        .map(|c| with_version(named(&c[1], None), c.get(2)))
}

fn extract_nag(text: &str) -> Option<Extraction> {
    let c = NAG.captures(text)?;
    let mut e = named(&c[1], None);
    e.detail = Some(c[3].trim().to_owned());
    Some(e.var("nag", c[3].trim().to_owned()))
}

/// `[Tag] Plugin Foo v1.4 does not support ...` → plugin and version.
fn extract_plugin_version_or_tag(text: &str) -> Option<Extraction> {
    if let Some(c) = PLUGIN_VERSION.captures(text) {
        return Some(with_version(named(&c[1], None), c.get(2)));
    }
    leading_plugin_tag(text).map(|t| named(t, None))
}

/// Requires a plugin tag: data-save failures are only attributed when the plugin's own
/// logger reported them.
fn extract_tagged(text: &str) -> Option<Extraction> {
    let tag = leading_plugin_tag(text)?;
    let what = text[tag.len() + 2..].trim();
    Some(named(tag, None).var("what", what.to_owned()))
}

fn vault_service(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    let service = VAULT_SERVICE.captures(exc.message.as_deref()?)?[1].to_owned();
    let hint = match service.as_str() {
        "economy" => "an economy plugin such as EssentialsX or CMI",
        "chat" => "a plugin that provides chat prefixes and suffixes, such as LuckPerms",
        _ => "a permissions plugin such as LuckPerms",
    };
    Some(
        Extraction {
            group: Some(service.clone()),
            detail: Some(format!("Vault {service} service")),
            ..Extraction::default()
        }
        .var("service", service)
        .var("provider_hint", hint),
    )
}

fn missing_dependency_meta() -> Arc<RuleMeta> {
    RuleMeta::new(MISSING_DEPENDENCY_ID, Category::Plugin, Severity::Error)
        .title("Plugin dependency missing")
        .description("A plugin declares a hard dependency on another plugin that is not installed (or failed to load), so the dependent plugin was not loaded.")
        .evidence("An `UnknownDependencyException`, or a server message stating that a plugin is missing dependencies.")
        .user_title("{plugin|A plugin} needs {dependency|another plugin} to be installed")
        .explain("{plugin|A plugin} requires {dependency|another plugin} to run, but it isn't installed (or it didn't load). The server skipped {plugin|that plugin}, so it isn't running.")
        .fix(&[
            "Download {dependency|the missing plugin} from its official page and put it in your server's plugins folder.",
            "Restart the server (a full restart, not /reload).",
            "If {dependency|it} is already installed, look in this report for an error about {dependency|it} — it may have failed to load.",
        ])
        .shared()
}

fn unsupported_api_meta() -> Arc<RuleMeta> {
    RuleMeta::new(UNSUPPORTED_API_ID, Category::Plugin, Severity::Error)
        .title("Plugin requires a newer server API")
        .description("The plugin declares an `api-version` newer than this server supports, so the server refused to load it.")
        .evidence("An `InvalidPluginException`/message containing `Unsupported API version`.")
        .user_title("{plugin|A plugin} needs a newer Minecraft version")
        .explain("{plugin|A plugin} was made for a newer Minecraft version[[ ({api_version})]] than this server runs, so the server refused to load it.")
        .fix(&[
            "Download an older release of {plugin|the plugin} that supports your Minecraft version.",
            "Or update your server to the Minecraft version the plugin needs (back up your worlds first).",
        ])
        .shared()
}

fn data_save_meta() -> Arc<RuleMeta> {
    RuleMeta::new(DATA_SAVE_ID, Category::Plugin, Severity::Error)
        .title("Plugin failed to save data")
        .description("A plugin reported that it could not save data (player data, balances, settings).")
        .evidence("A line from a plugin's logger containing `could not save`, `failed to save` or similar.")
        .user_title("{plugin|A plugin} couldn't save its data")
        .explain("{plugin|A plugin} reported that saving failed[[: \"{what}\"]]. Recent changes it manages (player data, balances, ranks, settings) may be lost if the server stops before it can save again.")
        .fix(&[
            "Look for another problem from {plugin|the plugin} just before this one in the report (often a database or disk problem) and fix that first.",
            "Check free disk space, and if {plugin|the plugin} uses a database, that the database is reachable.",
            "Avoid stopping the server until {plugin|the plugin} saves successfully again.",
        ])
        .shared()
}

/// Exception rules for plugins.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(missing_dependency_meta(), &["org.bukkit.plugin.UnknownDependencyException"])
            .priority(40)
            .extract(missing_dependency_from_exception),
        ExceptionRule::new(unsupported_api_meta(), &["org.bukkit.plugin.InvalidPluginException"])
            .message_any(&["unsupported api version"])
            .priority(40)
            .extract(api_version_from_exception),
        ExceptionRule::new(
            RuleMeta::new(INVALID_DESCRIPTION_ID, Category::Plugin, Severity::Error)
                .title("Invalid plugin.yml")
                .description("The plugin's description file (plugin.yml / paper-plugin.yml) is missing or invalid: a corrupted jar, a non-Bukkit jar, or a broken build.")
                .evidence("An `org.bukkit.plugin.InvalidDescriptionException` in an exception chain.")
                .user_title("{plugin|A plugin} file is broken or isn't a server plugin")
                .explain("The file[[ {file}]] doesn't contain valid plugin information (its plugin.yml is missing or broken), so the server can't load it. The download may be incomplete, or the file may be a mod, a proxy plugin, or a library instead of a server plugin.")
                .fix(&[
                    "Re-download {plugin|the plugin} from its official page.",
                    "Make sure it's made for your server type (Paper/Spigot), not Velocity, BungeeCord, Forge or Fabric.",
                    "Restart the server.",
                ])
                .shared(),
            &["org.bukkit.plugin.InvalidDescriptionException"],
        )
        .priority(40),
        ExceptionRule::new(
            RuleMeta::new("PLUGIN-ASYNC-API-ACCESS", Category::Plugin, Severity::Error)
                .title("Server API accessed from an asynchronous thread")
                .description("A plugin called a main-thread-only server API from an asynchronous task; the server rejected the call.")
                .evidence("An `IllegalStateException` whose message mentions asynchronous/synchronous access (e.g. `Asynchronous chunk load!`).")
                .user_title("{plugin|A plugin} has a threading bug")
                .explain("{plugin|A plugin} tried to change the world from a background task, which the server doesn't allow. The server blocked it[[ ({exception_message})]], so that feature of the plugin failed. This is a bug in the plugin, not your configuration.[[ The code came from {suspect}.]]")
                .fix(&[
                    "Update {plugin|the plugin}[[ ({suspect})]] to the newest version.",
                    "If no fixed version exists, report it to the author with the log lines below.",
                ])
                .shared(),
            &["java.lang.IllegalStateException"],
        )
        .message_any(&["asynchronous", "synchronously", "async "])
        .priority(30),
        ExceptionRule::new(
            RuleMeta::new("PLUGIN-VAULT-SERVICE-MISSING", Category::Plugin, Severity::Error)
                .title("Vault service provider missing")
                .description("A NullPointerException on a Vault service object (Chat/Economy/Permission): Vault is present but no plugin registered a provider for that service, or the dependent plugin looked it up too early.")
                .evidence("A `NullPointerException` whose message references `net.milkbowl.vault.chat|economy|permission`.")
                .user_title("{plugin|A plugin} needs a Vault {service|service} provider")
                .explain("{plugin|A plugin} asked Vault for the {service|requested} service, but no plugin is providing it, so {plugin|the plugin} failed. Vault is only a bridge between plugins: another plugin has to actually provide the {service|service} features.")
                .fix(&[
                    "Make sure Vault is installed and enabled (look for \"Enabling Vault\" when the server starts).",
                    "Install {provider_hint|a plugin that provides this service to Vault}, then restart the server.",
                    "If you already have one, make sure it starts before {plugin|the plugin} and has no errors of its own in this report.",
                    "If it still fails, update {plugin|the plugin}.",
                ])
                .shared(),
            &["java.lang.NullPointerException"],
        )
        .message_any(&["net.milkbowl.vault.chat", "net.milkbowl.vault.economy", "net.milkbowl.vault.permission"])
        .priority(35)
        .extract(vault_service),
    ]
}

fn context_rule(
    id: &str,
    severity: Severity,
    title: &str,
    description: &str,
    evidence: &str,
) -> RuleMeta {
    RuleMeta::new(id, Category::Plugin, severity)
        .title(title)
        .description(description)
        .evidence(evidence)
}

/// Text rules for plugins.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(
            context_rule("PLUGIN-ENABLE-FAILED", Severity::Error, "Plugin failed to enable", "The server caught an exception while enabling a plugin; the plugin is disabled or partially working.", "A server message `Error occurred while enabling <plugin>`.")
                .user_title("{plugin|A plugin} failed to start")
                .explain("{plugin|A plugin} crashed while starting up[[: {error_hint}]]. It is now disabled, so its commands and features won't work, and plugins that depend on it may fail too.")
                .fix(&[
                    UPDATE,
                    "Check that every plugin {plugin|it} depends on is installed (see its download page).",
                    "Check {plugin|the plugin}'s config for mistakes, or rename its config file so a fresh default one is created.",
                    REPORT,
                ])
                .context("This happened while {plugin|the plugin} was starting, so {plugin|it} is now disabled.")
                .shared(),
            &["error occurred while enabling "],
        )
        .extract_required(extract_enabling)
        .boxed(),
        TextRule::new(
            context_rule("PLUGIN-LOAD-FAILED", Severity::Error, "Plugin failed to load", "The server could not load a plugin jar, so the plugin is not running.", "A server message `Could not load '<file>'` / `Could not load plugin '<name>'`.")
                .user_title("{plugin|A plugin} could not be loaded")
                .explain("The server couldn't load {plugin|a plugin}[[ ({file})]], so it isn't running at all.[[ Reason: {error_hint}.]]")
                .fix(&[
                    "Re-download {plugin|the plugin} from its official page; a broken or incomplete download is a common cause.",
                    "Make sure it's made for your server type (Paper/Spigot) and your Minecraft version.",
                    "Restart the server.",
                ])
                .context("")
                .shared(),
            &["could not load '", "could not load plugin '"],
        )
        .extract(extract_load)
        .boxed(),
        TextRule::new(missing_dependency_meta(), &["missing dependenc", "unknown dependenc", "unknown/missing dependenc"])
            .extract_required(parse_missing_dependency)
            .boxed(),
        TextRule::new(unsupported_api_meta(), &["unsupported api version"])
            .extract(extract_api_version)
            .boxed(),
        TextRule::new(
            RuleMeta::new("PLUGIN-UNSUPPORTED-SERVER-VERSION", Category::Plugin, Severity::Error)
                .title("Plugin does not support the server version")
                .description("A plugin reported that it does not support the running server/Minecraft version and disabled itself.")
                .evidence("A plugin message such as `does not support this server version` or `unsupported Minecraft version`.")
                .user_title("{plugin|A plugin} doesn't support your server version")
                .explain("{plugin|A plugin}[[ (version {plugin_version})]] reported that it doesn't work with this server's Minecraft version[[ ({minecraft_version})]] and turned itself off. Its features won't be available.")
                .fix(&[
                    "Look for a newer version of {plugin|the plugin} that supports your Minecraft version.",
                    "If there isn't one, look for an alternative plugin, or keep using a Minecraft version it supports.",
                    "Restart the server after replacing it.",
                ])
                .shared(),
            &[
                "does not support this server version",
                "doesn't support this server version",
                "unsupported minecraft version",
                "unsupported server version",
                "not compatible with this server version",
                "not compatible with your server version",
                "is not supported on this server version",
            ],
        )
        .excluding(&["disabling "])
        .extract(extract_plugin_version_or_tag)
        .boxed(),
        TextRule::new(
            context_rule("PLUGIN-EVENT-EXCEPTION", Severity::Error, "Plugin event handler threw an exception", "An exception escaped a plugin's event listener; the server names the plugin that owns the listener.", "A server message `Could not pass event <Event> to <plugin>`.")
                .user_title("{plugin|A plugin} hit an error when {event_action|handling a server event}")
                .explain("{plugin|A plugin} crashed while reacting to {event_action|a server event}[[: {error_hint}]]. Whatever {plugin|it} normally does at that moment (messages, rewards, protection, logging) didn't happen.")
                .fix(&[UPDATE, CHECK_CONFIG, REPORT])
                .context("It happened when {event_action|a server event was handled}.")
                .shared(),
            &["could not pass event "],
        )
        .extract_required(extract_pass_event)
        .boxed(),
        TextRule::new(
            context_rule("PLUGIN-TASK-EXCEPTION", Severity::Error, "Plugin scheduled task threw an exception", "An exception escaped a task scheduled by a plugin; repeating tasks fail on every run.", "A server message `Plugin <plugin> generated an exception while executing task <id>`.")
                .user_title("{plugin|A plugin}'s background task is failing")
                .explain("A background task run by {plugin|a plugin} crashed[[: {error_hint}]]. Tasks like this often repeat, so the error can fill the log and slow the server down.")
                .fix(&[UPDATE, CHECK_CONFIG, REPORT])
                .context("It happened in a background task run by {plugin|the plugin}.")
                .shared(),
            &["generated an exception while executing task"],
        )
        .extract_required(extract_task)
        .boxed(),
        TextRule::new(
            context_rule("PLUGIN-COMMAND-EXCEPTION", Severity::Warning, "Plugin command threw an exception", "An exception escaped a plugin command handler; the command failed.", "A server message `Unhandled exception executing command '<cmd>' in plugin <plugin>`.")
                .user_title("A command from {plugin|a plugin} crashed")
                .explain("Running[[ {command}]] caused an error in {plugin|a plugin}[[: {error_hint}]]. The command didn't work for whoever ran it.")
                .fix(&[
                    "Try the command again with the correct arguments, and check the player has the right permissions.",
                    UPDATE,
                    REPORT,
                ])
                .context("It happened when someone ran {command|a command}.")
                .shared(),
            &["unhandled exception executing "],
        )
        .extract_required(extract_command)
        .boxed(),
        TextRule::new(
            context_rule("PLUGIN-DISABLE-FAILED", Severity::Warning, "Plugin failed to disable cleanly", "A plugin threw an exception while being disabled, usually during shutdown; data saved on shutdown may be missing.", "A server message `Error occurred while disabling <plugin>`.")
                .user_title("{plugin|A plugin} had an error while shutting down")
                .explain("{plugin|A plugin} crashed while the server was turning it off[[: {error_hint}]]. Anything it normally saves when shutting down may not have been saved.")
                .fix(&[
                    "After the next start, check that {plugin|the plugin}'s data (homes, balances, settings) is intact.",
                    UPDATE,
                ])
                .context("It happened while {plugin|the plugin} was shutting down, so some of its data may not have been saved.")
                .shared(),
            &["error occurred while disabling "],
        )
        .extract_required(extract_disabling)
        .boxed(),
        TextRule::new(data_save_meta(), &["could not save", "couldn't save", "failed to save", "unable to save", "error saving", "error while saving"])
            .excluding(&["chunk"])
            .extract_required(extract_tagged)
            .boxed(),
        TextRule::new(
            RuleMeta::new("PLUGIN-AMBIGUOUS-NAME", Category::Plugin, Severity::Warning)
                .title("Duplicate plugin installed")
                .description("Two jars declare the same plugin name; only one is loaded and which one is not guaranteed.")
                .evidence("A server message `Ambiguous plugin name`.")
                .user_title("{plugin|A plugin} is installed twice")
                .explain("Two files in the plugins folder are the same plugin ({plugin|same name}). Only one of them gets loaded, and it may not be the version you expect.")
                .fix(&[
                    "Open the plugins folder and delete the older copy of {plugin|the duplicated plugin}.",
                    "Restart the server.",
                ])
                .shared(),
            &["ambiguous plugin name"],
        )
        .extract(extract_ambiguous)
        .boxed(),
        TextRule::new(
            RuleMeta::new("PLUGIN-RELOAD-USED", Category::Plugin, Severity::Warning)
                .title("Server reload (/reload) was used")
                .description("The server was reloaded in place. Reloading is unsupported: many plugins leak memory or break state across reloads.")
                .evidence("The server's reload warning `this command is not supported and may cause issues`.")
                .user_title("The server was reloaded with /reload")
                .explain("Someone ran /reload, which restarts all plugins without restarting the server. Many plugins don't handle this well, so errors that appear after a reload may be caused by the reload itself.")
                .fix(&[
                    "Restart the server fully instead of using /reload.",
                    "If errors appeared after the reload, restart and check whether they come back.",
                ])
                .shared(),
            &["this command is not supported and may cause issues"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("PLUGIN-LEGACY-API", Category::Plugin, Severity::Info)
                .title("Legacy plugin without api-version")
                .description("A plugin does not declare an api-version, so the server runs it through the legacy material compatibility layer.")
                .evidence("A server message `Legacy plugin <plugin> does not specify an api-version`.")
                .user_title("{plugin|A plugin} is very old")
                .explain("{plugin|A plugin} wasn't updated for modern Minecraft (1.13 or newer). The server runs it in a compatibility mode, which slows down startup and can cause problems with newer blocks and items.")
                .fix(&["Update {plugin|the plugin}, or replace it with a maintained alternative."])
                .shared(),
            &["does not specify an api-version"],
        )
        .extract(extract_legacy)
        .boxed(),
        TextRule::new(
            RuleMeta::new("PLUGIN-NAG", Category::Plugin, Severity::Info)
                .title("Server warned about plugin behavior")
                .description("The server flagged a plugin for using an API incorrectly (a 'nag' message).")
                .evidence("A server message `Nag author(s): ... of '<plugin>' about the following: ...`.")
                .user_title("The server warned about {plugin|a plugin}")
                .explain("The server noticed {plugin|a plugin} using it in a way it shouldn't[[: {nag}]]. This usually doesn't break anything.")
                .fix(&["No action needed right now; update {plugin|the plugin} when a new version comes out."])
                .shared(),
            &["nag author(s):", "nag author:"],
        )
        .extract(extract_nag)
        .boxed(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling() {
        let e = extract_enabling(
            "Error occurred while enabling Essentials v2.20.1 (Is it up to date?)",
        )
        .unwrap();
        assert_eq!(e.plugin.as_deref(), Some("Essentials"));
        let e = extract_enabling("Error occurred while enabling Foo (Is it up to date?)").unwrap();
        assert_eq!(e.plugin.as_deref(), Some("Foo"));
    }

    #[test]
    fn missing_dependency_messages() {
        let e = parse_missing_dependency("Unknown/missing dependency plugins: [Vault, PlaceholderAPI]. Please download and install these plugins to run 'EconomyShop'.").unwrap();
        assert_eq!(e.plugin.as_deref(), Some("EconomyShop"));
        assert_eq!(e.implicated.len(), 2);
        assert_eq!(e.implicated[1].name, "PlaceholderAPI");
        let e = parse_missing_dependency(
            "Can't load plugin chatbridge due to missing dependency luckperms",
        )
        .unwrap();
        assert_eq!(e.plugin.as_deref(), Some("chatbridge"));
        assert_eq!(e.detail.as_deref(), Some("luckperms"));
        assert!(parse_missing_dependency("Loaded 4 dependencies").is_none());
    }

    #[test]
    fn pass_event() {
        let e = extract_pass_event("Could not pass event PlayerJoinEvent to WelcomePlus v1.4.2")
            .unwrap();
        assert_eq!(e.plugin.as_deref(), Some("WelcomePlus"));
        assert_eq!(e.detail.as_deref(), Some("PlayerJoinEvent"));
        assert!(
            e.vars
                .contains(&("event_action", "a player joined".to_owned()))
        );
    }

    #[test]
    fn load_path() {
        let e = extract_load("Could not load 'plugins/BrokenPlugin-1.0.jar' in folder 'plugins'")
            .unwrap();
        assert_eq!(e.plugin.as_deref(), Some("BrokenPlugin"));
    }

    #[test]
    fn tags() {
        assert_eq!(leading_plugin_tag("[Ranks] Could not save"), Some("Ranks"));
        assert_eq!(leading_plugin_tag("[Server] Done"), None);
        assert_eq!(leading_plugin_tag("Could not save"), None);
    }
}
