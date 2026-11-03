//! Networking and proxy communication.
//!
//! Network exceptions are common in healthy servers (clients disconnecting, scanners
//! probing the port). Rules here deliberately ignore player disconnect messages and
//! assign `info` severity to conditions that are usually client-side.

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{Category, ExceptionChain, RuleMeta, Severity, ThrownException};
use regex::Regex;

use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9.\-]+/)?(\d+(?:\.\d+){3}|[A-Za-z0-9.\-]+):(\d{2,5})")
        .expect("valid regex")
});
static BACKEND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:unable to connect (?:you )?to (?:server )?|-> )([A-Za-z0-9_.\-]+)")
        .expect("valid regex")
});

const FORWARDING_PHRASES: &[&str] = &[
    "please enable it in your bungeecord config",
    "unable to verify player details",
    "didn't send a forwarding request",
    "doesn't have forwarding",
    "requires you to connect with velocity",
    "if you wish to use ip forwarding",
    "forwarding is configured incorrectly",
    "invalid player info forwarding",
];

/// Groups network failures by remote endpoint, taken from the first message in the
/// chain that contains one. Without an endpoint, all occurrences form one group.
fn endpoint(chain: &ExceptionChain, _: &ThrownException) -> Option<Extraction> {
    let host = chain.exceptions.iter().find_map(|e| {
        let c = HOST.captures(e.message.as_deref()?)?;
        Some(format!("{}:{}", &c[2], &c[3]))
    });
    let mut e = Extraction {
        headline: host.clone(),
        detail: host.clone(),
        group: Some(host.clone().unwrap_or_default()),
        ..Extraction::default()
    };
    if let Some(h) = host {
        e.vars.push(("endpoint", h));
    }
    Some(e)
}

fn unknown_host(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    let host = exc
        .message
        .as_deref()?
        .split([':', ' '])
        .next()?
        .trim()
        .to_owned();
    (!host.is_empty()).then(|| {
        Extraction {
            headline: Some(host.clone()),
            detail: Some(host.clone()),
            group: Some(host.clone()),
            ..Extraction::default()
        }
        .var("host", host)
    })
}

fn backend(text: &str) -> Option<Extraction> {
    let c = BACKEND.captures(text)?;
    let server = c[1].trim_end_matches([':', '.']).to_owned();
    Some(
        Extraction {
            headline: Some(server.clone()),
            detail: Some(server.clone()),
            group: Some(server.to_ascii_lowercase()),
            ..Extraction::default()
        }
        .var("server_label", format!("the backend server '{server}'"))
        .var("server", server),
    )
}

fn forwarding_server(text: &str) -> Option<Extraction> {
    Some(
        backend(text)
            .map(|e| Extraction { group: None, ..e })
            .unwrap_or_default(),
    )
}

const CHECK_TARGET: &str = "Make sure the service at {endpoint|that address} is running[[ (if '{server}' is a backend server, check its own console for startup errors)]].";
const CHECK_ADDRESS: &str = "Double-check the address and port in the config that points to it[[ (for a proxy: the '{server}' entry in velocity.toml)]].";
const CHECK_FIREWALL: &str =
    "Check that no firewall is blocking the connection between the two machines.";

fn forwarding_meta() -> Arc<RuleMeta> {
    RuleMeta::new("NET-PROXY-FORWARDING", Category::Networking, Severity::Error)
        .title("Proxy player-info forwarding misconfigured")
        .description("The proxy and backend server disagree about player information forwarding (BungeeCord legacy or Velocity modern), so players are rejected or join with wrong UUIDs/skins.")
        .evidence("A proxy/backend message about IP or player-info forwarding (e.g. `please enable it in your BungeeCord config`, `requires you to connect with Velocity`).")
        .user_title("The proxy and {server_label|the backend server} disagree about player forwarding")
        .explain("Your proxy (Velocity or BungeeCord) and {server_label|the backend server} aren't set up the same way for passing player information (UUIDs, skins, IP addresses), so players are being rejected when they try to join.[[ The server said: \"{exception_message}\"]]")
        .fix(&[
            "Pick one forwarding mode and use it everywhere. For Velocity \"modern\" forwarding: set player-info-forwarding-mode = \"modern\" in velocity.toml.",
            "On every Paper backend, open config/paper-global.yml and set proxies.velocity.enabled: true and proxies.velocity.secret to the same text as Velocity's forwarding.secret file.",
            "For BungeeCord/legacy forwarding instead: set bungeecord: true in spigot.yml on every backend.",
            "Restart the proxy and all backend servers, then try joining again.",
        ])
        .shared()
}

/// Exception rules.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(
            RuleMeta::new("NET-CONNECTION-REFUSED", Category::Networking, Severity::Error)
                .title("Outbound connection refused")
                .description("The server (or a plugin) connected to another service and the connection was actively refused: nothing is listening at that address/port.")
                .evidence("A `ConnectException` (or Netty `AnnotatedConnectException`) with `Connection refused`.")
                .user_title("Nothing is accepting connections at {endpoint|the target address}[[ (backend server '{server}')]]")
                .explain("The server or a plugin tried to connect to {endpoint|another service} (a backend server, database or website), but the connection was refused: nothing is running at that address and port, or a firewall rejected it.")
                .fix(&[CHECK_TARGET, CHECK_ADDRESS, CHECK_FIREWALL])
                .shared(),
            &["java.net.ConnectException", "AnnotatedConnectException"],
        )
        .message_any(&["connection refused"])
        .priority(30)
        .extract(endpoint),
        ExceptionRule::new(
            timeout_meta(),
            &[
                "java.net.SocketTimeoutException",
                "io.netty.channel.ConnectTimeoutException",
                "java.net.http.HttpTimeoutException",
                "java.net.http.HttpConnectTimeoutException",
            ],
        )
        .priority(20)
        .extract(endpoint),
        ExceptionRule::new(timeout_meta(), &["java.net.ConnectException", "AnnotatedConnectException"])
            .message_any(&["timed out"])
            .priority(25)
            .extract(endpoint),
        ExceptionRule::new(
            RuleMeta::new("NET-DNS-FAILURE", Category::Networking, Severity::Error)
                .title("DNS resolution failed")
                .description("A hostname could not be resolved: no working DNS, a misspelled hostname, or a domain that no longer exists.")
                .evidence("A `java.net.UnknownHostException` in an exception chain.")
                .user_title("Couldn't find the address {host|of a remote service}")
                .explain("The server couldn't look up the IP address for {host|a hostname} (the DNS lookup failed). The name may be misspelled, the domain may no longer exist, or DNS isn't working on the server's machine.")
                .fix(&[
                    "Check {host|the hostname} for typos in {plugin|the plugin}'s config.",
                    "If it's an internal name (like a database container), make sure it can be resolved from the server's machine or container.",
                    "As a test, use the IP address instead of the hostname.",
                ])
                .shared(),
            &["java.net.UnknownHostException"],
        )
        .priority(30)
        .extract(unknown_host),
        ExceptionRule::new(
            RuleMeta::new("NET-CONNECTION-RESET", Category::Networking, Severity::Info)
                .title("Connection reset by peer")
                .description("A remote peer closed a connection abruptly. For player connections this is normal (clients crashing, losing Wi-Fi, port scanners).")
                .evidence("An exception whose message contains `Connection reset`.")
                .user_title("A connection was closed unexpectedly")
                .explain("Something on the other end closed a network connection suddenly. Usually it's just a player closing the game or losing their internet, which is harmless. It only matters if it happens very often.")
                .fix(&["No action needed unless it happens very often or players complain about disconnects."])
                .shared(),
            &["java.net.SocketException", "java.io.IOException", "NativeIoException"],
        )
        .message_any(&["connection reset"])
        .priority(20),
        ExceptionRule::any_class(forwarding_meta())
            .message_any(FORWARDING_PHRASES)
            .priority(45),
    ]
}

fn timeout_meta() -> Arc<RuleMeta> {
    RuleMeta::new("NET-TIMEOUT", Category::Networking, Severity::Warning)
        .title("Network operation timed out")
        .description("An outbound connection or read did not complete in time; the remote service is slow, overloaded or unreachable.")
        .evidence("A `SocketTimeoutException`, `ConnectTimeoutException`, `HttpTimeoutException`, or a `ConnectException` with `timed out`.")
        .user_title("Connection to {endpoint|a remote service} timed out[[ (backend server '{server}')]]")
        .explain("The server or a plugin tried to connect to {endpoint|another service}, but it didn't answer in time. It may be offline, overloaded, or blocked by a firewall.")
        .fix(&[CHECK_TARGET, CHECK_ADDRESS, CHECK_FIREWALL])
        .shared()
}

/// Text rules.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(forwarding_meta(), FORWARDING_PHRASES)
            .extract(forwarding_server)
            .boxed(),
        TextRule::new(
            RuleMeta::new("NET-PROXY-BACKEND-UNREACHABLE", Category::Networking, Severity::Error)
                .title("Proxy could not connect to a backend server")
                .description("The proxy failed to connect a player to a backend server: the backend is offline, still starting, or its address in the proxy configuration is wrong.")
                .evidence("A proxy message `unable to connect to server <name>` or `Exception connecting to backend server`.")
                .user_title("Players can't connect to {server_label|a backend server}")
                .explain("The proxy couldn't send players to {server_label|a backend server}[[: {error_hint}]]. That server may be offline, still starting, or listed with the wrong address in the proxy config.")
                .fix(&[
                    "Check that {server_label|the backend server} is running and has finished starting.",
                    "Check its address and port in the [servers] section of velocity.toml.",
                    "Look at the backend server's own log for errors at the same time.",
                ])
                .context("Players trying to join {server_label|the backend server} couldn't connect.")
                .shared(),
            &["unable to connect to server ", "unable to connect you to ", "exception connecting to backend server", "exception connecting to server"],
        )
        .excluding(&["lost connection", "disconnected:"])
        .extract(backend)
        .boxed(),
    ]
}
