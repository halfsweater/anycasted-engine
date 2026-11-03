//! Database connectivity and credentials (MySQL/MariaDB/PostgreSQL via JDBC/HikariCP).
//!
//! Plugins usually retry database connections, so these rules carry recovery markers:
//! if the same plugin later reports a successful connection, the finding is marked as
//! recovered and its severity lowered.

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{Category, ExceptionChain, RuleMeta, Severity, ThrownException};
use regex::Regex;

use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

/// Id of the access-denied rule.
pub const ACCESS_DENIED_ID: &str = "DB-ACCESS-DENIED";

static USER_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)for user '([^']*)'@'([^']*)'").expect("valid regex"));
static PG_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)authentication failed for user "([^"]*)""#).expect("valid regex")
});

const RECOVERY: &[&str] = &[
    "connection established",
    "connected to database",
    "connected to the database",
    "database connection established",
    "successfully connected",
    "reconnected",
    "connection restored",
];

fn credentials(text: &str) -> Option<Extraction> {
    let mut e = Extraction::default();
    if let Some(c) = USER_HOST.captures(text) {
        e.vars.push(("db_user", c[1].to_owned()));
        e.vars.push(("db_host", c[2].to_owned()));
        e.detail = Some(format!("{}@{}", &c[1], &c[2]));
    } else if let Some(c) = PG_USER.captures(text) {
        e.vars.push(("db_user", c[1].to_owned()));
        e.detail = Some(c[1].to_owned());
    }
    Some(e)
}

fn credentials_from_exception(_: &ExceptionChain, exc: &ThrownException) -> Option<Extraction> {
    credentials(exc.message.as_deref()?)
}

fn access_denied_meta() -> Arc<RuleMeta> {
    RuleMeta::new(ACCESS_DENIED_ID, Category::Database, Severity::Error)
        .title("Database authentication failed")
        .description("The database server rejected the login: wrong username/password, or the user is not permitted to connect from this host.")
        .evidence("`Access denied for user '...'@'...'` or `password authentication failed for user`.")
        .user_title("{plugin|A plugin} can't log in to its database")
        .explain("{plugin|A plugin} reached the database server, but the login was rejected[[ for user '{db_user}']][[ connecting from {db_host}]]. The username or password is wrong, or that user isn't allowed to connect from this server.")
        .fix(&[
            "Check the database username and password in {plugin|the plugin}'s config file (watch for extra spaces or quotes).",
            "In your database panel, make sure the user exists, has access to the right database, and is allowed to connect from this server's IP[[ ({db_host})]].",
            "Restart the server after fixing it.",
        ])
        .recovers_on(RECOVERY)
        .shared()
}

fn unreachable_meta() -> Arc<RuleMeta> {
    RuleMeta::new("DB-UNREACHABLE", Category::Database, Severity::Error)
        .title("Database unreachable or connection pool exhausted")
        .description("A plugin could not obtain a database connection: the database is down or unreachable, connection settings are wrong, or the connection pool is exhausted.")
        .evidence("A JDBC/HikariCP connection exception, or a plugin message such as `Could not connect to database` / `Failed to obtain a database connection`.")
        .user_title("{plugin|A plugin} can't connect to its database")
        .explain("{plugin|A plugin} couldn't get a connection to its database[[ ({exception_message})]]. Features that store data (ranks, economy, stats, logs) won't work, and changes may not be saved until it reconnects.")
        .fix(&[
            "Check that the database server is running.",
            "Check the database host, port and database name in {plugin|the plugin}'s config file.",
            "If the database is on another machine, make sure the firewall allows connections from this server.",
            "If it mentions the connection pool or \"Connection is not available\", the database may be overloaded or {plugin|the plugin} may be keeping connections open: restart the server and update {plugin|the plugin}.",
        ])
        .recovers_on(RECOVERY)
        .shared()
}

/// Exception rules.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::any_class(access_denied_meta())
            .message_any(&[
                "access denied for user",
                "password authentication failed for user",
            ])
            .priority(45)
            .extract(credentials_from_exception),
        ExceptionRule::new(
            unreachable_meta(),
            &[
                "java.sql.SQLTransientConnectionException",
                "java.sql.SQLNonTransientConnectionException",
                "PoolInitializationException",
                "CommunicationsException",
                "com.mysql.cj.exceptions.CJCommunicationsException",
            ],
        )
        .priority(35)
        .extract(|_, _| {
            Some(Extraction {
                group: Some(String::new()),
                ..Extraction::default()
            })
        }),
        ExceptionRule::new(
            unreachable_meta(),
            &["java.sql.SQLException", "org.postgresql.util.PSQLException"],
        )
        .message_any(&[
            "communications link failure",
            "connection refused",
            "connection timed out",
            "could not create connection",
            "connection attempt failed",
        ])
        .priority(35)
        .extract(|_, _| {
            Some(Extraction {
                group: Some(String::new()),
                ..Extraction::default()
            })
        }),
    ]
}

/// Text rules.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(
            access_denied_meta(),
            &[
                "access denied for user",
                "password authentication failed for user",
            ],
        )
        .extract(credentials)
        .boxed(),
        TextRule::new(
            unreachable_meta(),
            &[
                "could not connect to database",
                "couldn't connect to database",
                "failed to connect to database",
                "unable to connect to database",
                "could not connect to the database",
                "failed to connect to the database",
                "failed to obtain a database connection",
                "communications link failure",
                "connection is not available, request timed out",
                "failed to initialize pool",
            ],
        )
        .superseded_by(&[ACCESS_DENIED_ID])
        .boxed(),
    ]
}
