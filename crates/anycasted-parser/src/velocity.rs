//! Velocity proxy specifics.
//!
//! Velocity uses the same log4j line layouts as Paper (handled by
//! [`crate::minecraft`]), but announces itself, its plugins and its shutdown
//! differently.

use std::sync::LazyLock;

use regex::Regex;

static BOOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Booting up Velocity (\S+)").expect("valid regex"));
static PLUGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Loaded plugin ([A-Za-z0-9_.\-]+) (\S+)(?: by .*)?$").expect("valid regex")
});

/// Version announced by `Booting up Velocity <version>...`.
pub fn boot_version(message: &str) -> Option<&str> {
    if !message.starts_with("Booting up Velocity") {
        return None;
    }
    BOOT.captures(message)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim_end_matches('.'))
}

/// `(name, version)` from `Loaded plugin <name> <version> by <authors>`.
pub fn loaded_plugin(message: &str) -> Option<(&str, &str)> {
    if !message.starts_with("Loaded plugin ") {
        return None;
    }
    let c = PLUGIN.captures(message)?;
    Some((c.get(1)?.as_str(), c.get(2)?.as_str()))
}

/// Whether the message marks the start of a proxy shutdown.
pub fn is_shutdown_marker(message: &str) -> bool {
    message.starts_with("Shutting down the proxy")
}

/// Whether a logger name belongs to Velocity itself.
pub fn is_velocity_logger(logger: &str) -> bool {
    logger.starts_with("com.velocitypowered")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_velocity_messages() {
        assert_eq!(
            boot_version("Booting up Velocity 3.3.0-SNAPSHOT (git-a1b2c3d4-b400)..."),
            Some("3.3.0-SNAPSHOT")
        );
        assert_eq!(
            boot_version("Booting up Velocity 3.3.0-SNAPSHOT..."),
            Some("3.3.0-SNAPSHOT")
        );
        assert_eq!(
            loaded_plugin("Loaded plugin luckperms 5.4.102 by Luck"),
            Some(("luckperms", "5.4.102"))
        );
        assert!(is_shutdown_marker("Shutting down the proxy..."));
    }
}
