//! Conservative attribution of findings to plugins.
//!
//! The engine never labels a plugin as the *cause* of a problem because it appears in
//! a stack trace. Instead it records [`Implication`]s with an explicit basis and a
//! `hypothesis` classification. Only plugins named explicitly by the log (logger tag,
//! server messages) become a finding's `subject.plugin`.

use anycasted_core::models::{Classification, ExceptionChain, Implication, ImplicationBasis};

/// Bracket tags at the start of Paper/Spigot messages that are server components, not
/// plugins.
const INTERNAL_TAGS: &[&str] = &[
    "bootstrap",
    "PluginInitializerManager",
    "DirectoryProviderSource",
    "ModernPluginLoadingStrategy",
    "LegacyPluginLoadingStrategy",
    "PluginRemapper",
    "PaperPluginLoader",
    "STDOUT",
    "STDERR",
    "Server",
    "MinecraftServer",
    "minecraft",
    "Minecraft",
    "Spigot",
    "Paper",
    "Purpur",
    "CraftBukkit",
    "Bukkit",
    "ChunkTaskScheduler",
    "Watchdog",
];

/// Whether a message tag names a plugin logger.
pub fn is_plugin_tag(tag: &str) -> bool {
    !INTERNAL_TAGS.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

/// Archive name prefixes (lower-case) of server builds and shared libraries. Frames
/// from these archives are not attributed to plugins.
const NON_PLUGIN_JAR_PREFIXES: &[&str] = &[
    "paper-",
    "purpur-",
    "spigot-",
    "craftbukkit-",
    "bukkit-",
    "patched_",
    "server-",
    "minecraft-",
    "minecraft_server",
    "velocity-",
    "folia-",
    "pufferfish-",
    "leaf-",
    "gale-",
    "netty-",
    "guava-",
    "gson-",
    "log4j-",
    "slf4j-",
    "commons-",
    "fastutil",
    "brigadier-",
    "datafixerupper-",
    "authlib-",
    "adventure-",
    "examination-",
    "snakeyaml-",
    "asm-",
    "jopt-",
    "jline-",
    "oshi-",
    "lwjgl",
    "jna-",
    "checker-qual",
    "caffeine-",
    "configurate-",
    "geantyref-",
    "javax.",
    "jakarta.",
    "joml-",
    "byte-buddy",
    "jackson-",
    "okhttp-",
    "okio-",
    "annotations-",
    "error_prone",
    "jsr305",
    "lz4-",
    "zstd-",
    "httpclient-",
    "httpcore-",
    "kotlin-stdlib",
    "kotlin-reflect",
    "sqlite-jdbc",
    "mysql-connector",
    "mariadb-java",
    "hikaricp-",
    "h2-",
    "java.base",
    "jdk.",
    "fabric-loader",
    "forge-",
    "fmlcore",
    "modlauncher",
    "bootstraplauncher",
    "securejarhandler",
    "sponge-mixin",
    "mixin-",
];

/// Archive stems (lower-case) that are server builds.
const NON_PLUGIN_JAR_STEMS: &[&str] = &[
    "server",
    "paper",
    "purpur",
    "spigot",
    "craftbukkit",
    "velocity",
    "minecraft",
    "folia",
];

/// Derives a plugin name from a frame's archive name, or `None` for server and library
/// archives. Version suffixes are removed (`EssentialsX-2.20.1.jar` → `EssentialsX`).
pub fn plugin_from_jar(jar: &str) -> Option<String> {
    let stem = jar.strip_suffix(".jar").unwrap_or(jar);
    let lower = stem.to_ascii_lowercase();
    if stem.is_empty()
        || NON_PLUGIN_JAR_STEMS.contains(&lower.as_str())
        || NON_PLUGIN_JAR_PREFIXES.iter().any(|p| lower.starts_with(p))
    {
        return None;
    }
    let bytes = stem.as_bytes();
    let cut = (1..bytes.len())
        .find(|&i| {
            matches!(bytes[i - 1], b'-' | b'_' | b' ')
                && (bytes[i].is_ascii_digit()
                    || (matches!(bytes[i], b'v' | b'V')
                        && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)))
        })
        .map_or(stem.len(), |i| i - 1);
    let name = stem[..cut].trim_end_matches(['-', '_', ' ']);
    (!name.is_empty()).then(|| name.to_owned())
}

/// Plugins whose archives appear in the chain's stack frames, in order of first
/// appearance (outermost throwable first), as hypotheses.
pub fn implicated_from_frames(chain: &ExceptionChain, limit: usize) -> Vec<Implication> {
    let mut out: Vec<Implication> = Vec::new();
    for frame in chain.frames() {
        if out.len() >= limit {
            break;
        }
        let Some(name) = frame.jar.as_deref().and_then(plugin_from_jar) else {
            continue;
        };
        if !out.iter().any(|i| i.name.eq_ignore_ascii_case(&name)) {
            out.push(Implication {
                name,
                basis: ImplicationBasis::StackFrame,
                classification: Classification::Hypothesis,
                seen_loading: None,
            });
        }
    }
    out
}

/// Well-known packages and the plugin that ships them.
const PACKAGE_OWNERS: &[(&str, &str)] = &[
    ("net.milkbowl.vault", "Vault"),
    ("me.clip.placeholderapi", "PlaceholderAPI"),
    ("com.sk89q.worldguard", "WorldGuard"),
    ("com.sk89q.worldedit", "WorldEdit (or FastAsyncWorldEdit)"),
    ("com.fastasyncworldedit", "FastAsyncWorldEdit"),
    ("com.comphenix.protocol", "ProtocolLib"),
    ("net.luckperms.api", "LuckPerms"),
    ("me.lucko.luckperms", "LuckPerms"),
    ("com.earth2me.essentials", "EssentialsX"),
    ("net.ess3", "EssentialsX"),
    ("net.essentialsx", "EssentialsX"),
    ("de.tr7zw.nbtapi", "NBTAPI"),
    ("de.tr7zw.changeme.nbtapi", "NBTAPI"),
    ("com.github.retrooper.packetevents", "packetevents"),
    ("io.github.retrooper.packetevents", "packetevents"),
    ("me.lucko.spark", "spark"),
    ("net.citizensnpcs", "Citizens"),
    ("io.lumine.mythic", "MythicMobs"),
    ("com.onarandombox.multiversecore", "Multiverse-Core"),
    ("org.mvplugins.multiverse", "Multiverse-Core"),
    ("dev.lone.itemsadder", "ItemsAdder"),
    ("org.geysermc.geyser", "Geyser"),
    ("org.geysermc.floodgate", "floodgate"),
    ("com.viaversion.viaversion", "ViaVersion"),
    ("us.myles.viaversion", "ViaVersion"),
    ("net.coreprotect", "CoreProtect"),
    ("com.zrips.cmi", "CMI"),
    ("eu.decentsoftware.holograms", "DecentHolograms"),
    ("me.filoghost.holographicdisplays", "HolographicDisplays"),
    (
        "com.gmail.filoghost.holographicdisplays",
        "HolographicDisplays",
    ),
    ("net.dmulloy2", "ProtocolLib"),
];

/// The plugin that ships a class, for well-known packages.
pub fn plugin_for_class(class: &str) -> Option<&'static str> {
    let lower = class.to_ascii_lowercase();
    PACKAGE_OWNERS
        .iter()
        .find(|(pkg, _)| {
            lower.starts_with(pkg) && lower.as_bytes().get(pkg.len()).is_none_or(|&b| b == b'.')
        })
        .map(|(_, owner)| *owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jar_names() {
        assert_eq!(
            plugin_from_jar("EssentialsX-2.20.1.jar").as_deref(),
            Some("EssentialsX")
        );
        assert_eq!(
            plugin_from_jar("LuckPerms-Bukkit-5.4.102.jar").as_deref(),
            Some("LuckPerms-Bukkit")
        );
        assert_eq!(plugin_from_jar("Vault.jar").as_deref(), Some("Vault"));
        assert_eq!(
            plugin_from_jar("MyPlugin_v1.2.jar").as_deref(),
            Some("MyPlugin")
        );
        assert_eq!(plugin_from_jar("paper-1.20.4.jar"), None);
        assert_eq!(plugin_from_jar("netty-codec-4.1.97.Final.jar"), None);
        assert_eq!(plugin_from_jar("patched_1.20.4.jar"), None);
        assert_eq!(plugin_from_jar("server.jar"), None);
        assert_eq!(
            plugin_from_jar("ServerUtils-1.0.jar").as_deref(),
            Some("ServerUtils")
        );
    }

    #[test]
    fn packages() {
        assert_eq!(
            plugin_for_class("net.milkbowl.vault.economy.Economy"),
            Some("Vault")
        );
        assert_eq!(plugin_for_class("net.milkbowl.vaultx.Foo"), None);
        assert_eq!(plugin_for_class("org.example.Foo"), None);
    }

    #[test]
    fn tags() {
        assert!(is_plugin_tag("LuckPerms"));
        assert!(!is_plugin_tag("bootstrap"));
    }
}
