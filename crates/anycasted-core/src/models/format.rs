//! Input format identification.

use std::fmt;

use serde::Serialize;

use super::finding::Evidence;

/// Identified input format / server software.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// PaperMC server log.
    Paper,
    /// Purpur (Paper fork) server log.
    Purpur,
    /// Spigot / CraftBukkit server log.
    Spigot,
    /// Vanilla (Mojang) dedicated server log.
    Vanilla,
    /// Velocity proxy log.
    Velocity,
    /// Fabric server log.
    Fabric,
    /// Forge / NeoForge server log.
    Forge,
    /// Recognizable Minecraft/log4j line syntax, but the server software could not be
    /// identified.
    GenericMinecraft,
    /// A Minecraft crash report.
    CrashReport,
    /// No known structure was recognized.
    Unknown,
}

impl LogFormat {
    /// Display name.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Paper => "Paper",
            Self::Purpur => "Purpur",
            Self::Spigot => "Spigot",
            Self::Vanilla => "Vanilla",
            Self::Velocity => "Velocity",
            Self::Fabric => "Fabric",
            Self::Forge => "Forge",
            Self::GenericMinecraft => "Minecraft (unidentified software)",
            Self::CrashReport => "Minecraft crash report",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// How certain the format identification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FormatConfidence {
    /// Only generic structure matched; software unknown.
    Low,
    /// Indirect indicators matched (or identification by absence of other markers).
    Medium,
    /// The software explicitly identified itself (e.g. `This server is running Paper`).
    High,
}

/// Result of format detection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FormatDetection {
    /// Identified format.
    pub format: LogFormat,
    /// Confidence of the identification.
    pub confidence: FormatConfidence,
    /// `true` unless confidence is `high`.
    pub uncertain: bool,
    /// Lines that support the identification.
    pub indicators: Vec<Evidence>,
}
