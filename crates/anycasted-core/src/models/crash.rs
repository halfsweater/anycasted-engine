//! Minecraft crash report model.

use serde::Serialize;

use super::event::SourceLine;
use super::java::ExceptionChain;

/// A value together with the source line it was read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Located<T> {
    /// The value.
    pub value: T,
    /// 1-based source line.
    pub line: u64,
}

impl<T> Located<T> {
    /// Creates a located value.
    pub fn new(value: T, line: u64) -> Self {
        Self { value, line }
    }
}

/// A `Key: Value` entry inside a crash report section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrashDetail {
    /// Key as printed.
    pub key: String,
    /// Value as printed (may be empty when the value continues on nested lines).
    pub value: String,
    /// 1-based source line.
    pub line: u64,
    /// Indentation depth (1 for top-level details, 2+ for nested ones).
    pub depth: u8,
}

/// A `-- Name --` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrashSection {
    /// Section name (`Head`, `System Details`, `Entity being ticked`, ...).
    pub name: String,
    /// Line of the section header.
    pub line: u64,
    /// Details in printed order.
    pub details: Vec<CrashDetail>,
}

impl CrashSection {
    /// Finds a detail by key, case-insensitively.
    pub fn detail(&self, key: &str) -> Option<&CrashDetail> {
        self.details
            .iter()
            .find(|d| d.key.eq_ignore_ascii_case(key))
    }
}

/// JVM heap figures from the `Memory:` system detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryInfo {
    /// Free bytes in the currently allocated heap.
    pub free_bytes: u64,
    /// Currently allocated heap bytes.
    pub total_bytes: u64,
    /// Maximum heap bytes (`-Xmx`).
    pub max_bytes: u64,
    /// Source line.
    pub line: u64,
}

impl MemoryInfo {
    /// Heap in use as a fraction of the maximum heap (0.0-1.0).
    pub fn used_fraction_of_max(&self) -> f64 {
        if self.max_bytes == 0 {
            return 0.0;
        }
        self.total_bytes.saturating_sub(self.free_bytes) as f64 / self.max_bytes as f64
    }
}

/// A parsed Minecraft crash report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrashReport {
    /// Line of `---- Minecraft Crash Report ----`.
    pub header_line: u64,
    /// `Time:` value.
    pub time: Option<Located<String>>,
    /// `Description:` value.
    pub description: Option<Located<String>>,
    /// The main exception chain printed after the description.
    pub exception: Option<ExceptionChain>,
    /// Source lines of the main exception block.
    pub exception_lines: Vec<SourceLine>,
    /// Sections in printed order.
    pub sections: Vec<CrashSection>,
    /// `Minecraft Version`.
    pub minecraft_version: Option<Located<String>>,
    /// `Java Version`.
    pub java_version: Option<Located<String>>,
    /// `Operating System`.
    pub operating_system: Option<Located<String>>,
    /// Parsed `Memory`.
    pub memory: Option<MemoryInfo>,
    /// `JVM Flags`.
    pub jvm_flags: Option<Located<String>>,
    /// Server brand (`Is Modded`, `BrandInfo`, `Server Brand`).
    pub server_brand: Option<Located<String>>,
    /// Mods listed under `Suspected Mods` / `Suspected Mod` (excluding `None`).
    pub suspected_mods: Vec<Located<String>>,
    /// Plugin names listed in CraftBukkit information.
    pub plugins: Vec<String>,
    /// Number of lines in the report.
    pub total_lines: u64,
}

impl CrashReport {
    /// Finds a section by name, case-insensitively.
    pub fn section(&self, name: &str) -> Option<&CrashSection> {
        self.sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// Finds the first detail with `key` in any section.
    pub fn detail(&self, key: &str) -> Option<&CrashDetail> {
        self.sections.iter().find_map(|s| s.detail(key))
    }
}
