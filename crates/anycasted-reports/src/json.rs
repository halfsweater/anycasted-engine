//! JSON rendering of reports.

use std::io::Write;

use anycasted_core::models::Report;

/// Serializes a report as pretty-printed JSON.
pub fn to_json_pretty(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

/// Serializes a report as compact JSON.
pub fn to_json(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string(report)
}

/// Writes a report as pretty-printed JSON followed by a newline.
pub fn write_json<W: Write>(report: &Report, mut writer: W) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, report)?;
    writer.write_all(b"\n")?;
    writer.flush()
}
