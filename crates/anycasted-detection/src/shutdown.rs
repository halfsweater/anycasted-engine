//! Shutdown failures, crashes reported in logs, and world/resource loading problems.

use std::sync::{Arc, LazyLock};

use anycasted_core::models::{Category, LogLevel, RuleMeta, Severity};
use regex::Regex;

use crate::plugins::DATA_SAVE_ID;
use crate::rule::{ExceptionRule, Extraction, LogRule, TextRule};

static SAVED_TO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)crash report has been saved to:?\s*(\S.*)").expect("valid regex")
});
static CHUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)chunk(?: at)?\s*\[?\(?\s*(-?\d+)\s*,\s*(-?\d+)\s*\]?\)?").expect("valid regex")
});
static WORLD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:in world|world) '([^']+)'").expect("valid regex"));

fn saved_path(text: &str) -> Option<Extraction> {
    let c = SAVED_TO.captures(text)?;
    let path = c[1].trim().to_owned();
    let file = path.rsplit(['/', '\\']).next().unwrap_or(&path).to_owned();
    Some(
        Extraction {
            headline: Some(file.clone()),
            detail: Some(path.clone()),
            group: Some(file.clone()),
            ..Extraction::default()
        }
        .var("file", file)
        .var("path", path),
    )
}

/// Chunk coordinates, region file and world from a chunk error message.
fn chunk_location(text: &str) -> Option<Extraction> {
    let mut e = Extraction::default();
    if let Some(c) = CHUNK.captures(text) {
        let (x, z): (i64, i64) = (c[1].parse().ok()?, c[2].parse().ok()?);
        e.group = Some(format!("{x},{z}"));
        e.headline = Some(format!("chunk {x}, {z}"));
        e.vars.push(("chunk", format!("{x}, {z}")));
        e.vars.push((
            "region_file",
            format!("r.{}.{}.mca", x.div_euclid(32), z.div_euclid(32)),
        ));
    }
    if let Some(c) = WORLD.captures(text) {
        e.vars.push(("world", c[1].to_owned()));
    }
    Some(e)
}

fn chunk_meta() -> Arc<RuleMeta> {
    RuleMeta::new("RESOURCE-CHUNK-LOAD-FAILED", Category::Resource, Severity::Error)
        .title("Chunk or region data could not be read")
        .description("Stored chunk or region data is corrupted or unreadable (decompression/format errors while reading region files). Affected chunks may fail to load or be regenerated.")
        .evidence("A chunk loading/reading error message, or a decompression exception (`DataFormatException`, `ZipException`, `EOFException`) while loading a chunk or region file.")
        .user_title("Part of the world is damaged[[: chunk {chunk}]][[ in '{world}']]")
        .explain("The saved world data[[ for chunk {chunk}]][[ in world '{world}']] is corrupted and can't be read[[ ({exception_message})]]. That area may fail to load, or the server may generate it again from scratch, which would erase anything built there. This is usually caused by the server being killed while saving, or by disk problems.")
        .fix(&[
            "Make a backup of the whole world folder before changing anything.",
            "Restore the damaged region from a backup if you have one[[: chunk {chunk} is stored in region/{region_file}]].",
            "If you have no backup, use a tool such as MCA Selector to delete just the damaged chunk so it regenerates (builds in that chunk will be lost).",
            "If damage keeps appearing, ask your host to check the disk, and always stop the server with /stop instead of killing it.",
        ])
        .shared()
}

/// Exception rules: decompression errors only mean corruption when the log entry is
/// about chunk or region data.
pub fn exception_rules() -> Vec<ExceptionRule> {
    vec![
        ExceptionRule::new(
            chunk_meta(),
            &[
                "java.util.zip.DataFormatException",
                "java.util.zip.ZipException",
                "java.io.EOFException",
                "java.io.UTFDataFormatException",
            ],
        )
        .context_any(&["chunk", "region"])
        .priority(40),
    ]
}

/// Text rules.
pub fn log_rules() -> Vec<Box<dyn LogRule>> {
    vec![
        TextRule::new(
            RuleMeta::new("CRASH-SERVER-THREAD", Category::Crash, Severity::Critical)
                .title("Server thread crashed")
                .description("The main server thread threw an exception it could not recover from and the server shut down.")
                .evidence("The server message `Encountered an unexpected exception`.")
                .user_title("The server crashed")
                .explain("The main server thread hit an error it couldn't recover from[[: {error_hint}]], so the server shut down and players were disconnected.")
                .fix(&[
                    "Look at the other problems in this report from the same moment; they usually explain the crash.",
                    "Open the crash report the server saved (in the crash-reports folder) and analyze it with Anycasted for more detail.",
                ])
                .context("This error crashed the server.")
                .shared(),
            &["encountered an unexpected exception"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("CRASH-REPORT-WRITTEN", Category::Crash, Severity::Info)
                .title("Crash report written")
                .description("The server wrote a crash report file containing the full details of the crash.")
                .evidence("The server message `This crash report has been saved to: <path>`.")
                .user_title("A crash report was saved[[: {file}]]")
                .explain("The server wrote a detailed crash report file. It contains more information about the crash than the log does.")
                .fix(&["Download {path|the crash report from the crash-reports folder} and analyze it with Anycasted."])
                .shared(),
            &["crash report has been saved to"],
        )
        .extract(saved_path)
        .boxed(),
        TextRule::new(
            RuleMeta::new("JVM-FATAL-ERROR", Category::Crash, Severity::Critical)
                .title("JVM fatal error")
                .description("The Java virtual machine itself crashed (e.g. SIGSEGV in native code); an hs_err_pid<N>.log file has details.")
                .evidence("The JVM banner `A fatal error has been detected by the Java Runtime Environment`.")
                .user_title("Java itself crashed")
                .explain("The Java runtime crashed at a low level. This is not a normal plugin error: it's usually caused by a plugin's native (non-Java) library, a bug in Java, or a hardware or memory problem on the machine.")
                .fix(&[
                    "Look for a file named hs_err_pid<number>.log in the server folder and send it to your host or plugin authors.",
                    "Update Java to the newest release of the same version (for example the latest Java 21).",
                    "If it happens repeatedly, ask your host to check the machine's hardware.",
                ])
                .shared(),
            &["a fatal error has been detected by the java runtime environment"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("SHUTDOWN-EXCEPTION", Category::Shutdown, Severity::Error)
                .title("Exception while stopping the server")
                .description("The server encountered an exception during shutdown; data saved during shutdown may be incomplete.")
                .evidence("The server message `Exception stopping the server` / `Exception while stopping`.")
                .user_title("An error happened while the server was stopping")
                .explain("Something went wrong while the server was shutting down[[: {error_hint}]]. World or plugin data that is saved at shutdown may be incomplete.")
                .fix(&[
                    "After the next start, check that the world and plugin data look right.",
                    "Update the plugin mentioned in the error, if any.",
                ])
                .context("It happened while the server was shutting down, so some data may not have been saved.")
                .shared(),
            &["exception stopping the server", "exception while stopping", "error while shutting down"],
        )
        .boxed(),
        TextRule::new(
            RuleMeta::new("RESOURCE-CHUNK-SAVE-FAILED", Category::Resource, Severity::Error)
                .title("Failed to save world data")
                .description("The server could not write chunk, entity or player data to disk; recent world changes may be lost.")
                .evidence("A server message such as `Failed to save chunk`, `Failed to store chunk` or `Couldn't save chunk`.")
                .user_title("The server couldn't save part of the world")
                .explain("Saving world data to disk failed. Recent changes to the world or player data may be lost if the server stops.")
                .fix(&[
                    "Check that the disk isn't full (and that your plan's storage limit isn't reached).",
                    "Make sure the server is allowed to write to the world folder.",
                    "Ask your host to check the disk for errors if it keeps happening.",
                ])
                .shared(),
            &["failed to save chunk", "failed to store chunk", "couldn't save chunk", "failed to save player data", "failed to save level"],
        )
        .superseded_by(&[DATA_SAVE_ID])
        .boxed(),
        TextRule::new(
            chunk_meta(),
            &[
                "exception loading chunk",
                "error loading chunk",
                "couldn't load chunk",
                "failed to read chunk",
                "failed to load chunk",
                "is in the wrong location",
                "corrupted chunk",
            ],
        )
        .extract(chunk_location)
        .boxed(),
        TextRule::new(
            RuleMeta::new("RESOURCE-WORLD-LOAD-FAILED", Category::Resource, Severity::Critical)
                .title("World or data packs failed to load")
                .description("The server could not load the world (level.dat) or its data packs; the server usually fails to start.")
                .evidence("A server message such as `Failed to load level`, `Exception reading ./world/level.dat` or `Errors in currently selected data packs prevented the world from loading`.")
                .user_title("The world couldn't be loaded")
                .explain("The server couldn't load the world's main data (level.dat) or one of its data packs, so it usually can't start.")
                .fix(&[
                    "Back up the world folder first.",
                    "If level.dat is damaged, replace it with level.dat_old from the same folder (or a backup).",
                    "If data packs are mentioned, remove or update them in the world's datapacks folder.",
                ])
                .shared(),
            &["failed to load level", "level.dat", "errors in currently selected data packs", "failed to load datapacks", "failed to load data packs"],
        )
        .excluding(&["preparing level", "level.dat_old"])
        .min_level(LogLevel::Warn)
        .boxed(),
    ]
}
