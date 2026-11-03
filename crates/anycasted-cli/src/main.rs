//! `anycasted` — command-line interface for the Anycasted Diagnostics Engine.
//!
//! Exit codes:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Analysis completed; no `error` or `critical` findings |
//! | 1 | Analysis could not run (missing file, unsupported input, I/O error) |
//! | 2 | Invalid command-line usage |
//! | 3 | Analysis completed; highest severity is `error` |
//! | 4 | Analysis completed; at least one `critical` finding |

use std::fs::File;
use std::io::{BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anycasted_engine::core::models::{Report, Severity};
use anycasted_engine::reports::{self, TextOptions};
use anycasted_engine::{Engine, EngineConfig};
use clap::{Args, Parser, Subcommand, ValueEnum};

const EXIT_FAILURE: u8 = 1;
const EXIT_ERRORS: u8 = 3;
const EXIT_CRITICAL: u8 = 4;
const MIB: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "anycasted",
    about = "Anycasted Diagnostics Engine — evidence-backed Minecraft server diagnostics",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a server log (.log, .txt, .gz) or a crash report.
    Analyze(AnalyzeArgs),
    /// List the detection rules.
    Rules {
        /// Print the rule catalog as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print version information.
    Version,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable summary.
    Text,
    /// Versioned JSON report.
    Json,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// File to analyze.
    path: PathBuf,
    /// Output format (default: text, or json when --output is given).
    #[arg(long, short = 'f', value_enum)]
    format: Option<OutputFormat>,
    /// Write the report to this file instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,
    /// Also show technical details (rule ids, all log lines, related problems).
    #[arg(long, short = 'v')]
    verbose: bool,
    /// Print internal debug logs to stderr.
    #[arg(long, hide = true)]
    debug: bool,
    /// Disable colored output.
    #[arg(long)]
    no_color: bool,
    /// Maximum input file size on disk, in MiB.
    #[arg(long, value_name = "MIB")]
    max_file_size: Option<u64>,
    /// Maximum decompressed bytes analyzed, in MiB.
    #[arg(long, value_name = "MIB")]
    max_decompressed_size: Option<u64>,
    /// Occurrences at which a finding is additionally reported as a repeated error.
    #[arg(long, value_name = "N")]
    repeat_threshold: Option<u64>,
    /// Accept files with any extension (content is still checked).
    #[arg(long)]
    allow_any_extension: bool,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };
    match cli.command {
        Command::Analyze(args) => analyze(&args),
        Command::Rules { json } => rules(json),
        Command::Version => {
            println!(
                "{} {}",
                anycasted_engine::core::ENGINE_NAME,
                anycasted_engine::core::ENGINE_VERSION
            );
            println!(
                "report schema {}",
                anycasted_engine::core::REPORT_SCHEMA_VERSION
            );
            ExitCode::SUCCESS
        }
    }
}

fn init_tracing(debug: bool) {
    let level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn config_from(args: &AnalyzeArgs) -> EngineConfig {
    let mut config = EngineConfig::default();
    if let Some(mib) = args.max_file_size {
        config.limits.max_file_bytes = mib.saturating_mul(MIB);
    }
    if let Some(mib) = args.max_decompressed_size {
        config.limits.max_decompressed_bytes = mib.saturating_mul(MIB);
    }
    if let Some(n) = args.repeat_threshold {
        config.analysis.repeated_error_threshold = n;
    }
    config.allow_any_extension = args.allow_any_extension;
    config
}

fn use_color(args: &AnalyzeArgs) -> bool {
    !args.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn analyze(args: &AnalyzeArgs) -> ExitCode {
    init_tracing(args.debug);
    let format = args.format.unwrap_or(if args.output.is_some() {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    });
    let text = TextOptions {
        color: use_color(args),
        verbose: args.verbose,
    };
    let show_text_summary = format == OutputFormat::Text || args.output.is_some();
    if show_text_summary {
        print!("{}", reports::banner(text));
    }

    let started = Instant::now();
    let result = Engine::new(config_from(args)).and_then(|engine| engine.analyze_path(&args.path));
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let elapsed = started.elapsed();

    if let Some(path) = &args.output {
        if let Err(e) = write_report(&report, format, text, path) {
            eprintln!("error: could not write {}: {e}", path.display());
            return ExitCode::from(EXIT_FAILURE);
        }
        print!("{}", reports::render(&report, text));
        println!("\n  Report written to {}", path.display());
    } else if format == OutputFormat::Json {
        if let Err(e) = reports::write_json(&report, std::io::stdout().lock()) {
            eprintln!("error: could not write report: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    } else {
        print!("{}", reports::render(&report, text));
    }
    if show_text_summary {
        print_completion(&report, elapsed, text.color);
    }
    exit_code(&report)
}

fn write_report(
    report: &Report,
    format: OutputFormat,
    text: TextOptions,
    path: &Path,
) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    match format {
        OutputFormat::Json => reports::write_json(report, writer),
        OutputFormat::Text => {
            let plain = TextOptions {
                color: false,
                ..text
            };
            writer.write_all(reports::banner(plain).as_bytes())?;
            writer.write_all(reports::render(report, plain).as_bytes())?;
            writer.flush()
        }
    }
}

fn print_completion(report: &Report, elapsed: std::time::Duration, color: bool) {
    let total = report.summary.total_findings;
    let (mark, code) = match report.summary.highest_severity {
        Some(Severity::Critical | Severity::Error) => ("✖", "1;31"),
        Some(Severity::Warning) => ("⚠", "1;33"),
        _ => ("✔", "1;32"),
    };
    let found = match total {
        0 => "no problems found".to_owned(),
        1 => "1 problem found".to_owned(),
        n => format!("{n} problems found"),
    };
    let line = format!("{mark} Done in {} ms — {found}", elapsed.as_millis());
    if color {
        println!("\n  \x1b[{code}m{line}\x1b[0m\n");
    } else {
        println!("\n  {line}\n");
    }
}

fn exit_code(report: &Report) -> ExitCode {
    match report.summary.highest_severity {
        Some(Severity::Critical) => ExitCode::from(EXIT_CRITICAL),
        Some(Severity::Error) => ExitCode::from(EXIT_ERRORS),
        _ => ExitCode::SUCCESS,
    }
}

fn rules(json: bool) -> ExitCode {
    let engine = match Engine::new(EngineConfig::default()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let catalog = engine.rule_catalog();
    if json {
        let metas: Vec<_> = catalog.iter().map(|m| m.as_ref()).collect();
        match serde_json_string(&metas) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(EXIT_FAILURE);
            }
        }
    } else {
        for m in &catalog {
            println!(
                "{:<34} {:<9} {:<14} {}",
                m.id,
                m.severity.as_str(),
                m.category.as_str(),
                m.title
            );
        }
        println!("\n{} rules", catalog.len());
    }
    ExitCode::SUCCESS
}

fn serde_json_string<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}
