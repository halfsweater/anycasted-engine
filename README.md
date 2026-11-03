# Anycasted Diagnostics Engine

The Rust core of **Anycasted**: deterministic, evidence-backed diagnostics for Minecraft
server logs (Paper, Purpur, Spigot, Vanilla, Velocity) and Minecraft crash reports.

Every finding cites verbatim lines from the input, with accurate line numbers. Detection is
rule-based (structured parsing + rules + correlation). No LLM is involved.

Findings are written for server owners. Each one gives a plain title naming the
affected plugin, server, port or file, says what happened, and lists numbered fix steps.
Technical details stay available for support staff (`--verbose`) and integrations (JSON).

```text
$ anycasted analyze logs/latest.log

  ▲ ANYCASTED  Diagnostics Engine v0.2.0
  ────────────────────────────────────────────
  File      latest.log
  Type      Paper log
  Server    Paper 1.21.1-123 · Minecraft 1.21.1 · Java 21 · 14 plugins
  Startup   finished in 6.2 s
  Checked   18,420 lines
  Result    1 problem found: 1 error

  ✖ ERROR  WelcomePlus needs a Vault chat provider  [plugin-001]

    What happened
      WelcomePlus asked Vault for the chat service, but no plugin is providing it, so
      WelcomePlus failed. Vault is only a bridge between plugins: another plugin has to
      actually provide the chat features. It happened when a player joined.

    How to fix
      1. Make sure Vault is installed and enabled (look for "Enabling Vault" when the server
         starts).
      2. Install a plugin that provides chat prefixes and suffixes, such as LuckPerms, then
         restart the server.
      3. If you already have one, make sure it starts before WelcomePlus and has no errors
         of its own in this report.
      4. If it still fails, update WelcomePlus.

    Seen once (line 1) · confidence: certain
    Log line 2: java.lang.NullPointerException: Cannot invoke "net.milkbowl.vault.chat.Chat.getPla…

  ✖ Done in 41 ms — 1 problem found
```

## Quick start

```bash
cargo build --release
./target/release/anycasted analyze latest.log                  # human-readable
./target/release/anycasted analyze latest.log --format json    # JSON to stdout
./target/release/anycasted analyze latest.log.gz -o report.json
./target/release/anycasted analyze crash-2024-04-21_18.03.11-server.txt --verbose
./target/release/anycasted rules                               # rule catalog (--json available)
./target/release/anycasted version
```

| Option | Meaning |
|---|---|
| `-f, --format text\|json` | Output format (default `text`; `json` when `--output` is given) |
| `-o, --output FILE` | Write the report to a file (a text summary is still printed) |
| `-v, --verbose` | Also show technical details: rule ids, all evidence lines, involved plugins, related problems |
| `--max-file-size MIB` | On-disk size limit (default 512 MiB) |
| `--max-decompressed-size MIB` | Decompressed bytes analyzed (default 2048 MiB) |
| `--repeat-threshold N` | Occurrences that trigger `PATTERN-REPEATED-ERROR` (default 25) |
| `--allow-any-extension` | Accept extensions other than `.log`/`.txt`/`.gz` (content is still checked) |
| `--no-color` / `NO_COLOR` | Disable colors |

**Exit codes:** `0` no error/critical findings · `1` analysis could not run · `2` usage
error · `3` highest severity is `error` · `4` at least one `critical` finding.

## Library use

```rust
use anycasted_engine::{Engine, EngineConfig};

let engine = Engine::new(EngineConfig::default())?;
let report = engine.analyze_path("latest.log".as_ref())?;          // or analyze_reader / analyze_bytes
let json = anycasted_engine::reports::to_json_pretty(&report)?;
```

`Engine` is `Clone + Send + Sync`. With the `async` feature,
`Engine::analyze_path_async` runs analysis on Tokio's blocking pool. That is the intended
integration point for the future Axum API layer, which should live in its own crate and
not inside the engine. See `examples/analyze_file.rs`.

## Architecture

```text
anycasted-engine/              root crate: the pipeline (`Engine`) wiring the stages
├── crates/
│   ├── anycasted-core         models, report schema, config/limits, errors, fingerprints
│   ├── anycasted-ingestion    bounded streaming line reader, gzip, binary/extension checks
│   ├── anycasted-parser       log headers, Java stack traces, event grouping,
│   │                          format detection, server profile, Velocity, crash reports
│   ├── anycasted-detection    rule framework + built-in rules + attribution
│   ├── anycasted-analysis     grouping/fingerprinting, correlation, scoring
│   ├── anycasted-reports      JSON and terminal rendering
│   └── anycasted-cli          `anycasted` binary
├── tests/                     integration tests + fixtures
└── examples/
```

The orchestration lives in the root crate (`src/pipeline.rs`) rather than in
`anycasted-core/src/engine.rs`, because it depends on every stage and `core` must stay
dependency-free so that all stages can share its models.

Pipeline (single pass, streaming):

1. **Ingestion** validates the path (regular file, size, extension), detects gzip by magic
   bytes, rejects binary content, and yields decoded lines. Invalid UTF-8 is decoded
   lossily, and NUL bytes, ANSI color codes and `\r` are stripped. Line length and total
   decompressed bytes are capped. Mid-stream errors (e.g. a truncated `.gz`) end the stream
   and mark the report incomplete instead of failing.
2. **Parsing** groups lines into `LogEvent`s (a header line plus continuation lines) and
   extracts timestamp (including midnight roll-over), level, thread, logger, plugin tag and
   chat/command detection. It parses `Caused by:`/`Suppressed:` chains with frames, module,
   source line and jar. In parallel it identifies the software and collects versions, Java/OS,
   plugin inventory, startup completion and shutdown markers. Crash reports are recognized
   by their header and parsed into sections and details.
3. **Detection** runs rules against each event. An Aho-Corasick prefilter selects the
   candidate text rules in one pass per line. For each exception chain, the rule matching
   the throwable closest to the root cause wins, with ties broken by priority. Chains
   without a specific rule produce `JAVA-UNCLASSIFIED-EXCEPTION`, so no logged failure is
   dropped silently.
4. **Analysis** groups hits by rule and fingerprint (stack signature without line numbers,
   or rule-specific keys such as plugin or endpoint). It keeps counts, first/last
   occurrence, bounded samples and representative evidence, then derives correlations,
   repetition findings and ordering.
5. **Reports** are rendered as JSON or text.

### Supported inputs

| Software | Line layouts recognized |
|---|---|
| Paper / Purpur / Spigot | `[T] [thread/LEVEL]: msg`, console `[T LEVEL]: msg`, legacy `YYYY-MM-DD T [LEVEL] msg` |
| Vanilla | `[T] [thread/LEVEL]: msg`, `[T] [thread/LEVEL] [logger]: msg` |
| Velocity | `[T] [thread/LEVEL] [logger]: msg`, `[T LEVEL] [plugin]: msg` |
| Forge (syntax only) | `[ddMMMyyyy T] [thread/LEVEL] [logger/]: msg` |
| Crash reports | `---- Minecraft Crash Report ----` documents |

Timestamps may include milliseconds or ISO dates. Lines that match no layout (raw stderr,
`Exception in thread "…"`, panel output) are still analyzed as header-less events. Format
identification reports `format_confidence` (`high` only when the software names itself)
and `format_uncertain`.

## Report schema (`schema_version` 2.0.0)

Top level: `schema_version`, `engine`, `input`, `server` (logs), `crash_report` (crash
reports), `summary`, `findings`, `correlations`. Empty inputs produce a valid report with
`findings: []`. Breaking changes bump the major schema version.

Each finding contains:

- **For server owners** (rendered with names from the log):
  - `title`: e.g. "Port 25565 is already in use".
  - `explanation`: what happened and what it affects.
  - `recommendations`: ordered fix steps.
  - `confidence_label`: `certain`, `likely`, `possible` or `speculative`.
  - `recovered`: the log line where the problem resolved itself, when it did. Its
    severity is then lowered one level.
- **For support and integrations:** `id` (`<category>-<nnn>`), `rule_id`,
  `technical_title`, `description`, `category`, `severity`, `classification`,
  `confidence`, `occurrences`, `first_seen`, `last_seen`, `repetition`,
  `evidence[]` (`line`, verbatim `text`, `role`, `timestamp`),
  `other_occurrence_lines`, `subject`, `implicated[]`, `fingerprint` (stable across
  runs and Rust versions), `notes` and `related`.

Schema 2.0.0 (engine 0.2.0) changed `title` and `recommendations` from technical text to
plain language, and added `explanation`, `technical_title`, `confidence_label`,
`recovered`, the `database` category and `subject`-aware grouping.

**One problem, one finding.** Servers often print a context message ("Could not pass event
PlayerJoinEvent to WelcomePlus", "Error occurred while enabling Foo", "Encountered an
unexpected exception") followed by the exception that explains it. Hits from the same log
entry are merged:
- A specific diagnosis (missing dependency, out of memory, Vault provider missing, …)
  absorbs the context. For example, "This error crashed the server." is added to an
  out-of-memory finding.
- When the exception is generic (NullPointerException, …), the context finding absorbs it
  and explains it in plain terms ("a value it needed (`this.chat`) was missing").

**Evidence.** `text` is the decoded input line, cut with `…` beyond 600 characters. The
test suite checks every evidence line of every fixture against the input file.

**Confidence** is the engine's confidence that the condition in the title is present in
the input. It is not a probability that the condition caused an outage. `1.0` means an
unambiguous signature (exception class, exact server message). `0.5–0.7` means a heuristic
(e.g. a missing startup completion marker, a nearly full heap at crash time). Below `0.5`
is a hypothesis for investigation.

**Classification** separates:
- `observed`: directly visible in the input.
- `likely_contributing`: the input suggests it contributed but does not prove it.
- `hypothesis`: plausible, unconfirmed (e.g. a plugin appears in stack frames or in a
  crash report's "Suspected Mods").

**Attribution.** `subject.plugin` is set only when the log names the plugin (its logger
tag, or a server message such as `Could not pass event … to Foo`). A plugin whose jar
appears in stack frames is listed under `implicated` as a `hypothesis` with basis
`stack_frame`. Server and library jars (paper, netty, guava, …) are never implicated.
`seen_loading` records whether the implicated plugin was seen loading in the same log.

**Correlations** are `same_event` (printed in one log entry), `temporal_cluster`,
`preceded_shutdown`, `near_end_of_log` and `same_plugin`. Apart from `same_event`, they
express proximity only, and their descriptions say so.

## Rules

`anycasted rules` lists all 72 rules. Categories: `exception`, `memory`, `dependency`,
`plugin`, `startup`, `configuration`, `networking`, `database`, `performance`,
`shutdown`, `resource`, `crash`, `pattern`. Each rule has:
- an id, category, severity, classification and confidence;
- a technical title, description and evidence requirement;
- plain-language title, explanation and fix-step templates;
- a merge role (specific, context or generic cause);
- optional recovery markers. Highlights:

- **Java:** `JAVA-NULL-POINTER`, `-ILLEGAL-STATE`, `-ILLEGAL-ARGUMENT`,
  `-CONCURRENT-MODIFICATION`, `-STACK-OVERFLOW`, `-CLASS-NOT-FOUND`, `-NO-CLASS-DEF-FOUND`,
  `-NO-SUCH-METHOD`, `-NO-SUCH-FIELD`, `-INCOMPATIBLE-CLASS-CHANGE`, `-UNCLASSIFIED-EXCEPTION`.
- **Memory:** `MEM-HEAP-EXHAUSTED`, `-GC-OVERHEAD`, `-DIRECT-BUFFER`, `-METASPACE`,
  `-NATIVE-THREAD`, `-OUT-OF-MEMORY`, `-JVM-TERMINATED-OOM`, `-NATIVE-ALLOCATION-FAILED`.
- **Plugins:**
  - enable/load/disable failures;
  - missing dependencies (checked against the plugin inventory);
  - Vault chat/economy/permission provider missing;
  - plugin doesn't support the server version, or needs a newer API version;
  - invalid plugin.yml;
  - listener/task/command errors (with event names turned into phrases such as "a
    player joined");
  - async API misuse;
  - failed data saves;
  - duplicates, `/reload`, legacy API and nag messages.
- **Database:** login rejected (user and host extracted), database unreachable or
  connection pool exhausted. Both are marked recovered when the plugin later reconnects.
- **Startup / config:** port bind, EULA, Java version mismatch, failed start, startup
  incomplete, invalid YAML/JSON, unreadable `server.properties`.
- **Networking:** connection refused, timeouts, DNS failures, connection resets (info),
  proxy forwarding misconfiguration, unreachable backends.
- **Performance:** server lag (merging "can't keep up" and low TPS reports), watchdog
  stall and crash.
- **Crashes:** server thread crash, JVM fatal error, crash report signatures (ticking
  entity/block entity with type and location, watchdog, world generation, NBT), low heap
  at crash, suspected mods.
- **World / resources:** corrupted chunks (coordinates, world and region file, including
  decompression errors while loading chunks), world/data pack load failures, failed
  saves.
- **Other:** shutdown exceptions, repeated errors.

### Adding a rule

```rust
use anycasted_engine::core::models::{Category, RuleMeta, Severity};
use anycasted_engine::detection::{RuleSet, TextRule};

let meta = RuleMeta::new("CUSTOM-RULE", Category::Plugin, Severity::Warning)
    .title("…").description("…").evidence("…")          // technical
    .user_title("{plugin|A plugin} did something odd")     // plain language
    .explain("{plugin|A plugin} …[[ on port {port}]].")
    .fix(&["Update {plugin|the plugin}.", "[[Free up port {port}.]]"])
    .shared();
let rules = RuleSet::builtin().with_log_rule(TextRule::new(meta, &["needle"]).boxed());
let engine = anycasted_engine::Engine::with_rules(Default::default(), rules)?;
```

`TextRule` (substrings + optional extractor), `ExceptionRule` (class + message +
priority) and the `LogRule`/`CrashRule` traits cover the built-in rules. Built-in rules
live in `crates/anycasted-detection/src/*.rs` by domain. The engine does not change when
rules are added.

**Template syntax for user-facing text:**
- `{var}` inserts a variable extracted from the log (`plugin`, `port`, `dependency`,
  `missing_class`, `endpoint`, `chunk`, `exception_message`, `error_hint`, …).
- `{var|fallback}` uses the fallback when the variable is unknown.
- `[[ … ]]` is an optional segment, dropped unless all of its variables are known.

**Validation.** `RuleSet::validate` rejects:
- malformed ids or missing texts;
- templates where a variable outside `[[ … ]]` has no fallback;
- context rules without a context note;
- one id used with conflicting metadata.

A test also checks that no rendered finding contains leftover template syntax.

## Resource limits and security

All limits are in `anycasted_core::Limits` (serde-configurable): on-disk size (512 MiB),
decompressed bytes (2 GiB, the gzip-bomb guard), bytes per line (64 KiB), retained lines
per event (2,000), frames per exception (256), finding groups (5,000), evidence per
finding (8), crash report lines (200,000), plugin inventory (1,024).

- Input is never executed, and no shell or subprocess is used.
- Paths must be regular files. Content must not look binary.
- All regexes use the `regex` crate, which runs in linear time with no backtracking. Most
  matching is substring or Aho-Corasick based.
- Internal tracing never logs input content.
- Player chat and command echoes are never used as evidence.

## Performance

Measured with a release build on a synthetic 1-million-line (about 80 MB) Paper log with
about 6,000 problems:

| Input | Time | Peak RSS |
|---|---|---|
| 81 MB plain (v0.1) | 1.2 s | 11 MiB |
| 8.7 MB `.gz`, same content (v0.1) | 1.6 s | 11 MiB |
| ~80 MB plain (v0.2, with merging and plain-language rendering) | 1.4 s | — |

Memory is bounded by the limits above, not by input size. `cargo run --release --example
bench_stages -- <file>` times each stage. Rayon is not used: the pipeline is a single
streaming pass dominated by line decoding and parsing. Parallelizing it would require
chunking with stack-trace-aware boundaries, which is not justified at the current
throughput. Revisit when profiling multi-GB inputs.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo test --all-features            # 122 tests: unit + integration
```

Integration tests (`tests/`):
- `scenario_tests.rs`: 13 real-world-style logs in `tests/fixtures/scenarios`. Each test
  pins the exact problems reported and the plain-language titles shown to users.
- `parser_tests.rs`: header layouts, multi-line grouping, line numbers, crash sections,
  midnight roll-over, randomized malformed input.
- `detection_tests.rs`: every fixture's evidence is verified against the input; rules,
  attribution, grouping, correlations, negative tests, JSON shape.
- `ingestion_tests.rs`: gzip (single, concatenated, truncated), decompression bomb,
  invalid UTF-8/NUL/CRLF/ANSI, truncated logs, binary/extension/directory/missing/oversize
  rejection, overlong lines, a 250,000-line log.

Fixtures cover Paper (clean, plugin failures, OOM), Purpur, Velocity, Vanilla, legacy
Spigot, two crash reports, an empty file and non-log text.

## Not yet implemented

- The Axum API layer (planned as a separate crate on top of `Engine`).
- Mod-specific rules for Forge/Fabric (their line syntax is parsed and identified, but
  rules target Bukkit-family servers and Velocity). No BungeeCord-specific markers.
- `hs_err_pid*.log` JVM crash files and Paper thread-dump analysis beyond detecting the
  watchdog messages.
- Cross-file correlation (e.g. a proxy log together with backend logs).
- The fixtures are realistic reconstructions of real log formats, not captured production
  logs. Validating against a corpus of real customer logs is the next accuracy milestone.
