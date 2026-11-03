//! `anycasted-api` — HTTP server for the Anycasted Diagnostics Engine.
//!
//! Configuration (environment variables):
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `ANYCASTED_ADDR` | `127.0.0.1:8080` | Listen address |
//! | `ANYCASTED_API_KEY` | unset | If set, `/v1/*` requires `Authorization: Bearer <key>` |
//! | `ANYCASTED_MAX_UPLOAD_MIB` | `64` | Maximum upload size |
//! | `ANYCASTED_MAX_CONCURRENT` | CPU count | Analyses running at once |
//! | `RUST_LOG`-style level via `ANYCASTED_LOG` | `info` | `error`, `warn`, `info`, `debug` |

use std::process::ExitCode;

use anycasted_api::{ApiConfig, router};
use anycasted_engine::{Engine, EngineConfig};

const MIB: u64 = 1024 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    let level = match std::env::var("ANYCASTED_LOG").as_deref() {
        Ok("error") => tracing::Level::ERROR,
        Ok("warn") => tracing::Level::WARN,
        Ok("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .try_init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let mut config = ApiConfig {
        api_key: std::env::var("ANYCASTED_API_KEY")
            .ok()
            .filter(|k| !k.is_empty()),
        ..ApiConfig::default()
    };
    if let Some(mib) = env_number("ANYCASTED_MAX_UPLOAD_MIB")? {
        config.max_upload_bytes = mib.saturating_mul(MIB);
    }
    if let Some(n) = env_number("ANYCASTED_MAX_CONCURRENT")? {
        config.max_concurrent = usize::try_from(n).unwrap_or(usize::MAX);
    }
    let addr = std::env::var("ANYCASTED_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());

    let mut engine_config = EngineConfig::default();
    engine_config.limits.max_file_bytes = config.max_upload_bytes;
    let engine = Engine::new(engine_config).map_err(|e| e.to_string())?;

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("could not listen on {addr}: {e}"))?;
    tracing::info!(
        %addr,
        auth = config.api_key.is_some(),
        max_upload_mib = config.max_upload_bytes / MIB,
        "anycasted-api listening"
    );
    if config.api_key.is_none() {
        tracing::warn!("ANYCASTED_API_KEY is not set; the API is open to anyone who can reach it");
    }

    axum::serve(listener, router(engine, &config))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
        .map_err(|e| e.to_string())
}

fn env_number(name: &str) -> Result<Option<u64>, String> {
    match std::env::var(name) {
        Ok(v) => v
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| format!("{name} must be a whole number, got {v:?}")),
        Err(_) => Ok(None),
    }
}
