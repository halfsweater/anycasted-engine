//! HTTP API for the Anycasted Diagnostics Engine.
//!
//! | Method | Path | Description |
//! |---|---|---|
//! | `GET` | `/health` | Liveness check (never requires auth) |
//! | `GET` | `/v1/version` | Engine and report schema versions |
//! | `GET` | `/v1/rules` | Rule catalog as JSON |
//! | `POST` | `/v1/analyze` | Analyze a log or crash report (raw body or multipart `file` field) |
//!
//! `POST /v1/analyze` query parameters:
//! - `filename`: display name for a raw-body upload (default `upload.log`).
//! - `format`: `json` (default) or `text`.
//! - `verbose`: `true` to include technical details in `text` output.
//!
//! Errors are returned as `{"error": {"code": "...", "message": "..."}}`.

use std::sync::Arc;

use anycasted_engine::core::models::Report;
use anycasted_engine::reports::{self, TextOptions};
use anycasted_engine::{Engine, EngineError};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;

/// Default display name for raw-body uploads.
const DEFAULT_FILENAME: &str = "upload.log";

/// API server settings.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// When set, `/v1/*` requires `Authorization: Bearer <key>`.
    pub api_key: Option<String>,
    /// Maximum request body size in bytes (also the engine's input size limit).
    pub max_upload_bytes: u64,
    /// Maximum analyses running at the same time; further requests wait.
    pub max_concurrent: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            max_upload_bytes: 64 * 1024 * 1024,
            max_concurrent: std::thread::available_parallelism().map_or(4, |n| n.get()),
        }
    }
}

#[derive(Clone)]
struct AppState {
    engine: Engine,
    api_key: Option<Arc<str>>,
    permits: Arc<Semaphore>,
}

/// Builds the router. `engine` should be configured with
/// `limits.max_file_bytes <= config.max_upload_bytes`.
pub fn router(engine: Engine, config: &ApiConfig) -> Router {
    let state = AppState {
        engine,
        api_key: config.api_key.as_deref().map(Arc::from),
        permits: Arc::new(Semaphore::new(config.max_concurrent.max(1))),
    };
    let body_limit = usize::try_from(config.max_upload_bytes).unwrap_or(usize::MAX);
    let v1 = Router::new()
        .route("/version", get(version))
        .route("/rules", get(rules))
        .route("/analyze", post(analyze))
        .layer(DefaultBodyLimit::max(body_limit))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_key));
    Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .nest("/v1", v1)
        .fallback(|| async {
            ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
        })
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A JSON error response.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": { "code": self.code, "message": self.message } });
        (self.status, Json(body)).into_response()
    }
}

impl From<EngineError> for ApiError {
    fn from(e: EngineError) -> Self {
        let (status, code) = match &e {
            EngineError::FileTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "file_too_large"),
            EngineError::UnsupportedInput(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_input")
            }
            EngineError::Io { .. } => (StatusCode::BAD_REQUEST, "unreadable_input"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        Self::new(status, code, e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async fn require_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if let Some(expected) = &state.api_key {
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !constant_time_eq(given.as_bytes(), expected.as_bytes()) {
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid API key (use `Authorization: Bearer <key>`)",
            )
            .into_response();
        }
    }
    next.run(request).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "engine": anycasted_engine::core::ENGINE_NAME,
        "version": anycasted_engine::core::ENGINE_VERSION,
        "report_schema": anycasted_engine::core::REPORT_SCHEMA_VERSION,
    }))
}

async fn rules(State(state): State<AppState>) -> Response {
    let catalog = state.engine.rule_catalog();
    let metas: Vec<_> = catalog.iter().map(|m| m.as_ref()).collect();
    Json(metas).into_response()
}

#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Format {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Default, Deserialize)]
struct AnalyzeQuery {
    filename: Option<String>,
    #[serde(default)]
    format: Format,
    #[serde(default)]
    verbose: bool,
}

async fn analyze(
    State(state): State<AppState>,
    Query(query): Query<AnalyzeQuery>,
    request: Request,
) -> Result<Response, ApiError> {
    let is_multipart = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("multipart/form-data"));

    let (name, bytes) = if is_multipart {
        read_multipart(request).await?
    } else {
        let bytes = Bytes::from_request(request, &())
            .await
            .map_err(|e| ApiError::new(e.status(), "invalid_body", e.body_text()))?;
        let name = query
            .filename
            .clone()
            .unwrap_or_else(|| DEFAULT_FILENAME.into());
        (name, bytes)
    };
    if bytes.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_body",
            "send the log as the request body, or as a multipart field named `file`",
        ));
    }

    let report = run_analysis(&state, name, bytes).await?;
    Ok(match query.format {
        Format::Json => Json(report).into_response(),
        Format::Text => {
            let opts = TextOptions {
                color: false,
                verbose: query.verbose,
            };
            let mut text = reports::banner(opts);
            text.push_str(&reports::render(&report, opts));
            ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response()
        }
    })
}

async fn read_multipart(request: Request) -> Result<(String, Bytes), ApiError> {
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|e| ApiError::new(e.status(), "invalid_multipart", e.body_text()))?;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::new(e.status(), "invalid_multipart", e.body_text()))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let name = field
            .file_name()
            .map(sanitize_filename)
            .unwrap_or_else(|| DEFAULT_FILENAME.into());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::new(e.status(), "invalid_multipart", e.body_text()))?;
        return Ok((name, bytes));
    }
    Err(ApiError::new(
        StatusCode::BAD_REQUEST,
        "missing_file",
        "multipart request has no field named `file`",
    ))
}

/// Keeps only the final path component of a client-supplied filename.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    if base.is_empty() {
        DEFAULT_FILENAME.into()
    } else {
        base.chars().take(255).collect()
    }
}

async fn run_analysis(state: &AppState, name: String, bytes: Bytes) -> Result<Report, ApiError> {
    let _permit = state.permits.acquire().await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
        )
    })?;
    let engine = state.engine.clone();
    tokio::task::spawn_blocking(move || engine.analyze_bytes(&name, bytes.into()))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "analysis failed",
            )
        })?
        .map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_reduced_to_basename() {
        assert_eq!(sanitize_filename("../../etc/latest.log"), "latest.log");
        assert_eq!(sanitize_filename("C:\\logs\\crash.txt"), "crash.txt");
        assert_eq!(sanitize_filename("dir/"), DEFAULT_FILENAME);
    }

    #[test]
    fn key_comparison() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
