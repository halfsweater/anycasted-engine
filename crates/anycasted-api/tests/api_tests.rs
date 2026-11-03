//! End-to-end tests of the HTTP API (in-process, no network).

use anycasted_api::{ApiConfig, router};
use anycasted_engine::{Engine, EngineConfig};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/scenarios/11-port-in-use.log"
);

fn app(api_key: Option<&str>, max_upload_bytes: u64) -> axum::Router {
    let config = ApiConfig {
        api_key: api_key.map(Into::into),
        max_upload_bytes,
        max_concurrent: 2,
    };
    let mut engine_config = EngineConfig::default();
    engine_config.limits.max_file_bytes = max_upload_bytes;
    router(Engine::new(engine_config).unwrap(), &config)
}

async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn analyze_raw_body_returns_json_report() {
    let log = std::fs::read(FIXTURE).unwrap();
    let req = Request::post("/v1/analyze?filename=latest.log")
        .body(Body::from(log))
        .unwrap();
    let (status, body) = send(app(None, 1 << 20), req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let report: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(report["input"]["filename"], "latest.log");
    assert!(report["summary"]["total_findings"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn analyze_multipart_and_text_format() {
    let log = std::fs::read_to_string(FIXTURE).unwrap();
    let boundary = "XBOUNDARYX";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../x/latest.log\"\r\n\
         Content-Type: text/plain\r\n\r\n{log}\r\n--{boundary}--\r\n"
    );
    let req = Request::post("/v1/analyze?format=text")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let (status, body) = send(app(None, 1 << 20), req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("latest.log"));
    assert!(
        !body.contains('\x1b'),
        "text output must not contain ANSI colors"
    );
}

#[tokio::test]
async fn api_key_is_enforced() {
    let (status, _) = send(
        app(Some("secret"), 1 << 20),
        Request::get("/v1/rules").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = send(
        app(Some("secret"), 1 << 20),
        Request::get("/v1/rules")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        serde_json::from_str::<Vec<serde_json::Value>>(&body)
            .unwrap()
            .len()
            > 10
    );

    let (status, _) = send(
        app(Some("secret"), 1 << 20),
        Request::get("/health").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "health check must not need a key");
}

#[tokio::test]
async fn errors_are_json() {
    let (status, body) = send(
        app(None, 16),
        Request::post("/v1/analyze")
            .body(Body::from(vec![b'a'; 64]))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");

    let (status, body) = send(
        app(None, 1 << 20),
        Request::post("/v1/analyze").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], "empty_body");

    let (status, body) = send(
        app(None, 1 << 20),
        Request::post("/v1/analyze")
            .body(Body::from([0u8, 1, 2, 3, 0, 0, 0xff, 7].repeat(64)))
            .unwrap(),
    )
    .await;
    assert!(status.is_client_error(), "binary input: {status} {body}");
}
