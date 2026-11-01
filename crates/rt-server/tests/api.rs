//! Integration tests for the REST surface.
//!
//! Every test drives the `axum::Router` directly through
//! `tower::ServiceExt::oneshot`, so no socket is bound and the suite stays fast
//! and deterministic. One test additionally exercises [`rt_server::serve`] over
//! a real loopback socket to prove the listener and graceful shutdown work.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use rt_core::config::{ApiKeyConfig, Config, ResolvedPaths, UserConfig};
use rt_core::crypto;
use rt_core::logging::{AuditLog, LogEventSink};
use rt_server::{router, AppState, ServerOptions};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

/// Password shared by the fixture users.
const PASSWORD: &str = "password123";

/// `Host` the mocked client speaks to (matches [`peer`]).
const HOST: &str = "127.0.0.1:51234";

/// Upper bound for one response body read in the tests.
const BODY_LIMIT: usize = 16 * 1024 * 1024;

/// One isolated server instance with its own temporary workspace.
struct Fixture {
    /// Keeps the temporary directory alive for as long as the fixture lives.
    _dir: TempDir,
    state: Arc<AppState>,
    app: Router,
    /// Raw value of `server.api_keys[0]`; only its digest is configured.
    api_key: String,
    /// Audit trail location, when the fixture records one.
    audit_file: Option<std::path::PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        Self::build(tweak, false)
    }

    /// Fixture with a real JSONL audit trail next to the temporary workspace.
    fn with_audit() -> Self {
        Self::build(|_| {}, true)
    }

    fn build(tweak: impl FnOnce(&mut Config), with_audit: bool) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");

        let api_key = crypto::random_token(32);
        let mut config = Config::default();
        config.server.enabled = true;
        config.server.tls = false;
        config.server.bind = "127.0.0.1".to_string();
        config.server.port = 0;
        config.server.rate_limit_per_min = 1_000_000;
        config.server.workspace.root = workspace;
        config.server.users = vec![
            UserConfig {
                name: "admin".to_string(),
                password_hash: crypto::hash_password(PASSWORD).expect("hash admin"),
                scope: "full".to_string(),
                enabled: true,
            },
            UserConfig {
                name: "worker".to_string(),
                password_hash: crypto::hash_password(PASSWORD).expect("hash worker"),
                scope: "workspace".to_string(),
                enabled: true,
            },
        ];
        config.server.api_keys = vec![ApiKeyConfig {
            name: "automation".to_string(),
            key_sha256: crypto::sha256_hex(api_key.as_bytes()),
            scope: "full".to_string(),
            enabled: true,
            created_at: None,
        }];
        tweak(&mut config);

        let paths = ResolvedPaths::resolve(&config, dir.path());
        let audit_file = with_audit.then(|| dir.path().join("logs").join("audit.jsonl"));
        let audit = audit_file.as_ref().map(|path| {
            std::fs::create_dir_all(path.parent().expect("audit parent")).expect("log dir");
            Arc::new(AuditLog::open(path).expect("audit log"))
        });
        let state = AppState::new(ServerOptions {
            config,
            paths,
            sink: LogEventSink::new(256),
            audit,
        })
        .expect("app state");
        let app = router(Arc::clone(&state)).layer(MockConnectInfo(peer()));

        Self {
            _dir: dir,
            state,
            app,
            api_key,
            audit_file,
        }
    }

    async fn call(&self, req: Request<Body>) -> Response {
        send(&self.app, req).await
    }

    async fn login(&self, user: &str, password: &str) -> Response {
        let req = json_request(
            Method::POST,
            "/api/v1/auth/login",
            json!({ "username": user, "password": password }),
        );
        self.call(req).await
    }

    /// Logs `user` in and returns the bearer token.
    async fn token(&self, user: &str) -> String {
        let res = self.login(user, PASSWORD).await;
        assert_eq!(res.status(), StatusCode::OK, "login must succeed");
        let body = json_body(res).await;
        body["access_token"]
            .as_str()
            .expect("access_token in login response")
            .to_string()
    }
}

/// Runs one request through a router, defaulting `Host` to the mocked listener.
async fn send(app: &Router, mut req: Request<Body>) -> Response {
    // Every request has to name a host this server answers to; unless a test is
    // deliberately probing the host guard, that is loopback.
    if !req.headers().contains_key(header::HOST) {
        req.headers_mut().insert(header::HOST, HeaderValue::from_static(HOST));
    }
    app.clone()
        .oneshot(req)
        .await
        .expect("router is infallible")
}

/// Second router over the same state, used to simulate another client address.
fn app_for(state: &Arc<AppState>, peer: SocketAddr) -> Router {
    router(Arc::clone(state)).layer(MockConnectInfo(peer))
}

/// The peer address every mocked request pretends to come from.
fn peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51234)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    with_token(Request::builder().method(Method::GET).uri(uri), token)
        .body(Body::empty())
        .expect("request")
}

fn authed_post(uri: &str, token: &str) -> Request<Body> {
    with_token(Request::builder().method(Method::POST).uri(uri), token)
        .body(Body::empty())
        .expect("request")
}

fn json_request(method: Method, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn authed_json(method: Method, uri: &str, token: &str, body: Value) -> Request<Body> {
    with_token(Request::builder().method(method).uri(uri), token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn with_token(builder: axum::http::request::Builder, token: &str) -> axum::http::request::Builder {
    builder.header(header::AUTHORIZATION, format!("Bearer {token}"))
}

async fn split(res: Response) -> (StatusCode, HeaderMap, Value) {
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = to_bytes(res.into_body(), BODY_LIMIT)
        .await
        .expect("read response body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

async fn json_body(res: Response) -> Value {
    let (_, _, body) = split(res).await;
    body
}

#[tokio::test]
async fn healthz_is_public_and_reports_the_version() {
    let fx = Fixture::new();
    let (status, _, body) = split(fx.call(get("/healthz")).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], rt_protocol::APP_VERSION);
}

#[tokio::test]
async fn info_is_public_and_leaks_no_secrets() {
    let fx = Fixture::new();
    let (status, _, body) = split(fx.call(get("/api/v1/info")).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], fx.state.server_info().name);
    assert_eq!(body["protocol_version"], rt_protocol::PROTOCOL_VERSION);
    assert_eq!(body["max_scope"], "full");
    assert!(body["capabilities"].is_array());
    assert!(body["endpoints"].is_array());
    // TLS is off, so there is no fingerprint to advertise.
    assert!(body["cert_fingerprint"].is_null());

    let raw = body.to_string().to_lowercase();
    for needle in [
        "access_token",
        "password",
        "key_sha256",
        "api_key",
        "secret",
        "authorization",
    ] {
        assert!(!raw.contains(needle), "/api/v1/info leaks `{needle}`: {raw}");
    }
}

#[tokio::test]
async fn protected_routes_reject_missing_credentials() {
    let fx = Fixture::new();
    for uri in [
        "/api/v1/auth/me",
        "/api/v1/fs/roots",
        "/api/v1/sysinfo",
        "/api/v1/logs",
        "/api/v1/audit",
        "/api/v1/ws/info",
    ] {
        let (status, headers, body) = split(fx.call(get(uri)).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(body["error"]["code"], "unauthorized", "{uri}");
        assert!(
            body["error"]["request_id"].as_str().is_some(),
            "{uri} missing request_id: {body}"
        );
        assert!(headers.contains_key("x-request-id"), "{uri}");
        assert!(
            headers.contains_key(header::WWW_AUTHENTICATE),
            "{uri} missing WWW-Authenticate"
        );
    }

    // POST-only endpoints are protected the same way.
    for uri in ["/api/v1/auth/ws-ticket", "/api/v1/auth/logout"] {
        let (status, _, body) = split(fx.call(authed_post(uri, "")).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(body["error"]["code"], "unauthorized", "{uri}");
    }
}

#[tokio::test]
async fn unknown_tokens_are_rejected() {
    let fx = Fixture::new();
    let (status, _, body) = split(fx.call(authed_get("/api/v1/auth/me", "rt_not-a-key")).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn login_issues_a_full_scope_token() {
    let fx = Fixture::new();
    let (status, _, body) = split(fx.login("admin", PASSWORD).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["username"], "admin");
    assert_eq!(body["scope"], "full");
    assert!(body["expires_in_secs"].as_u64().unwrap_or(0) > 0);
    assert!(body["expires_at"].as_str().is_some());
    assert!(
        body["access_token"]
            .as_str()
            .map(|t| t.len() >= 32)
            .unwrap_or(false),
        "token looks too short: {body}"
    );
    assert_eq!(body["server"]["protocol_version"], rt_protocol::PROTOCOL_VERSION);
    assert_eq!(body["server"]["issued_scope"], "full");
}

#[tokio::test]
async fn login_failure_gives_one_uniform_answer() {
    let fx = Fixture::new();
    let mut bodies = Vec::new();
    for _ in 0..3 {
        let (status, _, body) = split(fx.login("admin", "definitely-wrong").await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
        // SECURITY.md S-32: no attempt counter, no hint about which half of the
        // credential pair was wrong.
        assert!(
            body["error"]["detail"].is_null(),
            "failure body must not carry detail: {body}"
        );
        assert!(
            !body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("attempt"),
            "failure message leaks the attempt counter: {body}"
        );
        bodies.push(body["error"]["message"].clone());
    }
    assert_eq!(bodies[0], bodies[1], "answers must not change per attempt");
    assert_eq!(bodies[1], bodies[2], "answers must not change per attempt");

    // An unknown user and a wrong password are indistinguishable.
    let (status, _, unknown) = split(fx.login("nobody", "definitely-wrong").await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown["error"]["message"], bodies[0]);
}

#[tokio::test]
async fn repeated_failures_lock_the_client_out() {
    let fx = Fixture::with(|cfg| cfg.server.login_max_attempts = 2);
    for _ in 0..2 {
        let (status, _, _) = split(fx.login("admin", "definitely-wrong").await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, body) = split(fx.login("admin", PASSWORD).await).await;
    assert_eq!(status, StatusCode::CONFLICT, "locked out: {body}");
    assert_eq!(body["error"]["code"], "locked");
    assert!(body["error"]["retry_after_secs"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn me_reports_the_session_and_logout_revokes_it() {
    let fx = Fixture::new();
    let token = fx.token("worker").await;

    let (status, _, body) = split(fx.call(authed_get("/api/v1/auth/me", &token)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "worker");
    assert_eq!(body["scope"], "workspace");
    assert_eq!(body["auth_kind"], "password");
    let remote = body["remote_addr"].as_str().unwrap_or_default();
    assert!(remote.starts_with("127.0.0.1:"), "remote_addr was {remote}");

    let (status, _, _) = split(fx.call(authed_post("/api/v1/auth/logout", &token)).await).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = split(fx.call(authed_get("/api/v1/auth/me", &token)).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn api_key_bearer_is_accepted() {
    let fx = Fixture::new();
    let (status, _, body) = split(fx.call(authed_get("/api/v1/auth/me", &fx.api_key)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "automation");
    assert_eq!(body["auth_kind"], "api_key");
    assert_eq!(body["scope"], "full");
}

#[tokio::test]
async fn session_listing_and_revocation_go_through_the_store() {
    let fx = Fixture::new();
    let token = fx.token("admin").await;
    let sessions = fx.state.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].username, "admin");
    assert!(fx.state.revoke_session(&token));
    assert!(fx.state.sessions().is_empty());
    assert!(!fx.state.revoke_session(&token), "second revoke is a no-op");
}

#[tokio::test]
async fn workspace_scope_cannot_escape_its_root() {
    let fx = Fixture::new();
    let token = fx.token("worker").await;

    let (status, _, body) = split(fx.call(authed_get("/api/v1/fs/list", &token)).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "workspace");
    assert!(body["entries"].is_array(), "entries: {body}");

    let escape = "/api/v1/fs/list?path=%5C..%5C..%5CWindows";
    let (status, _, body) = split(fx.call(authed_get(escape, &token)).await).await;
    assert!(
        status.is_client_error(),
        "escaping the workspace must fail, got {status}: {body}"
    );
    let code = body["error"]["code"].as_str().unwrap_or_default();
    assert!(
        matches!(code, "scope_violation" | "invalid_path" | "forbidden"),
        "unexpected error code {code}: {body}"
    );
}

#[tokio::test]
async fn write_read_and_ranged_download_roundtrip() {
    let fx = Fixture::new();
    let token = fx.token("worker").await;
    let payload = b"hello ranged world";

    let req = with_token(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/fs/write?path=hello.txt&overwrite=true"),
        &token,
    )
    .header(header::CONTENT_TYPE, "application/octet-stream")
    .body(Body::from(payload.to_vec()))
    .expect("request");
    let (status, _, body) = split(fx.call(req).await).await;
    assert!(status.is_success(), "write failed with {status}: {body}");
    assert_eq!(body["size"], payload.len() as u64);

    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/fs/read?path=hello.txt", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["text"], "hello ranged world");
    assert_eq!(body["size"], payload.len() as u64);

    let req = with_token(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/fs/download?path=hello.txt"),
        &token,
    )
    .header(header::RANGE, "bytes=6-11")
    .body(Body::empty())
    .expect("request");
    let res = fx.call(req).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    let headers = res.headers().clone();
    let expected_range = format!("bytes 6-11/{}", payload.len());
    assert_eq!(
        headers
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok()),
        Some(expected_range.as_str())
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain")
    );
    let disposition = headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(disposition.contains("hello.txt"), "{disposition}");
    let bytes = to_bytes(res.into_body(), 1024).await.expect("body");
    assert_eq!(&bytes[..], b"ranged");
}

#[tokio::test]
async fn fs_operations_cover_mkdir_copy_rename_and_delete() {
    let fx = Fixture::new();
    let token = fx.token("worker").await;

    let mkdir = authed_json(
        Method::POST,
        "/api/v1/fs/mkdir",
        &token,
        json!({ "path": "sub", "create_parents": true }),
    );
    let (status, _, body) = split(fx.call(mkdir).await).await;
    assert!(status.is_success(), "mkdir failed with {status}: {body}");
    assert_eq!(body["is_dir"], true);

    let write = with_token(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/fs/write?path=sub%5Cnote.txt"),
        &token,
    )
    .header(header::CONTENT_TYPE, "application/octet-stream")
    .body(Body::from("note".as_bytes().to_vec()))
    .expect("request");
    let (status, _, body) = split(fx.call(write).await).await;
    assert!(status.is_success(), "write failed with {status}: {body}");

    let copy = authed_json(
        Method::POST,
        "/api/v1/fs/copy",
        &token,
        json!({ "from": "sub\\note.txt", "to": "copy.txt" }),
    );
    let (status, _, body) = split(fx.call(copy).await).await;
    assert!(status.is_success(), "copy failed with {status}: {body}");

    let rename = authed_json(
        Method::POST,
        "/api/v1/fs/rename",
        &token,
        json!({ "from": "copy.txt", "to": "moved.txt" }),
    );
    let (status, _, body) = split(fx.call(rename).await).await;
    assert!(status.is_success(), "rename failed with {status}: {body}");

    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/fs/stat?path=moved.txt", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entry"]["name"], "moved.txt");

    let delete = authed_json(
        Method::POST,
        "/api/v1/fs/delete",
        &token,
        json!({ "paths": ["moved.txt"] }),
    );
    let (status, _, body) = split(fx.call(delete).await).await;
    assert!(status.is_success(), "delete failed with {status}: {body}");
    assert_eq!(body["deleted"].as_array().map(|v| v.len()), Some(1));

    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/fs/stat?path=moved.txt", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn multipart_upload_streams_into_the_workspace() {
    let fx = Fixture::new();
    let token = fx.token("worker").await;
    let boundary = "rt-test-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"up.txt\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"uploaded content");
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let req = with_token(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/fs/upload?path=up.txt&overwrite=true"),
        &token,
    )
    .header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body))
    .expect("request");
    let (status, _, body) = split(fx.call(req).await).await;
    assert!(status.is_success(), "upload failed with {status}: {body}");
    assert_eq!(body["size"], "uploaded content".len() as u64);

    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/fs/read?path=up.txt", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["text"], "uploaded content");
}

#[tokio::test]
async fn exec_runs_a_shell_or_reports_not_implemented() {
    let fx = Fixture::new();
    let token = fx.token("admin").await;
    let req = authed_json(
        Method::POST,
        "/api/v1/exec",
        &token,
        json!({ "shell": { "kind": "cmd" }, "command": "echo hi" }),
    );
    let (status, _, body) = split(fx.call(req).await).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
        "unexpected exec status {status}: {body}"
    );
    if status == StatusCode::OK {
        assert_eq!(body["exit_code"], 0);
        let stdout = body["stdout"].as_str().unwrap_or_default().to_lowercase();
        assert!(stdout.contains("hi"), "stdout was {stdout:?}");
    }

    let (status, _, body) = split(fx.call(authed_get("/api/v1/exec/shells", &token)).await).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
        "unexpected shells status {status}: {body}"
    );
}

#[tokio::test]
async fn sysinfo_endpoints_answer_or_report_not_implemented() {
    let fx = Fixture::new();
    let token = fx.token("admin").await;
    for uri in [
        "/api/v1/sysinfo",
        "/api/v1/sysinfo/quick",
        "/api/v1/sysinfo/processes?limit=10",
    ] {
        let (status, _, body) = split(fx.call(authed_get(uri, &token)).await).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
            "{uri} returned {status}: {body}"
        );
    }
}

#[tokio::test]
async fn logs_and_audit_require_full_scope() {
    let fx = Fixture::new();
    let worker = fx.token("worker").await;
    let admin = fx.token("admin").await;

    for uri in ["/api/v1/logs?limit=5", "/api/v1/audit?limit=5"] {
        let (status, _, body) = split(fx.call(authed_get(uri, &worker)).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert_eq!(body["error"]["code"], "forbidden", "{uri}");

        let (status, _, body) = split(fx.call(authed_get(uri, &admin)).await).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert!(body.is_array(), "{uri} should return an array: {body}");
    }
}

#[tokio::test]
async fn ws_ticket_is_issued_and_bogus_tickets_are_rejected() {
    let fx = Fixture::new();
    let token = fx.token("admin").await;

    let (status, _, body) = split(
        fx.call(authed_post("/api/v1/auth/ws-ticket", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["ticket"].as_str().map(|t| !t.is_empty()).unwrap_or(false));
    assert_eq!(body["expires_in_secs"], 15);
    assert_eq!(body["ws_path"], rt_protocol::ws::WS_PATH);

    let (status, _, body) = split(fx.call(get("/api/v1/ws?ticket=not-a-ticket")).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    let (status, _, body) = split(fx.call(get("/api/v1/ws/info")).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn openapi_document_is_public_and_describes_the_api() {
    let fx = Fixture::new();
    let (status, headers, body) = split(fx.call(get("/api/v1/openapi.json")).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "application/json"
    );
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(
        body["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );
    for path in [
        "/healthz",
        "/api/v1/info",
        "/api/v1/auth/login",
        "/api/v1/exec",
        "/api/v1/fs/list",
        "/api/v1/capture/raw",
        "/api/v1/ws",
    ] {
        assert!(
            body["paths"][path].is_object(),
            "openapi.json is missing {path}"
        );
    }
}

#[tokio::test]
async fn errors_use_the_documented_envelope() {
    let fx = Fixture::new();

    // Unknown route → 404.
    let (status, _, body) = split(fx.call(get("/api/v1/nope")).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    assert!(body["error"]["message"].as_str().is_some());

    // Wrong method → 405.
    let (status, _, body) = split(fx.call(get("/api/v1/exec")).await).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "bad_request");

    // Malformed JSON → 400.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .expect("request");
    let (status, _, body) = split(fx.call(req).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "bad_request");

    // Wrong content type → 415.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("{}"))
        .expect("request");
    let (status, _, body) = split(fx.call(req).await).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(body["error"]["code"], "unsupported_media_type");

    // Client-supplied request id is echoed back.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/me")
        .header("x-request-id", "test-request-id")
        .body(Body::empty())
        .expect("request");
    let (status, headers, body) = split(fx.call(req).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["request_id"], "test-request-id");
    assert_eq!(
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        Some("test-request-id")
    );
}

#[tokio::test]
async fn request_rate_limit_returns_429_with_a_retry_hint() {
    let fx = Fixture::with(|cfg| cfg.server.rate_limit_per_min = 2);

    // `/healthz` is exempt so health probes cannot throttle themselves.
    for _ in 0..4 {
        let (status, _, _) = split(fx.call(get("/healthz")).await).await;
        assert_eq!(status, StatusCode::OK);
    }

    let mut limited = None;
    for _ in 0..6 {
        let (status, headers, body) = split(fx.call(get("/api/v1/info")).await).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some((headers, body));
            break;
        }
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (headers, body) = limited.expect("rate limit never triggered");
    assert_eq!(body["error"]["code"], "rate_limited");
    assert!(body["error"]["retry_after_secs"].as_u64().unwrap_or(0) >= 1);
    assert!(headers.contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn ip_allowlist_rejects_foreign_clients() {
    let fx = Fixture::with(|cfg| cfg.server.ip_allowlist = vec!["10.1.2.".to_string()]);
    let (status, _, body) = split(fx.call(get("/healthz")).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn serve_terminates_tls_and_reports_the_fingerprint() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let fx = Fixture::with(|cfg| cfg.server.tls = true);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = rt_server::serve(Arc::clone(&fx.state), shutdown_rx)
        .await
        .expect("serve");

    assert!(handle.tls);
    assert!(
        handle.url.starts_with("https://127.0.0.1:"),
        "url {}",
        handle.url
    );
    let fingerprint = handle.fingerprint.clone().expect("fingerprint");

    // TOFU client: it accepts the self-signed certificate and records its
    // fingerprint, which must match the one the server advertises.
    let probe = crypto::FingerprintProbe::new();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto::client_config_tofu(
        probe.clone(),
    )));
    let tcp = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost").expect("valid server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "unexpected response: {text}");
    assert!(text.contains("\"status\":\"ok\""), "unexpected body: {text}");

    assert_eq!(probe.get().as_deref(), Some(fingerprint.as_str()));
    handle.stop();
}

/// Reads one unmasked WebSocket frame from `stream`.
async fn read_frame(stream: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.expect("frame header");
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await.expect("frame length");
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await.expect("frame length");
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.expect("frame mask");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.expect("frame payload");
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    (opcode, payload)
}

/// Writes one masked text frame to `stream`.
async fn write_text_frame(stream: &mut tokio::net::TcpStream, text: &str) {
    use tokio::io::AsyncWriteExt;

    let payload = text.as_bytes();
    assert!(payload.len() < 126, "test frames stay short");
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.push(0x81);
    frame.push(0x80 | payload.len() as u8);
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }
    stream.write_all(&frame).await.expect("write frame");
}

/// Reads one plain HTTP/1.1 response status line from `stream`.
async fn http_status_line(stream: &mut tokio::net::TcpStream, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn websocket_accepts_one_time_tickets_and_answers_pings() {
    use tokio::io::AsyncWriteExt;

    let fx = Fixture::new();
    let token = fx.token("admin").await;
    let (status, _, ticket_body) = split(
        fx.call(authed_post("/api/v1/auth/ws-ticket", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ticket_body}");
    let ticket = ticket_body["ticket"].as_str().expect("ticket").to_string();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = rt_server::serve(Arc::clone(&fx.state), shutdown_rx)
        .await
        .expect("serve");

    let mut stream = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    let upgrade = format!(
        "GET /api/v1/ws?ticket={ticket} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(upgrade.as_bytes())
        .await
        .expect("send upgrade");

    // The 101 response is a header block terminated by an empty line.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        use tokio::io::AsyncReadExt;
        stream.read_exact(&mut byte).await.expect("handshake byte");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(head.len() < 8192, "handshake response is absurdly long");
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 101"), "handshake failed: {head}");
    assert!(
        head.to_ascii_lowercase().contains("sec-websocket-accept"),
        "missing accept header: {head}"
    );

    write_text_frame(&mut stream, r#"{"type":"ping","id":7}"#).await;
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, 0x1, "expected a text frame");
    let message: Value = serde_json::from_slice(&payload).expect("json frame");
    assert_eq!(message["type"], "pong");
    assert_eq!(message["id"], 7);
    drop(stream);

    // Tickets are single use: the same value is rejected after the upgrade.
    let mut again = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    let status_line = http_status_line(
        &mut again,
        &format!("GET /api/v1/ws?ticket={ticket} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(
        status_line.starts_with("HTTP/1.1 401"),
        "reused ticket was accepted: {status_line}"
    );

    handle.stop();
}

#[tokio::test]
async fn serve_binds_a_port_and_stops_on_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let fx = Fixture::new();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = rt_server::serve(Arc::clone(&fx.state), shutdown_rx)
        .await
        .expect("serve");

    assert_ne!(handle.local_addr.port(), 0);
    assert_eq!(handle.local_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(handle.url.starts_with("http://127.0.0.1:"), "url {}", handle.url);
    assert!(!handle.tls);
    assert!(handle.fingerprint.is_none());
    assert!(Arc::ptr_eq(&handle.state(), &fx.state));

    let mut stream = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "unexpected response: {text}");
    assert!(text.contains("\"status\":\"ok\""), "unexpected body: {text}");

    handle.stop();
}

/// Opens a WebSocket connection with a one-time ticket and returns the socket.
async fn open_socket(addr: SocketAddr, ticket: &str) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "GET /api/v1/ws?ticket={ticket} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send upgrade");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("handshake byte");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(head.len() < 8192, "handshake response is absurdly long");
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 101"), "handshake failed: {head}");
    stream
}

/// Reads one JSON text frame from a WebSocket.
async fn read_json_frame(stream: &mut tokio::net::TcpStream) -> Value {
    let (opcode, payload) = read_frame(stream).await;
    assert_eq!(opcode, 0x1, "expected a text frame");
    serde_json::from_slice(&payload).expect("json frame")
}

#[tokio::test]
async fn workspace_sessions_cannot_execute_or_capture() {
    let fx = Fixture::new();
    let worker = fx.token("worker").await;
    let admin = fx.token("admin").await;

    let exec_body = json!({ "shell": { "kind": "cmd" }, "command": "echo hi" });
    let capture_body = json!({ "target": { "kind": "primary" } });

    let cases = [
        (
            "exec",
            authed_json(Method::POST, "/api/v1/exec", &worker, exec_body.clone()),
            authed_json(Method::POST, "/api/v1/exec", &admin, exec_body.clone()),
        ),
        (
            "capture",
            authed_json(Method::POST, "/api/v1/capture", &worker, capture_body.clone()),
            authed_json(Method::POST, "/api/v1/capture", &admin, capture_body.clone()),
        ),
        (
            "capture raw",
            authed_get("/api/v1/capture/raw?target=primary&format=png", &worker),
            authed_get("/api/v1/capture/raw?target=primary&format=png", &admin),
        ),
        (
            "capture windows",
            authed_get("/api/v1/capture/windows", &worker),
            authed_get("/api/v1/capture/windows", &admin),
        ),
    ];

    for (name, denied, allowed) in cases {
        let (status, _, body) = split(fx.call(denied).await).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{name} must be full-scope only: {body}"
        );
        assert_eq!(body["error"]["code"], "forbidden", "{name}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("full scope"),
            "{name}: {body}"
        );

        // The full-scope session is authorised; the stub or a headless host may
        // still answer 501/503, which is fine here.
        let status = fx.call(allowed).await.status();
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "admin must keep {name} available"
        );
    }
}

#[tokio::test]
async fn process_listing_requires_full_scope() {
    let fx = Fixture::new();
    let worker = fx.token("worker").await;
    let admin = fx.token("admin").await;

    // The process table exposes command lines and user names host-wide.
    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/sysinfo/processes", &worker))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden", "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("full scope"),
        "{body}"
    );
    let status = fx
        .call(authed_get("/api/v1/sysinfo/processes?limit=5", &admin))
        .await
        .status();
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "admin must keep the process table"
    );

    // Hardware and load overviews stay part of the workspace experience.
    for uri in ["/api/v1/sysinfo", "/api/v1/sysinfo/quick"] {
        let (status, _, body) = split(fx.call(authed_get(uri, &worker)).await).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
    }

    // SECURITY.md S-27: the overview must not hand a jailed session the host
    // layout, and a full-scope session still sees the real paths.
    let (status, _, body) = split(fx.call(authed_get("/api/v1/sysinfo", &worker)).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["app"]["workspace_root"], "\\", "{body}");
    assert_eq!(body["app"]["config_path"], "", "{body}");
    assert_eq!(body["app"]["data_dir"], "", "{body}");
    assert!(
        body.get("processes").is_none(),
        "the snapshot must not embed a process table: {body}"
    );

    let (status, _, body) = split(fx.call(authed_get("/api/v1/sysinfo", &admin)).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["app"]["config_path"], "", "{body}");
}

#[tokio::test]
async fn websocket_streams_enforce_the_session_scope() {
    let fx = Fixture::new();
    let worker = fx.token("worker").await;
    let (status, _, body) = split(
        fx.call(authed_post("/api/v1/auth/ws-ticket", &worker))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ticket = body["ticket"].as_str().expect("ticket").to_string();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = rt_server::serve(Arc::clone(&fx.state), shutdown_rx)
        .await
        .expect("serve");
    let mut socket = open_socket(handle.local_addr, &ticket).await;

    let denied = [
        json!({ "type": "exec", "id": 1, "request": { "shell": { "kind": "cmd" }, "command": "echo hi" } }),
        json!({ "type": "capture_stream", "id": 2, "request": { "target": { "kind": "primary" } }, "fps": 1 }),
        json!({ "type": "subscribe_logs", "id": 3 }),
    ];
    for message in denied {
        write_text_frame(&mut socket, &message.to_string()).await;
        let frame = read_json_frame(&mut socket).await;
        assert_eq!(frame["type"], "error", "unexpected frame: {frame}");
        assert_eq!(frame["id"], message["id"], "{frame}");
        assert_eq!(frame["error"]["code"], "forbidden", "{frame}");
    }

    // Status streaming is not sensitive to the path jail, so it stays allowed.
    write_text_frame(&mut socket, r#"{"type":"subscribe_status","id":4,"fps":1}"#).await;
    let frame = read_json_frame(&mut socket).await;
    assert_eq!(frame["type"], "accepted", "unexpected frame: {frame}");
    assert_eq!(frame["id"], 4);

    drop(socket);
    handle.stop();
}

#[tokio::test]
async fn serve_refuses_a_configuration_the_validator_rejects() {
    let fx = Fixture::with(|cfg| {
        cfg.server.bind = "0.0.0.0".to_string();
        cfg.server.tls = false;
        cfg.server.allow_insecure_lan = false;
    });
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let error = rt_server::serve(Arc::clone(&fx.state), shutdown_rx)
        .await
        .expect_err("plaintext HTTP on a LAN bind must be refused");
    let text = error.to_string().to_lowercase();
    assert!(text.contains("tls"), "unexpected error: {text}");
}
#[tokio::test]
async fn request_host_and_origin_are_validated() {
    let fx = Fixture::new();

    // A page served from an attacker-controlled name must not reach us (DNS
    // rebinding).
    let rebound = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header(header::HOST, "evil.example")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = split(send(&fx.app, rebound).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden");
    assert!(body["error"]["request_id"].as_str().is_some(), "{body}");

    // A request without any Host header is malformed. `send` would fill one in,
    // so this one goes straight to the router.
    let anonymous = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .body(Body::empty())
        .expect("request");
    let raw = fx
        .app
        .clone()
        .oneshot(anonymous)
        .await
        .expect("router is infallible");
    let (status, _, body) = split(raw).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "bad_request", "{body}");

    // Cross-site origin, and its header-less variant.
    let cross_site = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = split(send(&fx.app, cross_site).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let fetch_metadata = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/info")
        .header(header::HOST, HOST)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = split(send(&fx.app, fetch_metadata).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Same-origin callers are unaffected; the scheme has to match the listener.
    let same_origin = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/info")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = split(send(&fx.app, same_origin).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let wrong_scheme = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/info")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .body(Body::empty())
        .expect("request");
    let (status, _, _) = split(send(&fx.app, wrong_scheme).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn forwarded_headers_are_only_trusted_from_a_local_peer() {
    // An allow-list that only matches the forwarded address: the request is
    // accepted exactly when the proxy hop is trusted (SECURITY.md S-11).
    let fixture = || {
        Fixture::with(|cfg| {
            cfg.server.trust_forwarded_for = true;
            cfg.server.ip_allowlist = vec!["10.9.9.".to_string()];
        })
    };

    let forwarded = || {
        Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .header(header::HOST, HOST)
            .header("x-forwarded-for", "10.9.9.9")
            .body(Body::empty())
            .expect("request")
    };

    // Loopback peer: a reverse proxy on the same machine is believed.
    let local = fixture();
    let (status, _, _) = split(local.call(forwarded()).await).await;
    assert_eq!(status, StatusCode::OK, "local proxy must be trusted");

    // Remote peer: the header is attacker-controlled and must be ignored.
    let remote = fixture();
    let far_away = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 41000);
    let (status, _, body) = split(send(&app_for(&remote.state, far_away), forwarded()).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn websocket_tickets_are_bound_to_the_issuing_address() {
    let fx = Fixture::new();
    let token = fx.token("admin").await;
    let (status, _, body) = split(fx.call(authed_post("/api/v1/auth/ws-ticket", &token)).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ticket = body["ticket"].as_str().expect("ticket").to_string();

    let ticket_request = || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ws?ticket={ticket}"))
            .body(Body::empty())
            .expect("request")
    };

    // Another address (a leaked ticket) cannot redeem it.
    let stranger = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4444);
    let (status, _, body) =
        split(send(&app_for(&fx.state, stranger), ticket_request()).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden");

    // Even the rightful client finds the ticket consumed after a misuse.
    let (status, _, body) = split(fx.call(ticket_request()).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn repeated_failures_back_off_per_account() {
    // Keep the per-address lockout out of the way so the account throttle is
    // what answers (SECURITY.md S-22).
    let fx = Fixture::with(|cfg| cfg.server.login_max_attempts = 100_000);
    for attempt in 1..=4 {
        let (status, _, _) = split(fx.login("admin", "definitely-wrong").await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt} must reach the password check");
    }

    let (status, headers, body) = split(fx.login("admin", PASSWORD).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "rate_limited");
    assert!(body["error"]["retry_after_secs"].as_u64().unwrap_or(0) >= 1, "{body}");
    assert!(headers.contains_key(header::RETRY_AFTER), "{body}");

    // Other accounts are unaffected.
    let (status, _, body) = split(fx.login("worker", PASSWORD).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn credential_changes_apply_without_a_restart() {
    let fx = Fixture::new();
    let existing = fx.token("worker").await;
    let current = split(fx.call(authed_get("/api/v1/auth/me", &fx.api_key)).await).await;
    assert_eq!(current.0, StatusCode::OK, "the configured key starts out valid");

    // Rewrite the configuration file: drop the API key, add a user.
    let mut config = fx.state.config();
    config.server.api_keys.clear();
    config.server.users.push(UserConfig {
        name: "fresh".to_string(),
        password_hash: crypto::hash_password("password456").expect("hash fresh"),
        scope: "workspace".to_string(),
        enabled: true,
    });
    config
        .save_atomic(&fx.state.paths().config_file)
        .expect("save config");
    // Reloading is throttled to once a second.
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    let revoked = split(fx.call(authed_get("/api/v1/auth/me", &fx.api_key)).await).await;
    assert_eq!(revoked.0, StatusCode::UNAUTHORIZED, "revoked key: {}", revoked.2);
    assert_eq!(revoked.2["error"]["code"], "unauthorized");

    let (status, _, body) = split(fx.login("fresh", "password456").await).await;
    assert_eq!(status, StatusCode::OK, "new user must be able to sign in: {body}");
    assert_eq!(body["scope"], "workspace");

    // Sessions issued before the change keep working.
    let (status, _, _) = split(fx.call(authed_get("/api/v1/auth/me", &existing)).await).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn file_reads_are_recorded_in_the_audit_trail() {
    let fx = Fixture::with_audit();
    let token = fx.token("worker").await;

    let upload = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/fs/write?path=note.txt")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from("hello audit"))
        .expect("request");
    let (status, _, body) = split(fx.call(upload).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = split(
        fx.call(authed_get("/api/v1/fs/read?path=note.txt", &token))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["text"], "hello audit");

    let path = fx.audit_file.clone().expect("audit trail");
    let trail = std::fs::read_to_string(path).expect("read audit trail");
    let record: Value = trail
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["action"] == "fs.read")
        .expect("fs.read must be audited");
    assert_eq!(record["result"], "success");
    assert_eq!(record["username"], "worker");
    let detail = record["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("returned=11"), "unexpected detail: {detail}");
    assert!(record["request_id"].as_str().is_some(), "{record}");
}

#[tokio::test]
async fn every_response_carries_the_hardening_headers() {
    let fx = Fixture::with(|_| {});
    let token = fx.token("worker").await;

    // Public JSON
    let (status, headers, _) = split(fx.call(get("/healthz")).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");

    // Authenticated file download (raw binary body)
    let upload = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/fs/write?path=page.html")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from("<script>alert(1)</script>"))
        .expect("request");
    let (status, _, body) = split(fx.call(upload).await).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let download = Request::builder()
        .uri("/api/v1/fs/download?path=page.html")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let (status, headers, _) = split(fx.call(download).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["referrer-policy"], "no-referrer");

    // Error envelope
    let (status, headers, _) = split(fx.call(get("/api/v1/fs/roots")).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers["x-content-type-options"], "nosniff");
}
