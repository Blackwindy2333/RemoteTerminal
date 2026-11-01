//! HTTP route table (architecture §5) and the layer stack around it.
//!
//! Layer order, outermost first: request id → timeout → trace → body limit →
//! authentication → handler. The request-id layer sits outermost so that error
//! bodies produced by any inner layer can be stamped with the same id.

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::middleware as layer;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub(crate) mod auth;
pub(crate) mod capture;
pub(crate) mod exec;
pub(crate) mod fs;
pub(crate) mod health;
pub(crate) mod meta;
pub(crate) mod sysinfo;
pub(crate) mod ws;

/// Assembles the full router for one server instance.
pub(crate) fn build(state: Arc<AppState>) -> Router {
    let max_json = state.max_json_bytes();

    Router::new()
        // Unauthenticated ------------------------------------------------------
        .route("/healthz", get(health::healthz))
        .route("/api/v1/info", get(health::info))
        .route("/api/v1/openapi.json", get(meta::openapi))
        .route("/api/v1/auth/login", post(auth::login))
        // Authentication -------------------------------------------------------
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/ws-ticket", post(auth::ws_ticket))
        // Command execution ----------------------------------------------------
        .route("/api/v1/exec/shells", get(exec::shells))
        .route("/api/v1/exec", post(exec::run))
        // Filesystem -----------------------------------------------------------
        .route("/api/v1/fs/roots", get(fs::roots))
        .route("/api/v1/fs/list", get(fs::list))
        .route("/api/v1/fs/stat", get(fs::stat))
        .route("/api/v1/fs/mkdir", post(fs::mkdir))
        .route("/api/v1/fs/delete", post(fs::delete))
        .route("/api/v1/fs/rename", post(fs::rename))
        .route("/api/v1/fs/copy", post(fs::copy))
        .route("/api/v1/fs/read", get(fs::read))
        .route("/api/v1/fs/download", get(fs::download))
        .route(
            "/api/v1/fs/write",
            post(fs::write).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/fs/upload",
            post(fs::upload).layer(DefaultBodyLimit::disable()),
        )
        // Machine information --------------------------------------------------
        .route("/api/v1/sysinfo", get(sysinfo::sysinfo))
        .route("/api/v1/sysinfo/quick", get(sysinfo::quick))
        .route("/api/v1/sysinfo/processes", get(sysinfo::processes))
        // Screen capture -------------------------------------------------------
        .route("/api/v1/capture/screens", get(capture::screens))
        .route("/api/v1/capture/windows", get(capture::windows))
        .route("/api/v1/capture", post(capture::capture))
        .route("/api/v1/capture/raw", get(capture::raw))
        // Streaming ------------------------------------------------------------
        .route("/api/v1/ws", get(ws::upgrade))
        .route("/api/v1/ws/info", get(ws::info))
        // Diagnostics ----------------------------------------------------------
        .route("/api/v1/logs", get(meta::logs))
        .route("/api/v1/audit", get(meta::audit))
        .with_state(state.clone())
        // Authentication and throttling: innermost of the cross-cutting layers.
        .layer(layer::from_fn_with_state(
            state.clone(),
            crate::middleware::auth_layer,
        ))
        .layer(DefaultBodyLimit::max(max_json))
        .layer(TraceLayer::new_for_http())
        .layer(layer::from_fn_with_state(
            state.clone(),
            crate::middleware::timeout_layer,
        ))
        // Host / Origin validation runs before authentication so DNS rebinding
        // and cross-site requests never reach the credential path.
        .layer(layer::from_fn_with_state(
            state.clone(),
            crate::middleware::origin_layer,
        ))
        .layer(layer::from_fn_with_state(
            state,
            crate::middleware::request_id_layer,
        ))
        .fallback(crate::middleware::not_found_fallback)
        .method_not_allowed_fallback(crate::middleware::method_not_allowed_fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{header, Request, StatusCode};
    use rt_core::config::{Config, ResolvedPaths, UserConfig};
    use rt_core::logging::LogEventSink;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    use crate::ServerOptions;

    fn test_state(dir: &std::path::Path) -> Arc<AppState> {
        let mut config = Config::default();
        config.server.enabled = true;
        config.server.tls = false;
        config.server.bind = "127.0.0.1".to_string();
        config.server.port = 0;
        config.server.rate_limit_per_min = 1_000_000;
        config.server.workspace.root = dir.join("workspace");
        config.server.users = vec![UserConfig {
            name: "admin".to_string(),
            password_hash: rt_core::crypto::hash_password("password123").expect("hash"),
            scope: "full".to_string(),
            enabled: true,
        }];
        let paths = ResolvedPaths::resolve(&config, dir);
        AppState::new(ServerOptions {
            config,
            paths,
            sink: LogEventSink::new(64),
            audit: None,
        })
        .expect("state")
    }

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51234)
    }

    async fn send(app: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.clone().oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn requests_are_shed_when_every_blocking_slot_is_taken() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = test_state(dir.path());
        let app = build(state.clone()).layer(MockConnectInfo(peer()));

        let login = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header(header::HOST, "127.0.0.1:51234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"password123"}"#,
            ))
            .expect("request");
        let (status, body) = send(&app, login).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["access_token"].as_str().expect("token").to_string();

        // Occupy the whole admission budget the way a burst of uploads would.
        let slots = state.blocking_slots();
        let held: Vec<_> = (0..crate::state::BLOCKING_ADMISSION_SLOTS)
            .map(|_| slots.clone().try_acquire_owned().expect("free permit"))
            .collect();

        let blocked = Request::builder()
            .uri("/api/v1/fs/roots")
            .header(header::HOST, "127.0.0.1:51234")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&app, blocked).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"]["code"], "unavailable", "{body}");
        assert!(
            body["error"]["retry_after_secs"].as_u64().unwrap_or(0) >= 1,
            "the client must be told when to retry: {body}"
        );

        drop(held);
        let retry = Request::builder()
            .uri("/api/v1/fs/roots")
            .header(header::HOST, "127.0.0.1:51234")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&app, retry).await;
        assert_ne!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    }
}
