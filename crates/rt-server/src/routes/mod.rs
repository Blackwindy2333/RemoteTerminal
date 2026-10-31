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
        .layer(layer::from_fn_with_state(
            state,
            crate::middleware::request_id_layer,
        ))
        .fallback(crate::middleware::not_found_fallback)
        .method_not_allowed_fallback(crate::middleware::method_not_allowed_fallback)
}
