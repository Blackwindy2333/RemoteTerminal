//! Liveness and public server description.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use rt_protocol::ServerInfo;

use crate::state::AppState;

/// `GET /healthz` — cheap liveness probe, no credentials required.
pub(crate) async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": rt_protocol::APP_VERSION,
    }))
}

/// `GET /api/v1/info` — what this server is, without any secret material.
pub(crate) async fn info(State(state): State<Arc<AppState>>) -> Json<ServerInfo> {
    Json(state.server_info())
}
