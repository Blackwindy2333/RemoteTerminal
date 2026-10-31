//! Server introspection: log tail, audit trail and the OpenAPI document.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::Json;
use rt_protocol::ws::LogEvent;
use serde::Deserialize;

use crate::middleware::{blocking, require_full_scope, session_of, ApiQuery, ApiResult};
use crate::state::AppState;

/// `?limit=` shared by the log and audit tails.
#[derive(Debug, Deserialize)]
pub(crate) struct TailQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Largest tail the endpoints will return in one answer.
const MAX_TAIL: usize = 2000;

/// Default tail length when `limit` is absent.
const DEFAULT_TAIL: usize = 200;

/// `GET /api/v1/logs?limit=` — recent log lines (full scope only).
pub(crate) async fn logs(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<TailQuery>,
    req: Request,
) -> ApiResult<Json<Vec<LogEvent>>> {
    let ctx = session_of(&req)?;
    require_full_scope(&ctx, "reading server logs")?;
    let limit = query.limit.unwrap_or(DEFAULT_TAIL).clamp(1, MAX_TAIL);
    Ok(Json(state.recent_logs(limit)))
}

/// `GET /api/v1/audit?limit=` — recent audit records (full scope only).
pub(crate) async fn audit(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<TailQuery>,
    req: Request,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    let ctx = session_of(&req)?;
    require_full_scope(&ctx, "reading the audit trail")?;
    let limit = query.limit.unwrap_or(DEFAULT_TAIL).clamp(1, MAX_TAIL);
    let path = state.paths().audit_file.clone();
    let records = blocking(move || Ok(tail_json_lines(&path, limit))).await?;
    Ok(Json(records))
}

/// `GET /api/v1/openapi.json` — machine-readable description of this API.
pub(crate) async fn openapi() -> Json<serde_json::Value> {
    Json(crate::openapi::document())
}

/// Reads the last `limit` JSON lines of a file (audit trail).
fn tail_json_lines(path: &std::path::Path, limit: usize) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut records: Vec<serde_json::Value> = content
        .lines()
        .rev()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .take(limit)
        .collect();
    records.reverse();
    records
}
