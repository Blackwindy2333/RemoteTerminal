//! Host telemetry: full snapshot, quick status and process list.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::Json;
use rt_core::sysinfo::ProcessQuery;
use rt_protocol::{ProcessListResponse, QuickStatus, SysInfoSnapshot};
use serde::Deserialize;

use crate::middleware::{blocking, session_of, ApiQuery, ApiResult};
use crate::state::AppState;

/// `GET /api/v1/sysinfo/processes?limit=&query=&sort=&descending=`.
#[derive(Debug, Deserialize)]
pub(crate) struct ProcessesQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub descending: Option<bool>,
}

/// `GET /api/v1/sysinfo` — one deep snapshot of the machine.
pub(crate) async fn sysinfo(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<SysInfoSnapshot>> {
    let ctx = session_of(&req)?;
    let service = state.sysinfo();
    let app = state.app_info(ctx.scope);
    Ok(Json(blocking(move || service.snapshot(app)).await?))
}

/// `GET /api/v1/sysinfo/quick` — the cheap version used by dashboards.
pub(crate) async fn quick(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<QuickStatus>> {
    let _ctx = session_of(&req)?;
    let service = state.sysinfo();
    let active = state.session_store().count();
    Ok(Json(blocking(move || service.quick(active)).await?))
}

/// `GET /api/v1/sysinfo/processes` — sampled task list.
pub(crate) async fn processes(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<ProcessesQuery>,
    req: Request,
) -> ApiResult<Json<ProcessListResponse>> {
    let _ctx = session_of(&req)?;
    let service = state.sysinfo();
    let ceiling = state.cfg().server.max_list_entries.max(1);
    let spec = ProcessQuery {
        limit: query.limit.unwrap_or(200).clamp(1, ceiling),
        query: query.query.filter(|text| !text.trim().is_empty()),
        sort: query.sort.unwrap_or_else(|| "cpu".to_string()),
        descending: query.descending.unwrap_or(true),
    };
    Ok(Json(blocking(move || service.processes(&spec)).await?))
}
