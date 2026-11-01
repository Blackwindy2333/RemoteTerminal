//! Screen and window capture.
//!
//! `POST /api/v1/capture` returns base64 inside JSON (for API clients), while
//! `GET /api/v1/capture/raw` streams the encoded image so a browser `<img>`
//! tag or a WS frame consumer can use it directly.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rt_protocol::error::ErrorCode;
use rt_protocol::{
    CaptureRequest, CaptureResponse, CaptureTarget, ImageFormat, ScreenListResponse, WindowListResponse,
};
use serde::Deserialize;

use crate::middleware::{
    json_body, req_id, require_full_scope, session_of, ApiErr, ApiQuery, ApiResult,
};
use crate::state::AppState;

use super::auth::json_limit;

/// `GET /api/v1/capture/raw?target=primary&format=png&quality=80&max_width=`.
#[derive(Debug, Deserialize)]
pub(crate) struct RawQuery {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub quality: Option<u8>,
    #[serde(default)]
    pub max_width: Option<u32>,
    #[serde(default)]
    pub max_height: Option<u32>,
}

/// `GET /api/v1/capture/screens` — connected displays.
pub(crate) async fn screens(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<ScreenListResponse>> {
    let _ctx = session_of(&req)?;
    let screens = state.spawn_blocking_admitted(rt_core::capture::list_screens).await?;
    Ok(Json(ScreenListResponse { screens }))
}

/// `GET /api/v1/capture/windows` — capturable top-level windows.
pub(crate) async fn windows(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<WindowListResponse>> {
    let ctx = session_of(&req)?;
    require_full_scope(&ctx, "listing windows")?;
    let windows = state.spawn_blocking_admitted(rt_core::capture::list_windows).await?;
    Ok(Json(WindowListResponse {
        windows,
        truncated: false,
        sampled_at: rt_core::auth::rfc3339_ms(rt_core::auth::now_ms()),
    }))
}

/// `POST /api/v1/capture` — capture as base64 inside JSON.
pub(crate) async fn capture(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<CaptureResponse>> {
    let ctx = session_of(&req)?;
    // Screen pixels are outside the workspace jail, so this needs full scope.
    require_full_scope(&ctx, "capturing the screen")?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: CaptureRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    let target_label = format!("{:?}", body.target);

    let result = state.spawn_blocking_admitted(move || rt_core::capture::capture(&body)).await;
    state.record_audit(
        ctx.audit(
            "capture.request",
            if result.is_ok() { "success" } else { "failure" },
        )
        .target(&target_label)
        .request_id(request_id),
    );
    Ok(Json(result?))
}

/// `GET /api/v1/capture/raw` — the encoded image itself, cheap for browsers.
pub(crate) async fn raw(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<RawQuery>,
    req: Request,
) -> ApiResult<Response> {
    let ctx = session_of(&req)?;
    // Screen pixels are outside the workspace jail, so this needs full scope.
    require_full_scope(&ctx, "capturing the screen")?;
    let request_id = req_id(&req);

    let target = parse_target(query.target.as_deref().unwrap_or("primary"))?;
    let format = match query.format.as_deref() {
        Some(raw) => ImageFormat::parse(raw).ok_or_else(|| {
            ApiErr::new(
                ErrorCode::BadRequest,
                format!("unsupported image format `{raw}`; use png, jpeg or bmp"),
            )
        })?,
        None => ImageFormat::Png,
    };
    let request = CaptureRequest {
        target: target.clone(),
        format,
        quality: query.quality.or(Some(80)).filter(|_| format == ImageFormat::Jpeg),
        max_width: query.max_width,
        max_height: query.max_height,
    };

    // `capture_bytes` skips the base64 round-trip `capture` needs for JSON.
    let result = state.spawn_blocking_admitted(move || rt_core::capture::capture_bytes(&request)).await;
    let response = match result {
        Ok((meta, bytes)) => {
            let len = bytes.len();
            let mut response = (StatusCode::OK, bytes).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(meta.format.mime()),
            );
            if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(response)
        }
        Err(err) => Err(err.into()),
    };

    state.record_audit(
        ctx.audit(
            "capture.raw",
            if response.is_ok() { "success" } else { "failure" },
        )
        .target(format!("{target:?}"))
        .request_id(request_id),
    );
    response
}

/// Parses `primary` / `all` / `screen:<id>` / `window:<id>`.
fn parse_target(raw: &str) -> Result<CaptureTarget, ApiErr> {
    let text = raw.trim();
    let lower = text.to_ascii_lowercase();
    match lower.as_str() {
        "" | "primary" | "main" => Ok(CaptureTarget::Primary),
        "all" | "all_screens" | "allscreens" => Ok(CaptureTarget::AllScreens),
        _ => {
            if let Some(rest) = lower.strip_prefix("screen:") {
                let id = rest.trim().parse::<u32>().map_err(|_| {
                    ApiErr::bad_request(format!("`{text}` needs a numeric screen id"))
                })?;
                return Ok(CaptureTarget::Screen { id });
            }
            if let Some(rest) = lower.strip_prefix("window:") {
                let id = rest.trim().parse::<u64>().map_err(|_| {
                    ApiErr::bad_request(format!("`{text}` needs a numeric window id"))
                })?;
                return Ok(CaptureTarget::Window { id });
            }
            Err(ApiErr::bad_request(format!(
                "unknown capture target `{text}`; use primary, all, screen:<id> or window:<id>"
            )))
        }
    }
}
