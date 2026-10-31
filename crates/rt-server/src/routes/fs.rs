//! Browsing and mutating the target machine's filesystem.
//!
//! Every path that arrives here is untrusted: `rt_core::fsops` resolves it
//! through a [`PathGuard`] built from the caller's scope, so this module never
//! joins or canonicalises paths on its own.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Multipart, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use rt_core::fsops;
use rt_core::pathscope::PathGuard;
use rt_core::util;
use rt_core::{RtError, SessionContext};
use rt_protocol::error::{ApiErrorBody, ErrorCode};
use rt_protocol::{
    Ack, CopyRequest, DeleteRequest, DeleteResult, FsEntry, FsRoots, ListDirResponse, MkdirRequest,
    ReadFileResult, RenameRequest, StatResponse, WriteResult,
};

use crate::middleware::{
    blocking, json_body, req_id, session_of, ApiErr, ApiQuery, ApiResult, ReqId,
};
use crate::state::AppState;
use crate::streams;

use super::auth::json_limit;

/// `?path=` for the read-only endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct PathQuery {
    pub path: Option<String>,
}

/// `GET /api/v1/fs/read?path=&offset=&length=`.
#[derive(Debug, Deserialize)]
pub(crate) struct ReadQuery {
    pub path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
}

/// `POST /api/v1/fs/write?path=&overwrite=&create_parents=`.
#[derive(Debug, Deserialize)]
pub(crate) struct WriteQuery {
    pub path: String,
    #[serde(default)]
    pub overwrite: Option<bool>,
    #[serde(default)]
    pub create_parents: Option<bool>,
}

/// `POST /api/v1/fs/upload?path=&overwrite=&create_parents=`.
#[derive(Debug, Deserialize)]
pub(crate) struct UploadQuery {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub overwrite: Option<bool>,
    #[serde(default)]
    pub create_parents: Option<bool>,
}

/// `GET /api/v1/fs/roots` — drives and quick paths for this session.
pub(crate) async fn roots(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<FsRoots>> {
    let ctx = session_of(&req)?;
    let guard = state.guard(ctx.scope)?;
    Ok(Json(blocking(move || fsops::roots(&guard)).await?))
}

/// `GET /api/v1/fs/list?path=` — one directory listing.
pub(crate) async fn list(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<PathQuery>,
    req: Request,
) -> ApiResult<Json<ListDirResponse>> {
    let ctx = session_of(&req)?;
    let guard = state.guard(ctx.scope)?;
    let path = query
        .path
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| state.default_list_path(&guard));
    let limits = state.fs_limits();
    Ok(Json(
        blocking(move || fsops::list(&guard, &path, &limits)).await?,
    ))
}

/// `GET /api/v1/fs/stat?path=` — metadata for a single entry.
pub(crate) async fn stat(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<PathQuery>,
    req: Request,
) -> ApiResult<Json<StatResponse>> {
    let ctx = session_of(&req)?;
    let guard = state.guard(ctx.scope)?;
    let path = query
        .path
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| state.default_list_path(&guard));
    Ok(Json(blocking(move || fsops::stat(&guard, &path)).await?))
}

/// `POST /api/v1/fs/mkdir` — creates one directory.
pub(crate) async fn mkdir(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<FsEntry>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: MkdirRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    let target = body.path.clone();
    let guard = state.guard(ctx.scope)?;
    let result = blocking(move || fsops::mkdir(&guard, &body)).await;
    audit_fs(&state, &ctx, "fs.mkdir", &target, result.as_ref().err(), None, &request_id);
    Ok(Json(result?))
}

/// `POST /api/v1/fs/delete` — removes files or directory trees.
pub(crate) async fn delete(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<DeleteResult>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: DeleteRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    let target = body.paths.join(", ");
    let guard = state.guard(ctx.scope)?;
    let result = blocking(move || fsops::delete(&guard, &body)).await;
    audit_fs(&state, &ctx, "fs.delete", &target, result.as_ref().err(), None, &request_id);
    Ok(Json(result?))
}

/// `POST /api/v1/fs/rename` — moves or renames one entry.
pub(crate) async fn rename(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<Ack>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: RenameRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    let target = format!("{} -> {}", body.from, body.to);
    let guard = state.guard(ctx.scope)?;
    let result = blocking(move || fsops::rename(&guard, &body)).await;
    audit_fs(&state, &ctx, "fs.rename", &target, result.as_ref().err(), None, &request_id);
    result?;
    Ok(Json(Ack::with_message("renamed")))
}

/// `POST /api/v1/fs/copy` — copies one entry.
pub(crate) async fn copy(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<WriteResult>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: CopyRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    let target = format!("{} -> {}", body.from, body.to);
    let guard = state.guard(ctx.scope)?;
    let result = blocking(move || fsops::copy(&guard, &body)).await;
    audit_fs(&state, &ctx, "fs.copy", &target, result.as_ref().err(), None, &request_id);
    Ok(Json(result?))
}

/// `GET /api/v1/fs/read?path=&offset=&length=` — inline text/base64 preview.
pub(crate) async fn read(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<ReadQuery>,
    req: Request,
) -> ApiResult<Json<ReadFileResult>> {
    let _ctx = session_of(&req)?;
    let guard = state.guard(_ctx.scope)?;
    let limits = state.fs_limits();
    let path = query.path;
    let offset = query.offset.unwrap_or(0);
    let length = query.length;
    Ok(Json(
        blocking(move || fsops::read(&guard, &path, offset, length, &limits)).await?,
    ))
}

/// `GET /api/v1/fs/download?path=` — streams a file, honouring `Range`.
pub(crate) async fn download(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<PathQuery>,
    req: Request,
) -> ApiResult<Response> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let path = query.path.filter(|p| !p.trim().is_empty()).ok_or_else(|| {
        ApiErr::bad_request("`path` query parameter is required for downloads")
    })?;
    let display_path = path.clone();
    let guard = state.guard(ctx.scope)?;

    let opened = blocking(move || fsops::open_for_read(&guard, &path)).await;
    let (real_path, file, size) = match opened {
        Ok(found) => found,
        Err(err) => {
            audit_fs(
                &state,
                &ctx,
                "fs.download",
                &display_path,
                Some(&err),
                None,
                &request_id,
            );
            return Err(err.into());
        }
    };

    let byte_range = match parse_range(range_header.as_deref(), size) {
        Ok(range) => range,
        Err(body) => {
            let failure = ApiErr::from(RtError::RangeNotSatisfiable(
                "unsatisfiable range".to_string(),
            ));
            audit_fs(
                &state,
                &ctx,
                "fs.download",
                &display_path,
                Some(&failure),
                None,
                &request_id,
            );
            return Ok(range_not_satisfiable(body, size));
        }
    };

    let (start, length) = byte_range.bounds(size);
    let mut handle = tokio::fs::File::from_std(file);
    if start > 0 {
        if let Err(err) = handle.seek(std::io::SeekFrom::Start(start)).await {
            return Err(ApiErr::internal(format!("seek failed: {err}")));
        }
    }
    let stream = ReaderStream::with_capacity(handle.take(length), 64 * 1024);

    let mime = mime_guess::from_path(&real_path).first_or_octet_stream();
    let filename = util::sanitize_filename(
        real_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download"),
    );

    let mut response = (
        if matches!(byte_range, ByteRange::Partial { .. }) {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        },
        Body::from_stream(stream),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header_value(mime.essence_str()));
    headers.insert(header::CONTENT_LENGTH, header_value(&length.to_string()));
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        header_value(&format!("attachment; filename=\"{filename}\"")),
    );
    if let ByteRange::Partial { start, end } = byte_range {
        headers.insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {start}-{end}/{size}")),
        );
    }

    audit_fs(
        &state,
        &ctx,
        "fs.download",
        &display_path,
        None,
        Some(format!("{} bytes", length)),
        &request_id,
    );
    Ok(response)
}

/// `POST /api/v1/fs/write?path=&overwrite=&create_parents=` — raw body upload.
pub(crate) async fn write(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<WriteQuery>,
    req: Request,
) -> ApiResult<Json<WriteResult>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let max_bytes = max_upload_bytes(&state);
    let guard = state.guard(ctx.scope)?;
    let limits = state.fs_limits();
    let target = query.path.clone();
    let overwrite = query.overwrite.unwrap_or(false);
    let create_parents = query.create_parents.unwrap_or(true);

    let (mut writer, reader) = streams::channel();
    let task_path = target.clone();
    let task = tokio::task::spawn_blocking(move || {
        fsops::write_stream(&guard, &task_path, reader, overwrite, create_parents, &limits)
    });

    let mut received: u64 = 0;
    let mut stream = req.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                writer.fail(format!("request body aborted: {err}"));
                return Err(ApiErr::bad_request(format!(
                    "request body could not be read: {err}"
                )));
            }
        };
        if chunk.is_empty() {
            continue;
        }
        received = received.saturating_add(chunk.len() as u64);
        if received > max_bytes {
            writer.fail("upload exceeds max_upload_mb");
            return Err(ApiErr::new(
                ErrorCode::PayloadTooLarge,
                format!("upload exceeds the {} byte limit", max_bytes),
            ));
        }
        if !writer.send(chunk).await {
            break;
        }
    }
    writer.finish();

    let result = join_writer(task).await;
    audit_fs(
        &state,
        &ctx,
        "fs.write",
        &target,
        result.as_ref().err(),
        Some(format!("{received} bytes uploaded")),
        &request_id,
    );
    Ok(Json(result?))
}

/// `POST /api/v1/fs/upload?path=&overwrite=&create_parents=` — multipart form.
pub(crate) async fn upload(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<SessionContext>,
    Extension(req_id_ext): Extension<ReqId>,
    ApiQuery(query): ApiQuery<UploadQuery>,
    mut multipart: Multipart,
) -> ApiResult<Json<WriteResult>> {
    let max_bytes = max_upload_bytes(&state);
    // Shared so every loop iteration can hand an owned handle to the writer
    // task; the guard itself is read-only after construction.
    let guard = Arc::new(state.guard(ctx.scope)?);
    let limits = Arc::new(state.fs_limits());
    let overwrite = query.overwrite.unwrap_or(false);
    let create_parents = query.create_parents.unwrap_or(true);
    let hint = query.path.clone();

    loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|err| ApiErr::bad_request(format!("invalid multipart body: {}", err.body_text())))?;
        let Some(mut field) = field else {
            return Err(ApiErr::bad_request(
                "multipart body must contain a `file` field",
            ));
        };

        let is_named_file = field.name() == Some("file");
        let has_filename = field.file_name().is_some();
        if !is_named_file && !has_filename {
            continue;
        }

        let filename = field.file_name().map(str::to_string);
        let target = upload_target(&state, &guard, hint.as_deref(), filename.as_deref());

        let (mut writer, reader) = streams::channel();
        let task_path = target.clone();
        let task_guard = Arc::clone(&guard);
        let task_limits = Arc::clone(&limits);
        let task = tokio::task::spawn_blocking(move || {
            fsops::write_stream(
                &task_guard,
                &task_path,
                reader,
                overwrite,
                create_parents,
                &task_limits,
            )
        });

        let mut received: u64 = 0;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    received = received.saturating_add(chunk.len() as u64);
                    if received > max_bytes {
                        writer.fail("upload exceeds max_upload_mb");
                        return Err(ApiErr::new(
                            ErrorCode::PayloadTooLarge,
                            format!("upload exceeds the {} byte limit", max_bytes),
                        ));
                    }
                    if !writer.send(chunk).await {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    writer.fail(format!("multipart body aborted: {err}"));
                    return Err(ApiErr::bad_request(format!(
                        "multipart body could not be read: {}",
                        err.body_text()
                    )));
                }
            }
        }
        writer.finish();

        let result = join_writer(task).await;
        audit_fs(
            &state,
            &ctx,
            "fs.upload",
            &target,
            result.as_ref().err(),
            Some(format!("{received} bytes uploaded")),
            &req_id_ext.0,
        );
        return Ok(Json(result?));
    }
}

// --------------------------------------------------------------------- helpers

/// One `Range` request, resolved against the file size.
#[derive(Debug, Clone, Copy)]
enum ByteRange {
    Full,
    Partial { start: u64, end: u64 },
}

impl ByteRange {
    fn bounds(self, size: u64) -> (u64, u64) {
        match self {
            ByteRange::Full => (0, size),
            ByteRange::Partial { start, end } => (start, end - start + 1),
        }
    }
}

/// Parses `Range: bytes=…`; only single ranges are supported.
fn parse_range(raw: Option<&str>, size: u64) -> Result<ByteRange, ApiErrorBody> {
    let Some(raw) = raw else {
        return Ok(ByteRange::Full);
    };
    let raw = raw.trim();
    let spec = raw
        .strip_prefix("bytes=")
        .map(str::trim)
        .ok_or_else(|| range_error(size))?;
    if size == 0 {
        return Err(range_error(size));
    }
    let spec = spec.split(',').next().unwrap_or("").trim();
    let (start_raw, end_raw) = spec.split_once('-').ok_or_else(|| range_error(size))?;

    let (start, end) = if start_raw.trim().is_empty() {
        // Suffix form: the last N bytes.
        let want: u64 = end_raw
            .trim()
            .parse()
            .map_err(|_| range_error(size))?;
        if want == 0 {
            return Err(range_error(size));
        }
        (size.saturating_sub(want), size - 1)
    } else {
        let start: u64 = start_raw
            .trim()
            .parse()
            .map_err(|_| range_error(size))?;
        let end = if end_raw.trim().is_empty() {
            size - 1
        } else {
            end_raw
                .trim()
                .parse::<u64>()
                .map_err(|_| range_error(size))?
                .min(size - 1)
        };
        if start > end || start >= size {
            return Err(range_error(size));
        }
        (start, end)
    };

    Ok(ByteRange::Partial { start, end })
}

fn range_error(size: u64) -> ApiErrorBody {
    ApiErrorBody::new(
        ErrorCode::RangeNotSatisfiable,
        "requested byte range cannot be satisfied",
    )
    .with_detail(serde_json::json!({ "size": size }))
}

/// `416` answer that advertises the real size.
fn range_not_satisfiable(mut body: ApiErrorBody, size: u64) -> Response {
    body = body.with_detail(serde_json::json!({ "size": size }));
    let mut response = (StatusCode::RANGE_NOT_SATISFIABLE, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_RANGE,
        header_value(&format!("bytes */{size}")),
    );
    response
}

/// Builds a header value, falling back to a static placeholder on bad input.
fn header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
}

/// Upload ceiling in bytes (`server.max_upload_mb`).
fn max_upload_bytes(state: &AppState) -> u64 {
    state
        .cfg()
        .server
        .max_upload_mb
        .max(1)
        .saturating_mul(1024 * 1024)
}

/// Awaits a streaming writer task, turning a panic into a plain 500.
async fn join_writer(
    task: tokio::task::JoinHandle<rt_core::Result<WriteResult>>,
) -> ApiResult<WriteResult> {
    match task.await {
        Ok(result) => result.map_err(ApiErr::from),
        Err(err) => Err(ApiErr::internal(format!("upload worker failed: {err}"))),
    }
}

/// Chooses the destination of a multipart upload.
///
/// A `path` ending in a separator is treated as a directory; anything else is
/// the full target path. Without `path` the file lands in the session root.
fn upload_target(
    state: &AppState,
    guard: &PathGuard,
    hint: Option<&str>,
    filename: Option<&str>,
) -> String {
    let name = filename
        .map(util::sanitize_filename)
        .filter(|name| !name.trim().is_empty());

    match hint.map(str::trim).filter(|hint| !hint.is_empty()) {
        Some(hint) if hint.ends_with('\\') || hint.ends_with('/') => match name {
            Some(name) => join_display(hint, &name),
            None => hint.to_string(),
        },
        Some(hint) => hint.to_string(),
        None => match name {
            Some(name) => join_display(&state.default_list_path(guard), &name),
            None => state.default_list_path(guard),
        },
    }
}

/// Appends `name` to `dir` without doubling separators.
fn join_display(dir: &str, name: &str) -> String {
    let trimmed = dir.trim_end_matches(['\\', '/']);
    format!("{trimmed}\\{name}")
}

/// Records one filesystem operation in the audit trail.
fn audit_fs(
    state: &AppState,
    ctx: &SessionContext,
    action: &str,
    target: &str,
    outcome: Option<&ApiErr>,
    extra: Option<String>,
    request_id: &str,
) {
    let event = match outcome {
        Some(_) => ctx.audit(action, "failure"),
        None => ctx.audit(action, "success"),
    };
    let event = event.target(target);
    let event = match (outcome, extra) {
        (Some(err), Some(extra)) => event.detail(format!("{}; {extra}", err.message())),
        (Some(err), None) => event.detail(err.message()),
        (None, Some(extra)) => event.detail(extra),
        (None, None) => event,
    };
    state.record_audit(event.request_id(request_id));
}
