//! Server introspection: log tail, audit trail and the OpenAPI document.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::Json;
use rt_protocol::ws::LogEvent;
use serde::Deserialize;

use crate::middleware::{require_full_scope, session_of, ApiQuery, ApiResult};
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
    let records = state.spawn_blocking_admitted(move || Ok(tail_json_lines(&path, limit))).await?;
    Ok(Json(records))
}

/// `GET /api/v1/openapi.json` — machine-readable description of this API.
pub(crate) async fn openapi() -> Json<serde_json::Value> {
    Json(crate::openapi::document())
}

/// Bytes read per backwards step while tailing a file.
const TAIL_CHUNK: u64 = 16 * 1024;

/// Reads the last `limit` JSON lines of a file, newest last.
///
/// The audit trail is append-only and can reach gigabytes, so the tail is
/// rebuilt from the end in fixed-size blocks instead of loading the whole file
/// (SECURITY.md S-35).
fn tail_json_lines(path: &std::path::Path, limit: usize) -> Vec<serde_json::Value> {
    tail_lines(path, limit)
        .into_iter()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
        .collect()
}

/// Last `limit` non-empty lines of a file, newest first.
fn tail_lines(path: &std::path::Path, limit: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};

    if limit == 0 {
        return Vec::new();
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }

    let mut tail: Vec<u8> = Vec::new();
    let mut position = size;
    let mut newlines = 0usize;
    while position > 0 && newlines <= limit {
        let step = position.min(TAIL_CHUNK);
        position -= step;
        let mut block = vec![0u8; step as usize];
        if file.seek(SeekFrom::Start(position)).is_err() || file.read_exact(&mut block).is_err() {
            break;
        }
        newlines += block.iter().filter(|byte| **byte == b'\n').count();
        block.extend_from_slice(&tail);
        tail = block;
    }

    // Stopping before the start of the file means the first line of the window
    // was cut by the seek, so it is discarded.
    if position > 0 {
        match tail.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                tail.drain(..=index);
            }
            None => tail.clear(),
        }
    }

    tail.split(|byte| *byte == b'\n')
        .map(|line| String::from_utf8_lossy(line).trim_end().to_string())
        .filter(|line| !line.is_empty())
        .rev()
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_lines(dir: &std::path::Path, count: usize) -> std::path::PathBuf {
        let path = dir.join("audit.jsonl");
        let mut body = String::new();
        for index in 0..count {
            // `ts_ms` stays unpadded so every line is valid JSON.
            body.push_str(&format!(
                "{{\"action\":\"test\",\"ts_ms\":{index},\"detail\":\"{}\"}}\n",
                "x".repeat(20)
            ));
        }
        std::fs::write(&path, body).expect("write audit file");
        path
    }

    #[test]
    fn tail_returns_the_newest_lines_in_order() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_lines(dir.path(), 40);
        let records = tail_json_lines(&path, 3);
        let stamps: Vec<u64> = records
            .iter()
            .map(|value| value["ts_ms"].as_u64().expect("ts"))
            .collect();
        assert_eq!(stamps, vec![37, 38, 39]);
    }

    #[test]
    fn tail_handles_files_larger_than_one_chunk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_lines(dir.path(), 2000);
        assert!(std::fs::metadata(&path).expect("metadata").len() > TAIL_CHUNK);

        let records = tail_json_lines(&path, 5);
        assert_eq!(records.len(), 5, "a chunk seam must not drop a line");
        assert_eq!(records[4]["ts_ms"].as_u64(), Some(1999));
        assert_eq!(records[0]["ts_ms"].as_u64(), Some(1995));
    }

    #[test]
    fn tail_of_a_missing_file_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(tail_json_lines(&dir.path().join("absent.jsonl"), 10).is_empty());
    }

    #[test]
    fn tail_skips_lines_that_are_not_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"a\":1}\nnot json\n{\"a\":2}\n").expect("write");
        let records = tail_json_lines(&path, 5);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["a"].as_u64(), Some(1));
        assert_eq!(records[1]["a"].as_u64(), Some(2));
    }
}
