//! WebSocket multiplexing: one socket carries command streams, capture frames
//! and live log tails, keyed by a client-chosen `id`.
//!
//! Every message is a JSON text frame with an explicit `type` tag so the
//! protocol can grow without breaking old clients.

use serde::{Deserialize, Serialize};

use crate::{
    ApiErrorDetail, CaptureFrame, CaptureRequest, ExecRequest, ExecSummary, OutputStream,
};

pub const WS_PATH: &str = "/api/v1/ws";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// `trace` | `debug` | `info` | `warn` | `error`
    pub level: String,
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    Ping {
        id: u64,
    },
    /// Run a command, streaming output back with the same `id`.
    Exec {
        id: u64,
        request: ExecRequest,
    },
    /// Cancel a running stream (exec or capture).
    Cancel {
        id: u64,
    },
    /// Push frames at `fps` until stopped or `max_frames` is reached.
    CaptureStream {
        id: u64,
        request: CaptureRequest,
        #[serde(default = "default_fps")]
        fps: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_frames: Option<u32>,
    },
    /// Tail the server log.
    SubscribeLogs {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        level: Option<String>,
        #[serde(default = "default_log_backlog")]
        backlog: u32,
    },
    /// Push one-off status samples (CPU/mem) at `fps`.
    SubscribeStatus {
        id: u64,
        #[serde(default = "default_status_fps")]
        fps: u8,
    },
    Unsubscribe {
        id: u64,
    },
}

fn default_fps() -> u8 {
    2
}

fn default_status_fps() -> u8 {
    1
}

fn default_log_backlog() -> u32 {
    200
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMessage {
    Pong {
        id: u64,
    },
    /// Request accepted; the stream will follow.
    Accepted {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    ExecStarted {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        shell: String,
    },
    ExecOutput {
        id: u64,
        stream: OutputStream,
        /// Decoded text chunk (encoding normalised server side).
        data: String,
        /// Raw byte offset within this stream, so clients can de-duplicate.
        #[serde(default)]
        seq: u64,
    },
    ExecFinished {
        id: u64,
        summary: ExecSummary,
        /// Buffered tail (bounded) so a late joiner still sees something.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_tail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stderr_tail: Option<String>,
    },
    CaptureFrame {
        id: u64,
        frame: CaptureFrame,
    },
    CaptureStopped {
        id: u64,
        reason: String,
        frames: u64,
    },
    Log {
        id: u64,
        event: LogEvent,
    },
    Status {
        id: u64,
        status: crate::QuickStatus,
    },
    Unsubscribed {
        id: u64,
    },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        error: ApiErrorDetail,
    },
}

impl WsServerMessage {
    pub fn error(id: Option<u64>, detail: ApiErrorDetail) -> Self {
        WsServerMessage::Error { id, error: detail }
    }
}

/// Reply to `GET /api/v1/ws/info`: what this socket endpoint supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsInfo {
    pub path: String,
    pub max_message_bytes: u64,
    pub max_frame_fps: u8,
    pub max_concurrent_streams: u32,
}
