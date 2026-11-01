//! WebSocket endpoint: streaming `exec`, capture previews, log and status tails.
//!
//! The socket authenticates with a one-time ticket (minted over REST), never
//! with the bearer token, so credentials never appear in URLs or logs. Every
//! stream started by a client message runs as its own task and is aborted when
//! the socket closes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Request, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{self, error::TrySendError, unbounded_channel};
use tokio::task::JoinHandle;

use rt_core::exec::{self, ExecControl, ExecEvent};
use rt_core::logging::AuditEvent;
use rt_core::{RtError, SessionContext};
use rt_protocol::error::{ApiErrorBody, ErrorCode};
use rt_protocol::ws::{WsClientMessage, WsInfo, WsServerMessage};
use rt_protocol::{ExecRequest, ExecSummary, OutputStream};

use crate::middleware::{api_detail, error_response};
use crate::state::{AppState, TicketError, WS_MAX_CONCURRENT_STREAMS, WS_MAX_MESSAGE_BYTES};

/// How many bytes of each stream tail are echoed in `exec_finished`.
const TAIL_BYTES: usize = 2000;

/// Default width cap for WebSocket capture previews.
const WS_CAPTURE_MAX_WIDTH: u32 = 1280;

/// Frames buffered per socket before the server starts dropping them.
///
/// The socket feed must stay bounded: a client that stops reading would
/// otherwise grow server memory without limit. Dropped frames are counted and
/// reported to the client as soon as the queue catches up.
const WS_OUTBOUND_CAPACITY: usize = 256;

/// One running client-requested stream.
struct StreamTask {
    control: Option<ExecControl>,
    handle: JoinHandle<()>,
}

/// What happened to a frame handed to the outbound queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Queued {
    /// The frame is waiting for the writer task.
    Sent,
    /// The queue was full and the frame was dropped to bound memory.
    Dropped,
    /// The peer is gone, so the producing stream can stop.
    Closed,
}

/// Bounded, cloneable handle to one socket's outbound frame queue.
#[derive(Clone)]
struct Outbound {
    tx: mpsc::Sender<WsServerMessage>,
    dropped: Arc<AtomicU64>,
}

impl Outbound {
    /// Creates the queue and the receiver drained by the socket writer task.
    fn channel(capacity: usize) -> (Self, mpsc::Receiver<WsServerMessage>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Queues a frame without ever blocking the producer.
    fn send(&self, message: WsServerMessage) -> Queued {
        match self.tx.try_send(message) {
            Ok(()) => Queued::Sent,
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Queued::Dropped
            }
            Err(TrySendError::Closed(_)) => Queued::Closed,
        }
    }

    /// Returns how many frames were dropped since the previous call.
    fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Error frame used when a stream needs more scope than the session has.
fn scope_error(what: &str) -> RtError {
    RtError::Forbidden(format!(
        "{what} requires the full scope; this session is limited to the workspace"
    ))
}

/// Serialises one server message into the socket.
async fn write_frame(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    message: &WsServerMessage,
) -> Result<(), ()> {
    let Ok(text) = serde_json::to_string(message) else {
        return Ok(());
    };
    sink.send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

/// Notice telling the client how many frames the server had to drop.
fn drop_notice(dropped: u64) -> WsServerMessage {
    WsServerMessage::error(
        None,
        api_detail(RtError::Unavailable(format!(
            "dropped {dropped} frame(s) because this client stopped reading"
        ))),
    )
}

/// `GET /api/v1/ws?ticket=` — validates the ticket, then upgrades.
pub(crate) async fn upgrade(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let ticket = ticket_from_query(req.uri().query().unwrap_or_default());
    // The ticket is bound to the address that minted it, so a ticket can only
    // be redeemed by the client it was issued to (SECURITY.md S-24).
    let client_ip = crate::middleware::client_of(&req).ip;
    let ctx = match state.take_ticket(&ticket, &client_ip) {
        Ok(ctx) => ctx,
        Err(TicketError::Unknown) => {
            return error_response(ApiErrorBody::new(
                ErrorCode::Unauthorized,
                "invalid or expired websocket ticket",
            ))
        }
        Err(TicketError::AddressMismatch) => {
            return error_response(ApiErrorBody::new(
                ErrorCode::Forbidden,
                "this websocket ticket was issued to another address",
            ))
        }
    };

    let (mut parts, _body) = req.into_parts();
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    upgrade
        .max_message_size(WS_MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| run_socket(state, ctx, socket))
}

/// `GET /api/v1/ws/info` — describes the streaming endpoint's limits.
pub(crate) async fn info(State(state): State<Arc<AppState>>) -> Json<WsInfo> {
    Json(state.ws_info())
}

/// Extracts `ticket=` out of a raw query string.
fn ticket_from_query(query: &str) -> String {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("ticket="))
        .unwrap_or("")
        .to_string()
}

/// Drives one socket until either side closes it.
async fn run_socket(state: Arc<AppState>, ctx: SessionContext, socket: WebSocket) {
    let (out, mut out_rx) = Outbound::channel(WS_OUTBOUND_CAPACITY);
    let (mut sink, mut stream) = socket.split();

    state.record_audit(
        AuditEvent::new("ws.connect", "success")
            .user(ctx.username.clone())
            .scope(ctx.scope.as_str())
            .remote(ctx.remote.clone().unwrap_or_default())
            .request_id(ctx.request_id.clone()),
    );
    tracing::info!(target: "ws", user = %ctx.username, scope = %ctx.scope.as_str(), "websocket connected");

    let writer_out = out.clone();
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if write_frame(&mut sink, &message).await.is_err() {
                break;
            }
            let dropped = writer_out.take_dropped();
            if dropped > 0 && write_frame(&mut sink, &drop_notice(dropped)).await.is_err() {
                break;
            }
        }
    });

    let mut tasks: HashMap<u64, StreamTask> = HashMap::new();

    while let Some(frame) = stream.next().await {
        let text = match frame {
            Ok(Message::Text(text)) => text.to_string(),
            Ok(Message::Binary(bytes)) => match String::from_utf8(bytes.to_vec()) {
                Ok(text) => text,
                Err(_) => {
                    send_error(&out, None, RtError::bad_request("binary frames must be UTF-8 JSON"));
                    continue;
                }
            },
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => break,
            Err(err) => {
                tracing::debug!(target: "ws", "socket read error: {err}");
                break;
            }
        };

        let message: WsClientMessage = match serde_json::from_str(&text) {
            Ok(message) => message,
            Err(err) => {
                send_error(
                    &out,
                    None,
                    RtError::bad_request(format!("invalid client message: {err}")),
                );
                continue;
            }
        };

        // Finished streams are dropped opportunistically so a long session does
        // not slowly exhaust the stream budget.
        tasks.retain(|_, task| !task.handle.is_finished());

        match message {
            WsClientMessage::Ping { id } => {
                let _ = out.send(WsServerMessage::Pong { id });
            }

            WsClientMessage::Exec { id, request } => {
                // Running an arbitrary process would bypass the path jail.
                if !ctx.scope.is_full() {
                    send_error(&out, Some(id), scope_error("executing commands"));
                    continue;
                }
                if tasks.contains_key(&id) {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Conflict(format!("id {id} is already in use")),
                    );
                    continue;
                }
                if tasks.len() >= WS_MAX_CONCURRENT_STREAMS as usize {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Unavailable("too many concurrent streams on this socket".into()),
                    );
                    continue;
                }
                match start_exec(&state, &ctx, id, request, &out) {
                    Ok((control, handle)) => {
                        tasks.insert(
                            id,
                            StreamTask {
                                control: Some(control),
                                handle,
                            },
                        );
                    }
                    Err(err) => send_error(&out, Some(id), err),
                }
            }

            WsClientMessage::Cancel { id } => match tasks.get(&id) {
                Some(task) => {
                    if let Some(control) = &task.control {
                        control.cancel();
                    }
                    let _ = out.send(WsServerMessage::Accepted {
                        id,
                        detail: Some("cancellation requested".to_string()),
                    });
                }
                None => {
                    let _ = out.send(WsServerMessage::Accepted {
                        id,
                        detail: Some("no running stream with that id".to_string()),
                    });
                }
            },

            WsClientMessage::CaptureStream {
                id,
                request,
                fps,
                max_frames,
            } => {
                if tasks.contains_key(&id) {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Conflict(format!("id {id} is already in use")),
                    );
                    continue;
                }
                if tasks.len() >= WS_MAX_CONCURRENT_STREAMS as usize {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Unavailable("too many concurrent streams on this socket".into()),
                    );
                    continue;
                }
                // Screen pixels are outside the workspace jail.
                if !ctx.scope.is_full() {
                    send_error(&out, Some(id), scope_error("capturing the screen"));
                    continue;
                }
                let handle = start_capture(&state, id, request, fps, max_frames, &out);
                tasks.insert(
                    id,
                    StreamTask {
                        control: None,
                        handle,
                    },
                );
                let _ = out.send(WsServerMessage::Accepted {
                    id,
                    detail: Some("capture stream started".to_string()),
                });
            }

            WsClientMessage::SubscribeLogs { id, level, backlog } => {
                // The REST tail is full-scope only; the socket must not differ.
                if !ctx.scope.is_full() {
                    send_error(&out, Some(id), scope_error("streaming logs"));
                    continue;
                }
                tasks.retain(|_, task| !task.handle.is_finished());
                if tasks.len() >= WS_MAX_CONCURRENT_STREAMS as usize {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Unavailable("too many concurrent streams on this socket".into()),
                    );
                    continue;
                }
                let handle = start_logs(&state, id, level.clone(), backlog, &out);
                tasks.insert(
                    id,
                    StreamTask {
                        control: None,
                        handle,
                    },
                );
                let _ = out.send(WsServerMessage::Accepted {
                    id,
                    detail: Some(format!("streaming logs since level {:?}", level)),
                });
            }

            WsClientMessage::SubscribeStatus { id, fps } => {
                tasks.retain(|_, task| !task.handle.is_finished());
                if tasks.len() >= WS_MAX_CONCURRENT_STREAMS as usize {
                    send_error(
                        &out,
                        Some(id),
                        RtError::Unavailable("too many concurrent streams on this socket".into()),
                    );
                    continue;
                }
                let handle = start_status(&state, id, fps, &out);
                tasks.insert(
                    id,
                    StreamTask {
                        control: None,
                        handle,
                    },
                );
                let _ = out.send(WsServerMessage::Accepted {
                    id,
                    detail: Some(format!("streaming status at {fps} fps")),
                });
            }

            WsClientMessage::Unsubscribe { id } => {
                if let Some(task) = tasks.remove(&id) {
                    if let Some(control) = &task.control {
                        control.cancel();
                    }
                    task.handle.abort();
                }
                let _ = out.send(WsServerMessage::Unsubscribed { id });
            }
        }
    }

    // Socket closed: stop every stream it owns.
    for (_, task) in tasks.drain() {
        if let Some(control) = task.control {
            control.cancel();
        }
        task.handle.abort();
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;

    state.record_audit(
        AuditEvent::new("ws.disconnect", "success")
            .user(ctx.username.clone())
            .scope(ctx.scope.as_str())
            .remote(ctx.remote.clone().unwrap_or_default())
            .request_id(ctx.request_id.clone()),
    );
    tracing::info!(target: "ws", user = %ctx.username, "websocket disconnected");
}

/// Queues one error frame; ignores send failures (the peer is gone anyway).
fn send_error(out: &Outbound, id: Option<u64>, err: RtError) {
    let _ = out.send(WsServerMessage::error(id, api_detail(err)));
}

/// Spawns the bridging task that runs one command and forwards its events.
fn start_exec(
    state: &Arc<AppState>,
    ctx: &SessionContext,
    id: u64,
    request: ExecRequest,
    out: &Outbound,
) -> Result<(ExecControl, JoinHandle<()>), RtError> {
    if let Err(message) = request.validate() {
        return Err(RtError::bad_request(message));
    }
    let guard = state.guard(ctx.scope)?;
    let limits = state.exec_limits();
    let slots = state.exec_slots();
    let control = ExecControl::new();

    let tracker = control.clone();
    let runner = control.clone();
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    let audit_request = request.clone();
    let out = out.clone();

    let handle = tokio::spawn(async move {
        let permit = match slots.acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                send_error(&out, Some(id), RtError::Unavailable("server is shutting down".into()));
                return;
            }
        };

        let (event_tx, mut event_rx) = unbounded_channel::<ExecEvent>();
        let runner_control = runner;

        let blocking = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut stdout_tail = String::new();
            let mut stderr_tail = String::new();
            let result = {
                let mut sink = |event: ExecEvent| {
                    if let ExecEvent::Output(stream, data) = &event {
                        match stream {
                            OutputStream::Stdout => push_tail(&mut stdout_tail, data),
                            OutputStream::Stderr => push_tail(&mut stderr_tail, data),
                            OutputStream::Notice => {}
                        }
                    }
                    let _ = event_tx.send(event);
                };
                exec::run_streaming(&guard, &request, &limits, runner_control, &mut sink)
            };
            (result, stdout_tail, stderr_tail)
        });

        let mut seq: u64 = 0;
        let mut events_open = true;
        let mut blocking = Box::pin(blocking);

        let joined = loop {
            tokio::select! {
                maybe = event_rx.recv(), if events_open => match maybe {
                    Some(event) => forward_event(&out, id, &mut seq, event),
                    None => events_open = false,
                },
                joined = &mut blocking => break joined,
            }
        };

        let (result, stdout_tail, stderr_tail) = match joined {
            Ok(value) => value,
            Err(join_error) => (
                Err(RtError::internal(format!("exec worker failed: {join_error}"))),
                String::new(),
                String::new(),
            ),
        };

        match result {
            Ok(full) => {
                let summary = ExecSummary {
                    exit_code: full.exit_code,
                    duration_ms: full.duration_ms,
                    timed_out: full.timed_out,
                    truncated: full.truncated,
                    stdout_bytes: full.stdout_bytes,
                    stderr_bytes: full.stderr_bytes,
                    pid: full.pid,
                    cancelled: Some(tracker.is_cancelled()),
                };
                let _ = out.send(WsServerMessage::ExecFinished {
                    id,
                    summary: summary.clone(),
                    stdout_tail: non_empty(&stdout_tail),
                    stderr_tail: non_empty(&stderr_tail),
                });
                state.record_audit(
                    ctx.audit("exec.run", "success")
                        .target(full.shell.clone())
                        .detail(format!(
                            "exit={} cmd={} via=ws",
                            summary.exit_code,
                            truncate(&audit_request.command, 400)
                        ))
                        .request_id(ctx.request_id.clone()),
                );
                tracing::info!(
                    target: "exec",
                    user = %ctx.username,
                    shell = %full.shell,
                    exit_code = full.exit_code,
                    duration_ms = full.duration_ms,
                    "ws exec finished"
                );
            }
            Err(err) => {
                state.record_audit(
                    ctx.audit("exec.run", "failure")
                        .detail(format!("{} cmd={} via=ws", err.public_message(), truncate(&audit_request.command, 400)))
                        .request_id(ctx.request_id.clone()),
                );
                send_error(&out, Some(id), err);
            }
        }
    });

    Ok((control, handle))
}

/// Spawns the periodic screenshot stream.
fn start_capture(
    state: &Arc<AppState>,
    id: u64,
    request: rt_protocol::CaptureRequest,
    fps: u8,
    max_frames: Option<u32>,
    out: &Outbound,
) -> JoinHandle<()> {
    let max_fps = state.cfg().server.capture_max_fps.max(1);
    let effective = fps.max(1).min(max_fps);
    let period = Duration::from_millis((1000 / u64::from(effective)).max(1));
    let out = out.clone();

    // Full-resolution PNG costs >1 MB and ~165 ms per frame, so a preview
    // stream would stall immediately; cap the width when the client did not ask
    // for a specific size (measured in m00263).
    let mut request = request;
    if request.max_width.is_none() && request.max_height.is_none() {
        request.max_width = Some(WS_CAPTURE_MAX_WIDTH);
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seq: u64 = 0;

        loop {
            ticker.tick().await;
            let request = request.clone();
            let capture = tokio::task::spawn_blocking(move || {
                rt_core::capture::capture_frame(&request, seq)
            })
            .await;

            match capture {
                Ok(Ok(frame)) => {
                    seq += 1;
                    if out.send(WsServerMessage::CaptureFrame { id, frame }) == Queued::Closed {
                        return;
                    }
                    if let Some(limit) = max_frames {
                        if seq >= u64::from(limit) {
                            let _ = out.send(WsServerMessage::CaptureStopped {
                                id,
                                reason: "max_frames reached".to_string(),
                                frames: seq,
                            });
                            return;
                        }
                    }
                }
                Ok(Err(err)) => {
                    send_error(&out, Some(id), err);
                    let _ = out.send(WsServerMessage::CaptureStopped {
                        id,
                        reason: "capture failed".to_string(),
                        frames: seq,
                    });
                    return;
                }
                Err(join_error) => {
                    send_error(
                        &out,
                        Some(id),
                        RtError::internal(format!("capture worker failed: {join_error}")),
                    );
                    let _ = out.send(WsServerMessage::CaptureStopped {
                        id,
                        reason: "capture worker failed".to_string(),
                        frames: seq,
                    });
                    return;
                }
            }
        }
    })
}

/// Spawns the log tail: backlog first, then live broadcasts.
fn start_logs(
    state: &Arc<AppState>,
    id: u64,
    level: Option<String>,
    backlog: u32,
    out: &Outbound,
) -> JoinHandle<()> {
    let sink = state.sink();
    let mut receiver = sink.subscribe();
    let backlog_events = sink.recent(backlog as usize);
    let out = out.clone();

    tokio::spawn(async move {
        for event in backlog_events {
            if !level_matches(&event.level, level.as_deref()) {
                continue;
            }
            if out.send(WsServerMessage::Log { id, event }) == Queued::Closed {
                return;
            }
        }
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if !level_matches(&event.level, level.as_deref()) {
                        continue;
                    }
                    if out.send(WsServerMessage::Log { id, event }) == Queued::Closed {
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// Spawns the periodic quick-status stream.
fn start_status(
    state: &Arc<AppState>,
    id: u64,
    fps: u8,
    out: &Outbound,
) -> JoinHandle<()> {
    let max_fps = state.cfg().server.status_max_fps.max(1);
    let effective = fps.max(1).min(max_fps);
    let period = Duration::from_millis((1000 / u64::from(effective)).max(1));
    let state = Arc::clone(state);
    let out = out.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let service = state.sysinfo();
            let active = state.session_store().count();
            let sample = tokio::task::spawn_blocking(move || service.quick(active)).await;
            match sample {
                Ok(Ok(status)) => {
                    if out.send(WsServerMessage::Status { id, status }) == Queued::Closed {
                        return;
                    }
                }
                Ok(Err(err)) => {
                    send_error(&out, Some(id), err);
                    return;
                }
                Err(join_error) => {
                    send_error(
                        &out,
                        Some(id),
                        RtError::internal(format!("status worker failed: {join_error}")),
                    );
                    return;
                }
            }
        }
    })
}

/// Forward one execution event to the client.
fn forward_event(
    out: &Outbound,
    id: u64,
    seq: &mut u64,
    event: ExecEvent,
) {
    match event {
        ExecEvent::Started { pid, shell } => {
            let _ = out.send(WsServerMessage::ExecStarted {
                id,
                pid,
                shell: shell.display_name().to_string(),
            });
        }
        ExecEvent::Output(stream, data) => {
            *seq += 1;
            let _ = out.send(WsServerMessage::ExecOutput {
                id,
                stream,
                data,
                seq: *seq,
            });
        }
        // The authoritative result arrives through the worker's return value.
        ExecEvent::Finished(_) => {}
    }
}

/// Keeps the last [`TAIL_BYTES`] of a stream for the `exec_finished` frame.
fn push_tail(tail: &mut String, data: &str) {
    tail.push_str(data);
    if tail.len() > TAIL_BYTES * 2 {
        let cut = tail.len() - TAIL_BYTES;
        let boundary = tail
            .char_indices()
            .map(|(index, _)| index)
            .find(|index| *index >= cut)
            .unwrap_or(0);
        tail.drain(..boundary);
    }
}

/// Returns `Some` only when the tail is non-empty.
fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Truncates a command for audit lines.
fn truncate(text: &str, max_chars: usize) -> String {
    let head: String = text.chars().take(max_chars).collect();
    if head.chars().count() < text.chars().count() {
        format!("{head}…")
    } else {
        head
    }
}

/// Level filter used by `subscribe_logs`: a filter keeps itself and above.
fn level_matches(event_level: &str, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let rank = |name: &str| match name.to_ascii_lowercase().as_str() {
        "trace" => Some(0),
        "debug" => Some(1),
        "info" => Some(2),
        "warn" | "warning" => Some(3),
        "error" => Some(4),
        _ => None,
    };
    match (rank(event_level), rank(filter)) {
        (Some(event), Some(minimum)) => event >= minimum,
        _ => event_level.eq_ignore_ascii_case(filter),
    }
}
