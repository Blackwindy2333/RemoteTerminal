//! WebSocket channel: live exec output, capture streaming, log/status
//! subscriptions.
//!
//! Three layers are offered:
//! * [`WsClient`] — a thin, manually driven connection (one `send`, one `recv`),
//!   handy for scripts and tests.
//! * [`spawn_session`] — the driver the GUI uses: an outgoing queue plus an
//!   incoming stream, so `egui` never has to hold a socket.
//! * [`spawn_capture_stream`] — a dedicated socket for one screen/window stream
//!   (the server sends JPEG frames at the requested fps, see
//!   `WsClientMessage::CaptureStream`), so a preview never fights with the exec
//!   page for the shared session.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rt_protocol::capture::CaptureFrame;
use rt_protocol::ws::{WsClientMessage, WsServerMessage};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;

use crate::{ClientError, RemoteClient, Result};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

type SplitSink = futures_util::stream::SplitSink<Socket, Message>;
type SplitSource = futures_util::stream::SplitStream<Socket>;

/// A connected WebSocket speaking the RemoteTerminal protocol.
pub struct WsClient {
    stream: Socket,
}

impl WsClient {
    /// Fetches a one-shot ticket over HTTPS and opens the socket.
    pub async fn connect(client: &RemoteClient) -> Result<Self> {
        let ticket = client.ws_ticket().await?;
        let url = client.target().ws_url(&ticket.ticket);
        let connector = client
            .tls_config()
            .map(tokio_tungstenite::Connector::Rustls);

        let (stream, _response) = tokio::time::timeout(
            Duration::from_secs(20),
            tokio_tungstenite::connect_async_tls_with_config(url.as_str(), None, false, connector),
        )
        .await
        .map_err(|_| ClientError::Transport("websocket handshake timed out".into()))?
        .map_err(|e| ClientError::Transport(format!("websocket handshake failed: {e}")))?;

        Ok(Self { stream })
    }

    /// Wraps an already open socket (used by tests).
    pub fn from_socket(stream: Socket) -> Self {
        Self { stream }
    }

    pub async fn send(&mut self, message: &WsClientMessage) -> Result<()> {
        let text = serde_json::to_string(message)
            .map_err(|e| ClientError::Request(format!("cannot encode message: {e}")))?;
        self.stream
            .send(Message::Text(text.into()))
            .await
            .map_err(|e| ClientError::Transport(format!("websocket send failed: {e}")))
    }

    /// Returns `None` once the peer closed the connection.
    pub async fn recv(&mut self) -> Result<Option<WsServerMessage>> {
        loop {
            match self.stream.next().await {
                None => return Ok(None),
                Some(Err(e)) => {
                    return Err(ClientError::Transport(format!("websocket error: {e}")))
                }
                Some(Ok(Message::Text(text))) => {
                    let parsed = serde_json::from_str::<WsServerMessage>(text.as_str())
                        .map_err(|e| {
                            ClientError::Transport(format!("malformed websocket message: {e}"))
                        })?;
                    return Ok(Some(parsed));
                }
                Some(Ok(Message::Close(_))) => return Ok(None),
                // Ping/Pong/Binary are handled by the library or irrelevant here.
                Some(Ok(_)) => continue,
            }
        }
    }

    pub async fn ping(&mut self, id: u64) -> Result<()> {
        self.send(&WsClientMessage::Ping { id }).await
    }

    pub async fn close(&mut self) -> Result<()> {
        let _ = self.stream.close(None).await;
        Ok(())
    }

    /// Consumes the client and returns independent read/write halves.
    pub fn split(self) -> (SplitSink, SplitSource) {
        StreamExt::split(self.stream)
    }
}

/// Handle returned by [`spawn_session`].
pub struct WsSession {
    pub outbound: mpsc::UnboundedSender<WsClientMessage>,
    pub inbound: mpsc::UnboundedReceiver<WsServerMessage>,
    /// Set when the connection ends; the GUI shows it as a status hint.
    pub closed: tokio::sync::watch::Receiver<Option<String>>,
    task: JoinHandle<()>,
}

impl WsSession {
    pub fn send(&self, message: WsClientMessage) {
        let _ = self.outbound.send(message);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }

    pub fn close_reason(&self) -> Option<String> {
        self.closed.borrow().clone()
    }

    /// Aborts the driver tasks (call when the GUI drops the session).
    pub fn shutdown(&self) {
        self.task.abort();
    }
}

/// Opens a socket and runs both directions in the background.
pub fn spawn_session(client: RemoteClient) -> WsSession {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsClientMessage>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<WsServerMessage>();
    let (close_tx, close_rx) = tokio::sync::watch::channel(None::<String>);

    let task = tokio::spawn(async move {
        let ws = match WsClient::connect(&client).await {
            Ok(ws) => ws,
            Err(e) => {
                let _ = close_tx.send(Some(e.message()));
                return;
            }
        };

        let (mut sink, mut source) = ws.split();

        let writer = tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                let Ok(text) = serde_json::to_string(&message) else {
                    continue;
                };
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let mut reason: Option<String> = None;
        loop {
            match source.next().await {
                None => break,
                Some(Err(e)) => {
                    reason = Some(format!("websocket error: {e}"));
                    break;
                }
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<WsServerMessage>(text.as_str()) {
                        Ok(message) => {
                            if in_tx.send(message).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "ignored malformed websocket frame");
                        }
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    reason = frame.map(|f| f.reason.to_string());
                    break;
                }
                Some(Ok(_)) => {}
            }
        }

        writer.abort();
        let _ = close_tx.send(reason);
    });

    WsSession {
        outbound: out_tx,
        inbound: in_rx,
        closed: close_rx,
        task,
    }
}

// ---------------------------------------------------------------------------
// Live capture streams
// ---------------------------------------------------------------------------

/// A live screen/window stream driven over its own WebSocket.
///
/// The stream is deliberately lossy: frames arrive faster than the UI can
/// paint, so [`Self::latest_frame`] drops everything but the newest one. When
/// the server stops (max frames reached, capture failure, blocked queue) the
/// reason comes back from [`Self::poll_stop_reason`].
pub struct CaptureStream {
    /// The stream id used in `Unsubscribe` and echoed by the server.
    pub id: u64,
    frames: mpsc::UnboundedReceiver<CaptureFrame>,
    stopped: mpsc::UnboundedReceiver<String>,
    closed: tokio::sync::watch::Receiver<Option<String>>,
    outbound: mpsc::UnboundedSender<WsClientMessage>,
    task: Option<JoinHandle<()>>,
}

impl CaptureStream {
    /// Pops the oldest frame, preserving order.
    pub fn try_frame(&mut self) -> Option<CaptureFrame> {
        self.frames.try_recv().ok()
    }

    /// Pops frames until the queue is empty and returns the newest one, which
    /// is what a preview wants: painting an outdated frame only adds latency.
    pub fn latest_frame(&mut self) -> Option<CaptureFrame> {
        let mut latest = None;
        while let Ok(frame) = self.frames.try_recv() {
            latest = Some(frame);
        }
        latest
    }

    /// The reason the server stopped the stream, or the socket failure.
    pub fn poll_stop_reason(&mut self) -> Option<String> {
        if let Ok(reason) = self.stopped.try_recv() {
            return Some(reason);
        }
        self.closed.borrow().clone()
    }

    /// True once the socket ended for any reason.
    pub fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }

    /// Asks the server to stop the stream (best effort) without dropping the
    /// handle; the socket task keeps running until [`Drop`].
    pub fn request_stop(&self) {
        let _ = self
            .outbound
            .send(WsClientMessage::Unsubscribe { id: self.id });
    }

    /// Stops the stream and closes the socket immediately.
    pub fn stop(&mut self) {
        self.request_stop();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for CaptureStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Opens a dedicated socket and starts streaming frames for `request`.
///
/// The returned handle never blocks the caller: connect failures surface
/// through [`CaptureStream::poll_stop_reason`] so the UI can fall back to
/// one-shot captures.
pub fn spawn_capture_stream(
    client: RemoteClient,
    id: u64,
    request: rt_protocol::CaptureRequest,
    fps: u8,
    max_frames: Option<u32>,
) -> CaptureStream {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsClientMessage>();
    let (frame_tx, frame_rx) = mpsc::unbounded_channel::<CaptureFrame>();
    let (stop_tx, stop_rx) = mpsc::unbounded_channel::<String>();
    let (close_tx, close_rx) = tokio::sync::watch::channel(None::<String>);

    let task = tokio::spawn(async move {
        let ws = match WsClient::connect(&client).await {
            Ok(ws) => ws,
            Err(e) => {
                let message = e.message();
                let _ = stop_tx.send(message.clone());
                let _ = close_tx.send(Some(message));
                return;
            }
        };

        let (mut sink, mut source) = ws.split();
        let request_message = WsClientMessage::CaptureStream {
            id,
            request,
            fps,
            max_frames,
        };

        let writer = tokio::spawn(async move {
            if let Ok(text) = serde_json::to_string(&request_message) {
                if sink.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
            }
            while let Some(message) = out_rx.recv().await {
                let Ok(text) = serde_json::to_string(&message) else {
                    continue;
                };
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let mut reason: Option<String> = None;
        loop {
            match source.next().await {
                None => break,
                Some(Err(e)) => {
                    reason = Some(format!("websocket error: {e}"));
                    break;
                }
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<WsServerMessage>(text.as_str()) {
                        Ok(WsServerMessage::CaptureFrame { id: stream, frame }) if stream == id => {
                            if frame_tx.send(frame).is_err() {
                                break;
                            }
                        }
                        Ok(WsServerMessage::CaptureStopped {
                            id: stream,
                            reason: why,
                            ..
                        }) if stream == id => {
                            reason = Some(why);
                            break;
                        }
                        Ok(WsServerMessage::Error {
                            id: Some(stream),
                            error,
                        }) if stream == id => {
                            reason = Some(format!("{}: {}", error.code.as_str(), error.message));
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::debug!(error = %e, "ignored malformed websocket frame"),
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    reason = frame.map(|f| f.reason.to_string());
                    break;
                }
                Some(Ok(_)) => {}
            }
        }

        let final_reason = reason.unwrap_or_else(|| "stream closed by the server".to_string());
        let _ = stop_tx.send(final_reason.clone());
        let _ = close_tx.send(Some(final_reason));
        writer.abort();
    });

    CaptureStream {
        id,
        frames: frame_rx,
        stopped: stop_rx,
        closed: close_rx,
        outbound: out_tx,
        task: Some(task),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_protocol::ws::{LogEvent, WsServerMessage};

    #[test]
    fn roundtrips_protocol_messages() {
        // Encoding/decoding is what the driver relies on; verify both shapes.
        let msg = WsClientMessage::Ping { id: 7 };
        let text = serde_json::to_string(&msg).unwrap();
        assert!(text.contains("\"type\":\"ping\""));

        let status = WsServerMessage::Log {
            id: 1,
            event: LogEvent {
                ts_ms: 123,
                level: "INFO".into(),
                target: "rt".into(),
                message: "hello".into(),
                fields: None,
            },
        };
        let text = serde_json::to_string(&status).unwrap();
        let back: WsServerMessage = serde_json::from_str(&text).unwrap();
        match back {
            WsServerMessage::Log { id, event } => {
                assert_eq!(id, 1);
                assert_eq!(event.message, "hello");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn session_channels_are_wired() {
        // A session with no socket still exposes usable channels.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsClientMessage>();
        out_tx.send(WsClientMessage::Ping { id: 1 }).unwrap();
        assert!(matches!(
            out_rx.try_recv(),
            Ok(WsClientMessage::Ping { id: 1 })
        ));
    }
}
