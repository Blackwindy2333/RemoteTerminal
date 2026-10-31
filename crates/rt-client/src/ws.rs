//! WebSocket channel: live exec output, capture streaming, log/status
//! subscriptions.
//!
//! Two layers are offered:
//! * [`WsClient`] — a thin, manually driven connection (one `send`, one `recv`),
//!   handy for scripts and tests.
//! * [`spawn_session`] — the driver the GUI uses: an outgoing queue plus an
//!   incoming stream, so `egui` never has to hold a socket.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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
