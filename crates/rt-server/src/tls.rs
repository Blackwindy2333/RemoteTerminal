//! TLS termination for the axum server.
//!
//! axum 0.8's [`axum::serve`] is generic over a [`Listener`], so the accept loop
//! can perform the rustls handshake before handing the connection to hyper. The
//! listener never surfaces handshake failures to axum: a bad client is logged at
//! debug level and the loop keeps accepting, otherwise one broken probe would
//! take the whole service down.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::serve::Listener;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// How long a peer may take to complete the TLS handshake.
///
/// Without this bound one idle TCP connection that never sends a ClientHello
/// would stall the accept loop, so any remote scanner could deny service.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `Listener` that upgrades every accepted TCP stream to TLS first.
pub(crate) struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Wraps a bound TCP listener with a TLS acceptor.
    pub(crate) fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(value) => value,
                Err(err) => {
                    // Transient accept failures (EMFILE, ECONNABORTED, …) must
                    // not kill the listener; back off briefly and retry.
                    tracing::warn!(target: "tls", "tcp accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // A peer that never finishes the handshake must not hold the loop:
            // time out, drop the socket and keep accepting (S-05).
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return (tls, addr),
                Ok(Err(err)) => {
                    tracing::debug!(target: "tls", peer = %addr, "tls handshake failed: {err}");
                }
                Err(_) => {
                    tracing::debug!(target: "tls", peer = %addr, "tls handshake timed out");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
