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

            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(err) => {
                    tracing::debug!(target: "tls", peer = %addr, "tls handshake failed: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
