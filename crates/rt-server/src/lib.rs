//! RemoteTerminal network server: REST + WebSocket API over a Windows host.
//!
//! The crate is organised in layers:
//!
//! * [`routes`] — one module per API family; handlers only translate between the
//!   wire protocol and `rt-core`.
//! * [`AppState`] — everything long-lived: config, paths, sessions, throttles,
//!   the sysinfo collector and WebSocket tickets.
//! * [`middleware`] — request id, timeout, tracing, body limits and bearer
//!   authentication.
//! * [`openapi`] — the hand-written OpenAPI 3.1 description.
//!
//! Entry points are [`router`] (state in, `axum::Router` out, no TLS — used by
//! tests) and [`serve`] (binds a socket, optionally terminates TLS and returns a
//! [`ServerHandle`]).
//!
//! Security model (architecture §3): every request is authenticated with a
//! bearer session token or API key, every filesystem path is resolved through
//! [`rt_core::pathscope::PathGuard`], and the WebSocket channel is entered with
//! a single-use ticket instead of a long-lived credential.

pub mod openapi;

mod middleware;
mod routes;
mod state;
mod streams;
mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

// axum only implements `Connected<IncomingStream<'_, TcpListener>>` for
// `SocketAddr`, so a custom TLS listener cannot feed `ConnectInfo` directly.
// `ListenerExt::tap_io` wraps any listener in `TapIo<L, F>`, for which axum does
// provide `Connected<...> for L::Addr` — that keeps `ConnectInfo<SocketAddr>`
// (and therefore per-IP throttling) working on the TLS path.
use axum::serve::ListenerExt;

pub use state::{AppState, ServerOptions};

/// Marker other crates can check to confirm this module is implemented.
pub const CRATE_READY: bool = true;

/// Builds the HTTP router for one server instance; includes no TLS.
pub fn router(state: Arc<AppState>) -> axum::Router {
    routes::build(state)
}

/// A live server: its bound address and a handle to shut it down.
pub struct ServerHandle {
    /// The address the socket is actually bound to (resolved when `port = 0`).
    pub local_addr: SocketAddr,
    /// Convenience URL clients can dial, e.g. `https://127.0.0.1:46666`.
    pub url: String,
    /// SHA-256 of the serving certificate, colon separated, when TLS is on.
    pub fingerprint: Option<String>,
    /// Whether this instance terminated TLS itself.
    pub tls: bool,
    state: Arc<AppState>,
    stop_tx: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ServerHandle {
    /// The state this server was built from.
    pub fn state(&self) -> Arc<AppState> {
        Arc::clone(&self.state)
    }

    /// Asks the accept loop to stop; connections finish their current request.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("local_addr", &self.local_addr)
            .field("url", &self.url)
            .field("tls", &self.tls)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop();
        if let Ok(mut slot) = self.task.lock() {
            if let Some(task) = slot.take() {
                // The graceful signal is already sent; abort only to guarantee
                // the socket is released when the handle goes away.
                task.abort();
            }
        }
    }
}

/// Binds the configured address, optionally terminates TLS and serves `state`
/// in the background.
///
/// The returned handle owns the accept loop: dropping it (or calling
/// [`ServerHandle::stop`]) stops the server. `port = 0` asks the OS for a free
/// port, which is reported back in [`ServerHandle::local_addr`].
pub async fn serve(
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<ServerHandle> {
    let config = state.config();
    let server = config.server.clone();
    let bind = if server.bind.trim().is_empty() {
        "0.0.0.0".to_string()
    } else {
        server.bind.trim().to_string()
    };

    let addr = format!("{bind}:{}", server.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|err| anyhow::anyhow!("failed to bind {addr}: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| anyhow::anyhow!("failed to read the bound address: {err}"))?;

    let material = if server.tls {
        Some(match (server.cert_path.as_ref(), server.key_path.as_ref()) {
            (Some(cert), Some(key)) => rt_core::crypto::load_custom_tls(cert, key)
                .map_err(|err| anyhow::anyhow!("cannot load the configured TLS material: {err}"))?,
            _ => rt_core::crypto::ensure_self_signed_tls(
                &state.paths().tls_dir,
                &tls_hostnames(&bind),
            )
            .map_err(|err| anyhow::anyhow!("cannot prepare the self-signed certificate: {err}"))?,
        })
    } else {
        None
    };

    let fingerprint = material.as_ref().map(|m| m.fingerprint.clone());
    state.set_runtime(Some(local_addr), fingerprint.clone());

    let scheme = if server.tls { "https" } else { "http" };
    let url = format!("{scheme}://{}:{}", url_host(&bind), local_addr.port());

    let app = routes::build(Arc::clone(&state)).into_make_service_with_connect_info::<SocketAddr>();

    let (stop_tx, mut stop_rx) = watch::channel(false);
    let mut external = shutdown;
    let graceful = async move {
        loop {
            if *external.borrow() || *stop_rx.borrow() {
                break;
            }
            tokio::select! {
                changed = external.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let task = match material {
        Some(material) => {
            let acceptor = TlsAcceptor::from(
                material
                    .server_config()
                    .map_err(|err| anyhow::anyhow!("invalid TLS configuration: {err}"))?,
            );
            let listener = tls::TlsListener::new(listener, acceptor);
            // The closure is only there to obtain axum's `TapIo` wrapper; the
            // handshake already happened inside the listener.
            let listener = listener.tap_io(|_io| {});
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, app)
                    .with_graceful_shutdown(graceful)
                    .await
                {
                    tracing::error!(target: "server", "TLS server stopped: {err}");
                }
            })
        }
        None => tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(graceful)
                .await
            {
                tracing::error!(target: "server", "server stopped: {err}");
            }
        }),
    };

    tracing::info!(
        target: "server",
        %local_addr,
        %url,
        tls = server.tls,
        fingerprint = fingerprint.as_deref().unwrap_or("-"),
        "server listening"
    );

    Ok(ServerHandle {
        local_addr,
        url,
        fingerprint,
        tls: server.tls,
        state,
        stop_tx,
        task: Mutex::new(Some(task)),
    })
}

/// Hosts to embed in the certificate: the bind address plus local aliases.
fn tls_hostnames(bind: &str) -> Vec<String> {
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let host = rt_core::util::hostname();
    if !host.is_empty() && !names.iter().any(|name| name == &host) {
        names.push(host);
    }
    let trimmed = bind.trim_start_matches('[').trim_end_matches(']');
    if !trimmed.is_empty()
        && trimmed != "0.0.0.0"
        && trimmed != "::"
        && !names.iter().any(|name| name == trimmed)
    {
        names.push(trimmed.to_string());
    }
    names
}

/// Host to advertise in the URL: wildcard binds map to the loopback address.
fn url_host(bind: &str) -> String {
    let trimmed = bind.trim_start_matches('[').trim_end_matches(']');
    match trimmed {
        "" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        host if host.contains(':') => format!("[{host}]"),
        host => host.to_string(),
    }
}
