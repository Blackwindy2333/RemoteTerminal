//! `rt-core` — everything the app can actually do, independent of transport.
//!
//! Layering (bottom-up):
//! * [`error`] — one error type for every layer.
//! * [`config`] — persistent settings, atomic writes, validation.
//! * [`logging`] — tracing pipeline, in-memory tail, audit trail, panic hook.
//! * [`crypto`] — Argon2id, SHA-256, tokens, TLS material + fingerprint pinning.
//! * [`pathscope`] — the path jail every filesystem request passes through.
//! * [`auth`] — credential checks, sessions, throttling, allow-lists.
//! * [`exec`] / [`fsops`] / [`sysinfo`] / [`capture`] — the four feature modules.
//!
//! The HTTP layer (`rt-server`), the client (`rt-client`), the GUI (`rt-app`)
//! and the MCP bridge all sit on top of this crate, which keeps the transport
//! swappable and makes every feature testable without a socket.

pub mod auth;
pub mod capture;
pub mod config;
pub mod crypto;
pub mod error;
pub mod exec;
pub mod fsops;
pub mod logging;
pub mod pathscope;
pub mod sysinfo;
pub mod util;

pub use error::{Result, RtError};

/// Everything a feature module needs to know about the session it acts for.
///
/// Passing this explicitly (instead of a global) keeps the scope check and the
/// audit identity impossible to forget: a function that has a `SessionContext`
/// has already been authorised.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub username: String,
    pub scope: rt_protocol::Scope,
    pub auth_kind: String,
    /// Client address, for audit lines only.
    pub remote: Option<String>,
    /// Correlation id echoed in error bodies and written to the audit trail.
    pub request_id: String,
}

impl SessionContext {
    pub fn new(
        username: impl Into<String>,
        scope: rt_protocol::Scope,
        auth_kind: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            scope,
            auth_kind: auth_kind.into(),
            remote: None,
            request_id: uuid_like(),
        }
    }

    pub fn with_remote(mut self, remote: Option<String>) -> Self {
        self.remote = remote;
        self
    }

    pub fn audit(&self, action: impl Into<String>, result: impl Into<String>) -> logging::AuditEvent {
        logging::AuditEvent::new(action, result)
            .user(self.username.clone())
            .scope(self.scope.as_str())
            .request_id(self.request_id.clone())
            .apply_remote(self.remote.clone())
    }
}

trait AuditRemoteExt {
    fn apply_remote(self, remote: Option<String>) -> Self;
}

impl AuditRemoteExt for logging::AuditEvent {
    fn apply_remote(mut self, remote: Option<String>) -> Self {
        if let Some(remote) = remote {
            self.remote = Some(remote);
        }
        self
    }
}

fn uuid_like() -> String {
    crypto::random_token(9)
}
