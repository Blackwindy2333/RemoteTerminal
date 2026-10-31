//! Authentication wire types.
//!
//! Design notes (security):
//! * Passwords only ever travel inside the TLS channel; the server stores an
//!   Argon2id PHC hash, never the password.
//! * Successful logins return an opaque, high-entropy bearer token. Tokens live
//!   in server memory only (restart invalidates them) and carry an expiry.
//! * API keys (for automation / harness tools) are long-lived, high entropy and
//!   stored as SHA-256 digests in the config file.

use serde::{Deserialize, Serialize};

use crate::Scope;

/// `POST /api/v1/auth/login`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Free-form client identity recorded in the audit log.
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Seconds until `access_token` expires.
    pub expires_in_secs: u64,
    /// RFC 3339 expiry timestamp (UTC).
    pub expires_at: String,
    pub scope: Scope,
    pub username: String,
    pub server: crate::ServerInfo,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// `GET /api/v1/auth/me`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub username: String,
    pub scope: Scope,
    pub expires_at: String,
    pub issued_at: String,
    /// `password` for interactive logins, `api_key` for automation.
    pub auth_kind: String,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
}

/// Short-lived, single-use ticket that lets a browser (or any client that cannot
/// set headers on a WebSocket upgrade) authenticate the WS handshake without
/// putting the bearer token into a URL that ends up in logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsTicketResponse {
    pub ticket: String,
    pub expires_in_secs: u64,
    /// Ready-to-use path, e.g. `/api/v1/ws?ticket=...`.
    pub ws_path: String,
}

/// Rotating credential material for automation clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub name: String,
    pub scope: Scope,
    /// First 8 hex chars of the SHA-256 digest, for identification only.
    pub fingerprint: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
}
