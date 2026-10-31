//! `rt-protocol` — wire contract shared by server, client, GUI and external tooling.
//!
//! Everything in this crate is pure data: no IO, no runtime. That keeps the
//! protocol reusable from unit tests, the MCP bridge, and third-party clients
//! generated from `docs/openapi.json`.

pub mod auth;
pub mod capture;
pub mod error;
pub mod exec;
pub mod fs;
pub mod info;
pub mod ws;

pub use auth::*;
pub use capture::*;
pub use error::*;
pub use exec::*;
pub use fs::*;
pub use info::*;
pub use ws::*;

/// Bumped whenever a wire-incompatible change lands. The server advertises it in
/// [`ServerInfo`] and refuses clients speaking a different major version.
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Human-facing product identity, shared by CLI, GUI, logs and HTTP headers.
pub const APP_NAME: &str = "RemoteTerminal";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capability strings advertised by a server. Clients use these to decide
/// whether a feature exists before calling it (modular features stay honest).
pub mod capabilities {
    pub const EXEC: &str = "exec";
    pub const EXEC_PTY: &str = "exec.pty";
    pub const FS: &str = "fs";
    pub const FS_STREAM: &str = "fs.stream";
    pub const SYSINFO: &str = "sysinfo";
    pub const CAPTURE: &str = "capture";
    pub const CAPTURE_STREAM: &str = "capture.stream";
    pub const WS: &str = "ws";
    pub const AUDIT: &str = "audit";

    pub fn all() -> Vec<&'static str> {
        vec![
            EXEC, EXEC_PTY, FS, FS_STREAM, SYSINFO, CAPTURE, CAPTURE_STREAM, WS, AUDIT,
        ]
    }
}

/// Access level of a session. This is enforced *server side* on every request;
/// the client only mirrors it for UI affordances.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Remote file operations are jailed to the configured workspace root.
    Workspace,
    /// Remote file operations may touch the whole filesystem (device paths aside).
    Full,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Workspace => "workspace",
            Scope::Full => "full",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "workspace" | "work" | "jail" => Some(Scope::Workspace),
            "full" | "admin" | "root" => Some(Scope::Full),
            _ => None,
        }
    }

    /// `Full` outranks `Workspace`; `Scope::min` is used when a policy can only
    /// narrow a request (e.g. a `workspace` API key on a `full` server).
    pub fn min(self, other: Scope) -> Scope {
        if self <= other {
            self
        } else {
            other
        }
    }

    pub fn is_full(&self) -> bool {
        matches!(self, Scope::Full)
    }
}

impl Default for Scope {
    fn default() -> Self {
        Scope::Full
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Public description of a server instance. Contains no secrets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    /// Friendly name (configurable, defaults to the hostname).
    pub name: String,
    pub app_version: String,
    pub protocol_version: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    /// Highest scope this server can ever hand out.
    pub max_scope: Scope,
    /// What a login with *these* credentials will actually get.
    #[serde(default)]
    pub issued_scope: Option<Scope>,
    /// SHA-256 (hex) of the TLS leaf certificate; clients pin this.
    pub cert_fingerprint: Option<String>,
    pub capabilities: Vec<String>,
    pub started_at: String,
    pub uptime_secs: u64,
    /// Loopback/LAN URLs this server believes it is reachable at.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// Build id reported in `/healthz` and in the GUI footer.
pub fn build_info() -> serde_json::Value {
    serde_json::json!({
        "name": APP_NAME,
        "version": APP_VERSION,
        "protocol": PROTOCOL_VERSION,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}
