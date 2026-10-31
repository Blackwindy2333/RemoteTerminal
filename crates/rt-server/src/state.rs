//! Shared, long-lived server state.
//!
//! Everything that must survive across requests lives in [`AppState`]: the
//! config snapshot, resolved paths, the session store, both throttles, the
//! sysinfo collector and the in-memory WebSocket ticket map.
//!
//! All of `rt-core`'s stores (`SessionStore`, `LoginLimiter`, `RateLimiter`)
//! take `&self` and lock internally, so they are simply held by value here; the
//! only `Mutex` in this module guards the ticket map and never spans an await.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rt_core::auth::{self, LoginLimiter, RateLimiter, SessionStore};
use rt_core::config::{Config, ResolvedPaths};
use rt_core::exec::ExecLimits;
use rt_core::fsops::FsLimits;
use rt_core::logging::{AuditEvent, AuditLog, LogEventSink};
use rt_core::pathscope::PathGuard;
use rt_core::sysinfo::SysInfoService;
use rt_core::{Result, SessionContext};
use rt_protocol::ws::{LogEvent, WsInfo, WS_PATH};
use rt_protocol::{AppInfo, Scope, ServerInfo, SessionInfo};
use tokio::sync::Semaphore;

/// Lifetime of a WebSocket upgrade ticket (architecture §3).
pub const WS_TICKET_TTL_MS: i64 = 60_000;

/// Largest WebSocket message the server will accept.
pub const WS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Concurrent WebSocket streams allowed per socket.
pub const WS_MAX_CONCURRENT_STREAMS: u32 = 16;

/// Largest slice `GET /api/v1/fs/read` will return in one response.
pub const MAX_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Everything the router needs that is built once at start-up.
pub struct ServerOptions {
    /// Effective configuration (already loaded by the app layer).
    pub config: Config,
    /// Where the config file, workspace, logs and TLS material live.
    pub paths: ResolvedPaths,
    /// In-memory log ring buffer shared with the GUI and the WS log tail.
    pub sink: Arc<LogEventSink>,
    /// Optional JSONL audit trail; `None` disables file auditing.
    pub audit: Option<Arc<AuditLog>>,
}

/// A single-use WebSocket ticket, bound to the session that minted it.
#[derive(Debug, Clone)]
struct Ticket {
    username: String,
    scope: Scope,
    auth_kind: String,
    remote: Option<String>,
    expires_at_ms: i64,
}

/// Facts only known once the socket is bound (filled in by `serve`).
#[derive(Debug, Default)]
struct RuntimeInfo {
    local_addr: Option<SocketAddr>,
    fingerprint: Option<String>,
}

/// Immutable-ish configuration plus every mutable runtime service.
pub struct AppState {
    config: Config,
    paths: ResolvedPaths,
    sink: Arc<LogEventSink>,
    audit: Option<Arc<AuditLog>>,
    sessions: SessionStore,
    login_limiter: LoginLimiter,
    rate_limiter: RateLimiter,
    sysinfo: Arc<SysInfoService>,
    exec_slots: Arc<Semaphore>,
    tickets: Mutex<HashMap<String, Ticket>>,
    started_at_ms: i64,
    started: Instant,
    max_scope: Scope,
    runtime: Mutex<RuntimeInfo>,
}

impl AppState {
    /// Builds the shared state; fails only when the workspace or TLS dir is
    /// unusable.
    pub fn new(opts: ServerOptions) -> anyhow::Result<Arc<Self>> {
        let ServerOptions {
            config,
            paths,
            sink,
            audit,
        } = opts;

        if let Err(err) = paths.ensure_dirs() {
            // Not fatal: read-only deployments still serve, they just cannot
            // persist logs/transfers.
            tracing::warn!(target: "server", "could not create data directories: {err}");
        }

        let ttl_secs = config.server.session_ttl_minutes.saturating_mul(60).max(60);
        let sessions = SessionStore::new(ttl_secs, config.server.max_sessions.max(1));
        let login_limiter = LoginLimiter::new(
            config.server.login_max_attempts.max(1),
            config.server.login_lockout_secs.max(1),
        );
        let rate_limiter = RateLimiter::new(config.server.rate_limit_per_min);
        let exec_slots = Arc::new(Semaphore::new(config.server.max_concurrent_exec.max(1)));
        let max_scope = highest_scope(&config);

        // Fail fast when workspace-scoped sessions cannot be jailed.
        PathGuard::new(Scope::Workspace, Some(paths.workspace_root.as_path()))
            .map_err(|err| anyhow::anyhow!("workspace root {:?} is unusable: {err}", paths.workspace_root))?;

        Ok(Arc::new(Self {
            config,
            paths,
            sink,
            audit,
            sessions,
            login_limiter,
            rate_limiter,
            sysinfo: Arc::new(SysInfoService::new()),
            exec_slots,
            tickets: Mutex::new(HashMap::new()),
            started_at_ms: auth::now_ms(),
            started: Instant::now(),
            max_scope,
            runtime: Mutex::new(RuntimeInfo::default()),
        }))
    }

    /// Copy of the effective configuration.
    pub fn config(&self) -> Config {
        self.config.clone()
    }

    /// Resolved filesystem locations (config, workspace, logs, TLS, …).
    pub fn paths(&self) -> &ResolvedPaths {
        &self.paths
    }

    /// Public description of this server; contains no secrets.
    pub fn server_info(&self) -> ServerInfo {
        self.server_info_with_scope(None)
    }

    /// Same as [`Self::server_info`] but records what a login will hand out.
    pub(crate) fn server_info_with_scope(&self, issued: Option<Scope>) -> ServerInfo {
        ServerInfo {
            name: self.config.server_display_name(),
            app_version: rt_protocol::APP_VERSION.to_string(),
            protocol_version: rt_protocol::PROTOCOL_VERSION.to_string(),
            hostname: rt_core::util::hostname(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            max_scope: self.max_scope,
            issued_scope: issued,
            cert_fingerprint: self.runtime.lock().ok().and_then(|r| r.fingerprint.clone()),
            capabilities: self.capabilities(),
            started_at: auth::rfc3339_ms(self.started_at_ms),
            uptime_secs: self.uptime_secs(),
            endpoints: self.endpoints(),
        }
    }

    /// Capabilities this build can actually serve right now.
    fn capabilities(&self) -> Vec<String> {
        let capture = rt_core::capture::is_available();
        let mut out: Vec<String> = rt_protocol::capabilities::all()
            .into_iter()
            .filter(|cap| {
                capture
                    || !matches!(
                        *cap,
                        rt_protocol::capabilities::CAPTURE
                            | rt_protocol::capabilities::CAPTURE_STREAM
                    )
            })
            .map(str::to_string)
            .collect();
        if self.audit.is_none() {
            out.retain(|cap| cap != rt_protocol::capabilities::AUDIT);
        }
        out
    }

    /// Currently valid sessions, newest expiry last.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.sessions.list()
    }

    /// Invalidates one session token; `false` when it was unknown or expired.
    pub fn revoke_session(&self, token: &str) -> bool {
        self.sessions.revoke(token)
    }

    /// Most recent `limit` log events from the shared ring buffer (oldest first).
    pub fn recent_logs(&self, limit: usize) -> Vec<LogEvent> {
        self.sink.recent(limit)
    }

    /// The shared log sink (for GUI and WS tails).
    pub fn sink(&self) -> Arc<LogEventSink> {
        Arc::clone(&self.sink)
    }

    /// Uptime of this server instance in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    // ----------------------------------------------------------------- internals

    /// Borrowed configuration, for hot paths that must not clone.
    pub(crate) fn cfg(&self) -> &Config {
        &self.config
    }

    /// Session store (token → session).
    pub(crate) fn session_store(&self) -> &SessionStore {
        &self.sessions
    }

    /// Per-IP failed-login throttle.
    pub(crate) fn login_limiter(&self) -> &LoginLimiter {
        &self.login_limiter
    }

    /// Per-IP request throttle.
    pub(crate) fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Resident, lock-protected machine-information collector.
    pub(crate) fn sysinfo(&self) -> Arc<SysInfoService> {
        Arc::clone(&self.sysinfo)
    }

    /// Concurrency guard for `exec` (REST and WS share it).
    pub(crate) fn exec_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.exec_slots)
    }

    /// Writes an audit event to the JSONL trail and/or the tracing mirror.
    pub(crate) fn record_audit(&self, event: AuditEvent) {
        match &self.audit {
            Some(log) => log.log(event),
            None => tracing::info!(
                target: "audit",
                action = %event.action,
                result = %event.result,
                user = event.username.as_deref().unwrap_or("-"),
                target = event.target.as_deref().unwrap_or("-"),
                detail = event.detail.as_deref().unwrap_or("-"),
                "audit event"
            ),
        }
    }

    /// Execution ceilings derived from `[server]`.
    pub(crate) fn exec_limits(&self) -> ExecLimits {
        ExecLimits::new(
            self.config.server.exec_timeout_secs.max(1),
            (self.config.server.exec_max_output_kb.max(1) as usize) * 1024,
        )
    }

    /// Filesystem ceilings derived from `[server]`.
    pub(crate) fn fs_limits(&self) -> FsLimits {
        FsLimits::new(
            self.config.server.max_list_entries.max(1),
            MAX_READ_BYTES,
            self.max_upload_bytes(),
        )
    }

    /// Largest single upload the server accepts.
    pub(crate) fn max_upload_bytes(&self) -> u64 {
        self.config
            .server
            .max_upload_mb
            .max(1)
            .saturating_mul(1024 * 1024)
    }

    /// Largest JSON request body the server accepts.
    pub(crate) fn max_json_bytes(&self) -> usize {
        let kb = self.config.server.max_json_kb.max(1);
        (kb.min(64 * 1024) as usize).saturating_mul(1024)
    }

    /// Builds the path jail for a session scope. `Full` sessions get no root.
    pub(crate) fn guard(&self, scope: Scope) -> Result<PathGuard> {
        match scope {
            Scope::Full => PathGuard::new(Scope::Full, None),
            Scope::Workspace => {
                PathGuard::new(Scope::Workspace, Some(self.paths.workspace_root.as_path()))
            }
        }
    }

    /// Mints a single-use, session-bound WebSocket ticket.
    pub(crate) fn issue_ticket(&self, ctx: &SessionContext) -> String {
        let ticket = rt_core::crypto::random_token(24);
        let now = auth::now_ms();
        if let Ok(mut map) = self.tickets.lock() {
            map.retain(|_, t| t.expires_at_ms > now);
            map.insert(
                ticket.clone(),
                Ticket {
                    username: ctx.username.clone(),
                    scope: ctx.scope,
                    auth_kind: ctx.auth_kind.clone(),
                    remote: ctx.remote.clone(),
                    expires_at_ms: now + WS_TICKET_TTL_MS,
                },
            );
        }
        ticket
    }

    /// Consumes a ticket (single use) and returns the session it belonged to.
    pub(crate) fn take_ticket(&self, ticket: &str) -> Option<SessionContext> {
        if ticket.trim().is_empty() {
            return None;
        }
        let entry = {
            let mut map = self.tickets.lock().ok()?;
            let now = auth::now_ms();
            map.retain(|_, t| t.expires_at_ms > now);
            map.remove(ticket)?
        };
        if entry.expires_at_ms <= auth::now_ms() {
            return None;
        }
        Some(
            SessionContext::new(entry.username, entry.scope, entry.auth_kind)
                .with_remote(entry.remote),
        )
    }

    /// Records the bound address / TLS fingerprint so `info` can report it.
    pub(crate) fn set_runtime(&self, local_addr: Option<SocketAddr>, fingerprint: Option<String>) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.local_addr = local_addr;
            runtime.fingerprint = fingerprint;
        }
    }

    /// Application facts embedded in `/api/v1/sysinfo`.
    pub(crate) fn app_info(&self, scope: Scope) -> AppInfo {
        AppInfo {
            version: rt_protocol::APP_VERSION.to_string(),
            protocol_version: rt_protocol::PROTOCOL_VERSION.to_string(),
            server_enabled: self.config.server.enabled,
            active_sessions: self.sessions.count().min(u32::MAX as usize) as u32,
            uptime_secs: self.uptime_secs(),
            scope,
            workspace_root: Some(self.paths.workspace_root.display().to_string()),
            config_path: self.paths.config_file.display().to_string(),
            data_dir: self.paths.data_dir.display().to_string(),
            server: Some(self.server_info_with_scope(Some(scope))),
        }
    }

    /// Description of the WebSocket endpoint for `GET /api/v1/ws/info`.
    pub(crate) fn ws_info(&self) -> WsInfo {
        WsInfo {
            path: WS_PATH.to_string(),
            max_message_bytes: WS_MAX_MESSAGE_BYTES as u64,
            max_frame_fps: self.config.server.capture_max_fps.max(1),
            max_concurrent_streams: WS_MAX_CONCURRENT_STREAMS,
        }
    }

    /// Upper bound for one non-streaming request (covers the slowest `exec`).
    pub(crate) fn request_timeout(&self) -> std::time::Duration {
        let exec = self.config.server.exec_timeout_secs;
        let client = self.config.client.request_timeout_secs;
        std::time::Duration::from_secs(exec.max(client).saturating_add(60).max(30))
    }

    /// Cheap default directory for endpoints whose `?path=` is optional.
    pub(crate) fn default_list_path(&self, guard: &PathGuard) -> String {
        match guard.root() {
            Some(_) => "\\".to_string(),
            None => {
                let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
                format!("{drive}\\")
            }
        }
    }

    /// URLs this server believes it is reachable at.
    fn endpoints(&self) -> Vec<String> {
        let scheme = if self.config.server.tls { "https" } else { "http" };
        let port = self
            .runtime
            .lock()
            .ok()
            .and_then(|r| r.local_addr.map(|a| a.port()))
            .unwrap_or(self.config.server.port);
        let mut hosts: Vec<String> = vec!["127.0.0.1".to_string()];
        let bind = self.config.server.bind.trim();
        if !bind.is_empty() && bind != "0.0.0.0" && bind != "::" && bind != "[::]" {
            if !hosts.iter().any(|h| h == bind) {
                hosts.push(bind.to_string());
            }
        } else {
            let host = rt_core::util::hostname();
            if !host.is_empty() {
                hosts.push(host);
            }
        }
        hosts
            .into_iter()
            .map(|host| {
                if host.contains(':') && !host.starts_with('[') {
                    format!("{scheme}://[{host}]:{port}")
                } else {
                    format!("{scheme}://{host}:{port}")
                }
            })
            .collect()
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("paths", &self.paths.workspace_root)
            .field("sessions", &self.sessions.count())
            .field("max_scope", &self.max_scope)
            .field("uptime_secs", &self.uptime_secs())
            .finish_non_exhaustive()
    }
}

/// Highest scope any enabled credential can obtain.
fn highest_scope(config: &Config) -> Scope {
    let from_users = config
        .server
        .users
        .iter()
        .filter(|u| u.enabled)
        .map(auth::scope_of);
    let from_keys = config
        .server
        .api_keys
        .iter()
        .filter(|k| k.enabled)
        .map(|k| Scope::parse(&k.scope).unwrap_or(Scope::Workspace));
    from_users.chain(from_keys).max().unwrap_or(Scope::Full)
}

/// Kind string used for `SessionInfo::auth_kind` of API-key callers.
pub(crate) const AUTH_KIND_API_KEY: &str = "api_key";
