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
use rt_core::{Result, RtError, SessionContext};
use rt_protocol::ws::{LogEvent, WsInfo, WS_PATH};
use rt_protocol::{AppInfo, Scope, ServerInfo, SessionInfo};
use tokio::sync::Semaphore;

use crate::middleware::ApiResult;

/// Lifetime of a WebSocket upgrade ticket.
///
/// Short on purpose: the ticket travels in the query string, so it ends up in
/// proxy logs and browser history (SECURITY.md S-24).
pub const WS_TICKET_TTL_MS: i64 = 15_000;

/// Bytes one session may read (inline reads + downloads) per minute.
///
/// Bounds the value of a stolen session token as an exfiltration channel
/// (SECURITY.md S-09).
pub const READ_BUDGET_PER_MINUTE: u64 = 512 * 1024 * 1024;

/// Sliding window the read budget is measured over.
const READ_BUDGET_WINDOW_MS: i64 = 60_000;

/// Failed sign-ins tolerated per account inside [`USER_FAILURE_WINDOW_MS`].
const USER_FAILURE_LIMIT: u32 = 50;

/// Window the per-account failure counter is measured over.
const USER_FAILURE_WINDOW_MS: i64 = 3_600_000;

/// First backoff step after a failed sign-in; doubles per consecutive failure.
const USER_BACKOFF_BASE_SECS: u64 = 1;

/// Failures a single account may get wrong before any delay is applied.
///
/// Typing a password wrong twice must not lock anyone out, while brute force
/// still meets the growing delay from the third miss on.
const USER_BACKOFF_FREE_FAILURES: u32 = 3;

/// Backoff ceiling ("at most 15 minutes", SECURITY.md S-22).
const USER_BACKOFF_CAP_SECS: u64 = 900;

/// How often the credentials snapshot is re-checked against the config file.
const CREDENTIAL_RELOAD_INTERVAL_MS: i64 = 1_000;

/// Largest WebSocket message the server will accept.
pub const WS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Concurrent WebSocket streams allowed per socket.
pub const WS_MAX_CONCURRENT_STREAMS: u32 = 16;

/// Largest slice `GET /api/v1/fs/read` will return in one response.
pub const MAX_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Blocking jobs the server admits at once before it starts shedding load.
///
/// The blocking pool itself is shared with the rest of the process, so this is
/// deliberately smaller than a naive thread count: past this point waiting
/// requests get `503` with a retry hint instead of an ever-growing queue.
pub const BLOCKING_ADMISSION_SLOTS: usize = 64;

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

/// A single-use WebSocket ticket, bound to the session that minted it and to
/// the address it was minted for (a stolen URL is useless elsewhere).
#[derive(Debug, Clone)]
struct Ticket {
    username: String,
    scope: Scope,
    auth_kind: String,
    remote: Option<String>,
    ip: String,
    expires_at_ms: i64,
}

/// Why a ticket was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketError {
    /// Unknown, already used or expired.
    Unknown,
    /// Minted for a different client address (SECURITY.md S-24).
    AddressMismatch,
}

/// Credential half of the configuration, reloadable without a restart.
#[derive(Debug)]
pub(crate) struct Credentials {
    /// Password users (already filtered by `enabled` at check time).
    pub(crate) users: Vec<rt_core::config::UserConfig>,
    /// API keys; each request compares against this live snapshot.
    pub(crate) api_keys: Vec<rt_core::config::ApiKeyConfig>,
    /// Highest scope any enabled credential can obtain right now.
    pub(crate) max_scope: Scope,
}

impl Credentials {
    fn from_config(config: &Config) -> Self {
        Self {
            users: config.server.users.clone(),
            api_keys: config.server.api_keys.clone(),
            max_scope: highest_scope(config),
        }
    }
}

/// Cheap identity of the config file used to notice edits (SECURITY.md S-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigSignature {
    modified_ms: u64,
    len: u64,
}

impl ConfigSignature {
    fn of(path: &std::path::Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let modified_ms = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|since| since.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        Some(Self {
            modified_ms,
            len: meta.len(),
        })
    }
}

/// Throttle state for the credential reload (never spans an await).
#[derive(Debug, Default)]
struct ReloadState {
    last_check_ms: i64,
    signature: Option<ConfigSignature>,
}

/// One session's traffic inside the current budget window.
#[derive(Debug, Clone, Copy)]
struct BudgetEntry {
    window_start_ms: i64,
    bytes: u64,
}

/// Per-session read allowance, to blunt bulk exfiltration (SECURITY.md S-09).
pub(crate) struct ReadBudget {
    limit: u64,
    entries: Mutex<HashMap<String, BudgetEntry>>,
}

impl ReadBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit: limit.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Charges `bytes` to `key`; `429` with a retry hint when exhausted.
    pub(crate) fn charge(&self, key: &str, bytes: u64) -> Result<()> {
        self.charge_at(key, bytes, auth::now_ms())
    }

    fn charge_at(&self, key: &str, bytes: u64, now_ms: i64) -> Result<()> {
        let Ok(mut entries) = self.entries.lock() else {
            // A poisoned lock must not open the gate; treat it as exhausted.
            return Err(RtError::Unavailable(
                "read budget is temporarily unavailable".to_string(),
            ));
        };
        entries.retain(|_, entry| now_ms.saturating_sub(entry.window_start_ms) < READ_BUDGET_WINDOW_MS);
        let entry = entries.entry(key.to_string()).or_insert(BudgetEntry {
            window_start_ms: now_ms,
            bytes: 0,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= READ_BUDGET_WINDOW_MS {
            entry.window_start_ms = now_ms;
            entry.bytes = 0;
        }
        if entry.bytes.saturating_add(bytes) > self.limit {
            let elapsed = now_ms.saturating_sub(entry.window_start_ms);
            let retry_after_secs = ((READ_BUDGET_WINDOW_MS - elapsed).max(1) / 1000).max(1) as u64;
            return Err(RtError::RateLimited {
                message: "read budget for this session is exhausted; try again shortly".to_string(),
                retry_after_secs,
            });
        }
        entry.bytes = entry.bytes.saturating_add(bytes);
        Ok(())
    }
}

/// Per-account sign-in backoff (SECURITY.md S-22).
///
/// Deliberately *not* a hard lock for one stale counter: the delay grows
/// exponentially and is reset by a successful sign-in, so a victim can still
/// get back in after at most [`USER_BACKOFF_CAP_SECS`].
pub(crate) struct UsernameThrottle {
    inner: Mutex<HashMap<String, UserAttempts>>,
}

#[derive(Debug, Clone, Copy)]
struct UserAttempts {
    window_start_ms: i64,
    failures: u32,
    retry_at_ms: i64,
}

/// Outcome of one failed sign-in for one account.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UserFailure {
    /// Consecutive failures inside the current window.
    pub(crate) failures: u32,
    /// Delay the next attempt has to respect.
    pub(crate) retry_after_secs: u64,
}

impl UsernameThrottle {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Rejects attempts that are still inside their backoff window.
    pub(crate) fn check(&self, username: &str) -> Result<()> {
        self.check_at(username, auth::now_ms())
    }

    fn check_at(&self, username: &str, now_ms: i64) -> Result<()> {
        let key = username_key(username);
        let Ok(inner) = self.inner.lock() else {
            return Ok(());
        };
        let Some(state) = inner.get(&key).copied() else {
            return Ok(());
        };
        if state.retry_at_ms > now_ms {
            let retry_after_secs = ((state.retry_at_ms - now_ms).max(1) as u64).div_ceil(1000);
            return Err(RtError::RateLimited {
                message: format!(
                    "too many failed sign-ins for this account; try again in {retry_after_secs}s"
                ),
                retry_after_secs,
            });
        }
        Ok(())
    }

    /// Records a failure and returns the backoff the next attempt has to wait.
    pub(crate) fn record_failure(&self, username: &str) -> UserFailure {
        self.record_failure_at(username, auth::now_ms())
    }

    fn record_failure_at(&self, username: &str, now_ms: i64) -> UserFailure {
        let key = username_key(username);
        let Ok(mut inner) = self.inner.lock() else {
            return UserFailure {
                failures: 1,
                retry_after_secs: USER_BACKOFF_BASE_SECS,
            };
        };
        inner.retain(|_, state| now_ms.saturating_sub(state.window_start_ms) < USER_FAILURE_WINDOW_MS);
        let state = inner.entry(key).or_insert(UserAttempts {
            window_start_ms: now_ms,
            failures: 0,
            retry_at_ms: 0,
        });
        if now_ms.saturating_sub(state.window_start_ms) >= USER_FAILURE_WINDOW_MS {
            state.window_start_ms = now_ms;
            state.failures = 0;
        }
        state.failures = state.failures.saturating_add(1);
        let mut backoff = if state.failures <= USER_BACKOFF_FREE_FAILURES {
            0
        } else {
            let step = (state.failures - USER_BACKOFF_FREE_FAILURES - 1).min(20);
            USER_BACKOFF_BASE_SECS
                .saturating_mul(1u64 << step)
                .min(USER_BACKOFF_CAP_SECS)
        };
        // Past the hourly allowance the account stays blocked until the window
        // rolls over, so a rotating source address cannot keep guessing.
        if state.failures >= USER_FAILURE_LIMIT {
            let window_left = USER_FAILURE_WINDOW_MS
                .saturating_sub(now_ms.saturating_sub(state.window_start_ms));
            backoff = backoff.max((window_left.max(1) as u64).div_ceil(1000));
        }
        state.retry_at_ms = now_ms.saturating_add((backoff as i64).saturating_mul(1000));
        UserFailure {
            failures: state.failures,
            retry_after_secs: backoff,
        }
    }

    /// Clears the counter after a successful sign-in.
    pub(crate) fn record_success(&self, username: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.remove(&username_key(username));
        }
    }

    /// Number of accounts tracked right now (diagnostics/tests).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().map(|inner| inner.len()).unwrap_or(0)
    }
}

/// Account keys are case-insensitive, like Windows account names.
pub(crate) fn username_key(username: &str) -> String {
    username.trim().to_lowercase()
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
    blocking_slots: Arc<Semaphore>,
    tickets: Mutex<HashMap<String, Ticket>>,
    creds: Mutex<Arc<Credentials>>,
    reload: Mutex<ReloadState>,
    read_budget: ReadBudget,
    user_throttle: UsernameThrottle,
    started_at_ms: i64,
    started: Instant,
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
        let blocking_slots = Arc::new(Semaphore::new(BLOCKING_ADMISSION_SLOTS));

        // Fail fast when workspace-scoped sessions cannot be jailed.
        PathGuard::new(Scope::Workspace, Some(paths.workspace_root.as_path()))
            .map_err(|err| anyhow::anyhow!("workspace root {:?} is unusable: {err}", paths.workspace_root))?;

        let creds = Credentials::from_config(&config);
        let signature = ConfigSignature::of(&paths.config_file);

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
            blocking_slots,
            tickets: Mutex::new(HashMap::new()),
            creds: Mutex::new(Arc::new(creds)),
            reload: Mutex::new(ReloadState {
                last_check_ms: auth::now_ms(),
                signature,
            }),
            read_budget: ReadBudget::new(READ_BUDGET_PER_MINUTE),
            user_throttle: UsernameThrottle::new(),
            started_at_ms: auth::now_ms(),
            started: Instant::now(),
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
            max_scope: self.credentials().max_scope,
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

    /// Live credential snapshot, refreshed from the config file at most once a
    /// second so keys can be revoked without a restart (SECURITY.md S-14).
    pub(crate) fn credentials(&self) -> Arc<Credentials> {
        self.reload_credentials();
        match self.creds.lock() {
            Ok(current) => Arc::clone(&current),
            Err(_) => Arc::new(Credentials::from_config(&self.config)),
        }
    }

    /// Re-reads `users`/`api_keys` when the config file changed on disk.
    fn reload_credentials(&self) {
        let now = auth::now_ms();
        {
            let Ok(mut reload) = self.reload.lock() else {
                return;
            };
            if now.saturating_sub(reload.last_check_ms) < CREDENTIAL_RELOAD_INTERVAL_MS {
                return;
            }
            reload.last_check_ms = now;
        }

        let path = self.paths.config_file.as_path();
        // Never reload from a vanished file: `load_or_create` would write a
        // defaults-only config and silently drop every credential.
        let Some(signature) = ConfigSignature::of(path) else {
            return;
        };
        let unchanged = self
            .reload
            .lock()
            .map(|reload| reload.signature == Some(signature))
            .unwrap_or(true);
        if unchanged {
            return;
        }

        match rt_core::config::load_or_create(Some(path)) {
            Ok(loaded) => {
                let fresh = Credentials::from_config(&loaded.config);
                if let Ok(mut current) = self.creds.lock() {
                    *current = Arc::new(fresh);
                }
                if let Ok(mut reload) = self.reload.lock() {
                    reload.signature = Some(signature);
                }
                tracing::info!(
                    target: "server",
                    path = %path.display(),
                    "credentials reloaded from the configuration file"
                );
            }
            Err(err) => {
                // Keep the previous snapshot and retry on the next check.
                tracing::warn!(
                    target: "server",
                    path = %path.display(),
                    "configuration reload failed, keeping current credentials: {err}"
                );
            }
        }
    }

    /// Per-session read allowance (server-side exfiltration cap).
    pub(crate) fn read_budget(&self) -> &ReadBudget {
        &self.read_budget
    }

    /// Per-account failed sign-in backoff.
    pub(crate) fn user_throttle(&self) -> &UsernameThrottle {
        &self.user_throttle
    }

    /// Concurrency guard for `exec` (REST and WS share it).
    pub(crate) fn exec_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.exec_slots)
    }

    /// Admission permits for blocking work (jobs beyond this many are shed).
    pub(crate) fn blocking_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.blocking_slots)
    }

    /// Runs blocking `rt-core` work under the shared admission budget.
    ///
    /// Every handler that enters the blocking pool goes through here so a burst
    /// of requests cannot saturate it and stall unrelated endpoints.
    pub(crate) async fn spawn_blocking_admitted<T, F>(&self, work: F) -> ApiResult<T>
    where
        F: FnOnce() -> rt_core::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        crate::middleware::blocking_admitted(&self.blocking_slots, work).await
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

    /// Mints a single-use, session-bound WebSocket ticket for one client.
    pub(crate) fn issue_ticket(&self, ctx: &SessionContext, client_ip: &str) -> String {
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
                    ip: client_ip.to_string(),
                    expires_at_ms: now + WS_TICKET_TTL_MS,
                },
            );
        }
        ticket
    }

    /// Consumes a ticket (single use) and returns the session it belonged to.
    ///
    /// The second argument is the presenting client address: a ticket minted
    /// for one host cannot be replayed from another (SECURITY.md S-24).
    pub(crate) fn take_ticket(
        &self,
        ticket: &str,
        client_ip: &str,
    ) -> std::result::Result<SessionContext, TicketError> {
        if ticket.trim().is_empty() {
            return Err(TicketError::Unknown);
        }
        let entry = {
            let mut map = self.tickets.lock().map_err(|_| TicketError::Unknown)?;
            let now = auth::now_ms();
            map.retain(|_, t| t.expires_at_ms > now);
            map.remove(ticket).ok_or(TicketError::Unknown)?
        };
        if entry.expires_at_ms <= auth::now_ms() {
            return Err(TicketError::Unknown);
        }
        if !entry.ip.eq_ignore_ascii_case(client_ip) {
            tracing::warn!(
                target: "server",
                issued_for = %entry.ip,
                presented_by = %client_ip,
                "rejected websocket ticket presented from a different address"
            );
            return Err(TicketError::AddressMismatch);
        }
        Ok(
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

    /// Address the listener is bound to, once `serve` has started.
    pub(crate) fn runtime_addr(&self) -> Option<SocketAddr> {
        self.runtime.lock().ok().and_then(|runtime| runtime.local_addr)
    }

    /// Application facts embedded in `/api/v1/sysinfo`.
    ///
    /// Workspace sessions get a virtual root and no host paths: the machine
    /// layout is host reconnaissance beyond their jail (SECURITY.md S-27).
    pub(crate) fn app_info(&self, scope: Scope) -> AppInfo {
        let (workspace_root, config_path, data_dir) = if scope.is_full() {
            (
                self.paths.workspace_root.display().to_string(),
                self.paths.config_file.display().to_string(),
                self.paths.data_dir.display().to_string(),
            )
        } else {
            ("\\".to_string(), String::new(), String::new())
        };
        AppInfo {
            version: rt_protocol::APP_VERSION.to_string(),
            protocol_version: rt_protocol::PROTOCOL_VERSION.to_string(),
            server_enabled: self.config.server.enabled,
            active_sessions: self.sessions.count().min(u32::MAX as usize) as u32,
            uptime_secs: self.uptime_secs(),
            scope,
            workspace_root: Some(workspace_root),
            config_path,
            data_dir,
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
            .field("max_scope", &self.credentials().max_scope)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_budget_blocks_a_session_and_resets_after_the_window() {
        let budget = ReadBudget::new(100);
        assert!(budget.charge_at("a", 60, 1_000).is_ok());
        assert!(budget.charge_at("a", 60, 1_000).is_err(), "over the cap");
        // A different session has its own allowance.
        assert!(budget.charge_at("b", 100, 1_000).is_ok());
        // The window slides: one minute after the first charge it is refilled.
        assert!(budget.charge_at("a", 100, 1_000 + READ_BUDGET_WINDOW_MS).is_ok());
    }

    #[test]
    fn read_budget_reports_a_retry_hint() {
        let budget = ReadBudget::new(10);
        assert!(budget.charge_at("a", 10, 0).is_ok());
        match budget.charge_at("a", 1, 20_000) {
            Err(RtError::RateLimited {
                retry_after_secs, ..
            }) => assert_eq!(retry_after_secs, 40),
            other => panic!("expected a rate-limit error, got {other:?}"),
        }
    }

    #[test]
    fn username_throttle_backs_off_exponentially_and_resets_on_success() {
        let throttle = UsernameThrottle::new();
        assert!(throttle.check_at("admin", 0).is_ok());

        let first = throttle.record_failure_at("admin", 0);
        assert_eq!((first.failures, first.retry_after_secs), (1, 0));
        assert!(
            throttle.check_at("admin", 500).is_ok(),
            "one typo must not delay the next attempt"
        );
        let second = throttle.record_failure_at("admin", 2_000);
        assert_eq!((second.failures, second.retry_after_secs), (2, 0));
        let third = throttle.record_failure_at("admin", 4_000);
        assert_eq!((third.failures, third.retry_after_secs), (3, 0));

        // From the fourth miss on the delay doubles with every attempt.
        let fourth = throttle.record_failure_at("admin", 6_000);
        assert_eq!((fourth.failures, fourth.retry_after_secs), (4, 1));
        match throttle.check_at("admin", 6_500) {
            Err(RtError::RateLimited {
                retry_after_secs, ..
            }) => assert_eq!(retry_after_secs, 1),
            other => panic!("expected a rate-limit error, got {other:?}"),
        }
        let fifth = throttle.record_failure_at("admin", 8_000);
        assert_eq!((fifth.failures, fifth.retry_after_secs), (5, 2));

        // Accounts are independent.
        assert!(throttle.check_at("worker", 8_000).is_ok());

        // A success clears the counter.
        throttle.record_success("admin");
        assert!(throttle.check_at("admin", 8_000).is_ok());
        assert_eq!(throttle.record_failure_at("admin", 8_000).failures, 1);
    }

    #[test]
    fn username_throttle_recovers_after_the_window() {
        let throttle = UsernameThrottle::new();
        for step in 0..20 {
            throttle.record_failure_at("admin", step * 1_000);
        }
        // Well past the window the counter starts from scratch.
        let later = USER_FAILURE_WINDOW_MS * 2;
        assert!(throttle.check_at("admin", later).is_ok());
        assert_eq!(throttle.record_failure_at("admin", later).failures, 1);
        assert_eq!(throttle.tracked(), 1);
    }

    #[test]
    fn username_keys_are_case_insensitive() {
        let throttle = UsernameThrottle::new();
        // Failure counters are shared across the spellings of one account.
        assert_eq!(throttle.record_failure_at("Admin", 0).failures, 1);
        let same_account = throttle.record_failure_at(" admin ", 100);
        assert_eq!(same_account.failures, 2, "the spelling must share a counter");
        assert_eq!(throttle.tracked(), 1, "one account, one entry");
        // A later success on any spelling clears the shared counter.
        throttle.record_success("ADMIN");
        assert_eq!(throttle.record_failure_at("aDmIn", 200).failures, 1);
    }

    #[test]
    fn config_signature_notices_edits() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        assert!(ConfigSignature::of(&path).is_none(), "missing file");

        std::fs::write(&path, b"a = 1\n").expect("write");
        let first = ConfigSignature::of(&path).expect("signature");
        assert_eq!(first.len, 6);

        std::fs::write(&path, b"a = 1\nb = 2\n").expect("rewrite");
        let second = ConfigSignature::of(&path).expect("signature");
        assert_ne!(first, second, "length change must be noticed");
    }
}

/// Kind string used for `SessionInfo::auth_kind` of API-key callers.
pub(crate) const AUTH_KIND_API_KEY: &str = "api_key";
