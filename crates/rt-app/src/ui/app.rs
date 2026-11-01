//! Application shell: state, connection lifecycle, navigation and chrome.
//!
//! The shell owns everything long-lived: the loaded [`Config`], the resolved
//! paths, the log sink, the tokio runtime, the connection state machine and the
//! per-page state. Pages draw into the central panel and are never allowed to
//! block: every network call is a tokio task that reports back over a channel
//! and calls `Context::request_repaint`.

use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use egui::{Align, Color32, Frame, Key, Layout, Margin, Modifiers, RichText, Sense, Stroke, Vec2};
use rt_client::{ClientError, RemoteClient, Target};
use rt_core::config::{Config, ResolvedPaths, Theme as ConfigTheme};
use rt_core::logging::{AuditLog, LogEventSink};
use rt_protocol::{QuickStatus, Scope, ServerInfo, SessionInfo};

use crate::Bootstrapped;

use super::pages;
use super::theme::{self, palette, Palette, Radius, Space, Tone, Type};
use super::widgets::{self, Btn, Toasts};

/// Runtime key used to persist the window size between sessions.
const KEY_WINDOW: &str = "remote-terminal.window";
/// Device name reported to the server for GUI sessions.
const DEVICE_NAME: &str = "gui";
/// Interval of the shared `quick_status` heartbeat.
const PULSE_INTERVAL: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// The six top-level views reachable from the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// Connection form, server identity and live statistics.
    Dashboard,
    /// Remote command execution.
    Exec,
    /// Remote filesystem browser.
    Files,
    /// Remote screen capture.
    Screen,
    /// Configuration editor.
    Settings,
    /// In-process log and audit tail.
    Logs,
}

impl Page {
    /// Every page in sidebar order.
    pub const ALL: [Page; 6] = [
        Page::Dashboard,
        Page::Exec,
        Page::Files,
        Page::Screen,
        Page::Settings,
        Page::Logs,
    ];

    /// Chinese navigation label.
    pub fn title(self) -> &'static str {
        match self {
            Page::Dashboard => "总览",
            Page::Exec => "命令",
            Page::Files => "文件",
            Page::Screen => "屏幕",
            Page::Settings => "设置",
            Page::Logs => "日志",
        }
    }

    /// Small leading glyph (drawn before the label).
    pub fn icon(self) -> &'static str {
        match self {
            Page::Dashboard => "◎",
            Page::Exec => "❯",
            Page::Files => "▤",
            Page::Screen => "▣",
            Page::Settings => "⚙",
            Page::Logs => "≡",
        }
    }

    /// Keyboard shortcut hint.
    pub fn shortcut(self) -> &'static str {
        match self {
            Page::Dashboard => "Ctrl+1",
            Page::Exec => "Ctrl+2",
            Page::Files => "Ctrl+3",
            Page::Screen => "Ctrl+4",
            Page::Settings => "Ctrl+5",
            Page::Logs => "Ctrl+6",
        }
    }

    /// One-line purpose shown in the top bar.
    pub fn hint(self) -> &'static str {
        match self {
            Page::Dashboard => "连接状态、远端身份与实时负载",
            Page::Exec => "在目标机器上执行命令并查看实时输出",
            Page::Files => "浏览、上传、下载与整理远端文件",
            Page::Screen => "截取远端屏幕或窗口",
            Page::Settings => "服务端、用户、密钥与客户端设置",
            Page::Logs => "本进程日志与审计记录",
        }
    }
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// A live, authenticated connection.
pub struct Connected {
    /// Authenticated client used by every page.
    pub client: RemoteClient,
    /// Identity of the remote server.
    pub info: ServerInfo,
    /// Details of the session that was issued.
    pub session: SessionInfo,
    /// Certificate fingerprint actually presented (pinned or TOFU).
    pub fingerprint: Option<String>,
    /// `host:port` the client dialled.
    pub address: String,
    /// Transport security of this connection.
    pub tls: bool,
    /// When this connection became usable.
    pub since: Instant,
}

/// Connection state machine (architecture §2).
pub enum Conn {
    /// No server attached.
    Offline,
    /// A connect attempt is in flight.
    Connecting {
        /// `host:port` being dialled.
        label: String,
        /// When the attempt started.
        started: Instant,
    },
    /// Connected and authenticated.
    Online(Box<Connected>),
}

/// Everything needed for one connect attempt.
#[derive(Clone, Debug)]
pub struct ConnectRequest {
    /// Host name or IP.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Use TLS (`https`/`wss`) instead of plaintext.
    pub tls: bool,
    /// Password login user name.
    pub username: String,
    /// Password login secret (never logged).
    pub password: String,
    /// When set, authenticate with this API key instead of a password.
    pub api_key: Option<String>,
    /// Certificate fingerprint to pin.
    pub pin: Option<String>,
    /// Explicit trust-on-first-use consent for this attempt.
    pub accept_new: bool,
    /// Per-request timeout.
    pub timeout_secs: u64,
}

/// Result of a background connect attempt.
pub enum ConnEvent {
    /// Connected and authenticated.
    Online(Box<Connected>),
    /// Failed; carries `ClientError::message()` verbatim.
    Failed(String),
    /// The server presented a certificate that is not pinned yet.
    TrustRequired {
        /// The request that produced this fingerprint, ready to be retried.
        request: Box<ConnectRequest>,
        /// Server identity learned over the unverified channel.
        info: Box<ServerInfo>,
        /// Fingerprint the server presented.
        fingerprint: Option<String>,
    },
    /// Result of an unauthenticated reachability probe.
    Probed(Box<Probe>),
}

/// Probes a server without sending any credential.
async fn perform_probe(target: Target, timeout: Duration) -> Probe {
    let started = Instant::now();
    let client = match RemoteClient::with_timeout(target, timeout) {
        Ok(client) => client,
        Err(err) => return Probe::Err(describe_error(&err)),
    };
    match client.info().await {
        Ok(server) => Probe::Ok {
            latency_ms: started.elapsed().as_millis() as u64,
            server: Box::new(server),
            fingerprint: client.presented_fingerprint(),
        },
        Err(err) => Probe::Err(describe_error(&err)),
    }
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// Stable identifier handed to background tasks so results find their host.
pub type HostId = u64;

/// How many hosts may be connected at the same time.
pub const MAX_HOSTS: usize = 8;

/// Per-host page state for the pages that are scoped to one connection.
///
/// Only the active host's pages live in [`App`] so page code can keep using
/// plain fields; every other host keeps its pages parked here. Switching hosts
/// moves the two sets, which is a handful of cheap moves.
#[derive(Default)]
pub struct HostPages {
    dashboard: pages::dashboard::State,
    exec: pages::exec::State,
    files: pages::files::State,
    screen: pages::screen::State,
}

/// Outcome of the lightweight reachability probe (no credentials are sent).
pub enum Probe {
    /// The server answered `/info`.
    Ok {
        /// Round-trip time of the probe.
        latency_ms: u64,
        /// Identity the server reported.
        server: Box<ServerInfo>,
        /// Certificate fingerprint it presented, when TLS is used.
        fingerprint: Option<String>,
    },
    /// The server did not answer.
    Err(String),
}

/// One remote host the user can talk to.
pub struct HostSlot {
    /// Stable id used by background tasks.
    pub id: HostId,
    /// Sidebar label.
    pub label: String,
    /// Host/port/TLS/fingerprint this slot dials.
    pub target: Target,
    /// Connection state of this host only.
    pub conn: Conn,
    /// Last error of this host (shown on its sidebar row).
    pub error: Option<String>,
    /// Credentials of the last successful attempt, reused by 重连.
    ///
    /// Holds a password or API key in memory for this process only; nothing is
    /// ever written to the config file or the log.
    pub last_request: Option<ConnectRequest>,
    /// Reachability probe result.
    pub probe: Option<Probe>,
    /// A probe is in flight.
    pub probe_running: bool,
    /// Whether this host came from `config.client.hosts`.
    pub configured: bool,
    /// Re-run `last_request` automatically on next start.
    pub auto_connect: bool,
    /// Write the host back into the config file after a successful connect.
    pub persist: bool,
    /// Server identity from the last connection, kept after disconnecting.
    pub info: Option<ServerInfo>,
    /// Pending trust-on-first-use prompt for a host that is not resident.
    pub trust: Option<pages::dashboard::TrustPrompt>,
    /// Page state (parked unless this is the resident host).
    pages: HostPages,
}

impl HostSlot {
    /// Creates a slot, optionally seeded from a configured host entry.
    fn new(id: HostId, host: Option<&rt_core::config::HostConfig>) -> Self {
        let mut slot = Self {
            id,
            label: String::new(),
            target: Target::new("127.0.0.1", 46666),
            conn: Conn::Offline,
            error: None,
            last_request: None,
            probe: None,
            probe_running: false,
            configured: host.is_some(),
            auto_connect: false,
            persist: true,
            info: None,
            trust: None,
            pages: HostPages::default(),
        };
        match host {
            Some(host) => {
                slot.label = host_label(host);
                slot.target = Target::new(host.host.clone(), host.port);
                if let Some(fingerprint) = &host.fingerprint {
                    slot.target = slot.target.with_fingerprint(fingerprint.clone());
                }
                slot.auto_connect = host.auto_connect;
                slot.pages.dashboard.seed_from_host(host);
            }
            None => {
                slot.label = "本机".to_string();

            }
        }
        slot
    }

    /// `host:port` shown in the sidebar and the status line.
    pub fn address(&self) -> String {
        format!("{}:{}", self.target.host, self.target.port)
    }

    /// Whether this host currently holds a usable connection.
    pub fn online(&self) -> bool {
        matches!(self.conn, Conn::Online(_))
    }

    /// Whether this host is connecting or connected (counts against the cap).
    pub fn busy(&self) -> bool {
        matches!(self.conn, Conn::Connecting { .. } | Conn::Online(_))
    }

    /// Status colour and one-word state used by the sidebar rows.
    fn state_label(&self) -> (HostState, &'static str) {
        match &self.conn {
            Conn::Online(_) => (HostState::Online, "在线"),
            Conn::Connecting { .. } => (HostState::Connecting, "连接中"),
            Conn::Offline => match &self.probe {
                Some(Probe::Ok { .. }) => (HostState::Reachable, "待登录"),
                Some(Probe::Err(_)) => (HostState::Unreachable, "不可达"),
                None => (HostState::Offline, "未连接"),
            },
        }
    }
}
/// Coarse state of a host row in the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostState {
    /// Never connected and never probed.
    Offline,
    /// A connect attempt is in flight.
    Connecting,
    /// Authenticated.
    Online,
    /// Answered a probe but is waiting for credentials.
    Reachable,
    /// Did not answer the probe.
    Unreachable,
}

impl HostState {
    /// Semantic colour of this state.
    pub fn tone(self) -> Tone {
        match self {
            HostState::Online => Tone::Success,
            HostState::Connecting => Tone::Warning,
            HostState::Reachable => Tone::Accent,
            HostState::Unreachable => Tone::Danger,
            HostState::Offline => Tone::Neutral,
        }
    }
}

/// Snapshot of one sidebar host row, so drawing never borrows `App` twice.
struct HostRow {
    index: usize,
    label: String,
    address: String,
    state: HostState,
    active: bool,
    error: Option<String>,
    busy: bool,
}

/// Deferred sidebar host action, applied after the rows are drawn.
enum HostAction {
    Switch(usize),
    Connect(usize),
    Disconnect(usize),
    Probe(usize),
    Remove(usize),
}

/// Normalises a user-typed certificate fingerprint into bare lowercase hex.
fn clean_fingerprint(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.len() >= 16 {
        Some(cleaned)
    } else {
        None
    }
}
/// Human label of a configured host (`name`, or `host:port` when unnamed).
fn host_label(host: &rt_core::config::HostConfig) -> String {
    let name = host.name.trim();
    if name.is_empty() {
        format!("{}:{}", host.host, host.port)
    } else {
        name.to_string()
    }
}

/// The 「添加主机」 modal form.
pub struct HostForm {
    /// Optional display name.
    pub label: String,
    /// Host name or IP.
    pub host: String,
    /// Port as text so partial input does not fight the parser.
    pub port: String,
    /// Use TLS.
    pub tls: bool,
    /// Password login user name.
    pub username: String,
    /// Password (memory only).
    pub password: String,
    /// Authenticate with an API key instead.
    pub use_api_key: bool,
    /// API key text.
    pub api_key: String,
    /// Certificate fingerprint to pin.
    pub pin: String,
    /// Remember this host in the config file.
    pub persist: bool,
    /// Inline validation error.
    pub error: Option<String>,
}

impl Default for HostForm {
    fn default() -> Self {
        Self {
            label: String::new(),
            host: "127.0.0.1".to_string(),
            port: "46666".to_string(),
            tls: true,
            username: "admin".to_string(),
            password: String::new(),
            use_api_key: false,
            api_key: String::new(),
            pin: String::new(),
            persist: true,
            error: None,
        }
    }
}
/// Renders the client error exactly as the protocol reported it.
pub fn describe_error(err: &ClientError) -> String {
    match err.status() {
        Some(status) => format!("{}（HTTP {}）", err.message(), status),
        None => err.message(),
    }
}

/// Performs one connect attempt; runs on the tokio runtime, never on the UI thread.
async fn perform_connect(request: ConnectRequest, require_pin: bool) -> ConnEvent {
    let mut target = Target::new(request.host.clone(), request.port);
    target.tls = request.tls;
    if let Some(pin) = request.pin.clone() {
        target = target.with_fingerprint(pin);
    }
    let timeout = Duration::from_secs(request.timeout_secs.clamp(3, 600));
    let client = match RemoteClient::with_timeout(target, timeout) {
        Ok(client) => client,
        Err(err) => return ConnEvent::Failed(describe_error(&err)),
    };

    // Identity first: `/info` is unauthenticated, so nothing secret is sent
    // before the user has seen the certificate fingerprint.
    let info = match client.info().await {
        Ok(info) => info,
        Err(err) => return ConnEvent::Failed(describe_error(&err)),
    };
    let presented = client.presented_fingerprint();
    if request.tls && request.pin.is_none() && require_pin && !request.accept_new {
        return ConnEvent::TrustRequired {
            request: Box::new(request),
            info: Box::new(info),
            fingerprint: presented,
        };
    }

    let api_key = request
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty());
    let session = if let Some(key) = api_key {
        client.use_api_key(key);
        match client.me().await {
            Ok(session) => session,
            Err(err) => return ConnEvent::Failed(describe_error(&err)),
        }
    } else {
        match client.login(&request.username, &request.password, DEVICE_NAME).await {
            Ok(_) => match client.me().await {
                Ok(session) => session,
                Err(err) => return ConnEvent::Failed(describe_error(&err)),
            },
            Err(err) => return ConnEvent::Failed(describe_error(&err)),
        }
    };

    ConnEvent::Online(Box::new(Connected {
        client,
        info,
        session,
        fingerprint: presented.or(request.pin.clone()),
        address: format!("{}:{}", request.host, request.port),
        tls: request.tls,
        since: Instant::now(),
    }))
}

// ---------------------------------------------------------------------------
// Server lifecycle (client/server in one GUI)
// ---------------------------------------------------------------------------

/// A server started from inside the GUI.
pub struct EmbeddedServer {
    /// Bound address, url and certificate fingerprint.
    pub handle: rt_server::ServerHandle,
    /// When it was started.
    pub since: Instant,
    /// Shutdown signal kept alive with the handle.
    _shutdown: tokio::sync::watch::Sender<bool>,
}

/// Result of a background server start/stop.
pub enum ServerEvent {
    /// The server is listening.
    Started(Box<EmbeddedServer>),
    /// Starting failed; carries the raw error.
    Failed(String),
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

/// Root application object.
pub struct App {
    /// Egui context, cloned into background tasks so they can repaint.
    pub ctx: egui::Context,
    /// Live configuration (edited by the settings page, saved on demand).
    pub config: Config,
    /// Resolved data directories.
    pub paths: ResolvedPaths,
    /// Config file that [`Config::save_with_header`] writes.
    pub config_path: PathBuf,
    /// In-memory log ring shared with the server and the log page.
    pub sink: Arc<LogEventSink>,
    /// Audit trail, when file auditing is enabled.
    pub audit: Option<Arc<AuditLog>>,
    /// Handle to the tokio runtime; the runtime itself is kept alive below.
    pub runtime: tokio::runtime::Handle,
    /// Reduced-motion preference (not persisted: no config key yet).
    pub reduce_motion: bool,

    /// Every host the user has added, in sidebar order.
    pub hosts: Vec<HostSlot>,
    /// Index of the host the UI is currently showing.
    pub active: usize,
    /// Index of the slot that owns the page state stored in `App`.
    ///
    /// Equal to `active` outside [`App::poll_pages`], which temporarily loads
    /// another host's pages so its background results are drained too.
    resident: Option<usize>,
    /// Id source for new slots.
    next_host_id: HostId,
    /// Background connect/probe results, tagged with the host they belong to.
    conn_tx: mpsc::Sender<(HostId, ConnEvent)>,
    conn_rx: mpsc::Receiver<(HostId, ConnEvent)>,
    /// Open 「添加主机」 form.
    host_form: Option<HostForm>,

    /// Server started from this GUI process, if any.
    pub server: Option<EmbeddedServer>,
    server_tx: mpsc::Sender<ServerEvent>,
    server_rx: mpsc::Receiver<ServerEvent>,

    /// Active page.
    pub page: Page,
    /// Sidebar collapsed to icons only.
    pub sidebar_collapsed: bool,
    /// Toast overlay queue.
    pub toasts: Toasts,
    /// Last error shown in the status line.
    pub last_error: Option<String>,
    /// Free-form status line message (cleared after a few seconds).
    pub status: Option<(String, Instant)>,
    /// Set by Ctrl+R; the active page consumes it.
    pub refresh_requested: bool,

    /// Last `quick_status` sample, shared by the status line and the dashboard.
    pub pulse: Option<QuickStatus>,
    pulse_rx: mpsc::Receiver<QuickStatus>,
    pulse_tx: mpsc::Sender<QuickStatus>,
    pulse_next: Instant,
    pulse_inflight: bool,

    /// Page state of the resident host (see [`App::resident`]).
    pub dashboard: pages::dashboard::State,
    pub exec: pages::exec::State,
    pub files: pages::files::State,
    pub screen: pages::screen::State,
    /// Process-wide pages; these are not tied to a host.
    pub settings: pages::settings::State,
    pub logs: pages::logs::State,

    /// Style actually installed, so the theme is only rebuilt on change.
    applied: Option<(ConfigTheme, String, bool)>,
    /// Keeps the tokio runtime alive for the whole process (dropped last).
    _runtime: tokio::runtime::Runtime,
}

impl App {
    /// Builds the application from the bootstrapped configuration.
    pub fn new(cc: &eframe::CreationContext<'_>, boot: Bootstrapped, runtime: tokio::runtime::Runtime) -> Self {
        let ctx = cc.egui_ctx.clone();
        if theme::install_fonts(&ctx).is_none() {
            tracing::warn!(target: "gui", "no CJK font found; Chinese labels may render as boxes");
        }
        let config = boot.loaded.config.clone();
        theme::apply(&ctx, config.app.theme, &config.app.accent, false);
        theme::set_reduce_motion(&ctx, false);

        // Restore the previous window size when the user asked us to.
        if config.app.remember_window {
            if let Some(storage) = cc.storage {
                if let Some([w, h]) = eframe::get_value::<[f32; 2]>(storage, KEY_WINDOW) {
                    if w >= 640.0 && h >= 480.0 {
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(w, h)));
                    }
                }
            }
        }

        let (conn_tx, conn_rx) = mpsc::channel();
        let (server_tx, server_rx) = mpsc::channel();
        let (pulse_tx, pulse_rx) = mpsc::channel();
        let mut toasts = Toasts::default();
        for warning in &boot.loaded.warnings {
            toasts.warn(warning.clone());
        }

        let mut app = Self {
            ctx,
            config,
            paths: boot.paths.clone(),
            config_path: boot.paths.config_file.clone(),
            sink: boot.logging.sink.clone(),
            audit: boot.logging.audit.clone(),
            runtime: runtime.handle().clone(),
            reduce_motion: false,
            hosts: Vec::new(),
            active: 0,
            resident: None,
            next_host_id: 1,
            conn_tx,
            conn_rx,
            host_form: None,
            server: None,
            server_tx,
            server_rx,
            page: Page::Dashboard,
            sidebar_collapsed: false,
            toasts,
            last_error: None,
            status: None,
            refresh_requested: false,
            pulse: None,
            pulse_rx,
            pulse_tx,
            pulse_next: Instant::now(),
            pulse_inflight: false,
            dashboard: pages::dashboard::State::default(),
            exec: pages::exec::State::default(),
            files: pages::files::State::default(),
            screen: pages::screen::State::default(),
            settings: pages::settings::State::default(),
            logs: pages::logs::State::default(),
            applied: None,
            _runtime: runtime,
        };
        // One slot per configured host; a blank local one keeps the UI usable
        // on a fresh install.
        app.seed_hosts();
        // Page state is per host, so only the resident slot is seeded here.
        app.exec.seed_from_config(&app.config);
        app.files.seed_from_config(&app.config);
        app.screen.seed_from_config(&app.config);
        app.settings.seed_from_config(&app.config, &app.paths);
        app.logs.seed_from_config(&app.config);
        app.auto_probe_hosts();
        app
    }

    // -- accessors ----------------------------------------------------------

    /// Slot that owns the page state currently stored in `App`.
    fn slot(&self) -> Option<&HostSlot> {
        self.resident.and_then(|index| self.hosts.get(index))
    }

    /// Slot the sidebar highlights.
    pub fn active_slot(&self) -> Option<&HostSlot> {
        self.hosts.get(self.active)
    }

    /// Read-only access to any slot.
    pub fn slot_ref(&self, index: usize) -> Option<&HostSlot> {
        self.hosts.get(index)
    }

    /// Mutable access to any slot.
    pub fn slot_mut(&mut self, index: usize) -> Option<&mut HostSlot> {
        self.hosts.get_mut(index)
    }

    /// Connect form of any host, resident or parked.
    pub fn slot_dashboard(&self, index: usize) -> Option<&pages::dashboard::State> {
        if Some(index) == self.resident {
            Some(&self.dashboard)
        } else {
            self.hosts.get(index).map(|slot| &slot.pages.dashboard)
        }
    }

    /// Index of the slot carrying `id`.
    fn index_of(&self, id: HostId) -> Option<usize> {
        self.hosts.iter().position(|slot| slot.id == id)
    }

    /// Authenticated client of the resident host, if any.
    pub fn client(&self) -> Option<RemoteClient> {
        match &self.slot()?.conn {
            Conn::Online(connected) => Some(connected.client.clone()),
            _ => None,
        }
    }

    /// Connected state of the resident host.
    pub fn connected(&self) -> Option<&Connected> {
        match &self.slot()?.conn {
            Conn::Online(connected) => Some(connected),
            _ => None,
        }
    }

    /// Whether the resident host is authenticated.
    pub fn is_online(&self) -> bool {
        self.connected().is_some()
    }

    /// Scope granted by the resident server, if connected.
    pub fn scope(&self) -> Option<Scope> {
        self.connected().map(|c| c.session.scope)
    }

    /// Short status message shown at the bottom of the window.
    pub fn set_status(&mut self, text: impl Into<String>) {
        self.status = Some((text.into(), Instant::now()));
    }

    /// Reports an error both as a toast and in the status line.
    pub fn fail(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.last_error = Some(text.clone());
        self.toasts.error(text);
    }

    /// Spawns a fire-and-forget task that repaints when it finishes.
    pub fn spawn_task<F>(&self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            task.await;
            ctx.request_repaint();
        });
    }

    /// Spawns a blocking job (file dialogs, argon2 hashing) off the UI thread.
    pub fn spawn_blocking<F, T>(&self, job: F, deliver: impl FnOnce(T) + Send + 'static)
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            if let Ok(value) = tokio::task::spawn_blocking(job).await {
                deliver(value);
            }
            ctx.request_repaint();
        });
    }

    // -- host slots ---------------------------------------------------------

    /// Builds the slot list from `config.client.hosts`.
    fn seed_hosts(&mut self) {
        let configured = self.config.client.hosts.clone();
        if configured.is_empty() {
            let index = self.push_slot(None);
            self.load_pages(index);
            self.active = index;
            return;
        }
        let mut start = 0;
        for host in &configured {
            let index = self.push_slot(Some(host));
            if start == 0 && host.auto_connect {
                start = index;
            }
        }
        self.load_pages(start);
        self.active = start;
    }

    /// Appends a slot and returns its index.
    fn push_slot(&mut self, host: Option<&rt_core::config::HostConfig>) -> usize {
        let id = self.next_host_id;
        self.next_host_id += 1;
        self.hosts.push(HostSlot::new(id, host));
        self.hosts.len() - 1
    }

    /// Moves the page state held by `App` back into its owning slot.
    fn park_pages(&mut self) {
        let Some(index) = self.resident.take() else {
            return;
        };
        let Some(slot) = self.hosts.get_mut(index) else {
            return;
        };
        slot.pages.dashboard = std::mem::take(&mut self.dashboard);
        slot.pages.exec = std::mem::take(&mut self.exec);
        slot.pages.files = std::mem::take(&mut self.files);
        slot.pages.screen = std::mem::take(&mut self.screen);
    }

    /// Makes `index` the resident host: its page state moves into `App`.
    fn load_pages(&mut self, index: usize) {
        if index >= self.hosts.len() {
            return;
        }
        self.park_pages();
        let slot = &mut self.hosts[index];
        self.dashboard = std::mem::take(&mut slot.pages.dashboard);
        self.exec = std::mem::take(&mut slot.pages.exec);
        self.files = std::mem::take(&mut slot.pages.files);
        self.screen = std::mem::take(&mut slot.pages.screen);
        self.resident = Some(index);
        // A trust prompt that arrived while this host was in the background.
        if let Some(prompt) = self.hosts[index].trust.take() {
            self.dashboard.pending_trust = Some(prompt);
        }
    }

    /// Switches the visible host without touching its connection.
    pub fn activate(&mut self, index: usize) {
        if index >= self.hosts.len() || index == self.active {
            return;
        }
        // The live preview belongs to the host that is leaving the screen.
        if self.page == Page::Screen {
            self.screen.suspend_live();
        }
        self.load_pages(index);
        self.active = index;
        // Heartbeat samples belong to the previous host.
        self.pulse = None;
        self.pulse_inflight = false;
        self.pulse_next = Instant::now();
    }

    /// Number of hosts that are connecting or connected.
    pub fn live_hosts(&self) -> usize {
        self.hosts.iter().filter(|slot| slot.busy()).count()
    }

    // -- connection ---------------------------------------------------------

    /// Starts a connect attempt for the active host.
    pub fn connect(&mut self, request: ConnectRequest) {
        let index = self.active;
        self.connect_slot(index, request);
    }

    /// Starts a connect attempt for one host.
    pub fn connect_slot(&mut self, index: usize, request: ConnectRequest) {
        if index >= self.hosts.len() {
            return;
        }
        let others = self
            .hosts
            .iter()
            .filter(|slot| slot.id != self.hosts[index].id && slot.busy())
            .count();
        if others >= MAX_HOSTS {
            let message = format!(
                "最多同时连接 {MAX_HOSTS} 台主机，请先断开一台再连接 {}",
                self.hosts[index].address()
            );
            self.fail(message);
            return;
        }
        // The user witnesses this connection, so bring the host forward.
        self.activate(index);
        if let Some(slot) = self.hosts.get_mut(index) {
            slot.error = None;
            slot.label = if slot.label.trim().is_empty() {
                slot.address()
            } else {
                slot.label.clone()
            };
            slot.target = {
                let mut target = Target::new(request.host.clone(), request.port);
                target.tls = request.tls;
                match request.pin.clone() {
                    Some(pin) => target.with_fingerprint(pin),
                    None => target,
                }
            };
            slot.conn = Conn::Connecting {
                label: format!("{}:{}", request.host, request.port),
                started: Instant::now(),
            };
            // Kept for 重连; the password never leaves this process.
            slot.last_request = Some(request.clone());
        }
        self.last_error = None;
        let id = self.hosts[index].id;
        let tx = self.conn_tx.clone();
        let ctx = self.ctx.clone();
        let require_pin = self.config.client.require_pinned_fingerprint;
        self.runtime.spawn(async move {
            let event = perform_connect(request, require_pin).await;
            let _ = tx.send((id, event));
            ctx.request_repaint();
        });
    }

    /// Drops the connection of the active host.
    pub fn disconnect(&mut self) {
        let index = self.active;
        self.disconnect_slot(index);
    }

    /// Drops the connection of one host, keeping its page state.
    pub fn disconnect_slot(&mut self, index: usize) {
        if index >= self.hosts.len() {
            return;
        }
        let resident = self.resident == Some(index);
        if !resident {
            // Load the host so its WebSocket and capture stream are stopped.
            self.load_pages(index);
        }
        if let Some(slot) = self.hosts.get_mut(index) {
            slot.conn = Conn::Offline;
            slot.last_request = None;
        }
        self.files.reset_after_disconnect();
        self.exec.close_ws();
        self.screen.reset_after_disconnect();
        if resident {
            self.pulse = None;
            self.pulse_inflight = false;
        } else {
            self.load_pages(self.active);
        }
        if index == self.active {
            self.set_status("已断开连接");
        } else {
            let label = self.hosts[index].label.clone();
            self.set_status(format!("已断开 {label}"));
        }
    }

    /// Removes a host from the sidebar.
    pub fn remove_host(&mut self, index: usize) {
        if index >= self.hosts.len() || self.hosts.len() == 1 {
            self.toasts.warn("至少保留一台主机");
            return;
        }
        self.disconnect_slot(index);
        self.hosts.remove(index);
        // The page state in flight belonged to the removed slot, so drop the
        // residency claim instead of parking it into a neighbouring host.
        self.resident = match self.resident {
            Some(resident) if resident == index => None,
            Some(resident) if resident > index => Some(resident - 1),
            other => other,
        };
        if self.active >= self.hosts.len() {
            self.active = self.hosts.len() - 1;
        }
        // The removed slot's pages are gone; reload whatever is active now.
        self.load_pages(self.active);
        self.set_status("已移除主机");
    }

    /// Re-runs the last successful credentials of a host.
    pub fn reconnect_slot(&mut self, index: usize) {
        let request = self
            .hosts
            .get(index)
            .and_then(|slot| slot.last_request.clone())
            .or_else(|| {
                self.slot_dashboard(index)
                    .and_then(|state| state.build_request(&self.config).ok())
            });
        match request {
            Some(request) => self.connect_slot(index, request),
            None => {
                self.activate(index);
                let label = self.hosts[index].label.clone();
                self.toasts
                    .warn(format!("请先在总览页填写 {label} 的用户名与密码"));
                self.set_page(Page::Dashboard);
            }
        }
    }

    /// Runs the unauthenticated reachability probe for a host.
    pub fn probe_slot(&mut self, index: usize) {
        let Some(slot) = self.hosts.get_mut(index) else {
            return;
        };
        if slot.probe_running {
            return;
        }
        slot.probe_running = true;
        let id = slot.id;
        let target = slot.target.clone();
        let timeout = Duration::from_secs(self.config.client.request_timeout_secs.clamp(3, 600));
        let tx = self.conn_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let probe = perform_probe(target, timeout).await;
            let _ = tx.send((id, ConnEvent::Probed(Box::new(probe))));
            ctx.request_repaint();
        });
    }

    /// Probes at most two `auto_connect` hosts so startup stays fast.
    fn auto_probe_hosts(&mut self) {
        let targets: Vec<usize> = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.auto_connect)
            .map(|(index, _)| index)
            .take(2)
            .collect();
        for index in targets {
            self.probe_slot(index);
        }
    }

    /// Applies background connect and probe results.
    fn poll_connection(&mut self) {
        while let Ok((id, event)) = self.conn_rx.try_recv() {
            let Some(index) = self.index_of(id) else {
                continue;
            };
            match event {
                ConnEvent::Online(connected) => {
                    let address = connected.address.clone();
                    let scope = connected.session.scope;
                    let fingerprint = connected.fingerprint.clone();
                    let info = connected.info.clone();
                    if let Some(slot) = self.hosts.get_mut(index) {
                        slot.conn = Conn::Online(connected);
                        slot.error = None;
                        slot.info = Some(info);
                        // Pin the fingerprint we actually saw, for 重连.
                        if let Some(request) = slot.last_request.as_mut() {
                            if request.pin.is_none() {
                                request.pin = fingerprint.clone();
                                request.accept_new = false;
                            }
                        }
                    }
                    let persistent = self.hosts[index].persist;
                    let username = self
                        .slot_dashboard(index)
                        .map(|state| state.username.trim().to_string())
                        .unwrap_or_default();
                    self.record_host(&address, scope, &username, fingerprint.clone());
                    if index == self.active {
                        self.activate_connected(index, &address);
                        self.set_status(format!("已连接到 {address}"));
                        self.toasts.success(format!("已连接到 {address}"));
                    } else {
                        let label = self.hosts[index].label.clone();
                        self.toasts.info(format!("{label} 已连接"));
                    }
                    if persistent {
                        self.persist_hosts();
                    }
                }
                ConnEvent::Failed(message) => {
                    if let Some(slot) = self.hosts.get_mut(index) {
                        slot.conn = Conn::Offline;
                        slot.error = Some(message.clone());
                    }
                    let label = self.hosts[index].label.clone();
                    self.last_error = Some(message.clone());
                    self.toasts.error(format!("{label}：{message}"));
                    if index == self.active && self.page == Page::Dashboard {
                        self.with_dashboard(|state, _app| {
                            state.form_error = Some(message.clone());
                        });
                    }
                }
                ConnEvent::TrustRequired {
                    request,
                    info,
                    fingerprint,
                } => {
                    let prompt = pages::dashboard::TrustPrompt {
                        request: *request,
                        info,
                        fingerprint,
                    };
                    if let Some(slot) = self.hosts.get_mut(index) {
                        slot.conn = Conn::Offline;
                        if index == self.resident.unwrap_or(usize::MAX) {
                            self.dashboard.pending_trust = Some(prompt);
                        } else {
                            // Shown as soon as the user opens that host.
                            slot.trust = Some(prompt);
                        }
                    }
                    let label = self.hosts[index].label.clone();
                    self.toasts
                        .warn(format!("{label} 的证书尚未固定，需要确认指纹"));
                    self.activate(index);
                }
                ConnEvent::Probed(probe) => {
                    if let Some(slot) = self.hosts.get_mut(index) {
                        slot.probe_running = false;
                        slot.probe = Some(*probe);
                    }
                }
            }
        }
    }

    /// Post-connect plumbing for the host the user is looking at.
    fn activate_connected(&mut self, index: usize, address: &str) {
        if Some(index) != self.resident {
            return;
        }
        self.pulse_next = Instant::now();
        self.dashboard.on_connected(address);
    }

    /// Remembers `username`/`last_connected`/fingerprint for the host list.
    fn record_host(&mut self, address: &str, scope: Scope, username: &str, fingerprint: Option<String>) {
        let Some((host, port)) = address.rsplit_once(':') else {
            return;
        };
        let Ok(port) = port.parse::<u16>() else {
            return;
        };
        let fingerprint =
            fingerprint.map(|value| rt_core::crypto::format_fingerprint(&value));
        let entry = self.config.host_entry_mut(host, port);
        entry.last_connected = Some(rt_core::util::now_rfc3339());
        entry.last_scope = Some(scope.as_str().to_string());
        if entry.username.is_empty() {
            entry.username = username.to_string();
        }
        if entry.fingerprint.is_none() {
            entry.fingerprint = fingerprint;
        }
    }

    /// Writes the host list back to the config file, reporting failures.
    fn persist_hosts(&mut self) {
        if let Err(err) = self.config.save_with_header(&self.config_path) {
            self.toasts.error(format!("保存主机列表失败：{err}"));
            return;
        }
        self.set_status(format!("主机列表已保存到 {}", self.config_path.display()));
    }

    // -- heartbeat ----------------------------------------------------------

    /// Polls `quick_status` every few seconds while connected.
    fn poll_pulse(&mut self) {
        while let Ok(status) = self.pulse_rx.try_recv() {
            self.pulse = Some(status);
            self.pulse_inflight = false;
        }
        if !self.is_online() {
            return;
        }
        if self.pulse_inflight || Instant::now() < self.pulse_next {
            return;
        }
        let Some(client) = self.client() else { return };
        self.pulse_inflight = true;
        self.pulse_next = Instant::now() + PULSE_INTERVAL;
        let tx = self.pulse_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            if let Ok(status) = client.quick_status().await {
                let _ = tx.send(status);
            }
            ctx.request_repaint();
        });
    }

    // -- server lifecycle ---------------------------------------------------

    /// Starts the embedded server with the current in-memory configuration.
    pub fn start_server(&mut self) {
        if self.server.is_some() {
            self.toasts.info("服务端已在运行");
            return;
        }
        if !self.config.server.enabled {
            self.toasts.warn("请先启用服务端（设置 → 服务端）");
            return;
        }
        if !self.config.validate().is_ok() {
            self.toasts.error("配置未通过校验，无法启动服务端；请先修复设置页中的错误");
            return;
        }
        // Persist before serving. The UI can start a server from settings that
        // were never written to disk; a later `remote-terminal serve` would
        // then read an empty config and reject every login.
        let config_path = self.paths.config_file.clone();
        if let Err(err) = self.config.save_with_header(&config_path) {
            self.toasts
                .error(format!("无法保存配置，服务端未启动：{err}"));
            return;
        }
        let options = rt_server::ServerOptions {
            config: self.config.clone(),
            paths: self.paths.clone(),
            sink: self.sink.clone(),
            audit: self.audit.clone(),
        };
        let state = match rt_server::AppState::new(options) {
            Ok(state) => state,
            Err(err) => {
                self.toasts.error(format!("无法初始化服务端：{err}"));
                return;
            }
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let tx = self.server_tx.clone();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            match rt_server::serve(state, shutdown_rx).await {
                Ok(handle) => {
                    let _ = tx.send(ServerEvent::Started(Box::new(EmbeddedServer {
                        handle,
                        since: Instant::now(),
                        _shutdown: shutdown_tx,
                    })));
                }
                Err(err) => {
                    let _ = tx.send(ServerEvent::Failed(format!("{err:#}")));
                }
            }
            ctx.request_repaint();
        });
        self.set_status("正在启动服务端…");
    }

    /// Stops the embedded server.
    pub fn stop_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.handle.stop();
            self.set_status("服务端已停止");
            self.toasts.info("服务端已停止");
        }
    }

    /// Drains background server events.
    fn poll_server(&mut self) {
        while let Ok(event) = self.server_rx.try_recv() {
            match event {
                ServerEvent::Started(server) => {
                    let url = server.handle.url.clone();
                    self.server = Some(*server);
                    self.set_status(format!("服务端已启动：{url}"));
                    self.toasts.success(format!("服务端已启动：{url}"));
                }
                ServerEvent::Failed(message) => {
                    self.last_error = Some(message.clone());
                    self.toasts.error(format!("服务端启动失败：{message}"));
                }
            }
        }
    }

    // -- page plumbing ------------------------------------------------------

    /// Runs `f` with temporary ownership of the dashboard state.
    ///
    /// Pages need `&mut` access to their own state *and* to the shared app
    /// (toasts, config, client). Taking the state out of the struct sidesteps
    /// the aliasing rules without any interior mutability.
    pub fn with_dashboard<R>(&mut self, f: impl FnOnce(&mut pages::dashboard::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.dashboard);
        let out = f(&mut state, self);
        self.dashboard = state;
        out
    }

    /// Same as [`App::with_dashboard`] for the 命令 page.
    pub fn with_exec<R>(&mut self, f: impl FnOnce(&mut pages::exec::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.exec);
        let out = f(&mut state, self);
        self.exec = state;
        out
    }

    /// Same as [`App::with_dashboard`] for the 文件 page.
    pub fn with_files<R>(&mut self, f: impl FnOnce(&mut pages::files::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.files);
        let out = f(&mut state, self);
        self.files = state;
        out
    }

    /// Same as [`App::with_dashboard`] for the 屏幕 page.
    pub fn with_screen<R>(&mut self, f: impl FnOnce(&mut pages::screen::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.screen);
        let out = f(&mut state, self);
        self.screen = state;
        out
    }

    /// Same as [`App::with_dashboard`] for the 设置 page.
    pub fn with_settings<R>(&mut self, f: impl FnOnce(&mut pages::settings::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.settings);
        let out = f(&mut state, self);
        self.settings = state;
        out
    }

    /// Same as [`App::with_dashboard`] for the 日志 page.
    pub fn with_logs<R>(&mut self, f: impl FnOnce(&mut pages::logs::State, &mut App) -> R) -> R {
        let mut state = std::mem::take(&mut self.logs);
        let out = f(&mut state, self);
        self.logs = state;
        out
    }

    /// Drains every page's background results before drawing.
    ///
    /// Background hosts are polled too: their exec streams and capture workers
    /// must keep draining while the user looks at a different machine. Page
    /// state is swapped in and out around each host (cheap moves, no clones).
    fn poll_pages(&mut self) {
        let active = self.active;
        for index in 0..self.hosts.len() {
            if Some(index) != self.resident {
                self.load_pages(index);
            }
            self.with_dashboard(|state, app| state.poll(app));
            self.with_exec(|state, app| state.poll(app));
            self.with_files(|state, app| state.poll(app));
            self.with_screen(|state, app| state.poll(app));
        }
        if Some(active) != self.resident {
            self.load_pages(active);
        }
        // Process-wide pages.
        self.with_settings(|state, app| state.poll(app));
        self.with_logs(|state, app| state.poll(app));
    }

    // -- theme --------------------------------------------------------------

    /// Rebuilds the egui style when the theme inputs changed.
    fn sync_theme(&mut self) {
        let key = (self.config.app.theme, self.config.app.accent.clone(), self.reduce_motion);
        if self.applied.as_ref() != Some(&key) {
            theme::apply(&self.ctx, key.0, &key.1, self.reduce_motion);
            theme::set_reduce_motion(&self.ctx, self.reduce_motion);
            self.applied = Some(key);
        }
    }

    // -- chrome -------------------------------------------------------------

    /// Top bar: page title on the left, connection chip on the right.
    fn top_bar(&mut self, root: &mut egui::Ui) {
        let p = palette(root.ctx());
        egui::Panel::top("rt.topbar")
            .exact_size(52.0)
            .resizable(false)
            .frame(
                Frame::default()
                    .fill(p.surface)
                    .inner_margin(Margin::symmetric(Space::LG as i8, Space::SM as i8)),
            )
            .show(root, |ui| {
                // 1 px hairline along the bottom edge of the bar.
                let rect = ui.max_rect();
                ui.painter().line_segment(
                    [
                        egui::Pos2::new(rect.left(), rect.bottom()),
                        egui::Pos2::new(rect.right(), rect.bottom()),
                    ],
                    Stroke::new(1.0, p.hairline),
                );
                ui.horizontal_centered(|ui| {
                    ui.label(
                        RichText::new(self.page.title())
                            .size(Type::TITLE)
                            .strong()
                            .color(p.text),
                    );
                    ui.add_space(Space::SM);
                    ui.label(
                        RichText::new(self.page.hint())
                            .size(Type::CAPTION)
                            .color(p.text_muted),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        self.connection_chip(ui);
                    });
                });
            });
    }

    /// The connection chip: status dot, address, scope badge, connect button.
    fn connection_chip(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        let slot = self.active_slot();
        let host_label = slot.map(|slot| slot.label.clone()).unwrap_or_default();
        let (dot, label, detail, tone, online) = match slot.map(|slot| &slot.conn) {
            Some(Conn::Connecting { label, started }) => (
                p.warning,
                format!("连接中 {label}"),
                format!("{:.0}s", started.elapsed().as_secs_f32()),
                Tone::Warning,
                false,
            ),
            Some(Conn::Online(connected)) => (
                p.success,
                connected.address.clone(),
                rt_core::util::format_uptime(connected.since.elapsed().as_secs()),
                Tone::Success,
                true,
            ),
            _ => (p.text_faint, "未连接".to_string(), String::new(), Tone::Neutral, false),
        };
        // Show which host the chip refers to when several are in play.
        let multi = self.hosts.len() > 1;
        let busy = slot.map(|slot| slot.busy()).unwrap_or(false);

        Frame::default()
            .fill(p.raised)
            .stroke(Stroke::new(1.0, p.hairline_strong))
            .corner_radius(Radius::MD)
            .inner_margin(Margin::symmetric(Space::MD as i8, Space::XS as i8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    widgets::status_dot(ui, dot, online);
                    if multi && !online {
                        ui.label(
                            RichText::new(&host_label)
                                .size(Type::CAPTION)
                                .color(p.text_muted),
                        );
                    }
                    ui.label(RichText::new(&label).size(Type::CAPTION).color(p.text).monospace());
                    if !detail.is_empty() {
                        ui.label(RichText::new(detail).size(Type::CAPTION).color(p.text_muted));
                    }
                    if let Some(scope) = self.scope() {
                        widgets::badge(
                            ui,
                            if scope.is_full() { "完全访问" } else { "工作区" },
                            if scope.is_full() { Tone::Danger } else { Tone::Warning },
                        );
                    }
                    let _ = tone;
                    if online {
                        if widgets::button(
                            ui,
                            Btn::new("top.disconnect", "断开", "关闭连接并停止所有后台请求").small().ghost(),
                        )
                        .clicked()
                        {
                            self.disconnect();
                        }
                    } else {
                        if widgets::button(
                            ui,
                            Btn::new("top.connect", "连接", "使用总览页中的凭据连接服务器")
                                .small()
                                .primary()
                                .enabled(!busy),
                        )
                        .clicked()
                        {
                            self.set_page(Page::Dashboard);
                        }
                    }
                });
            });
    }

    /// Left navigation rail.
    fn sidebar(&mut self, root: &mut egui::Ui) {
        let target = if self.sidebar_collapsed { 68.0 } else { 240.0 };
        let width = theme::spring_value(root.ctx(), egui::Id::unique("rt.nav.width"), target);
        let p = palette(root.ctx());
        egui::Panel::left("rt.nav")
            .exact_size(width)
            .resizable(false)
            .frame(
                Frame::default()
                    .fill(p.surface)
                    .inner_margin(Margin::symmetric(Space::MD as i8, Space::MD as i8)),
            )
            .show(root, |ui| {
                self.sidebar_header(ui);
                ui.add_space(Space::MD);
                let mut target = None;
                for page in Page::ALL {
                    if self.nav_item(ui, page) {
                        target = Some(page);
                    }
                }
                if let Some(page) = target {
                    // Applied after the loop so the borrow of `self` ends first.
                    self.set_page(page);
                }
                self.host_list(ui);
                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    self.sidebar_footer(ui);
                });
            });
    }

    /// Product mark plus the collapse toggle.
    fn sidebar_header(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
            ui.painter().rect_filled(rect, Radius::SM, p.accent);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "RT",
                egui::FontId::proportional(13.0),
                p.on_accent,
            );
            if !self.sidebar_collapsed {
                ui.add_space(Space::SM);
                ui.label(
                    RichText::new(crate::DISPLAY_NAME)
                        .size(Type::BODY)
                        .strong()
                        .color(p.text),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let glyph = if self.sidebar_collapsed { "»" } else { "«" };
                if widgets::button(
                    ui,
                    Btn::new("nav.collapse", glyph, "折叠或展开侧边栏").small().ghost(),
                )
                .clicked()
                {
                    self.sidebar_collapsed = !self.sidebar_collapsed;
                }
            });
        });
    }

    /// One navigation row; returns true when clicked.
    fn nav_item(&mut self, ui: &mut egui::Ui, page: Page) -> bool {
        let p = palette(ui.ctx());
        let active = self.page == page;
        let width = ui.available_width();
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 38.0), Sense::click());
        let response = response.on_hover_text(format!("{}{}", page.title(), page.shortcut()));
        if response.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        let hover = theme::spring_bool(
            ui.ctx(),
            egui::Id::unique(("nav.hover", page.title())),
            response.hovered(),
            theme::RESPONSE_FAST,
        );
        let selected = theme::spring_bool(
            ui.ctx(),
            egui::Id::unique(("nav.selected", page.title())),
            active,
            theme::RESPONSE_DEFAULT,
        );

        let painter = ui.painter();
        let fill = theme::mix(Color32::TRANSPARENT, p.raised, hover * 0.85);
        let fill = theme::mix(fill, theme::wash(p.accent, if p.dark { 0x2A } else { 0x18 }), selected);
        painter.rect_filled(rect, Radius::MD, fill);
        if selected > 0.01 {
            // Accent bar grows in from the left as the page becomes active.
            let bar = egui::Rect::from_min_size(
                rect.min + Vec2::new(0.0, 9.0),
                Vec2::new(3.0 * selected, rect.height() - 18.0),
            );
            painter.rect_filled(bar, Radius::SM, theme::fade(p.accent, selected));
        }

        let color = theme::mix(p.text_muted, p.text, selected.max(hover));
        if self.sidebar_collapsed {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                page.icon(),
                egui::FontId::proportional(Type::HEADING),
                theme::mix(color, p.accent, selected),
            );
        } else {
            painter.text(
                rect.left_center() + Vec2::new(Space::MD, 0.0),
                egui::Align2::LEFT_CENTER,
                page.icon(),
                egui::FontId::proportional(Type::BODY),
                theme::mix(color, p.accent, selected),
            );
            painter.text(
                rect.left_center() + Vec2::new(Space::MD + 22.0, 0.0),
                egui::Align2::LEFT_CENTER,
                page.title(),
                egui::FontId::proportional(Type::BODY),
                color,
            );
            painter.text(
                rect.right_center() - Vec2::new(Space::MD, 0.0),
                egui::Align2::RIGHT_CENTER,
                page.shortcut(),
                egui::FontId::proportional(Type::CAPTION),
                theme::mix(p.text_faint, p.text_muted, hover),
            );
        }
        response.clicked()
    }

    /// Host list under the navigation: switch, connect and forget hosts.
    fn host_list(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        let collapsed = self.sidebar_collapsed;
        ui.add_space(Space::MD);
        widgets::divider(ui);
        ui.add_space(Space::SM);

        let mut add = false;
        if collapsed {
            if widgets::button(ui, Btn::new("hosts.add", "＋", "添加一台新主机").small().ghost())
                .clicked()
            {
                add = true;
            }
        } else {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("主机")
                        .size(Type::CAPTION)
                        .strong()
                        .color(p.text_muted),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::button(
                        ui,
                        Btn::new("hosts.add", "＋", "添加一台新主机").small().ghost(),
                    )
                    .clicked()
                    {
                        add = true;
                    }
                    ui.label(
                        RichText::new(format!("{}/{}", self.live_hosts(), MAX_HOSTS))
                            .size(11.0)
                            .color(p.text_faint),
                    )
                    .on_hover_text("已连接 / 最多同时连接的主机数");
                });
            });
        }
        if add {
            self.host_form = Some(HostForm::default());
        }
        ui.add_space(Space::XS);

        // Snapshot first: the drawing loop must not hold a borrow of `self`.
        let rows: Vec<HostRow> = self
            .hosts
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let (state, _) = slot.state_label();
                HostRow {
                    index,
                    label: slot.label.clone(),
                    address: slot.address(),
                    state,
                    active: index == self.active,
                    error: slot.error.clone(),
                    busy: slot.busy(),
                }
            })
            .collect();

        let mut action: Option<HostAction> = None;
        // Rows scroll inside the rail so eight hosts stay reachable.
        let max_height = (ui.available_height() - 90.0).max(120.0);
        egui::ScrollArea::vertical()
            .id_salt("rt.hosts")
            .max_height(max_height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for row in rows {
                    let height = if collapsed { 28.0 } else { 40.0 };
                    let (rect, response) =
                        ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());
                    if response.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }

                    let hover = theme::spring_bool(
                        ui.ctx(),
                        egui::Id::unique(("host.hover", row.index)),
                        response.hovered(),
                        theme::RESPONSE_FAST,
                    );
                    let selected = theme::spring_bool(
                        ui.ctx(),
                        egui::Id::unique(("host.selected", row.index)),
                        row.active,
                        theme::RESPONSE_DEFAULT,
                    );
                    let painter = ui.painter();
                    let fill = theme::mix(Color32::TRANSPARENT, p.raised, hover * 0.8);
                    let fill = theme::mix(
                        fill,
                        theme::wash(p.accent, if p.dark { 0x2A } else { 0x18 }),
                        selected,
                    );
                    painter.rect_filled(rect, Radius::MD, fill);
                    if selected > 0.01 {
                        let bar = egui::Rect::from_min_size(
                            rect.min + Vec2::new(0.0, 7.0),
                            Vec2::new(3.0 * selected, rect.height() - 14.0),
                        );
                        painter.rect_filled(bar, Radius::SM, theme::fade(p.accent, selected));
                    }

                    // Status dot, with a slow halo while a handshake is running.
                    let dot_color = p.tone(row.state.tone());
                    let dot_center = egui::Pos2::new(rect.left() + Space::SM + 5.0, rect.center().y);
                    painter.circle_filled(dot_center, 3.5, dot_color);
                    if row.state == HostState::Connecting {
                        let phase = (ui.ctx().input(|i| i.time) as f32 * 1.6).sin() * 0.5 + 0.5;
                        painter.circle_stroke(
                            dot_center,
                            5.0 + phase * 3.0,
                            egui::Stroke::new(1.0, theme::fade(dot_color, 0.5 * (1.0 - phase))),
                        );
                    }

                    if response.clicked() {
                        action = Some(HostAction::Switch(row.index));
                    }

                    if collapsed {
                        // Compact rail: the dot doubles as the switch.
                        let _ = response.clone().on_hover_text(format!(
                            "{} · {} — 点击切换到此主机",
                            row.label, row.address
                        ));
                    } else {
                        let text_color = theme::mix(p.text_muted, p.text, selected.max(hover));
                        let line = egui::Pos2::new(rect.left() + Space::SM + 16.0, rect.center().y);
                        painter.text(
                            line + Vec2::new(0.0, -7.0),
                            egui::Align2::LEFT_CENTER,
                            &row.label,
                            egui::FontId::proportional(Type::CAPTION),
                            text_color,
                        );
                        painter.text(
                            line + Vec2::new(0.0, 8.0),
                            egui::Align2::LEFT_CENTER,
                            &row.address,
                            egui::FontId::proportional(10.5),
                            p.text_faint,
                        );

                        // Per-row 连接 / 断开 button on the right.
                        let btn_rect = egui::Rect::from_min_size(
                            egui::Pos2::new(rect.right() - Space::SM - 40.0, rect.center().y - 10.0),
                            Vec2::new(40.0, 20.0),
                        );
                        let btn = ui.interact(
                            btn_rect,
                            egui::Id::unique(("host.toggle", row.index)),
                            Sense::click(),
                        );
                        let btn_hover = theme::spring_bool(
                            ui.ctx(),
                            egui::Id::unique(("host.toggle.hover", row.index)),
                            btn.hovered(),
                            theme::RESPONSE_FAST,
                        );
                        ui.painter().rect_filled(
                            btn_rect,
                            Radius::SM,
                            theme::mix(Color32::TRANSPARENT, p.raised, btn_hover),
                        );
                        let (btn_text, btn_tip) = if row.busy {
                            ("断开", "断开这台主机，其它主机不受影响")
                        } else {
                            ("连接", "连接或重连这台主机")
                        };
                        ui.painter().text(
                            btn_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            btn_text,
                            egui::FontId::proportional(11.0),
                            theme::mix(p.text_muted, p.text, btn_hover),
                        );
                        let btn = btn.on_hover_text(btn_tip);
                        if btn.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        // Checked after the row click so the button wins the frame.
                        if btn.clicked() {
                            action = Some(if row.busy {
                                HostAction::Disconnect(row.index)
                            } else {
                                HostAction::Connect(row.index)
                            });
                        }
                    }

                    let mut tip = format!("{} · {}", row.label, row.address);
                    if let Some(error) = &row.error {
                        tip.push_str("\n");
                        tip.push_str(error);
                    }
                    tip.push_str("\n点击切换到此主机，右键查看更多操作");
                    let index = row.index;
                    let _ = response.on_hover_text(tip).context_menu(|ui| {
                        if ui.button("探测可达性").clicked() {
                            action = Some(HostAction::Probe(index));
                            ui.close();
                        }
                        if ui.button("移除这台主机").clicked() {
                            action = Some(HostAction::Remove(index));
                            ui.close();
                        }
                    });
                }
            });
        match action {
            Some(HostAction::Switch(index)) => self.activate(index),
            Some(HostAction::Connect(index)) => self.reconnect_slot(index),
            Some(HostAction::Disconnect(index)) => self.disconnect_slot(index),
            Some(HostAction::Probe(index)) => self.probe_slot(index),
            Some(HostAction::Remove(index)) => self.remove_host(index),
            None => {}
        }
    }

    /// The 「添加主机」 modal.
    fn host_modal(&mut self, ctx: &egui::Context) {
        let Some(mut form) = self.host_form.take() else {
            return;
        };
        let p = palette(ctx);
        let mut keep = true;
        let mut submit = false;

        let modal = egui::Modal::new(egui::Id::unique("rt.host.form"))
            .frame(
                Frame::default()
                    .fill(p.surface)
                    .stroke(egui::Stroke::new(1.0, p.hairline))
                    .corner_radius(Radius::LG)
                    .inner_margin(Margin::same(Space::LG as i8))
                    .shadow(theme::card_shadow(p.dark)),
            )
            .show(ctx, |ui| {
                ui.set_width(460.0);
                ui.label(
                    RichText::new("添加主机")
                        .size(Type::TITLE)
                        .strong()
                        .color(p.text),
                );
                widgets::caption(ui, "凭据只保存在本次运行的内存里，不会写进配置文件。");
                ui.add_space(Space::MD);

                egui::Grid::new("rt.host.form.grid")
                    .num_columns(2)
                    .spacing([Space::MD, Space::SM])
                    .show(ui, |ui| {
                        ui.label(RichText::new("名称").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("可留空，默认用 host:port");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.label)
                                .hint_text("办公室主机")
                                .desired_width(250.0),
                        );
                        ui.end_row();

                        ui.label(RichText::new("主机").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("主机名或 IP");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.host)
                                .hint_text("192.168.1.20")
                                .desired_width(250.0),
                        );
                        ui.end_row();

                        ui.label(RichText::new("端口").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("默认 46666");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.port)
                                .hint_text("46666")
                                .desired_width(110.0),
                        );
                        ui.end_row();

                        ui.label(RichText::new("TLS").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("服务端启用 TLS 时必须开启");
                        widgets::toggle_switch(
                            ui,
                            "rt.host.form.tls",
                            &mut form.tls,
                            "使用 TLS 加密连接",
                        );
                        ui.end_row();

                        ui.label(RichText::new("用户名").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("密码登录使用的用户名");
                        ui.add_enabled(
                            !form.use_api_key,
                            egui::TextEdit::singleline(&mut form.username)
                                .hint_text("admin")
                                .desired_width(250.0),
                        );
                        ui.end_row();

                        ui.label(RichText::new("密码").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("只保存在内存中，不会写盘");
                        ui.add_enabled(
                            !form.use_api_key,
                            egui::TextEdit::singleline(&mut form.password)
                                .password(true)
                                .hint_text("至少 8 位")
                                .desired_width(250.0),
                        );
                        ui.end_row();

                        ui.label(RichText::new("用 API 密钥").size(Type::CAPTION).color(p.text_muted))
                            .on_hover_text("不用密码，直接用服务端签发的密钥登录");
                        widgets::toggle_switch(
                            ui,
                            "rt.host.form.apikey",
                            &mut form.use_api_key,
                            "改用 API 密钥登录",
                        );
                        ui.end_row();

                        if form.use_api_key {
                            ui.label(
                                RichText::new("API 密钥")
                                    .size(Type::CAPTION)
                                    .color(p.text_muted),
                            )
                            .on_hover_text("以 rt_ 开头的密钥");
                            ui.add(
                                egui::TextEdit::singleline(&mut form.api_key)
                                    .hint_text("rt_…")
                                    .desired_width(250.0),
                            );
                            ui.end_row();
                        }

                        ui.label(
                            RichText::new("证书指纹")
                                .size(Type::CAPTION)
                                .color(p.text_muted),
                        )
                        .on_hover_text("留空则在首次连接时询问并记住");
                        ui.add(
                            egui::TextEdit::singleline(&mut form.pin)
                                .hint_text("AB:CD:…（可留空）")
                                .desired_width(250.0),
                        );
                        ui.end_row();

                        ui.label(
                            RichText::new("记住主机")
                                .size(Type::CAPTION)
                                .color(p.text_muted),
                        )
                        .on_hover_text("连接成功后写回配置文件");
                        widgets::toggle_switch(
                            ui,
                            "rt.host.form.persist",
                            &mut form.persist,
                            "连接成功后把主机写回配置文件",
                        );
                        ui.end_row();
                    });

                if let Some(error) = &form.error {
                    ui.add_space(Space::SM);
                    widgets::error_banner(ui, error);
                }

                ui.add_space(Space::MD);
                ui.horizontal(|ui| {
                    if widgets::button(
                        ui,
                        Btn::new("rt.host.form.ok", "添加并连接", "创建这台主机并立即连接")
                            .primary(),
                    )
                    .clicked()
                    {
                        submit = true;
                    }
                    if widgets::button(
                        ui,
                        Btn::new("rt.host.form.cancel", "取消", "关闭窗口，不添加主机").ghost(),
                    )
                    .clicked()
                    {
                        keep = false;
                    }
                });
            });

        if modal.should_close() {
            keep = false;
        }
        if submit {
            match self.create_host(&form) {
                Ok(()) => keep = false,
                Err(err) => {
                    form.error = Some(err);
                    keep = true;
                }
            }
        }
        if keep {
            self.host_form = Some(form);
        }
    }

    /// Validates the add-host form, creates a slot and starts connecting.
    fn create_host(&mut self, form: &HostForm) -> Result<(), String> {
        let host = form.host.trim().to_string();
        if host.is_empty() {
            return Err("请输入主机名或 IP".to_string());
        }
        let port: u16 = match form.port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => return Err("端口必须是 1-65535 之间的整数".to_string()),
        };
        let api_key = form.api_key.trim().to_string();
        if form.use_api_key && api_key.is_empty() {
            return Err("请输入 API 密钥".to_string());
        }
        let username = form.username.trim().to_string();
        if !form.use_api_key && username.is_empty() {
            return Err("请输入用户名".to_string());
        }
        if !form.use_api_key && form.password.is_empty() {
            return Err("请输入密码".to_string());
        }
        if self.live_hosts() >= MAX_HOSTS {
            return Err(format!("最多同时连接 {MAX_HOSTS} 台主机，请先断开一台"));
        }

        let label = match form.label.trim() {
            "" => format!("{host}:{port}"),
            name => name.to_string(),
        };
        let index = self.push_slot(None);
        self.activate(index);
        if let Some(slot) = self.hosts.get_mut(index) {
            slot.label = label;
            slot.persist = form.persist;
            slot.target = Target::new(host.clone(), port);
            slot.target.tls = form.tls;
        }

        // Mirror the form into the now-resident dashboard page.
        self.dashboard.host = host.clone();
        self.dashboard.port = port.to_string();
        self.dashboard.username = username.clone();
        self.dashboard.password = form.password.clone();
        self.dashboard.use_api_key = form.use_api_key;
        self.dashboard.api_key = api_key.clone();
        self.dashboard.tls = form.tls;
        self.dashboard.pin = form.pin.clone();
        self.dashboard.form_error = None;

        let request = ConnectRequest {
            host,
            port,
            tls: form.tls,
            username,
            password: form.password.clone(),
            api_key: form.use_api_key.then_some(api_key),
            pin: clean_fingerprint(&form.pin),
            accept_new: false,
            timeout_secs: self.config.client.request_timeout_secs,
        };
        self.connect_slot(index, request);
        self.set_page(Page::Dashboard);
        Ok(())
    }
    /// Theme switcher and version footer.
    fn sidebar_footer(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        ui.add_space(Space::SM);
        if self.sidebar_collapsed {
            if widgets::button(
                ui,
                Btn::new("nav.theme", "◐", "切换浅色 / 深色主题").small().ghost(),
            )
            .clicked()
            {
                self.cycle_theme();
            }
        } else {
            ui.horizontal(|ui| {
                let label = match self.config.app.theme {
                    ConfigTheme::System => "跟随系统",
                    ConfigTheme::Light => "浅色",
                    ConfigTheme::Dark => "深色",
                };
                if widgets::button(
                    ui,
                    Btn::new("nav.theme", label, "在 跟随系统 / 浅色 / 深色 之间切换").small().ghost(),
                )
                .clicked()
                {
                    self.cycle_theme();
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("v{}", rt_protocol::APP_VERSION))
                            .size(Type::CAPTION)
                            .color(p.text_faint),
                    );
                });
            });
        }
        widgets::divider(ui);
    }

    /// Cycles the app theme and repaints with the new palette.
    fn cycle_theme(&mut self) {
        self.config.app.theme = match self.config.app.theme {
            ConfigTheme::System => ConfigTheme::Light,
            ConfigTheme::Light => ConfigTheme::Dark,
            ConfigTheme::Dark => ConfigTheme::System,
        };
        self.applied = None;
    }

    /// Bottom status line: connection, load, version.
    fn status_bar(&mut self, root: &mut egui::Ui) {
        let p = palette(root.ctx());
        egui::Panel::bottom("rt.status")
            .exact_size(26.0)
            .resizable(false)
            .frame(
                Frame::default()
                    .fill(p.surface)
                    .inner_margin(Margin::symmetric(Space::LG as i8, 2)),
            )
            .show(root, |ui| {
                let rect = ui.max_rect();
                ui.painter().line_segment(
                    [
                        egui::Pos2::new(rect.left(), rect.top()),
                        egui::Pos2::new(rect.right(), rect.top()),
                    ],
                    Stroke::new(1.0, p.hairline),
                );
                ui.horizontal_centered(|ui| {
                    let (dot, text) = match self.active_slot().map(|slot| &slot.conn) {
                        Some(Conn::Connecting { label, .. }) => {
                            (p.warning, format!("正在连接 {label}…"))
                        }
                        Some(Conn::Online(connected)) => {
                            let uptime = rt_core::util::format_uptime(connected.since.elapsed().as_secs());
                            (
                                p.success,
                                format!(
                                    "{}  ·  {}  ·  已连接 {}",
                                    connected.address,
                                    connected.session.username,
                                    uptime
                                ),
                            )
                        }
                        _ => (p.text_faint, "未连接".to_string()),
                    };
                    widgets::status_dot(ui, dot, self.is_online());
                    ui.label(RichText::new(text).size(Type::CAPTION).color(p.text_muted));

                    if let Some(pulse) = &self.pulse {
                        ui.add_space(Space::LG);
                        let cpu = pulse.cpu_usage_percent;
                        let mem_ratio = if pulse.memory_total_bytes > 0 {
                            pulse.memory_used_bytes as f32 / pulse.memory_total_bytes as f32
                        } else {
                            0.0
                        };
                        ui.label(
                            RichText::new(format!(
                                "CPU {cpu:.0}%  ·  内存 {:.0}%  ·  进程 {}",
                                mem_ratio * 100.0,
                                pulse.process_count
                            ))
                            .size(Type::CAPTION)
                            .color(p.text_faint),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some((message, at)) = &self.status {
                            if at.elapsed().as_secs_f32() < 8.0 {
                                ui.label(
                                    RichText::new(message)
                                        .size(Type::CAPTION)
                                        .color(p.text_muted),
                                );
                                ui.ctx().request_repaint_after(Duration::from_millis(500));
                            } else {
                                self.status = None;
                            }
                        } else if let Some(err) = &self.last_error {
                            ui.label(
                                RichText::new(err)
                                    .size(Type::CAPTION)
                                    .color(p.danger),
                            );
                        }
                        if self.server.is_some() {
                            ui.label(
                                RichText::new("服务端运行中")
                                    .size(Type::CAPTION)
                                    .color(p.success),
                            );
                        }
                    });
                });
            });
    }

    /// Switches the visible page, stopping page-scoped background work.
    ///
    /// The screen page owns a WebSocket capture stream that must not outlive
    /// its view, so leaving it shuts the stream down explicitly.
    pub fn set_page(&mut self, page: Page) {
        if self.page != page {
            if self.page == Page::Screen {
                self.screen.suspend_live();
            }
            self.page = page;
        }
    }

    /// Global keyboard shortcuts (page switching and refresh).
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let mut target = None;
        ctx.input_mut(|input| {
            let keys = [
                (Key::Num1, Page::Dashboard),
                (Key::Num2, Page::Exec),
                (Key::Num3, Page::Files),
                (Key::Num4, Page::Screen),
                (Key::Num5, Page::Settings),
                (Key::Num6, Page::Logs),
            ];
            for (key, page) in keys {
                if input.consume_key(Modifiers::CTRL, key) {
                    target = Some(page);
                }
            }
            if input.consume_key(Modifiers::CTRL, Key::R) {
                self.refresh_requested = true;
            }
        });
        if let Some(page) = target {
            self.set_page(page);
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // 1. Drain background results before drawing so the frame is consistent.
        self.poll_connection();
        self.poll_server();
        self.poll_pulse();
        self.poll_pages();
        self.sync_theme();

        // 2. Global shortcuts.
        self.handle_shortcuts(&ctx);

        // 3. Chrome. Panels are outermost-first: top, left, bottom, then centre.
        self.top_bar(ui);
        self.sidebar(ui);
        self.status_bar(ui);

        // 4. Page content fills whatever is left.
        let p = palette(&ctx);
        egui::CentralPanel::default()
            .frame(Frame::default().fill(p.bg).inner_margin(Margin::same(Space::XL as i8)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("rt.page", self.page.title()))
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        Page::Dashboard => pages::dashboard::ui(self, ui),
                        Page::Exec => pages::exec::ui(self, ui),
                        Page::Files => pages::files::ui(self, ui),
                        Page::Screen => pages::screen::ui(self, ui),
                        Page::Settings => pages::settings::ui(self, ui),
                        Page::Logs => pages::logs::ui(self, ui),
                    });
            });

        // 5. Overlays last so they sit above everything.
        self.toasts.show(&ctx);
        self.host_modal(&ctx);
        pages::dashboard::dialogs(self, &ctx);
        pages::exec::dialogs(self, &ctx);
        pages::files::dialogs(self, &ctx);
        pages::screen::dialogs(self, &ctx);
        pages::settings::dialogs(self, &ctx);

        // Refresh politely while something is animating or streaming.
        if self
            .hosts
            .iter()
            .any(|slot| matches!(slot.conn, Conn::Connecting { .. }))
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        self.refresh_requested = false;
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if !self.config.app.remember_window {
            return;
        }
        // Stored as a plain pair so it survives config edits.
        let size = self.ctx.input(|i| i.viewport().inner_rect.map(|r| [r.width(), r.height()]));
        if let Some(size) = size {
            eframe::set_value(storage, KEY_WINDOW, &size);
        }
    }
}

/// Convenience alias used by pages for the shared palette type.
pub type UiPalette = Palette;
