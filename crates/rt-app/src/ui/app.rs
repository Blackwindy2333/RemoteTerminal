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

    /// Connection state.
    pub conn: Conn,
    conn_tx: mpsc::Sender<ConnEvent>,
    conn_rx: mpsc::Receiver<ConnEvent>,

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

    /// Per-page state.
    pub dashboard: pages::dashboard::State,
    pub exec: pages::exec::State,
    pub files: pages::files::State,
    pub screen: pages::screen::State,
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
            conn: Conn::Offline,
            conn_tx,
            conn_rx,
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
        app.dashboard.seed_from_config(&app.config);
        app.exec.seed_from_config(&app.config);
        app.files.seed_from_config(&app.config);
        app.screen.seed_from_config(&app.config);
        app.settings.seed_from_config(&app.config, &app.paths);
        app.logs.seed_from_config(&app.config);
        app
    }

    // -- accessors ----------------------------------------------------------

    /// Authenticated client for the current connection, if any.
    pub fn client(&self) -> Option<RemoteClient> {
        match &self.conn {
            Conn::Online(connected) => Some(connected.client.clone()),
            _ => None,
        }
    }

    /// Connected state, if any.
    pub fn connected(&self) -> Option<&Connected> {
        match &self.conn {
            Conn::Online(connected) => Some(connected),
            _ => None,
        }
    }

    /// Whether a server is currently attached.
    pub fn is_online(&self) -> bool {
        matches!(self.conn, Conn::Online(_))
    }

    /// Scope granted by the server, if connected.
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

    // -- connection ---------------------------------------------------------

    /// Starts a connect attempt in the background.
    pub fn connect(&mut self, request: ConnectRequest) {
        self.conn = Conn::Connecting {
            label: format!("{}:{}", request.host, request.port),
            started: Instant::now(),
        };
        self.last_error = None;
        let tx = self.conn_tx.clone();
        let ctx = self.ctx.clone();
        let require_pin = self.config.client.require_pinned_fingerprint;
        self.runtime.spawn(async move {
            let event = perform_connect(request, require_pin).await;
            let _ = tx.send(event);
            ctx.request_repaint();
        });
    }

    /// Drops the current connection.
    pub fn disconnect(&mut self) {
        self.conn = Conn::Offline;
        self.pulse = None;
        self.files.reset_after_disconnect();
        self.exec.close_ws();
        self.screen.reset_after_disconnect();
        self.set_status("已断开连接");
    }

    /// Applies the outcome of a background connect attempt.
    fn poll_connection(&mut self) {
        while let Ok(event) = self.conn_rx.try_recv() {
            match event {
                ConnEvent::Online(connected) => {
                    let address = connected.address.clone();
                    let scope = connected.session.scope;
                    self.record_host(&address, scope);
                    self.conn = Conn::Online(connected);
                    self.pulse_next = Instant::now();
                    self.dashboard.on_connected(&address);
                    self.set_status(format!("已连接到 {address}"));
                }
                ConnEvent::Failed(message) => {
                    self.conn = Conn::Offline;
                    self.last_error = Some(message.clone());
                    self.toasts.error(message);
                }
                ConnEvent::TrustRequired {
                    request,
                    info,
                    fingerprint,
                } => {
                    self.conn = Conn::Offline;
                    self.dashboard.pending_trust = Some(pages::dashboard::TrustPrompt {
                        request: *request,
                        info,
                        fingerprint,
                    });
                }
            }
        }
    }

    /// Remembers `username`/`last_connected`/fingerprint for the host list.
    fn record_host(&mut self, address: &str, scope: Scope) {
        let Some((host, port)) = address.rsplit_once(':') else {
            return;
        };
        let Ok(port) = port.parse::<u16>() else {
            return;
        };
        // Collect everything we need from `self` before mutably borrowing config.
        let username = self.dashboard.username.clone();
        let fingerprint = self
            .connected()
            .and_then(|c| c.fingerprint.as_ref().map(|f| rt_core::crypto::format_fingerprint(f)));
        let entry = self.config.host_entry_mut(host, port);
        entry.last_connected = Some(rt_core::util::now_rfc3339());
        entry.last_scope = Some(scope.as_str().to_string());
        if entry.username.is_empty() {
            entry.username = username;
        }
        if entry.fingerprint.is_none() {
            entry.fingerprint = fingerprint;
        }
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
    fn poll_pages(&mut self) {
        self.with_dashboard(|state, app| state.poll(app));
        self.with_exec(|state, app| state.poll(app));
        self.with_files(|state, app| state.poll(app));
        self.with_screen(|state, app| state.poll(app));
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
        let (dot, label, detail, tone, online) = match &self.conn {
            Conn::Offline => (p.text_faint, "未连接".to_string(), String::new(), Tone::Neutral, false),
            Conn::Connecting { label, started } => (
                p.warning,
                format!("连接中 {label}"),
                format!("{:.0}s", started.elapsed().as_secs_f32()),
                Tone::Warning,
                false,
            ),
            Conn::Online(connected) => (
                p.success,
                connected.address.clone(),
                rt_core::util::format_uptime(connected.since.elapsed().as_secs()),
                Tone::Success,
                true,
            ),
        };

        Frame::default()
            .fill(p.raised)
            .stroke(Stroke::new(1.0, p.hairline_strong))
            .corner_radius(Radius::MD)
            .inner_margin(Margin::symmetric(Space::MD as i8, Space::XS as i8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    widgets::status_dot(ui, dot, online);
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
                        let busy = matches!(self.conn, Conn::Connecting { .. });
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
                    let (dot, text) = match &self.conn {
                        Conn::Offline => (p.text_faint, "未连接".to_string()),
                        Conn::Connecting { label, .. } => (p.warning, format!("正在连接 {label}…")),
                        Conn::Online(connected) => {
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
        pages::dashboard::dialogs(self, &ctx);
        pages::exec::dialogs(self, &ctx);
        pages::files::dialogs(self, &ctx);
        pages::screen::dialogs(self, &ctx);
        pages::settings::dialogs(self, &ctx);

        // Refresh politely while something is animating or streaming.
        if matches!(self.conn, Conn::Connecting { .. }) {
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
