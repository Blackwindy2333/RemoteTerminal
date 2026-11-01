//! 总览 — connection form, remote identity, live load and quick actions.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText, ScrollArea, TextEdit, Ui};
use rt_client::{RemoteClient, Target};
use rt_core::config::Config;
use rt_protocol::{QuickStatus, ServerInfo, SysInfoSnapshot};

use crate::ui::app::{describe_error, App, ConnectRequest, Page};
use crate::ui::theme::{palette, Palette, Radius, Space, Tone, Type};
use crate::ui::widgets::{self, Btn};

/// How often the expensive full `sysinfo` snapshot is refreshed.
const SYSINFO_INTERVAL: Duration = Duration::from_secs(15);

/// The certificate presented by a server that is not pinned yet.
pub struct TrustPrompt {
    /// The connect attempt that produced it, ready to be retried with a pin.
    pub request: ConnectRequest,
    /// Server identity learned over TLS before any credential was sent.
    pub info: Box<ServerInfo>,
    /// Fingerprint the server presented (`None` when TLS is disabled).
    pub fingerprint: Option<String>,
}

/// Page state for 总览.
pub struct State {
    /// Host field.
    pub host: String,
    /// Port field (text so partial input does not fight the parser).
    pub port: String,
    /// User name for password login.
    pub username: String,
    /// Password (never persisted, never logged).
    pub password: String,
    /// Authenticate with an API key instead of a password.
    pub use_api_key: bool,
    /// API key text.
    pub api_key: String,
    /// Use TLS.
    pub tls: bool,
    /// Pinned certificate fingerprint (hex, colons optional).
    pub pin: String,
    /// Persist a newly trusted fingerprint into the config file.
    pub remember_pin: bool,
    /// Pending trust-on-first-use decision.
    pub pending_trust: Option<TrustPrompt>,
    /// Inline validation error for the connection form.
    pub form_error: Option<String>,
    /// Full system snapshot of the remote machine.
    pub info: Option<Box<SysInfoSnapshot>>,
    sysinfo_rx: Option<mpsc::Receiver<Result<SysInfoSnapshot, String>>>,
    sysinfo_inflight: bool,
    sysinfo_next: Instant,
    /// Result of the explicit "fetch fingerprint" probe.
    probe_rx: Option<mpsc::Receiver<Result<(Option<String>, String), String>>>,
    probe_inflight: bool,
    /// Message from the last probe, shown under the fingerprint field.
    pub probe_note: Option<String>,
    /// When the snapshot was last updated.
    pub snapshot_at: Option<Instant>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: "46666".to_string(),
            username: "admin".to_string(),
            password: String::new(),
            use_api_key: false,
            api_key: String::new(),
            tls: true,
            pin: String::new(),
            remember_pin: true,
            pending_trust: None,
            form_error: None,
            info: None,
            sysinfo_rx: None,
            sysinfo_inflight: false,
            sysinfo_next: Instant::now(),
            probe_rx: None,
            probe_inflight: false,
            probe_note: None,
            snapshot_at: None,
        }
    }
}

impl State {
    /// Pre-fills the connection form from the configured host list.
    pub fn seed_from_config(&mut self, config: &Config) {
        self.tls = true;
        if let Some(host) = config
            .client
            .hosts
            .iter()
            .find(|h| h.auto_connect)
            .or_else(|| config.client.hosts.first())
        {
            self.host = host.host.clone();
            self.port = host.port.to_string();
            if !host.username.is_empty() {
                self.username = host.username.clone();
            }
            if let Some(fingerprint) = &host.fingerprint {
                self.pin = fingerprint.clone();
            }
        }
    }

    /// Fills the connect form from one configured host entry.
    pub fn seed_from_host(&mut self, host: &rt_core::config::HostConfig) {
        self.host = host.host.clone();
        self.port = host.port.to_string();
        if !host.username.is_empty() {
            self.username = host.username.clone();
        }
        self.pin = host.fingerprint.clone().unwrap_or_default();
        self.tls = true;
    }

    /// Validates the form and produces a connect request.
    pub fn build_request(&self, config: &Config) -> Result<ConnectRequest, String> {
        let port: u16 = match self.port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => return Err("端口必须是 1-65535 之间的整数".to_string()),
        };
        let host = self.host.trim().to_string();
        if host.is_empty() {
            return Err("请输入主机名或 IP".to_string());
        }
        let api_key = self.api_key.trim().to_string();
        if self.use_api_key && api_key.is_empty() {
            return Err("请输入 API 密钥".to_string());
        }
        let password = self.password.clone();
        if !self.use_api_key && password.is_empty() {
            return Err("请输入密码".to_string());
        }
        let username = self.username.trim().to_string();
        if !self.use_api_key && username.is_empty() {
            return Err("请输入用户名".to_string());
        }
        Ok(ConnectRequest {
            host,
            port,
            tls: self.tls,
            username,
            password,
            api_key: self.use_api_key.then_some(api_key),
            pin: normalize_fingerprint(&self.pin),
            accept_new: false,
            timeout_secs: config.client.request_timeout_secs,
        })
    }

    /// Called by the shell once a connection becomes usable.
    pub fn on_connected(&mut self, address: &str) {
        self.form_error = None;
        self.pending_trust = None;
        self.info = None;
        self.snapshot_at = None;
        self.sysinfo_next = Instant::now();
        // Credentials are only needed for the handshake.
        self.password.clear();
        self.api_key.clear();
        self.probe_note = Some(format!("已连接到 {address}"));
    }

    /// Drains background refreshes.
    pub fn poll(&mut self, app: &mut App) {
        if let Some(rx) = &self.probe_rx {
            match rx.try_recv() {
                Ok(Ok((fingerprint, label))) => {
                    self.probe_inflight = false;
                    self.probe_rx = None;
                    match fingerprint {
                        Some(fingerprint) => {
                            self.pin = fingerprint;
                            self.probe_note =
                                Some(format!("{label} 提供的证书指纹（已填入，核对后点连接）"));
                        }
                        None => self.probe_note = Some(format!("{label} 未启用 TLS，没有证书指纹")),
                    }
                }
                Ok(Err(err)) => {
                    self.probe_inflight = false;
                    self.probe_rx = None;
                    self.probe_note = None;
                    app.toasts.error(format!("探测指纹失败：{err}"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.probe_inflight = false;
                    self.probe_rx = None;
                }
            }
        }

        if let Some(rx) = &self.sysinfo_rx {
            match rx.try_recv() {
                Ok(Ok(snapshot)) => {
                    self.info = Some(Box::new(snapshot));
                    self.snapshot_at = Some(Instant::now());
                    self.sysinfo_inflight = false;
                    self.sysinfo_rx = None;
                }
                Ok(Err(err)) => {
                    self.sysinfo_inflight = false;
                    self.sysinfo_rx = None;
                    app.toasts.warn(format!("读取系统信息失败：{err}"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.sysinfo_inflight = false;
                    self.sysinfo_rx = None;
                }
            }
        }
    }

    /// Whether a full snapshot should be requested right now.
    fn wants_snapshot(&self) -> bool {
        !self.sysinfo_inflight
            && (self.info.is_none() || Instant::now() >= self.sysinfo_next)
    }

    /// Requests a fresh full snapshot in the background.
    pub fn refresh(&mut self, app: &mut App) {
        let Some(client) = app.client() else { return };
        if self.sysinfo_inflight {
            return;
        }
        self.sysinfo_inflight = true;
        self.sysinfo_next = Instant::now() + SYSINFO_INTERVAL;
        let (tx, rx) = mpsc::channel();
        self.sysinfo_rx = Some(rx);
        app.spawn_task(async move {
            let result = match client.sysinfo().await {
                Ok(snapshot) => Ok(snapshot),
                Err(err) => Err(describe_error(&err)),
            };
            let _ = tx.send(result);
        });
    }

    /// Probes a server for its certificate fingerprint without logging in.
    pub fn probe_fingerprint(&mut self, app: &mut App) {
        let Ok(port) = self.port.trim().parse::<u16>() else {
            self.form_error = Some("端口必须是 1-65535 之间的整数".to_string());
            return;
        };
        let host = self.host.trim().to_string();
        if host.is_empty() {
            self.form_error = Some("请输入主机名或 IP".to_string());
            return;
        }
        if self.probe_inflight {
            return;
        }
        let mut target = Target::new(host, port);
        target.tls = self.tls;
        let timeout = Duration::from_secs(app.config.client.request_timeout_secs.clamp(3, 120));
        let (tx, rx) = mpsc::channel();
        self.probe_rx = Some(rx);
        self.probe_inflight = true;
        self.probe_note = None;
        app.spawn_task(async move {
            let outcome = match RemoteClient::with_timeout(target, timeout) {
                Ok(client) => match client.info().await {
                    Ok(info) => Ok((
                        client.presented_fingerprint(),
                        format!("{} · {}", info.name, info.hostname),
                    )),
                    Err(err) => Err(describe_error(&err)),
                },
                Err(err) => Err(describe_error(&err)),
            };
            let _ = tx.send(outcome);
        });
    }
}

/// Draws the whole page.
pub fn ui(app: &mut App, ui: &mut Ui) {
    if app.is_online() {
        // Auto-refresh the snapshot every couple of seconds / on Ctrl+R.
        let due = app.dashboard.wants_snapshot();
        if due || app.refresh_requested {
            app.with_dashboard(|state, app| state.refresh(app));
        }
        identity_card(app, ui);
        ui.add_space(Space::LG);
        load_grid(app, ui);
        ui.add_space(Space::LG);
        quick_actions(app, ui);
        ui.add_space(Space::LG);
        recent_logs(app, ui);
    } else {
        connect_form(app, ui);
    }
}

// ---------------------------------------------------------------------------
// Disconnected
// ---------------------------------------------------------------------------

fn connect_form(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    widgets::page_header(
        ui,
        "连接到服务器",
        "输入目标机器的地址与凭据；凭据只在内存中使用，不会写入配置文件",
    );

    let busy = app.active_slot().map(|slot| slot.busy()).unwrap_or(false);
    let mut probe = false;
    let mut submit = false;

    {
        let state = &mut app.dashboard;
        widgets::card(ui, |ui| {
            ui.set_max_width(760.0);
            widgets::section_label(ui, "连接");
            ui.add_space(Space::SM);

            egui::Grid::new("dash.connect.grid")
                .num_columns(2)
                .spacing([Space::MD, Space::SM])
                .min_col_width(88.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("主机").size(Type::CAPTION).color(p.text_muted));
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut state.host)
                                .hint_text("127.0.0.1 或 主机名")
                                .desired_width(200.0)
                                .text_color(p.text),
                        )
                        .on_hover_text("服务器地址：主机名、IPv4 或 IPv6");
                        ui.label(RichText::new("端口").size(Type::CAPTION).color(p.text_muted));
                        ui.add(
                            TextEdit::singleline(&mut state.port)
                                .desired_width(72.0)
                                .text_color(p.text),
                        )
                        .on_hover_text("默认 46666");
                    });
                    ui.end_row();

                    ui.label(RichText::new("用户名").size(Type::CAPTION).color(p.text_muted));
                    ui.add_enabled(
                        !state.use_api_key,
                        TextEdit::singleline(&mut state.username)
                            .desired_width(180.0)
                            .text_color(p.text),
                    )
                    .on_hover_text("使用密码登录时必填");
                    ui.end_row();

                    ui.label(RichText::new("密码").size(Type::CAPTION).color(p.text_muted));
                    ui.add_enabled(
                        !state.use_api_key,
                        TextEdit::singleline(&mut state.password)
                            .password(true)
                            .desired_width(220.0)
                            .hint_text("连接成功后从内存清除"),
                    )
                    .on_hover_text("密码仅用于本次连接");
                    ui.end_row();

                    ui.label(RichText::new("认证方式").size(Type::CAPTION).color(p.text_muted));
                    ui.horizontal(|ui| {
                        let mut api = state.use_api_key;
                        if widgets::toggle_switch(ui, "dash.use_api_key", &mut api, "改用 API 密钥登录")
                            .changed()
                        {
                            state.use_api_key = api;
                        }
                        ui.label(
                            RichText::new(if state.use_api_key { "API 密钥" } else { "密码" })
                                .size(Type::CAPTION)
                                .color(p.text),
                        );
                    });
                    ui.end_row();

                    if state.use_api_key {
                        ui.label(RichText::new("API 密钥").size(Type::CAPTION).color(p.text_muted));
                        ui.add(
                            TextEdit::singleline(&mut state.api_key)
                                .password(true)
                                .desired_width(360.0)
                                .hint_text("rt_…"),
                        )
                        .on_hover_text("在服务端的设置页生成，只保存在内存中");
                        ui.end_row();
                    }

                    ui.label(RichText::new("TLS").size(Type::CAPTION).color(p.text_muted));
                    ui.horizontal(|ui| {
                        let mut tls = state.tls;
                        if widgets::toggle_switch(ui, "dash.tls", &mut tls, "启用 HTTPS / WSS（推荐）")
                            .changed()
                        {
                            state.tls = tls;
                        }
                        ui.label(
                            RichText::new(if state.tls { "加密连接" } else { "明文连接" })
                                .size(Type::CAPTION)
                                .color(if state.tls { p.success } else { p.warning }),
                        );
                    });
                    ui.end_row();

                    ui.label(RichText::new("证书指纹").size(Type::CAPTION).color(p.text_muted));
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut state.pin)
                                .hint_text("留空则在首次连接时询问（推荐）")
                                .desired_width(280.0)
                                .text_color(p.text),
                        )
                        .on_hover_text("已固定的服务器证书 SHA-256 指纹，冒号可有可无");
                        if widgets::button(
                            ui,
                            Btn::new(
                                "dash.probe",
                                "获取指纹",
                                "读取服务器证书指纹，不会发送任何凭据",
                            )
                            .small()
                            .enabled(!state.probe_inflight && !busy),
                        )
                        .clicked()
                        {
                            probe = true;
                        }
                    });
                    ui.end_row();
                });

            if let Some(note) = &state.probe_note {
                widgets::caption(ui, note);
            }

            ui.add_space(Space::SM);
            widgets::switch_row(
                ui,
                "dash.remember_pin",
                &mut state.remember_pin,
                "记住服务器指纹",
                "首次信任后把指纹写入 config.toml，以后自动校验",
            );

            ui.add_space(Space::MD);
            ui.horizontal(|ui| {
                if widgets::button(
                    ui,
                    Btn::new("dash.connect", "连接", "使用上面的地址与凭据连接服务器")
                        .primary()
                        .enabled(!busy),
                )
                .clicked()
                {
                    submit = true;
                }
                if busy {
                    widgets::spinner_row(ui, "正在连接…");
                }
            });

            if let Some(error) = &state.form_error {
                ui.add_space(Space::SM);
                widgets::error_banner(ui, error);
            }
        });
    }

    if probe {
        app.with_dashboard(|state, app| state.probe_fingerprint(app));
    }
    if submit {
        submit_connect(app);
    }

    ui.add_space(Space::LG);
    known_hosts(app, ui);
}

/// Validates the form and starts a connect attempt.
fn submit_connect(app: &mut App) {
    let result = app.with_dashboard(|state, app| state.build_request(&app.config));
    match result {
        Ok(request) => {
            app.dashboard.form_error = None;
            app.connect(request);
        }
        Err(err) => app.dashboard.form_error = Some(err),
    }
}

/// Strips separators from a hex fingerprint so user input is tolerant.
fn normalize_fingerprint(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

// ---------------------------------------------------------------------------
// Connected: identity
// ---------------------------------------------------------------------------

fn identity_card(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    let Some(connected) = app.connected() else {
        return;
    };
    let hostname = connected.info.hostname.clone();
    let server_name = connected.info.name.clone();
    let app_version = connected.info.app_version.clone();
    let protocol_version = connected.info.protocol_version.clone();
    let os = connected.info.os.clone();
    let arch = connected.info.arch.clone();
    let uptime = connected.info.uptime_secs;
    let address = connected.address.clone();
    let tls = connected.tls;
    let username = connected.session.username.clone();
    let auth_kind = connected.session.auth_kind.clone();
    let scope = connected.session.scope;
    let expires = connected.session.expires_at.clone();
    let fingerprint = connected.fingerprint.clone();

    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(44.0), egui::Sense::hover());
            ui.painter().rect_filled(
                rect,
                Radius::MD,
                crate::ui::theme::wash(p.accent, if p.dark { 0x30 } else { 0x1C }),
            );
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "SRV",
                egui::FontId::proportional(13.0),
                p.accent,
            );
            ui.add_space(Space::MD);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&hostname)
                            .size(Type::TITLE)
                            .strong()
                            .color(p.text),
                    );
                    widgets::badge(
                        ui,
                        if scope.is_full() { "完全访问" } else { "工作区" },
                        if scope.is_full() { Tone::Danger } else { Tone::Warning },
                    );
                    if !tls {
                        widgets::badge(ui, "明文", Tone::Warning);
                    }
                });
                ui.label(
                    RichText::new(format!("{os} · {arch} · {address}"))
                        .size(Type::CAPTION)
                        .color(p.text_muted),
                );
            });
        });
        ui.add_space(Space::MD);
        widgets::divider(ui);

        egui::Grid::new("dash.identity")
            .num_columns(2)
            .spacing([Space::LG, Space::XS])
            .show(ui, |ui| {
                widgets::key_value_row(ui, "服务器名称", &server_name, false);
                ui.end_row();
                widgets::key_value_row(
                    ui,
                    "版本",
                    &format!("应用 {app_version} · 协议 {protocol_version}"),
                    true,
                );
                ui.end_row();
                widgets::key_value_row(
                    ui,
                    "登录身份",
                    &format!(
                        "{username}（{}）· 有效期至 {expires}",
                        if auth_kind == "api_key" { "API 密钥" } else { "密码" }
                    ),
                    false,
                );
                ui.end_row();
                let shown_fp = fingerprint
                    .as_deref()
                    .map(rt_core::crypto::format_fingerprint)
                    .unwrap_or_else(|| "未启用 TLS".to_string());
                widgets::key_value_row(ui, "证书指纹", &shown_fp, true);
                ui.end_row();
                widgets::key_value_row(
                    ui,
                    "服务器已运行",
                    &rt_core::util::format_uptime(uptime),
                    false,
                );
                ui.end_row();
            });
    });
}

// ---------------------------------------------------------------------------
// Connected: live load
// ---------------------------------------------------------------------------

fn load_grid(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    let snapshot = app.dashboard.info.clone();
    let pulse: Option<QuickStatus> = app.pulse.clone();
    let snapshot_at = app.dashboard.snapshot_at;

    ui.columns(2, |columns| {
        widgets::card(&mut columns[0], |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("实时负载")
                        .size(Type::HEADING)
                        .strong()
                        .color(p.text),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(at) = snapshot_at {
                        ui.label(
                            RichText::new(format!("{} 秒前更新", at.elapsed().as_secs()))
                                .size(Type::CAPTION)
                                .color(p.text_faint),
                        );
                    }
                });
            });
            ui.add_space(Space::SM);

            let cpu = pulse
                .as_ref()
                .map(|q| q.cpu_usage_percent)
                .or_else(|| snapshot.as_ref().map(|s| s.cpu.usage_percent))
                .unwrap_or(0.0);
            let cpu_tone = if cpu > 85.0 {
                Tone::Danger
            } else if cpu > 60.0 {
                Tone::Warning
            } else {
                Tone::Success
            };
            widgets::stat_bar(
                ui,
                "dash.cpu",
                "CPU",
                cpu / 100.0,
                &format!("{cpu:.0}%"),
                cpu_tone,
            );
            ui.add_space(Space::SM);

            let (used, total) = pulse
                .as_ref()
                .map(|q| (q.memory_used_bytes, q.memory_total_bytes))
                .or_else(|| {
                    snapshot
                        .as_ref()
                        .map(|s| (s.memory.used_bytes, s.memory.total_bytes))
                })
                .unwrap_or((0, 0));
            let ratio = if total > 0 {
                used as f32 / total as f32
            } else {
                0.0
            };
            widgets::stat_bar(
                ui,
                "dash.mem",
                "内存",
                ratio,
                &format!(
                    "{} / {}",
                    rt_core::util::format_bytes(used),
                    rt_core::util::format_bytes(total)
                ),
                if ratio > 0.9 {
                    Tone::Danger
                } else {
                    Tone::Accent
                },
            );
            ui.add_space(Space::MD);

            match snapshot.as_ref() {
                Some(snapshot) => {
                    widgets::key_value_row(
                        ui,
                        "处理器",
                        &format!(
                            "{}  ·  {} 核 / {} 线程",
                            snapshot.cpu.brand.trim(),
                            snapshot.cpu.physical_cores,
                            snapshot.cpu.logical_cores
                        ),
                        false,
                    );
                    widgets::key_value_row(
                        ui,
                        "运行时长",
                        &rt_core::util::format_uptime(snapshot.uptime_secs),
                        false,
                    );
                    widgets::key_value_row(ui, "进程数", &snapshot.process_count.to_string(), false);
                    if let Some(battery) = &snapshot.battery {
                        widgets::key_value_row(
                            ui,
                            "电池",
                            &format!(
                                "{:.0}%{}",
                                battery.percent,
                                if battery.is_charging { "（充电中）" } else { "" }
                            ),
                            false,
                        );
                    }
                }
                None => widgets::spinner_row(ui, "正在读取系统信息…"),
            }
        });

        widgets::card(&mut columns[1], |ui| {
            ui.label(RichText::new("磁盘").size(Type::HEADING).strong().color(p.text));
            ui.add_space(Space::SM);
            let Some(snapshot) = &snapshot else {
                widgets::spinner_row(ui, "正在读取系统信息…");
                return;
            };
            if snapshot.disks.is_empty() {
                widgets::caption(ui, "未检测到磁盘");
                return;
            }
            ScrollArea::vertical()
                .id_salt("dash.disks")
                .max_height(190.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for disk in &snapshot.disks {
                        let used = disk.total_bytes.saturating_sub(disk.available_bytes);
                        let ratio = if disk.total_bytes > 0 {
                            used as f32 / disk.total_bytes as f32
                        } else {
                            0.0
                        };
                        let tone = if ratio > 0.92 {
                            Tone::Danger
                        } else if ratio > 0.8 {
                            Tone::Warning
                        } else {
                            Tone::Accent
                        };
                        let label = if disk.name.is_empty() {
                            disk.mount_point.clone()
                        } else {
                            disk.name.clone()
                        };
                        widgets::stat_bar(
                            ui,
                            ("dash.disk", &disk.mount_point),
                            &label,
                            ratio,
                            &format!(
                                "{} 可用 / {}",
                                rt_core::util::format_bytes(disk.available_bytes),
                                rt_core::util::format_bytes(disk.total_bytes)
                            ),
                            tone,
                        );
                        ui.add_space(Space::SM);
                    }
                });
        });
    });
}

// ---------------------------------------------------------------------------
// Quick actions
// ---------------------------------------------------------------------------

fn quick_actions(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    let mut go: Option<Page> = None;
    let mut refresh = false;
    widgets::card(ui, |ui| {
        ui.label(
            RichText::new("快捷操作")
                .size(Type::HEADING)
                .strong()
                .color(p.text),
        );
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            if widgets::button(
                ui,
                Btn::new("dash.go.exec", "执行命令", "打开命令页，在远端执行 PowerShell")
                    .primary(),
            )
            .clicked()
            {
                go = Some(Page::Exec);
            }
            if widgets::button(
                ui,
                Btn::new("dash.go.files", "浏览文件", "打开文件页，浏览远端工作区与磁盘"),
            )
            .clicked()
            {
                go = Some(Page::Files);
            }
            if widgets::button(
                ui,
                Btn::new("dash.go.screen", "截图", "打开屏幕页，截取远端屏幕或窗口"),
            )
            .clicked()
            {
                go = Some(Page::Screen);
            }
            if widgets::button(
                ui,
                Btn::new("dash.refresh", "刷新", "立即重新读取服务器的系统信息"),
            )
            .clicked()
            {
                refresh = true;
            }
        });
    });
    if refresh {
        app.with_dashboard(|state, app| state.refresh(app));
    }
    if let Some(page) = go {
        app.page = page;
    }
}

// ---------------------------------------------------------------------------
// Recent logs
// ---------------------------------------------------------------------------

fn recent_logs(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    let events = app.sink.recent_desc(20);
    let mut open_logs = false;
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("最近日志")
                    .size(Type::HEADING)
                    .strong()
                    .color(p.text),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::button(
                    ui,
                    Btn::new("dash.logs", "全部日志", "切换到日志页查看完整日志与审计记录").small(),
                )
                .clicked()
                {
                    open_logs = true;
                }
            });
        });
        ui.add_space(Space::XS);
        ScrollArea::vertical()
            .id_salt("dash.logs")
            .max_height(200.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if events.is_empty() {
                    widgets::caption(ui, "暂无日志");
                }
                for event in &events {
                    let color = level_color(&p, &event.level);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(time_of(event.ts_ms))
                                .font(Type::mono())
                                .color(p.text_faint),
                        );
                        ui.label(
                            RichText::new(event.level.to_uppercase())
                                .font(Type::mono())
                                .color(color),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(&event.message).font(Type::mono()).color(p.text_muted),
                            )
                            .wrap(),
                        );
                    });
                }
            });
    });
    if open_logs {
        app.page = Page::Logs;
    }
}

fn level_color(p: &Palette, level: &str) -> egui::Color32 {
    match level.to_ascii_lowercase().as_str() {
        "error" => p.danger,
        "warn" => p.warning,
        "info" => p.accent,
        "debug" => p.text_muted,
        _ => p.text_faint,
    }
}

fn time_of(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S%.3f")
            .to_string(),
        None => "--:--:--".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Known hosts
// ---------------------------------------------------------------------------

fn known_hosts(app: &mut App, ui: &mut Ui) {
    let p = palette(ui.ctx());
    let hosts = app.config.client.hosts.clone();
    if hosts.is_empty() {
        return;
    }
    // (host, port, username, fingerprint)
    let mut pick: Option<(String, u16, String, Option<String>)> = None;
    widgets::card(ui, |ui| {
        ui.label(
            RichText::new("已知服务器")
                .size(Type::HEADING)
                .strong()
                .color(p.text),
        );
        ui.add_space(Space::SM);
        for host in &hosts {
            ui.horizontal(|ui| {
                let label = if host.name.is_empty() {
                    format!("{}:{}", host.host, host.port)
                } else {
                    format!("{} · {}:{}", host.name, host.host, host.port)
                };
                if widgets::button(
                    ui,
                    Btn::new(
                        ("dash.host", &host.host, host.port),
                        &label,
                        "填入上面的连接表单",
                    )
                    .small()
                    .ghost(),
                )
                .clicked()
                {
                    pick = Some((
                        host.host.clone(),
                        host.port,
                        host.username.clone(),
                        host.fingerprint.clone(),
                    ));
                }
                if let Some(last) = &host.last_connected {
                    ui.label(RichText::new(last.clone()).size(Type::CAPTION).color(p.text_faint));
                }
            });
        }
    });
    if let Some((host, port, username, fingerprint)) = pick {
        app.dashboard.host = host;
        app.dashboard.port = port.to_string();
        if !username.is_empty() {
            app.dashboard.username = username;
        }
        if let Some(fingerprint) = fingerprint {
            app.dashboard.pin = fingerprint;
        }
    }
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

/// Renders the trust-on-first-use dialog.
pub fn dialogs(app: &mut App, ctx: &egui::Context) {
    let Some(prompt) = app.dashboard.pending_trust.as_ref() else {
        return;
    };
    let p = palette(ctx);
    let shown = prompt
        .fingerprint
        .as_deref()
        .map(rt_core::crypto::format_fingerprint);
    let hostname = prompt.info.hostname.clone();
    let server_name = prompt.info.name.clone();
    let address = format!("{}:{}", prompt.request.host, prompt.request.port);
    let mut accept = false;
    let mut cancel = false;

    let modal = egui::Modal::new(egui::Id::unique("dash.trust"))
        .frame(
            egui::Frame::default()
                .fill(p.surface)
                .stroke(egui::Stroke::new(1.0, p.hairline_strong))
                .corner_radius(Radius::LG)
                .inner_margin(egui::Margin::same(Space::LG as i8))
                .shadow(crate::ui::theme::card_shadow(!p.dark)),
        )
        .backdrop_color(crate::ui::theme::fade(
            egui::Color32::BLACK,
            if p.dark { 0.55 } else { 0.28 },
        ));
    let response = modal.show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(
            RichText::new("首次连接到该服务器")
                .size(Type::TITLE)
                .strong()
                .color(p.text),
        );
        ui.add_space(Space::SM);
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "配置要求必须固定指纹，但 {address} 尚未被信任。请核对下面的指纹后再决定。"
                ))
                .size(Type::BODY)
                .color(p.text_muted),
            )
            .wrap(),
        );
        ui.add_space(Space::MD);
        widgets::inset(ui, |ui| {
            widgets::key_value_row(ui, "服务器", &server_name, false);
            widgets::key_value_row(ui, "主机名", &hostname, false);
            ui.add_space(Space::XS);
            match shown.as_deref() {
                Some(fingerprint) => {
                    widgets::section_label(ui, "SHA-256 证书指纹");
                    ui.add(
                        egui::Label::new(
                            RichText::new(fingerprint).font(Type::mono()).color(p.text),
                        )
                        .wrap(),
                    );
                }
                None => widgets::caption(ui, "该连接未使用 TLS，没有证书指纹可供核对。"),
            }
        });
        ui.add_space(Space::MD);
        ui.horizontal(|ui| {
            if shown.is_some()
                && widgets::button(
                    ui,
                    Btn::new("dash.trust.copy", "复制指纹", "复制到剪贴板，便于与服务器核对"),
                )
                .clicked()
            {
                if let Some(fingerprint) = &shown {
                    ui.ctx().copy_text(fingerprint.clone());
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::button(
                    ui,
                    Btn::new("dash.trust.ok", "信任并连接", "固定该指纹并继续登录")
                        .primary()
                        .enabled(shown.is_some()),
                )
                .clicked()
                {
                    accept = true;
                }
                if widgets::button(
                    ui,
                    Btn::new("dash.trust.cancel", "取消", "不要连接该服务器").ghost(),
                )
                .clicked()
                {
                    cancel = true;
                }
            });
        });
    });

    if accept {
        app.with_dashboard(|state, app| {
            if let Some(prompt) = state.pending_trust.take() {
                let mut request = prompt.request;
                request.pin = prompt.fingerprint.clone();
                request.accept_new = true;
                if state.remember_pin {
                    if let Some(fingerprint) = &prompt.fingerprint {
                        state.pin = fingerprint.clone();
                    }
                }
                app.connect(request);
            }
        });
    } else if cancel || response.should_close() {
        app.with_dashboard(|state, app| {
            state.pending_trust = None;
            app.toasts.info("已取消连接");
        });
    }
}
