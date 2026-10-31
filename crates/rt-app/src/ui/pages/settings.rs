//! Settings page: edits the configuration in memory and persists it to
//! `config.toml`, manages server users and API keys, and starts/stops the
//! embedded server.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{RichText, Ui};
use rt_core::config::{ApiKeyConfig, Config, ResolvedPaths, Theme, ValidationReport, UserConfig};
use rt_protocol::auth::ApiKeyInfo;

use crate::ui::app::App;
use crate::ui::theme::{self, palette, Space, Tone, Type};
use crate::ui::widgets::{self, Btn};

/// Editor state for a not-yet-added user.
struct NewUser {
    name: String,
    password: String,
    scope: String,
    reveal: bool,
}

impl Default for NewUser {
    fn default() -> Self {
        Self {
            name: String::new(),
            password: String::new(),
            scope: "full".to_string(),
            reveal: false,
        }
    }
}

/// Settings page state.
pub struct State {
    new_user: NewUser,
    hashing: bool,
    hash_rx: Option<mpsc::Receiver<Result<UserConfig, String>>>,
    new_key_name: String,
    new_key_scope: String,
    /// Plaintext of the most recently generated key; shown exactly once.
    generated: Option<(String, String)>,
    remote_keys: Vec<ApiKeyInfo>,
    keys_error: Option<String>,
    keys_inflight: bool,
    keys_rx: Option<mpsc::Receiver<Result<Vec<ApiKeyInfo>, String>>>,
    report: Option<ValidationReport>,
    last_saved: Option<Instant>,
    pending_restart: bool,
    confirm_remove_user: Option<usize>,
    confirm_remove_key: Option<usize>,
    pick_rx: Option<mpsc::Receiver<Option<PathBuf>>>,
    pick_target: Option<&'static str>,
    note: Option<(Instant, String)>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            new_user: NewUser::default(),
            hashing: false,
            hash_rx: None,
            new_key_name: String::new(),
            new_key_scope: "workspace".to_string(),
            generated: None,
            remote_keys: Vec::new(),
            keys_error: None,
            keys_inflight: false,
            keys_rx: None,
            report: None,
            last_saved: None,
            pending_restart: false,
            confirm_remove_user: None,
            confirm_remove_key: None,
            pick_rx: None,
            pick_target: None,
            note: None,
        }
    }
}

impl State {
    /// Pre-fills UI scratch values from the configuration.
    pub fn seed_from_config(&mut self, config: &Config, _paths: &ResolvedPaths) {
        self.new_key_scope = config
            .server
            .api_keys
            .last()
            .map(|key| key.scope.clone())
            .unwrap_or_else(|| "workspace".to_string());
    }

    /// Drains background work.
    pub fn poll(&mut self, app: &mut App) {
        if let Some(rx) = self.hash_rx.as_ref() {
            while let Ok(result) = rx.try_recv() {
                self.hashing = false;
                match result {
                    Ok(user) => {
                        let name = user.name.clone();
                        app.config.server.users.push(user);
                        self.note = Some((Instant::now(), format!("已添加用户 {name}（记得保存）")));
                        app.toasts.success(format!("已添加用户 {name}"));
                    }
                    Err(err) => app.fail(err),
                }
            }
        }
        if let Some(rx) = self.keys_rx.as_ref() {
            while let Ok(result) = rx.try_recv() {
                self.keys_inflight = false;
                match result {
                    Ok(keys) => {
                        self.remote_keys = keys;
                        self.keys_error = None;
                    }
                    Err(err) => self.keys_error = Some(err),
                }
            }
        }
        if let Some(rx) = self.pick_rx.as_ref() {
            while let Ok(choice) = rx.try_recv() {
                if let (Some(path), Some(target)) = (choice, self.pick_target.take()) {
                    let text = path.display().to_string();
                    match target {
                        "workspace" => app.config.server.workspace.root = PathBuf::from(text),
                        "download" => app.config.client.download_dir = PathBuf::from(text),
                        _ => {}
                    }
                }
            }
        }
        if self.hashing || self.keys_inflight {
            app.ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    /// Validates and writes the configuration file.
    fn save(&mut self, app: &mut App) {
        let report = app.config.validate();
        if !report.is_ok() {
            self.report = Some(report);
            app.fail("配置未通过校验，未写入文件");
            return;
        }
        let path = app.config_path.clone();
        match app.config.save_with_header(&path) {
            Ok(()) => {
                self.report = Some(report);
                self.last_saved = Some(Instant::now());
                self.pending_restart = false;
                app.set_status(format!("配置已保存到 {}", path.display()));
                app.toasts.success("配置已保存");
            }
            Err(err) => app.fail(format!("保存失败：{err}")),
        }
    }

    /// Re-reads the configuration file from disk.
    fn reload(&mut self, app: &mut App) {
        let path = app.config_path.clone();
        match rt_core::config::load_or_create(Some(&path)) {
            Ok(loaded) => {
                app.config = loaded.config;
                self.report = Some(ValidationReport::default());
                self.note = Some((Instant::now(), "已从磁盘重新载入配置".to_string()));
                app.toasts.success("已重新载入配置");
                for warning in loaded.warnings {
                    app.toasts.warn(warning);
                }
            }
            Err(err) => app.fail(format!("读取配置失败：{err}")),
        }
    }

    /// Hashes the password on a blocking thread and appends a user.
    fn add_user(&mut self, app: &mut App) {
        let name = self.new_user.name.trim().to_string();
        if name.is_empty() {
            app.fail("用户名不能为空");
            return;
        }
        if self.new_user.password.chars().count() < 8 {
            app.fail("密码至少 8 位");
            return;
        }
        if app
            .config
            .server
            .users
            .iter()
            .any(|user| user.name.eq_ignore_ascii_case(&name))
        {
            app.fail(format!("用户 {name} 已存在"));
            return;
        }
        let password = std::mem::take(&mut self.new_user.password);
        let scope = self.new_user.scope.clone();
        let (tx, rx) = mpsc::channel();
        self.hash_rx = Some(rx);
        self.hashing = true;
        let user_name = name.clone();
        app.spawn_blocking(
            move || -> Result<UserConfig, String> {
                let hash = rt_core::crypto::hash_password(&password).map_err(|err| {
                    format!("密码哈希失败：{err}")
                })?;
                Ok(UserConfig {
                    name: user_name,
                    password_hash: hash,
                    scope,
                    enabled: true,
                })
            },
            move |result| {
                let _ = tx.send(result);
            },
        );
        self.new_user.name.clear();
        app.set_status(format!("正在为 {name} 计算密码哈希…"));
    }

    /// Generates a new API key and appends the digest to the configuration.
    fn generate_key(&mut self, app: &mut App) {
        let name = if self.new_key_name.trim().is_empty() {
            format!("key-{}", app.config.server.api_keys.len() + 1)
        } else {
            self.new_key_name.trim().to_string()
        };
        let (plaintext, digest) = rt_core::config::generate_api_key();
        app.config.server.api_keys.push(ApiKeyConfig {
            name: name.clone(),
            key_sha256: digest,
            scope: self.new_key_scope.clone(),
            enabled: true,
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        });
        self.generated = Some((name.clone(), plaintext));
        self.new_key_name.clear();
        self.note = Some((Instant::now(), format!("已生成密钥 {name}（记得保存）")));
        app.toasts.success(format!("已生成 API 密钥 {name}"));
    }

    /// Loads key metadata from the connected server.
    fn load_remote_keys(&mut self, app: &App) {
        let Some(client) = app.client() else {
            self.keys_error = Some("尚未连接服务器".to_string());
            return;
        };
        if self.keys_inflight {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.keys_rx = Some(rx);
        self.keys_inflight = true;
        app.spawn_task(async move {
            let result = client.api_keys_info().await.map_err(|err| err.message());
            let _ = tx.send(result);
        });
    }
}

/// Signature of the server-relevant configuration, used to flag a pending restart.
fn server_signature(config: &Config) -> String {
    format!(
        "{}/{}/{}/{}/{:?}/{:?}/{:?}/{}",
        config.server.enabled,
        config.server.bind,
        config.server.port,
        config.server.tls,
        config.server.cert_path,
        config.server.key_path,
        config.server.workspace.root,
        config.server.users.len(),
    )
}

/// Page entry point.
pub fn ui(app: &mut App, ui: &mut Ui) {
    app.with_settings(|state, app| {
        let p = palette(ui.ctx());
        widgets::page_header(
            ui,
            "设置",
            "改动即时生效；点击“保存”后写入 config.toml。服务端相关改动需要重启服务端。",
        );

        let before = server_signature(&app.config);
        config_card(ui, state, app);
        server_card(ui, state, app, &p);
        users_card(ui, state, app, &p);
        keys_card(ui, state, app, &p);
        client_card(ui, state, app);
        appearance_card(ui, state, app, &p);
        logging_card(ui, state, app);

        if server_signature(&app.config) != before && app.server.is_some() {
            state.pending_restart = true;
        }
    });
}

/// Config file path, save / reload / open-folder actions and validation output.
fn config_card(ui: &mut Ui, state: &mut State, app: &mut App) {
    let p = palette(ui.ctx());
    widgets::card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "配置文件");
            ui.label(
                RichText::new(app.config_path.display().to_string())
                    .monospace()
                    .size(Type::CAPTION)
                    .color(p.text_muted),
            );
        });
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            if widgets::button(
                ui,
                Btn::new("settings.save", "保存", "校验并写入 config.toml（会自动备份）").primary(),
            )
            .clicked()
            {
                state.save(app);
            }
            if widgets::button(
                ui,
                Btn::new("settings.reload", "重新载入", "丢弃未保存改动，从磁盘重新读取"),
            )
            .clicked()
            {
                state.reload(app);
            }
            if widgets::button(
                ui,
                Btn::new("settings.open_dir", "打开配置目录", "在资源管理器中打开配置目录"),
            )
            .clicked()
            {
                let dir = app.paths.base_dir.clone();
                app.spawn_blocking(
                    move || {
                        let _ = open::that(&dir);
                    },
                    |()| {},
                );
            }
            if state.pending_restart {
                widgets::badge(ui, "服务端需重启", Tone::Warning);
            }
            if let Some(at) = state.last_saved {
                if at.elapsed() < Duration::from_secs(30) {
                    widgets::badge(ui, "已保存", Tone::Success);
                }
            }
            if let Some((at, note)) = &state.note {
                if at.elapsed() < Duration::from_secs(10) {
                    widgets::caption(ui, note);
                }
            }
        });

        if let Some(report) = &state.report {
            if !report.errors.is_empty() {
                ui.add_space(Space::SM);
                widgets::section_label(ui, "校验错误");
                for error in &report.errors {
                    widgets::error_banner(ui, error);
                }
            }
            if !report.warnings.is_empty() {
                ui.add_space(Space::SM);
                widgets::section_label(ui, "提示");
                for warning in &report.warnings {
                    widgets::note_banner(ui, warning);
                }
            }
        }
    });
}

/// Embedded server configuration and lifecycle controls.
fn server_card(ui: &mut Ui, state: &mut State, app: &mut App, p: &theme::Palette) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section_label(ui, "服务端");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &app.server {
                    Some(_server) => {
                        widgets::status_dot(ui, p.success, true);
                        widgets::badge(ui, "运行中", Tone::Success);
                    }
                    None => {
                        widgets::status_dot(ui, p.text_faint, false);
                        widgets::badge(ui, "已停止", Tone::Neutral);
                    }
                }
            });
        });

        // -- lifecycle ------------------------------------------------------
        if let Some(server) = &app.server {
            let url = server.handle.url.clone();
            let fingerprint = server.handle.fingerprint.clone();
            let tls = server.handle.tls;
            let uptime = server.since.elapsed().as_secs();
            ui.add_space(Space::XS);
            widgets::key_value_row(ui, "地址", &url, true);
            widgets::key_value_row(
                ui,
                "证书指纹",
                &fingerprint
                    .as_deref()
                    .map(rt_core::crypto::format_fingerprint)
                    .unwrap_or_else(|| "（未启用 TLS）".to_string()),
                true,
            );
            widgets::key_value_row(ui, "运行时长", &rt_core::util::format_uptime(uptime), false);
            widgets::key_value_row(
                ui,
                "传输加密",
                if tls {
                    "TLS 已启用"
                } else {
                    "明文传输（仅建议本机回环地址）"
                },
                false,
            );
            ui.horizontal(|ui| {
                if widgets::button(
                    ui,
                    Btn::new("settings.server.copy_url", "复制地址", "复制服务端地址，便于其他设备连接"),
                )
                .clicked()
                {
                    ui.ctx().copy_text(url.clone());
                    app.toasts.info("已复制服务端地址");
                }
                if let Some(fp) = fingerprint.clone() {
                    if widgets::button(
                        ui,
                        Btn::new(
                            "settings.server.copy_fp",
                            "复制指纹",
                            "对端首次连接时需要核对这个指纹",
                        ),
                    )
                    .clicked()
                    {
                        ui.ctx().copy_text(rt_core::crypto::format_fingerprint(&fp));
                        app.toasts.info("已复制证书指纹");
                    }
                }
                if widgets::button(
                    ui,
                    Btn::new("settings.server.stop", "停止服务端", "停止监听；已有会话会被断开")
                        .danger(),
                )
                .clicked()
                {
                    app.stop_server();
                    state.pending_restart = false;
                }
            });
        } else {
            ui.add_space(Space::SM);
            ui.horizontal(|ui| {
                if widgets::button(
                    ui,
                    Btn::new(
                        "settings.server.start",
                        "启动服务端",
                        "用当前配置启动服务端；未保存的改动同样生效",
                    )
                    .primary(),
                )
                .clicked()
                {
                    app.start_server();
                    state.pending_restart = false;
                }
                if !app.config.server.enabled {
                    widgets::caption(ui, "需要先勾选“启用服务端”");
                }
            });
        }

        ui.add_space(Space::SM);
        widgets::divider(ui);
        ui.add_space(Space::SM);

        // -- settings -------------------------------------------------------
        widgets::switch_row(
            ui,
            "settings.server.enabled",
            &mut app.config.server.enabled,
            "启用服务端",
            "允许其他设备连接这台机器",
        );
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "名称");
            let mut name = app.config.server.name.clone().unwrap_or_default();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut name)
                        .hint_text("默认使用主机名")
                        .desired_width(180.0),
                )
                .on_hover_text("显示给客户端看的服务端名称")
                .changed()
            {
                app.config.server.name = if name.trim().is_empty() {
                    None
                } else {
                    Some(name.trim().to_string())
                };
            }
            ui.add_space(Space::MD);
            widgets::section_label(ui, "监听地址");
            ui.add(
                egui::TextEdit::singleline(&mut app.config.server.bind)
                    .hint_text("0.0.0.0")
                    .desired_width(130.0),
            )
            .on_hover_text("0.0.0.0 监听所有网卡，127.0.0.1 仅本机");
            widgets::section_label(ui, "端口");
            ui.add(egui::DragValue::new(&mut app.config.server.port).range(1..=65535))
                .on_hover_text("默认 46666");
        });
        ui.add_space(Space::SM);
        widgets::switch_row(
            ui,
            "settings.server.tls",
            &mut app.config.server.tls,
            "启用 TLS",
            "局域网连接强烈建议开启；关闭需要额外确认",
        );
        if !app.config.server.tls {
            ui.horizontal(|ui| {
                widgets::switch_row(
                    ui,
                    "settings.server.insecure",
                    &mut app.config.server.allow_insecure_lan,
                    "允许明文 HTTP",
                    "非回环地址上的明文连接（不推荐）",
                );
            });
        }
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "会话有效期");
            ui.add(
                egui::DragValue::new(&mut app.config.server.session_ttl_minutes)
                    .range(0..=43_200)
                    .suffix(" 分钟"),
            )
            .on_hover_text("0 表示永不过期");
            ui.add_space(Space::MD);
            widgets::section_label(ui, "最大并发会话");
            ui.add(egui::DragValue::new(&mut app.config.server.max_sessions).range(1..=512))
                .on_hover_text("同一时间允许的登录会话数量");
            ui.add_space(Space::MD);
            widgets::section_label(ui, "命令超时");
            ui.add(
                egui::DragValue::new(&mut app.config.server.exec_timeout_secs)
                    .range(1..=86_400)
                    .suffix(" 秒"),
            )
            .on_hover_text("单条命令的最长执行时间");
        });
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "工作区根目录");
            let mut root = app.config.server.workspace.root.display().to_string();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut root)
                        .hint_text("workspace")
                        .desired_width(280.0),
                )
                .on_hover_text("工作区范围会话被限制在这个目录内")
                .changed()
            {
                app.config.server.workspace.root = PathBuf::from(root.trim());
            }
            if widgets::button(
                ui,
                Btn::new("settings.server.pick_root", "选择…", "浏览并选择工作区根目录").small(),
            )
            .clicked()
            {
                pick_folder(app, state, "workspace");
            }
            widgets::switch_row(
                ui,
                "settings.server.create_root",
                &mut app.config.server.workspace.create,
                "自动创建",
                "目录不存在时自动创建",
            );
        });
        ui.add_space(Space::SM);
        ui.horizontal(|ui| {
            widgets::section_label(ui, "默认权限范围");
            let mut scope = app
                .config
                .server
                .users
                .first()
                .map(|user| user.scope.clone())
                .unwrap_or_else(|| "full".to_string());
            let before = scope.clone();
            widgets::segmented(
                ui,
                "settings.server.default_scope",
                &[("full", "完全访问"), ("workspace", "仅工作区")],
                &mut scope,
            );
            if scope != before {
                // Apply to every user so the default is unambiguous.
                for user in &mut app.config.server.users {
                    user.scope = scope.clone();
                }
            }
            ui.add_space(Space::SM);
            widgets::caption(ui, "新用户默认使用该范围");
        });
    });
}

/// User list with add / remove / scope / enable controls.
fn users_card(ui: &mut Ui, state: &mut State, app: &mut App, p: &theme::Palette) {
    widgets::card(ui, |ui| {
        widgets::section_label(ui, "用户");

        if app.config.server.users.is_empty() {
            widgets::caption(ui, "还没有用户；启用服务端前至少需要一个设置了密码的用户。");
        }

        let mut remove: Option<usize> = None;
        for (index, user) in app.config.server.users.iter_mut().enumerate() {
            let has_password = !user.password_hash.trim().is_empty();
            ui.add_space(Space::SM);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&user.name).size(Type::BODY).strong().color(p.text));
                widgets::badge(
                    ui,
                    if has_password { "已设置密码" } else { "未设置密码" },
                    if has_password {
                        Tone::Success
                    } else {
                        Tone::Warning
                    },
                );
                let mut scope = user.scope.clone();
                let before = scope.clone();
                let id = format!("settings.user.scope.{index}");
                widgets::segmented(
                    ui,
                    &id,
                    &[("full", "完全访问"), ("workspace", "仅工作区")],
                    &mut scope,
                );
                if scope != before {
                    user.scope = scope;
                }
                let mut enabled = user.enabled;
                widgets::toggle_switch(
                    ui,
                    ("settings.user.enabled", index),
                    &mut enabled,
                    "禁用后该用户无法登录",
                );
                user.enabled = enabled;
                if widgets::button(
                    ui,
                    Btn::new(
                        ("settings.user.remove", index),
                        "移除",
                        "从配置中删除该用户（保存后生效）",
                    )
                    .small()
                    .danger(),
                )
                .clicked()
                {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            state.confirm_remove_user = Some(index);
        }

        ui.add_space(Space::SM);
        widgets::divider(ui);
        ui.add_space(Space::SM);
        widgets::section_label(ui, "添加用户");
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.new_user.name)
                    .hint_text("用户名")
                    .desired_width(140.0),
            )
            .on_hover_text("登录时使用的账号名");
            ui.add(
                egui::TextEdit::singleline(&mut state.new_user.password)
                    .hint_text("密码（至少 8 位）")
                    .password(!state.new_user.reveal)
                    .desired_width(180.0),
            )
            .on_hover_text("只用于计算 Argon2id 哈希，不会保存明文");
            if widgets::button(
                ui,
                Btn::new(
                    "settings.user.reveal",
                    if state.new_user.reveal { "隐藏" } else { "显示" },
                    "切换密码可见性",
                )
                .small()
                .ghost(),
            )
            .clicked()
            {
                state.new_user.reveal = !state.new_user.reveal;
            }
            widgets::segmented(
                ui,
                "settings.new_user.scope",
                &[("full", "完全访问"), ("workspace", "仅工作区")],
                &mut state.new_user.scope,
            );
            let busy = state.hashing;
            if widgets::button(
                ui,
                Btn::new("settings.user.add", "添加用户", "计算密码哈希并加入待保存列表")
                    .primary()
                    .enabled(!busy),
            )
            .clicked()
            {
                state.add_user(app);
            }
            if busy {
                widgets::spinner_row(ui, "计算密码哈希…");
            }
        });
        widgets::caption(ui, "密码只以 Argon2id 哈希形式写入配置，界面不会显示已有哈希。");
    });
}

/// API keys: local config entries plus the server's own key metadata.
fn keys_card(ui: &mut Ui, state: &mut State, app: &mut App, p: &theme::Palette) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section_label(ui, "API 密钥");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button(
                    ui,
                    Btn::new(
                        "settings.keys.remote",
                        "刷新服务端密钥",
                        "读取已连接服务器上的密钥信息（不含密钥本身）",
                    )
                    .small()
                    .enabled(app.is_online() && !state.keys_inflight),
                )
                .clicked()
                {
                    state.load_remote_keys(app);
                }
            });
        });

        let mut remove: Option<usize> = None;
        for (index, key) in app.config.server.api_keys.iter_mut().enumerate() {
            ui.add_space(Space::XS);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&key.name).size(Type::BODY).color(p.text));
                let mut scope = key.scope.clone();
                let before = scope.clone();
                let id = format!("settings.key.scope.{index}");
                widgets::segmented(
                    ui,
                    &id,
                    &[("full", "完全访问"), ("workspace", "仅工作区")],
                    &mut scope,
                );
                if scope != before {
                    key.scope = scope;
                }
                ui.label(
                    RichText::new(short_digest(&key.key_sha256))
                        .monospace()
                        .size(Type::CAPTION)
                        .color(p.text_faint),
                );
                let mut enabled = key.enabled;
                widgets::toggle_switch(
                    ui,
                    ("settings.key.enabled", index),
                    &mut enabled,
                    "禁用后该密钥无法通过认证",
                );
                key.enabled = enabled;
                if widgets::button(
                    ui,
                    Btn::new(
                        ("settings.key.remove", index),
                        "移除",
                        "从配置中删除该密钥（保存后生效）",
                    )
                    .small()
                    .danger(),
                )
                .clicked()
                {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            state.confirm_remove_key = Some(index);
        }
        if app.config.server.api_keys.is_empty() {
            widgets::caption(ui, "还没有本地 API 密钥。");
        }

        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.new_key_name)
                    .hint_text("密钥名称")
                    .desired_width(140.0),
            )
            .on_hover_text("便于在配置文件中识别用途");
            widgets::segmented(
                ui,
                "settings.new_key.scope",
                &[("full", "完全访问"), ("workspace", "仅工作区")],
                &mut state.new_key_scope,
            );
            if widgets::button(
                ui,
                Btn::new(
                    "settings.key.generate",
                    "生成新密钥",
                    "生成本机密钥并写入配置；明文只显示一次",
                )
                .primary(),
            )
            .clicked()
            {
                state.generate_key(app);
            }
        });
        if let Some((name, key)) = state.generated.clone() {
            ui.add_space(Space::XS);
            widgets::note_banner(
                ui,
                &format!("密钥 {name} 只显示一次，请立即复制：{key}"),
            );
            if widgets::button(
                ui,
                Btn::new("settings.key.copy", "复制密钥", "复制到剪贴板（关闭面板后无法再取出）")
                    .small(),
            )
            .clicked()
            {
                ui.ctx().copy_text(key.clone());
                app.toasts.info("已复制 API 密钥");
            }
            if widgets::button(
                ui,
                Btn::new("settings.key.dismiss", "已保存，隐藏", "从界面上移除明文")
                    .small()
                    .ghost(),
            )
            .clicked()
            {
                state.generated = None;
            }
        }

        if let Some(error) = &state.keys_error {
            widgets::error_banner(ui, error);
        }
        if state.keys_inflight {
            widgets::spinner_row(ui, "读取服务端密钥…");
        }
        if !state.remote_keys.is_empty() {
            ui.add_space(Space::SM);
            widgets::section_label(ui, "服务端已注册的密钥");
            for key in &state.remote_keys {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&key.name).size(Type::CAPTION).color(p.text));
                    widgets::badge(
                        ui,
                        if key.scope.is_full() { "完全访问" } else { "仅工作区" },
                        if key.scope.is_full() { Tone::Success } else { Tone::Warning },
                    );
                    ui.label(
                        RichText::new(&key.fingerprint)
                            .monospace()
                            .size(Type::CAPTION)
                            .color(p.text_faint),
                    );
                    if let Some(used) = &key.last_used_at {
                        widgets::caption(ui, &format!("最近使用 {used}"));
                    }
                });
            }
        }
    });
}

/// Client connection behaviour.
fn client_card(ui: &mut Ui, state: &mut State, app: &mut App) {
    let p = palette(ui.ctx());
    widgets::card(ui, |ui| {
        widgets::section_label(ui, "客户端");
        widgets::switch_row(
            ui,
            "settings.client.pin",
            &mut app.config.client.require_pinned_fingerprint,
            "要求固定证书指纹",
            "未固定指纹的服务器需要手动确认后才能连接（推荐开启）",
        );
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "请求超时");
            ui.add(
                egui::DragValue::new(&mut app.config.client.request_timeout_secs)
                    .range(1..=3600)
                    .suffix(" 秒"),
            )
            .on_hover_text("单次 HTTP 请求的最长时间");
            ui.add_space(Space::MD);
            widgets::section_label(ui, "默认 Shell");
            widgets::segmented(
                ui,
                "settings.client.shell",
                &[("pwsh", "pwsh"), ("powershell", "Windows PowerShell"), ("cmd", "cmd")],
                &mut app.config.client.default_shell,
            );
        });
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "下载目录");
            let mut dir = app.config.client.download_dir.display().to_string();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut dir)
                        .hint_text("downloads")
                        .desired_width(300.0),
                )
                .on_hover_text("相对路径基于配置文件所在目录")
                .changed()
            {
                app.config.client.download_dir = PathBuf::from(dir.trim());
            }
            if widgets::button(
                ui,
                Btn::new(
                    "settings.client.pick_download",
                    "选择…",
                    "浏览并选择下载目录",
                )
                .small(),
            )
            .clicked()
            {
                pick_folder(app, state, "download");
            }
        });
        ui.add_space(Space::XS);
        widgets::caption(
            ui,
            &format!("解析后的下载目录：{}", app.paths.downloads_dir.display()),
        );
        ui.add_space(Space::XS);
        widgets::caption(
            ui,
            &format!("已知主机 {} 个", app.config.client.hosts.len()),
        );
        let _ = p;
    });
}

/// Appearance options.
fn appearance_card(ui: &mut Ui, state: &mut State, app: &mut App, p: &theme::Palette) {
    let _ = state;
    widgets::card(ui, |ui| {
        widgets::section_label(ui, "界面");
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "主题");
            let mut name = app.config.app.theme.as_str().to_string();
            let before = name.clone();
            widgets::segmented(
                ui,
                "settings.app.theme",
                &[("system", "跟随系统"), ("light", "浅色"), ("dark", "深色")],
                &mut name,
            );
            if name != before {
                if let Some(theme) = Theme::parse(&name) {
                    app.config.app.theme = theme;
                }
            }
        });
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "强调色");
            for (value, label) in theme::ACCENTS {
                let active = app.config.app.accent.eq_ignore_ascii_case(value);
                let color = theme::accent_color(value);
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(28.0, 22.0),
                    egui::Sense::click(),
                );
                ui.painter().rect_filled(rect, theme::Radius::SM, color);
                if active {
                    ui.painter().rect_stroke(
                        rect,
                        theme::Radius::SM,
                        egui::Stroke::new(2.0, p.text),
                        egui::StrokeKind::Inside,
                    );
                }
                if response.clicked() {
                    app.config.app.accent = (*value).to_string();
                }
                response.on_hover_text(format!("强调色：{label}"));
            }
            widgets::caption(ui, app.config.app.accent.as_str());
        });
        ui.add_space(Space::SM);
        widgets::switch_row(
            ui,
            "settings.app.reduce_motion",
            &mut app.reduce_motion,
            "减少动效",
            "关闭弹簧动画，改用快速淡入淡出（跟随系统无障碍设置时也建议开启）",
        );
        widgets::switch_row(
            ui,
            "settings.app.start_minimized",
            &mut app.config.app.start_minimized,
            "启动时最小化",
            "下次启动直接进入托盘/后台（保存后生效）",
        );
        widgets::switch_row(
            ui,
            "settings.app.single_instance",
            &mut app.config.app.single_instance,
            "单实例运行",
            "重复启动时复用已打开的窗口（保存后生效）",
        );
        widgets::switch_row(
            ui,
            "settings.app.remember_window",
            &mut app.config.app.remember_window,
            "记住窗口大小",
            "下次启动恢复上次的窗口尺寸",
        );
    });
}

/// Logging options.
fn logging_card(ui: &mut Ui, state: &mut State, app: &mut App) {
    let _ = state;
    widgets::card(ui, |ui| {
        widgets::section_label(ui, "日志");
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "级别");
            widgets::segmented(
                ui,
                "settings.log.level",
                &[
                    ("error", "ERROR"),
                    ("warn", "WARN"),
                    ("info", "INFO"),
                    ("debug", "DEBUG"),
                    ("trace", "TRACE"),
                ],
                &mut app.config.logging.level,
            );
        });
        ui.add_space(Space::SM);
        widgets::switch_row(
            ui,
            "settings.log.console",
            &mut app.config.logging.console,
            "输出到控制台",
            "同时把日志写到 stderr（便于无界面运行）",
        );
        widgets::switch_row(
            ui,
            "settings.log.json",
            &mut app.config.logging.json,
            "JSON 日志",
            "每行一条 JSON，便于机器解析",
        );
        widgets::switch_row(
            ui,
            "settings.log.audit",
            &mut app.config.logging.audit,
            "审计日志",
            "记录登录、命令与文件操作的独立审计文件",
        );
        ui.add_space(Space::SM);
        ui.horizontal_wrapped(|ui| {
            widgets::section_label(ui, "保留文件数");
            ui.add(egui::DragValue::new(&mut app.config.logging.max_files).range(1..=365))
                .on_hover_text("按天滚动，超出后删除最旧的文件");
            ui.add_space(Space::MD);
            widgets::section_label(ui, "界面缓冲");
            ui.add(
                egui::DragValue::new(&mut app.config.logging.ui_buffer_lines)
                    .range(200..=50_000)
                    .suffix(" 行"),
            )
            .on_hover_text("日志页在内存中保留的行数（重启后生效）");
        });
    });
}

/// Opens a folder picker and routes the choice to a config field.
fn pick_folder(app: &App, state: &mut State, target: &'static str) {
    let (tx, rx) = mpsc::channel();
    state.pick_rx = Some(rx);
    state.pick_target = Some(target);
    app.spawn_blocking(
        move || rfd::FileDialog::new().pick_folder(),
        move |choice| {
            let _ = tx.send(choice);
        },
    );
}

/// Truncates a SHA-256 digest for display.
fn short_digest(digest: &str) -> String {
    if digest.trim().is_empty() {
        return "（空）".to_string();
    }
    if digest.len() <= 16 {
        return digest.to_string();
    }
    format!("{}…{}", &digest[..8], &digest[digest.len() - 4..])
}

/// Draws page dialogs: remove-user and remove-key confirmations.
pub fn dialogs(app: &mut App, ctx: &egui::Context) {
    app.with_settings(|state, app| {
        if let Some(index) = state.confirm_remove_user {
            let name = app
                .config
                .server
                .users
                .get(index)
                .map(|user| user.name.clone())
                .unwrap_or_else(|| "该用户".to_string());
            let body = format!("确定要从配置中移除用户「{name}」吗？保存后该用户将无法登录。");
            let outcome = widgets::confirm_modal(
                ctx,
                widgets::Confirm {
                    id: "settings.confirm.user",
                    title: "移除用户",
                    body: &body,
                    confirm: "移除",
                    danger: true,
                },
            );
            match outcome {
                widgets::ConfirmOutcome::Accepted => {
                    if index < app.config.server.users.len() {
                        app.config.server.users.remove(index);
                    }
                    state.confirm_remove_user = None;
                    app.toasts.info("已移除用户（记得保存）");
                }
                widgets::ConfirmOutcome::Cancelled => state.confirm_remove_user = None,
                widgets::ConfirmOutcome::Pending => {}
            }
        }

        if let Some(index) = state.confirm_remove_key {
            let name = app
                .config
                .server
                .api_keys
                .get(index)
                .map(|key| key.name.clone())
                .unwrap_or_else(|| "该密钥".to_string());
            let body = format!("确定要从配置中删除密钥「{name}」吗？保存后该密钥立即失效。");
            let outcome = widgets::confirm_modal(
                ctx,
                widgets::Confirm {
                    id: "settings.confirm.key",
                    title: "移除 API 密钥",
                    body: &body,
                    confirm: "删除",
                    danger: true,
                },
            );
            match outcome {
                widgets::ConfirmOutcome::Accepted => {
                    if index < app.config.server.api_keys.len() {
                        app.config.server.api_keys.remove(index);
                    }
                    state.confirm_remove_key = None;
                    app.toasts.info("已删除密钥（记得保存）");
                }
                widgets::ConfirmOutcome::Cancelled => state.confirm_remove_key = None,
                widgets::ConfirmOutcome::Pending => {}
            }
        }
    });
}
