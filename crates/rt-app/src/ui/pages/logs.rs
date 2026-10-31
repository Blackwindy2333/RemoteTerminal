//! Live log viewer plus a tail of the security audit trail.
//!
//! The runtime log buffer is fed by [`rt_core::logging::LogEventSink`]; the audit
//! file is read from disk on demand so multi-megabyte trails never block the UI.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chrono::TimeZone;
use egui::{Color32, RichText, Ui};
use rt_core::config::Config;
use rt_protocol::ws::LogEvent;

use crate::ui::app::App;
use crate::ui::theme::{palette, Palette, Space, Tone, Type};
use crate::ui::widgets::{self, Btn};

/// How many audit lines are loaded at most.
const AUDIT_TAIL_LINES: usize = 200;

/// Which view is active.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Runtime,
    Audit,
}

/// Enabled severity levels.
struct Levels {
    error: bool,
    warn: bool,
    info: bool,
    debug: bool,
    trace: bool,
}

impl Default for Levels {
    fn default() -> Self {
        Self {
            error: true,
            warn: true,
            info: true,
            debug: false,
            trace: false,
        }
    }
}

impl Levels {
    /// Whether a level passes the current filter.
    fn allows(&self, level: &str) -> bool {
        match level.to_ascii_lowercase().as_str() {
            "error" => self.error,
            "warn" | "warning" => self.warn,
            "info" => self.info,
            "debug" => self.debug,
            "trace" => self.trace,
            _ => true,
        }
    }

    /// Label of the strictest enabled level.
    fn summary(&self) -> &'static str {
        if self.error {
            "ERROR 及以上始终显示"
        } else if self.warn {
            "WARN 及以上"
        } else if self.info {
            "INFO 及以上"
        } else if self.debug {
            "DEBUG 及以上"
        } else {
            "仅 TRACE"
        }
    }
}

/// Log page state.
pub struct State {
    tab: Tab,
    buffer: Vec<LogEvent>,
    sink_open: bool,
    rx: Option<tokio::sync::broadcast::Receiver<LogEvent>>,
    levels: Levels,
    search: String,
    autoscroll: bool,
    capacity: usize,
    audit: Vec<String>,
    audit_loaded: Option<Instant>,
    audit_error: Option<String>,
    audit_rx: Option<mpsc::Receiver<Result<Vec<String>, String>>>,
    audit_inflight: bool,
    note: Option<(Instant, String)>,
    dropped: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            tab: Tab::Runtime,
            buffer: Vec::new(),
            sink_open: false,
            rx: None,
            levels: Levels::default(),
            search: String::new(),
            autoscroll: true,
            capacity: 2000,
            audit: Vec::new(),
            audit_loaded: None,
            audit_error: None,
            audit_rx: None,
            audit_inflight: false,
            note: None,
            dropped: 0,
        }
    }
}

impl State {
    /// Pre-fills the in-memory buffer size from the configuration.
    pub fn seed_from_config(&mut self, config: &Config) {
        self.capacity = config.logging.ui_buffer_lines.clamp(200, 50_000);
    }

    /// Drains new log events into the in-memory buffer.
    pub fn poll(&mut self, app: &mut App) {
        if !self.sink_open {
            // Seed with the backlog that the tracing layer already collected.
            self.buffer = app.sink.recent(self.capacity);
            self.dropped = app.sink.dropped();
            self.rx = Some(app.sink.subscribe());
            self.sink_open = true;
        }

        if let Some(rx) = self.rx.as_mut() {
            loop {
                match rx.try_recv() {
                    Ok(event) => {
                        self.buffer.push(LogEvent {
                            ts_ms: event.ts_ms,
                            level: event.level.clone(),
                            target: event.target.clone(),
                            message: event.message.clone(),
                            fields: event.fields.clone(),
                        });
                        if self.buffer.len() > self.capacity {
                            let excess = self.buffer.len() - self.capacity;
                            self.buffer.drain(0..excess);
                        }
                    }
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                        self.dropped = self.dropped.saturating_add(1);
                        continue;
                    }
                    Err(_) => break,
                }
            }
        }

        // Pull the audit tail result, if a read is in flight.
        if let Some(rx) = self.audit_rx.as_ref() {
            while let Ok(result) = rx.try_recv() {
                self.audit_inflight = false;
                match result {
                    Ok(lines) => {
                        self.audit = lines;
                        self.audit_error = None;
                        self.audit_loaded = Some(Instant::now());
                    }
                    Err(err) => self.audit_error = Some(err),
                }
            }
        }
        if self.audit_inflight {
            app.ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    /// Reloads the audit tail from disk.
    fn load_audit(&mut self, app: &App) {
        if self.audit_inflight {
            return;
        }
        let path = app.paths.audit_file.clone();
        let (tx, rx) = mpsc::channel();
        self.audit_rx = Some(rx);
        self.audit_inflight = true;
        app.spawn_blocking(move || read_tail(&path, AUDIT_TAIL_LINES), move |result| {
            let _ = tx.send(result);
        });
    }

    /// Rows that pass the current filter.
    fn visible(&self) -> Vec<&LogEvent> {
        let needle = self.search.trim().to_ascii_lowercase();
        self.buffer
            .iter()
            .filter(|event| self.levels.allows(&event.level))
            .filter(|event| {
                needle.is_empty()
                    || event.message.to_ascii_lowercase().contains(&needle)
                    || event.target.to_ascii_lowercase().contains(&needle)
                    || event
                        .fields
                        .as_deref()
                        .map(|f| f.to_ascii_lowercase().contains(&needle))
                        .unwrap_or(false)
            })
            .collect()
    }

    /// Renders the filtered rows into plain text for copy/export.
    fn export_text(&self) -> String {
        let mut out = String::new();
        for event in self.visible() {
            out.push_str(&format_row(event, true));
            out.push('\n');
        }
        out
    }
}

/// Reads the last `count` lines of a file.
fn read_tail(path: &PathBuf, count: usize) -> Result<Vec<String>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("审计日志尚未生成（{}）", path.display()))
        }
        Err(err) => return Err(format!("无法读取审计日志：{err}")),
    };
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    if lines.len() > count {
        lines.drain(0..lines.len() - count);
    }
    Ok(lines)
}

/// Formats a timestamp as `HH:MM:SS.mmm` in local time.
fn timestamp(ts_ms: i64) -> String {
    match chrono::Local.timestamp_millis_opt(ts_ms).single() {
        Some(dt) => dt.format("%H:%M:%S%.3f").to_string(),
        None => format!("{ts_ms}"),
    }
}

/// Colour used for a severity level.
fn level_color(p: &Palette, level: &str) -> Color32 {
    match level.to_ascii_lowercase().as_str() {
        "error" => p.danger,
        "warn" | "warning" => p.warning,
        "info" => p.accent,
        "debug" => p.text_muted,
        _ => p.text_faint,
    }
}

/// Formats one row as a single monospace line.
fn format_row(event: &LogEvent, with_fields: bool) -> String {
    let level = event.level.to_ascii_uppercase();
    let mut line = format!(
        "{} {:<5} {} — {}",
        timestamp(event.ts_ms),
        level,
        event.target,
        event.message
    );
    if with_fields {
        if let Some(fields) = &event.fields {
            line.push_str("  ");
            line.push_str(fields);
        }
    }
    line
}

/// Page entry point.
pub fn ui(app: &mut App, ui: &mut Ui) {
    app.with_logs(|state, app| {
        let p = palette(ui.ctx());
        widgets::page_header(
            ui,
            "日志",
            "运行时日志与安全审计记录；运行时缓冲在内存中，审计记录按需从文件读取。",
        );

        // -- toolbar ---------------------------------------------------------
        widgets::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::section_label(ui, "级别");
                widgets::chip(ui, "logs.err", "ERROR", &mut state.levels.error);
                widgets::chip(ui, "logs.warn", "WARN", &mut state.levels.warn);
                widgets::chip(ui, "logs.info", "INFO", &mut state.levels.info);
                widgets::chip(ui, "logs.debug", "DEBUG", &mut state.levels.debug);
                widgets::chip(ui, "logs.trace", "TRACE", &mut state.levels.trace);
                ui.add_space(Space::MD);
                ui.add(
                    egui::TextEdit::singleline(&mut state.search)
                        .hint_text("搜索消息 / 模块 / 字段")
                        .desired_width(220.0),
                )
                .on_hover_text("在当前缓冲中按关键字过滤，大小写不敏感");
            });
            ui.add_space(Space::SM);
            ui.horizontal_wrapped(|ui| {
                let mut auto = state.autoscroll;
                widgets::toggle_switch(
                    ui,
                    "logs.autoscroll",
                    &mut auto,
                    "开启后日志视图始终跟随最新一条",
                );
                ui.label(
                    RichText::new("自动滚动")
                        .size(Type::CAPTION)
                        .color(p.text_muted),
                );
                state.autoscroll = auto;

                ui.add_space(Space::MD);
                let shown = state.visible().len();
                widgets::badge(
                    ui,
                    &format!("{shown} / {} 条", state.buffer.len()),
                    Tone::Neutral,
                );
                if state.dropped > 0 {
                    widgets::badge(ui, &format!("丢弃 {}", state.dropped), Tone::Warning);
                }
                ui.add_space(Space::SM);
                widgets::caption(ui, state.levels.summary());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::button(
                        ui,
                        Btn::new("logs.export", "导出", "把当前过滤结果写入日志目录"),
                    )
                    .clicked()
                    {
                        let text = state.export_text();
                        export(app, &text);
                    }
                    if widgets::button(ui, Btn::new("logs.copy", "复制", "复制当前过滤结果到剪贴板"))
                        .clicked()
                    {
                        let text = state.export_text();
                        ui.ctx().copy_text(text);
                        app.toasts.info("已复制当前日志视图");
                    }
                    if widgets::button(
                        ui,
                        Btn::new("logs.clear", "清空缓冲", "只清空界面缓冲，不影响磁盘日志文件")
                            .ghost(),
                    )
                    .clicked()
                    {
                        state.buffer.clear();
                        app.sink.clear();
                        state.note = Some((Instant::now(), "已清空界面日志缓冲".to_string()));
                    }
                });
            });
            if state.tab == Tab::Audit {
                if let Some(error) = &state.audit_error {
                    widgets::error_banner(ui, error);
                }
            }
            if let Some((at, note)) = &state.note {
                if at.elapsed() < Duration::from_secs(8) {
                    widgets::note_banner(ui, note);
                }
            }
        });

        // -- tabs ------------------------------------------------------------
        ui.add_space(Space::MD);
        let mut tab_label = if state.tab == Tab::Runtime {
            "runtime".to_string()
        } else {
            "audit".to_string()
        };
        let mut switch: Option<Tab> = None;
        ui.horizontal(|ui| {
            widgets::segmented(
                ui,
                "logs.tab",
                &[("runtime", "实时日志"), ("audit", "审计日志")],
                &mut tab_label,
            );
            switch = Some(if tab_label == "audit" {
                Tab::Audit
            } else {
                Tab::Runtime
            });
            if state.tab == Tab::Audit {
                ui.add_space(Space::SM);
                widgets::caption(ui, &format!("{}", app.paths.audit_file.display()));
                if widgets::button(
                    ui,
                    Btn::new("logs.audit.refresh", "重新读取", "重新读取审计文件末尾 200 行")
                        .small()
                        .ghost(),
                )
                .clicked()
                {
                    state.load_audit(app);
                }
                if state.audit_inflight {
                    widgets::spinner_row(ui, "读取中…");
                }
            }
        });
        if let Some(target) = switch {
            if target != state.tab {
                state.tab = target;
                if target == Tab::Audit {
                    state.load_audit(app);
                }
            }
        }
        ui.add_space(Space::SM);

        match state.tab {
            Tab::Runtime => runtime_view(ui, state, &p),
            Tab::Audit => audit_view(ui, state, &p),
        }

        if state.tab == Tab::Audit && state.audit_loaded.is_none() && !state.audit_inflight {
            state.load_audit(app);
        }
    });
}

/// The live, filterable log list.
fn runtime_view(ui: &mut Ui, state: &mut State, p: &Palette) {
    if state.buffer.is_empty() {
        widgets::empty_state(
            ui,
            "📜",
            "还没有日志",
            "运行命令、连接服务器或操作文件后，这里会显示对应的日志行。",
            None,
        );
        return;
    }
    let rows: Vec<LogEvent> = state.visible().into_iter().cloned().collect();
    if rows.is_empty() {
        widgets::empty_state(
            ui,
            "🔍",
            "没有匹配的日志",
            "尝试放宽级别过滤或清空搜索关键字。",
            None,
        );
        return;
    }

    let height = (ui.available_height() - 16.0).max(240.0);
    egui::ScrollArea::vertical()
        .id_salt("logs.runtime")
        .auto_shrink([false, false])
        .stick_to_bottom(state.autoscroll)
        .max_height(height)
        .show(ui, |ui| {
            for event in &rows {
                let color = level_color(p, &event.level);
                let text = format_row(event, true);
                ui.add(
                    egui::Label::new(RichText::new(text).monospace().size(Type::MONO).color(color))
                        .selectable(true),
                );
            }
        });
    if state.autoscroll {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// The audit file tail.
fn audit_view(ui: &mut Ui, state: &State, p: &Palette) {
    if state.audit.is_empty() {
        widgets::empty_state(
            ui,
            "🛡",
            "没有审计记录",
            "启用审计（logging.audit = true）后，登录、命令执行与文件操作都会记录在这里。",
            None,
        );
        return;
    }
    let height = (ui.available_height() - 16.0).max(240.0);
    egui::ScrollArea::vertical()
        .id_salt("logs.audit")
        .auto_shrink([false, false])
        .stick_to_bottom(state.autoscroll)
        .max_height(height)
        .show(ui, |ui| {
            for line in &state.audit {
                let denied = line.contains("denied") || line.contains("failed");
                let color = if denied { p.danger } else { p.text_muted };
                ui.add(
                    egui::Label::new(
                        RichText::new(line.clone())
                            .monospace()
                            .size(Type::MONO)
                            .color(color),
                    )
                    .selectable(true),
                );
            }
        });
}

/// Writes the current view into the log directory.
fn export(app: &mut App, text: &str) {
    let dir = app.paths.logs_dir.clone();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let path = dir.join(format!("ui-export-{stamp}.log"));
    let body = if text.is_empty() {
        "（当前过滤结果为空）\n".to_string()
    } else {
        text.to_string()
    };
    let display = path.display().to_string();
    app.spawn_blocking(
        move || -> Result<(), String> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| format!("无法创建目录：{err}"))?;
            }
            std::fs::write(&path, body).map_err(|err| format!("写入失败：{err}"))
        },
        |_result| {},
    );
    app.set_status(format!("已导出到 {display}"));
    app.toasts.success(format!("已导出到 {display}"));
}

/// Draws page dialogs (none for this page).
pub fn dialogs(_app: &mut App, _ctx: &egui::Context) {}
