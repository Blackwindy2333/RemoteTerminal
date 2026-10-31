//! 命令 — remote shell with live WebSocket streaming and a one-shot fallback.

use std::sync::mpsc;
use std::time::Instant;

use egui::{Align, Layout, RichText, TextEdit, Ui};
use rt_client::ws::spawn_session;
use rt_core::config::Config;
use rt_protocol::exec::{ExecRequest, OutputStream, ShellKind};
use rt_protocol::ws::{WsClientMessage, WsServerMessage};

use crate::ui::app::{describe_error, App};
use crate::ui::theme::{palette, Space, Tone, Type};
use crate::ui::widgets::{self, Btn, OutputKind, OutputLine};

/// Console line budget; older lines are dropped from the front.
const MAX_LINES: usize = 4000;
/// How many commands are kept in the quick-recall list.
const HISTORY: usize = 20;

/// Result summary of the last finished command.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// Process exit code (`-1` when the shell could not run).
    pub code: i32,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// The server killed the process at the timeout.
    pub timed_out: bool,
    /// Output was cut at the configured byte limit.
    pub truncated: bool,
    /// The command was cancelled by the user.
    pub cancelled: bool,
}

/// One recalled command.
#[derive(Clone, Debug)]
struct HistoryItem {
    command: String,
    shell: String,
    at: String,
    code: Option<i32>,
}

/// Events delivered from the streaming task to the UI thread.
enum Event {
    /// A raw WebSocket message.
    Ws(WsServerMessage),
    /// The socket closed (`None` = clean shutdown, `Some` = reason).
    Closed(Option<String>),
    /// Result of the non-streaming fallback.
    Fallback(Box<Result<rt_protocol::exec::ExecResult, String>>),
}

/// Page state for 命令.
pub struct State {
    /// Selected shell name (`pwsh` / `powershell` / `cmd`).
    pub shell_name: String,
    /// Working directory override.
    pub cwd: String,
    /// Timeout in seconds; `0` keeps the server default.
    pub timeout_secs: u32,
    /// The command being edited.
    pub command: String,
    /// Console contents.
    pub output: Vec<OutputLine>,
    /// A command is running (or waiting for its final frame).
    pub running: bool,
    /// Cancellation requested but not yet acknowledged.
    pub cancelling: bool,
    /// Identifier of the current stream.
    stream_id: u64,
    /// Sender half of the live session, kept so we can cancel.
    ws_tx: Option<tokio::sync::mpsc::UnboundedSender<WsClientMessage>>,
    /// Receiver for streaming/fallback events.
    rx: Option<mpsc::Receiver<Event>>,
    /// Summary of the last finished command.
    pub outcome: Option<Outcome>,
    /// Recent commands, newest last.
    history: Vec<HistoryItem>,
    /// Keep the console pinned to the newest line.
    pub auto_scroll: bool,
    /// Set when the socket path failed and the fallback was used.
    pub fallback_note: Option<String>,
    /// Local start time, used for the elapsed display.
    started: Option<Instant>,
    /// Remote pid, when the server reported it.
    pub pid: Option<u32>,
    /// Whether this run produced any streamed output yet.
    streamed: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            shell_name: "pwsh".to_string(),
            cwd: String::new(),
            timeout_secs: 0,
            command: String::new(),
            output: Vec::new(),
            running: false,
            cancelling: false,
            stream_id: 0,
            ws_tx: None,
            rx: None,
            outcome: None,
            history: Vec::new(),
            auto_scroll: true,
            fallback_note: None,
            started: None,
            pid: None,
            streamed: false,
        }
    }
}

impl State {
    /// Pre-fills defaults from the configuration.
    pub fn seed_from_config(&mut self, config: &Config) {
        if ShellKind::parse_name(&config.client.default_shell).is_some() {
            self.shell_name = config.client.default_shell.clone();
        }
        self.cwd = config.server.workspace.root.display().to_string();
        self.timeout_secs = config.server.exec_timeout_secs.min(3600) as u32;
    }

    /// Drops the live session (called by the shell on disconnect).
    pub fn close_ws(&mut self) {
        if let Some(tx) = self.ws_tx.take() {
            let _ = tx.send(WsClientMessage::Unsubscribe { id: self.stream_id });
        }
        self.rx = None;
        self.running = false;
        self.cancelling = false;
    }

    /// Drains streamed output.
    pub fn poll(&mut self, app: &mut App) {
        let mut events = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }
        let mut fallback = false;
        for event in events {
            match event {
                Event::Ws(message) => {
                    self.streamed = true;
                    match message {
                        WsServerMessage::ExecStarted { pid, shell, .. } => {
                            self.pid = pid;
                            widgets::push_output(
                                &mut self.output,
                                OutputKind::Notice,
                                &format!(
                                    "已启动 {shell}{}",
                                    pid.map(|p| format!("（pid {p}）")).unwrap_or_default()
                                ),
                                MAX_LINES,
                            );
                        }
                        WsServerMessage::ExecOutput { stream, data, .. } => {
                            self.streamed = true;
                            let kind = match stream {
                                OutputStream::Stdout => OutputKind::Stdout,
                                OutputStream::Stderr => OutputKind::Stderr,
                                OutputStream::Notice => OutputKind::Notice,
                            };
                            widgets::push_output(&mut self.output, kind, &data, MAX_LINES);
                        }
                        WsServerMessage::ExecFinished { summary, .. } => {
                            self.running = false;
                            self.cancelling = false;
                            self.ws_tx = None;
                            self.rx = None;
                            let outcome = Outcome {
                                code: summary.exit_code,
                                duration_ms: summary.duration_ms,
                                timed_out: summary.timed_out,
                                truncated: summary.truncated,
                                cancelled: summary.cancelled.unwrap_or(false),
                            };
                            if let Some(item) = self.history.last_mut() {
                                item.code = Some(outcome.code);
                            }
                            widgets::push_output(
                                &mut self.output,
                                OutputKind::Notice,
                                &format!(
                                    "{} · 退出码 {} · 用时 {}",
                                    if outcome.cancelled { "已取消" } else { "执行结束" },
                                    outcome.code,
                                    rt_core::util::format_duration_ms(outcome.duration_ms)
                                ),
                                MAX_LINES,
                            );
                            self.outcome = Some(outcome);
                        }
                        WsServerMessage::Error { error, .. } => {
                            self.running = false;
                            self.cancelling = false;
                            self.ws_tx = None;
                            self.rx = None;
                            self.fallback_note = None;
                            app.toasts.error(format!("执行失败：{}", error.message));
                        }
                        WsServerMessage::Accepted { .. } | WsServerMessage::Pong { .. } => {}
                        _ => {}
                    }
                }
                Event::Closed(reason) => {
                    self.ws_tx = None;
                    self.rx = None;
                    if self.running && !self.streamed {
                        // The socket never delivered anything: retry over HTTP.
                        fallback = true;
                    } else if self.running {
                        self.running = false;
                        self.cancelling = false;
                        let detail = reason.unwrap_or_else(|| "连接被关闭".to_string());
                        widgets::push_output(
                            &mut self.output,
                            OutputKind::Notice,
                            &format!("实时连接中断：{detail}"),
                            MAX_LINES,
                        );
                        app.toasts.warn(format!("实时连接中断：{detail}"));
                    }
                }
                Event::Fallback(result) => {
                    self.running = false;
                    self.cancelling = false;
                    self.pid = None;
                    match *result {
                        Ok(result) => {
                            if !result.stdout.is_empty() {
                                widgets::push_output(
                                    &mut self.output,
                                    OutputKind::Stdout,
                                    &result.stdout,
                                    MAX_LINES,
                                );
                            }
                            if !result.stderr.is_empty() {
                                widgets::push_output(
                                    &mut self.output,
                                    OutputKind::Stderr,
                                    &result.stderr,
                                    MAX_LINES,
                                );
                            }
                            let outcome = Outcome {
                                code: result.exit_code,
                                duration_ms: result.duration_ms,
                                timed_out: result.timed_out,
                                truncated: result.truncated,
                                cancelled: false,
                            };
                            if let Some(item) = self.history.last_mut() {
                                item.code = Some(outcome.code);
                            }
                            widgets::push_output(
                                &mut self.output,
                                OutputKind::Notice,
                                &format!(
                                    "退出码 {} · 用时 {}",
                                    outcome.code,
                                    rt_core::util::format_duration_ms(outcome.duration_ms)
                                ),
                                MAX_LINES,
                            );
                            self.outcome = Some(outcome);
                        }
                        Err(err) => {
                            widgets::push_output(
                                &mut self.output,
                                OutputKind::Stderr,
                                &err,
                                MAX_LINES,
                            );
                            app.toasts.error(format!("执行失败：{err}"));
                        }
                    }
                }
            }
        }
        if fallback {
            self.spawn_fallback(app);
        }
    }

    /// Builds the request described by the form.
    fn build_request(&self) -> Result<ExecRequest, String> {
        let shell = ShellKind::parse_name(&self.shell_name).unwrap_or_default();
        let mut request = ExecRequest::new(shell, self.command.clone());
        let cwd = self.cwd.trim();
        if !cwd.is_empty() {
            request.cwd = Some(cwd.to_string());
        }
        if self.timeout_secs > 0 {
            request.timeout_ms = Some(self.timeout_secs as u64 * 1000);
        }
        request.validate()?;
        Ok(request)
    }

    /// Starts a command over the live WebSocket session.
    pub fn run(&mut self, app: &mut App) {
        if self.running {
            app.toasts.warn("已有命令在执行，请先取消或等待结束");
            return;
        }
        if self.command.trim().is_empty() {
            app.toasts.warn("请输入要执行的命令");
            return;
        }
        let Some(client) = app.client() else {
            app.toasts.error("尚未连接服务器");
            return;
        };
        let request = match self.build_request() {
            Ok(request) => request,
            Err(err) => {
                app.toasts.error(format!("命令参数无效：{err}"));
                return;
            }
        };

        self.output.clear();
        self.outcome = None;
        self.pid = None;
        self.streamed = false;
        self.cancelling = false;
        self.fallback_note = None;
        self.running = true;
        self.started = Some(Instant::now());
        self.stream_id = self.stream_id.wrapping_add(1).max(1);
        let id = self.stream_id;
        self.history.push(HistoryItem {
            command: self.command.clone(),
            shell: self.shell_name.clone(),
            at: rt_core::util::now_rfc3339(),
            code: None,
        });
        while self.history.len() > HISTORY {
            self.history.remove(0);
        }

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        let session = spawn_session(client);
        self.ws_tx = Some(session.outbound.clone());
        app.spawn_task(async move {
            let mut session = session;
            session.send(WsClientMessage::Exec { id, request });
            // `send` is fire-and-forget; a dead socket only shows up as a close.
            if session.is_closed() {
                let _ = tx.send(Event::Closed(
                    session
                        .close_reason()
                        .or_else(|| Some("无法建立实时连接".to_string())),
                ));
                return;
            }
            while let Some(message) = session.inbound.recv().await {
                if tx.send(Event::Ws(message)).is_err() {
                    break;
                }
            }
            let reason = session.close_reason();
            let _ = tx.send(Event::Closed(reason));
            session.shutdown();
        });
    }

    /// Runs the command with the plain HTTP endpoint (no live streaming).
    fn spawn_fallback(&mut self, app: &mut App) {
        let Some(client) = app.client() else { return };
        let request = match self.build_request() {
            Ok(request) => request,
            Err(err) => {
                app.toasts.error(format!("命令参数无效：{err}"));
                self.running = false;
                return;
            }
        };
        self.ws_tx = None;
        self.fallback_note = Some("实时连接不可用，已改用一次性执行（输出在结束后返回）".to_string());
        app.toasts.warn("实时连接不可用，已改用一次性执行");
        widgets::push_output(
            &mut self.output,
            OutputKind::Notice,
            "实时连接不可用，改用一次性执行（输出不再逐行返回）",
            MAX_LINES,
        );
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.running = true;
        app.spawn_task(async move {
            let result = match client.exec(&request).await {
                Ok(result) => Ok(result),
                Err(err) => Err(describe_error(&err)),
            };
            let _ = tx.send(Event::Fallback(Box::new(result)));
        });
    }

    /// Asks the server to cancel the running command.
    pub fn cancel(&mut self, app: &mut App) {
        if !self.running || self.cancelling {
            return;
        }
        match &self.ws_tx {
            Some(tx) => {
                if tx
                    .send(WsClientMessage::Cancel { id: self.stream_id })
                    .is_ok()
                {
                    self.cancelling = true;
                    app.toasts.info("已请求取消");
                } else {
                    self.running = false;
                    app.toasts.warn("取消请求无法送达，连接可能已断开");
                }
            }
            None => {
                self.running = false;
                app.toasts.warn("当前命令无法取消（非流式执行）");
            }
        }
    }
}

/// Draws the page.
pub fn ui(app: &mut App, ui: &mut Ui) {
    widgets::page_header(
        ui,
        "命令",
        "在远端执行 PowerShell 命令；输出通过 WebSocket 实时返回",
    );

    if !app.is_online() {
        offline(ui);
        return;
    }

    // Ctrl+Enter runs the command from anywhere on the page.
    let run_pressed = ui
        .input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::Enter));
    let mut run_now = false;
    let mut cancel_now = false;
    let mut recall: Option<String> = None;

    {
        let p = palette(ui.ctx());
        let state = &mut app.exec;
        widgets::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("解释器").size(Type::CAPTION).color(p.text_muted));
                widgets::segmented(
                    ui,
                    "exec.shell",
                    &[
                        ("pwsh", "pwsh 7"),
                        ("powershell", "PowerShell 5"),
                        ("cmd", "cmd"),
                    ],
                    &mut state.shell_name,
                );
                ui.add_space(Space::MD);
                ui.label(RichText::new("工作目录").size(Type::CAPTION).color(p.text_muted));
                ui.add(
                    TextEdit::singleline(&mut state.cwd)
                        .desired_width(260.0)
                        .hint_text("留空则使用服务器工作区"),
                )
                .on_hover_text("远端工作目录，接受绝对路径或工作区相对路径");
                ui.add_space(Space::MD);
                ui.label(RichText::new("超时").size(Type::CAPTION).color(p.text_muted));
                ui.add(
                    egui::DragValue::new(&mut state.timeout_secs)
                        .range(0..=3600)
                        .speed(5.0)
                        .suffix(" 秒"),
                )
                .on_hover_text("0 表示使用服务器默认超时");
            });
            ui.add_space(Space::SM);

            let editor = ui.add(
                TextEdit::multiline(&mut state.command)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .font(Type::mono())
                    .hint_text("输入命令，例如 Get-Process | Sort-Object WS -Descending | Select -First 10")
                    .lock_focus(true),
            );
            editor.on_hover_text("Ctrl+Enter 直接执行");

            ui.add_space(Space::SM);
            ui.horizontal(|ui| {
                if widgets::button(
                    ui,
                    Btn::new("exec.run", "运行", "执行上面的命令（Ctrl+Enter）")
                        .primary()
                        .enabled(!state.running),
                )
                .clicked()
                {
                    run_now = true;
                }
                if widgets::button(
                    ui,
                    Btn::new("exec.cancel", "取消", "请求服务器终止正在运行的命令")
                        .danger()
                        .enabled(state.running && !state.cancelling),
                )
                .clicked()
                {
                    cancel_now = true;
                }
                if widgets::button(ui, Btn::new("exec.clear", "清空", "清空输出与状态"))
                    .clicked()
                {
                    state.output.clear();
                    state.outcome = None;
                    state.fallback_note = None;
                }
                if state.running {
                    widgets::spinner_row(ui, "执行中…");
                }
                if let (Some(started), true) = (state.started, state.running) {
                    widgets::caption(ui, &format!("已运行 {:.1}s", started.elapsed().as_secs_f32()));
                }
            });
            if let Some(note) = &state.fallback_note {
                ui.add_space(Space::SM);
                widgets::note_banner(ui, note);
            }
        });
    }

    if run_now || run_pressed {
        app.with_exec(|state, app| state.run(app));
    }
    if cancel_now {
        app.with_exec(|state, app| state.cancel(app));
    }

    ui.add_space(Space::MD);

    // Output card: badges + console.
    let p = palette(ui.ctx());
    let outcome = app.exec.outcome.clone();
    let running = app.exec.running;
    let pid = app.exec.pid;
    let mut clear = false;
    let mut copy_all = false;
    {
        let state = &mut app.exec;
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("输出").size(Type::HEADING).strong().color(p.text));
                match &outcome {
                    Some(outcome) if outcome.cancelled => {
                        widgets::badge(ui, "已取消", Tone::Warning);
                    }
                    Some(outcome) if outcome.code == 0 => {
                        widgets::badge(ui, "退出码 0", Tone::Success);
                    }
                    Some(outcome) => {
                        widgets::badge(ui, &format!("退出码 {}", outcome.code), Tone::Danger);
                    }
                    None if running => {
                        widgets::badge(ui, "运行中", Tone::Accent);
                    }
                    None => {}
                }
                if let Some(outcome) = &outcome {
                    ui.label(
                        RichText::new(rt_core::util::format_duration_ms(outcome.duration_ms))
                            .size(Type::CAPTION)
                            .color(p.text_muted),
                    );
                    if outcome.timed_out {
                        widgets::badge(ui, "超时", Tone::Warning);
                    }
                    if outcome.truncated {
                        widgets::badge(ui, "输出被截断", Tone::Warning);
                    }
                }
                if let Some(pid) = pid {
                    ui.label(
                        RichText::new(format!("pid {pid}"))
                            .size(Type::CAPTION)
                            .color(p.text_faint),
                    );
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let mut follow = state.auto_scroll;
                    if widgets::toggle_switch(ui, "exec.follow", &mut follow, "自动滚动到最新输出")
                        .changed()
                    {
                        state.auto_scroll = follow;
                    }
                    ui.label(RichText::new("跟随").size(Type::CAPTION).color(p.text_muted));
                    if widgets::button(
                        ui,
                        Btn::new("exec.copy", "复制全部", "把全部输出复制到剪贴板").small(),
                    )
                    .clicked()
                    {
                        copy_all = true;
                    }
                    if widgets::button(ui, Btn::new("exec.clear2", "清空", "清空输出").small())
                        .clicked()
                    {
                        clear = true;
                    }
                });
            });
            ui.add_space(Space::XS);
            let panel = widgets::code_panel(
                ui,
                "exec.console",
                &state.output,
                ui.available_height().max(220.0).min(420.0),
                state.auto_scroll,
            );
            if panel.copy {
                copy_all = true;
            }
        });
    }
    if copy_all {
        let text = widgets::output_text(&app.exec.output);
        if text.is_empty() {
            app.toasts.info("没有可复制的输出");
        } else {
            app.ctx.copy_text(text);
            app.toasts.success("输出已复制");
        }
    }
    if clear {
        app.exec.output.clear();
    }

    ui.add_space(Space::MD);
    history_card(app, ui, &mut recall);
    if let Some(command) = recall {
        app.exec.command = command;
    }
}

/// Hint shown when no server is attached.
fn offline(ui: &mut Ui) {
    widgets::empty_state(
        ui,
        "⌘",
        "尚未连接",
        "先在总览页连接到服务器，然后就能在这里执行命令。",
        Some(("返回总览", "切换到总览页的连接表单")),
    );
}

fn history_card(app: &mut App, ui: &mut Ui, recall: &mut Option<String>) {
    let p = palette(ui.ctx());
    let items = app.exec.history.clone();
    widgets::card(ui, |ui| {
        ui.label(
            RichText::new("最近命令")
                .size(Type::HEADING)
                .strong()
                .color(p.text),
        );
        ui.add_space(Space::XS);
        if items.is_empty() {
            widgets::caption(ui, "还没有执行过命令");
            return;
        }
        for item in items.iter().rev() {
            ui.horizontal(|ui| {
                let code = item.code;
                if widgets::button(
                    ui,
                    Btn::new(
                        ("exec.hist", &item.at),
                        &truncate(&item.command, 72),
                        "把这条命令填回输入框",
                    )
                    .small()
                    .ghost(),
                )
                .clicked()
                {
                    *recall = Some(item.command.clone());
                }
                match code {
                    Some(0) => {
                        widgets::badge(ui, "0", Tone::Success);
                    }
                    Some(code) => {
                        widgets::badge(ui, &code.to_string(), Tone::Danger);
                    }
                    None => {}
                }
                ui.label(
                    RichText::new(format!("{} · {}", item.shell, item.at))
                        .size(Type::CAPTION)
                        .color(p.text_faint),
                );
            });
        }
    });
}

fn truncate(text: &str, max: usize) -> String {
    let mut out: String = text.lines().next().unwrap_or("").chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

/// Draws page dialogs (none for this page).
pub fn dialogs(_app: &mut App, _ctx: &egui::Context) {}
