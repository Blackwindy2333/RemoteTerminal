//! Remote file browser page.
//!
//! The browser is deliberately fail-visible: every scope violation and every
//! permission error reported by the server is rendered next to the entry that
//! caused it instead of being swallowed.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{RichText, Ui};
use rt_protocol::fs::{
    DeleteRequest, FsRoots, ListDirResponse, MkdirRequest, ReadFileResult, RenameRequest,
};
use rt_protocol::Scope;

use crate::ui::app::App;
use crate::ui::theme::{self, palette, Space, Tone, Type};
use crate::ui::widgets::{self, Btn, Confirm, ConfirmOutcome, OutputKind, OutputLine};

/// How many bytes of a remote file we fetch for the inline preview.
const PREVIEW_BYTES: u64 = 96 * 1024;
/// Directory listings larger than this are truncated client-side as well.
const MAX_ROWS: usize = 4000;

/// Column the listing can be sorted by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Name,
    Size,
    Modified,
    Attrs,
}

impl SortKey {
    fn label(self) -> &'static str {
        match self {
            SortKey::Name => "名称",
            SortKey::Size => "大小",
            SortKey::Modified => "修改时间",
            SortKey::Attrs => "属性",
        }
    }
}

/// A file opened in the inline preview pane.
struct Preview {
    path: String,
    text: String,
    size: u64,
    truncated: bool,
    binary: bool,
}

/// Result of a directory mutation (mkdir / rename / delete / upload).
struct OpDone {
    note: String,
}

/// Messages produced by background file jobs.
enum Event {
    Roots(Result<FsRoots, String>),
    Listed(Box<Result<ListDirResponse, String>>),
    Op(Box<Result<OpDone, String>>),
    Preview(Box<Result<ReadFileResult, String>>),
    Downloaded(Result<PathBuf, String>),
}

/// Interaction state of the file browser.
pub struct State {
    /// Current directory (server path; `""` means the roots view).
    path: String,
    /// Text inside the path bar.
    input: String,
    listing: Option<ListDirResponse>,
    roots: Option<FsRoots>,
    loading: bool,
    error: Option<String>,
    sort: SortKey,
    ascending: bool,
    selected: Option<String>,
    preview: Option<Preview>,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    /// Files picked by the local upload dialog.
    pick_tx: mpsc::Sender<Option<PathBuf>>,
    pick_rx: mpsc::Receiver<Option<PathBuf>>,
    /// Delete confirmation payload.
    pending_delete: Option<Vec<String>>,
    /// Rename dialog: (source path, editable name).
    rename: Option<(String, String)>,
    /// New-folder dialog buffer.
    new_folder: Option<String>,
    /// Last successful operation, shown as a note in the toolbar.
    note: Option<(String, Instant)>,
    /// Set while a local file dialog is open.
    picking: bool,
}

impl Default for State {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let (pick_tx, pick_rx) = mpsc::channel();
        Self {
            path: String::new(),
            input: String::new(),
            listing: None,
            roots: None,
            loading: false,
            error: None,
            sort: SortKey::Name,
            ascending: true,
            selected: None,
            preview: None,
            tx,
            rx,
            pick_tx,
            pick_rx,
            pending_delete: None,
            rename: None,
            new_folder: None,
            note: None,
            picking: false,
        }
    }
}

impl State {
    /// Pre-fills from configuration.
    pub fn seed_from_config(&mut self, _config: &rt_core::config::Config) {}

    /// Called when the connection is dropped.
    pub fn reset_after_disconnect(&mut self) {
        self.listing = None;
        self.roots = None;
        self.preview = None;
        self.selected = None;
        self.error = None;
        self.loading = false;
        self.path.clear();
        self.input.clear();
    }

    /// Drains background results.
    pub fn poll(&mut self, app: &mut App) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Roots(Ok(roots)) => {
                    self.roots = Some(roots);
                }
                Event::Roots(Err(err)) => {
                    self.error = Some(err);
                }
                Event::Listed(result) => {
                    self.loading = false;
                    match *result {
                        Ok(listing) => {
                            self.path = listing.path.clone();
                            self.input = listing.path.clone();
                            self.error = None;
                            self.listing = Some(listing);
                        }
                        Err(err) => {
                            self.error = Some(err);
                        }
                    }
                }
                Event::Op(result) => match *result {
                    Ok(done) => {
                        self.note = Some((done.note.clone(), Instant::now()));
                        app.set_status(done.note);
                        self.reload(app);
                    }
                    Err(err) => {
                        self.error = Some(err.clone());
                        app.fail(err);
                    }
                },
                Event::Preview(result) => match *result {
                    Ok(file) => {
                        let binary = file.text.is_none();
                        self.preview = Some(Preview {
                            path: file.path.clone(),
                            text: file
                                .text
                                .unwrap_or_else(|| "（二进制内容，无法以文本预览）".to_string()),
                            size: file.size,
                            truncated: file.truncated,
                            binary,
                        });
                    }
                    Err(err) => {
                        self.error = Some(err.clone());
                        app.fail(err);
                    }
                },
                Event::Downloaded(result) => match result {
                    Ok(path) => {
                        let note = format!("已下载到 {}", path.display());
                        self.note = Some((note.clone(), Instant::now()));
                        app.toasts.success(note);
                    }
                    Err(err) => {
                        self.error = Some(err.clone());
                        app.fail(err);
                    }
                },
            }
        }

        while let Ok(picked) = self.pick_rx.try_recv() {
            self.picking = false;
            if let Some(local) = picked {
                self.upload(app, local);
            }
        }
    }

    /// Loads the roots list once per connection.
    fn ensure_roots(&mut self, app: &App) {
        if self.roots.is_some() || self.loading {
            return;
        }
        let Some(client) = app.client() else { return };
        let tx = self.tx.clone();
        app.spawn_task(async move {
            let result = client.roots().await.map_err(|err| err.message());
            let _ = tx.send(Event::Roots(result));
        });
    }

    /// Reloads the current directory (or the roots view when no path is set).
    pub fn reload(&mut self, app: &App) {
        let Some(client) = app.client() else { return };
        let tx = self.tx.clone();
        if self.path.is_empty() {
            app.spawn_task(async move {
                let result = client.roots().await.map_err(|err| err.message());
                let _ = tx.send(Event::Roots(result));
            });
            return;
        }
        let path = self.path.clone();
        self.loading = true;
        app.spawn_task(async move {
            let result = client.list(&path).await.map_err(|err| err.message());
            let _ = tx.send(Event::Listed(Box::new(result)));
        });
    }

    /// Navigates to `path` (workspace-relative or absolute).
    fn navigate(&mut self, app: &App, path: impl Into<String>) {
        let path = path.into();
        self.path.clone_from(&path);
        self.input.clone_from(&path);
        self.selected = None;
        self.preview = None;
        self.reload(app);
    }

    /// Directory new files land in.
    fn target_dir(&self) -> String {
        if self.path.is_empty() {
            self.roots
                .as_ref()
                .and_then(|r| r.workspace_root.clone())
                .unwrap_or_default()
        } else {
            self.path.clone()
        }
    }

    fn open_preview(&mut self, app: &App, path: String) {
        let Some(client) = app.client() else { return };
        let tx = self.tx.clone();
        app.spawn_task(async move {
            let result = client
                .read_file(&path, None, Some(PREVIEW_BYTES))
                .await
                .map_err(|err| err.message());
            let _ = tx.send(Event::Preview(Box::new(result)));
        });
    }

    fn download(&mut self, app: &mut App, path: String) {
        let Some(client) = app.client() else { return };
        let dir = app.paths.downloads_dir.clone();
        let tx = self.tx.clone();
        app.set_status(format!("正在下载 {path}"));
        app.spawn_task(async move {
            let result = client
                .download_auto(&path, &dir)
                .await
                .map_err(|err| err.message());
            let _ = tx.send(Event::Downloaded(result));
        });
    }

    fn upload(&mut self, app: &mut App, local: PathBuf) {
        let Some(client) = app.client() else { return };
        let Some(name) = local.file_name().map(|n| n.to_string_lossy().to_string()) else {
            app.fail("无法读取所选文件名");
            return;
        };
        let dir = self.target_dir();
        let remote = join_remote(&dir, &name);
        let tx = self.tx.clone();
        app.set_status(format!("正在上传 {name}"));
        app.spawn_task(async move {
            let result = client
                .upload_file(&local, &remote, false, true)
                .await
                .map(|res| OpDone {
                    note: format!("已上传 {} （{}）", name, rt_core::util::format_bytes(res.size)),
                })
                .map_err(|err| err.message());
            let _ = tx.send(Event::Op(Box::new(result)));
        });
    }

    fn mkdir(&mut self, app: &App, name: String) {
        let Some(client) = app.client() else { return };
        let path = join_remote(&self.target_dir(), &name);
        let tx = self.tx.clone();
        app.spawn_task(async move {
            let req = MkdirRequest {
                path,
                create_parents: true,
                allow_existing: false,
            };
            let result = client
                .mkdir(&req)
                .await
                .map(|entry| OpDone {
                    note: format!("已创建文件夹 {}", entry.name),
                })
                .map_err(|err| err.message());
            let _ = tx.send(Event::Op(Box::new(result)));
        });
    }

    fn rename(&mut self, app: &App, from: String, to: String) {
        let Some(client) = app.client() else { return };
        let tx = self.tx.clone();
        let note = format!("已重命名为 {to}");
        app.spawn_task(async move {
            let req = RenameRequest {
                from,
                to,
                overwrite: false,
            };
            let result = client
                .rename(&req)
                .await
                .map(|()| OpDone { note })
                .map_err(|err| err.message());
            let _ = tx.send(Event::Op(Box::new(result)));
        });
    }

    fn delete(&mut self, app: &App, paths: Vec<String>) {
        let Some(client) = app.client() else { return };
        let count = paths.len();
        let tx = self.tx.clone();
        app.spawn_task(async move {
            let req = DeleteRequest {
                paths,
                recursive: true,
                even_if_readonly: false,
            };
            let result = client
                .delete(&req)
                .await
                .map(|res| {
                    let failed = res.failed.len();
                    let note = if failed == 0 {
                        format!("已删除 {count} 项")
                    } else {
                        format!(
                            "已删除 {} 项，{} 项失败：{}",
                            res.deleted.len(),
                            failed,
                            res.failed
                                .iter()
                                .map(|f| format!("{}: {}", f.path, f.message))
                                .collect::<Vec<_>>()
                                .join("；")
                        )
                    };
                    OpDone { note }
                })
                .map_err(|err| err.message());
            let _ = tx.send(Event::Op(Box::new(result)));
        });
    }

    /// Entries sorted according to the current sort key.
    ///
    /// Cloned so the caller can mutate selection state while drawing the table.
    fn sorted_entries(&self) -> Vec<rt_protocol::fs::FsEntry> {
        let Some(listing) = &self.listing else {
            return Vec::new();
        };
        let mut entries: Vec<rt_protocol::fs::FsEntry> = listing.entries.clone();
        entries.sort_by(|a, b| {
            // Directories always come first, like Explorer.
            let dir = b.is_dir.cmp(&a.is_dir);
            if dir != std::cmp::Ordering::Equal {
                return dir;
            }
            let ord = match self.sort {
                SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortKey::Size => a.size.cmp(&b.size),
                SortKey::Modified => a.modified_ms.unwrap_or(0).cmp(&b.modified_ms.unwrap_or(0)),
                SortKey::Attrs => a.attributes.len().cmp(&b.attributes.len()),
            };
            if self.ascending {
                ord
            } else {
                ord.reverse()
            }
        });
        entries.truncate(MAX_ROWS);
        entries
    }
}

/// Joins a remote directory and a child name using the server's separator.
fn join_remote(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return name.to_string();
    }
    if dir.ends_with('\\') || dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

/// Last path component, used for labels and dialogs.
fn leaf(path: &str) -> &str {
    path.rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or(path)
}

/// Page entry point.
pub fn ui(app: &mut App, ui: &mut Ui) {
    if app.client().is_none() {
        offline(ui);
        return;
    }

    app.with_files(|state, app| {
        state.ensure_roots(app);
        let p = palette(ui.ctx());

        ui.horizontal(|ui| {
            ui.label(RichText::new("文件").size(Type::TITLE).strong().color(p.text));
            ui.add_space(Space::SM);
            if let Some(scope) = app.scope() {
                widgets::badge(
                    ui,
                    if scope.is_full() { "完全访问" } else { "工作区" },
                    if scope.is_full() { Tone::Success } else { Tone::Warning },
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if state.loading {
                    widgets::spinner_row(ui, "读取中…");
                }
            });
        });
        ui.add_space(Space::MD);

        // -- toolbar -------------------------------------------------------
        let mut nav_to: Option<String> = None;
        let mut up: Option<String> = None;
        let mut act_upload = false;
        let mut act_mkdir = false;
        let mut act_rename = false;
        let mut act_delete = false;
        let mut act_download = false;

        ui.horizontal(|ui| {
            if widgets::button(
                ui,
                Btn::new("files.up", "↑", "返回上一级目录").small().ghost(),
            )
            .clicked()
            {
                up = state
                    .listing
                    .as_ref()
                    .and_then(|l| l.parent.clone())
                    .or_else(|| Some(String::new()));
            }
            if widgets::button(
                ui,
                Btn::new("files.roots", "根目录", "回到磁盘与工作区列表")
                    .small()
                    .ghost(),
            )
            .clicked()
            {
                nav_to = Some(String::new());
            }

            // Breadcrumb: every segment is clickable.
            let crumb_path = if state.path.is_empty() {
                "全部位置".to_string()
            } else {
                state.path.clone()
            };
            if let Some(target) = widgets::path_breadcrumb(ui, &crumb_path) {
                nav_to = Some(target);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                act_upload = widgets::button(
                    ui,
                    Btn::new("files.upload", "上传", "从本机选择文件上传到当前目录").small(),
                )
                .clicked();
                act_mkdir = widgets::button(
                    ui,
                    Btn::new("files.mkdir", "新建文件夹", "在当前目录创建子文件夹").small(),
                )
                .clicked();
                let has_selection = state.selected.is_some();
                act_download = widgets::button(
                    ui,
                    Btn::new("files.download", "下载", "下载选中文件到本机下载目录")
                        .small()
                        .enabled(has_selection),
                )
                .clicked();
                act_rename = widgets::button(
                    ui,
                    Btn::new("files.rename", "重命名", "重命名选中的条目")
                        .small()
                        .enabled(has_selection),
                )
                .clicked();
                act_delete = widgets::button(
                    ui,
                    Btn::new("files.delete", "删除", "删除选中的条目（需要确认）")
                        .small()
                        .danger()
                        .enabled(has_selection),
                )
                .clicked();
            });
        });

        ui.add_space(Space::SM);

        // -- path input ----------------------------------------------------
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("路径")
                    .size(Type::CAPTION)
                    .color(p.text_muted),
            );
            let edit = ui.add(
                egui::TextEdit::singleline(&mut state.input)
                    .hint_text(r"例如 workspace\sub 或 D:\projects")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if enter {
                nav_to = Some(state.input.trim().to_string());
            }
            edit.on_hover_text("支持工作区相对路径（\\sub\\dir）与绝对路径，回车跳转");
        });

        if let Some((note, at)) = &state.note {
            if at.elapsed() < Duration::from_secs(6) {
                widgets::note_banner(ui, note);
            }
        }
        if let Some(error) = &state.error {
            widgets::error_banner(ui, error);
        }

        ui.add_space(Space::MD);

        // -- body: roots rail + listing ------------------------------------
        let body_height = (ui.available_height() - 220.0).max(240.0);
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(210.0, body_height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    roots_rail(state, ui, &mut nav_to);
                },
            );
            ui.add_space(Space::MD);
            ui.vertical(|ui| {
                if state.path.is_empty() {
                    widgets::empty_state(
                        ui,
                        "🗂",
                        "选择一个位置",
                        "从左侧选择一个磁盘、工作区或常用路径开始浏览",
                        None,
                    );
                } else {
                    listing_table(state, app, ui, body_height, &mut act_download);
                }
            });
        });

        // -- applied actions ------------------------------------------------
        if let Some(target) = nav_to {
            state.navigate(app, target);
        }
        if let Some(parent) = up {
            state.navigate(app, parent);
        }
        if act_upload && !state.picking {
            pick_upload(state, app);
        }
        if act_mkdir {
            state.new_folder = Some(String::new());
        }
        if act_rename {
            if let Some(path) = state.selected.clone() {
                state.rename = Some((path.clone(), leaf(&path).to_string()));
            }
        }
        if act_delete {
            if let Some(path) = state.selected.clone() {
                state.pending_delete = Some(vec![path]);
            }
        }
        if act_download {
            if let Some(path) = state.selected.clone() {
                state.download(app, path);
            }
        }

        // Preview pane sits under the table so long listings stay scannable.
        if let Some(preview) = &state.preview {
            ui.add_space(Space::MD);
            let mut close = false;
            widgets::card_titled(
                ui,
                &format!("预览 · {}", leaf(&preview.path)),
                Some("关闭"),
                |ui, action| {
                    close = *action;
                    widgets::caption(
                        ui,
                        &format!(
                            "{} · {} · {}",
                            rt_core::util::format_bytes(preview.size),
                            if preview.binary {
                                "二进制"
                            } else {
                                "文本"
                            },
                            if preview.truncated {
                                "已截断（仅显示前缀）"
                            } else {
                                "完整"
                            }
                        ),
                    );
                    ui.add_space(Space::SM);
                    let lines: Vec<OutputLine> = preview
                        .text
                        .lines()
                        .take(400)
                        .map(|line| OutputLine {
                            stream: OutputKind::Stdout,
                            text: line.to_string(),
                        })
                        .collect();
                    let _ = widgets::code_panel(ui, "files.preview", &lines, 220.0, false);
                },
            );
            if close {
                state.preview = None;
            }
        }
    });
}

/// Left rail with drives, workspace and quick paths.
fn roots_rail(state: &State, ui: &mut Ui, nav_to: &mut Option<String>) {
    let p = palette(ui.ctx());
    widgets::card(ui, |ui| {
        let Some(roots) = &state.roots else {
            widgets::caption(ui, "正在读取磁盘列表…");
            return;
        };
        widgets::section_label(ui, "工作区");
        match &roots.workspace_root {
            Some(root) => {
                if widgets::link_button(ui, root, "打开服务器工作区根目录").clicked() {
                    *nav_to = Some(root.clone());
                }
            }
            None => widgets::caption(ui, "服务器未配置工作区"),
        }

        if !roots.drives.is_empty() {
            ui.add_space(Space::SM);
            widgets::section_label(ui, "磁盘");
            for drive in &roots.drives {
                let detail = format!(
                    "{} 可用 / {}",
                    rt_core::util::format_bytes(drive.free_bytes),
                    rt_core::util::format_bytes(drive.total_bytes)
                );
                ui.horizontal(|ui| {
                    if widgets::link_button(ui, &drive.path, &detail).clicked() {
                        *nav_to = Some(drive.path.clone());
                    }
                    if let Some(label) = &drive.label {
                        if !label.is_empty() {
                            ui.label(
                                RichText::new(label)
                                    .size(Type::CAPTION)
                                    .color(p.text_faint),
                            );
                        }
                    }
                });
            }
        }

        if !roots.quick_paths.is_empty() {
            ui.add_space(Space::SM);
            widgets::section_label(ui, "常用位置");
            for quick in &roots.quick_paths {
                if widgets::link_button(ui, &quick.label, &quick.path).clicked() {
                    *nav_to = Some(quick.path.clone());
                }
            }
        }

        ui.add_space(Space::SM);
        widgets::caption(
            ui,
            match roots.scope {
                Scope::Full => "完全访问：可浏览整台服务器",
                Scope::Workspace => "工作区范围：仅限服务器工作区目录",
            },
        );
    });
}

/// The sortable directory table.
fn listing_table(state: &mut State, app: &mut App, ui: &mut Ui, height: f32, act_download: &mut bool) {
    let p = palette(ui.ctx());
    let mut enter: Option<String> = None;
    let mut preview: Option<String> = None;
    let download: Option<String> = None;

    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            let name_width = (ui.available_width() - 390.0).max(120.0);
            widgets::table_header_label(ui, "名称");
            ui.allocate_exact_size(egui::vec2((name_width - 40.0).max(0.0), 20.0), egui::Sense::hover());
            header_cell(ui, state, SortKey::Size, 90.0);
            header_cell(ui, state, SortKey::Modified, 150.0);
            header_cell(ui, state, SortKey::Attrs, 150.0);
        });
        widgets::divider(ui);

        egui::ScrollArea::vertical()
            .id_salt("files.listing")
            .max_height(height - 40.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if state.listing.is_none() && !state.loading {
                    widgets::caption(ui, "这个目录是空的");
                }
                let entries = state.sorted_entries();
                if entries.is_empty() && state.listing.is_some() && !state.loading {
                    widgets::caption(ui, "这个目录是空的");
                }
                for entry in entries {
                    let selected = state.selected.as_deref() == Some(entry.path.as_str());
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 28.0),
                        egui::Sense::click(),
                    );
                    let hovered = response.hovered();
                    if selected {
                        ui.painter().rect_filled(rect, theme::Radius::SM, p.accent_soft);
                    } else if hovered {
                        ui.painter().rect_filled(rect, theme::Radius::SM, p.raised);
                    }

                    // Name column with an icon and inline error if present.
                    let icon = if entry.is_dir { "📁" } else { "📄" };
                    let mut x = rect.left() + 6.0;
                    let icon_rect = ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        icon,
                        egui::FontId::proportional(13.0),
                        p.text,
                    );
                    x = icon_rect.right() + 6.0;
                    let name_color = if entry.error.is_some() { p.danger } else { p.text };
                    let name_rect = ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        &entry.name,
                        theme::Type::body(),
                        name_color,
                    );
                    if entry.hidden {
                        ui.painter().text(
                            egui::pos2(name_rect.right() + 8.0, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            "隐藏",
                            theme::Type::caption(),
                            p.text_faint,
                        );
                    }

                    // Size / modified / attributes columns.
                    let size = if entry.is_dir {
                        "—".to_string()
                    } else {
                        rt_core::util::format_bytes(entry.size)
                    };
                    let modified = entry
                        .modified_ms
                        .map(widgets::format_ms)
                        .unwrap_or_else(|| "—".to_string());
                    let attrs = entry.attributes.join(" ");
                    let mut col = rect.right() - 390.0;
                    for (idx, text) in [&size, &modified, &attrs].into_iter().enumerate() {
                        ui.painter().text(
                            egui::pos2(col, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            text,
                            theme::Type::caption(),
                            p.text_muted,
                        );
                        col += if idx == 0 { 90.0 } else { 150.0 };
                    }

                    if response.clicked() {
                        state.selected = Some(entry.path.clone());
                    }
                    if response.double_clicked() {
                        if entry.is_dir {
                            enter = Some(entry.path.clone());
                        } else {
                            preview = Some(entry.path.clone());
                        }
                    }
                    let tip = if entry.is_dir {
                        format!("双击进入 {}", entry.name)
                    } else {
                        format!("双击预览 {}", entry.name)
                    };
                    response.on_hover_text(tip);

                    if let Some(err) = &entry.error {
                        ui.painter().text(
                            egui::pos2(rect.right() - 8.0, rect.center().y),
                            egui::Align2::RIGHT_CENTER,
                            err,
                            theme::Type::caption(),
                            p.danger,
                        );
                    }
                }
                if let Some(listing) = &state.listing {
                    if listing.truncated {
                        ui.add_space(Space::SM);
                        widgets::caption(ui, "目录条目过多，已截断显示");
                    }
                }
            });
    });

    if let Some(path) = enter {
        state.navigate(app, path);
    }
    if let Some(path) = preview {
        state.open_preview(app, path);
    }
    if let Some(path) = download {
        state.download(app, path);
        *act_download = false;
    }
}

/// One clickable, sortable column header.
fn header_cell(ui: &mut Ui, state: &mut State, key: SortKey, width: f32) {
    let p = palette(ui.ctx());
    let marker = if state.sort == key {
        if state.ascending {
            " ▲"
        } else {
            " ▼"
        }
    } else {
        ""
    };
    let text = format!("{}{}", key.label(), marker);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 20.0), egui::Sense::click());
    let color = if state.sort == key { p.text } else { p.text_muted };
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        text,
        theme::Type::caption(),
        color,
    );
    if response.clicked() {
        if state.sort == key {
            state.ascending = !state.ascending;
        } else {
            state.sort = key;
            state.ascending = true;
        }
    }
    response.on_hover_text(format!("按{}排序", key.label()));
}

/// Opens the local file picker off the UI thread.
fn pick_upload(state: &mut State, app: &App) {
    let tx = state.pick_tx.clone();
    state.picking = true;
    app.spawn_blocking(
        move || rfd::FileDialog::new().set_title("选择要上传的文件").pick_file(),
        move |picked| {
            let _ = tx.send(picked);
        },
    );
}

/// Shown when there is no connection.
fn offline(ui: &mut Ui) {
    widgets::empty_state(
        ui,
        "🔌",
        "尚未连接",
        "连接服务器后即可浏览远端文件；前往总览页填写地址与凭据。",
        None,
    );
}

/// Modal dialogs: delete confirmation, rename and new folder.
pub fn dialogs(app: &mut App, ctx: &egui::Context) {
    if app.client().is_none() {
        return;
    }
    app.with_files(|state, app| {
        // -- delete --------------------------------------------------------
        if let Some(paths) = state.pending_delete.clone() {
            let body = if paths.len() == 1 {
                format!("确定要删除 {} 吗？此操作不可撤销。", leaf(&paths[0]))
            } else {
                format!("确定要删除这 {} 个条目吗？此操作不可撤销。", paths.len())
            };
            let outcome = widgets::confirm_modal(
                ctx,
                Confirm {
                    id: "files.delete.confirm",
                    title: "删除",
                    body: &body,
                    confirm: "删除",
                    danger: true,
                },
            );
            match outcome {
                ConfirmOutcome::Accepted => {
                    state.delete(app, paths);
                    state.pending_delete = None;
                }
                ConfirmOutcome::Cancelled => {
                    state.pending_delete = None;
                }
                ConfirmOutcome::Pending => {}
            }
        }

        // -- rename --------------------------------------------------------
        if let Some((from, current)) = state.rename.clone() {
            let mut name = current;
            let mut submit = false;
            let mut cancel = false;
            let modal = egui::Modal::new(egui::Id::unique("files.rename.modal")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.label(RichText::new("重命名").size(Type::HEADING).strong());
                ui.add_space(Space::SM);
                widgets::caption(ui, &from);
                ui.add_space(Space::XS);
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .desired_width(f32::INFINITY)
                        .hint_text("新名称"),
                );
                if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }
                ui.add_space(Space::MD);
                ui.horizontal(|ui| {
                    if widgets::button(
                        ui,
                        Btn::new("files.rename.ok", "确定", "应用新名称").primary(),
                    )
                    .clicked()
                    {
                        submit = true;
                    }
                    if widgets::button(
                        ui,
                        Btn::new("files.rename.cancel", "取消", "放弃重命名").ghost(),
                    )
                    .clicked()
                    {
                        cancel = true;
                    }
                });
            });
            if modal.should_close() {
                cancel = true;
            }
            if submit && !name.trim().is_empty() {
                let dir = from
                    .rfind(['\\', '/'])
                    .map(|idx| from[..idx].to_string())
                    .unwrap_or_default();
                let to = join_remote(&dir, name.trim());
                state.rename(app, from, to);
                state.rename = None;
            } else if cancel {
                state.rename = None;
            } else {
                state.rename = Some((from, name));
            }
        }

        // -- new folder ----------------------------------------------------
        if let Some(current) = state.new_folder.clone() {
            let mut name = current;
            let mut submit = false;
            let mut cancel = false;
            let target = state.target_dir();
            let modal = egui::Modal::new(egui::Id::unique("files.mkdir.modal")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.label(RichText::new("新建文件夹").size(Type::HEADING).strong());
                ui.add_space(Space::SM);
                widgets::caption(ui, &format!("位置：{target}"));
                ui.add_space(Space::XS);
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .desired_width(f32::INFINITY)
                        .hint_text("文件夹名称"),
                );
                if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }
                ui.add_space(Space::MD);
                ui.horizontal(|ui| {
                    if widgets::button(
                        ui,
                        Btn::new("files.mkdir.ok", "创建", "在当前目录创建该文件夹").primary(),
                    )
                    .clicked()
                    {
                        submit = true;
                    }
                    if widgets::button(
                        ui,
                        Btn::new("files.mkdir.cancel", "取消", "放弃创建").ghost(),
                    )
                    .clicked()
                    {
                        cancel = true;
                    }
                });
            });
            if modal.should_close() {
                cancel = true;
            }
            if submit && !name.trim().is_empty() {
                state.mkdir(app, name.trim().to_string());
                state.new_folder = None;
            } else if cancel {
                state.new_folder = None;
            } else {
                state.new_folder = Some(name);
            }
        }
    });
}
