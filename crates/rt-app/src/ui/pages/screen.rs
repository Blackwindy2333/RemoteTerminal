//! Remote screen and window capture page.
//!
//! Previews are fetched as encoded image bytes, decoded with the `image` crate
//! and uploaded into an egui texture. The "live preview" mode runs a repeating
//! tokio task at 1–2 fps and stops itself on the first error.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{RichText, TextureHandle, TextureOptions, Ui};
use rt_protocol::capture::{CaptureRequest, CaptureTarget, ImageFormat, ScreenInfo, WindowInfo};

use crate::ui::app::App;
use crate::ui::theme::{self, palette, Space, Tone, Type};
use crate::ui::widgets::{self, Btn};

/// The last captured frame with its metadata.
struct Frame {
    texture: TextureHandle,
    format: String,
    width: u32,
    height: u32,
    bytes: usize,
    duration_ms: u64,
    target: String,
    resized: bool,
}

/// Content moved from a capture task to the UI thread.
struct Captured {
    target: String,
    format: String,
    width: u32,
    height: u32,
    duration_ms: u64,
    resized: bool,
    rgba: Vec<u8>,
    /// Original encoded bytes, kept so the user can save exactly what arrived.
    encoded: Vec<u8>,
}

/// One live-preview frame.
struct LiveFrame {
    rgba: Vec<u8>,
    width: u32,
    height: u32,
}

/// Messages produced by background capture jobs.
enum Event {
    Screens(Result<Vec<ScreenInfo>, String>),
    Windows(Result<Vec<WindowInfo>, String>),
    Captured(Box<Result<Captured, String>>),
    Live(Box<Result<LiveFrame, String>>),
    Saved(Result<String, String>),
}

/// Screen page state.
pub struct State {
    screens: Vec<ScreenInfo>,
    windows: Vec<WindowInfo>,
    window_filter: String,
    loading_lists: bool,
    error: Option<String>,
    frame: Option<Frame>,
    /// Encoded bytes of `frame`, used by the save buttons.
    encoded: Option<Vec<u8>>,
    target: CaptureTarget,
    target_label: String,
    format: ImageFormat,
    quality: u8,
    max_width: u32,
    live: bool,
    live_generation: u64,
    live_fps: u8,
    live_stop_rx: Option<tokio::sync::watch::Receiver<bool>>,
    live_stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    live_error: Option<(String, Instant)>,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    note: Option<(String, Instant)>,
}

impl Default for State {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            screens: Vec::new(),
            windows: Vec::new(),
            window_filter: String::new(),
            loading_lists: false,
            error: None,
            frame: None,
            encoded: None,
            target: CaptureTarget::Primary,
            target_label: "主显示器".to_string(),
            format: ImageFormat::Png,
            quality: 80,
            max_width: 1920,
            live: false,
            live_generation: 0,
            live_fps: 1,
            live_stop_rx: None,
            live_stop_tx: None,
            live_error: None,
            tx,
            rx,
            note: None,
        }
    }
}

impl State {
    /// Pre-fills capture defaults from the configuration.
    pub fn seed_from_config(&mut self, config: &rt_core::config::Config) {
        if let Some(format) = ImageFormat::parse(&config.client.capture_format) {
            self.format = format;
        }
        self.quality = config.client.capture_quality.clamp(10, 100);
        self.live_fps = config.client.capture_fps.clamp(1, 2);
    }

    /// Called when the connection is dropped.
    pub fn reset_after_disconnect(&mut self) {
        self.screens.clear();
        self.windows.clear();
        self.frame = None;
        self.encoded = None;
        self.error = None;
        self.loading_lists = false;
        self.stop_live();
    }

    /// Drains background results.
    pub fn poll(&mut self, app: &mut App) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Screens(result) => {
                    self.loading_lists = false;
                    match result {
                        Ok(screens) => {
                            if matches!(self.target, CaptureTarget::Primary) {
                                if let Some(primary) = screens.iter().find(|s| s.is_primary) {
                                    self.target = CaptureTarget::Screen { id: primary.id };
                                    self.target_label = format!("显示器 {}", primary.name);
                                }
                            }
                            self.screens = screens;
                        }
                        Err(err) => self.error = Some(err),
                    }
                }
                Event::Windows(result) => match result {
                    Ok(windows) => self.windows = windows,
                    Err(err) => self.error = Some(err),
                },
                Event::Captured(result) => match *result {
                    Ok(captured) => {
                        if let Some(texture) =
                            upload_rgba(app, &captured.rgba, captured.width, captured.height)
                        {
                            self.note = Some((
                                format!(
                                    "已截取 {}（{}×{}）",
                                    captured.target, captured.width, captured.height
                                ),
                                Instant::now(),
                            ));
                            self.frame = Some(Frame {
                                texture,
                                format: captured.format.clone(),
                                width: captured.width,
                                height: captured.height,
                                bytes: captured.encoded.len(),
                                duration_ms: captured.duration_ms,
                                target: captured.target.clone(),
                                resized: captured.resized,
                            });
                            self.encoded = Some(captured.encoded);
                        } else {
                            let err = "截图数据无法解码".to_string();
                            self.error = Some(err.clone());
                            app.fail(err);
                        }
                    }
                    Err(err) => {
                        self.error = Some(err.clone());
                        app.fail(err);
                    }
                },
                Event::Live(result) => match *result {
                    Ok(frame) => {
                        if let Some(texture) = upload_rgba(app, &frame.rgba, frame.width, frame.height)
                        {
                            let format = self.format_label().to_string();
                            self.frame = Some(Frame {
                                texture,
                                format,
                                width: frame.width,
                                height: frame.height,
                                bytes: frame.rgba.len(),
                                duration_ms: 0,
                                target: "实时预览".to_string(),
                                resized: true,
                            });
                            self.encoded = None;
                        }
                    }
                    Err(err) => {
                        // Auto-stop on the first error.
                        self.stop_live();
                        self.live_error = Some((err.clone(), Instant::now()));
                        app.fail(format!("实时预览已停止：{err}"));
                    }
                },
                Event::Saved(result) => match result {
                    Ok(path) => {
                        self.note = Some((format!("已保存到 {path}"), Instant::now()));
                        app.toasts.success(format!("已保存到 {path}"));
                    }
                    Err(err) => {
                        self.error = Some(err.clone());
                        app.fail(err);
                    }
                },
            }
        }
    }

    /// Human readable capture format.
    fn format_label(&self) -> &'static str {
        match self.format {
            ImageFormat::Png => "PNG",
            ImageFormat::Jpeg => "JPEG",
            ImageFormat::Bmp => "BMP",
        }
    }

    /// Loads the monitor and window lists.
    pub fn load_lists(&mut self, app: &mut App) {
        let Some(client) = app.client() else { return };
        self.loading_lists = true;
        let tx_screens = self.tx.clone();
        let tx_windows = self.tx.clone();
        let screens_client = client.clone();
        app.spawn_task(async move {
            let screens = screens_client.screens().await.map_err(|err| err.message());
            let _ = tx_screens.send(Event::Screens(screens));
        });
        app.spawn_task(async move {
            let windows = client.windows().await.map_err(|err| err.message());
            let _ = tx_windows.send(Event::Windows(windows));
        });
    }

    /// Builds the request for the current options and target.
    fn request(&self, format: ImageFormat, max_width: u32, quality: u8) -> CaptureRequest {
        CaptureRequest {
            target: self.target.clone(),
            format,
            quality: if format == ImageFormat::Jpeg {
                Some(quality)
            } else {
                None
            },
            max_width: if max_width > 0 { Some(max_width) } else { None },
            max_height: None,
        }
    }

    /// Captures the current target once.
    pub fn capture(&mut self, app: &mut App) {
        let Some(client) = app.client() else { return };
        let request = self.request(self.format, self.max_width, self.quality);
        let label = self.target_label.clone();
        let tx = self.tx.clone();
        app.set_status(format!("正在截取 {label}"));
        app.spawn_task(async move {
            let result = capture_once(&client, request, label).await;
            let _ = tx.send(Event::Captured(Box::new(result)));
        });
    }

    /// Starts the low-fps live preview loop.
    fn start_live(&mut self, app: &mut App) {
        let Some(client) = app.client() else { return };
        let interval = Duration::from_millis(1000 / self.live_fps.clamp(1, 2) as u64);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        self.live_stop_tx = Some(stop_tx);
        self.live_stop_rx = Some(stop_rx.clone());
        self.live = true;
        self.live_generation = self.live_generation.wrapping_add(1);
        let tx = self.tx.clone();
        app.spawn_task(async move {
            let mut stop = stop_rx;
            loop {
                if *stop.borrow() {
                    break;
                }
                let bytes = client
                    .capture_raw("primary", "jpeg", 60, Some(1280))
                    .await
                    .map_err(|err| err.message());
                match bytes.and_then(|bytes| {
                    decode(&bytes).ok_or_else(|| "帧数据无法解码".to_string())
                }) {
                    Ok((rgba, width, height)) => {
                        if tx.send(Event::Live(Box::new(Ok(LiveFrame { rgba, width, height })))).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(Event::Live(Box::new(Err(err))));
                        break;
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = stop.changed() => {}
                }
            }
        });
    }

    /// Stops the live preview loop.
    fn stop_live(&mut self) {
        if let Some(tx) = self.live_stop_tx.take() {
            let _ = tx.send(true);
        }
        self.live_stop_rx = None;
        self.live = false;
    }

    /// Saves the current capture through the most faithful path available.
    fn save_current(&mut self, app: &mut App, as_jpeg: bool) {
        let (Some(encoded), Some(frame)) = (self.encoded.clone(), self.frame.as_ref()) else {
            app.fail("当前没有可保存的截图");
            return;
        };
        let dir = app.paths.captures_dir.clone();
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let ext = if as_jpeg { "jpg" } else { "png" };
        let path = dir.join(format!("capture-{stamp}.{ext}"));
        let bytes = if as_jpeg {
            // Re-encode only when the user explicitly asks for JPEG.
            match decode(&encoded) {
                Some((rgba, width, height)) => {
                    match image::RgbaImage::from_raw(width, height, rgba) {
                        Some(buffer) => {
                            let mut out = std::io::Cursor::new(Vec::new());
                            if image::DynamicImage::ImageRgba8(buffer)
                                .write_to(&mut out, image::ImageFormat::Jpeg)
                                .is_err()
                            {
                                app.fail("无法编码 JPEG");
                                return;
                            }
                            out.into_inner()
                        }
                        None => {
                            app.fail("图像缓冲区尺寸不匹配");
                            return;
                        }
                    }
                }
                None => encoded,
            }
        } else {
            encoded
        };
        let label = frame.target.clone();
        let _ = label;
        let tx = self.tx.clone();
        app.spawn_blocking(
            move || -> Result<String, String> {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| format!("无法创建目录：{err}"))?;
                }
                std::fs::write(&path, &bytes).map_err(|err| format!("写入失败：{err}"))?;
                Ok(path.display().to_string())
            },
            move |result| {
                let _ = tx.send(Event::Saved(result));
            },
        );
        app.set_status("正在保存截图…");
    }

    /// Title used for a window entry.
    fn window_label(window: &WindowInfo) -> String {
        let app = window.app_name.as_deref().unwrap_or("未知应用");
        if window.title.trim().is_empty() {
            format!("{app}（无标题）")
        } else {
            format!("{app} · {}", window.title)
        }
    }
}

/// Captures once and returns the decoded payload.
async fn capture_once(
    client: &rt_client::RemoteClient,
    request: CaptureRequest,
    label: String,
) -> Result<Captured, String> {
    let response = client
        .capture(&request)
        .await
        .map_err(|err: rt_client::ClientError| err.message())?;
    let meta = response.meta.clone();
    let encoded = response
        .into_bytes()
        .ok_or_else(|| "服务器返回了无效的 base64 图像".to_string())?;
    let (rgba, width, height) = decode(&encoded).ok_or_else(|| "无法解码服务器返回的图像".to_string())?;
    Ok(Captured {
        target: label,
        format: match meta.format {
            ImageFormat::Png => "PNG",
            ImageFormat::Jpeg => "JPEG",
            ImageFormat::Bmp => "BMP",
        }
        .to_string(),
        width,
        height,
        duration_ms: meta.duration_ms,
        resized: meta.resized,
        rgba,
        encoded,
    })
}

/// Decodes encoded image bytes into RGBA8.
fn decode(bytes: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let image = image::load_from_memory(bytes).ok()?;
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    Some((rgba.into_raw(), width, height))
}

/// Uploads decoded pixels into a texture.
fn upload_rgba(app: &App, rgba: &[u8], width: u32, height: u32) -> Option<TextureHandle> {
    if width == 0 || height == 0 {
        return None;
    }
    let image = egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], rgba);
    Some(
        app.ctx
            .load_texture("screen.preview", image, TextureOptions::LINEAR),
    )
}

/// Page entry point.
pub fn ui(app: &mut App, ui: &mut Ui) {
    if app.client().is_none() {
        widgets::empty_state(
            ui,
            "🖥",
            "尚未连接",
            "连接后可以查看远端显示器与窗口，并按需截图。",
            None,
        );
        return;
    }

    app.with_screen(|state, app| {
        let p = palette(ui.ctx());
        if state.screens.is_empty() && !state.loading_lists {
            state.load_lists(app);
        }

        ui.horizontal(|ui| {
            ui.label(RichText::new("屏幕").size(Type::TITLE).strong().color(p.text));
            ui.add_space(Space::SM);
            if let Some(scope) = app.scope() {
                widgets::badge(
                    ui,
                    if scope.is_full() { "完全访问" } else { "工作区" },
                    if scope.is_full() { Tone::Success } else { Tone::Warning },
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button(
                    ui,
                    Btn::new("screen.refresh", "刷新列表", "重新读取显示器与窗口列表")
                        .small()
                        .ghost(),
                )
                .clicked()
                {
                    state.loading_lists = false;
                    state.load_lists(app);
                }
            });
        });
        ui.add_space(Space::MD);

        // -- capture options -----------------------------------------------
        let mut capture = false;
        widgets::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::section_label(ui, "目标");
                ui.label(RichText::new(&state.target_label).size(Type::BODY).color(p.text));
                ui.add_space(Space::MD);
                widgets::section_label(ui, "格式");
                let mut format = state.format_label().to_string();
                let before = format.clone();
                widgets::segmented(
                    ui,
                    "screen.format",
                    &[("PNG", "PNG"), ("JPEG", "JPEG"), ("BMP", "BMP")],
                    &mut format,
                );
                if format != before {
                    state.format =
                        ImageFormat::parse(&format.to_lowercase()).unwrap_or(ImageFormat::Png);
                }
                if state.format == ImageFormat::Jpeg {
                    ui.add_space(Space::SM);
                    widgets::section_label(ui, "质量");
                    ui.add(egui::Slider::new(&mut state.quality, 10..=100))
                        .on_hover_text("JPEG 质量，越小传输越快");
                }
                ui.add_space(Space::SM);
                widgets::section_label(ui, "最大宽度");
                ui.add(egui::DragValue::new(&mut state.max_width).range(0..=7680).suffix(" px"))
                    .on_hover_text("0 表示不缩放；缩小可显著加快传输");
            });
            ui.add_space(Space::SM);
            ui.horizontal(|ui| {
                capture = widgets::button(
                    ui,
                    Btn::new("screen.capture", "截图", "截取当前选中的显示器或窗口").primary(),
                )
                .clicked();
                if widgets::button(
                    ui,
                    Btn::new("screen.all", "全部屏幕", "一次截取所有显示器"),
                )
                .clicked()
                {
                    state.target = CaptureTarget::AllScreens;
                    state.target_label = "全部屏幕".to_string();
                    capture = true;
                }
                let live_label = if state.live { "停止实时" } else { "实时预览" };
                if widgets::button(
                    ui,
                    Btn::new(
                        "screen.live",
                        live_label,
                        if state.live {
                            "停止低帧率实时预览"
                        } else {
                            "以 1–2 fps 持续截取，出错会自动停止"
                        },
                    )
                    .ghost(),
                )
                .clicked()
                {
                    if state.live {
                        state.stop_live();
                    } else {
                        state.start_live(app);
                    }
                }
                if state.live {
                    ui.add(egui::Slider::new(&mut state.live_fps, 1..=2).suffix(" fps"))
                        .on_hover_text("实时预览帧率");
                    widgets::badge(ui, "实时", Tone::Success);
                }
            });
        });

        if let Some(error) = &state.error {
            widgets::error_banner(ui, error);
        }
        if let Some((err, at)) = &state.live_error {
            if at.elapsed() < Duration::from_secs(12) {
                widgets::note_banner(ui, &format!("实时预览已停止：{err}"));
            }
        }
        if let Some((note, at)) = &state.note {
            if at.elapsed() < Duration::from_secs(8) {
                widgets::note_banner(ui, note);
            }
        }

        ui.add_space(Space::MD);

        // -- preview -------------------------------------------------------
        if let Some(frame) = &state.frame {
            let width = frame.width;
            let height = frame.height;
            let format = frame.format.clone();
            let bytes = frame.bytes;
            let duration = frame.duration_ms;
            let target = frame.target.clone();
            let resized = frame.resized;
            let texture = frame.texture.clone();
            widgets::card(ui, |ui| {
                let max = egui::vec2(ui.available_width().max(200.0), 460.0);
                let scale = (max.x / width as f32)
                    .min(max.y / height as f32)
                    .min(1.0)
                    .max(0.01);
                let size = egui::vec2(
                    (width as f32 * scale).max(1.0),
                    (height as f32 * scale).max(1.0),
                );
                let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                ui.painter().rect_filled(rect, theme::Radius::MD, p.sunken);
                ui.painter().image(
                    texture.id(),
                    rect,
                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                );
                ui.add_space(Space::SM);
                ui.horizontal_wrapped(|ui| {
                    widgets::key_value_row(ui, "目标", &target, false);
                    widgets::key_value_row(ui, "格式", &format, true);
                    widgets::key_value_row(ui, "尺寸", &format!("{width}×{height}"), true);
                    widgets::key_value_row(
                        ui,
                        "数据量",
                        &rt_core::util::format_bytes(bytes as u64),
                        true,
                    );
                    if duration > 0 {
                        widgets::key_value_row(
                            ui,
                            "耗时",
                            &rt_core::util::format_duration_ms(duration),
                            true,
                        );
                    }
                    if resized {
                        widgets::badge(ui, "已缩放", Tone::Neutral);
                    }
                });
                ui.add_space(Space::SM);
                ui.horizontal(|ui| {
                    if widgets::button(
                        ui,
                        Btn::new("screen.save_png", "保存 PNG", "把当前截图保存到本地截图目录"),
                    )
                    .clicked()
                    {
                        state.save_current(app, false);
                    }
                    if widgets::button(
                        ui,
                        Btn::new("screen.save_jpg", "保存 JPEG", "以 JPEG 保存，体积更小"),
                    )
                    .clicked()
                    {
                        state.save_current(app, true);
                    }
                    if widgets::button(
                        ui,
                        Btn::new("screen.open_dir", "打开截图目录", "在资源管理器中打开截图目录"),
                    )
                    .clicked()
                    {
                        let dir = app.paths.captures_dir.clone();
                        app.spawn_blocking(
                            move || {
                                let _ = std::fs::create_dir_all(&dir);
                                let _ = open::that(&dir);
                            },
                            |()| {},
                        );
                    }
                });
            });
        } else {
            widgets::empty_state(
                ui,
                "📷",
                "还没有截图",
                "在下面的列表里选择显示器或窗口，然后点击“截图”。",
                None,
            );
        }

        // -- monitors and windows -------------------------------------------
        ui.add_space(Space::MD);
        let mut pick: Option<(CaptureTarget, String)> = None;
        ui.columns(2, |columns| {
            widgets::card(&mut columns[0], |ui| {
                widgets::section_label(ui, "显示器");
                if state.screens.is_empty() {
                    widgets::caption(ui, "没有检测到显示器");
                }
                for screen in &state.screens {
                    let label = format!(
                        "{} · {}×{}{}",
                        screen.name,
                        screen.width,
                        screen.height,
                        if screen.is_primary { " · 主屏" } else { "" }
                    );
                    if widgets::button(
                        ui,
                        Btn::new(
                            ("screen.pick", screen.id),
                            &label,
                            if screen.is_capturable {
                                "点击后把该显示器设为截图目标"
                            } else {
                                "该显示器当前不可截取"
                            },
                        )
                        .enabled(screen.is_capturable)
                        .ghost(),
                    )
                    .clicked()
                    {
                        pick = Some((
                            CaptureTarget::Screen { id: screen.id },
                            format!("显示器 {}", screen.name),
                        ));
                    }
                }
            });

            widgets::card(&mut columns[1], |ui| {
                ui.horizontal(|ui| {
                    widgets::section_label(ui, "窗口");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.window_filter)
                            .hint_text("过滤窗口标题")
                            .desired_width(140.0),
                    )
                    .on_hover_text("按标题或进程名过滤窗口列表");
                });
                let filter = state.window_filter.to_lowercase();
                let windows: Vec<WindowInfo> = state
                    .windows
                    .iter()
                    .filter(|w| {
                        filter.is_empty()
                            || w.title.to_lowercase().contains(&filter)
                            || w
                                .app_name
                                .as_deref()
                                .unwrap_or("")
                                .to_lowercase()
                                .contains(&filter)
                    })
                    .take(80)
                    .cloned()
                    .collect();
                if windows.is_empty() {
                    widgets::caption(ui, "没有匹配的窗口");
                }
                egui::ScrollArea::vertical()
                    .id_salt("screen.windows")
                    .max_height(260.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for window in windows {
                            let label = State::window_label(&window);
                            if widgets::button(
                                ui,
                                Btn::new(
                                    ("screen.window", window.id),
                                    &label,
                                    if window.is_capturable {
                                        "点击后把该窗口设为截图目标"
                                    } else {
                                        "该窗口当前不可截取"
                                    },
                                )
                                .enabled(window.is_capturable)
                                .ghost(),
                            )
                            .clicked()
                            {
                                pick = Some((CaptureTarget::Window { id: window.id }, label));
                            }
                        }
                    });
            });
        });

        if let Some((target, label)) = pick {
            state.target = target;
            state.target_label = label;
            if state.live {
                // Restart the stream against the new target.
                state.stop_live();
                state.start_live(app);
            }
        }
        if capture {
            state.capture(app);
        }

        // Keep the live loop repainting regularly.
        if state.live {
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
    });
}

/// Draws page dialogs (none for this page).
pub fn dialogs(_app: &mut App, _ctx: &egui::Context) {}
