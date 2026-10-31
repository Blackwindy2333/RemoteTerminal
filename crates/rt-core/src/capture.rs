//! Screen and window capture.
//!
//! One frame per call: [`capture`] grabs a single image and encodes it. The
//! WebSocket layer owns the frame loop and the rate limit and calls
//! [`capture_frame`] on a blocking thread.
//!
//! Design notes:
//! * Everything here **blocks** — `xcap` reaches GDI / `PrintWindow` on the
//!   calling thread — so callers must run these functions inside
//!   `tokio::task::spawn_blocking`.
//! * Nothing panics: on a session without an interactive desktop (a service
//!   session, a disconnected RDP session, a locked workstation) `xcap` returns
//!   errors and we translate them into [`RtError::Unavailable`].
//! * The five public signatures are the frozen contract consumed by `rt-server`
//!   and `rt-client`.
//!
//! `xcap` already filters out the windows Windows itself hides (invisible,
//! DWM-cloaked, zero-area, owned by this process), so [`list_windows`] lists
//! exactly the candidates a remote user can reasonably expect to see.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use base64::Engine as _;
use image::codecs::bmp::BmpEncoder;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::imageops::FilterType;
use image::{ExtendedColorType, ImageEncoder, Rgba, RgbaImage};
use rt_protocol::{
    CaptureFrame, CaptureMeta, CaptureRequest, CaptureResponse, CaptureTarget, ImageFormat,
    ScreenInfo, WindowInfo,
};

use crate::error::{Result, RtError};

/// Refuse to materialise a bitmap bigger than this.
///
/// A 4-monitor 4K virtual desktop is already ~33 Mpx (132 MB as RGBA); the cap
/// keeps a pathological layout (or a bogus request) from turning into an
/// allocation the remote side can never transfer anyway.
const MAX_PIXELS: u64 = 64_000_000;

/// JPEG quality used when the request does not specify one.
const DEFAULT_JPEG_QUALITY: u8 = 75;

// ---------------------------------------------------------------------------
// Minimal Win32 bindings
// ---------------------------------------------------------------------------

/// The few Win32 facts `xcap` does not expose.
///
/// `xcap` keeps `GetForegroundWindow` and the process-image query private, and
/// it has no "process path" accessor at all, so we declare the four functions
/// we need ourselves instead of pulling in the `windows` crate (which is not a
/// dependency of this crate).
#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // SAFETY: every declaration below matches the documented Win32 signature
    // (`BOOL` is `i32`, `HANDLE`/`HWND` are pointer-sized integers). Calls are
    // wrapped in `unsafe` blocks at the use site and all handles are released.
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetForegroundWindow() -> isize;
        fn IsWindowVisible(hwnd: isize) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        fn QueryFullProcessImageNameW(
            process: isize,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(object: isize) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    /// `QueryFullProcessImageNameW` accepts long paths, so do not cap at MAX_PATH.
    const EXE_NAME_CAPACITY: u32 = 4096;

    /// `HWND` of the window that currently has keyboard focus.
    pub fn foreground_window() -> Option<u32> {
        // SAFETY: no arguments, no aliasing; returns 0 when there is none.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd == 0 {
            None
        } else {
            Some(hwnd as u32)
        }
    }

    /// `WS_VISIBLE` state of a window; `None` when the handle is not a window.
    pub fn is_window_visible(hwnd: u32) -> Option<bool> {
        // SAFETY: read-only query of a handle obtained from `xcap`.
        Some(unsafe { IsWindowVisible(hwnd as isize) } != 0)
    }

    /// Full image path of a process, best effort (fails for protected or
    /// elevated processes we may not open).
    pub fn process_image_path(pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        // SAFETY: plain FFI calls; the handle is closed on every path below.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == 0 {
                return None;
            }
            let mut buffer = vec![0u16; EXE_NAME_CAPACITY as usize];
            let mut size = EXE_NAME_CAPACITY;
            let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
            CloseHandle(handle);
            if ok == 0 || size == 0 {
                return None;
            }
            buffer.truncate(size as usize);
            let path = OsString::from_wide(&buffer).to_string_lossy().into_owned();
            if path.is_empty() {
                None
            } else {
                Some(path)
            }
        }
    }
}

/// Non-Windows fallbacks so the crate keeps building for `cargo check` on a
/// developer machine that is not running Windows.
#[cfg(not(windows))]
mod win {
    pub fn foreground_window() -> Option<u32> {
        None
    }

    pub fn is_window_visible(_hwnd: u32) -> Option<bool> {
        None
    }

    pub fn process_image_path(_pid: u32) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn unavailable(context: &str, err: impl std::fmt::Display) -> RtError {
    RtError::Unavailable(format!("{context}: {err}"))
}

/// Rejects sizes that would allocate an unreasonable bitmap before we touch
/// GDI (which would happily try and then fail somewhere less predictable).
fn check_pixel_budget(width: u32, height: u32, what: &str) -> Result<()> {
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_PIXELS {
        return Err(RtError::bad_request(format!(
            "{what} is too large for a single image ({width}x{height}, {pixels} pixels > {MAX_PIXELS} limit); capture one screen at a time"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// Every capturable monitor, ordered primary-first.
pub fn list_screens() -> Result<Vec<ScreenInfo>> {
    let monitors = xcap::Monitor::all().map_err(|err| unavailable("monitor enumeration failed", err))?;
    let mut screens = Vec::with_capacity(monitors.len());

    for (index, monitor) in monitors.iter().enumerate() {
        let id = monitor.id().unwrap_or(0);
        let width = monitor.width().unwrap_or(0);
        let height = monitor.height().unwrap_or(0);
        // The friendly name ("DELL U2720Q") is what a human wants; fall back to
        // the device name (`\\.\DISPLAY1`) and finally to a stable synthetic one.
        let name = monitor
            .friendly_name()
            .ok()
            .filter(|name| !name.is_empty() && !name.starts_with("Unknown Monitor "))
            .or_else(|| monitor.name().ok().filter(|name| !name.is_empty()))
            .unwrap_or_else(|| format!("display {}", index + 1));
        screens.push(ScreenInfo {
            id,
            name,
            x: monitor.x().unwrap_or(0),
            y: monitor.y().unwrap_or(0),
            width,
            height,
            scale_factor: monitor
                .scale_factor()
                .ok()
                .filter(|factor| *factor > 0.0)
                .unwrap_or(1.0),
            is_primary: monitor.is_primary().unwrap_or(false),
            refresh_hz: monitor
                .frequency()
                .ok()
                .filter(|hz| *hz >= 1.0 && *hz <= 1000.0)
                .map(|hz| hz.round() as u32),
            is_capturable: width > 0 && height > 0,
        });
    }

    // Primary first, then left-to-right (then top, then id) so the GUI list and
    // the "default target" are stable regardless of enumeration order.
    screens.sort_by(|a, b| {
        b.is_primary
            .cmp(&a.is_primary)
            .then(a.x.cmp(&b.x))
            .then(a.y.cmp(&b.y))
            .then(a.id.cmp(&b.id))
    });
    Ok(screens)
}

/// Top-level visible windows, in z-order (topmost first).
///
/// Windows we cannot capture are still listed, with `is_capturable = false`, so
/// the UI can grey them out instead of hiding them.
pub fn list_windows() -> Result<Vec<WindowInfo>> {
    let windows = xcap::Window::all().map_err(|err| unavailable("window enumeration failed", err))?;
    let foreground = win::foreground_window();
    // Several windows usually belong to one process; query each pid once.
    let mut path_cache: HashMap<u32, Option<String>> = HashMap::new();
    let mut out = Vec::with_capacity(windows.len());

    for window in &windows {
        let raw_id = match window.id() {
            Ok(id) => id,
            // The handle died between enumeration and inspection.
            Err(_) => continue,
        };
        let (width, height) = match (window.width(), window.height()) {
            (Ok(width), Ok(height)) => (width, height),
            // Gone, or not on a monitor we can address.
            _ => continue,
        };
        // Nothing to draw: skip instead of listing an unusable 0x0 entry.
        if width == 0 || height == 0 {
            continue;
        }

        let title = window.title().unwrap_or_default();
        let pid = window.pid().ok().filter(|pid| *pid != 0);
        let process_path = pid.and_then(|pid| cached_process_path(pid, &mut path_cache));
        let app_name = window
            .app_name()
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| process_path.as_deref().and_then(file_name_of));
        // Window state, not process state: minimized windows stay in the list
        // (a remote user may want to know they exist) but cannot be grabbed.
        let is_minimized = window.is_minimized().unwrap_or(false);
        let is_visible = win::is_window_visible(raw_id).unwrap_or(true);
        let is_capturable = !title.is_empty() && !is_minimized && is_visible;

        out.push(WindowInfo {
            id: u64::from(raw_id),
            title,
            app_name,
            process_path,
            pid,
            x: window.x().unwrap_or(0),
            y: window.y().unwrap_or(0),
            width,
            height,
            is_foreground: foreground == Some(raw_id),
            is_minimized,
            is_visible,
            is_capturable,
        });
    }

    Ok(out)
}

fn cached_process_path(pid: u32, cache: &mut HashMap<u32, Option<String>>) -> Option<String> {
    if let Some(hit) = cache.get(&pid) {
        return hit.clone();
    }
    let path = win::process_image_path(pid);
    cache.insert(pid, path.clone());
    path
}

fn file_name_of(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

/// Grabs one frame according to `req`, resizing when requested.
pub fn capture(req: &CaptureRequest) -> Result<CaptureResponse> {
    let (meta, data) = capture_bytes(req)?;
    Ok(CaptureResponse {
        meta,
        data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
    })
}

/// Same as [`capture`] but tagged with a stream sequence number.
pub fn capture_frame(req: &CaptureRequest, seq: u64) -> Result<CaptureFrame> {
    let (meta, data) = capture_bytes(req)?;
    Ok(CaptureFrame {
        seq,
        meta,
        data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
    })
}

/// Grabs one frame and returns the encoded bytes with their metadata.
///
/// This is the primitive behind [`capture`] / [`capture_frame`]; the raw-bytes
/// endpoint (`GET /api/v1/capture/raw`) and the WebSocket frame stream should
/// use it directly to skip a pointless base64 round-trip.
pub fn capture_bytes(req: &CaptureRequest) -> Result<(CaptureMeta, Vec<u8>)> {
    let started = Instant::now();
    validate_request(req)?;

    let (image, description) = grab(&req.target)?;
    let (image, resized) = downscale(image, req.max_width, req.max_height);
    let (width, height) = image.dimensions();
    let data = encode(&image, req.format, req.quality)?;

    let meta = CaptureMeta {
        format: req.format,
        // Encoded dimensions: what the receiver will actually see.
        width,
        height,
        bytes: data.len() as u64,
        captured_at_ms: next_stamp_ms(),
        duration_ms: started.elapsed().as_millis() as u64,
        target: description,
        resized,
    };
    tracing::debug!(
        target: "capture",
        target = %meta.target,
        format = ?meta.format,
        width = meta.width,
        height = meta.height,
        bytes = meta.bytes,
        duration_ms = meta.duration_ms,
        "captured frame"
    );
    Ok((meta, data))
}

fn validate_request(req: &CaptureRequest) -> Result<()> {
    if let Some(quality) = req.quality {
        if !(1..=100).contains(&quality) {
            return Err(RtError::bad_request(format!(
                "quality must be between 1 and 100, got {quality}"
            )));
        }
    }
    for (name, cap) in [("max_width", req.max_width), ("max_height", req.max_height)] {
        if cap == Some(0) {
            return Err(RtError::bad_request(format!(
                "{name} must be greater than 0 (omit it for no limit)"
            )));
        }
    }
    Ok(())
}

/// Resolves the target and produces the raw RGBA frame.
fn grab(target: &CaptureTarget) -> Result<(RgbaImage, String)> {
    match target {
        CaptureTarget::Primary => grab_primary(),
        CaptureTarget::Screen { id } => grab_screen(*id),
        CaptureTarget::AllScreens => grab_all_screens(),
        CaptureTarget::Window { id } => grab_window(*id),
    }
}

fn grab_primary() -> Result<(RgbaImage, String)> {
    let monitors = xcap::Monitor::all().map_err(|err| unavailable("monitor enumeration failed", err))?;
    let monitor = monitors
        .iter()
        .find(|monitor| monitor.is_primary().unwrap_or(false))
        // Some virtual/remote adapters never flag a primary monitor; the first
        // one is the sane fallback.
        .or_else(|| monitors.first())
        .ok_or_else(|| {
            RtError::Unavailable(
                "no monitor available for capture (is an interactive desktop attached?)".into(),
            )
        })?;
    let (image, description) = grab_monitor(monitor)?;
    Ok((image, format!("{description} primary")))
}

fn grab_screen(id: u32) -> Result<(RgbaImage, String)> {
    let monitors = xcap::Monitor::all().map_err(|err| unavailable("monitor enumeration failed", err))?;
    let monitor = monitors
        .iter()
        .find(|monitor| monitor.id().map(|monitor_id| monitor_id == id).unwrap_or(false))
        .ok_or_else(|| RtError::not_found(format!("screen {id} does not exist")))?;
    grab_monitor(monitor)
}

fn grab_monitor(monitor: &xcap::Monitor) -> Result<(RgbaImage, String)> {
    let id = monitor.id().unwrap_or(0);
    let width = monitor.width().map_err(|err| unavailable(&format!("screen {id} geometry unavailable"), err))?;
    let height = monitor.height().map_err(|err| unavailable(&format!("screen {id} geometry unavailable"), err))?;
    if width == 0 || height == 0 {
        return Err(RtError::Unavailable(format!(
            "screen {id} has no drawable area ({width}x{height})"
        )));
    }
    check_pixel_budget(width, height, "screen")?;
    let image = monitor
        .capture_image()
        .map_err(|err| unavailable(&format!("screen {id} capture failed"), err))?;
    if image.width() == 0 || image.height() == 0 {
        return Err(RtError::Unavailable(format!("screen {id} produced an empty frame")));
    }
    let description = format!("screen:{id} ({}x{})", image.width(), image.height());
    Ok((image, description))
}

/// Stitches every monitor into one canvas that mirrors the virtual-desktop
/// layout: each screen is blitted at its real `(x, y)` offset, everything
/// outside the union of the screens stays black.
fn grab_all_screens() -> Result<(RgbaImage, String)> {
    let monitors = xcap::Monitor::all().map_err(|err| unavailable("monitor enumeration failed", err))?;
    if monitors.is_empty() {
        return Err(RtError::Unavailable(
            "no monitor available for capture (is an interactive desktop attached?)".into(),
        ));
    }

    let mut parts: Vec<(i32, i32, RgbaImage)> = Vec::with_capacity(monitors.len());
    for monitor in &monitors {
        let id = monitor.id().unwrap_or(0);
        let (x, y) = match (monitor.x(), monitor.y()) {
            (Ok(x), Ok(y)) => (x, y),
            _ => {
                tracing::warn!(target: "capture", screen = id, "monitor position unavailable; leaving it black");
                continue;
            }
        };
        if let Ok(width) = monitor.width() {
            if let Ok(height) = monitor.height() {
                if check_pixel_budget(width, height, "screen").is_err() {
                    tracing::warn!(target: "capture", screen = id, width, height, "monitor skipped: too large");
                    continue;
                }
            }
        }
        match monitor.capture_image() {
            Ok(image) if image.width() > 0 && image.height() > 0 => parts.push((x, y, image)),
            Ok(_) => {
                tracing::warn!(target: "capture", screen = id, "monitor produced an empty frame; leaving it black")
            }
            Err(err) => {
                tracing::warn!(target: "capture", screen = id, error = %err, "monitor capture failed; leaving it black")
            }
        }
    }
    if parts.is_empty() {
        return Err(RtError::Unavailable("capture failed for every monitor".into()));
    }

    let left = parts.iter().map(|(x, _, _)| *x).min().unwrap_or(0);
    let top = parts.iter().map(|(_, y, _)| *y).min().unwrap_or(0);
    let right = parts
        .iter()
        .map(|(x, _, image)| *x + image.width() as i32)
        .max()
        .unwrap_or(0);
    let bottom = parts
        .iter()
        .map(|(_, y, image)| *y + image.height() as i32)
        .max()
        .unwrap_or(0);
    let width = (right - left).max(0) as u32;
    let height = (bottom - top).max(0) as u32;
    if width == 0 || height == 0 {
        return Err(RtError::Unavailable("virtual desktop has no drawable area".into()));
    }
    check_pixel_budget(width, height, "virtual desktop")?;

    let mut canvas = RgbaImage::from_pixel(width, height, Rgba([0, 0, 0, 255]));
    for (x, y, image) in &parts {
        // `overlay` clips whatever falls outside the canvas, which is exactly
        // the "crop the parts that do not fit" behaviour we want.
        image::imageops::overlay(&mut canvas, image, i64::from(*x - left), i64::from(*y - top));
    }

    let description = format!("all-screens:{} ({width}x{height})", parts.len());
    Ok((canvas, description))
}

fn grab_window(id: u64) -> Result<(RgbaImage, String)> {
    let windows = xcap::Window::all().map_err(|err| unavailable("window enumeration failed", err))?;
    let window = windows
        .iter()
        .find(|window| window.id().map(|window_id| u64::from(window_id) == id).unwrap_or(false))
        .ok_or_else(|| {
            RtError::not_found(format!("window {id} does not exist or is not visible"))
        })?;

    let (Ok(width), Ok(height)) = (window.width(), window.height()) else {
        return Err(RtError::not_found(format!("window {id} vanished before capture")));
    };
    if width == 0 || height == 0 {
        return Err(RtError::Unavailable(format!(
            "window {id} has no drawable area ({width}x{height})"
        )));
    }
    // Guard before calling into `xcap`: its window path resizes/crops to the
    // window size and a minimized window can report an empty client area.
    if window.is_minimized().unwrap_or(false) {
        return Err(RtError::Unavailable(format!(
            "window {id} is minimized; restore it before capturing"
        )));
    }
    check_pixel_budget(width, height, "window")?;

    let image = window
        .capture_image()
        .map_err(|err| unavailable(&format!("window {id} capture failed"), err))?;
    if image.width() == 0 || image.height() == 0 {
        return Err(RtError::Unavailable(format!("window {id} produced an empty frame")));
    }
    let description = format!("window:{id} ({}x{})", image.width(), image.height());
    Ok((image, description))
}

// ---------------------------------------------------------------------------
// Scaling / encoding
// ---------------------------------------------------------------------------

/// Shrinks the frame so neither dimension exceeds its cap, preserving the
/// aspect ratio. Returns the image unchanged (plus `false`) when it already
/// fits, and never enlarges.
fn downscale(image: RgbaImage, max_width: Option<u32>, max_height: Option<u32>) -> (RgbaImage, bool) {
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 {
        return (image, false);
    }

    let mut target_width = width;
    let mut target_height = height;
    if let Some(cap) = max_width {
        if target_width > cap {
            target_height = scale_dimension(height, cap, width);
            target_width = cap;
        }
    }
    if let Some(cap) = max_height {
        if target_height > cap {
            target_width = scale_dimension(target_width, cap, target_height);
            target_height = cap;
        }
    }
    if target_width == width && target_height == height {
        return (image, false);
    }

    // `Triangle` is a good speed/quality compromise for live screen previews.
    let resized = image::imageops::resize(&image, target_width, target_height, FilterType::Triangle);
    (resized, true)
}

/// `length` scaled by `cap / original`, rounded, and clamped to at least 1px.
fn scale_dimension(length: u32, cap: u32, original: u32) -> u32 {
    if original == 0 {
        return 1;
    }
    let scaled = (f64::from(length) * (f64::from(cap) / f64::from(original))).round();
    if scaled < 1.0 {
        1
    } else if scaled > f64::from(u32::MAX) {
        u32::MAX
    } else {
        scaled as u32
    }
}

fn encode(image: &RgbaImage, format: ImageFormat, quality: Option<u8>) -> Result<Vec<u8>> {
    let (width, height) = image.dimensions();
    let mut out: Vec<u8> = Vec::new();
    let result = match format {
        ImageFormat::Png => PngEncoder::new(&mut out).write_image(
            image.as_raw(),
            width,
            height,
            ExtendedColorType::Rgba8,
        ),
        // JPEG has no alpha channel; `encode_image` takes the RGBA buffer and
        // drops the alpha while converting to YCbCr.
        ImageFormat::Jpeg => JpegEncoder::new_with_quality(
            &mut out,
            quality.unwrap_or(DEFAULT_JPEG_QUALITY),
        )
        .encode_image(image),
        ImageFormat::Bmp => BmpEncoder::new(&mut out).write_image(
            image.as_raw(),
            width,
            height,
            ExtendedColorType::Rgba8,
        ),
    };
    result.map_err(|err| {
        RtError::Internal(format!(
            "{} encoding of a {width}x{height} frame failed: {err}",
            format.extension()
        ))
    })?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Last stamp handed out, so `captured_at_ms` is strictly increasing.
static LAST_STAMP_MS: AtomicI64 = AtomicI64::new(0);

/// Unix-epoch milliseconds, forced to be strictly increasing.
///
/// Clients order frames by this value; two frames inside the same millisecond
/// (or a backwards system-clock step) would otherwise compare as "same"/"newer".
fn next_stamp_ms() -> i64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0);
    let previous = LAST_STAMP_MS.load(Ordering::Relaxed);
    let stamp = if wall > previous {
        wall
    } else {
        previous.saturating_add(1)
    };
    LAST_STAMP_MS.store(stamp, Ordering::Relaxed);
    stamp
}

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

/// Cheap liveness probe used by `/healthz` and the status panel.
///
/// The answer is cached for the life of the process: enumerating monitors costs
/// a `EnumDisplayMonitors` round-trip and the result only changes when the
/// desktop session does, which is exactly when a restart is due anyway.
pub fn is_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| match xcap::Monitor::all() {
        Ok(_) => true,
        Err(err) => {
            tracing::warn!(target: "capture", error = %err, "screen capture is unavailable (no interactive desktop?)");
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_protocol::ErrorCode;

    #[test]
    fn list_screens_works() {
        let screens = match list_screens() {
            Ok(screens) => screens,
            Err(err) => {
                // RDP disconnect / service session: nothing to assert, but do
                // report why so a `--nocapture` run is diagnosable.
                eprintln!("list_screens failed in this session, skipping assertions: {err}");
                return;
            }
        };
        if screens.is_empty() {
            eprintln!("no monitor reported (no interactive desktop session?), skipping assertions");
            return;
        }

        for screen in &screens {
            assert!(
                screen.width > 0 && screen.height > 0,
                "screen {} reported an empty geometry {}x{}",
                screen.id,
                screen.width,
                screen.height
            );
            assert!(
                screen.scale_factor > 0.0,
                "screen {} reported scale factor {}",
                screen.id,
                screen.scale_factor
            );
            assert!(!screen.name.is_empty(), "screen {} has no name", screen.id);
            assert!(
                screen.is_capturable,
                "screen {} is listed but not capturable",
                screen.id
            );
            if let Some(hz) = screen.refresh_hz {
                assert!((1..=1000).contains(&hz), "screen {} reported {hz} Hz", screen.id);
            }
        }

        // Primary first, then left-to-right.
        let primary_flags: Vec<bool> = screens.iter().map(|screen| screen.is_primary).collect();
        assert!(
            !primary_flags.windows(2).any(|pair| !pair[0] && pair[1]),
            "non-primary monitor listed before the primary one: {primary_flags:?}"
        );
        let tail_x: Vec<i32> = screens
            .iter()
            .skip_while(|screen| screen.is_primary)
            .map(|screen| screen.x)
            .collect();
        assert!(
            tail_x.windows(2).all(|pair| pair[0] <= pair[1]),
            "screens are not ordered by x: {tail_x:?}"
        );
    }

    #[test]
    fn capture_primary_produces_png() {
        let request = CaptureRequest::png(CaptureTarget::Primary);
        let response = match capture(&request) {
            Ok(response) => response,
            Err(err) => {
                eprintln!("skipping: capture unavailable in this session ({err})");
                return;
            }
        };

        assert_eq!(response.meta.format, ImageFormat::Png);
        assert!(!response.meta.resized, "no cap was requested, nothing should be resized");
        assert!(response.meta.width > 0 && response.meta.height > 0);
        assert!(response.meta.target.starts_with("screen:"), "unexpected target label: {}", response.meta.target);

        let bytes = response.into_bytes().expect("data_b64 must be valid base64");
        assert_eq!(bytes.len() as u64, response.meta.bytes);
        assert!(bytes.len() > 1000, "PNG looks truncated: {} bytes", bytes.len());
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "missing PNG signature");

        // The native image decoder must agree with the reported geometry.
        let decoded = image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
            .expect("produced PNG must decode");
        assert_eq!(decoded.width(), response.meta.width);
        assert_eq!(decoded.height(), response.meta.height);
    }

    #[test]
    fn jpeg_quality_and_resize() {
        let request = CaptureRequest::jpeg_preview(CaptureTarget::Primary, 60, Some(320));
        let response = match capture(&request) {
            Ok(response) => response,
            Err(err) => {
                eprintln!("skipping: capture unavailable in this session ({err})");
                return;
            }
        };

        assert_eq!(response.meta.format, ImageFormat::Jpeg);
        assert!(
            response.meta.width <= 320,
            "max_width=320 was ignored: {}",
            response.meta.width
        );
        if response.meta.resized {
            // The cap is applied exactly, so a downscaled frame is exactly 320 wide.
            assert_eq!(response.meta.width, 320);
        } else {
            eprintln!(
                "screen is already {}px wide, aspect/size assertions skipped",
                response.meta.width
            );
        }

        let bytes = response.into_bytes().expect("data_b64 must be valid base64");
        assert_eq!(&bytes[..2], b"\xff\xd8", "missing JPEG SOI marker");
        assert_eq!(&bytes[bytes.len() - 2..], b"\xff\xd9", "missing JPEG EOI marker");
        let decoded = image::load_from_memory_with_format(&bytes, image::ImageFormat::Jpeg)
            .expect("produced JPEG must decode");
        assert_eq!(decoded.width(), response.meta.width);
        assert_eq!(decoded.height(), response.meta.height);
    }

    #[test]
    fn capture_bad_target_errors() {
        // Invalid requests are rejected before anything is grabbed, so these
        // hold even without a desktop session.
        let mut request = CaptureRequest::png(CaptureTarget::Primary);
        request.quality = Some(0);
        let err = capture(&request).expect_err("quality=0 must be rejected");
        assert_eq!(err.code(), ErrorCode::BadRequest, "unexpected error: {err}");

        request.quality = None;
        request.max_width = Some(0);
        let err = capture(&request).expect_err("max_width=0 must be rejected");
        assert_eq!(err.code(), ErrorCode::BadRequest, "unexpected error: {err}");

        // A screen id that cannot exist: not_found on a desktop session,
        // unavailable when there is no desktop to enumerate at all.
        let request = CaptureRequest::png(CaptureTarget::Screen { id: u32::MAX });
        let err = capture(&request).expect_err("unknown screen id must fail");
        assert!(
            matches!(err.code(), ErrorCode::NotFound | ErrorCode::Unavailable),
            "unexpected error for a bogus screen id: {err}"
        );

        let request = CaptureRequest::png(CaptureTarget::Window { id: u64::MAX });
        let err = capture(&request).expect_err("unknown window id must fail");
        assert!(
            matches!(err.code(), ErrorCode::NotFound | ErrorCode::Unavailable),
            "unexpected error for a bogus window id: {err}"
        );
    }

    /// Pure geometry test: runs everywhere, desktop session or not.
    #[test]
    fn resize_respects_caps() {
        let image = RgbaImage::from_pixel(1000, 500, Rgba([1, 2, 3, 255]));

        let (scaled, resized) = downscale(image.clone(), Some(320), None);
        assert!(resized);
        assert_eq!(scaled.dimensions(), (320, 160));

        let (scaled, resized) = downscale(image.clone(), None, Some(100));
        assert!(resized);
        assert_eq!(scaled.dimensions(), (200, 100));

        // Both caps apply: the tighter one wins, aspect is preserved.
        let (scaled, resized) = downscale(image.clone(), Some(500), Some(100));
        assert!(resized);
        assert_eq!(scaled.dimensions(), (200, 100));

        // Never enlarge, never resize when the frame already fits.
        let (same, resized) = downscale(image.clone(), Some(4000), Some(4000));
        assert!(!resized);
        assert_eq!(same.dimensions(), (1000, 500));

        // Degenerate caps still yield a usable 1px-wide image.
        let (tiny, resized) = downscale(image, Some(1), None);
        assert!(resized);
        assert_eq!(tiny.dimensions(), (1, 1));
    }

    #[test]
    fn stamps_increase() {
        let first = next_stamp_ms();
        let second = next_stamp_ms();
        assert!(second > first, "stamps must strictly increase: {first} then {second}");
        // Sanity: the stamp looks like a real epoch timestamp in this century.
        assert!(first > 1_600_000_000_000, "unexpected stamp: {first}");
    }
}
