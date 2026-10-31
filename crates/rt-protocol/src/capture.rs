//! Remote screen / window capture wire types.

use serde::{Deserialize, Serialize};

/// What to grab.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureTarget {
    /// Monitor flagged as primary.
    Primary,
    /// A specific monitor by id (see [`ScreenInfo::id`]).
    Screen { id: u32 },
    /// Every monitor stitched into one imagem.
    AllScreens,
    /// One top-level window by id (see [`WindowInfo::id`]).
    Window { id: u64 },
}

impl Default for CaptureTarget {
    fn default() -> Self {
        CaptureTarget::Primary
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    #[default]
    Png,
    Jpeg,
    /// Lossless but large; handy for pixel-exact inspection.
    Bmp,
}

impl ImageFormat {
    pub fn mime(&self) -> &'static str {
        match self {
            ImageFormat::Png => "image/png",
            ImageFormat::Jpeg => "image/jpeg",
            ImageFormat::Bmp => "image/bmp",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Bmp => "bmp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "png" | "image/png" => Some(ImageFormat::Png),
            "jpg" | "jpeg" | "image/jpeg" => Some(ImageFormat::Jpeg),
            "bmp" | "image/bmp" => Some(ImageFormat::Bmp),
            _ => None,
        }
    }
}

/// `POST /api/v1/capture`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRequest {
    #[serde(default)]
    pub target: CaptureTarget,
    #[serde(default)]
    pub format: ImageFormat,
    /// 1-100, JPEG only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<u8>,
    /// Downscale so neither dimension exceeds the cap (aspect preserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_height: Option<u32>,
}

impl CaptureRequest {
    pub fn png(target: CaptureTarget) -> Self {
        Self {
            target,
            format: ImageFormat::Png,
            quality: None,
            max_width: None,
            max_height: None,
        }
    }

    pub fn jpeg_preview(target: CaptureTarget, quality: u8, max_width: Option<u32>) -> Self {
        Self {
            target: target,
            format: ImageFormat::Jpeg,
            quality: Some(quality),
            max_width,
            max_height: None,
        }
    }
}

/// Metadata describing a produced image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureMeta {
    pub format: ImageFormat,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    /// Monotonic ms timestamp of the grab.
    pub captured_at_ms: i64,
    pub duration_ms: u64,
    /// Human description, e.g. `screen:1 (1920x1080)`.
    pub target: String,
    /// True when the frame was downscaled.
    #[serde(default)]
    pub resized: bool,
}

/// JSON variant of the capture response, used by MCP tools and the GUI's
/// history strip (raw-bytes endpoint is preferred for display).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResponse {
    #[serde(flatten)]
    pub meta: CaptureMeta,
    /// Base64-encoded image bytes.
    pub data_b64: String,
}

impl CaptureResponse {
    pub fn into_bytes(&self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(self.data_b64.as_bytes())
            .ok()
    }
}

/// A monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenInfo {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    /// Virtual-desktop origin in physical pixels (multi-monitor layouts).
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
    #[serde(default)]
    pub scale_factor: f32,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hz: Option<u32>,
    #[serde(default)]
    pub is_capturable: bool,
}

/// A top-level window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub id: u64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub is_foreground: bool,
    #[serde(default)]
    pub is_minimized: bool,
    #[serde(default)]
    pub is_visible: bool,
    #[serde(default)]
    pub is_capturable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenListResponse {
    pub screens: Vec<ScreenInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowListResponse {
    pub windows: Vec<WindowInfo>,
    #[serde(default)]
    pub truncated: bool,
    pub sampled_at: String,
}

/// One frame of a `capture.stream` WebSocket subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFrame {
    pub seq: u64,
    pub meta: CaptureMeta,
    /// Base64 JPEG/PNG payload.
    pub data_b64: String,
}
