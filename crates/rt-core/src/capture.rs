//! Screen and window capture (single frame now, frames are streamed by the
//! WebSocket layer).
//!
//! STATUS: interface stub — bodies are implemented by the capture module owner.
//! Signatures are the frozen contract used by `rt-server`.

use rt_protocol::{
    CaptureFrame, CaptureRequest, CaptureResponse, ScreenInfo, WindowInfo,
};

use crate::error::{Result, RtError};

fn todo<T>(what: &str) -> Result<T> {
    Err(RtError::NotImplemented(format!("capture::{what}")))
}

/// Every capturable monitor, ordered primary-first.
pub fn list_screens() -> Result<Vec<ScreenInfo>> {
    todo("list_screens")
}

/// Top-level visible windows. Windows we cannot capture are still listed, with
/// `is_capturable = false`, so the UI can grey them out instead of hiding them.
pub fn list_windows() -> Result<Vec<WindowInfo>> {
    todo("list_windows")
}

/// Grabs one frame according to `req`, resizing when requested.
pub fn capture(_req: &CaptureRequest) -> Result<CaptureResponse> {
    todo("capture")
}

/// Same as [`capture`] but tagged with a stream sequence number.
pub fn capture_frame(_req: &CaptureRequest, _seq: u64) -> Result<CaptureFrame> {
    todo("capture_frame")
}

/// Cheap liveness probe used by `/healthz` and the status panel.
pub fn is_available() -> bool {
    false
}
