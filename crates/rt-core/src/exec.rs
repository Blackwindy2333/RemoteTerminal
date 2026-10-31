//! Command execution: cmd, Windows PowerShell 5.1, PowerShell 7 and custom
//! programs, with timeout, output cap, encoding detection and cancellation.
//!
//! STATUS: interface stub — bodies are implemented by the exec module owner.
//! The public signatures below are the frozen contract used by `rt-server` and
//! the MCP bridge.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rt_protocol::{ExecRequest, ExecResult, ExecSummary, OutputStream, ShellKind, ShellListResponse};

use crate::error::{Result, RtError};
use crate::pathscope::PathGuard;

/// Execution ceilings from `[server]`.
#[derive(Debug, Clone)]
pub struct ExecLimits {
    pub default_timeout: Duration,
    pub max_timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(300),
            max_timeout: Duration::from_secs(3600),
            max_output_bytes: 8 * 1024 * 1024,
        }
    }
}

impl ExecLimits {
    pub fn new(default_timeout_secs: u64, max_output_bytes: usize) -> Self {
        Self {
            default_timeout: Duration::from_secs(default_timeout_secs.max(1)),
            max_timeout: Duration::from_secs(3600),
            max_output_bytes,
        }
    }
}

/// Cooperative cancellation handle shared between the HTTP layer and the
/// process runner (used by the WebSocket `cancel` message).
#[derive(Debug, Clone, Default)]
pub struct ExecControl {
    cancelled: Arc<AtomicBool>,
}

impl ExecControl {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Progress items emitted while a command runs.
#[derive(Debug, Clone)]
pub enum ExecEvent {
    /// The shell process is alive; `pid` is set when the platform reports one.
    Started { pid: Option<u32>, shell: ShellKind },
    /// A decoded chunk of output, ready to forward as-is.
    Output(OutputStream, String),
    /// Terminal event, emitted exactly once.
    Finished(Box<ExecResult>),
}

fn todo<T>(what: &str) -> Result<T> {
    Err(RtError::NotImplemented(format!("exec::{what}")))
}

/// Runs a command to completion and returns everything it produced.
pub fn run(_guard: &PathGuard, _req: &ExecRequest, _limits: &ExecLimits) -> Result<ExecResult> {
    todo("run")
}

/// Runs a command, forwarding decoded output to `sink` as it arrives and
/// honouring `control` for cancellation. The returned `ExecResult` carries the
/// truncated-to-cap tail so callers can still render the end of the output.
pub fn run_streaming(
    _guard: &PathGuard,
    _req: &ExecRequest,
    _limits: &ExecLimits,
    _control: ExecControl,
    _sink: &mut dyn FnMut(ExecEvent),
) -> Result<ExecResult> {
    todo("run_streaming")
}

/// Which shells exist on this machine and what each one resolves to.
pub fn available_shells() -> Result<ShellListResponse> {
    todo("available_shells")
}

/// Validates and normalises a request (timeouts clamped, cwd resolved through
/// the guard, shell availability checked).
pub fn prepare(_guard: &PathGuard, _req: &ExecRequest, _limits: &ExecLimits) -> Result<ExecRequest> {
    todo("prepare")
}

/// Runs a command and only reports the summary (used by the WS/async paths when
/// output is streamed elsewhere).
pub fn run_summary(
    _guard: &PathGuard,
    _req: &ExecRequest,
    _limits: &ExecLimits,
    _control: ExecControl,
    _sink: &mut dyn FnMut(ExecEvent),
) -> Result<ExecSummary> {
    todo("run_summary")
}
