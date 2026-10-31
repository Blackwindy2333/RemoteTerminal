//! Remote command execution wire types.
//!
//! Two shapes exist for the same feature:
//! * one-shot (`POST /api/v1/exec`) → buffered [`ExecResult`], bounded;
//! * streaming (WS `exec`) → [`OutputStream`] chunks then an [`ExecSummary`],
//!   which is what a terminal pane or a long build wants.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which interpreter runs the command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShellKind {
    /// `cmd.exe /d /s /c <command>`
    Cmd,
    /// Windows PowerShell 5.1 (`powershell.exe -NoProfile -NonInteractive -Command`)
    Powershell,
    /// PowerShell 7+ (`pwsh.exe -NoProfile -NonInteractive -Command`)
    Pwsh,
    /// Explicit program, e.g. `python.exe` with custom args.
    Custom {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

impl Default for ShellKind {
    fn default() -> Self {
        ShellKind::Pwsh
    }
}

impl ShellKind {
    pub fn display_name(&self) -> String {
        match self {
            ShellKind::Cmd => "cmd".into(),
            ShellKind::Powershell => "powershell".into(),
            ShellKind::Pwsh => "pwsh".into(),
            ShellKind::Custom { program, .. } => program.clone(),
        }
    }

    pub fn parse_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "cmd" | "cmd.exe" => Some(ShellKind::Cmd),
            "powershell" | "powershell.exe" | "ps" | "ps5" => Some(ShellKind::Powershell),
            "pwsh" | "pwsh.exe" | "ps7" => Some(ShellKind::Pwsh),
            _ => None,
        }
    }
}

/// How to decode raw child-process bytes into text. Windows tools disagree:
/// `cmd.exe` emits the OEM code page, PowerShell 7 emits UTF-8.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputEncoding {
    /// Strict UTF-8, falling back to the next candidate on failure.
    #[default]
    Auto,
    Utf8,
    /// GBK / code page 936 (simplified Chinese legacy output).
    Gbk,
    /// Latin-1 style byte→char mapping; never fails.
    Raw,
}

/// `POST /api/v1/exec`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    #[serde(default)]
    pub shell: ShellKind,
    pub command: String,
    /// Working directory; relative values resolve against the workspace root for
    /// jailed sessions, or against the server's CWD for full ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Hard wall-clock limit; the server clamps it to its configured maximum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Byte cap for each stream; excess is dropped and flagged `truncated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
    #[serde(default)]
    pub encoding: OutputEncoding,
    /// Feed these bytes to stdin, then close it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_b64: Option<String>,
}

impl ExecRequest {
    pub fn new(shell: ShellKind, command: impl Into<String>) -> Self {
        Self {
            shell,
            command: command.into(),
            cwd: None,
            env: BTreeMap::new(),
            timeout_ms: None,
            max_output_bytes: None,
            encoding: OutputEncoding::Auto,
            stdin_b64: None,
        }
    }

    /// Cheap syntactic sanity check; the server additionally enforces policy.
    pub fn validate(&self) -> Result<(), String> {
        if self.command.trim().is_empty() {
            return Err("command must not be empty".into());
        }
        if self.command.len() > 1_000_000 {
            return Err("command is too long (max 1 MiB)".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub truncated: bool,
    pub duration_ms: u64,
    pub shell: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_cwd: Option<String>,
    /// Encoding actually used for decoding.
    #[serde(default)]
    pub encoding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub stdout_bytes: u64,
    #[serde(default)]
    pub stderr_bytes: u64,
}

/// Which stream a chunk came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
    /// Server-side note (e.g. "process started", "timeout reached").
    Notice,
}

/// Final status after a streamed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSummary {
    pub exit_code: i32,
    pub duration_ms: u64,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub truncated: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
}

/// `GET /api/v1/exec/shells` — what this host can actually run, so the GUI can
/// hide `pwsh` when PowerShell 7 is not installed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellAvailability {
    pub shell: ShellKind,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellListResponse {
    pub shells: Vec<ShellAvailability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_shell: Option<String>,
}
