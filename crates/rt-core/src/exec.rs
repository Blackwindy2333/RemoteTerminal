//! Command execution.
//!
//! Implements non-interactive command execution for the three Windows shells
//! (cmd.exe, Windows PowerShell 5.1, PowerShell 7) plus explicitly allow-listed
//! custom programs.
//!
//! ## Design notes
//!
//! * Everything here is **blocking**. `rt-server` is responsible for calling
//!   these functions from `tokio::task::spawn_blocking`; pulling an async
//!   process runtime into the core layer would leak into every consumer.
//! * Each child gets a dedicated reader thread per stream. Threads accumulate
//!   raw bytes into a shared [`StreamState`] (bounded by the output cap) and,
//!   when streaming, hand complete chunks back over a channel. The caller's
//!   sink is invoked from the calling thread only, which keeps
//!   `run_streaming` free of `Send`/`Sync` bounds on the `&mut dyn FnMut`.
//! * `effective_cwd` is always an absolute, canonical path that was resolved
//!   through the [`PathGuard`] jail, so a caller may safely log it.
//! * A *cancelled* run is reported as `timed_out = false` and `exit_code = -1`;
//!   the cancellation flag itself lives on [`ExecSummary::cancelled`] because
//!   [`ExecResult`] carries no such field.
//!
//! Interactive PTY sessions are **not** implemented here.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rt_protocol::{
    ExecRequest, ExecResult, ExecSummary, OutputEncoding, OutputStream, ShellAvailability,
    ShellKind, ShellListResponse,
};

use crate::error::{Result, RtError};
use crate::pathscope::PathGuard;
use crate::util;

/// Poll interval for child exit / cancellation / timeout checks.
const TICK: Duration = Duration::from_millis(50);
/// Bytes requested per pipe read.
const READ_CHUNK: usize = 8 * 1024;
/// A partial line longer than this is flushed early (always at a UTF-8 boundary).
const STREAM_CHUNK: usize = 8 * 1024;
/// Grace period granted to reader threads once the child is gone.
const READER_GRACE: Duration = Duration::from_millis(500);

/// `CREATE_NO_WINDOW` — spawned helpers must not flash a console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Timeout / output limits applied to a single execution.
#[derive(Debug, Clone)]
pub struct ExecLimits {
    /// Used when the request does not specify its own timeout.
    pub default_timeout: Duration,
    /// Hard ceiling; longer requested timeouts are clamped to this value.
    pub max_timeout: Duration,
    /// Hard ceiling for captured bytes per stream.
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
    /// Builds limits from the persisted configuration values.
    pub fn new(default_timeout_secs: u64, max_output_bytes: usize) -> Self {
        Self {
            default_timeout: Duration::from_secs(default_timeout_secs.max(1)),
            max_timeout: Duration::from_secs(3600),
            max_output_bytes: max_output_bytes.max(1024),
        }
    }

    /// Applies the configured ceiling to a requested timeout.
    pub fn clamp_timeout(&self, requested: Duration) -> Duration {
        requested.min(self.max_timeout)
    }
}

/// Cooperative cancellation handle for a running command.
///
/// The value is cheap to clone; cancelling any clone cancels the run.
#[derive(Debug, Clone, Default)]
pub struct ExecControl {
    flag: Arc<AtomicBool>,
}

impl ExecControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. The child is killed at the next poll tick.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Returns `true` once [`ExecControl::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Progress events emitted while a command runs.
#[derive(Debug, Clone)]
pub enum ExecEvent {
    /// The child process was spawned.
    Started {
        pid: Option<u32>,
        shell: ShellKind,
    },
    /// Decoded output chunk of one stream.
    Output(OutputStream, String),
    /// Terminal event, emitted exactly once for a streaming run.
    Finished(Box<ExecResult>),
}

/// Which events a particular entry point wants to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `run`: no events at all, only the final result.
    Buffered,
    /// `run_streaming`: `Started` + `Output` + `Finished`.
    Stream,
    /// `run_summary`: `Started` + `Output`, no `Finished`.
    Summary,
}

impl Mode {
    fn emits_output(self) -> bool {
        !matches!(self, Mode::Buffered)
    }

    fn emits_started(self) -> bool {
        !matches!(self, Mode::Buffered)
    }

    fn emits_finished(self) -> bool {
        matches!(self, Mode::Stream)
    }
}

/// Program plus fixed arguments for one shell.
struct ShellPlan {
    program: PathBuf,
    args: Vec<OsString>,
}

/// Accumulated state of one output stream.
struct StreamState {
    buffer: Mutex<Vec<u8>>,
    raw_bytes: AtomicU64,
    truncated: AtomicBool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(Vec::new()),
            raw_bytes: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
        }
    }

    /// Appends bytes up to `cap`, flipping the truncation flag on overflow.
    ///
    /// Bytes past the cap are dropped here but still counted as read by the
    /// caller, so the child never notices: the pipe keeps draining.
    fn capture(&self, bytes: &[u8], cap: usize) {
        let mut guard = match self.buffer.lock() {
            Ok(guard) => guard,
            // A panicking reader thread must not lose what it already
            // collected: recover the guard instead of dropping the data.
            Err(poisoned) => poisoned.into_inner(),
        };
        let room = cap.saturating_sub(guard.len());
        if room >= bytes.len() {
            guard.extend_from_slice(bytes);
        } else {
            guard.extend_from_slice(&bytes[..room]);
            self.truncated.store(true, Ordering::SeqCst);
        }
    }

    /// Captured bytes, raw byte count and the truncation flag.
    fn snapshot(&self) -> (Vec<u8>, u64, bool) {
        let bytes = match self.buffer.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        (
            bytes,
            self.raw_bytes.load(Ordering::SeqCst),
            self.truncated.load(Ordering::SeqCst),
        )
    }
}

/// One chunk handed from a reader thread to the calling thread.
struct Chunk {
    stream: OutputStream,
    bytes: Vec<u8>,
}

/// Runs a request to completion, returning stdout/stderr as decoded strings.
pub fn run(guard: &PathGuard, req: &ExecRequest, limits: &ExecLimits) -> Result<ExecResult> {
    let control = ExecControl::new();
    let (result, _cancelled) = execute(guard, req, limits, &control, &mut |_| {}, Mode::Buffered)?;
    Ok(result)
}

/// Runs a request to completion while forwarding output chunks to `sink`.
///
/// `ExecEvent::Started` is emitted right after the spawn and
/// `ExecEvent::Finished` exactly once when the run ends — including the
/// timeout and cancellation paths.
pub fn run_streaming(
    guard: &PathGuard,
    req: &ExecRequest,
    limits: &ExecLimits,
    control: ExecControl,
    sink: &mut dyn FnMut(ExecEvent),
) -> Result<ExecResult> {
    let (result, _cancelled) = execute(guard, req, limits, &control, sink, Mode::Stream)?;
    Ok(result)
}

/// Runs a request and returns only its summary (no payload).
///
/// This variant can observe cancellation, which [`ExecResult`] cannot express.
pub fn run_summary(
    guard: &PathGuard,
    req: &ExecRequest,
    limits: &ExecLimits,
    control: ExecControl,
    sink: &mut dyn FnMut(ExecEvent),
) -> Result<ExecSummary> {
    let (result, cancelled) = execute(guard, req, limits, &control, sink, Mode::Summary)?;
    Ok(ExecSummary {
        exit_code: result.exit_code,
        duration_ms: result.duration_ms,
        timed_out: result.timed_out,
        truncated: result.truncated,
        stdout_bytes: result.stdout_bytes,
        stderr_bytes: result.stderr_bytes,
        pid: result.pid,
        cancelled: Some(cancelled),
    })
}

/// Probes every shell this host can actually run.
///
/// Probing costs one short process spawn per shell, so the result is cached for
/// the lifetime of the process (and the probe budget is kept well under 3s).
/// Failures never bubble up: an unavailable shell is reported with
/// `available = false` and no version.
pub fn available_shells() -> Result<ShellListResponse> {
    let shells = SHELL_CACHE.get_or_init(probe_shells).clone();
    Ok(ShellListResponse {
        default_shell: default_shell(&shells),
        shells,
    })
}

/// Validates and normalises a request before execution.
///
/// Returns a copy with a clamped timeout, an absolute `cwd` inside the jail and
/// the stdin payload checked. The execution entry points call this themselves,
/// so callers that run a request immediately do not need it.
pub fn prepare(guard: &PathGuard, req: &ExecRequest, limits: &ExecLimits) -> Result<ExecRequest> {
    req.validate().map_err(RtError::bad_request)?;

    // The shell must resolve; `Custom` programs must point at an existing file.
    let _plan = shell_plan(&req.shell)?;

    let mut prepared = req.clone();

    if prepared.stdin_b64.is_some() {
        let bytes = decode_base64(prepared.stdin_b64.as_deref().unwrap_or_default())?;
        if bytes.len() as u64 > limits.max_output_bytes as u64 {
            return Err(RtError::bad_request(format!(
                "stdin payload of {} bytes exceeds the {} byte limit",
                bytes.len(),
                limits.max_output_bytes
            )));
        }
    }

    let requested = prepared
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(limits.default_timeout);
    let effective = limits.clamp_timeout(requested.max(Duration::from_millis(1)));
    prepared.timeout_ms = Some(effective.as_millis().min(u64::MAX as u128) as u64);

    prepared.cwd = Some(match prepared.cwd.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let resolved = guard.resolve_existing(raw)?;
            if !resolved.is_dir() {
                return Err(RtError::bad_request(format!("`{raw}` is not a directory")));
            }
            resolved.display().to_string()
        }
        // No working directory requested: the workspace root for a jailed
        // guard, the process directory for a full-scope guard.
        _ => match guard.root() {
            Some(root) => root.display().to_string(),
            None => std::env::current_dir()
                .map_err(|e| RtError::io(".", e))?
                .display()
                .to_string(),
        },
    });

    Ok(prepared)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

static SHELL_CACHE: OnceLock<Vec<ShellAvailability>> = OnceLock::new();

/// PowerShell 5.1 / 7 prefix, minus the terminating `-Command`.
const POWER_SHELL_PREFIX: [&str; 5] = [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
];

/// PowerShell 7 prefix: the same flags minus `-ExecutionPolicy`.
const PWSH_PREFIX: [&str; 3] = ["-NoLogo", "-NoProfile", "-NonInteractive"];

const PS_VERSION_SCRIPT: &str = "$PSVersionTable.PSVersion.ToString()";

fn probe_shells() -> Vec<ShellAvailability> {
    let candidates = [
        (ShellKind::Cmd, "cmd.exe"),
        (ShellKind::Powershell, "powershell.exe"),
        (ShellKind::Pwsh, "pwsh.exe"),
    ];

    candidates
        .iter()
        .map(|(kind, program)| {
            let path = util::which(program);
            let version = match (&path, kind) {
                (Some(found), ShellKind::Cmd) => probe_output(
                    found,
                    &["/d", "/s", "/c", "ver"],
                    Duration::from_millis(600),
                )
                .and_then(|text| cmd_version(&text)),
                (Some(found), ShellKind::Powershell) => probe_output(
                    found,
                    &[
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        PS_VERSION_SCRIPT,
                    ],
                    Duration::from_millis(1200),
                )
                .map(|text| last_line(&text)),
                (Some(found), ShellKind::Pwsh) => probe_output(
                    found,
                    &[
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        PS_VERSION_SCRIPT,
                    ],
                    Duration::from_millis(900),
                )
                .map(|text| last_line(&text)),
                (Some(_), ShellKind::Custom { .. }) | (None, _) => None,
            };

            ShellAvailability {
                shell: kind.clone(),
                available: path.is_some(),
                path: path.map(|p| p.display().to_string()),
                version,
            }
        })
        .collect()
}

/// Picks the default shell reported to clients: Windows PowerShell 5.1 first
/// (present on every Windows install), then PowerShell 7, then cmd.
fn default_shell(shells: &[ShellAvailability]) -> Option<String> {
    let preference = [ShellKind::Powershell, ShellKind::Pwsh, ShellKind::Cmd];
    preference
        .iter()
        .find_map(|wanted| {
            shells
                .iter()
                .find(|s| s.available && s.shell == *wanted)
                .map(|s| s.shell.display_name().to_string())
        })
        .or_else(|| {
            shells
                .iter()
                .find(|s| s.available)
                .map(|s| s.shell.display_name().to_string())
        })
}

/// Runs a short probe command and returns its decoded stdout, if it succeeded.
fn probe_output(program: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }

    let mut bytes = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(64 * 1024).read_to_end(&mut bytes);
    }
    let (text, _) = util::decode_output(&bytes, OutputEncoding::Auto);
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Extracts the version from `cmd /c ver` ("Microsoft Windows [Version 10.0...]").
fn cmd_version(text: &str) -> Option<String> {
    if let Some(start) = text.find("[Version ") {
        let rest = &text[start + "[Version ".len()..];
        if let Some(end) = rest.find(']') {
            let version = rest[..end].trim();
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    let last = last_line(text);
    if last.is_empty() {
        None
    } else {
        Some(last)
    }
}

fn last_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .next_back()
        .unwrap_or_default()
        .to_string()
}

/// Resolves a shell kind into the program to spawn plus its fixed arguments.
///
/// The command itself is appended by the caller as the last argument.
fn shell_plan(kind: &ShellKind) -> Result<ShellPlan> {
    match kind {
        ShellKind::Cmd => Ok(ShellPlan {
            program: require_shell("cmd.exe", ShellKind::Cmd)?,
            args: vec![OsString::from("/C")],
        }),
        ShellKind::Powershell => Ok(ShellPlan {
            program: require_shell("powershell.exe", ShellKind::Powershell)?,
            args: command_args(&POWER_SHELL_PREFIX),
        }),
        // PowerShell 7 is reported as unavailable when missing: silently
        // falling back to 5.1 would run the user's script in a different
        // language version than requested.
        ShellKind::Pwsh => Ok(ShellPlan {
            program: require_shell("pwsh.exe", ShellKind::Pwsh)?,
            args: command_args(&PWSH_PREFIX),
        }),
        ShellKind::Custom { program, args } => {
            let trimmed = program.trim();
            if trimmed.is_empty() {
                return Err(RtError::bad_request("custom shell program is empty"));
            }
            let path = PathBuf::from(trimmed);
            if !path.is_absolute() {
                return Err(RtError::bad_request(format!(
                    "custom shell program `{trimmed}` must be an absolute path"
                )));
            }
            if !path.is_file() {
                return Err(RtError::bad_request(format!(
                    "custom shell program `{trimmed}` is not an existing file"
                )));
            }
            Ok(ShellPlan {
                program: path,
                args: args.iter().map(OsString::from).collect(),
            })
        }
    }
}

fn command_args(prefix: &[&str]) -> Vec<OsString> {
    prefix
        .iter()
        .map(|flag| OsString::from(*flag))
        .chain(std::iter::once(OsString::from("-Command")))
        .collect()
}

fn require_shell(program: &str, kind: ShellKind) -> Result<PathBuf> {
    util::which(program).ok_or_else(|| {
        RtError::Unavailable(format!(
            "{} is not installed on this host (`{program}` not found)",
            kind.display_name()
        ))
    })
}

fn silence_console(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| RtError::bad_request(format!("stdin payload is not valid base64: {e}")))
}

/// Spawns the reader thread for one child pipe.
fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    state: Arc<StreamState>,
    sender: Option<Sender<Chunk>>,
    stream: OutputStream,
    cap: usize,
    done: Arc<AtomicUsize>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; READ_CHUNK];

        loop {
            let read = match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };

            // Raw accounting always continues; only captured bytes are capped,
            // otherwise a chatty child would block forever on a full pipe.
            state.raw_bytes.fetch_add(read as u64, Ordering::SeqCst);
            state.capture(&buf[..read], cap);

            if let Some(sender) = &sender {
                pending.extend_from_slice(&buf[..read]);
                flush_complete(&mut pending, sender, stream);
            }
        }

        // Flush the tail of the last (unterminated) line.
        if let Some(sender) = &sender {
            if !pending.is_empty() {
                let _ = sender.send(Chunk {
                    stream,
                    bytes: std::mem::take(&mut pending),
                });
            }
        }

        done.fetch_add(1, Ordering::SeqCst);
    })
}

/// Emits every complete line plus oversized partial lines, never splitting a
/// multi-byte UTF-8 sequence.
///
/// A writer that ends a chunk in the middle of a character (common with CP936
/// or any multi-byte encoding) leaves those trailing bytes in `pending` until
/// the next read.
fn flush_complete(pending: &mut Vec<u8>, sender: &Sender<Chunk>, stream: OutputStream) {
    loop {
        let cut = match pending.iter().rposition(|byte| *byte == b'\n') {
            Some(last_newline) => last_newline + 1,
            None if pending.len() > STREAM_CHUNK => safe_split_point(pending),
            None => 0,
        };
        if cut == 0 {
            return;
        }
        let bytes: Vec<u8> = pending.drain(..cut).collect();
        let _ = sender.send(Chunk {
            stream: stream.clone(),
            bytes,
        });
    }
}

/// Largest boundary below `chunk` that does not split a UTF-8 sequence.
///
/// A byte is a continuation byte when its top two bits are `10`; cutting in
/// front of it means the previous code point stays intact.
fn safe_split_point(bytes: &[u8]) -> usize {
    let mut cut = bytes.len().min(STREAM_CHUNK);
    while cut > 0 && (bytes[cut] & 0b1100_0000) == 0b1000_0000 {
        cut -= 1;
    }
    if cut == 0 {
        // Every candidate was a continuation byte; keep the bytes and wait for
        // more input instead of corrupting the stream.
        0
    } else {
        cut
    }
}

fn forward_chunk(chunk: Chunk, encoding: OutputEncoding, sink: &mut dyn FnMut(ExecEvent)) {
    let (text, _) = util::decode_output(&chunk.bytes, encoding);
    if !text.is_empty() {
        sink(ExecEvent::Output(chunk.stream, text));
    }
}

/// Kills the child and, on Windows, its whole process tree.
fn kill_tree(child: &mut std::process::Child, pid: u32) {
    let _ = child.kill();

    #[cfg(windows)]
    {
        // `child.kill()` only reaches the direct child; cmd.exe / powershell.exe
        // usually have grandchildren that would keep running (and keep the pipe
        // open). `taskkill /T` is the portable way to take the tree down.
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        silence_console(&mut cmd);
        let _ = cmd.status();
    }

    let _ = child.wait();
}

/// Shared execution pipeline for `run`, `run_streaming` and `run_summary`.
fn execute(
    guard: &PathGuard,
    req: &ExecRequest,
    limits: &ExecLimits,
    control: &ExecControl,
    sink: &mut dyn FnMut(ExecEvent),
    mode: Mode,
) -> Result<(ExecResult, bool)> {
    let req = prepare(guard, req, limits)?;
    let plan = shell_plan(&req.shell)?;

    let stdin_bytes = match req.stdin_b64.as_deref() {
        Some(value) => Some(decode_base64(value)?),
        None => None,
    };

    let cwd = req
        .cwd
        .clone()
        .ok_or_else(|| RtError::internal("prepare() left no working directory"))?;

    let cap = req
        .max_output_bytes
        .map(|value| value.min(limits.max_output_bytes as u64))
        .unwrap_or(limits.max_output_bytes as u64) as usize;
    let timeout = req
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(limits.default_timeout)
        .max(Duration::from_millis(1))
        .min(limits.max_timeout);

    let mut command = Command::new(&plan.program);
    command
        .args(&plan.args)
        .arg(&req.command)
        .current_dir(&cwd)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &req.env {
        command.env(key, value);
    }
    silence_console(&mut command);

    let mut child = command
        .spawn()
        .map_err(|e| RtError::io(plan.program.clone(), e))?;
    let pid = child.id();
    let started_at = Instant::now();

    if mode.emits_started() {
        sink(ExecEvent::Started {
            pid: Some(pid),
            shell: req.shell.clone(),
        });
    }

    // Feed stdin, if any. A child that exits early closes the pipe; that is not
    // an error of its own — the exit status tells the story.
    if let Some(bytes) = stdin_bytes {
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(&bytes);
            let _ = pipe.flush();
        }
    }

    let out_state = Arc::new(StreamState::new());
    let err_state = Arc::new(StreamState::new());

    let (tx, rx): (Sender<Chunk>, Receiver<Chunk>) = mpsc::channel();
    let reader_channel = if mode.emits_output() {
        Some(tx.clone())
    } else {
        None
    };

    // `done` counts reader threads that reached EOF, so the caller can wait for
    // the pipes to drain without blocking forever on a stuck grandchild.
    let done = Arc::new(AtomicUsize::new(0));
    let mut readers = 0usize;
    if let Some(pipe) = child.stdout.take() {
        spawn_reader(
            pipe,
            Arc::clone(&out_state),
            reader_channel.clone(),
            OutputStream::Stdout,
            cap,
            Arc::clone(&done),
        );
        readers += 1;
    }
    if let Some(pipe) = child.stderr.take() {
        spawn_reader(
            pipe,
            Arc::clone(&err_state),
            reader_channel,
            OutputStream::Stderr,
            cap,
            Arc::clone(&done),
        );
        readers += 1;
    }
    // Drop our own sender so the receiver disconnects once both readers end.
    drop(tx);

    let mut status = None;
    let mut timed_out = false;
    let mut cancelled = false;
    let deadline = started_at + timeout;
    let mut channel_open = mode.emits_output();

    loop {
        if channel_open {
            match rx.recv_timeout(TICK) {
                Ok(chunk) => forward_chunk(chunk, req.encoding, sink),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => channel_open = false,
            }
        } else {
            std::thread::sleep(TICK);
        }

        match child.try_wait() {
            Ok(Some(exit)) => {
                status = Some(exit);
                break;
            }
            Ok(None) => {}
            Err(e) => {
                kill_tree(&mut child, pid);
                return Err(RtError::io(plan.program.clone(), e));
            }
        }

        if control.is_cancelled() {
            cancelled = true;
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
    }

    if status.is_none() {
        kill_tree(&mut child, pid);
        status = child.try_wait().ok().flatten();
    }

    // Drain what the readers produced, bounded by `READER_GRACE`. In buffered
    // mode only the EOF counter matters, because no chunks are being sent.
    let drain_deadline = Instant::now() + READER_GRACE;
    if mode.emits_output() {
        loop {
            let remaining = drain_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining.min(TICK)) {
                Ok(chunk) => forward_chunk(chunk, req.encoding, sink),
                Err(RecvTimeoutError::Timeout) => {
                    if done.load(Ordering::SeqCst) >= readers {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    } else {
        while done.load(Ordering::SeqCst) < readers && Instant::now() < drain_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let duration_ms = started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;

    let (stdout_captured, stdout_bytes, stdout_truncated) = out_state.snapshot();
    let (stderr_captured, stderr_bytes, stderr_truncated) = err_state.snapshot();

    let (stdout, stdout_label) = util::decode_output(&stdout_captured, req.encoding);
    let (stderr, stderr_label) = util::decode_output(&stderr_captured, req.encoding);
    // Report the encoding actually used for the stream that carried output; with
    // two empty streams fall back to the request's nominal encoding.
    let encoding_label = if !stdout_captured.is_empty() {
        stdout_label
    } else if !stderr_captured.is_empty() {
        stderr_label
    } else {
        let (_, nominal) = util::decode_output(&[], req.encoding);
        nominal
    };

    // A killed child (timeout / cancellation) has no portable exit code, so the
    // documented `-1` placeholder is used. `TerminateProcess` would otherwise
    // leak the `1` the killer passes, which clients misread as a real failure.
    let exit_code = if timed_out || cancelled {
        -1
    } else {
        status.and_then(|exit| exit.code()).unwrap_or(-1)
    };

    let result = ExecResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
        truncated: stdout_truncated || stderr_truncated,
        duration_ms,
        shell: req.shell.display_name().to_string(),
        effective_cwd: Some(cwd),
        encoding: encoding_label,
        pid: Some(pid),
        stdout_bytes,
        stderr_bytes,
    };

    if mode.emits_finished() {
        sink(ExecEvent::Finished(Box::new(result.clone())));
    }

    Ok((result, cancelled))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use rt_protocol::Scope;

    fn limits() -> ExecLimits {
        ExecLimits::new(30, 1024 * 1024)
    }

    fn guard() -> PathGuard {
        PathGuard::new(Scope::Full, None).expect("full-scope guard")
    }

    /// A temporary directory that is removed when the test ends.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rt_exec_{tag}_{}_{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Absolute path in the plain `C:\...` form the guard and `cmd` report;
    /// `canonicalize` returns the verbatim `\\?\C:\...` form on Windows.
    fn plain_path(path: &Path) -> String {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let text = canonical.to_string_lossy().into_owned();
        match text.strip_prefix(r"\\?\") {
            Some(stripped) => stripped.to_string(),
            None => text,
        }
    }

    fn have_powershell() -> bool {
        util::which("powershell.exe").is_some()
    }

    #[test]
    fn cmd_echo_reports_exit_code_and_stdout() {
        let req = ExecRequest::new(ShellKind::Cmd, "echo hello");
        let result = run(&guard(), &req, &limits()).expect("run");

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello");
        assert!(result.stderr.is_empty());
        assert!(!result.timed_out);
        assert!(!result.truncated);
        assert_eq!(result.encoding, "utf-8");
        assert!(result.pid.is_some());
        assert!(result.stdout_bytes >= 5);
        assert!(result.effective_cwd.is_some());
        assert_eq!(result.shell, "cmd");
    }

    #[test]
    fn cmd_non_zero_exit_code_is_preserved() {
        let req = ExecRequest::new(ShellKind::Cmd, "exit /b 7");
        let result = run(&guard(), &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 7);
        assert!(!result.timed_out);
    }

    /// UTF-8 bytes for 你好, written straight to stdout so the test does not
    /// depend on the console code page of the test host.
    #[test]
    fn utf8_output_is_decoded_without_mojibake() {
        if !have_powershell() {
            return;
        }
        let script = "[byte[]](0xE4,0xBD,0xA0,0xE5,0xA5,0xBD) | \
                      ForEach-Object { [Console]::OpenStandardOutput().Write([byte[]]@($_), 0, 1) }";
        let req = ExecRequest::new(ShellKind::Powershell, script);

        // Valid UTF-8 goes through untouched under `Auto`.
        let utf8 = run(&guard(), &req, &limits()).expect("run utf8");
        assert_eq!(utf8.stdout, "你好");
        assert_eq!(utf8.encoding, "utf-8");

        // Forcing GBK on UTF-8 bytes proves the override is honoured: this is
        // exactly the mojibake a client sees when it guesses the wrong code
        // page, and the label must say so.
        let mut forced = req.clone();
        forced.encoding = OutputEncoding::Gbk;
        let gbk = run(&guard(), &forced, &limits()).expect("run gbk");
        assert_eq!(gbk.encoding, "gbk");
        assert_ne!(gbk.stdout, utf8.stdout);
    }

    /// CP936 你 好 as *invalid* UTF-8: `Auto` must fall back to GBK.
    #[test]
    fn auto_encoding_falls_back_to_gbk() {
        if !have_powershell() {
            return;
        }
        let script = "[byte[]](0xC4,0xE3,0xBA,0xC3) | \
                      ForEach-Object { [Console]::OpenStandardOutput().Write([byte[]]@($_), 0, 1) }";
        let req = ExecRequest::new(ShellKind::Powershell, script);

        let auto = run(&guard(), &req, &limits()).expect("run auto");
        assert_eq!(auto.stdout, "你好");
        assert_eq!(auto.encoding, "gbk");

        // An explicit GBK request must agree with the auto-detected answer.
        let mut forced = req.clone();
        forced.encoding = OutputEncoding::Gbk;
        let gbk = run(&guard(), &forced, &limits()).expect("run gbk");
        assert_eq!(gbk.stdout, "你好");
        assert_eq!(gbk.encoding, "gbk");
    }

    #[test]
    fn timeout_kills_the_child_and_sets_the_flag() {
        if !have_powershell() {
            return;
        }
        let mut req = ExecRequest::new(ShellKind::Powershell, "Start-Sleep -Seconds 5");
        req.timeout_ms = Some(400);

        let started = Instant::now();
        let result = run(&guard(), &req, &limits()).expect("run");
        let elapsed = started.elapsed();

        assert!(result.timed_out, "request should have timed out");
        assert_eq!(result.exit_code, -1);
        assert!(
            elapsed < Duration::from_secs(4),
            "timeout must kill the child early, took {elapsed:?}"
        );
    }

    #[test]
    fn cancellation_is_reported_through_the_summary() {
        if !have_powershell() {
            return;
        }
        let mut req = ExecRequest::new(ShellKind::Powershell, "Start-Sleep -Seconds 5");
        req.timeout_ms = Some(30_000);

        let control = ExecControl::new();
        let trigger = Arc::new(control.clone());
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            trigger.cancel();
        });

        let started = Instant::now();
        let summary = run_summary(&guard(), &req, &limits(), control.clone(), &mut |_| {})
            .expect("run_summary");
        worker.join().expect("cancel thread");

        assert_eq!(summary.cancelled, Some(true));
        assert!(!summary.timed_out, "cancellation is not a timeout");
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn streaming_delivers_multiple_chunks_and_started_finished() {
        let script = "for /L %i in (1,1,6) do @(echo chunk-%i & ping -n 2 127.0.0.1 >nul)";
        let req = ExecRequest::new(ShellKind::Cmd, script);

        let mut events: Vec<ExecEvent> = Vec::new();
        let result = {
            let mut sink = |event: ExecEvent| events.push(event);
            run_streaming(
                &guard(),
                &req,
                &limits(),
                ExecControl::new(),
                &mut sink,
            )
        }
        .expect("run_streaming");

        assert_eq!(result.exit_code, 0);

        let started_count = events
            .iter()
            .filter(|event| matches!(event, ExecEvent::Started { .. }))
            .count();
        let finished_count = events
            .iter()
            .filter(|event| matches!(event, ExecEvent::Finished(_)))
            .count();
        assert_eq!(started_count, 1, "exactly one Started event");
        assert_eq!(finished_count, 1, "exactly one Finished event");

        let chunks: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                ExecEvent::Output(_, text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(
            chunks.len() >= 2,
            "expected several output chunks, got {chunks:?}"
        );

        let joined = chunks.concat();
        for index in 1..=6 {
            assert!(
                joined.contains(&format!("chunk-{index}")),
                "missing chunk-{index} in {joined:?}"
            );
        }
    }

    #[test]
    fn output_cap_truncates_but_keeps_reading() {
        let req = ExecRequest::new(
            ShellKind::Cmd,
            "for /L %i in (1,1,3000) do @echo 0123456789",
        );
        let tight = ExecLimits {
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(60),
            max_output_bytes: 4096,
        };

        let result = run(&guard(), &req, &tight).expect("run");
        assert_eq!(result.exit_code, 0, "the child must finish, not block");
        assert!(result.truncated, "truncation flag must be set");
        assert!(result.stdout_bytes > 4096, "raw counter keeps counting");
        assert!(result.stdout.len() <= 4096);
    }

    #[test]
    fn available_shells_always_include_cmd() {
        let list = available_shells().expect("shell list");
        assert_eq!(list.shells.len(), 3);
        let cmd = list
            .shells
            .iter()
            .find(|s| matches!(s.shell, ShellKind::Cmd))
            .expect("cmd entry");
        assert!(cmd.available, "cmd.exe must exist on Windows");
        assert!(cmd.path.as_deref().is_some_and(|p| p.to_lowercase().ends_with("cmd.exe")));

        // Cached: a second call must agree with the first.
        let again = available_shells().expect("cached shell list");
        assert_eq!(again.shells.len(), 3);
        assert!(list.default_shell.is_some());
    }

    #[test]
    fn workspace_cwd_is_jailed_and_used_as_effective_cwd() {
        let temp = TempRoot::new("cwd");
        std::fs::create_dir_all(temp.path().join("sub")).expect("mkdir");
        let guard = PathGuard::new(Scope::Workspace, Some(temp.path())).expect("jailed guard");
        let canonical = plain_path(temp.path());

        let req = ExecRequest::new(ShellKind::Cmd, "cd");
        let result = run(&guard, &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 0);

        let effective = result.effective_cwd.expect("effective cwd");
        assert!(
            PathBuf::from(&effective)
                .to_string_lossy()
                .eq_ignore_ascii_case(&canonical),
            "default cwd must be the workspace root, got {effective}"
        );
        assert!(
            result.stdout.trim().eq_ignore_ascii_case(&canonical),
            "`cmd /C cd` must report the guarded root, got {:?}",
            result.stdout
        );

        // Inside the jail is fine.
        let mut inside = ExecRequest::new(ShellKind::Cmd, "cd");
        inside.cwd = Some("sub".to_string());
        let result = run(&guard, &inside, &limits()).expect("run in sub");
        assert!(result.stdout.trim().ends_with("sub"));
    }

    #[test]
    fn cwd_outside_the_jail_is_rejected() {
        let temp = TempRoot::new("jail");
        let guard = PathGuard::new(Scope::Workspace, Some(temp.path())).expect("jailed guard");

        let mut req = ExecRequest::new(ShellKind::Cmd, "cd");
        req.cwd = Some("..".to_string());
        assert!(prepare(&guard, &req, &limits()).is_err());
        assert!(run(&guard, &req, &limits()).is_err());

        req.cwd = Some("C:\\Windows".to_string());
        assert!(run(&guard, &req, &limits()).is_err());
    }

    #[test]
    fn prepare_clamps_timeouts_and_rejects_custom_missing_program() {
        let guard = guard();
        let mut req = ExecRequest::new(ShellKind::Cmd, "echo hi");
        req.timeout_ms = Some(24 * 60 * 60 * 1000);
        let prepared = prepare(&guard, &req, &limits()).expect("prepare");
        assert_eq!(
            prepared.timeout_ms,
            Some(Duration::from_secs(3600).as_millis() as u64),
            "timeout must be clamped to max_timeout"
        );

        let mut custom = ExecRequest::new(
            ShellKind::Custom {
                program: "C:\\definitely\\not\\here.exe".to_string(),
                args: Vec::new(),
            },
            "echo hi",
        );
        custom.command = "echo hi".to_string();
        assert!(prepare(&guard, &custom, &limits()).is_err());

        let missing = ExecRequest::new(ShellKind::Pwsh, "echo hi");
        if util::which("pwsh.exe").is_none() {
            // PowerShell 7 is optional: a clear `Unavailable` beats a silent
            // downgrade to 5.1.
            let error = prepare(&guard, &missing, &limits()).expect_err("pwsh must be required");
            assert_eq!(error.code(), rt_protocol::ErrorCode::Unavailable);
        }
    }

    #[test]
    fn stdin_is_forwarded() {
        let mut req = ExecRequest::new(ShellKind::Cmd, "more");
        req.stdin_b64 = Some({
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(b"from stdin")
        });

        let result = run(&guard(), &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("from stdin"));
    }

    #[test]
    fn environment_overrides_reach_the_child() {
        let mut req = ExecRequest::new(ShellKind::Cmd, "echo %RT_EXEC_ENV_VALUE%");
        req.env
            .insert("RT_EXEC_ENV_VALUE".to_string(), "hello-env".to_string());

        let result = run(&guard(), &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello-env");
    }
}
