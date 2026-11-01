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
//!   when streaming, hand complete chunks back over a **bounded** channel: a
//!   consumer that stops draining throttles the child through the full pipes
//!   instead of growing the queue. The caller's sink is invoked from the calling
//!   thread only, which keeps `run_streaming` free of `Send`/`Sync` bounds on
//!   the `&mut dyn FnMut`.
//! * A consumer that walks away — or accepts nothing for a full second — aborts
//!   the run, kills the process tree and is reported as a cancellation, so a
//!   disconnected operator cannot leave the exporter collecting data nobody
//!   reads.
//! * On Windows the child is placed in a kill-on-close **job object**, so the
//!   whole process tree dies with the run even when a grandchild detaches from
//!   the direct child; `taskkill /T /F` remains as the fallback when the OS
//!   refuses the job, and it is always invoked through its absolute system
//!   path (resolved with `GetSystemDirectoryW`) so neither a poisoned `PATH` nor
//!   a rewritten `%SystemRoot%` can intercept the teardown.
//! * Standard input is decoded in bounded slices and written from a dedicated
//!   thread, so a child that never reads can be killed by the deadline instead
//!   of parking the collector inside a blocking write.
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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::mpsc::{self as stream_mpsc, Receiver, Sender};

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
/// Bounded depth of the streaming hand-off channel, in chunks.
///
/// Together with [`STREAM_CHUNK`] this caps the queue at roughly 2 MiB, so a
/// consumer that stops draining can no longer make the exporter grow without
/// bound (S-07): the readers block, the pipes fill and the child is throttled.
const STREAM_CHANNEL_CAPACITY: usize = 256;
/// Longest a reader waits to hand one chunk to the consumer. A consumer that
/// cannot take a single chunk for this long while the queue is full is treated
/// as gone and the run is aborted.
const STREAM_SEND_TIMEOUT: Duration = Duration::from_millis(1000);
/// Poll interval used while waiting for room in the bounded channel.
const STREAM_SEND_POLL: Duration = Duration::from_millis(5);
/// Largest decoded stdin slice handed to the child in one write.
///
/// The payload is decoded and written in pieces of this size, so a large
/// `stdin_b64` never materialises a second full copy in memory (S-12).
const STDIN_CHUNK_BYTES: usize = 64 * 1024;
/// Number of base64 characters whose decoding stays within
/// [`STDIN_CHUNK_BYTES`]. A multiple of four, so every slice decodes alone.
const STDIN_CHUNK_QUAD: usize = 4 * (STDIN_CHUNK_BYTES / 3);

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
    /// The script must be handed over as `-EncodedCommand` (base64 UTF-16LE)
    /// instead of being appended to the command line verbatim.
    encoded: bool,
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

/// Bounded hand-off channel between the pipe readers and the collector.
type ChunkSender = Sender<Chunk>;
/// Collecting end of the hand-off channel.
type ChunkReceiver = Receiver<Chunk>;

/// Hands one chunk to the consumer of a streaming run.
///
/// Returns `false` when the consumer is gone, which means the caller must tear
/// the run down. Two cases collapse into that verdict:
///
/// * the receiver was dropped (the operator disconnected);
/// * the bounded queue stayed full for [`STREAM_SEND_TIMEOUT`], i.e. the
///   consumer is wedged and would otherwise pin the child and this thread
///   forever.
///
/// `blocking_send` is the natural call here, but it parks the collector thread
/// until the consumer drains and therefore cannot be bounded by a timeout — a
/// wedged consumer would never be detected, which is exactly the leak this
/// channel is meant to close. Polling `try_send` provides the same backpressure
/// (a full queue blocks the reader, the pipe fills, the child throttles) while
/// keeping the wait bounded.
fn deliver(sender: &ChunkSender, chunk: Chunk) -> bool {
    let deadline = Instant::now() + STREAM_SEND_TIMEOUT;
    let mut chunk = chunk;
    loop {
        match sender.try_send(chunk) {
            Ok(()) => return true,
            Err(TrySendError::Closed(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                chunk = returned;
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(STREAM_SEND_POLL);
            }
        }
    }
}

/// Tears a run down because the consumer of the chunk stream went away.
///
/// Called from a reader thread, which holds no `Child` handle, so the tree is
/// killed by PID: the child must not keep running (and writing) for a consumer
/// that no longer exists.
fn abandon_consumer(pid: u32, abandoned: &AtomicBool) {
    abandoned.store(true, Ordering::SeqCst);
    kill_tree_by_pid(pid);
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

    if let Some(payload) = prepared.stdin_b64.as_deref() {
        // Decoded in slices: the check must not build a full copy of a hostile
        // payload before the command even starts.
        let decoded_len = for_each_base64_chunk(payload, |_slice| Ok(()))?;
        if decoded_len > limits.max_output_bytes as u64 {
            return Err(RtError::bad_request(format!(
                "stdin payload of {decoded_len} bytes exceeds the {} byte limit",
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
            encoded: false,
        }),
        ShellKind::Powershell => Ok(ShellPlan {
            program: require_shell("powershell.exe", ShellKind::Powershell)?,
            args: command_args(&POWER_SHELL_PREFIX),
            encoded: true,
        }),
        // PowerShell 7 is reported as unavailable when missing: silently
        // falling back to 5.1 would run the user's script in a different
        // language version than requested.
        ShellKind::Pwsh => Ok(ShellPlan {
            program: require_shell("pwsh.exe", ShellKind::Pwsh)?,
            args: command_args(&PWSH_PREFIX),
            encoded: true,
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
                encoded: false,
            })
        }
    }
}

/// Fixed switches that precede the command flag; the flag itself (`-Command`
/// or `-EncodedCommand`) is chosen at spawn time.
fn command_args(prefix: &[&str]) -> Vec<OsString> {
    prefix.iter().map(|flag| OsString::from(*flag)).collect()
}

/// Encodes a script for `-EncodedCommand`: base64 of UTF-16LE.
///
/// PowerShell re-parses a `-Command <text>` argument as a command line, so a
/// script that itself starts with a quoted string loses those quotes
/// (`"PS " + 2` arrives as `PS + 2`). The encoded form is handed over byte for
/// byte, which also makes non-ASCII scripts independent of the console code page.
fn encode_powershell_script(script: &str) -> String {
    use base64::Engine as _;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
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

/// Appends the shell command to the child command line.
///
/// `Command::arg` treats the command as one argv token: it wraps it in quotes
/// and escapes the embedded ones with backslashes. Neither `cmd.exe` nor
/// PowerShell understands that escaping, so `echo "a b"` would reach the shell
/// as `\"a b\"` and fail. The command is shell syntax, not an argument, so it
/// is appended verbatim to the raw command line.
fn append_command(command: &mut Command, raw: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.raw_arg(raw);
    }
    #[cfg(not(windows))]
    {
        command.arg(raw);
    }
}

/// Decodes a base64 payload in bounded slices, handing each one to `sink`.
///
/// Returns the number of decoded bytes. Whitespace between characters is
/// ignored, which is what clients produce when they wrap a payload. At most one
/// slice ([`STDIN_CHUNK_BYTES`]) is held at a time, so a hostile `stdin_b64`
/// costs memory only in the request string itself, never in a second copy.
///
/// Slices are cut on multiples of four characters, so each one decodes on its
/// own; padding therefore stays in the final slice, where the decoder expects it.
fn for_each_base64_chunk<F>(payload: &str, mut sink: F) -> Result<u64>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    use base64::Engine as _;

    let mut quad: Vec<u8> = Vec::with_capacity(STDIN_CHUNK_QUAD + 4);
    let mut total: u64 = 0;

    let decode = |slice: &[u8]| -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(slice)
            .map_err(|e| RtError::bad_request(format!("stdin payload is not valid base64: {e}")))
    };

    for ch in payload.chars() {
        if ch.is_whitespace() {
            continue;
        }
        // The base64 alphabet is ASCII; a non-ASCII character is invalid input
        // and is pushed through as its UTF-8 bytes so the decoder reports it.
        let mut buf = [0u8; 4];
        quad.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        if quad.len() >= STDIN_CHUNK_QUAD {
            let cut = quad.len() & !3;
            let decoded = decode(&quad[..cut])?;
            total += decoded.len() as u64;
            sink(&decoded)?;
            quad.drain(..cut);
        }
    }

    if !quad.is_empty() {
        let decoded = decode(&quad)?;
        total += decoded.len() as u64;
        sink(&decoded)?;
    }

    Ok(total)
}

/// Feeds the child's standard input from its own thread.
///
/// Writing on the collector thread would park the run: a child that never reads
/// leaves the pipe full and the write blocks outside the timeout window, so the
/// deadline could never fire (S-12). With a writer thread the collector keeps
/// polling, and killing the tree closes the pipe, which fails the pending write
/// and lets the thread exit. The returned receiver fires once the writer is
/// finished (or failed), so the collector only waits a bounded grace for it.
fn spawn_stdin_writer(
    mut pipe: std::process::ChildStdin,
    payload: String,
) -> std::sync::mpsc::Receiver<()> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // `prepare` validated the payload, so decode errors are not expected
        // here; a failed write only means the child stopped reading, which its
        // exit status already explains.
        let _ = for_each_base64_chunk(&payload, |chunk| {
            pipe.write_all(chunk)
                .map_err(|e| RtError::io(PathBuf::from("<stdin>"), e))
        });
        let _ = pipe.flush();
        let _ = done_tx.send(());
    });
    done_rx
}

/// Spawns the reader thread for one child pipe.
fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    state: Arc<StreamState>,
    sender: Option<ChunkSender>,
    stream: OutputStream,
    cap: usize,
    done: Arc<AtomicUsize>,
    pid: u32,
    abandoned: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; READ_CHUNK];
        let mut consumer_gone = false;

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
                if !flush_complete(&mut pending, sender, &stream) {
                    // The consumer went away: stop collecting immediately and
                    // take the child down so nothing keeps writing into a pipe
                    // that no longer has a reader.
                    abandon_consumer(pid, &abandoned);
                    consumer_gone = true;
                    break;
                }
            }
        }

        // Flush the tail of the last (unterminated) line.
        if !consumer_gone {
            if let Some(sender) = &sender {
                if !pending.is_empty() {
                    let tail = Chunk {
                        stream,
                        bytes: std::mem::take(&mut pending),
                    };
                    if !deliver(sender, tail) {
                        abandon_consumer(pid, &abandoned);
                    }
                }
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
/// the next read. Returns `false` as soon as the consumer refuses a chunk.
fn flush_complete(pending: &mut Vec<u8>, sender: &ChunkSender, stream: &OutputStream) -> bool {
    loop {
        let cut = match pending.iter().rposition(|byte| *byte == b'\n') {
            Some(last_newline) => last_newline + 1,
            None if pending.len() > STREAM_CHUNK => safe_split_point(pending),
            None => 0,
        };
        if cut == 0 {
            return true;
        }
        let bytes: Vec<u8> = pending.drain(..cut).collect();
        let chunk = Chunk {
            stream: (*stream).clone(),
            bytes,
        };
        if !deliver(sender, chunk) {
            return false;
        }
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

/// Forwards everything currently queued, then reports whether producers survive.
///
/// Returns `false` once the channel is disconnected, i.e. both readers finished
/// and the queue is empty.
fn drain_chunks(
    rx: &mut ChunkReceiver,
    encoding: OutputEncoding,
    sink: &mut dyn FnMut(ExecEvent),
) -> bool {
    loop {
        match rx.try_recv() {
            Ok(chunk) => forward_chunk(chunk, encoding, sink),
            Err(TryRecvError::Empty) => return true,
            Err(TryRecvError::Disconnected) => return false,
        }
    }
}

/// Kills the child and, on Windows, its whole process tree.
fn kill_tree(child: &mut std::process::Child, pid: u32) {
    let _ = child.kill();
    // `child.kill()` only reaches the direct child; cmd.exe / powershell.exe
    // usually have grandchildren that would keep running (and keep the pipe
    // open). `taskkill /T` is the portable way to take the tree down.
    kill_tree_by_pid(pid);
    let _ = child.wait();
}

/// Kills a process tree using nothing but its PID.
///
/// Reader threads have no `Child` handle, so the tree is taken down through
/// the system `taskkill`; the collector's own [`kill_tree`] path stays unchanged.
#[cfg(windows)]
fn kill_tree_by_pid(pid: u32) {
    let mut cmd = Command::new(taskkill_path());
    cmd.args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    silence_console(&mut cmd);
    let _ = cmd.status();
}

/// Resolves the system `taskkill.exe` without going through `PATH`.
///
/// A bare `taskkill` is looked up in `PATH`, where a writable directory (or a
/// planted `taskkill.exe`) can intercept the teardown of the process tree. The
/// kernel is therefore asked for the real system directory first, so neither
/// `PATH` nor an inherited `%SystemRoot%` can redirect the teardown; the
/// environment stays as the fallback, and the bare name as the last resort.
#[cfg(windows)]
fn taskkill_path() -> PathBuf {
    if let Some(directory) = system_directory() {
        let candidate = directory.join("taskkill.exe");
        if candidate.is_file() {
            return candidate;
        }
    }

    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let candidate = root.join("System32").join("taskkill.exe");
    if candidate.is_file() {
        candidate
    } else {
        PathBuf::from("taskkill")
    }
}

/// Asks the kernel for the system directory (`C:\Windows\System32`).
///
/// `GetSystemDirectoryW` never consults the environment, which is what makes it
/// a trustworthy anchor when `PATH` or `%SystemRoot%` may be attacker controlled.
/// Returns `None` when the call fails, so callers can fall back.
#[cfg(windows)]
fn system_directory() -> Option<PathBuf> {
    // `MAX_PATH` covers every supported install; the API reports the required
    // size (terminator included) when it does not, and the second call then
    // allocates exactly that much.
    const MAX_PATH: usize = 260;

    let mut buffer = vec![0u16; MAX_PATH];
    let mut written = unsafe {
        win32_system::GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) as usize
    };
    if written == 0 {
        return None;
    }

    if written >= buffer.len() {
        buffer = vec![0u16; written];
        written = unsafe {
            win32_system::GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) as usize
        };
        if written == 0 || written >= buffer.len() {
            return None;
        }
    }

    let directory = String::from_utf16_lossy(&buffer[..written]);
    if directory.is_empty() {
        None
    } else {
        Some(PathBuf::from(directory))
    }
}

/// Win32 bindings used to locate system binaries, declared by hand for the same
/// reason as [`win32_job`]: the layer has no `windows-sys` dependency.
#[cfg(windows)]
mod win32_system {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        /// Fills `buffer` with the system directory; returns the characters
        /// written (terminator excluded), or the required size when the buffer
        /// is too small, or 0 on failure.
        pub fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
}

/// Killing by PID is Windows-only; elsewhere the collector kills the child
/// through its handle after noticing the abandoned flag.
#[cfg(not(windows))]
fn kill_tree_by_pid(pid: u32) {
    let _ = pid;
}

/// Win32 job object bindings, declared by hand: the layer intentionally has no
/// `windows-sys` dependency.
#[cfg(windows)]
mod win32_job {
    use std::ffi::c_void;

    /// `JOBOBJECT_BASIC_LIMIT_INFORMATION`.
    ///
    /// The layout is fixed by Win32: two `LARGE_INTEGER` (8 bytes each), a
    /// `DWORD`, then 8-byte-aligned `SIZE_T`s. `repr(C)` inserts exactly the
    /// same padding Windows does, so `size_of` is 64 bytes on x64.
    #[repr(C)]
    #[derive(Default)]
    pub struct JobBasicLimitInformation {
        pub per_process_user_time_limit: i64,
        pub per_job_user_time_limit: i64,
        pub limit_flags: u32,
        pub minimum_working_set_size: usize,
        pub maximum_working_set_size: usize,
        pub active_process_limit: u32,
        pub affinity: usize,
        pub priority_class: u32,
        pub scheduling_class: u32,
    }

    /// `IO_COUNTERS`: six 64-bit counters, no padding.
    #[repr(C)]
    #[derive(Default)]
    pub struct IoCounters {
        pub read_operation_count: u64,
        pub write_operation_count: u64,
        pub other_operation_count: u64,
        pub read_transfer_count: u64,
        pub write_transfer_count: u64,
        pub other_transfer_count: u64,
    }

    /// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (144 bytes on x64).
    #[repr(C)]
    #[derive(Default)]
    pub struct JobExtendedLimitInformation {
        pub basic_limit_information: JobBasicLimitInformation,
        pub io_info: IoCounters,
        pub process_memory_limit: usize,
        pub job_memory_limit: usize,
        pub peak_process_memory_used: usize,
        pub peak_job_memory_used: usize,
    }

    /// The abi layout is checked instead of trusted: a mismatch here would make
    /// `SetInformationJobObject` read garbage.
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(std::mem::size_of::<JobBasicLimitInformation>() == 64);
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(std::mem::size_of::<JobExtendedLimitInformation>() == 144);

    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    /// `JobObjectExtendedLimitInformation`.
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    // Handles are declared as `isize`, the convention the rest of the crate uses
    // for kernel32 handles (`capture.rs`), so the two declarations agree.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> isize;
        pub fn SetInformationJobObject(
            job: isize,
            class: i32,
            info: *const c_void,
            info_len: u32,
        ) -> i32;
        pub fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
        pub fn CloseHandle(object: isize) -> i32;
    }
}

/// Owns a kill-on-close job object holding the child's process tree.
///
/// `taskkill /T /F` walks the parent chain, so it misses a grandchild whose
/// direct parent already exited (and any process that detached itself). Job
/// membership is inherited by every descendant, and closing the last handle
/// terminates the whole job — which is exactly what the `Drop` below does when
/// the run finishes normally, times out or is cancelled (S-13).
#[cfg(windows)]
struct ProcessJob {
    handle: isize,
}

#[cfg(windows)]
impl ProcessJob {
    /// Creates the job and joins `process` to it.
    ///
    /// Returns `None` when the OS refuses — the caller then relies on the
    /// `taskkill` fallback, so a missing job degrades the teardown but never
    /// fails the run. The child is assigned immediately after `spawn`, which
    /// leaves a narrow window in which it could fork a grandchild that escapes
    /// the job; Windows 8+ allows the nested job this needs, and the kill path
    /// still sweeps what `taskkill` can see.
    fn attach(process: isize) -> Option<Self> {
        let handle = unsafe { win32_job::CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle == 0 {
            return None;
        }

        let mut info = win32_job::JobExtendedLimitInformation::default();
        info.basic_limit_information.limit_flags = win32_job::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            win32_job::SetInformationJobObject(
                handle,
                win32_job::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of::<win32_job::JobExtendedLimitInformation>() as u32,
            )
        };
        if configured == 0 {
            unsafe { win32_job::CloseHandle(handle) };
            return None;
        }

        if unsafe { win32_job::AssignProcessToJobObject(handle, process) } == 0 {
            unsafe { win32_job::CloseHandle(handle) };
            return None;
        }

        Some(Self { handle })
    }
}

#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) {
        if self.handle != 0 {
            // Last handle: every remaining member is terminated.
            unsafe { win32_job::CloseHandle(self.handle) };
            self.handle = 0;
        }
    }
}

/// Puts the child into a kill-on-close job where the platform supports one.
#[cfg(windows)]
fn attach_job(child: &std::process::Child) -> Option<ProcessJob> {
    use std::os::windows::io::AsRawHandle;

    ProcessJob::attach(child.as_raw_handle() as isize)
}

/// No job objects outside Windows; the child handle is enough there.
#[cfg(not(windows))]
fn attach_job(_child: &std::process::Child) {}

/// Shared execution pipeline for `run`, `run_streaming` and `run_summary`.
fn execute(
    guard: &PathGuard,
    req: &ExecRequest,
    limits: &ExecLimits,
    control: &ExecControl,
    sink: &mut dyn FnMut(ExecEvent),
    mode: Mode,
) -> Result<(ExecResult, bool)> {
    let mut req = prepare(guard, req, limits)?;
    let plan = shell_plan(&req.shell)?;

    // The payload stays encoded: `prepare` already validated it and the writer
    // thread decodes it slice by slice, so no full decoded copy is held here.
    let stdin_payload = req.stdin_b64.take();

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
        .current_dir(&cwd)
        .stdin(if stdin_payload.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if plan.encoded {
        command.arg("-EncodedCommand");
        command.arg(encode_powershell_script(&req.command));
    } else {
        append_command(&mut command, &req.command);
    }
    for (key, value) in &req.env {
        command.env(key, value);
    }
    silence_console(&mut command);

    let mut child = command
        .spawn()
        .map_err(|e| RtError::io(plan.program.clone(), e))?;
    let pid = child.id();
    let started_at = Instant::now();

    // Join the child to a kill-on-close job before it can do much work, so any
    // grandchild it spawns inherits the membership and dies with the run.
    let job = attach_job(&child);

    if mode.emits_started() {
        sink(ExecEvent::Started {
            pid: Some(pid),
            shell: req.shell.clone(),
        });
    }

    let out_state = Arc::new(StreamState::new());
    let err_state = Arc::new(StreamState::new());

    let (tx, mut rx): (ChunkSender, ChunkReceiver) = stream_mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let reader_channel = if mode.emits_output() {
        Some(tx.clone())
    } else {
        None
    };

    // `abandoned` is raised by a reader thread when the consumer of the chunk
    // stream goes away; the run is then reported exactly like a cancellation.
    let abandoned = Arc::new(AtomicBool::new(false));

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
            pid,
            Arc::clone(&abandoned),
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
            pid,
            Arc::clone(&abandoned),
        );
        readers += 1;
    }
    // Drop our own sender so the receiver disconnects once both readers end.
    drop(tx);

    // Feed stdin from its own thread, now that the readers are draining the
    // output pipes: writing it inline would park the collector for as long as
    // the child refuses to read, and could deadlock against a child that fills
    // its stdout first.
    let stdin_writer = match stdin_payload {
        Some(payload) => {
            let pipe = child
                .stdin
                .take()
                .ok_or_else(|| RtError::internal("stdin pipe disappeared after spawn"))?;
            Some(spawn_stdin_writer(pipe, payload))
        }
        None => None,
    };

    let mut status = None;
    let mut timed_out = false;
    let mut cancelled = false;
    let deadline = started_at + timeout;
    let mut channel_open = mode.emits_output();

    loop {
        // Forward whatever the readers managed to hand over. A full queue means
        // the consumer is the bottleneck; the readers then block, the pipes fill
        // and the child is throttled — no unbounded buffering anywhere.
        if channel_open {
            channel_open = drain_chunks(&mut rx, req.encoding, sink);
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
        // The consumer went away (or wedged): the reader already killed the
        // tree, so stop collecting and report the run as cancelled.
        if abandoned.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }

        std::thread::sleep(TICK);
    }

    if status.is_none() {
        kill_tree(&mut child, pid);
        status = child.try_wait().ok().flatten();
    }

    // A reader may have killed the tree while the child was exiting, so the
    // abandonment verdict has to survive the `try_wait` race above.
    if abandoned.load(Ordering::SeqCst) {
        cancelled = true;
    }

    // Closing the job reaps every descendant — and the pipe handles they
    // inherited — before the drain below, so a stranded grandchild cannot keep
    // the readers waiting for the whole grace period.
    drop(job);

    // The child is gone, so a pending stdin write fails with a broken pipe and
    // the writer thread returns; the wait stays bounded in case it does not.
    if let Some(writer_done) = stdin_writer {
        let _ = writer_done.recv_timeout(READER_GRACE);
    }

    // Drain what the readers produced, bounded by `READER_GRACE`. In buffered
    // mode only the EOF counter matters, because no chunks are being sent.
    let drain_deadline = Instant::now() + READER_GRACE;
    if mode.emits_output() {
        loop {
            if !drain_chunks(&mut rx, req.encoding, sink) {
                // Both readers are done and the queue was just emptied.
                break;
            }
            if done.load(Ordering::SeqCst) >= readers {
                // No producer can add anything after its counter increment, but
                // a chunk may still have landed between the sweep above and this
                // read: one final sweep picks it up.
                let _ = drain_chunks(&mut rx, req.encoding, sink);
                break;
            }
            if Instant::now() >= drain_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
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

    /// A script that begins with a double-quoted string used to be re-parsed as
    /// a command line, so the quotes were stripped and the run failed; the
    /// encoded form must preserve them.
    #[test]
    fn script_starting_with_a_quoted_string_keeps_its_quotes() {
        if !have_powershell() {
            return;
        }
        let req = ExecRequest::new(ShellKind::Powershell, r#""PS " + 2"#);
        let result = run(&guard(), &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
        assert_eq!(result.stdout.trim(), "PS 2");
    }

    #[test]
    fn encoded_scripts_round_trip_as_utf16le() {
        use base64::Engine as _;
        let script = "Write-Output '中文'; \"x\"";
        let encoded = super::encode_powershell_script(script);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).expect("utf16"), script);
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
        // The child sleeps far longer than the timeout: without the kill this
        // test would take 20s, so an early return proves the tree went down.
        let mut req = ExecRequest::new(ShellKind::Powershell, "Start-Sleep -Seconds 20");
        req.timeout_ms = Some(400);

        let started = Instant::now();
        let result = run(&guard(), &req, &limits()).expect("run");
        let elapsed = started.elapsed();

        assert!(result.timed_out, "request should have timed out");
        assert_eq!(result.exit_code, -1);
        assert!(
            elapsed < Duration::from_secs(15),
            "timeout must kill the child early, took {elapsed:?}"
        );
    }

    #[test]
    fn cancellation_is_reported_through_the_summary() {
        if !have_powershell() {
            return;
        }
        let mut req = ExecRequest::new(ShellKind::Powershell, "Start-Sleep -Seconds 20");
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
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "cancellation must stop the run long before the 30s timeout"
        );
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
        // A payload much larger than the cap: the child keeps writing while the
        // parent stops accumulating. If the reader stopped draining the pipe the
        // child would block and the run would time out instead of exiting 0.
        let temp = TempRoot::new("cap");
        let path = temp.path().join("output.txt");
        let payload: String = (0..20_000u32)
            .map(|index| format!("line-{index}\r\n"))
            .collect();
        std::fs::write(&path, payload.as_bytes()).expect("write cap payload");

        let req = ExecRequest::new(ShellKind::Cmd, format!("type \"{}\"", plain_path(&path)));
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

    /// Polls a child until it exits, returning whether it did within `timeout`.
    fn wait_for_exit(child: &mut std::process::Child, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(_) => return false,
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Writes a large newline-delimited file and returns the temp root (kept
    /// alive by the caller) plus a `cmd` command that streams it fast.
    ///
    /// A file bigger than the bounded queue is what makes the backpressure and
    /// abandonment paths deterministic: `type` fills the pipes far quicker than
    /// an interpreted `for` loop can.
    fn big_output_file(tag: &str, lines: u32) -> (TempRoot, String, PathBuf) {
        let temp = TempRoot::new(tag);
        let path = temp.path().join("big.txt");
        let mut content = String::with_capacity(lines as usize * 13);
        for index in 0..lines {
            content.push_str("line-");
            content.push_str(&index.to_string());
            content.push_str("\r\n");
        }
        std::fs::write(&path, content.as_bytes()).expect("write big output file");
        let command = format!("type \"{}\"", plain_path(&path));
        (temp, command, path)
    }

    /// A consumer that drops the chunk stream must stop the reader and take the
    /// child down: this is the S-07 leak (unbounded growth when nobody reads).
    #[test]
    fn dropped_consumer_stops_the_reader_and_kills_the_child() {
        use std::os::windows::process::CommandExt;

        let (_temp, command, file) = big_output_file("drop", 300_000);

        let mut cmd = Command::new(util::which("cmd.exe").expect("cmd.exe"));
        cmd.arg("/C")
            .raw_arg(&command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        silence_console(&mut cmd);
        let mut child = cmd.spawn().expect("spawn chatty child");
        let pid = child.id();
        let pipe = child.stdout.take().expect("piped stdout");

        let state = Arc::new(StreamState::new());
        let done = Arc::new(AtomicUsize::new(0));
        let abandoned = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = stream_mpsc::channel::<Chunk>(STREAM_CHANNEL_CAPACITY);

        let reader = spawn_reader(
            pipe,
            Arc::clone(&state),
            Some(tx),
            OutputStream::Stdout,
            1024 * 1024,
            Arc::clone(&done),
            pid,
            Arc::clone(&abandoned),
        );

        for _ in 0..3 {
            let chunk = match rx.blocking_recv() {
                Some(chunk) => chunk,
                None => panic!(
                    "channel closed early: cmd={command:?} file_len={} status={:?} done={} raw={}",
                    std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0),
                    child.try_wait(),
                    done.load(Ordering::SeqCst),
                    state.raw_bytes.load(Ordering::SeqCst),
                ),
            };
            assert!(matches!(chunk.stream, OutputStream::Stdout));
            assert!(!chunk.bytes.is_empty());
        }
        drop(rx);

        // The reader notices the disconnect, kills the tree and returns; the
        // watchdog makes the "must not hang" requirement part of the assertion.
        let (report_tx, report_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = reader.join();
            let _ = report_tx.send(());
        });
        assert!(
            report_rx.recv_timeout(Duration::from_secs(15)).is_ok(),
            "the reader must stop once the consumer went away"
        );
        assert!(
            abandoned.load(Ordering::SeqCst),
            "consumer abandonment must be recorded"
        );
        assert!(
            wait_for_exit(&mut child, Duration::from_secs(15)),
            "the child tree must be killed when nobody reads its output"
        );
        assert_eq!(done.load(Ordering::SeqCst), 1, "reader must finish once");
    }

    /// Backpressure must not corrupt the stream: the consumer still sees every
    /// line, in order, exactly once.
    #[test]
    fn streaming_preserves_the_complete_line_sequence() {
        let req = ExecRequest::new(ShellKind::Cmd, "for /L %i in (1,1,40) do @echo seq-%i");

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

        let chunks: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                ExecEvent::Output(OutputStream::Stdout, text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(!chunks.is_empty(), "expected stdout chunks");

        // Only the final chunk may be a partial line.
        for chunk in chunks.iter().take(chunks.len() - 1) {
            assert!(
                chunk.ends_with('\n'),
                "a non-final chunk must end on a line boundary: {chunk:?}"
            );
        }

        let joined = chunks.concat();
        let lines: Vec<&str> = joined.lines().collect();
        assert_eq!(lines.len(), 40, "all lines must arrive exactly once");
        for (index, line) in lines.iter().enumerate() {
            assert_eq!(line.trim_end(), format!("seq-{}", index + 1));
        }
    }

    /// A consumer that stalls (here: sleeps inside the sink) must be treated as
    /// gone, not allowed to pin the run until the timeout expires.
    #[test]
    fn stalled_consumer_aborts_the_run_and_reports_cancelled() {
        let (_temp, command, _file) = big_output_file("stall", 300_000);
        let req = ExecRequest::new(ShellKind::Cmd, command);

        let mut stalled = false;
        let started = Instant::now();
        let summary = {
            let mut sink = |event: ExecEvent| {
                // Wedge on the first *output* event: the reader threads are
                // running by then, so the queue really backs up.
                if !stalled {
                    if let ExecEvent::Output(_, _) = event {
                        stalled = true;
                        std::thread::sleep(Duration::from_millis(1500));
                    }
                }
            };
            run_summary(&guard(), &req, &limits(), ExecControl::new(), &mut sink)
        }
        .expect("run_summary");
        let elapsed = started.elapsed();

        assert_eq!(
            summary.cancelled,
            Some(true),
            "a wedged consumer is reported as a cancelled run"
        );
        assert!(!summary.timed_out, "this must not look like a timeout");
        assert_eq!(summary.exit_code, -1);
        assert!(
            elapsed < Duration::from_secs(20),
            "the run must abort early instead of honouring the 30s timeout, took {elapsed:?}"
        );
    }

    /// Polls for a file to appear, returning whether it did within `timeout`.
    fn wait_for_file(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if path.exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A child that never reads its stdin must not pin the run: the payload is
    /// far larger than a pipe buffers, so the write blocks and only the deadline
    /// can end the command (S-12).
    #[test]
    fn large_stdin_cannot_outlive_the_deadline() {
        // 512 KiB decoded: many pipe buffers, so the write cannot drain before
        // the child is killed.
        let payload = vec![b'x'; 512 * 1024];
        let mut req = ExecRequest::new(ShellKind::Cmd, "ping -n 6 127.0.0.1 >nul");
        req.timeout_ms = Some(400);
        req.stdin_b64 = Some({
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&payload)
        });

        let started = Instant::now();
        let result = run(&guard(), &req, &limits()).expect("run");
        let elapsed = started.elapsed();

        assert!(
            result.timed_out,
            "the deadline must fire while the stdin write is blocked"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            elapsed < Duration::from_secs(15),
            "a blocked stdin write must not outlive the deadline, took {elapsed:?}"
        );
    }

    /// A grandchild that detaches from the direct child must still die with the
    /// run: once the parent exits, `taskkill /T` can no longer reach it, so only
    /// the job object can (S-13).
    #[test]
    fn grandchildren_are_reaped_when_the_run_ends() {
        // `cmd` treats `(`, `)` and `&` as syntax, so the fixture path must be
        // plain — a `TempRoot` name would carry the thread id in parentheses.
        let dir = std::env::temp_dir().join(format!("rt_exec_tree_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create grandchild fixture");

        let script = dir.join("grandchild.bat");
        std::fs::write(
            &script,
            "@echo off\r\n\
             echo started> \"%~dp0started.txt\"\r\n\
             ping -n 3 127.0.0.1 >nul\r\n\
             echo finished> \"%~dp0finished.txt\"\r\n",
        )
        .expect("write grandchild script");

        // `start /b` puts the grandchild outside the collector's process view;
        // the parent waits ~1s for it to boot and then exits, which is exactly
        // the case where the parent chain is gone.
        let command = format!(
            "start /b cmd /c \"{}\\grandchild.bat\" & ping -n 2 127.0.0.1 >nul",
            plain_path(&dir)
        );
        let req = ExecRequest::new(ShellKind::Cmd, command);

        let started = Instant::now();
        let result = run(&guard(), &req, &limits()).expect("run");
        assert_eq!(result.exit_code, 0, "the parent batch must succeed");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the run must not wait for the detached grandchild"
        );

        let started_marker = dir.join("started.txt");
        assert!(
            wait_for_file(&started_marker, Duration::from_secs(10)),
            "the grandchild never ran, so the escape case is not exercised"
        );

        // The grandchild pings for about two seconds; double that is enough to
        // see it finish if it survived.
        std::thread::sleep(Duration::from_secs(4));
        let survived = dir.join("finished.txt").exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !survived,
            "the grandchild survived the run and completed its work"
        );
    }

    /// The teardown must not resolve `taskkill` through `PATH`: a writable
    /// directory early in `PATH` could otherwise intercept the kill of the
    /// process tree (S-42).
    #[cfg(windows)]
    #[test]
    fn taskkill_is_invoked_through_its_absolute_system_path() {
        let path = taskkill_path();
        let text = path.to_string_lossy().to_lowercase();

        assert!(
            path.is_absolute(),
            "taskkill must be addressed absolutely, got {path:?}"
        );
        assert!(
            text.ends_with(r"\system32\taskkill.exe"),
            "taskkill must come from the system directory, got {path:?}"
        );
        assert!(
            path.is_file(),
            "the resolved taskkill must exist on disk: {path:?}"
        );

        // The kernel, not the environment, must be the source of the directory.
        let directory = system_directory().expect("GetSystemDirectoryW must report the system dir");
        assert!(
            directory.is_absolute(),
            "the kernel-reported system directory must be absolute, got {directory:?}"
        );
        assert!(
            directory.join("taskkill.exe").is_file(),
            "the kernel-reported directory must hold taskkill: {directory:?}"
        );
        assert!(
            path.starts_with(&directory),
            "expected the system copy under {directory:?}, got {path:?}"
        );
    }
}
