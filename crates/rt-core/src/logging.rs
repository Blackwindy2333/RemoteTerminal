//! Logging: rotating files, optional console mirror, an in-memory ring buffer
//! for the GUI/WS tail, and a separate append-only security audit trail.
//!
//! Three sinks, one `tracing` pipeline:
//! * **file** — daily rotation, bounded retention (`logging.max_files`).
//! * **console** — stderr, for headless/service mode.
//! * **memory** — last N events, replayed to the UI and to WS log subscribers.
//!
//! The audit trail is *not* a `tracing` target on purpose: it must keep working
//! (and stay greppable) even if the log level is raised to `error`.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rt_protocol::LogEvent;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;
use crate::error::{Result, RtError};

/// In-memory ring buffer plus a broadcast channel for live subscribers.
pub struct LogEventSink {
    capacity: usize,
    buf: Mutex<VecDeque<LogEvent>>,
    tx: tokio::sync::broadcast::Sender<LogEvent>,
    dropped: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for LogEventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogEventSink")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl LogEventSink {
    pub fn new(capacity: usize) -> Arc<Self> {
        let capacity = capacity.max(64);
        let (tx, _rx) = tokio::sync::broadcast::channel(capacity.min(8192));
        Arc::new(Self {
            capacity,
            buf: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn push(&self, event: LogEvent) {
        if let Ok(mut buf) = self.buf.lock() {
            if buf.len() >= self.capacity {
                buf.pop_front();
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            buf.push_back(event.clone());
        }
        // A send error only means "no live subscribers"; that is normal.
        let _ = self.tx.send(event);
    }

    /// Newest-last copy of the buffer, capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<LogEvent> {
        let Ok(buf) = self.buf.lock() else {
            return Vec::new();
        };
        let skip = buf.len().saturating_sub(limit);
        buf.iter().skip(skip).cloned().collect()
    }

    /// Newest-first slice for the GUI viewer.
    pub fn recent_desc(&self, limit: usize) -> Vec<LogEvent> {
        let mut v = self.recent(limit);
        v.reverse();
        v
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }

    pub fn clear(&self) {
        if let Ok(mut buf) = self.buf.lock() {
            buf.clear();
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// tracing layer → sink
// ---------------------------------------------------------------------------

struct SinkLayer {
    sink: Arc<LogEventSink>,
    max_level: LevelFilter,
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: BTreeMap<String, String>,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.to_string());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, value.to_string());
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, value.to_string());
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, value.to_string());
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }
}

fn level_str(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

impl<S> Layer<S> for SinkLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if self.max_level < *metadata.level() {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let fields = if visitor.fields.is_empty() {
            None
        } else {
            serde_json::to_string(&visitor.fields).ok()
        };
        self.sink.push(LogEvent {
            ts_ms: chrono::Local::now().timestamp_millis(),
            level: level_str(metadata.level()).to_string(),
            target: metadata.target().to_string(),
            message: visitor.message.unwrap_or_default(),
            fields,
        });
    }
}

// ---------------------------------------------------------------------------
// uniform writer (file / stderr / sink) for the fmt layers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Box<dyn Write + Send + Sync>>>);

impl SharedWriter {
    fn new(writer: Box<dyn Write + Send + Sync>) -> Self {
        Self(Arc::new(Mutex::new(writer)))
    }
}

struct SharedWriterGuard<'a>(std::sync::MutexGuard<'a, Box<dyn Write + Send + Sync>>);

impl Write for SharedWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        SharedWriterGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

// ---------------------------------------------------------------------------
// audit trail
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub ts_ms: i64,
    /// `login`, `login_failed`, `logout`, `exec`, `fs_write`, `fs_delete`,
    /// `capture`, `config_change`, `server_start`, `server_stop`, `key_used`, …
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `ok` | `denied` | `error`
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl AuditEvent {
    pub fn new(action: impl Into<String>, result: impl Into<String>) -> Self {
        let now = chrono::Local::now();
        Self {
            ts: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ts_ms: now.timestamp_millis(),
            action: action.into(),
            username: None,
            scope: None,
            remote: None,
            target: None,
            result: result.into(),
            detail: None,
            request_id: None,
        }
    }

    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.username = Some(u.into());
        self
    }
    pub fn scope(mut self, s: impl Into<String>) -> Self {
        self.scope = Some(s.into());
        self
    }
    pub fn remote(mut self, r: impl Into<String>) -> Self {
        self.remote = Some(r.into());
        self
    }
    pub fn target(mut self, t: impl fmt::Display) -> Self {
        self.target = Some(t.to_string());
        self
    }
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    writes: std::sync::atomic::AtomicU64,
    failures: std::sync::atomic::AtomicU64,
    /// Rotated `audit.jsonl.<stamp>` files to keep; older ones are deleted
    /// (S-25: rotation must not grow the disk without bound).
    max_rotated_files: usize,
    /// S-25: when true an audit failure is reported to checked callers so the
    /// request can be refused with 503 instead of silently going unrecorded.
    fail_closed: bool,
    /// Rotate once the live file is larger than this (default 16 MiB).
    rotate_bytes: u64,
    /// Only look at the file size every N appended lines.
    rotate_check_every: u64,
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .finish()
    }
}

const AUDIT_ROTATE_BYTES: u64 = 16 * 1024 * 1024;
/// Checking the size on every single append would stat the file per audit
/// event; every 500 lines is often enough for a 16 MiB threshold.
const AUDIT_ROTATE_CHECK_EVERY: u64 = 500;

/// True for the `YYYYMMDD-HHMMSS` suffix we append to rotated audit files.
/// Validating the shape (instead of a plain prefix match) keeps unrelated
/// neighbours such as `audit.jsonl.tmp` out of the retention logic.
fn is_rotation_stamp(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    bytes.len() == 15
        && bytes[8] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 8 || b.is_ascii_digit())
}

impl AuditLog {
    /// Open with the production defaults: keep
    /// [`crate::config::DEFAULT_AUDIT_MAX_FILES`] rotated files, best-effort
    /// auditing (a write failure is logged, not propagated).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, crate::config::DEFAULT_AUDIT_MAX_FILES, false)
    }

    /// Open with explicit retention and failure policy.
    ///
    /// `max_rotated_files` bounds the on-disk footprint: after every rotation,
    /// and once at open time, only the newest N `audit.jsonl.<stamp>` files are
    /// kept (S-25). `fail_closed` only changes how failures are *reported* to
    /// [`AuditLog::log_checked`] callers — [`AuditLog::log`] never returns an
    /// error, so existing call sites keep working.
    pub fn open_with(path: &Path, max_rotated_files: usize, fail_closed: bool) -> Result<Self> {
        Self::open_limits(
            path,
            max_rotated_files,
            fail_closed,
            AUDIT_ROTATE_BYTES,
            AUDIT_ROTATE_CHECK_EVERY,
        )
    }

    /// Test seam: the rotate threshold and check cadence are configurable so
    /// rotation and pruning can be exercised without writing 16 MiB.
    fn open_limits(
        path: &Path,
        max_rotated_files: usize,
        fail_closed: bool,
        rotate_bytes: u64,
        rotate_check_every: u64,
    ) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.to_path_buf(), e))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| RtError::io(path.to_path_buf(), e))?;
        let log = Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            writes: std::sync::atomic::AtomicU64::new(0),
            failures: std::sync::atomic::AtomicU64::new(0),
            max_rotated_files: max_rotated_files.max(1),
            fail_closed,
            rotate_bytes: rotate_bytes.max(1),
            rotate_check_every: rotate_check_every.max(1),
        };
        // A machine that has been rotating for months must not keep all of it.
        let pruned = log.prune_rotated();
        if pruned > 0 {
            tracing::info!(
                target: "rt_core::audit",
                "pruned {pruned} old audit file(s); keeping {}",
                log.max_rotated_files
            );
        }
        if log.fail_closed {
            tracing::info!(
                target: "rt_core::audit",
                "audit fail-closed is enabled: a failed audit write will be reported as an error"
            );
        }
        Ok(log)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of rotated files this log is allowed to keep.
    pub fn max_rotated_files(&self) -> usize {
        self.max_rotated_files
    }

    /// Whether the caller must treat an audit failure as fatal (`S-25`).
    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// How many audit writes have failed since start-up.
    pub fn failures(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Append one JSON line. Never panics and never propagates errors upward:
    /// an audit write failure must not take down the operation, but it *is*
    /// reported through `tracing` and counted in [`AuditLog::failures`].
    pub fn log(&self, event: AuditEvent) {
        let _ = self.write_event(&event);
    }

    /// Append one JSON line, propagating the failure.
    ///
    /// Callers behind `logging.audit_fail_closed = true` use this to answer 503
    /// instead of pretending the action was audited (S-25); the plain
    /// [`AuditLog::log`] keeps the historical fire-and-forget contract.
    pub fn log_checked(&self, event: AuditEvent) -> Result<()> {
        self.write_event(&event)
    }

    fn write_event(&self, event: &AuditEvent) -> Result<()> {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(target: "rt_core::audit", "failed to encode audit event: {err}");
                self.failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(RtError::Internal(format!(
                    "failed to encode audit event: {err}"
                )));
            }
        };
        // Rotate *before* appending, so the new line always lands in a fresh
        // live file and never inside the file that just became a rotation.
        let n = self.writes.load(std::sync::atomic::Ordering::Relaxed);
        if n % self.rotate_check_every == 0 {
            self.rotate_if_needed();
        }
        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let appended = writeln!(guard, "{line}").and_then(|()| guard.flush());
        drop(guard);
        if let Err(err) = appended {
            let failures = self
                .failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if self.fail_closed {
                tracing::error!(
                    target: "rt_core::audit",
                    "audit write failed ({failures} so far) and audit_fail_closed = true: {err}"
                );
            } else {
                tracing::error!(target: "rt_core::audit", "failed to write audit line: {err}");
            }
            // Mirror the intent anyway, so a normal log tail still shows the
            // action that could not be audited.
            self.mirror(event);
            return Err(RtError::io(self.path.clone(), err));
        }
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Mirror into the normal log at info so a single tail shows both.
        self.mirror(event);
        Ok(())
    }

    fn mirror(&self, event: &AuditEvent) {
        tracing::info!(
            target: "audit",
            action = %event.action,
            result = %event.result,
            user = event.username.as_deref().unwrap_or("-"),
            target_path = event.target.as_deref().unwrap_or("-"),
            remote = event.remote.as_deref().unwrap_or("-"),
            "audit: {} {}",
            event.action,
            event.result
        );
    }

    fn rotate_if_needed(&self) {
        let too_big = std::fs::metadata(&self.path)
            .map(|m| m.len() > self.rotate_bytes)
            .unwrap_or(false);
        if !too_big {
            return;
        }
        let Some(name) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let rotated = self.path.with_file_name(format!("{name}.{stamp}"));
        if std::fs::rename(&self.path, &rotated).is_err() {
            return;
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            if let Ok(mut guard) = self.file.lock() {
                *guard = file;
            }
        }
        // Retention: rotations must not accumulate forever (S-25).
        let pruned = self.prune_rotated();
        if pruned > 0 {
            tracing::debug!(target: "rt_core::audit", "pruned {pruned} old audit file(s)");
        }
    }

    /// Delete the oldest rotated audit files, keeping `max_rotated_files`.
    /// Returns how many files were removed.
    fn prune_rotated(&self) -> usize {
        let (Some(dir), Some(name)) = (
            self.path.parent(),
            self.path.file_name().and_then(|n| n.to_str()),
        ) else {
            return 0;
        };
        let prefix = format!("{name}.");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut stamps: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|file_name| {
                let stamp = file_name.strip_prefix(&prefix)?;
                is_rotation_stamp(stamp).then(|| stamp.to_string())
            })
            .collect();
        // The stamp is `YYYYMMDD-HHMMSS`, so name order is time order.
        stamps.sort();
        let excess = stamps.len().saturating_sub(self.max_rotated_files);
        let mut pruned = 0;
        for stamp in stamps.into_iter().take(excess) {
            if std::fs::remove_file(dir.join(format!("{prefix}{stamp}"))).is_ok() {
                pruned += 1;
            }
        }
        pruned
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync + 'static>;

/// Text or JSON file layer, chosen at runtime but erased into one boxed type.
fn make_file_layer<S>(cfg: &LoggingConfig, writer: SharedWriter) -> BoxedLayer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
{
    if cfg.json {
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_thread_names(true)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_thread_names(true)
            .with_timer(chrono_timer())
            .boxed()
    }
}

/// Handles owned by the caller; dropping them stops the background writer.
pub struct LoggingGuard {
    _worker: Option<tracing_appender::non_blocking::WorkerGuard>,
    pub sink: Arc<LogEventSink>,
    pub audit: Option<Arc<AuditLog>>,
    pub file_dir: PathBuf,
}

/// Install the global tracing subscriber.
///
/// `console` mirrors to stderr; the GUI passes `false` unless started headless.
pub fn init(cfg: &LoggingConfig, log_dir: &Path, console: bool) -> Result<LoggingGuard> {
    std::fs::create_dir_all(log_dir).map_err(|e| RtError::io(log_dir.to_path_buf(), e))?;

    let sink = LogEventSink::new(cfg.ui_buffer_lines);

    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(&cfg.file_prefix)
        .filename_suffix("log")
        .max_log_files(cfg.max_files.max(1))
        .build(log_dir)
        .map_err(|e| RtError::Config(format!("failed to open log directory: {e}")))?;
    let (file_writer, worker) = tracing_appender::non_blocking(appender);

    let file_layer = make_file_layer(cfg, SharedWriter::new(Box::new(file_writer)));

    let console_writer: Box<dyn Write + Send + Sync> = if console {
        Box::new(io::stderr())
    } else {
        Box::new(io::sink())
    };
    let console_layer: BoxedLayer<_> = tracing_subscriber::fmt::layer()
        .with_writer(SharedWriter::new(console_writer))
        .with_ansi(console && std::env::var_os("NO_COLOR").is_none())
        .with_target(true)
        .with_timer(chrono_timer())
        .boxed();

    let filter = build_filter(cfg);
    let ui_level = parse_level(&cfg.level).unwrap_or(LevelFilter::INFO);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .with(SinkLayer {
            sink: sink.clone(),
            max_level: ui_level,
        });

    // `try_init` keeps repeated init (tests, MCP subprocess) harmless.
    if let Err(err) = registry.try_init() {
        eprintln!("warning: tracing subscriber already set ({err}); continuing");
    }

    let audit = if cfg.audit {
        match AuditLog::open_with(&cfg.audit_file, cfg.audit_max_files, cfg.audit_fail_closed) {
            Ok(log) => {
                tracing::info!(
                    target: "rt_core::audit",
                    "audit log: {} (keeping {} rotated file(s), fail_closed = {})",
                    log.path().display(),
                    log.max_rotated_files(),
                    log.fail_closed()
                );
                Some(Arc::new(log))
            }
            Err(err) => {
                if cfg.audit_fail_closed {
                    tracing::error!(
                        target: "rt_core::audit",
                        "audit log unavailable with audit_fail_closed = true: {err}"
                    );
                } else {
                    tracing::warn!(target: "rt_core::audit", "audit log disabled: {err}");
                }
                None
            }
        }
    } else {
        None
    };

    install_panic_hook(log_dir);

    Ok(LoggingGuard {
        _worker: Some(worker),
        sink,
        audit,
        file_dir: log_dir.to_path_buf(),
    })
}

fn chrono_timer() -> tracing_subscriber::fmt::time::ChronoLocal {
    tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".to_string())
}

pub fn parse_level(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => Some(LevelFilter::OFF),
        "error" => Some(LevelFilter::ERROR),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

fn build_filter(cfg: &LoggingConfig) -> EnvFilter {
    // RUST_LOG wins over the config file: it is the ops escape hatch.
    if let Ok(env) = std::env::var("RUST_LOG") {
        if !env.trim().is_empty() {
            if let Ok(filter) = EnvFilter::try_new(&env) {
                return filter;
            }
        }
    }
    let level = cfg.level.trim();
    let level = if parse_level(level).is_some() {
        level.to_ascii_lowercase()
    } else {
        "info".to_string()
    };
    let mut filter = EnvFilter::new(format!("warn,{level}"));
    for (target, directive) in &cfg.filters {
        match format!("{target}={directive}").parse() {
            Ok(d) => filter = filter.add_directive(d),
            Err(err) => {
                eprintln!("warning: invalid log filter `{target}={directive}`: {err}")
            }
        }
    }
    // Keep noisy dependencies at arm's length.
    for quiet in [
        "hyper=warn",
        "rustls=warn",
        "tungstenite=warn",
        "h2=warn",
        "reqwest=warn",
    ] {
        if let Ok(d) = quiet.parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

/// `panic.log` is rotated to `panic.log.1` once it reaches this size, so a
/// crash loop cannot fill the disk (S-26). One backup is kept, no more.
const PANIC_LOG_MAX_BYTES: u64 = 1024 * 1024;

fn install_panic_hook(log_dir: &Path) {
    let path = log_dir.join("panic.log");
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let line = format!(
            "[{}] panic: {info}\nbacktrace:\n{backtrace}\n",
            chrono::Local::now().to_rfc3339()
        );
        let _ = append_panic_record(&path, &line);
        tracing::error!(target: "rt_core::panic", "{info}");
        previous(info);
    }));
}

/// Append one panic record, rotating the current file to `<name>.1` first when
/// it has reached [`PANIC_LOG_MAX_BYTES`]. Returns whether a rotation happened.
fn append_panic_record(path: &Path, line: &str) -> io::Result<bool> {
    let oversized = std::fs::metadata(path)
        .map(|meta| meta.len() >= PANIC_LOG_MAX_BYTES)
        .unwrap_or(false);
    let rotated = if oversized {
        rotate_panic_log(path)
    } else {
        false
    };
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(rotated)
}

/// Move `panic.log` to `panic.log.1`, replacing the previous backup.
fn rotate_panic_log(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let rotated = path.with_file_name(format!("{name}.1"));
    // Windows refuses to rename onto an existing file: drop the old backup.
    let _ = std::fs::remove_file(&rotated);
    std::fs::rename(path, &rotated).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_ring_buffer_is_bounded_and_ordered() {
        let sink = LogEventSink::new(64);
        for i in 0..100i64 {
            sink.push(LogEvent {
                ts_ms: i,
                level: "info".into(),
                target: "t".into(),
                message: format!("m{i}"),
                fields: None,
            });
        }
        let recent = sink.recent(1000);
        assert_eq!(recent.len(), 64);
        assert_eq!(recent.first().unwrap().message, "m36");
        assert_eq!(recent.last().unwrap().message, "m99");
        assert_eq!(sink.dropped(), 36);
        let desc = sink.recent_desc(2);
        assert_eq!(desc[0].message, "m99");
        assert_eq!(desc[1].message, "m98");
    }

    #[test]
    fn levels_parse() {
        assert_eq!(parse_level("DEBUG"), Some(LevelFilter::DEBUG));
        assert_eq!(parse_level("nonsense"), None);
    }

    #[test]
    fn audit_event_is_json_serializable() {
        let ev = AuditEvent::new("exec", "ok")
            .user("admin")
            .scope("workspace")
            .remote("192.168.1.5:5000")
            .target("dir/file.txt")
            .detail("exit=0");
        let json = serde_json::to_string(&ev).expect("json");
        assert!(json.contains("\"action\":\"exec\""));
        assert!(json.contains("\"result\":\"ok\""));
    }

    fn rotated_names(dir: &Path, name: &str) -> Vec<String> {
        let prefix = format!("{name}.");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|file_name| {
                file_name
                    .strip_prefix(&prefix)
                    .is_some_and(is_rotation_stamp)
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn rotation_stamps_are_strictly_recognised() {
        assert!(is_rotation_stamp("20261101-083000"));
        assert!(!is_rotation_stamp("20261101-08300"));
        assert!(!is_rotation_stamp("20261101083000"));
        assert!(!is_rotation_stamp("20261101_083000"));
        assert!(!is_rotation_stamp("tmp"));
    }

    #[test]
    fn audit_open_prunes_the_backlog_and_rotation_stays_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // Backlog from previous runs: five rotated files, a live file over the
        // (test) rotation threshold, and an unrelated neighbour.
        for stamp in [
            "20240101-000000",
            "20240102-000000",
            "20240103-000000",
            "20240104-000000",
            "20240105-000000",
        ] {
            std::fs::write(dir.path().join(format!("audit.jsonl.{stamp}")), b"{}\n").expect("seed");
        }
        std::fs::write(dir.path().join("audit.jsonl.tmp"), b"junk").expect("seed neighbour");
        std::fs::write(&path, vec![b'x'; 400]).expect("seed live");

        let log = AuditLog::open_limits(&path, 2, false, 300, 1).expect("open");
        assert_eq!(log.max_rotated_files(), 2);
        assert!(!log.fail_closed());
        // Opening trims the backlog to the two newest rotations.
        assert_eq!(
            rotated_names(dir.path(), "audit.jsonl"),
            vec![
                "audit.jsonl.20240104-000000".to_string(),
                "audit.jsonl.20240105-000000".to_string()
            ]
        );

        // The first append (check cadence = 1) sees an oversized live file,
        // rotates it, and keeps only the two newest rotations.
        log.log(AuditEvent::new("test.rotate", "ok"));
        let names = rotated_names(dir.path(), "audit.jsonl");
        assert_eq!(names.len(), 2, "rotation must stay bounded: {names:?}");
        assert_eq!(names[0], "audit.jsonl.20240105-000000");
        let fresh = names[1]
            .strip_prefix("audit.jsonl.")
            .expect("rotated prefix");
        assert!(is_rotation_stamp(fresh), "unexpected name: {}", names[1]);
        assert!(
            fresh > "20240105-000000",
            "the fresh rotation must sort last: {fresh}"
        );

        // The live file is new and holds exactly the appended event.
        let live = std::fs::read_to_string(&path).expect("read live");
        assert_eq!(live.lines().count(), 1);
        assert!(live.contains("\"action\":\"test.rotate\""));
        // The unrelated neighbour is never treated as a rotation.
        assert!(dir.path().join("audit.jsonl.tmp").exists());
    }

    #[test]
    fn audit_write_failure_is_reported_and_honours_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open_with(&path, 10, true).expect("open");
        assert!(log.fail_closed());
        log.log(AuditEvent::new("test.ok", "ok"));
        assert_eq!(log.failures(), 0);

        // Force the next write to fail: swap the append handle for a read-only
        // one. Without this a hook that never fails would go untested.
        {
            let mut guard = log.file.lock().expect("lock");
            *guard = std::fs::File::open(&path).expect("read-only handle");
        }
        let err = log
            .log_checked(AuditEvent::new("test.fail", "error"))
            .expect_err("a failed audit write must be reported");
        assert!(matches!(err, RtError::Io { .. }), "unexpected error: {err}");
        assert_eq!(log.failures(), 1);

        // The fire-and-forget path must not panic and still counts the failure.
        log.log(AuditEvent::new("test.fail2", "error"));
        assert_eq!(log.failures(), 2);
    }

    #[test]
    fn audit_fail_open_still_reports_to_checked_callers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open_with(&path, 1, false).expect("open");
        assert!(!log.fail_closed());
        assert_eq!(log.max_rotated_files(), 1);
        {
            let mut guard = log.file.lock().expect("lock");
            *guard = std::fs::File::open(&path).expect("read-only handle");
        }
        assert!(log
            .log_checked(AuditEvent::new("test.fail", "error"))
            .is_err());
        assert_eq!(log.failures(), 1);
    }

    #[test]
    fn panic_log_rotates_into_a_single_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("panic.log");
        let rotated = dir.path().join("panic.log.1");

        // Small records just append; nothing rotates yet.
        assert!(!append_panic_record(&path, "first\n").expect("append"));
        assert!(!append_panic_record(&path, "second\n").expect("append"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "first\nsecond\n"
        );
        assert!(!rotated.exists());

        // A full file is rotated once and the new record starts a fresh file.
        std::fs::write(&path, vec![b'x'; PANIC_LOG_MAX_BYTES as usize + 1]).expect("seed");
        assert!(append_panic_record(&path, "after rotation\n").expect("append"));
        assert_eq!(
            std::fs::metadata(&rotated).expect("backup").len(),
            PANIC_LOG_MAX_BYTES + 1
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "after rotation\n"
        );

        // A second rotation replaces the single backup instead of stacking.
        std::fs::write(&path, vec![b'y'; PANIC_LOG_MAX_BYTES as usize + 1]).expect("seed");
        assert!(append_panic_record(&path, "after second rotation\n").expect("append"));
        let backup = std::fs::read_to_string(&rotated).expect("backup");
        assert_eq!(backup.len(), PANIC_LOG_MAX_BYTES as usize + 1);
        assert_eq!(backup.as_bytes()[0], b'y');
    }
}
