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
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog").field("path", &self.path).finish()
    }
}

const AUDIT_ROTATE_BYTES: u64 = 16 * 1024 * 1024;

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.to_path_buf(), e))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| RtError::io(path.to_path_buf(), e))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            writes: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one JSON line. Never panics and never propagates errors upward:
    /// an audit write failure must not take down the operation, but it *is*
    /// reported through `tracing`.
    pub fn log(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(l) => l,
            Err(err) => {
                tracing::error!(target: "rt_core::audit", "failed to encode audit event: {err}");
                return;
            }
        };
        if let Ok(mut file) = self.file.lock() {
            if let Err(err) = writeln!(file, "{line}") {
                tracing::error!(target: "rt_core::audit", "failed to write audit line: {err}");
            }
            let _ = file.flush();
        }
        let n = self
            .writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n % 500 == 0 {
            self.rotate_if_needed();
        }
        // Mirror into the normal log at info so a single tail shows both.
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
            .map(|m| m.len() > AUDIT_ROTATE_BYTES)
            .unwrap_or(false);
        if !too_big {
            return;
        }
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let rotated = self.path.with_extension(format!("jsonl.{stamp}"));
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

    let file_layer = make_file_layer(
        cfg,
        SharedWriter::new(Box::new(file_writer)),
    );

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
        match AuditLog::open(&cfg.audit_file) {
            Ok(log) => Some(Arc::new(log)),
            Err(err) => {
                tracing::warn!(target: "rt_core::audit", "audit log disabled: {err}");
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
    for quiet in ["hyper=warn", "rustls=warn", "tungstenite=warn", "h2=warn", "reqwest=warn"] {
        if let Ok(d) = quiet.parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

fn install_panic_hook(log_dir: &Path) {
    let path = log_dir.join("panic.log");
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        let line = format!(
            "[{}] panic: {info}\nbacktrace:\n{backtrace}\n",
            chrono::Local::now().to_rfc3339()
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
        tracing::error!(target: "rt_core::panic", "{info}");
        previous(info);
    }));
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
}
