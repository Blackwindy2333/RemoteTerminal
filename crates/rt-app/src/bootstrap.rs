//! Startup glue shared by every entry point: configuration, directories,
//! logging, single-instance guard and the tokio runtime.
//!
//! Order matters and is deliberate:
//! 1. resolve + load (or create) `config.toml`
//! 2. resolve the directory layout and create it
//! 3. start logging — so anything that fails afterwards is still recorded
//! 4. validate the config and log the outcome (never fatal: a broken config
//!    must not brick an installed app, it must be reported in the UI)

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::Context;
use fs2::FileExt;
use rt_core::config::{self, Config, LoadedConfig, ResolvedPaths};
use rt_core::logging::{self, LoggingGuard};

/// Everything a front end needs after startup.
pub struct Bootstrapped {
    pub loaded: LoadedConfig,
    pub paths: ResolvedPaths,
    pub logging: LoggingGuard,
}

impl Bootstrapped {
    pub fn config(&self) -> &Config {
        &self.loaded.config
    }

    pub fn config_path(&self) -> &Path {
        &self.loaded.path
    }
}

/// Loads (creating when missing) the config, prepares the directory layout and
/// starts the logging stack.
///
/// `console` must be `false` for the MCP bridge (stdout carries JSON-RPC) and
/// `true` for `serve`/CLI subcommands.
pub fn bootstrap(
    config_path: Option<&Path>,
    verbose: bool,
    console: bool,
) -> anyhow::Result<Bootstrapped> {
    let mut loaded = config::load_or_create(config_path)?;

    if verbose {
        loaded.config.logging.level = "debug".to_string();
    }
    if let Ok(level) = std::env::var("RUST_LOG") {
        loaded.config.logging.level = level;
    }

    let paths = ResolvedPaths::resolve(&loaded.config, &loaded.base_dir);
    paths
        .ensure_dirs()
        .with_context(|| format!("cannot prepare data directories under {}", paths.data_dir.display()))?;

    let logging = logging::init(&loaded.config.logging, &paths.logs_dir, console)
        .context("cannot initialise logging")?;

    install_control_path_guards(&loaded, &paths);

    if loaded.created {
        tracing::info!(path = %loaded.path.display(), "created default configuration file");
    }
    for warning in &loaded.warnings {
        tracing::warn!(target: "config", "{warning}");
    }

    let report = loaded.config.validate();
    for warning in &report.warnings {
        tracing::warn!(target: "config", "{warning}");
    }
    for error in &report.errors {
        tracing::error!(target: "config", "{error}");
    }

    tracing::info!(
        version = rt_protocol::APP_VERSION,
        protocol = rt_protocol::PROTOCOL_VERSION,
        config = %loaded.path.display(),
        data_dir = %paths.data_dir.display(),
        base_dir = %loaded.base_dir.display(),
        server_enabled = loaded.config.server.enabled,
        "RemoteTerminal starting"
    );

    Ok(Bootstrapped {
        loaded,
        paths,
        logging,
    })
}

/// Keep the server control files out of reach of every remote session.
///
/// A fully privileged session may roam the machine, but it must not be able to
/// rewrite `config.toml` (and grant itself more users or a wider scope),
/// replace the TLS private key, or edit the audit trail. The list is installed
/// once per process, before any listener starts, and is enforced by
/// [`rt_core::pathscope::PathGuard::resolve`].
fn install_control_path_guards(loaded: &LoadedConfig, paths: &ResolvedPaths) {
    let mut protected = vec![
        loaded.path.clone(),
        paths.config_file.clone(),
        paths.audit_file.clone(),
        paths.tls_dir.clone(),
        paths.data_dir.join("instance.lock"),
    ];
    let mut backup = loaded.path.clone().into_os_string();
    backup.push(".bak");
    protected.push(PathBuf::from(backup));
    // Entries that do not exist yet are canonicalised on first use; duplicates
    // are harmless because the check is a prefix test.
    rt_core::pathscope::protect_paths(protected);
    tracing::debug!(
        target: "config",
        count = rt_core::pathscope::protected_paths().len(),
        "installed protected control paths"
    );
}

/// Single-instance guard: an exclusive lock on a file inside the data dir.
///
/// Returns `Ok(None)` when another instance already holds it. The lock dies with
/// the process, so a crash never leaves a stale guard behind.
pub fn acquire_single_instance(paths: &ResolvedPaths, enabled: bool) -> anyhow::Result<Option<File>> {
    if !enabled {
        return Ok(None);
    }
    let path = paths.data_dir.join("instance.lock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;

    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(_) => Ok(None),
    }
}

/// Multi-threaded runtime sized for a desktop app: a few workers are enough and
/// keep idle CPU low, while blocking work is pushed to the blocking pool.
pub fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        // S-23: blocking work (file I/O, process spawns, screen capture) runs on
        // this pool. It is deliberately larger than the synchronous core count
        // so a handful of slow captures cannot starve requests, and the server
        // additionally applies its own admission limit (64 permits) before
        // handing work to `spawn_blocking`, so the pool itself is the backstop
        // rather than the primary throttle.
        .max_blocking_threads(BLOCKING_THREADS)
        .thread_name("rt-worker")
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

/// Upper bound on threads doing blocking work; see [`runtime`].
pub const BLOCKING_THREADS: usize = 64;

/// Absolute path helper used by the CLI defaults.
pub fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
