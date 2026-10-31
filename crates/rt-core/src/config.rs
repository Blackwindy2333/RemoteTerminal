//! Persistent configuration.
//!
//! Rules that matter:
//! * The config is created automatically at first start, in the **current
//!   directory** (`./config.toml`), with commented defaults.
//! * Every write is atomic (temp file + fsync + rename) and keeps a `.bak`.
//! * No plaintext secret is ever stored: passwords are Argon2id PHC strings and
//!   API keys are SHA-256 digests.
//! * Paths inside the config are relative to the config file's directory, so a
//!   folder can be moved/copied as a unit.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{crypto, error::Result, error::RtError};

pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const CONFIG_VERSION: u32 = 1;
pub const ENV_CONFIG_PATH: &str = "REMOTE_TERMINAL_CONFIG";

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub config_version: u32,
    pub app: AppConfig,
    pub logging: LoggingConfig,
    pub server: ServerConfig,
    pub client: ClientConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
            app: AppConfig::default(),
            logging: LoggingConfig::default(),
            server: ServerConfig::default(),
            client: ClientConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// [app]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// UI language: `zh-CN` or `en-US`.
    pub language: String,
    pub theme: Theme,
    /// Small accents: `blue` | `purple` | `graphite`.
    pub accent: String,
    pub start_minimized: bool,
    pub single_instance: bool,
    /// Remember window geometry between runs.
    pub remember_window: bool,
    pub window: WindowConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            language: "zh-CN".into(),
            theme: Theme::System,
            accent: "blue".into(),
            start_minimized: false,
            single_instance: true,
            remember_window: true,
            window: WindowConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "system" | "auto" => Some(Theme::System),
            "light" => Some(Theme::Light),
            "dark" => Some(Theme::Dark),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowConfig {
    pub width: f32,
    pub height: f32,
    pub maximized: bool,
    pub sidebar_width: f32,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            width: 1180.0,
            height: 780.0,
            maximized: false,
            sidebar_width: 224.0,
        }
    }
}

// ---------------------------------------------------------------------------
// [logging]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// `trace` | `debug` | `info` | `warn` | `error`
    pub level: String,
    /// Per-module overrides, e.g. `{ "rt_server::routes" = "debug" }`.
    pub filters: std::collections::BTreeMap<String, String>,
    /// Log directory, relative to the config directory.
    pub dir: PathBuf,
    pub file_prefix: String,
    /// Daily rotation keeps at most this many files.
    pub max_files: usize,
    /// Also mirror logs to stderr (useful in headless mode).
    pub console: bool,
    /// Emit JSON lines instead of human-readable text.
    pub json: bool,
    /// Security audit trail (separate file, always JSON lines).
    pub audit: bool,
    pub audit_file: PathBuf,
    /// How many lines the GUI log viewer keeps in memory.
    pub ui_buffer_lines: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            filters: Default::default(),
            dir: PathBuf::from("logs"),
            file_prefix: "remote-terminal".into(),
            max_files: 14,
            console: true,
            json: false,
            audit: true,
            audit_file: PathBuf::from("logs/audit.jsonl"),
            ui_buffer_lines: 2000,
        }
    }
}

// ---------------------------------------------------------------------------
// [server]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// The embedded server only listens when this is true.
    pub enabled: bool,
    /// Display name; defaults to the machine hostname.
    pub name: Option<String>,
    /// Bind address. `0.0.0.0` = LAN, `127.0.0.1` = local only.
    pub bind: String,
    pub port: u16,

    // --- transport security ---
    /// TLS is on by default and required for non-loopback binds.
    pub tls: bool,
    /// Generate a self-signed certificate on first start.
    pub auto_cert: bool,
    /// Custom certificate (PEM). Used when `auto_cert = false`.
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// Escape hatch for trusted, isolated networks. Off = TLS mandatory off-LAN.
    pub allow_insecure_lan: bool,

    // --- policy ---
    pub session_ttl_minutes: u64,
    pub max_sessions: usize,
    pub login_max_attempts: u32,
    pub login_lockout_secs: u64,
    /// Max requests per minute per client IP (0 = unlimited).
    pub rate_limit_per_min: u32,
    /// Optional IP allow-list (`192.168.1.`, `10.0.0.5`, `::1`). Empty = any.
    pub ip_allowlist: Vec<String>,
    /// Honor `X-Forwarded-For` (only set when you really run a reverse proxy).
    pub trust_forwarded_for: bool,

    // --- limits ---
    pub max_upload_mb: u64,
    pub max_json_kb: u64,
    pub exec_timeout_secs: u64,
    pub exec_max_output_kb: u64,
    pub max_concurrent_exec: usize,
    pub capture_max_fps: u8,
    pub status_max_fps: u8,
    pub max_list_entries: usize,

    pub workspace: WorkspaceConfig,
    pub users: Vec<UserConfig>,
    pub api_keys: Vec<ApiKeyConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: None,
            bind: "0.0.0.0".into(),
            port: 46666,
            tls: true,
            auto_cert: true,
            cert_path: None,
            key_path: None,
            allow_insecure_lan: false,
            session_ttl_minutes: 720,
            max_sessions: 32,
            login_max_attempts: 5,
            login_lockout_secs: 300,
            rate_limit_per_min: 240,
            ip_allowlist: Vec::new(),
            trust_forwarded_for: false,
            max_upload_mb: 2048,
            max_json_kb: 256,
            exec_timeout_secs: 300,
            exec_max_output_kb: 8192,
            max_concurrent_exec: 8,
            capture_max_fps: 15,
            status_max_fps: 5,
            max_list_entries: 5000,
            workspace: WorkspaceConfig::default(),
            users: Vec::new(),
            api_keys: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceConfig {
    /// Jail root for `workspace` scope sessions, relative to the config dir.
    pub root: PathBuf,
    /// Create the folder if missing.
    pub create: bool,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("workspace"),
            create: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UserConfig {
    pub name: String,
    /// Argon2id PHC string. Empty means "no password yet" → login disabled.
    pub password_hash: String,
    /// `full` or `workspace`.
    pub scope: String,
    pub enabled: bool,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            name: "admin".into(),
            password_hash: String::new(),
            scope: "full".into(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiKeyConfig {
    pub name: String,
    /// SHA-256 hex digest of the key. Generate with `remote-terminal.exe genkey`.
    pub key_sha256: String,
    pub scope: String,
    pub enabled: bool,
    pub created_at: Option<String>,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            name: "automation".into(),
            key_sha256: String::new(),
            scope: "workspace".into(),
            enabled: true,
            created_at: None,
        }
    }
}

// ---------------------------------------------------------------------------
// [client]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    pub hosts: Vec<HostConfig>,
    /// Refuse to talk to an unpinned server unless the user explicitly confirms
    /// the fingerprint (TOFU dialog in the GUI).
    pub require_pinned_fingerprint: bool,
    pub request_timeout_secs: u64,
    /// `cmd` | `powershell` | `pwsh`
    pub default_shell: String,
    /// Where downloads land, relative to the config directory.
    pub download_dir: PathBuf,
    /// Default capture cadence for the live view.
    pub capture_fps: u8,
    pub capture_format: String,
    pub capture_quality: u8,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            require_pinned_fingerprint: true,
            request_timeout_secs: 60,
            default_shell: "pwsh".into(),
            download_dir: PathBuf::from("downloads"),
            capture_fps: 2,
            capture_format: "jpeg".into(),
            capture_quality: 75,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HostConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// SHA-256 hex of the server's TLS leaf certificate (trust pin).
    pub fingerprint: Option<String>,
    pub username: String,
    /// Last successful scope, for UI hints only.
    pub last_scope: Option<String>,
    pub last_connected: Option<String>,
    /// Connect automatically when the app starts.
    pub auto_connect: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            name: "local".into(),
            host: "127.0.0.1".into(),
            port: 46666,
            fingerprint: None,
            username: "admin".into(),
            last_scope: None,
            last_connected: None,
            auto_connect: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Resolution / persistence
// ---------------------------------------------------------------------------

/// Where the config came from, and where everything else lives.
#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    pub config_file: PathBuf,
    pub base_dir: PathBuf,
    pub data_dir: PathBuf,
    pub workspace_root: PathBuf,
    pub logs_dir: PathBuf,
    pub audit_file: PathBuf,
    pub tls_dir: PathBuf,
    pub downloads_dir: PathBuf,
    pub captures_dir: PathBuf,
    pub transfers_dir: PathBuf,
}

impl ResolvedPaths {
    pub fn resolve(config: &Config, base_dir: &Path) -> Self {
        let base = base_dir.to_path_buf();
        let join = |p: &PathBuf| if p.is_absolute() { p.clone() } else { base.join(p) };
        let data_dir = base.join("data");
        let logs_dir = join(&config.logging.dir);
        let audit_file = join(&config.logging.audit_file);
        Self {
            config_file: base.join(CONFIG_FILE_NAME),
            data_dir: data_dir.clone(),
            workspace_root: join(&config.server.workspace.root),
            logs_dir,
            audit_file,
            tls_dir: data_dir.join("tls"),
            downloads_dir: join(&config.client.download_dir),
            captures_dir: data_dir.join("captures"),
            transfers_dir: data_dir.join("transfers"),
            base_dir: base,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            &self.data_dir,
            &self.logs_dir,
            &self.tls_dir,
            &self.captures_dir,
            &self.transfers_dir,
        ] {
            std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.clone(), e))?;
        }
        Ok(())
    }
}

/// Result of [`load_or_create`].
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
    pub base_dir: PathBuf,
    /// True when the file did not exist and defaults were written.
    pub created: bool,
    /// Non-fatal notes to surface in the UI / log at startup.
    pub warnings: Vec<String>,
}

impl LoadedConfig {
    pub fn paths(&self) -> ResolvedPaths {
        ResolvedPaths::resolve(&self.config, &self.base_dir)
    }
}

fn is_writable_dir(dir: &Path) -> bool {
    let probe = dir.join(".rt_write_probe");
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Pick the config path: explicit flag → env var → CWD → exe dir → %APPDATA%.
pub fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(p) = std::env::var(ENV_CONFIG_PATH) {
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p));
        }
    }

    // 1) current directory — the documented default
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join(CONFIG_FILE_NAME);
        if candidate.exists() {
            return Ok(candidate);
        }
        if is_writable_dir(&cwd) {
            return Ok(candidate);
        }
    }

    // 2) directory that holds the executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(CONFIG_FILE_NAME);
            if candidate.exists() || is_writable_dir(dir) {
                return Ok(candidate);
            }
        }
    }

    // 3) per-user application data
    if let Some(dir) = dirs::config_dir() {
        let dir = dir.join(rt_protocol::APP_NAME);
        std::fs::create_dir_all(&dir).map_err(|e| RtError::io(dir.clone(), e))?;
        return Ok(dir.join(CONFIG_FILE_NAME));
    }

    Err(RtError::Config(
        "unable to determine a writable location for config.toml".into(),
    ))
}

/// Load the config, creating a commented default file when missing.
pub fn load_or_create(explicit_path: Option<&Path>) -> Result<LoadedConfig> {
    let path = resolve_config_path(explicit_path)?;
    let base_dir = path
        .parent()
        .map(|p| p.to_path_buf())
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut warnings = Vec::new();

    if path.exists() {
        let text = std::fs::read_to_string(&path).map_err(|e| RtError::io(path.clone(), e))?;
        let mut config: Config = toml::from_str(&text).map_err(|e| {
            RtError::Config(format!(
                "failed to parse {}: {e}\nHint: fix the TOML or delete the file to regenerate defaults.",
                path.display()
            ))
        })?;

        if config.config_version > CONFIG_VERSION {
            warnings.push(format!(
                "config version {} is newer than supported {}; unknown keys are ignored",
                config.config_version, CONFIG_VERSION
            ));
        }
        if config.config_version < CONFIG_VERSION {
            warnings.push(format!(
                "config migrated from version {} to {}",
                config.config_version, CONFIG_VERSION
            ));
            config.config_version = CONFIG_VERSION;
            let _ = config.save_atomic(&path);
        }

        Ok(LoadedConfig {
            config,
            path,
            base_dir,
            created: false,
            warnings,
        })
    } else {
        let config = Config::default();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.to_path_buf(), e))?;
        }
        config
            .save_with_header(&path)
            .map_err(|e| RtError::Config(format!("failed to write default config: {e}")))?;
        warnings.push(format!("created default config at {}", path.display()));
        Ok(LoadedConfig {
            config,
            path,
            base_dir,
            created: true,
            warnings,
        })
    }
}

impl Config {
    /// Serialize with an explanatory header, so the generated file is readable.
    pub fn to_toml_with_header(&self) -> Result<String> {
        let body = toml::to_string_pretty(self)
            .map_err(|e| RtError::Internal(format!("failed to serialize config: {e}")))?;
        let header = format!(
            "\
# =====================================================================
#  {app} — configuration
# =====================================================================
# This file was generated automatically. It is safe to edit: settings are
# re-read at every start, and invalid values fall back to defaults with a
# warning in the log.
#
# Security notes:
#  * Passwords are never stored in plaintext. `password_hash` is an
#    Argon2id PHC string; generate one with:
#        {app}.exe hash-password
#  * `key_sha256` is the SHA-256 hex digest of an API key; generate both with:
#        {app}.exe genkey --scope workspace
#  * TLS is mandatory unless the server binds to loopback (or you opt out
#    with `allow_insecure_lan`, which is logged as a warning).
#
# Paths are relative to the directory that contains this file.
# =====================================================================

",
            app = rt_protocol::APP_NAME
        );
        Ok(format!("{header}{body}"))
    }

    pub fn save_with_header(&self, path: &Path) -> Result<()> {
        let text = self.to_toml_with_header()?;
        write_atomic(path, text.as_bytes())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self)
            .map_err(|e| RtError::Internal(format!("failed to serialize config: {e}")))?;
        write_atomic(path, body.as_bytes())
    }

    /// Human-readable list of problems that prevent the server from starting.
    /// Splitting "errors" from "warnings" keeps the UI honest.
    pub fn validate(&self) -> ValidationReport {
        let mut report = ValidationReport::default();

        if self.server.port == 0 {
            report.errors.push("server.port must be 1-65535".into());
        }
        if self.server.bind.trim().is_empty() {
            report.errors.push("server.bind must not be empty".into());
        }
        let loopback_only = self.server.bind.trim() == "127.0.0.1"
            || self.server.bind.trim() == "::1"
            || self.server.bind.trim() == "localhost";

        if !self.server.tls && !loopback_only && !self.server.allow_insecure_lan {
            report.errors.push(
                "server.tls = false is only allowed for loopback binds; set allow_insecure_lan = true to override (not recommended)"
                    .into(),
            );
        }
        if !self.server.tls && self.server.allow_insecure_lan {
            report
                .warnings
                .push("plaintext HTTP is enabled on a non-loopback bind".into());
        }
        if self.server.enabled {
            match self.enabled_users() {
                users if users.is_empty() => report.errors.push(
                    "server.enabled = true but no user has a password set; run `hash-password` and paste the result into [[server.users]].password_hash"
                        .into(),
                ),
                _ => {}
            }
        }
        if self.server.users.iter().any(|u| {
            u.enabled
                && !u.password_hash.trim().is_empty()
                && !u.password_hash.starts_with("$argon2")
        }) {
            report.errors.push(
                "server.users[*].password_hash must be an Argon2id PHC string (starts with `$argon2`)"
                    .into(),
            );
        }
        for key in &self.server.api_keys {
            if !key.key_sha256.trim().is_empty() && key.key_sha256.len() != 64 {
                report.errors.push(format!(
                    "server.api_keys[{}].key_sha256 must be 64 hex chars",
                    key.name
                ));
            }
        }
        if self.server.session_ttl_minutes == 0 {
            report
                .warnings
                .push("session_ttl_minutes = 0 means sessions never expire".into());
        }
        if self.app.window.width < 640.0 || self.app.window.height < 480.0 {
            report
                .warnings
                .push("window size is smaller than the 640x480 minimum; using the minimum".into());
        }
        if let Some(name) = &self.server.name {
            if name.trim().is_empty() {
                report.warnings.push("server.name is empty; using hostname".into());
            }
        }
        report
    }

    pub fn enabled_users(&self) -> Vec<&UserConfig> {
        self.server
            .users
            .iter()
            .filter(|u| u.enabled && !u.password_hash.trim().is_empty())
            .collect()
    }

    pub fn server_display_name(&self) -> String {
        self.server
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "windows".into()))
    }

    /// Find (or create) a host entry by host:port.
    pub fn host_entry_mut(&mut self, host: &str, port: u16) -> &mut HostConfig {
        if let Some(idx) = self
            .client
            .hosts
            .iter()
            .position(|h| h.host.eq_ignore_ascii_case(host) && h.port == port)
        {
            &mut self.client.hosts[idx]
        } else {
            self.client.hosts.push(HostConfig {
                name: host.to_string(),
                host: host.to_string(),
                port,
                fingerprint: None,
                username: "admin".into(),
                last_scope: None,
                last_connected: None,
                auto_connect: false,
            });
            let last = self.client.hosts.len() - 1;
            &mut self.client.hosts[last]
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Atomic file write with backup. Used for config and TLS material.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| RtError::io(parent.to_path_buf(), e))?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("tmp")
    ));

    {
        let mut file = std::fs::File::create(&tmp).map_err(|e| RtError::io(tmp.clone(), e))?;
        file.write_all(bytes).map_err(|e| RtError::io(tmp.clone(), e))?;
        file.sync_all().map_err(|e| RtError::io(tmp.clone(), e))?;
    }

    if path.exists() {
        let bak = path.with_extension("toml.bak");
        // Best effort; a missing backup must not block a save.
        let _ = std::fs::copy(path, &bak);
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        RtError::io(path.to_path_buf(), e)
    })?;
    Ok(())
}

/// Generate a fresh API key pair (plaintext for the user, digest for the config).
pub fn generate_api_key() -> (String, String) {
    let key = format!("rt_{}", crypto::random_token(32));
    let digest = crypto::sha256_hex(key.as_bytes());
    (key, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrips() {
        let cfg = Config::default();
        let text = cfg.to_toml_with_header().expect("serialize");
        assert!(text.contains("[server]"));
        assert!(text.contains("[client]"));
        let parsed: Config = toml::from_str(&text).expect("parse");
        assert_eq!(parsed.server.port, 46666);
        assert_eq!(parsed.logging.level, "info");
    }

    #[test]
    fn validate_flags_plaintext_lan() {
        let mut cfg = Config::default();
        cfg.server.tls = false;
        cfg.server.bind = "0.0.0.0".into();
        assert!(!cfg.validate().is_ok());

        cfg.server.allow_insecure_lan = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_requires_password_when_enabled() {
        let mut cfg = Config::default();
        cfg.server.enabled = true;
        assert!(!cfg.validate().is_ok());
        cfg.server.users.push(UserConfig {
            name: "admin".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            scope: "full".into(),
            enabled: true,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn paths_resolve_relative_to_base() {
        let cfg = Config::default();
        let paths = ResolvedPaths::resolve(&cfg, Path::new("C:/app"));
        assert_eq!(paths.logs_dir, Path::new("C:/app/logs"));
        assert_eq!(paths.workspace_root, Path::new("C:/app/workspace"));
        assert_eq!(paths.config_file, Path::new("C:/app/config.toml"));
    }
}
