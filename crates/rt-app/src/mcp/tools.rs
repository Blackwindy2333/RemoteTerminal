//! Tool layer of the MCP bridge: every `rt_*` tool the harness can call.
//!
//! The bridge is a thin, stateless adapter over [`rt_client::RemoteClient`], so
//! anything reachable here is also reachable over plain REST — this keeps the
//! "external interface" promise honest (one API, two dialects).
//!
//! Credentials are never stored by the bridge; it reads them from the config
//! file (host entry) plus environment overrides:
//!
//! Connection settings come from one of three places, simplest first:
//!
//! * a **profile name** saved in `config.toml` (`args: ["mcp", "final"]`) —
//!   host, port, user name and the pinned certificate fingerprint all live in
//!   the file, so the harness entry only needs the password;
//! * a **compact target** (`user@host:port`, `rt://user:pass@host:port?fp=…`);
//! * the individual `RT_*` variables below (kept for compatibility).
//!
//! * `RT_TARGET` — the compact target, when passing it as an argument is not
//!   convenient
//! * `RT_HOST` / `REMOTE_TERMINAL_HOST` — `host` or `host:port`
//! * `RT_PORT` — port when the host has none
//! * `RT_USER` / `RT_PASSWORD` — password login
//! * `RT_TOKEN` — API key (`rt_...`) instead of a password
//! * `RT_FINGERPRINT` — pinned certificate fingerprint
//! * `RT_INSECURE=1` — allow a plaintext HTTP connection (also needs
//!   `RT_ALLOW_PLAINTEXT=1`, see [`Endpoint::resolve_with`])
//! * `RT_REQUIRE_APPROVAL=0` — disable the destructive-tool approval gate
//! * `RT_DOWNLOAD_DIR` / `RT_CAPTURE_DIR` — sandbox for files written locally

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use rt_client::{RemoteClient, Target};
use rt_core::config::{ClientConfig, Config};
use rt_protocol::{
    CaptureRequest, CaptureTarget, CopyRequest, DeleteRequest, ExecRequest, ImageFormat,
    MkdirRequest, OutputEncoding, RenameRequest, ShellKind,
};
use serde_json::{json, Value};

use super::approval::Approvals;

// ---------------------------------------------------------------------------
// Endpoint resolution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub fingerprint: Option<String>,
    pub username: String,
    pub password: Option<String>,
    pub api_key: Option<String>,
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Fields a compact target string can carry. Every field is optional so the
/// same parser serves `final`, `alice@host:port` and the full URL form.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TargetSpec {
    host: Option<String>,
    port: Option<u16>,
    tls: Option<bool>,
    fingerprint: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

/// Parses the one-string form of a target.
///
/// Accepted shapes, first match wins:
///
/// * `final` — a saved host **profile** from `[[client.hosts]]` in `config.toml`
///   (host, port, pinned fingerprint and user name all come from the file);
/// * `alice@10.0.0.5:46666` / `alice:secret@10.0.0.5:46666#AABB…`;
/// * `rt://alice:secret@10.0.0.5:46666?fp=AABB…` (TLS, default) or
///   `http://10.0.0.5:46666` (plaintext, needs `RT_ALLOW_PLAINTEXT=1`);
/// * `10.0.0.5:46666`, `[::1]:46666` or a bare host.
fn parse_connection_target(raw: &str, cfg: &Config) -> std::result::Result<TargetSpec, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(TargetSpec::default());
    }

    // 1. URL form: scheme://[user[:password]@]host[:port][?query]
    if let Some((scheme, rest)) = raw.split_once("://") {
        let mut spec = match scheme.to_ascii_lowercase().as_str() {
            "rt" | "rts" | "remote-terminal" | "remote_terminal" => TargetSpec {
                tls: Some(true),
                ..TargetSpec::default()
            },
            "https" | "wss" => TargetSpec {
                tls: Some(true),
                ..TargetSpec::default()
            },
            "http" | "ws" => TargetSpec {
                tls: Some(false),
                ..TargetSpec::default()
            },
            other => {
                return Err(format!(
                    "unsupported scheme `{other}://`; use rt:// (TLS) or http:// (plaintext)"
                ))
            }
        };
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        // `userinfo@authority` — the user name and password may themselves
        // contain `:`, so split at the last `@`.
        match rest.rsplit_once('@') {
            Some((userinfo, authority)) => {
                let (user, password) = match userinfo.split_once(':') {
                    Some((user, password)) => (user, Some(password.to_string())),
                    None => (userinfo, None),
                };
                if !user.trim().is_empty() {
                    spec.username = Some(url_decode(user));
                }
                spec.password = password.map(|p| url_decode(&p));
                parse_authority(authority, &mut spec)?;
            }
            None => parse_authority(rest, &mut spec)?,
        }
        if let Some(query) = query {
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let value = url_decode(value);
                match key.to_ascii_lowercase().as_str() {
                    "fp" | "fingerprint" => spec.fingerprint = Some(value),
                    "insecure" | "plaintext" => {
                        spec.tls = Some(!matches!(
                            value.to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes"
                        ))
                    }
                    "tls" => {
                        spec.tls = Some(matches!(
                            value.to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes"
                        ))
                    }
                    "token" | "api_key" | "key" => spec.token = Some(value),
                    other => warn_unknown_parameter(other),
                }
            }
        }
        return Ok(spec);
    }

    // 2. `user[:password]@host[:port][#fingerprint]`
    if let Some((userinfo, hostpart)) = raw.rsplit_once('@') {
        let mut spec = TargetSpec::default();
        let (user, password) = match userinfo.split_once(':') {
            Some((user, password)) => (user, Some(password.to_string())),
            None => (userinfo, None),
        };
        if !user.trim().is_empty() {
            spec.username = Some(url_decode(user));
        }
        spec.password = password.map(|p| url_decode(&p));
        parse_authority(hostpart, &mut spec)?;
        return Ok(spec);
    }

    // 3. A bare word is a profile name saved in config.toml.
    let looks_like_address = raw.contains(':')
        || raw.contains('#')
        || raw.starts_with('[')
        || raw.eq_ignore_ascii_case("localhost")
        || raw.chars().all(|c| c.is_ascii_digit() || c == '.');
    let host_like = raw.parse::<std::net::IpAddr>().is_ok();
    if !looks_like_address && !host_like {
        let wanted = raw.to_ascii_lowercase();
        let profile = cfg
            .client
            .hosts
            .iter()
            .find(|h| h.name.to_ascii_lowercase() == wanted)
            .ok_or_else(|| {
                let known: Vec<&str> = cfg.client.hosts.iter().map(|h| h.name.as_str()).collect();
                if known.is_empty() {
                    format!(
                        "`{raw}` is not a saved host; either add it with \
                         `remote-terminal fingerprint <host:port> --save {raw}` \
                         or pass a target like user@host:port"
                    )
                } else {
                    format!(
                        "`{raw}` is not a saved host; known profiles: {} \
                         (save a new one with `remote-terminal fingerprint <host:port> --save {raw}`)",
                        known.join(", ")
                    )
                }
            })?;
        return Ok(TargetSpec {
            host: Some(profile.host.clone()),
            port: Some(profile.port),
            tls: Some(true),
            fingerprint: profile.fingerprint.clone(),
            username: Some(profile.username.clone()),
            ..TargetSpec::default()
        });
    }

    // 4. `host[:port][#fingerprint]`
    let mut spec = TargetSpec::default();
    parse_authority(raw, &mut spec)?;
    Ok(spec)
}

/// Splits `host[:port][#fingerprint]` (IPv6 hosts in brackets) into `spec`.
fn parse_authority(raw: &str, spec: &mut TargetSpec) -> std::result::Result<(), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("target has no host".to_string());
    }
    let (raw, fingerprint) = match raw.split_once('#') {
        Some((raw, fp)) => (raw, Some(url_decode(fp))),
        None => (raw, None),
    };
    if let Some(fp) = fingerprint {
        if !fp.is_empty() {
            spec.fingerprint = Some(fp);
        }
    }

    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("`{raw}` is missing the closing `]` of an IPv6 host"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(port),
            _ => None,
        };
        (host.to_string(), port)
    } else {
        match raw.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                (host.to_string(), Some(port))
            }
            _ => (raw.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("target has no host".to_string());
    }
    spec.host = Some(host);
    if let Some(port) = port {
        let port: u16 = port
            .parse()
            .map_err(|_| format!("`{port}` is not a valid port number"))?;
        spec.port = Some(port);
    }
    Ok(())
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn warn_unknown_parameter(name: &str) {
    tracing::warn!(parameter = %name, "ignoring an unknown target query parameter");
}

impl Endpoint {
    /// Compatibility shim: a resolution failure degrades to the local default.
    pub fn resolve(cfg: &Config) -> Endpoint {
        match Self::resolve_with(cfg, None) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                tracing::warn!(error = %err, "falling back to the local default endpoint");
                Endpoint {
                    host: "127.0.0.1".to_string(),
                    port: cfg.server.port,
                    tls: true,
                    fingerprint: None,
                    username: "admin".to_string(),
                    password: None,
                    api_key: None,
                }
            }
        }
    }

    /// Resolves the endpoint to connect to.
    ///
    /// Precedence, most specific first: the explicit `target` argument (or
    /// `RT_TARGET`), then the individual `RT_*` variables, then the saved host
    /// from `config.toml`, then `127.0.0.1` + `server.port`.
    pub fn resolve_with(
        cfg: &Config,
        target: Option<&str>,
    ) -> std::result::Result<Endpoint, String> {
        let client: &ClientConfig = &cfg.client;
        let saved = client
            .hosts
            .iter()
            .find(|h| h.auto_connect)
            .or_else(|| client.hosts.first());

        let raw = target
            .map(|t| t.to_string())
            .or_else(|| env_first(&["RT_TARGET", "REMOTE_TERMINAL_TARGET"]));
        let spec = match raw.as_deref() {
            Some(raw) => parse_connection_target(raw, cfg)?,
            None => TargetSpec::default(),
        };

        let mut host = spec
            .host
            .clone()
            .or_else(|| env_first(&["RT_HOST", "REMOTE_TERMINAL_HOST"]))
            .or_else(|| saved.map(|s| s.host.clone()))
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let mut port = spec
            .port
            .or_else(|| env_first(&["RT_PORT", "REMOTE_TERMINAL_PORT"]).and_then(|p| p.parse().ok()))
            .or_else(|| saved.map(|s| s.port));

        // `host:port` in RT_HOST wins over RT_PORT. Only the environment may
        // pack a port into the host string; a parsed or saved host is already
        // split, and an IPv6 literal such as `::1` must survive untouched.
        if spec.host.is_none() {
            if let Some((h, p)) = host.rsplit_once(':') {
                if !h.is_empty() && !h.ends_with(']') {
                    if let Ok(parsed) = p.parse::<u16>() {
                        host = h.to_string();
                        port = Some(parsed);
                    }
                }
            }
        }

        // S-20: a plaintext connection sends the password in the clear, so it
        // takes two deliberate opt-ins. `RT_INSECURE=1` alone is ignored (and
        // complained about) rather than silently downgrading the transport.
        let insecure = env_first(&["RT_INSECURE", "REMOTE_TERMINAL_INSECURE"])
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let allow_plaintext = env_first(&["RT_ALLOW_PLAINTEXT", "REMOTE_TERMINAL_ALLOW_PLAINTEXT"])
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mut tls = spec.tls.unwrap_or(true);
        if !tls {
            if allow_plaintext {
                tracing::warn!(
                    "plaintext transport requested: credentials will travel in the clear; \
                     only do this on a trusted point-to-point link"
                );
            } else {
                return Err(
                    "a plaintext target needs RT_ALLOW_PLAINTEXT=1 as an explicit opt-in \
                     (and prefer rt:// with a pinned fingerprint whenever you can)"
                        .to_string(),
                );
            }
        } else if insecure {
            if allow_plaintext {
                tracing::warn!(
                    "RT_INSECURE=1: credentials will travel in plaintext; \
                     only do this on a trusted point-to-point link"
                );
                tls = false;
            } else {
                tracing::warn!("RT_INSECURE=1 ignored: plaintext also requires RT_ALLOW_PLAINTEXT=1");
            }
        }

        let fingerprint = spec
            .fingerprint
            .clone()
            .or_else(|| env_first(&["RT_FINGERPRINT", "REMOTE_TERMINAL_FINGERPRINT"]))
            .or_else(|| saved.and_then(|s| s.fingerprint.clone()))
            .map(|fp| fp.trim().to_string())
            .filter(|fp| !fp.is_empty());

        Ok(Endpoint {
            host,
            port: port.unwrap_or(cfg.server.port),
            tls,
            fingerprint,
            username: spec
                .username
                .clone()
                .or_else(|| env_first(&["RT_USER", "REMOTE_TERMINAL_USER"]))
                .or_else(|| saved.map(|s| s.username.clone()))
                .unwrap_or_else(|| "admin".to_string()),
            password: spec
                .password
                .clone()
                .or_else(|| env_first(&["RT_PASSWORD", "REMOTE_TERMINAL_PASSWORD"])),
            api_key: spec
                .token
                .clone()
                .or_else(|| env_first(&["RT_TOKEN", "REMOTE_TERMINAL_TOKEN"])),
        })
    }

    pub fn target(&self) -> Target {
        let mut target = Target {
            host: self.host.clone(),
            port: self.port,
            tls: self.tls,
            fingerprint: None,
        };
        if self.tls {
            target.fingerprint = self.fingerprint.clone();
        }
        target
    }
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

pub struct Bridge {
    pub client: RemoteClient,
    pub endpoint: Endpoint,
    /// Operator leases for destructive tools (S-17).
    pub approvals: Approvals,
}

impl Bridge {
    pub async fn connect(endpoint: Endpoint, approvals: Approvals) -> Result<Self, String> {
        let client = RemoteClient::new(endpoint.target())
            .map_err(|e| format!("cannot create client: {}", e.message()))?;

        // S-06: an MCP server has no interactive terminal, so trust-on-first-use
        // can never be confirmed. Do not transmit the password over an unpinned
        // TLS connection: probe the certificate fingerprint with an
        // unauthenticated health request, then demand that it be pinned.
        if endpoint.tls && endpoint.fingerprint.is_none() {
            let probe = client.health().await;
            match (probe, client.presented_fingerprint()) {
                (Ok(_), Some(presented)) => {
                    return Err(format!(
                        "refusing to send credentials over an unpinned TLS connection; \
                         pin the server certificate fingerprint first: set RT_FINGERPRINT={presented} \
                         (or `fingerprint = \"{presented}\"` on the [[client.hosts]] entry)"
                    ));
                }
                (Err(err), _) => {
                    return Err(format!(
                        "cannot reach {}: {}",
                        client.target().base_url(),
                        err.message()
                    ));
                }
                (Ok(_), None) => {}
            }
        }

        match &endpoint.api_key {
            Some(key) => client.use_api_key(key),
            None => {
                let password = endpoint
                    .password
                    .clone()
                    .ok_or_else(|| "no credentials: set RT_PASSWORD or RT_TOKEN".to_string())?;
                client
                    .login(&endpoint.username, &password, "mcp-bridge")
                    .await
                    .map_err(|e| format!("login failed: {}", e.message()))?;
            }
        }

        Ok(Self {
            client,
            endpoint,
            approvals,
        })
    }

    pub fn tool_definitions() -> Vec<Value> {
        vec![
            tool(
                "rt_info",
                "Server identity and capabilities: app/protocol version, hostname, scope, TLS fingerprint.",
                json!({}),
            ),
            tool(
                "rt_exec",
                "Run a cmd/pwsh command on the remote Windows machine and return exit code, stdout and stderr.",
                json!({
                    "command": {"type": "string", "description": "Command line to execute."},
                    "shell": {"type": "string", "enum": ["pwsh", "powershell", "cmd"], "description": "Shell to use; defaults to the server's configured shell."},
                    "cwd": {"type": "string", "description": "Working directory (scope-checked)."},
                    "timeout_ms": {"type": "integer", "description": "Wall-clock limit in milliseconds."},
                    "max_output_bytes": {"type": "integer", "description": "Per-stream output cap."},
                    "encoding": {"type": "string", "enum": ["auto", "utf8", "gbk", "raw"]},
                    "stdin_b64": {"type": "string", "description": "Base64 payload piped to stdin."}
                }),
            ),
            tool(
                "rt_fs_roots",
                "Discover where you may browse: the scope root, drives (full scope) and quick paths.",
                json!({}),
            ),
            tool(
                "rt_fs_list",
                "List a remote directory (scope-checked path).",
                json!({"path": {"type": "string", "description": "Directory path; omit for the scope root."}}),
            ),
            tool(
                "rt_fs_stat",
                "Stat one remote path: type, size, timestamps, attributes, volume space.",
                json!({"path": {"type": "string"}}),
            ),
            tool(
                "rt_fs_read",
                "Read the head/range of a remote file. Returns text when decodable, otherwise base64.",
                json!({
                    "path": {"type": "string"},
                    "offset": {"type": "integer"},
                    "length": {"type": "integer"}
                }),
            ),
            tool(
                "rt_fs_write",
                "Write a remote file from text or base64 content (atomic: temp file + rename).",
                json!({
                    "path": {"type": "string"},
                    "content": {"type": "string", "description": "UTF-8 text payload."},
                    "content_b64": {"type": "string", "description": "Base64 payload (wins over content)."},
                    "overwrite": {"type": "boolean"},
                    "create_parents": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_fs_mkdir",
                "Create a remote directory.",
                json!({
                    "path": {"type": "string"},
                    "create_parents": {"type": "boolean"},
                    "allow_existing": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_fs_delete",
                "Delete remote files or directories.",
                json!({
                    "paths": {"type": "array", "items": {"type": "string"}},
                    "recursive": {"type": "boolean"},
                    "even_if_readonly": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_fs_rename",
                "Rename or move a remote path.",
                json!({"from": {"type": "string"}, "to": {"type": "string"}, "overwrite": {"type": "boolean"}}),
            ),
            tool(
                "rt_fs_copy",
                "Copy a remote file or directory tree.",
                json!({
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "recursive": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_fs_download",
                "Download a remote file to this machine (streaming). Transfers resume by default: \
                 if an attempt was interrupted, calling the tool again continues from the bytes \
                 already on disk instead of starting over. Returns the local path, the remote size, \
                 how many bytes this call moved and where it resumed from.",
                json!({
                    "path": {"type": "string", "description": "Remote path."},
                    "local_path": {"type": "string", "description": "Destination file; defaults to <download_dir>/<name>."},
                    "resume": {
                        "type": "boolean",
                        "default": true,
                        "description": "Resume an interrupted transfer from its <local>.part file (default true). Set false to always start from zero."
                    }
                }),
            ),
            tool(
                "rt_fs_upload",
                "Upload a local file to the remote machine (streaming).",
                json!({
                    "local_path": {"type": "string"},
                    "remote_path": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "create_parents": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_sysinfo",
                "Full system snapshot: CPU, memory, disks, network, displays, battery, uptime, app info.",
                json!({}),
            ),
            tool(
                "rt_processes",
                "List remote processes, optionally filtered by name or executable.",
                json!({
                    "limit": {"type": "integer"},
                    "query": {"type": "string"},
                    "sort": {"type": "string", "enum": ["cpu", "memory", "name", "pid"]},
                    "descending": {"type": "boolean"}
                }),
            ),
            tool(
                "rt_screens",
                "Enumerate remote monitors with geometry and scale factor.",
                json!({}),
            ),
            tool(
                "rt_windows",
                "Enumerate remote top-level windows (title, app, pid, bounds, foreground flag).",
                json!({"filter": {"type": "string", "description": "Case-insensitive substring filter on title/app name."}}),
            ),
            tool(
                "rt_capture",
                "Capture a remote screen or window as PNG/JPEG and save it locally.",
                json!({
                    "target": {"type": "string", "description": "primary (default) | all | foreground | screen:<id> | window:<id>"},
                    "format": {"type": "string", "enum": ["png", "jpeg"]},
                    "quality": {"type": "integer", "description": "JPEG quality 1-100."},
                    "max_width": {"type": "integer"},
                    "local_path": {"type": "string", "description": "Where to write the image; defaults to <captures_dir>/capture-<ts>.<ext>."},
                    "inline": {"type": "boolean", "description": "Also return base64 image data (large!)."}
                }),
            ),
        ]
    }

    pub async fn call(&self, name: &str, args: &Value) -> Result<Value, String> {
        // S-17: destructive tools need an operator lease before anything is
        // sent to the remote machine.
        self.approvals.check(name)?;
        match name {
            "rt_info" => self.json(self.client.info().await),
            "rt_exec" => self.exec(args).await,
            "rt_fs_roots" => self.json(self.client.roots().await),
            "rt_fs_list" => {
                let path = arg_str(args, "path").unwrap_or_default();
                self.json(self.client.list(&path).await)
            }
            "rt_fs_stat" => {
                let path = req_str(args, "path")?;
                self.json(self.client.stat(&path).await)
            }
            "rt_fs_read" => {
                let path = req_str(args, "path")?;
                let offset = arg_u64(args, "offset");
                let length = arg_u64(args, "length");
                self.json(self.client.read_file(&path, offset, length).await)
            }
            "rt_fs_write" => {
                let path = req_str(args, "path")?;
                // S-18: never decode an unbounded base64 blob into memory. The
                // streaming upload path (`rt_fs_upload`) exists for big files.
                let data = match arg_str(args, "content_b64") {
                    Some(b64) => {
                        let decoded_len = b64.len() / 4 * 3;
                        if decoded_len > MAX_INLINE_WRITE_BYTES {
                            return Err(format!(
                                "content_b64 is about {decoded_len} bytes, over the \
                                 {MAX_INLINE_WRITE_BYTES}-byte inline limit; write the file locally \
                                 and use rt_fs_upload (streaming) instead"
                            ));
                        }
                        base64_decode(&b64)?
                    }
                    None => req_str(args, "content")?.into_bytes(),
                };
                let overwrite = arg_bool(args, "overwrite").unwrap_or(false);
                let create_parents = arg_bool(args, "create_parents").unwrap_or(true);
                self.json(
                    self.client
                        .write_file(&path, data, overwrite, create_parents)
                        .await,
                )
            }
            "rt_fs_mkdir" => {
                let req = MkdirRequest {
                    path: req_str(args, "path")?,
                    create_parents: arg_bool(args, "create_parents").unwrap_or(true),
                    allow_existing: arg_bool(args, "allow_existing").unwrap_or(true),
                };
                self.json(self.client.mkdir(&req).await)
            }
            "rt_fs_delete" => {
                let paths = args
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| p.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
                    .ok_or_else(|| "missing argument: paths".to_string())?;
                let req = DeleteRequest {
                    paths,
                    recursive: arg_bool(args, "recursive").unwrap_or(false),
                    even_if_readonly: arg_bool(args, "even_if_readonly").unwrap_or(false),
                };
                self.json(self.client.delete(&req).await)
            }
            "rt_fs_rename" => {
                let req = RenameRequest {
                    from: req_str(args, "from")?,
                    to: req_str(args, "to")?,
                    overwrite: arg_bool(args, "overwrite").unwrap_or(false),
                };
                self.json_void(self.client.rename(&req).await)
            }
            "rt_fs_copy" => {
                let req = CopyRequest {
                    from: req_str(args, "from")?,
                    to: req_str(args, "to")?,
                    overwrite: arg_bool(args, "overwrite").unwrap_or(false),
                    recursive: arg_bool(args, "recursive").unwrap_or(true),
                };
                self.json(self.client.copy(&req).await)
            }
            "rt_fs_download" => self.download(args).await,
            "rt_fs_upload" => self.upload(args).await,
            "rt_sysinfo" => self.json(self.client.sysinfo().await),
            "rt_processes" => {
                let limit = arg_u64(args, "limit").unwrap_or(60) as usize;
                let sort = arg_str(args, "sort").unwrap_or_else(|| "cpu".to_string());
                let descending = arg_bool(args, "descending").unwrap_or(true);
                let query = arg_str(args, "query");
                self.json(
                    self.client
                        .processes(limit, query.as_deref(), &sort, descending)
                        .await,
                )
            }
            "rt_screens" => self.json(self.client.screens().await),
            "rt_windows" => {
                let filter = arg_str(args, "filter");
                let windows = self
                    .client
                    .windows()
                    .await
                    .map_err(|e| e.message())?;
                let filtered: Vec<_> = match filter {
                    Some(f) => {
                        let needle = f.to_lowercase();
                        windows
                            .into_iter()
                            .filter(|w| {
                                w.title.to_lowercase().contains(&needle)
                                    || w
                                        .app_name
                                        .as_deref()
                                        .unwrap_or_default()
                                        .to_lowercase()
                                        .contains(&needle)
                            })
                            .collect()
                    }
                    None => windows,
                };
                Ok(json!({"windows": filtered, "count": filtered.len()}))
            }
            "rt_capture" => self.capture(args).await,
            other => Err(format!("unknown tool: {other}")),
        }
    }

    fn json<T: serde::Serialize>(&self, result: rt_client::Result<T>) -> Result<Value, String> {
        match result {
            Ok(value) => serde_json::to_value(value).map_err(|e| format!("serialize: {e}")),
            Err(e) => Err(e.message()),
        }
    }

    fn json_void(&self, result: rt_client::Result<()>) -> Result<Value, String> {
        match result {
            Ok(()) => Ok(json!({"ok": true})),
            Err(e) => Err(e.message()),
        }
    }

    async fn exec(&self, args: &Value) -> Result<Value, String> {
        let command = req_str(args, "command")?;
        let shell = match arg_str(args, "shell") {
            Some(s) => ShellKind::parse_name(&s).ok_or_else(|| format!("unknown shell: {s}"))?,
            None => ShellKind::Pwsh,
        };
        let encoding = match arg_str(args, "encoding").as_deref() {
            Some("utf8") | Some("utf-8") => OutputEncoding::Utf8,
            Some("gbk") => OutputEncoding::Gbk,
            Some("raw") => OutputEncoding::Raw,
            _ => OutputEncoding::Auto,
        };
        let mut request = ExecRequest::new(shell, command);
        request.cwd = arg_str(args, "cwd");
        request.timeout_ms = arg_u64(args, "timeout_ms");
        request.max_output_bytes = arg_u64(args, "max_output_bytes");
        request.encoding = encoding;
        request.stdin_b64 = arg_str(args, "stdin_b64");
        request.env = BTreeMap::new();
        request
            .validate()
            .map_err(|e| format!("invalid request: {e}"))?;
        self.json(self.client.exec(&request).await)
    }

    async fn download(&self, args: &Value) -> Result<Value, String> {
        let path = req_str(args, "path")?;
        let default_name = rt_core::util::sanitize_filename(
            path.rsplit(['\\', '/']).next().unwrap_or("download.bin"),
        );
        // S-19: the destination is still resolved through the local sandbox, no
        // matter which transfer path runs below.
        let local = resolve_local_target(
            arg_str(args, "local_path"),
            "RT_DOWNLOAD_DIR",
            || default_name.clone(),
        )?;

        // Resuming is the default: an interrupted transfer leaves `<local>.part`
        // behind, and the next call continues from there instead of restarting.
        if !arg_bool(args, "resume").unwrap_or(true) {
            let bytes = self
                .client
                .download_to(&path, &local)
                .await
                .map_err(|e| download_error(&path, &local, e.message()))?;
            return Ok(json!({
                "ok": true,
                "local_path": local.display().to_string(),
                "remote_path": path,
                "total_size": bytes,
                "bytes_written": bytes,
                "resumed_from": 0,
                "restarted": false,
            }));
        }

        let report = self
            .client
            .download_resume(&path, &local)
            .await
            .map_err(|e| download_error(&path, &local, e.message()))?;
        Ok(json!({
            "ok": true,
            "local_path": report.path.display().to_string(),
            "remote_path": report.remote_path,
            "total_size": report.total_size,
            "bytes_written": report.bytes_written,
            "resumed_from": report.resumed_from,
            "restarted": report.restarted,
        }))
    }

    async fn upload(&self, args: &Value) -> Result<Value, String> {
        let local = PathBuf::from(req_str(args, "local_path")?);
        let remote = req_str(args, "remote_path")?;
        if !local.exists() {
            return Err(format!("local file not found: {}", local.display()));
        }
        let result = self
            .client
            .upload_file(
                &local,
                &remote,
                arg_bool(args, "overwrite").unwrap_or(false),
                arg_bool(args, "create_parents").unwrap_or(true),
            )
            .await
            .map_err(|e| e.message())?;
        self.json(Ok(result))
    }

    async fn capture(&self, args: &Value) -> Result<Value, String> {
        let target = match arg_str(args, "target").as_deref() {
            None | Some("") | Some("primary") | Some("screen:primary") => CaptureTarget::Primary,
            Some("all") | Some("screens") => CaptureTarget::AllScreens,
            Some("foreground") | Some("active") | Some("window:foreground") => {
                let windows = self.client.windows().await.map_err(|err| err.message())?;
                let window = windows
                    .iter()
                    .find(|w| w.is_foreground)
                    .or_else(|| {
                        windows
                            .iter()
                            .find(|w| w.is_visible && !w.is_minimized && w.width > 0)
                    })
                    .ok_or_else(|| {
                        "no foreground window is available to capture on the remote desktop"
                            .to_string()
                    })?;
                CaptureTarget::Window { id: window.id }
            }
            Some(other) => parse_target(other)?,
        };
        let format = match arg_str(args, "format").as_deref() {
            Some("png") => ImageFormat::Png,
            _ => ImageFormat::Jpeg,
        };
        let request = CaptureRequest {
            target,
            format,
            quality: Some(arg_u64(args, "quality").unwrap_or(75).clamp(1, 100) as u8),
            max_width: arg_u64(args, "max_width").map(|v| v as u32),
            max_height: None,
        };

        let response = self
            .client
            .capture(&request)
            .await
            .map_err(|e| e.message())?;
        let bytes = response
            .into_bytes()
            .ok_or_else(|| "capture payload is not valid base64".to_string())?;
        let meta = response.meta.clone();

        let local = {
            let extension = meta.format.extension().to_string();
            resolve_local_target(arg_str(args, "local_path"), "RT_CAPTURE_DIR", || {
                let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S-%3f");
                format!("capture-{stamp}.{extension}")
            })?
        };
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        std::fs::write(&local, &bytes).map_err(|e| format!("write {}: {e}", local.display()))?;

        let mut out = json!({
            "ok": true,
            "local_path": local.display().to_string(),
            "meta": meta,
        });
        if arg_bool(args, "inline").unwrap_or(false) {
            out["data_b64"] = json!(response.data_b64);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tool(name: &str, description: &str, properties: Value) -> Value {
    let required: Vec<String> = match name {
        "rt_exec" => vec!["command".into()],
        "rt_fs_stat" | "rt_fs_read" | "rt_fs_write" | "rt_fs_mkdir" | "rt_fs_download" => {
            vec!["path".into()]
        }
        "rt_fs_delete" => vec!["paths".into()],
        "rt_fs_rename" | "rt_fs_copy" => vec!["from".into(), "to".into()],
        "rt_fs_upload" => vec!["local_path".into(), "remote_path".into()],
        _ => Vec::new(),
    };
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        }
    })
}

fn arg_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn req_str(args: &Value, key: &str) -> Result<String, String> {
    arg_str(args, key).ok_or_else(|| format!("missing argument: {key}"))
}

fn arg_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    })
}

fn arg_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_u64().map(|n| n != 0),
        _ => None,
    })
}

fn parse_target(spec: &str) -> Result<CaptureTarget, String> {
    let (kind, id) = spec
        .split_once(':')
        .ok_or_else(|| format!("bad target `{spec}` (expected screen:<id> or window:<id>)"))?;
    match kind {
        "screen" | "monitor" => {
            let id: u32 = id.parse().map_err(|_| format!("bad screen id: {id}"))?;
            Ok(CaptureTarget::Screen { id })
        }
        "window" => {
            let id: u64 = id.parse().map_err(|_| format!("bad window id: {id}"))?;
            Ok(CaptureTarget::Window { id })
        }
        other => Err(format!("unknown target kind: {other}")),
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(cleaned.as_bytes()))
        .map_err(|e| format!("bad base64: {e}"))
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let mut candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let mut index = 1;
    while candidate.exists() {
        candidate = dir.join(format!("{stem} ({index}){ext}"));
        index += 1;
    }
    candidate
}

/// Makes `path` absolute and resolves `.`/`..` without touching the filesystem,
/// so a sandbox check sees the path the OS would actually use.
fn normalize_absolute(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Case-insensitive containment check on normalised absolute paths.
fn is_within(root: &Path, candidate: &Path) -> bool {
    let root = root.to_string_lossy().to_lowercase();
    let candidate = candidate.to_string_lossy().to_lowercase();
    if candidate == root {
        return true;
    }
    let with_sep = if root.ends_with('\\') {
        root.clone()
    } else {
        format!("{root}\\")
    };
    candidate.starts_with(&with_sep) || candidate.starts_with(&root.replace('\\', "/"))
}

/// Root directory that locally written files must stay inside (S-19).
///
/// Defaults to the process working directory so behaviour stays predictable,
/// and can be pointed at a dedicated folder with `RT_DOWNLOAD_DIR` /
/// `RT_CAPTURE_DIR`.
fn local_sandbox(var: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(value) if !value.is_empty() => normalize_absolute(Path::new(&value)),
        _ => normalize_absolute(
            &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ),
    }
}

/// Resolves the `local_path` argument, refusing anything outside [`local_sandbox`].
fn resolve_local_target(
    raw: Option<String>,
    var: &str,
    default_name: impl FnOnce() -> String,
) -> Result<PathBuf, String> {
    let root = local_sandbox(var);
    let candidate = match raw {
        Some(value) if !value.trim().is_empty() => normalize_absolute(Path::new(value.trim())),
        _ => unique_path(&root, &default_name()),
    };
    if !is_within(&root, &candidate) {
        return Err(format!(
            "local_path must stay inside {var} ({}) but {} is outside it; \
             set {var} to a wider directory if that is really intended",
            root.display(),
            candidate.display()
        ));
    }
    Ok(candidate)
}

/// Partial-file path of a resumable download (`<file>.part`).
///
/// Mirrors the naming used by [`rt_client::RemoteClient::download_resume`] so
/// the failure message can report how much of an interrupted transfer survived
/// and how many bytes the next call would resume from.
fn partial_download_path(local: &Path) -> Option<PathBuf> {
    let name = local.file_name()?.to_string_lossy().to_string();
    Some(local.with_file_name(format!("{name}.part")))
}

/// Failure message for a download: names both ends of the transfer and tells the
/// operator whether a retry continues from the bytes already on disk.
fn download_error(remote: &str, local: &Path, reason: String) -> String {
    let mut message = format!("download `{remote}` -> {} failed: {reason}", local.display());
    let kept_bytes = partial_download_path(local)
        .and_then(|part| std::fs::metadata(&part).ok().map(|meta| (part, meta)))
        .filter(|(_, meta)| meta.is_file() && meta.len() > 0)
        .map(|(part, meta)| (part, meta.len()));
    if let Some((part, bytes)) = kept_bytes {
        message.push_str(&format!(
            "; the partial download is kept at {} ({bytes} bytes) — calling rt_fs_download \
             again resumes from those {bytes} bytes",
            part.display()
        ));
    }
    message
}

/// Inline (`content_b64`) writes above this size must use streaming upload (S-18).
const MAX_INLINE_WRITE_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_are_well_formed() {
        let tools = Bridge::tool_definitions();
        assert_eq!(tools.len(), 18);
        for tool in &tools {
            assert!(tool["name"].as_str().unwrap().starts_with("rt_"));
            assert!(tool["inputSchema"]["type"] == "object");
            assert!(tool["description"].as_str().unwrap().len() > 10);
        }
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"rt_exec"));
        assert!(names.contains(&"rt_capture"));
    }

    #[test]
    fn argument_parsing() {
        let args = json!({"path": "a.txt", "n": 5, "flag": true});
        assert_eq!(arg_str(&args, "path").as_deref(), Some("a.txt"));
        assert_eq!(arg_str(&args, "missing"), None);
        assert_eq!(arg_u64(&args, "n"), Some(5));
        assert_eq!(arg_bool(&args, "flag"), Some(true));
        assert!(req_str(&args, "missing").is_err());
    }

    #[test]
    fn targets_parse() {
        assert!(matches!(parse_target("screen:2").unwrap(), CaptureTarget::Screen { id: 2 }));
        assert!(matches!(parse_target("window:99").unwrap(), CaptureTarget::Window { id: 99 }));
        assert!(parse_target("bogus").is_err());
        assert!(parse_target("screen:abc").is_err());
    }

    #[test]
    fn base64_tolerates_padding_and_whitespace() {
        assert_eq!(base64_decode("aGVs\nbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert!(base64_decode("!!!!").is_err());
    }

    #[test]
    fn endpoint_defaults_to_config_host() {
        let mut cfg = Config::default();
        cfg.server.port = 5000;
        cfg.client.hosts.push(rt_core::config::HostConfig {
            name: "home".into(),
            host: "10.0.0.5".into(),
            port: 6000,
            fingerprint: Some("AB".repeat(32)),
            username: "alice".into(),
            last_scope: None,
            last_connected: None,
            auto_connect: true,
        });
        let ep = Endpoint::resolve(&cfg);
        assert_eq!(ep.host, "10.0.0.5");
        assert_eq!(ep.port, 6000);
        assert_eq!(ep.username, "alice");
        assert_eq!(ep.fingerprint.as_deref(), Some("ABAB".repeat(16).as_str()));
    }

    #[test]
    fn unique_path_avoids_overwrite() {
        let dir = std::env::temp_dir().join(format!("rt_mcp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let next = unique_path(&dir, "a.txt");
        assert_eq!(next.file_name().unwrap(), "a (1).txt");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn profile_cfg() -> Config {
        let mut cfg = Config::default();
        cfg.server.port = 5000;
        cfg.client.hosts.push(rt_core::config::HostConfig {
            name: "final".into(),
            host: "10.0.0.5".into(),
            port: 6000,
            fingerprint: Some("AB".repeat(32)),
            username: "alice".into(),
            last_scope: None,
            last_connected: None,
            auto_connect: false,
        });
        cfg
    }

    #[test]
    fn a_bare_word_selects_the_saved_profile() {
        let cfg = profile_cfg();
        let ep = Endpoint::resolve_with(&cfg, Some("final")).expect("profile resolves");
        assert_eq!(ep.host, "10.0.0.5");
        assert_eq!(ep.port, 6000);
        assert_eq!(ep.username, "alice");
        assert!(ep.tls);
        assert_eq!(ep.fingerprint.as_deref(), Some("AB".repeat(32).as_str()));

        // Names are matched case-insensitively.
        assert!(Endpoint::resolve_with(&cfg, Some("FINAL")).is_ok());
    }

    #[test]
    fn an_unknown_profile_lists_the_known_ones() {
        let cfg = profile_cfg();
        let err = Endpoint::resolve_with(&cfg, Some("nope")).expect_err("unknown profile");
        assert!(err.contains("not a saved host"), "{err}");
        assert!(
            err.contains("final"),
            "the message should name the known profile: {err}"
        );
    }

    #[test]
    fn inline_targets_carry_user_port_and_fingerprint() {
        let cfg = Config::default();

        let ep = Endpoint::resolve_with(&cfg, Some("bob@192.168.1.9:47000#AABBCC"))
            .expect("user@host:port");
        assert_eq!(ep.host, "192.168.1.9");
        assert_eq!(ep.port, 47000);
        assert_eq!(ep.username, "bob");
        assert_eq!(ep.fingerprint.as_deref(), Some("AABBCC"));

        // A bracketed IPv6 literal keeps its colons.
        let ep = Endpoint::resolve_with(&cfg, Some("[::1]:46666")).expect("ipv6");
        assert_eq!(ep.host, "::1");
        assert_eq!(ep.port, 46666);

        // A bare host keeps the server port.
        let ep = Endpoint::resolve_with(&cfg, Some("10.1.2.3")).expect("host only");
        assert_eq!(ep.host, "10.1.2.3");
        assert_eq!(ep.port, cfg.server.port);
    }

    #[test]
    fn url_targets_decode_credentials_and_queries() {
        let cfg = Config::default();
        let ep = Endpoint::resolve_with(
            &cfg,
            Some("rt://alice:s%40cret@10.0.0.5:46666?fp=AA%3ABB&token=rt_xyz"),
        )
        .expect("rt url");
        assert!(ep.tls);
        assert_eq!(ep.username, "alice");
        assert_eq!(ep.password.as_deref(), Some("s@cret"));
        assert_eq!(ep.fingerprint.as_deref(), Some("AA:BB"));
        assert_eq!(ep.api_key.as_deref(), Some("rt_xyz"));

        // An unknown scheme is a clear error rather than a silent fallback.
        let err = Endpoint::resolve_with(&cfg, Some("ftp://10.0.0.5")).expect_err("scheme");
        assert!(err.contains("unsupported scheme"), "{err}");
    }

    #[test]
    fn plaintext_targets_need_an_explicit_opt_in() {
        if env_first(&["RT_ALLOW_PLAINTEXT", "REMOTE_TERMINAL_ALLOW_PLAINTEXT"]).is_some() {
            // The environment already opts in; the refusal path is covered
            // below without racing on process-wide variables.
            return;
        }
        let cfg = Config::default();
        let err = Endpoint::resolve_with(&cfg, Some("http://10.0.0.5:46666"))
            .expect_err("plaintext needs RT_ALLOW_PLAINTEXT=1");
        assert!(err.contains("RT_ALLOW_PLAINTEXT"), "{err}");
    }

    #[test]
    fn an_out_of_range_port_is_reported() {
        let cfg = Config::default();
        // `host:abc` is a host name with a colon, not a port.
        let ep = Endpoint::resolve_with(&cfg, Some("myhost:abc")).expect("host with colon");
        assert_eq!(ep.host, "myhost:abc");
        // A numeric port outside 0..=65535 is rejected outright.
        let err = Endpoint::resolve_with(&cfg, Some("10.0.0.5:99999")).expect_err("port range");
        assert!(err.contains("not a valid port"), "{err}");
    }

    #[test]
    fn download_tool_documents_resume() {
        let tools = Bridge::tool_definitions();
        let download = tools
            .iter()
            .find(|tool| tool["name"] == "rt_fs_download")
            .expect("rt_fs_download definition");
        assert!(
            download["description"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("resume"),
            "the description must tell the agent that transfers resume"
        );
        let resume = &download["inputSchema"]["properties"]["resume"];
        assert_eq!(resume["type"], "boolean");
        assert_eq!(resume["default"], true);
        assert!(resume["description"].as_str().unwrap().contains("true"));
        // `resume` stays optional: only `path` is required.
        let required = download["inputSchema"]["required"].as_array().unwrap();
        assert_eq!(required, &vec![json!("path")]);
    }

    #[test]
    fn partial_path_mirrors_the_client_convention() {
        let local = Path::new(r"C:\downloads\report.zip");
        let part = partial_download_path(local).expect("partial path");
        assert_eq!(part, PathBuf::from(r"C:\downloads\report.zip.part"));
        assert_eq!(partial_download_path(Path::new("")), None);
    }

    /// `rt_fs_download` reads the flag exactly like this: absent means resume.
    #[test]
    fn resume_flag_defaults_on_and_parses_explicit_values() {
        let resume = |args: &Value| arg_bool(args, "resume").unwrap_or(true);
        assert!(resume(&json!({"path": "a.txt"})));
        assert!(!resume(&json!({"path": "a.txt", "resume": false})));
        assert!(!resume(&json!({"path": "a.txt", "resume": "false"})));
        assert!(!resume(&json!({"path": "a.txt", "resume": 0})));
        assert!(resume(&json!({"path": "a.txt", "resume": true})));
        assert!(resume(&json!({"path": "a.txt", "resume": "yes"})));
    }
}
