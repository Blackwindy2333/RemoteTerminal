//! MCP bridge — exposes every RemoteTerminal capability as a stdio tool server.
//!
//! `remote-terminal.exe mcp` starts a JSON-RPC 2.0 server on stdin/stdout, one
//! JSON message per line (the MCP stdio transport). Nothing else is ever written
//! to stdout: logs go to the log file and to stderr, so the harness can talk to
//! this process safely.
//!
//! The shortest way to register it is a saved host profile — one argument, one
//! secret:
//!
//! ```json
//! { "command": "remote-terminal.exe", "args": ["mcp", "final"],
//!   "env": { "RT_PASSWORD": "..." } }
//! ```
//!
//! Save the profile once with `remote-terminal.exe fingerprint <host>:<port>
//! --save final` (it stores host, port, user name and the pinned certificate
//! fingerprint in `config.toml`). `remote-terminal.exe mcp-config` prints the
//! whole snippet, ready to paste. Without a profile the target can be given
//! inline as `user@host:port` or `rt://user:pass@host:port?fp=…`; the individual
//! `RT_*` variables still work as a last resort.

pub mod approval;
pub mod tools;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

use approval::Approvals;
use tools::{Bridge, Endpoint};

const SERVER_NAME: &str = "remote-terminal";
const SUPPORTED_PROTOCOLS: &[&str] = &["2024-11-05", "2024-10-07", "2025-03-26", "2025-06-18"];
/// Largest accepted request line. A bigger one is refused instead of buffered
/// (S-37): the bridge must not turn a hostile agent into an OOM.
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Error text handed back to the model is clipped to this many characters
/// (S-36) so a chatty server error cannot flood the conversation.
const MAX_ERROR_CHARS: usize = 2000;

/// Runs the stdio bridge until stdin closes. Returns a process exit code.
///
/// `target` is the optional one-string target: a saved profile name, or
/// `user@host:port`, or `rt://user:pass@host:port?fp=…`.
pub async fn run(config_path: Option<PathBuf>, target: Option<String>) -> anyhow::Result<i32> {
    let loaded = rt_core::config::load_or_create(config_path.as_deref())
        .map_err(|e| anyhow::anyhow!("cannot load config: {e}"))?;
    let paths = rt_core::config::ResolvedPaths::resolve(&loaded.config, &loaded.base_dir);
    paths.ensure_dirs()?;

    // Console logging is off: stdout carries the protocol.
    let _logging = rt_core::logging::init(&loaded.config.logging, &paths.logs_dir, false)
        .map_err(|e| anyhow::anyhow!("cannot start logging: {e}"))?;
    tracing::info!(
        config = %loaded.path.display(),
        "MCP bridge starting (stdio transport)"
    );

    // A bad target must not kill the bridge: the tools still answer, they just
    // explain what to fix (the harness shows that text to the model).
    let (endpoint, target_error) = match Endpoint::resolve_with(&loaded.config, target.as_deref()) {
        Ok(endpoint) => (endpoint, None),
        Err(err) => {
            tracing::error!(error = %err, "cannot resolve the MCP target");
            (Endpoint::resolve(&loaded.config), Some(err))
        }
    };
    tracing::info!(
        host = %endpoint.host,
        port = endpoint.port,
        tls = endpoint.tls,
        pinned = endpoint.fingerprint.is_some(),
        "MCP bridge endpoint resolved"
    );

    // S-17: destructive tools stay locked until the operator grants a lease.
    let approvals = Approvals::resolve(&paths.data_dir);
    if approvals.enabled() {
        let pruned = approvals.prune();
        let live = approvals.grants();
        tracing::info!(
            file = %approvals.path().display(),
            pruned,
            leases = live.len(),
            "destructive MCP tools require an operator lease"
        );
        if live.is_empty() {
            tracing::warn!(
                "no destructive tool is currently approved; `rt_exec`, `rt_fs_write`, \
                 `rt_fs_delete`, `rt_fs_rename`, `rt_fs_copy` and `rt_fs_upload` will be \
                 refused until `remote-terminal approve <tool> --minutes N` runs"
            );
        }
    }

    let mut state = McpState {
        endpoint,
        approvals,
        bridge: None,
        target_invalid: target_error.is_some(),
        connect_error: target_error,
    };

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut writer = BufWriter::new(stdout);

    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // S-37: refuse oversized requests rather than parsing them.
        if line.len() > MAX_INPUT_BYTES {
            tracing::warn!(bytes = line.len(), "refusing an oversized MCP request line");
            let reply = error_reply(
                Value::Null,
                -32600,
                &format!("request too large: {} bytes (limit {MAX_INPUT_BYTES})", line.len()),
            );
            write_reply(&mut writer, &reply).await?;
            continue;
        }

        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let reply = error_reply(Value::Null, -32700, &format!("parse error: {e}"));
                write_reply(&mut writer, &reply).await?;
                continue;
            }
        };

        if let Some(reply) = state.handle(request).await {
            write_reply(&mut writer, &reply).await?;
        }
    }

    tracing::info!("MCP bridge stdin closed, exiting");
    Ok(0)
}

/// A ready-to-paste MCP registration plus the caveats worth knowing.
#[derive(Debug)]
pub struct Snippet {
    pub json: String,
    pub notes: Vec<String>,
}

/// Builds the `dsh-mcp.json` entry for this executable.
///
/// With a saved profile the args are just `["mcp", "<profile>"]` and the only
/// secret left is `RT_PASSWORD`, which keeps the harness entry short.
pub fn config_snippet(
    config: &rt_core::config::Config,
    target: Option<&str>,
    exe: &Path,
    config_path: Option<&Path>,
) -> std::result::Result<Snippet, String> {
    let raw = target.map(str::trim).filter(|t| !t.is_empty());
    let profile = match raw {
        Some(raw) => config
            .client
            .hosts
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(raw)),
        None => config
            .client
            .hosts
            .iter()
            .find(|h| h.auto_connect)
            .or_else(|| config.client.hosts.first()),
    };

    let (label, argument) = match (raw, profile) {
        (Some(raw), Some(saved)) => (saved.name.clone(), raw.to_string()),
        (None, Some(saved)) => (saved.name.clone(), saved.name.clone()),
        // An inline target already carries everything the profile would.
        (Some(raw), None) => (raw.to_string(), raw.to_string()),
        (None, None) => {
            return Err(
                "no saved host yet: run `remote-terminal fingerprint <host>:port --save <name>` \
                 (or `remote-terminal mcp-config --target user@host:port`)"
                    .to_string(),
            )
        }
    };

    let mut notes = Vec::new();
    if let Some(saved) = profile {
        if saved.fingerprint.is_none() {
            notes.push(format!(
                "profile `{}` has no pinned fingerprint yet; run \
                 `remote-terminal fingerprint {} --save {}` so the bridge can verify the server \
                 before it sends the password",
                saved.name, saved.name, saved.name
            ));
        }
    } else if !argument.contains('#') && !argument.contains("fp=") {
        notes.push(
            "the target has no certificate fingerprint; pin it (`#<hex>`, `?fp=<hex>`, or \
             RT_FINGERPRINT) or the bridge will refuse to send the password"
                .to_string(),
        );
    }
    notes.push(
        "replace REPLACE_WITH_THE_PASSWORD with the account password, or use \
         \"RT_TOKEN\": \"rt_…\" instead of RT_PASSWORD"
            .to_string(),
    );

    let name: String = label
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-');
    let name = if name.is_empty() {
        "remote-terminal"
    } else {
        name
    };

    let cwd = exe
        .parent()
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    // The bridge resolves `config.toml` from its working directory, so a config
    // living anywhere else has to be named explicitly or a second, empty config
    // would be created next to the executable.
    let needs_config_flag = config_path
        .map(|path| {
            let dir = path.parent().unwrap_or(Path::new(""));
            !dir.as_os_str().is_empty() && dir != Path::new(&cwd)
        })
        .unwrap_or(false);
    let mut args = Vec::new();
    if needs_config_flag {
        if let Some(path) = config_path {
            args.push("--config".to_string());
            args.push(path.display().to_string());
        }
    }
    args.push("mcp".to_string());
    args.push(argument.clone());

    let mut entry = serde_json::Map::new();
    entry.insert("transport".into(), json!("stdio"));
    entry.insert("enabled".into(), json!(true));
    entry.insert("command".into(), json!(exe.display().to_string()));
    entry.insert("args".into(), json!(args));
    entry.insert(
        "env".into(),
        json!({ "RT_PASSWORD": "REPLACE_WITH_THE_PASSWORD" }),
    );
    entry.insert("cwd".into(), json!(cwd));
    let mut servers = serde_json::Map::new();
    servers.insert(name.to_string(), serde_json::Value::Object(entry));
    let snippet = json!({ "version": 1, "servers": servers });
    let json = serde_json::to_string_pretty(&snippet)
        .map_err(|e| format!("cannot render the snippet: {e}"))?;
    Ok(Snippet { json, notes })
}

struct McpState {
    endpoint: Endpoint,
    approvals: Approvals,
    bridge: Option<Bridge>,
    /// Set when the target or the connection failed; every tool call reports it
    /// instead of silently talking to the wrong machine.
    connect_error: Option<String>,
    /// The stored error came from resolving the target, so retrying cannot help.
    target_invalid: bool,
}

impl McpState {
    /// Lazily connects so a temporarily unreachable server does not stop the
    /// harness from starting; errors surface on the first tool call, and every
    /// later call retries.
    async fn ensure_bridge(&mut self) -> Result<&Bridge, String> {
        if self.bridge.is_none() {
            // A bad target is a configuration error, not a transient one:
            // retrying would connect to the fallback host instead.
            if let Some(err) = self.fatal_error() {
                return Err(err);
            }
            match Bridge::connect(self.endpoint.clone(), self.approvals.clone()).await {
                Ok(bridge) => {
                    tracing::info!(
                        host = %self.endpoint.host,
                        port = self.endpoint.port,
                        "MCP bridge connected"
                    );
                    self.connect_error = None;
                    self.bridge = Some(bridge);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "MCP bridge connection failed");
                    self.connect_error = Some(e.clone());
                    return Err(e);
                }
            }
        }
        Ok(self.bridge.as_ref().expect("bridge set above"))
    }

    /// The stored error when it came from resolving the target.
    fn fatal_error(&self) -> Option<String> {
        if self.target_invalid {
            self.connect_error.clone()
        } else {
            None
        }
    }

    async fn handle(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let is_notification = request.get("id").is_none();
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_string();

        // Notifications never get a reply.
        if is_notification {
            match method.as_str() {
                "notifications/initialized" => tracing::debug!("client initialised"),
                "notifications/cancelled" => tracing::debug!("client cancelled a request"),
                _ => {}
            }
            return None;
        }

        let params = request.get("params").cloned().unwrap_or(Value::Null);

        match method.as_str() {
            "initialize" => {
                let requested = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or(SUPPORTED_PROTOCOLS[0]);
                let version = if SUPPORTED_PROTOCOLS.contains(&requested) {
                    requested
                } else {
                    SUPPORTED_PROTOCOLS[0]
                };
                Some(ok_reply(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": {
                            "name": SERVER_NAME,
                            "version": rt_protocol::APP_VERSION
                        },
                        "instructions": "RemoteTerminal bridge: run commands, move files, read system info and capture the screen of a paired Windows machine. Paths are scope-checked by the server."
                    }),
                ))
            }
            "ping" => Some(ok_reply(id, json!({}))),
            "tools/list" => Some(ok_reply(
                id,
                json!({ "tools": Bridge::tool_definitions() }),
            )),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                if name.is_empty() {
                    return Some(error_reply(id, -32602, "missing tool name"));
                }

                let result = match self.ensure_bridge().await {
                    Ok(bridge) => bridge.call(&name, &args).await,
                    Err(e) => Err(format!("not connected: {e}")),
                };

                match result {
                    Ok(payload) => Some(ok_reply(id, tool_content(&payload, false))),
                    Err(message) => {
                        tracing::warn!(tool = %name, error = %message, "tool call failed");
                        Some(ok_reply(id, tool_content(&json!({ "error": message }), true)))
                    }
                }
            }
            // Optional MCP methods some clients probe for; answering keeps the
            // handshake friendly without claiming capabilities we lack.
            "resources/list" => Some(ok_reply(id, json!({ "resources": [] }))),
            "prompts/list" => Some(ok_reply(id, json!({ "prompts": [] }))),
            "logging/setLevel" => Some(ok_reply(id, json!({}))),
            other => Some(error_reply(
                id,
                -32601,
                &format!("method not found: {other}"),
            )),
        }
    }
}

fn tool_content(payload: &Value, is_error: bool) -> Value {
    let payload = if is_error {
        clip_error_text(payload)
    } else {
        payload.clone()
    };
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    })
}

/// Clips an `{"error": "..."}` payload to [`MAX_ERROR_CHARS`] (S-36).
fn clip_error_text(payload: &Value) -> Value {
    let Some(message) = payload.get("error").and_then(|e| e.as_str()) else {
        return payload.clone();
    };
    if message.chars().count() <= MAX_ERROR_CHARS {
        return payload.clone();
    }
    let clipped: String = message.chars().take(MAX_ERROR_CHARS).collect();
    json!({
        "error": clipped,
        "truncated": true,
        "note": format!(
            "the error text was clipped to {MAX_ERROR_CHARS} characters"
        )
    })
}

fn ok_reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

async fn write_reply<W: AsyncWriteExt + Unpin>(writer: &mut W, reply: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_string(reply)
        .unwrap_or_else(|_| "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"encode error\"}}".to_string());
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> McpState {
        let dir = std::env::temp_dir().join(format!("rt-mcp-test-{}", std::process::id()));
        McpState {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                tls: false,
                fingerprint: None,
                username: "admin".into(),
                password: Some("x".into()),
                api_key: None,
            },
            approvals: Approvals::resolve(&dir),
            bridge: None,
            connect_error: None,
            target_invalid: false,
        }
    }

    #[tokio::test]
    async fn initialize_reports_capabilities() {
        let mut state = state();
        let reply = state
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
            }))
            .await
            .expect("reply");
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(reply["result"]["serverInfo"]["name"], "remote-terminal");
        assert!(reply["result"]["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn unknown_protocol_falls_back() {
        let mut state = state();
        let reply = state
            .handle(json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}))
            .await
            .unwrap();
        assert_eq!(reply["result"]["protocolVersion"], SUPPORTED_PROTOCOLS[0]);
    }

    #[tokio::test]
    async fn notifications_are_silent() {
        let mut state = state();
        let reply = state
            .handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert!(reply.is_none());
    }

    #[tokio::test]
    async fn tools_list_contains_all_tools() {
        let mut state = state();
        let reply = state
            .handle(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
            .await
            .unwrap();
        let tools = reply["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 18);
    }

    #[tokio::test]
    async fn tool_call_without_connection_returns_tool_error() {
        let mut state = state();
        let reply = state
            .handle(json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "rt_info", "arguments": {} }
            }))
            .await
            .unwrap();
        assert_eq!(reply["result"]["isError"], true);
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("error"));
    }

    #[tokio::test]
    async fn missing_tool_name_is_a_protocol_error() {
        let mut state = state();
        let reply = state
            .handle(json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}}))
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn unknown_method_is_rejected() {
        let mut state = state();
        let reply = state
            .handle(json!({"jsonrpc": "2.0", "id": 6, "method": "nope/nope"}))
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32601);
    }

    #[test]
    fn snippet_uses_the_profile_name_and_one_secret() {
        let mut cfg = rt_core::config::Config::default();
        cfg.client.hosts.push(rt_core::config::HostConfig {
            name: "书房的 工作站".into(),
            host: "10.0.0.5".into(),
            port: 6000,
            fingerprint: Some("ab".repeat(32)),
            username: "alice".into(),
            last_scope: None,
            last_connected: None,
            auto_connect: true,
        });
        let exe = std::path::Path::new(r"C:\apps\remote-terminal.exe");
        let snippet = config_snippet(&cfg, None, exe, None).expect("snippet");
        let value: Value = serde_json::from_str(&snippet.json).expect("valid json");
        let servers = value["servers"].as_object().expect("servers");
        assert_eq!(servers.len(), 1);
        // The profile name is kebab-cased so it stays a safe JSON key.
        let entry = servers.values().next().unwrap();
        assert_eq!(entry["args"], json!(["mcp", "书房的 工作站"]));
        assert_eq!(entry["transport"], "stdio");
        assert_eq!(entry["command"], json!(r"C:\apps\remote-terminal.exe"));
        assert_eq!(entry["cwd"], json!(r"C:\apps"));
        assert_eq!(entry["env"]["RT_PASSWORD"], "REPLACE_WITH_THE_PASSWORD");
        assert!(value["servers"]["书房的-工作站"].is_object());
        // A pinned profile needs no fingerprint note, only the password hint.
        assert_eq!(snippet.notes.len(), 1, "{:?}", snippet.notes);
    }

    #[test]
    fn snippet_names_a_missing_pin() {
        let mut cfg = rt_core::config::Config::default();
        cfg.client.hosts.push(rt_core::config::HostConfig {
            name: "final".into(),
            host: "10.0.0.5".into(),
            port: 6000,
            fingerprint: None,
            username: "alice".into(),
            last_scope: None,
            last_connected: None,
            auto_connect: true,
        });
        let exe = std::path::Path::new(r"C:\apps\remote-terminal.exe");
        let snippet = config_snippet(&cfg, Some("final"), exe, None).expect("snippet");
        assert!(
            snippet.notes.iter().any(|n| n.contains("fingerprint")),
            "{:?}",
            snippet.notes
        );
    }

    #[test]
    fn snippet_explains_what_to_do_without_any_host() {
        let cfg = rt_core::config::Config::default();
        let err = config_snippet(&cfg, None, std::path::Path::new("rt.exe"), None).expect_err("no host");
        assert!(err.contains("--save"), "{err}");
    }
}
