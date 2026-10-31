//! MCP bridge — exposes every RemoteTerminal capability as a stdio tool server.
//!
//! `remote-terminal.exe mcp` starts a JSON-RPC 2.0 server on stdin/stdout, one
//! JSON message per line (the MCP stdio transport). Nothing else is ever written
//! to stdout: logs go to the log file and to stderr, so the harness can talk to
//! this process safely.
//!
//! ```json
//! { "command": "remote-terminal.exe", "args": ["mcp"],
//!   "env": { "RT_HOST": "192.168.1.10", "RT_PASSWORD": "..." } }
//! ```
//!
//! `RT_HOST` may include the port (`192.168.1.10:46666`), `RT_TOKEN` may carry an
//! API key instead of a password, and `RT_FINGERPRINT` pins the TLS certificate
//! (recommended: run `remote-terminal.exe fingerprint <host>:<port>` once).

pub mod tools;

use std::path::PathBuf;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

use tools::{Bridge, Endpoint};

const SERVER_NAME: &str = "remote-terminal";
const SUPPORTED_PROTOCOLS: &[&str] = &["2024-11-05", "2024-10-07", "2025-03-26", "2025-06-18"];

/// Runs the stdio bridge until stdin closes. Returns a process exit code.
pub async fn run(config_path: Option<PathBuf>) -> anyhow::Result<i32> {
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

    let endpoint = Endpoint::resolve(&loaded.config);
    tracing::info!(
        host = %endpoint.host,
        port = endpoint.port,
        tls = endpoint.tls,
        pinned = endpoint.fingerprint.is_some(),
        "MCP bridge endpoint resolved"
    );

    let mut state = McpState {
        endpoint,
        bridge: None,
        connect_error: None,
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

struct McpState {
    endpoint: Endpoint,
    bridge: Option<Bridge>,
    connect_error: Option<String>,
}

impl McpState {
    /// Lazily connects so a temporarily unreachable server does not stop the
    /// harness from starting; errors surface on the first tool call, and every
    /// later call retries.
    async fn ensure_bridge(&mut self) -> Result<&Bridge, String> {
        if self.bridge.is_none() {
            match Bridge::connect(self.endpoint.clone()).await {
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
    let text = serde_json::to_string_pretty(payload)
        .unwrap_or_else(|_| payload.to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
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
            bridge: None,
            connect_error: None,
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
        assert_eq!(tools.len(), 17);
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
}
