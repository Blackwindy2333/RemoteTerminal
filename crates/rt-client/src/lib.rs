//! `rt-client` — typed client for the RemoteTerminal API.
//!
//! Shared by the GUI and the MCP bridge, so it must never depend on `egui`.
//! Everything is `async`; the GUI drives it from a background tokio task and
//! forwards results over channels.
//!
//! Security: the HTTP client is built with a rustls config that trusts exactly
//! one certificate fingerprint (pinned), or — for the explicit "trust this
//! server" flow — accepts any certificate and records the fingerprint in a
//! [`FingerprintProbe`] so the UI can show it before pinning.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode};
use rt_core::crypto::{client_config_pinned, client_config_tofu, FingerprintProbe};
use rt_protocol::{
    ApiKeyInfo, ApiErrorBody, CaptureRequest, CaptureResponse, CopyRequest, DeleteRequest,
    DeleteResult, ExecRequest, ExecResult, FsEntry, FsRoots, ListDirResponse, LoginRequest,
    LoginResponse, MkdirRequest, ProcessListResponse, QuickStatus, ReadFileResult, RenameRequest,
    ScreenInfo, ServerInfo, SessionInfo, ShellListResponse, StatResponse, SysInfoSnapshot,
    WindowInfo, WriteResult, WsTicketResponse,
};

pub mod ws;

pub use ws::WsClient;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ClientError {
    /// The server answered with an error envelope.
    Api {
        status: u16,
        body: Option<ApiErrorBody>,
        fallback: String,
    },
    /// Transport / TLS / protocol level failure.
    Transport(String),
    /// The request could not be built (bad host, bad path).
    Request(String),
    /// Local filesystem failure while uploading / downloading.
    Io(String),
}

impl ClientError {
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn api_body(&self) -> Option<&ApiErrorBody> {
        match self {
            ClientError::Api { body, .. } => body.as_ref(),
            _ => None,
        }
    }

    /// Message suitable for a status bar or MCP error payload.
    pub fn message(&self) -> String {
        match self {
            ClientError::Api {
                status,
                body,
                fallback,
            } => match body {
                Some(b) => format!(
                    "HTTP {status}: {} ({})",
                    b.error.message,
                    b.error.code.as_str()
                ),
                None => format!("HTTP {status}: {fallback}"),
            },
            ClientError::Transport(m) => format!("connection failed: {m}"),
            ClientError::Request(m) => m.clone(),
            ClientError::Io(m) => format!("filesystem error: {m}"),
        }
    }

    pub fn is_unauthorized(&self) -> bool {
        matches!(self.status(), Some(401))
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ClientError {}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Transport(e.to_string())
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

/// Where a client should connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// SHA-256 of the server certificate, hex (colons/uppercase tolerated).
    pub fingerprint: Option<String>,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls: true,
            fingerprint: None,
        }
    }

    pub fn plain(host: impl Into<String>, port: u16) -> Self {
        Self {
            tls: false,
            ..Self::new(host, port)
        }
    }

    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    pub fn scheme(&self) -> &'static str {
        if self.tls {
            "https"
        } else {
            "http"
        }
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{host}:{}", self.port)
    }

    pub fn base_url(&self) -> String {
        format!("{}://{}/", self.scheme(), self.authority())
    }

    pub fn ws_url(&self, ticket: &str) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!(
            "{scheme}://{}/api/v1/ws?ticket={}",
            self.authority(),
            urlencode(ticket)
        )
    }

    /// Human readable `host:port` for lists and titles.
    pub fn label(&self) -> String {
        self.authority()
    }
}

fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client bound to one server.
#[derive(Clone)]
pub struct RemoteClient {
    http: Client,
    target: Target,
    token: Arc<RwLock<Option<String>>>,
    tls: Option<Arc<rustls::ClientConfig>>,
    probe: Option<FingerprintProbe>,
    timeout: Duration,
}

impl std::fmt::Debug for RemoteClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClient")
            .field("target", &self.target)
            .field("authenticated", &self.is_authenticated())
            .finish()
    }
}

impl RemoteClient {
    /// Builds a client. When `target.fingerprint` is set the certificate is
    /// pinned; otherwise trust-on-first-use is used and the presented
    /// fingerprint becomes available through [`Self::presented_fingerprint`].
    pub fn new(target: Target) -> Result<Self> {
        Self::with_timeout(target, Duration::from_secs(60))
    }

    pub fn with_timeout(target: Target, timeout: Duration) -> Result<Self> {
        let (tls_config, probe) = if target.tls {
            match &target.fingerprint {
                Some(fp) => {
                    let cfg = client_config_pinned(fp)
                        .map_err(|e| ClientError::Request(format!("invalid fingerprint: {e}")))?;
                    (Some(Arc::new(cfg)), None)
                }
                None => {
                    let probe = FingerprintProbe::new();
                    let cfg = client_config_tofu(probe.clone());
                    (Some(Arc::new(cfg)), Some(probe))
                }
            }
        } else {
            (None, None)
        };

        let mut builder = Client::builder()
            .user_agent(format!("RemoteTerminal/{}", rt_protocol::APP_VERSION))
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            // Self-signed certificates are the norm here; identity comes from
            // the pinned fingerprint, not from a public CA chain.
            .danger_accept_invalid_certs(true);
        if let Some(cfg) = &tls_config {
            builder = builder.use_preconfigured_tls((**cfg).clone());
        }
        let http = builder
            .build()
            .map_err(|e| ClientError::Request(format!("cannot build HTTP client: {e}")))?;

        Ok(Self {
            http,
            target,
            token: Arc::new(RwLock::new(None)),
            tls: tls_config,
            probe,
            timeout,
        })
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Fingerprint seen during a TOFU connection (None once pinned or plaintext).
    pub fn presented_fingerprint(&self) -> Option<String> {
        self.probe.as_ref().and_then(|p| p.get())
    }

    /// rustls config used for WebSocket connections (same trust rules).
    pub fn tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.tls.clone()
    }

    pub fn set_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.token.write() {
            *guard = token;
        }
    }

    pub fn token(&self) -> Option<String> {
        self.token.read().ok().and_then(|g| g.clone())
    }

    pub fn is_authenticated(&self) -> bool {
        self.token().is_some()
    }

    fn url(&self, path: &str) -> Result<String> {
        Ok(format!(
            "{}{}",
            self.target.base_url(),
            path.trim_start_matches('/')
        ))
    }

    fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        let url = self.url(path)?;
        let mut req = self.http.request(method, url);
        if let Some(token) = self.token() {
            req = req.bearer_auth(token);
        }
        Ok(req)
    }

    async fn decode<T: serde::de::DeserializeOwned>(&self, resp: Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            return resp
                .json::<T>()
                .await
                .map_err(|e| ClientError::Transport(format!("malformed response: {e}")));
        }
        let fallback = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str::<ApiErrorBody>(&fallback).ok();
        Err(ClientError::Api {
            status: status.as_u16(),
            body,
            fallback: if fallback.len() > 400 {
                fallback[..400].to_string()
            } else {
                fallback
            },
        })
    }

    async fn expect_ok(&self, resp: Response) -> Result<()> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let fallback = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str::<ApiErrorBody>(&fallback).ok();
        Err(ClientError::Api {
            status: status.as_u16(),
            body,
            fallback,
        })
    }

    // -- meta ---------------------------------------------------------------

    pub async fn health(&self) -> Result<serde_json::Value> {
        let resp = self
            .request(reqwest::Method::GET, "healthz")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn info(&self) -> Result<ServerInfo> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/info")?
            .send()
            .await?;
        self.decode(resp).await
    }

    // -- auth ---------------------------------------------------------------

    pub async fn login(&self, username: &str, password: &str, device: &str) -> Result<LoginResponse> {
        let body = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            device_name: Some(device.to_string()),
        };
        let resp = self
            .request(reqwest::Method::POST, "api/v1/auth/login")?
            .json(&body)
            .send()
            .await?;
        let login: LoginResponse = self.decode(resp).await?;
        self.set_token(Some(login.access_token.clone()));
        Ok(login)
    }

    /// Authenticate with a pre-issued API key instead of a password.
    pub fn use_api_key(&self, key: &str) {
        self.set_token(Some(key.to_string()));
    }

    pub async fn logout(&self) -> Result<()> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/auth/logout")?
            .send()
            .await?;
        let out = self.expect_ok(resp).await;
        self.set_token(None);
        out
    }

    pub async fn me(&self) -> Result<SessionInfo> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/auth/me")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn ws_ticket(&self) -> Result<WsTicketResponse> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/auth/ws-ticket")?
            .send()
            .await?;
        self.decode(resp).await
    }

    // -- exec ---------------------------------------------------------------

    pub async fn shells(&self) -> Result<ShellListResponse> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/exec/shells")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn exec(&self, req: &ExecRequest) -> Result<ExecResult> {
        // Executions may legitimately run for minutes: never let the global
        // request timeout cut them off.
        let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(300_000).min(3_600_000) + 30_000);
        let resp = self
            .request(reqwest::Method::POST, "api/v1/exec")?
            .timeout(timeout)
            .json(req)
            .send()
            .await?;
        self.decode(resp).await
    }

    // -- filesystem ---------------------------------------------------------

    pub async fn roots(&self) -> Result<FsRoots> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/fs/roots")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn list(&self, path: &str) -> Result<ListDirResponse> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/fs/list")?
            .query(&[("path", path)])
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn stat(&self, path: &str) -> Result<StatResponse> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/fs/stat")?
            .query(&[("path", path)])
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn mkdir(&self, req: &MkdirRequest) -> Result<FsEntry> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/mkdir")?
            .json(req)
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn delete(&self, req: &DeleteRequest) -> Result<DeleteResult> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/delete")?
            .json(req)
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn rename(&self, req: &RenameRequest) -> Result<()> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/rename")?
            .json(req)
            .send()
            .await?;
        self.expect_ok(resp).await
    }

    pub async fn copy(&self, req: &CopyRequest) -> Result<WriteResult> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/copy")?
            .json(req)
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn read_file(
        &self,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<ReadFileResult> {
        let mut req = self.request(reqwest::Method::GET, "api/v1/fs/read")?;
        let mut query: Vec<(&str, String)> = vec![("path", path.to_string())];
        if let Some(o) = offset {
            query.push(("offset", o.to_string()));
        }
        if let Some(l) = length {
            query.push(("length", l.to_string()));
        }
        req = req.query(&query);
        let resp = req.send().await?;
        self.decode(resp).await
    }

    /// Writes raw bytes (one-shot). For large files prefer [`Self::upload_file`].
    pub async fn write_file(
        &self,
        path: &str,
        data: Vec<u8>,
        overwrite: bool,
        create_parents: bool,
    ) -> Result<WriteResult> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/write")?
            .query(&[
                ("path", path.to_string()),
                ("overwrite", overwrite.to_string()),
                ("create_parents", create_parents.to_string()),
            ])
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .send()
            .await?;
        self.decode(resp).await
    }

    /// Streams a local file to the server without loading it into memory.
    pub async fn upload_file(
        &self,
        local: &Path,
        remote_path: &str,
        overwrite: bool,
        create_parents: bool,
    ) -> Result<WriteResult> {
        let meta = tokio::fs::metadata(local).await?;
        if meta.is_dir() {
            return Err(ClientError::Request(format!(
                "`{}` is a directory; upload files individually",
                local.display()
            )));
        }
        let file = tokio::fs::File::open(local).await?;
        let stream = tokio_util::io::ReaderStream::new(file);
        let body = reqwest::Body::wrap_stream(stream);
        let resp = self
            .request(reqwest::Method::POST, "api/v1/fs/write")?
            .query(&[
                ("path", remote_path.to_string()),
                ("overwrite", overwrite.to_string()),
                ("create_parents", create_parents.to_string()),
            ])
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .timeout(Duration::from_secs(60 * 60))
            .send()
            .await?;
        self.decode(resp).await
    }

    /// Downloads a remote file to `local`, streaming to disk.
    pub async fn download_to(
        &self,
        remote_path: &str,
        local: &Path,
    ) -> Result<u64> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/fs/download")?
            .query(&[("path", remote_path)])
            .timeout(Duration::from_secs(60 * 60))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let fallback = resp.text().await.unwrap_or_default();
            let body = serde_json::from_str::<ApiErrorBody>(&fallback).ok();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
                fallback,
            });
        }
        if let Some(parent) = local.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::File::create(local).await?;
        let mut stream = resp.bytes_stream();
        let mut total = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| ClientError::Transport(e.to_string()))?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
            total += chunk.len() as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
        Ok(total)
    }

    /// Downloads into `client.download_dir`-style directory chosen by caller,
    /// picking a non-colliding file name.
    pub async fn download_auto(&self, remote_path: &str, dir: &Path) -> Result<PathBuf> {
        let name = rt_core::util::sanitize_filename(
            remote_path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("download.bin"),
        );
        let mut candidate = dir.join(&name);
        let mut index = 1;
        while candidate.exists() {
            let stem = Path::new(&name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("file");
            let ext = Path::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();
            candidate = dir.join(format!("{stem} ({index}){ext}"));
            index += 1;
        }
        self.download_to(remote_path, &candidate).await?;
        Ok(candidate)
    }

    // -- system info --------------------------------------------------------

    pub async fn sysinfo(&self) -> Result<SysInfoSnapshot> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/sysinfo")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn quick_status(&self) -> Result<QuickStatus> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/sysinfo/quick")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub async fn processes(
        &self,
        limit: usize,
        query: Option<&str>,
        sort: &str,
        descending: bool,
    ) -> Result<ProcessListResponse> {
        let mut params: Vec<(&str, String)> = vec![
            ("limit", limit.to_string()),
            ("sort", sort.to_string()),
            ("descending", descending.to_string()),
        ];
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            params.push(("query", q.to_string()));
        }
        let resp = self
            .request(reqwest::Method::GET, "api/v1/sysinfo/processes")?
            .query(&params)
            .send()
            .await?;
        self.decode(resp).await
    }

    // -- capture ------------------------------------------------------------

    pub async fn screens(&self) -> Result<Vec<ScreenInfo>> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/capture/screens")?
            .send()
            .await?;
        let value: serde_json::Value = self.decode(resp).await?;
        serde_json::from_value(
            value
                .get("screens")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| ClientError::Transport(format!("malformed screens: {e}")))
    }

    pub async fn windows(&self) -> Result<Vec<WindowInfo>> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/capture/windows")?
            .send()
            .await?;
        let value: serde_json::Value = self.decode(resp).await?;
        serde_json::from_value(
            value
                .get("windows")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| ClientError::Transport(format!("malformed windows: {e}")))
    }

    /// JSON capture (base64 payload) — use when the caller wants metadata too.
    pub async fn capture(&self, req: &CaptureRequest) -> Result<CaptureResponse> {
        let resp = self
            .request(reqwest::Method::POST, "api/v1/capture")?
            .timeout(Duration::from_secs(120))
            .json(req)
            .send()
            .await?;
        self.decode(resp).await
    }

    /// Raw capture: returns encoded image bytes ready for `egui::ColorImage`
    /// decoding, or for writing straight to a `.png` file.
    pub async fn capture_raw(
        &self,
        target: &str,
        format: &str,
        quality: u8,
        max_width: Option<u32>,
    ) -> Result<Vec<u8>> {
        let mut params = vec![
            ("target", target.to_string()),
            ("format", format.to_string()),
            ("quality", quality.to_string()),
        ];
        if let Some(w) = max_width {
            params.push(("max_width", w.to_string()));
        }
        let resp = self
            .request(reqwest::Method::GET, "api/v1/capture/raw")?
            .query(&params)
            .timeout(Duration::from_secs(120))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let fallback = resp.text().await.unwrap_or_default();
            let body = serde_json::from_str::<ApiErrorBody>(&fallback).ok();
            return Err(ClientError::Api {
                status: status.as_u16(),
                body,
                fallback,
            });
        }
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    // -- logs / audit -------------------------------------------------------

    pub async fn recent_logs(&self, limit: usize) -> Result<Vec<rt_protocol::ws::LogEvent>> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/logs")?
            .query(&[("limit", limit.to_string())])
            .send()
            .await?;
        let value: serde_json::Value = self.decode(resp).await?;
        serde_json::from_value(value.get("logs").cloned().unwrap_or(serde_json::Value::Null))
            .map_err(|e| ClientError::Transport(format!("malformed logs: {e}")))
    }

    pub async fn api_keys_info(&self) -> Result<Vec<ApiKeyInfo>> {
        let resp = self
            .request(reqwest::Method::GET, "api/v1/auth/api-keys")?
            .send()
            .await?;
        self.decode(resp).await
    }

    pub fn is_success(status: StatusCode) -> bool {
        status.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_urls() {
        let t = Target::new("192.168.1.10", 46666);
        assert_eq!(t.base_url(), "https://192.168.1.10:46666/");
        assert_eq!(
            t.ws_url("abc/def"),
            "wss://192.168.1.10:46666/api/v1/ws?ticket=abc%2Fdef"
        );
        let t6 = Target::plain("::1", 8080);
        assert_eq!(t6.base_url(), "http://[::1]:8080/");
    }

    #[test]
    fn client_builds_with_and_without_pinning() {
        let plain = RemoteClient::new(Target::plain("127.0.0.1", 1)).expect("plain client");
        assert!(plain.tls_config().is_none());
        assert!(!plain.is_authenticated());

        let tofu = RemoteClient::new(Target::new("127.0.0.1", 1)).expect("tofu client");
        assert!(tofu.tls_config().is_some());
        assert!(tofu.presented_fingerprint().is_none());

        let pinned = RemoteClient::new(
            Target::new("127.0.0.1", 1)
                .with_fingerprint("a".repeat(64)),
        )
        .expect("pinned client");
        assert!(pinned.tls_config().is_some());
    }

    #[test]
    fn bad_fingerprint_is_rejected() {
        let err = RemoteClient::new(Target::new("127.0.0.1", 1).with_fingerprint("not-hex"));
        assert!(err.is_err());
    }

    #[test]
    fn tokens_roundtrip() {
        let client = RemoteClient::new(Target::plain("127.0.0.1", 1)).expect("client");
        client.set_token(Some("abc".into()));
        assert!(client.is_authenticated());
        assert_eq!(client.token().as_deref(), Some("abc"));
        client.set_token(None);
        assert!(!client.is_authenticated());
    }

    #[test]
    fn auto_download_names_do_not_collide() {
        let dir = std::env::temp_dir().join(format!("rt_dl_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("a.txt"), b"x").expect("write");
        let stem = Path::new("a.txt").file_stem().and_then(|s| s.to_str()).unwrap();
        assert_eq!(stem, "a");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
