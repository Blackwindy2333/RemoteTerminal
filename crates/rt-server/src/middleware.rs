//! HTTP plumbing: request ids, authentication, throttling, timeouts and the
//! single error representation every handler returns.
//!
//! Order (outermost first) matches `docs/ARCHITECTURE.md` §5:
//! `RequestId` → `Timeout` → `Trace` → `BodyLimit` (per route group) → `Auth`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::{ConnectInfo, MockConnectInfo};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rt_core::auth;
use rt_core::{RtError, SessionContext};
use rt_protocol::error::{ApiErrorBody, ErrorCode};

use crate::state::AppState;

/// Convenience alias so handlers read like `ApiResult<Json<T>>`.
pub(crate) type ApiResult<T> = std::result::Result<T, ApiErr>;

/// Correlation id for one request, echoed in error bodies and audit lines.
#[derive(Debug, Clone)]
pub(crate) struct ReqId(pub String);

/// Where the request came from (after optional `X-Forwarded-For` unwrapping).
#[derive(Debug, Clone)]
pub(crate) struct ClientInfo {
    pub addr: Option<SocketAddr>,
    pub ip: String,
}

impl ClientInfo {
    /// `host:port` when known, otherwise the bare IP — for audit records.
    pub(crate) fn remote(&self) -> String {
        match self.addr {
            Some(addr) => addr.to_string(),
            None => self.ip.clone(),
        }
    }
}

/// The bearer credential that authenticated this request (kept for logout).
#[derive(Debug, Clone)]
pub(crate) struct PresentedToken(pub String);

/// Handler error type: wraps the wire envelope so axum can render it.
#[derive(Debug, Clone)]
pub(crate) struct ApiErr(pub ApiErrorBody);

impl ApiErr {
    /// Builds an error from a code and a human-facing message.
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(ApiErrorBody::new(code, message))
    }

    /// Adds a retry hint for 429/409 style answers.
    pub(crate) fn with_retry_after(mut self, secs: u64) -> Self {
        self.0 = self.0.with_retry_after(secs);
        self
    }

    /// Adds the request correlation id.
    pub(crate) fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.0 = self.0.with_request_id(id);
        self
    }

    /// `400 bad_request`.
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    /// `403 forbidden`.
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    /// `404 not_found`.
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// `500 internal`.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// Human-facing message of this error, for audit lines.
    pub(crate) fn message(&self) -> &str {
        &self.0.error.message
    }

    /// Consumes the error into the wire-level detail websocket frames carry.
    pub(crate) fn into_detail(self) -> rt_protocol::error::ApiErrorDetail {
        self.0.error
    }

    /// HTTP status this error will be answered with.
    #[cfg(test)]
    pub(crate) fn status(&self) -> u16 {
        self.0.status()
    }
}

impl From<RtError> for ApiErr {
    fn from(err: RtError) -> Self {
        Self(err.into())
    }
}

impl From<ApiErrorBody> for ApiErr {
    fn from(body: ApiErrorBody) -> Self {
        Self(body)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        error_response(self.0)
    }
}

/// Renders an [`ApiErrorBody`] with the status its code implies.
pub(crate) fn error_response(body: ApiErrorBody) -> Response {
    let status = StatusCode::from_u16(body.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let retry_after = body.error.retry_after_secs;
    let unauthorized = status == StatusCode::UNAUTHORIZED;

    let mut response = (status, Json(body)).into_response();
    if let Some(secs) = retry_after {
        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    if unauthorized {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}


/// How long a request may wait for a free blocking worker before it is shed.
pub(crate) const BLOCKING_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Reserves one admission permit, or sheds the caller after the wait budget.
///
/// Long-lived blocking jobs (uploads, websocket streams) hold this permit for
/// their whole lifetime, so a slow client still counts against the budget
/// instead of occupying a worker invisibly.
pub(crate) async fn admit(
    slots: &std::sync::Arc<tokio::sync::Semaphore>,
) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
    match tokio::time::timeout(BLOCKING_ADMISSION_WAIT, slots.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(ApiErr::new(
            ErrorCode::Unavailable,
            "the server is shutting down",
        )),
        Err(_) => {
            tracing::warn!(target: "server", "shedding a request: every blocking worker is busy");
            Err(ApiErr::new(
                ErrorCode::Unavailable,
                "the server is busy; retry shortly",
            )
            .with_retry_after(1))
        }
    }
}

/// Runs blocking `rt-core` work while holding an admission permit.
///
/// The permit is reserved before the job is queued, so a burst of requests
/// cannot pile up behind a saturated blocking pool: past the wait budget the
/// request is shed with `503` and a retry hint instead of waiting forever.
pub(crate) async fn blocking_admitted<T, F>(
    slots: &std::sync::Arc<tokio::sync::Semaphore>,
    work: F,
) -> ApiResult<T>
where
    F: FnOnce() -> rt_core::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let permit = admit(slots).await?;
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.into()),
        Err(join) => Err(ApiErr::internal(format!("worker task failed: {join}"))),
    }
}


/// Applies headers that keep browsers from sniffing or framing our replies.
pub(crate) async fn security_headers_layer(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Converts an `RtError` into the WS error payload.
pub(crate) fn api_detail(err: RtError) -> rt_protocol::ApiErrorDetail {
    let body: ApiErrorBody = err.into();
    body.error
}

/// Paths reachable without credentials (architecture §5).
fn is_public(path: &str) -> bool {
    matches!(
        path,
        "/healthz" | "/api/v1/info" | "/api/v1/auth/login" | "/api/v1/openapi.json" | "/api/v1/ws"
    )
}

/// Long-lived endpoints: they own their lifecycle, so no request timeout.
fn is_streaming(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/ws" | "/api/v1/fs/download" | "/api/v1/fs/upload" | "/api/v1/fs/write"
    )
}

fn is_error_status(status: StatusCode) -> bool {
    status.is_client_error() || status.is_server_error()
}

/// Accepts a client-supplied correlation id only when it is obviously safe.
fn sanitise_request_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    let ok = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    ok.then(|| trimmed.to_string())
}

/// Generates/forwards a request id and stamps it on every error body.
pub(crate) async fn request_id_layer(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(sanitise_request_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    req.extensions_mut().insert(ReqId(id.clone()));

    let response = next.run(req).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false);

    let mut response = if is_error_status(status) && is_json {
        match patch_request_id(response, &id).await {
            Ok(patched) => patched,
            Err(original) => original,
        }
    } else {
        response
    };

    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// Injects `error.request_id` into an already-rendered error body.
async fn patch_request_id(response: Response, id: &str) -> Result<Response, Response> {
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        // Body too large / broken: leave the original untouched.
        Err(_) => return Err(Response::from_parts(parts, Body::empty())),
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Err(Response::from_parts(parts, Body::from(bytes))),
    };
    let Some(detail) = value.get_mut("error").and_then(|e| e.as_object_mut()) else {
        return Err(Response::from_parts(parts, Body::from(bytes)));
    };
    let needs_id = detail
        .get("request_id")
        .map(|v| v.is_null())
        .unwrap_or(true);
    if !needs_id {
        return Err(Response::from_parts(parts, Body::from(bytes)));
    }
    detail.insert(
        "request_id".to_string(),
        serde_json::Value::String(id.to_string()),
    );
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| bytes.to_vec());
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    Ok(Response::from_parts(parts, Body::from(body)))
}

/// Fails slow requests instead of leaking connections; streaming routes opt out.
pub(crate) async fn timeout_layer(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if is_streaming(req.uri().path()) {
        return next.run(req).await;
    }
    let limit = state.request_timeout();
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(response) => response,
        Err(_) => error_response(ApiErrorBody::new(
            ErrorCode::Timeout,
            format!("request exceeded {}s", limit.as_secs()),
        )),
    }
}

/// Authentication + per-IP admission control for every request.
pub(crate) async fn auth_layer(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .extensions()
        .get::<ReqId>()
        .map(|id| id.0.clone())
        .unwrap_or_default();
    let path = req.uri().path().to_string();
    let client = client_info(&req, state.cfg());
    let cfg = state.cfg();

    if !auth::ip_allowed(&cfg.server.ip_allowlist, &client.ip) {
        tracing::warn!(target: "server", remote = %client.ip, path = %path, "rejected by ip allow-list");
        return error_response(
            ApiErrorBody::new(ErrorCode::Forbidden, "client address is not allowed")
                .with_request_id(request_id),
        );
    }

    // `/healthz` is exempt so monitors cannot lock themselves out.
    if path != "/healthz" {
        if let Err(err) = state.rate_limiter().check(&client.ip) {
            return error_response(rt_protocol::ApiErrorBody::from(err).with_request_id(request_id));
        }
    }

    req.extensions_mut().insert(client.clone());

    if is_public(&path) {
        return next.run(req).await;
    }

    let Some(token) = bearer_token(req.headers()) else {
        return error_response(
            ApiErrorBody::new(ErrorCode::Unauthorized, "missing bearer token")
                .with_request_id(request_id),
        );
    };

    let mut ctx = match state.session_store().lookup(&token) {
        Some(session) => SessionContext::new(
            session.username,
            session.scope,
            session.auth_kind.as_str(),
        ),
        // API keys are read from the live credential snapshot so revoking one
        // in `config.toml` takes effect without a restart (SECURITY.md S-14).
        None => match auth::verify_api_key(&state.credentials().api_keys, &token) {
            Some((name, scope)) => SessionContext::new(name, scope, crate::state::AUTH_KIND_API_KEY),
            None => {
                return error_response(
                    ApiErrorBody::new(
                        ErrorCode::Unauthorized,
                        "invalid or expired credentials",
                    )
                    .with_request_id(request_id),
                )
            }
        },
    };
    ctx.request_id = request_id;
    // Audit records want `host:port`; the throttle bucket uses the bare IP.
    ctx.remote = Some(client.remote());
    req.extensions_mut().insert(ctx);
    req.extensions_mut().insert(PresentedToken(token));

    next.run(req).await
}

/// Extracts `<scheme> <token>` from `Authorization`, tolerating case.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    let value = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// Resolves the caller address once per request.
///
/// `X-Forwarded-For` is honoured only when the connection itself comes from a
/// loopback or private proxy, so a client behind an untrusted hop cannot forge
/// its own address into the allow-list, the throttles or the audit trail
/// (SECURITY.md S-11).
pub(crate) fn client_info(req: &Request, cfg: &rt_core::config::Config) -> ClientInfo {
    let addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
        .or_else(|| {
            req.extensions()
                .get::<MockConnectInfo<SocketAddr>>()
                .map(|info| info.0)
        });

    if cfg.server.trust_forwarded_for {
        if let Some(peer) = addr.map(|addr| addr.ip()) {
            if is_trusted_proxy(peer) {
                if let Some(ip) = forwarded_ip(req.headers()) {
                    return ClientInfo {
                        addr,
                        ip: auth::normalise_ip(&ip.to_string()),
                    };
                }
            } else if has_forwarded_header(req.headers()) {
                warn_untrusted_forwarded(peer);
            }
        }
    }

    let ip = match addr {
        Some(addr) => auth::normalise_ip(&addr.ip().to_string()),
        // Without connection info (unit tests, unusual transports) everything
        // shares one bucket; that is the safe direction for throttling.
        None => "unknown".to_string(),
    };
    ClientInfo { addr, ip }
}

/// Reverse proxies are expected to be local (loopback) or on a private hop.
fn is_trusted_proxy(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_private() || mapped.is_link_local();
            }
            // Unique local addresses fc00::/7.
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn has_forwarded_header(headers: &HeaderMap) -> bool {
    headers.contains_key("x-forwarded-for") || headers.contains_key("x-real-ip")
}

/// Warns at most once a minute per peer so spoofing attempts cannot flood logs.
fn warn_untrusted_forwarded(peer: IpAddr) {
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<(IpAddr, i64)>>> =
        std::sync::OnceLock::new();
    let slot = LAST.get_or_init(|| std::sync::Mutex::new(None));
    let now = rt_core::auth::now_ms();
    if let Ok(mut last) = slot.lock() {
        let repeated = matches!(*last, Some((ip, at)) if ip == peer && now - at < 60_000);
        if !repeated {
            *last = Some((peer, now));
            tracing::warn!(
                target: "server",
                peer = %peer,
                "ignoring x-forwarded-for from an untrusted peer"
            );
        }
    }
}

/// Stable, non-secret key for the per-session read budget.
pub(crate) fn budget_key(req: &Request, ctx: &SessionContext) -> String {
    match req.extensions().get::<PresentedToken>() {
        Some(token) => format!("token:{}", rt_core::crypto::sha256_hex(token.0.as_bytes())),
        None => format!("user:{}:{}", ctx.username, ctx.auth_kind),
    }
}

fn forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    for name in ["x-forwarded-for", "x-real-ip"] {
        let Some(raw) = headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        for candidate in raw.split(',') {
            let candidate = candidate.trim();
            if candidate.is_empty() {
                continue;
            }
            if let Ok(ip) = candidate.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Correlation id attached by [`request_id_layer`].
pub(crate) fn req_id(req: &Request) -> String {
    req.extensions()
        .get::<ReqId>()
        .map(|id| id.0.clone())
        .unwrap_or_default()
}

/// Caller identity attached by [`auth_layer`].
pub(crate) fn client_of(req: &Request) -> ClientInfo {
    req.extensions()
        .get::<ClientInfo>()
        .cloned()
        .unwrap_or(ClientInfo {
            addr: None,
            ip: "unknown".to_string(),
        })
}

/// Session attached by [`auth_layer`]; only reachable on protected routes.
pub(crate) fn session_of(req: &Request) -> ApiResult<SessionContext> {
    req.extensions()
        .get::<SessionContext>()
        .cloned()
        .ok_or_else(|| ApiErr::new(ErrorCode::Unauthorized, "authentication required"))
}

/// Rejects non-`Full` sessions, used by the logs/audit endpoints.
pub(crate) fn require_full_scope(ctx: &SessionContext, what: &str) -> ApiResult<()> {
    if ctx.scope.is_full() {
        Ok(())
    } else {
        Err(ApiErr::forbidden(format!(
            "{what} requires the full scope; this session is limited to the workspace"
        )))
    }
}

/// Query-string extractor that reports failures in the standard envelope.
pub(crate) struct ApiQuery<T>(pub T);

impl<T, S> axum::extract::FromRequestParts<S> for ApiQuery<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        axum::extract::Query::<T>::try_from_uri(&parts.uri)
            .map(|query| Self(query.0))
            .map_err(|err| ApiErr::bad_request(format!("invalid query string: {}", err.body_text())))
    }
}

/// Reads and decodes a JSON body, bounded by `limit` bytes.
pub(crate) async fn json_body<T: serde::de::DeserializeOwned>(
    req: Request,
    limit: usize,
) -> ApiResult<T> {
    if let Some(raw) = req.headers().get(header::CONTENT_TYPE) {
        let raw = raw.to_str().unwrap_or("");
        let base = raw.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if !base.is_empty()
            && base != "application/json"
            && base != "text/json"
            && !base.ends_with("+json")
        {
            return Err(ApiErr::new(
                ErrorCode::UnsupportedMediaType,
                format!("expected application/json, received {base}"),
            ));
        }
    }

    let bytes = axum::body::to_bytes(req.into_body(), limit)
        .await
        .map_err(|_| {
            ApiErr::new(
                ErrorCode::PayloadTooLarge,
                format!("request body exceeds {limit} bytes"),
            )
        })?;
    if bytes.is_empty() {
        return Err(ApiErr::bad_request("request body is empty"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|err| ApiErr::bad_request(format!("invalid JSON body: {err}")))
}

/// Router fallback for unknown paths.
pub(crate) async fn not_found_fallback() -> ApiErr {
    ApiErr::not_found("no such endpoint")
}

/// Router fallback for known paths called with the wrong method.
pub(crate) async fn method_not_allowed_fallback() -> Response {
    let body = ApiErrorBody::new(ErrorCode::BadRequest, "method not allowed for this endpoint");
    let mut response = (StatusCode::METHOD_NOT_ALLOWED, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
    response
}

/// Rejects requests whose `Host` or `Origin` do not belong to this server.
///
/// The bearer token is the real authority, but a browser on a malicious page
/// can still reach a loopback listener; checking the host defeats DNS
/// rebinding and checking the origin defeats cross-site websocket hijacking
/// (SECURITY.md S-10).
pub(crate) async fn origin_layer(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let request_id = req_id(&req);
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    let Some(raw_host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return error_response(
            ApiErrorBody::new(ErrorCode::BadRequest, "missing host header")
                .with_request_id(request_id),
        );
    };
    let Some(host) = normalise_host(raw_host) else {
        return error_response(
            ApiErrorBody::new(ErrorCode::BadRequest, "invalid host header")
                .with_request_id(request_id),
        );
    };
    if !host_allowed(&state, &host) {
        tracing::warn!(
            target: "server",
            host = %host,
            path = %path,
            "rejected a request for a host this server does not answer to"
        );
        return error_response(
            ApiErrorBody::new(ErrorCode::Forbidden, "request host is not allowed")
                .with_request_id(request_id),
        );
    }

    let expected_scheme = if state.cfg().server.tls {
        "https"
    } else {
        "http"
    };
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let allowed = origin_scheme_and_host(origin)
            .map(|(scheme, origin_host)| scheme == expected_scheme && origin_host == host)
            .unwrap_or(false);
        if !allowed {
            tracing::warn!(
                target: "server",
                origin = %origin,
                host = %host,
                path = %path,
                "rejected a cross-origin request"
            );
            return error_response(
                ApiErrorBody::new(ErrorCode::Forbidden, "cross-origin request rejected")
                    .with_request_id(request_id),
            );
        }
    } else if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|site| site.eq_ignore_ascii_case("cross-site"))
    {
        tracing::warn!(
            target: "server",
            host = %host,
            path = %path,
            "rejected a cross-site request without an origin header"
        );
        return error_response(
            ApiErrorBody::new(ErrorCode::Forbidden, "cross-origin request rejected")
                .with_request_id(request_id),
        );
    }

    next.run(req).await
}

/// Lower-cases a `host[:port]` (or `[ipv6]` / `[ipv6]:port`) value to a bare host.
fn normalise_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let host = if let Some(rest) = value.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally followed by a port.
        let end = rest.find(']')?;
        &rest[..end]
    } else if value.matches(':').count() == 1 {
        // Exactly one colon: a port separator. Bare IPv6 keeps every colon.
        value.split(':').next().unwrap_or(value)
    } else {
        value
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Splits an `Origin` header into its scheme and host.
fn origin_scheme_and_host(origin: &str) -> Option<(String, String)> {
    let (scheme, authority) = origin.trim().split_once("://")?;
    let authority = authority.split('/').next()?;
    Some((scheme.to_ascii_lowercase(), normalise_host(authority)?))
}

/// True when `host` is one of the names this server answers to.
fn host_allowed(state: &AppState, host: &str) -> bool {
    allowed_host_list(state).iter().any(|entry| entry == host)
}

/// Names and addresses this server answers to.
fn allowed_host_list(state: &AppState) -> Vec<String> {
    let mut hosts = vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "::1".to_string(),
    ];

    let machine = rt_core::util::hostname().to_ascii_lowercase();
    if !machine.is_empty() {
        if let Some((short, _)) = machine.split_once('.') {
            hosts.push(short.to_string());
        }
        hosts.push(machine);
    }

    let cfg = state.cfg();
    let display = cfg.server_display_name().trim().to_ascii_lowercase();
    if !display.is_empty() {
        hosts.push(display);
    }

    if let Some(host) = normalise_host(&cfg.server.bind) {
        hosts.push(host);
    }
    if let Some(addr) = state.runtime_addr() {
        let ip = addr.ip();
        if !ip.is_unspecified() {
            hosts.push(ip.to_string());
        }
    }
    if let Some(ip) = primary_local_ip() {
        hosts.push(ip.to_string());
    }

    // Host-shaped allow-list entries (`nas.local`, `mybox`) are extra names.
    for entry in &cfg.server.ip_allowlist {
        let entry = entry.trim();
        if entry.is_empty() || entry.parse::<IpAddr>().is_ok() {
            continue;
        }
        let Some(host) = normalise_host(entry) else {
            continue;
        };
        let host_shaped = host
            .chars()
            .any(|c| !(c.is_ascii_digit() || c == '.' || c == ':'));
        if host_shaped {
            hosts.push(host);
        }
    }

    hosts.retain(|host| !host.is_empty());
    hosts.dedup();
    hosts
}

/// Address of the interface that reaches the internet, used in the host allow-list.
///
/// Connecting a UDP socket sends no packets; it only asks the routing table.
fn primary_local_ip() -> Option<IpAddr> {
    static LOCAL_IP: std::sync::OnceLock<Option<IpAddr>> = std::sync::OnceLock::new();
    *LOCAL_IP.get_or_init(|| {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        socket.local_addr().ok().map(|addr| addr.ip())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admit_sheds_the_caller_when_every_slot_is_taken() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let held: Vec<_> = (0..2)
            .map(|_| slots.clone().try_acquire_owned().expect("free permit"))
            .collect();

        let started = std::time::Instant::now();
        let err = admit(&slots).await.expect_err("must shed");
        assert_eq!(err.status(), 503, "load shedding answers 503");
        assert!(
            started.elapsed() >= BLOCKING_ADMISSION_WAIT,
            "the caller waits for the budget before it is shed"
        );

        drop(held);
        assert!(admit(&slots).await.is_ok(), "the permit is released again");
    }

    #[tokio::test]
    async fn blocking_admitted_returns_the_work_result() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let value = blocking_admitted(&slots, || Ok(41 + 1)).await.expect("ran");
        assert_eq!(value, 42);
        // The permit is dropped when the job finishes.
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn blocking_admitted_reports_core_errors() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let err = blocking_admitted(&slots, || -> rt_core::Result<()> {
            Err(RtError::NotFound("nothing here".to_string()))
        })
        .await
        .expect_err("error surfaces");
        assert_eq!(err.status(), 404);
        assert_eq!(slots.available_permits(), 1);
    }
}
