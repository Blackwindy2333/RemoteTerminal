//! Unified internal error type.
//!
//! Every layer returns [`RtError`]; the HTTP/WS boundary converts it once into
//! the wire envelope [`rt_protocol::ApiErrorBody`]. Keeping a single error type
//! means a handler never needs to know which module failed, and security
//! decisions (which code an IO error maps to) live in exactly one place.

use std::fmt;
use std::path::PathBuf;

use rt_protocol::{ApiErrorBody, ErrorCode};

pub type Result<T, E = RtError> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum RtError {
    /// IO failure with the path that produced it, so logs are actionable.
    Io {
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    /// Request is legal but outside the session's jail.
    ScopeViolation(String),
    /// Denied by configured policy (allow-list, disabled feature, …).
    PolicyDenied(String),
    Conflict(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
    RangeNotSatisfiable(String),
    InvalidPath(String),
    Timeout(String),
    RateLimited { message: String, retry_after_secs: u64 },
    Unavailable(String),
    NotImplemented(String),
    Config(String),
    Auth(String),
    Tls(String),
    /// Anything that is our bug rather than the caller's fault.
    Internal(String),
}

impl RtError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        RtError::Io {
            path: Some(path.into()),
            source,
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        RtError::Internal(msg.into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        RtError::BadRequest(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        RtError::NotFound(msg.into())
    }

    pub fn scope_violation(msg: impl Into<String>) -> Self {
        RtError::ScopeViolation(msg.into())
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            RtError::Io { source, .. } => match source.kind() {
                std::io::ErrorKind::NotFound => ErrorCode::NotFound,
                std::io::ErrorKind::PermissionDenied => ErrorCode::Forbidden,
                std::io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
                    ErrorCode::InvalidPath
                }
                std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
                _ => ErrorCode::Internal,
            },
            RtError::NotFound(_) => ErrorCode::NotFound,
            RtError::BadRequest(_) | RtError::Config(_) => ErrorCode::BadRequest,
            RtError::Unauthorized(_) | RtError::Auth(_) => ErrorCode::Unauthorized,
            RtError::Forbidden(_) => ErrorCode::Forbidden,
            RtError::ScopeViolation(_) => ErrorCode::ScopeViolation,
            RtError::PolicyDenied(_) => ErrorCode::PolicyDenied,
            RtError::Conflict(_) => ErrorCode::Conflict,
            RtError::PayloadTooLarge(_) => ErrorCode::PayloadTooLarge,
            RtError::UnsupportedMediaType(_) => ErrorCode::UnsupportedMediaType,
            RtError::RangeNotSatisfiable(_) => ErrorCode::RangeNotSatisfiable,
            RtError::InvalidPath(_) => ErrorCode::InvalidPath,
            RtError::Timeout(_) => ErrorCode::Timeout,
            RtError::RateLimited { .. } => ErrorCode::RateLimited,
            RtError::Unavailable(_) => ErrorCode::Unavailable,
            RtError::NotImplemented(_) => ErrorCode::NotImplemented,
            RtError::Tls(_) | RtError::Internal(_) => ErrorCode::Internal,
        }
    }

    /// Operator-facing message. Deliberately free of internal paths beyond what
    /// the caller already supplied, so error responses do not leak host layout
    /// more than necessary.
    pub fn public_message(&self) -> String {
        match self {
            RtError::Io { source, .. } => format!("I/O error: {source}"),
            RtError::RateLimited { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }
}

impl fmt::Display for RtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtError::Io {
                path: Some(path),
                source,
            } => write!(f, "I/O error at {}: {source}", path.display()),
            RtError::Io { path: None, source } => write!(f, "I/O error: {source}"),
            RtError::NotFound(m) => write!(f, "not found: {m}"),
            RtError::BadRequest(m) => write!(f, "bad request: {m}"),
            RtError::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            RtError::Forbidden(m) => write!(f, "forbidden: {m}"),
            RtError::ScopeViolation(m) => write!(f, "scope violation: {m}"),
            RtError::PolicyDenied(m) => write!(f, "denied by policy: {m}"),
            RtError::Conflict(m) => write!(f, "conflict: {m}"),
            RtError::PayloadTooLarge(m) => write!(f, "payload too large: {m}"),
            RtError::UnsupportedMediaType(m) => write!(f, "unsupported media type: {m}"),
            RtError::RangeNotSatisfiable(m) => write!(f, "range not satisfiable: {m}"),
            RtError::InvalidPath(m) => write!(f, "invalid path: {m}"),
            RtError::Timeout(m) => write!(f, "timeout: {m}"),
            RtError::RateLimited {
                message,
                retry_after_secs,
            } => write!(f, "rate limited: {message} (retry in {retry_after_secs}s)"),
            RtError::Unavailable(m) => write!(f, "unavailable: {m}"),
            RtError::NotImplemented(m) => write!(f, "not implemented: {m}"),
            RtError::Config(m) => write!(f, "config error: {m}"),
            RtError::Auth(m) => write!(f, "auth error: {m}"),
            RtError::Tls(m) => write!(f, "tls error: {m}"),
            RtError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for RtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RtError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RtError {
    fn from(source: std::io::Error) -> Self {
        RtError::Io { path: None, source }
    }
}

impl From<serde_json::Error> for RtError {
    fn from(err: serde_json::Error) -> Self {
        RtError::Internal(format!("json error: {err}"))
    }
}

impl From<rt_protocol::ApiErrorBody> for RtError {
    fn from(body: ApiErrorBody) -> Self {
        use ErrorCode::*;
        let msg = body.error.message.clone();
        match body.error.code {
            BadRequest => RtError::BadRequest(msg),
            Unauthorized => RtError::Unauthorized(msg),
            Forbidden => RtError::Forbidden(msg),
            NotFound => RtError::NotFound(msg),
            Conflict => RtError::Conflict(msg),
            PayloadTooLarge => RtError::PayloadTooLarge(msg),
            UnsupportedMediaType => RtError::UnsupportedMediaType(msg),
            RangeNotSatisfiable => RtError::RangeNotSatisfiable(msg),
            InvalidPath => RtError::InvalidPath(msg),
            ScopeViolation => RtError::ScopeViolation(msg),
            PolicyDenied => RtError::PolicyDenied(msg),
            Timeout => RtError::Timeout(msg),
            RateLimited => RtError::RateLimited {
                message: msg,
                retry_after_secs: body.error.retry_after_secs.unwrap_or(1),
            },
            Locked => RtError::Conflict(msg),
            Unavailable => RtError::Unavailable(msg),
            NotImplemented => RtError::NotImplemented(msg),
            Internal => RtError::Internal(msg),
        }
    }
}

impl From<RtError> for ApiErrorBody {
    fn from(err: RtError) -> Self {
        let code = err.code();
        let body = ApiErrorBody::new(code, err.public_message());
        match &err {
            RtError::RateLimited {
                retry_after_secs, ..
            } => body.with_retry_after(*retry_after_secs),
            _ => body,
        }
    }
}

/// Bridges `anyhow` at the few places where a generic error escapes a library
/// boundary (MCP loop, GUI task joins).
impl From<anyhow::Error> for RtError {
    fn from(err: anyhow::Error) -> Self {
        RtError::Internal(err.to_string())
    }
}
