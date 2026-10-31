//! Unified error envelope used by every REST/WS response.

use serde::{Deserialize, Serialize};

/// Machine-readable error taxonomy. The HTTP status is derived from this, so
/// clients can branch on a stable string instead of parsing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    RangeNotSatisfiable,
    /// Malformed, unparsable or unsafe path.
    InvalidPath,
    /// Path resolves outside the session's jail.
    ScopeViolation,
    /// Operation is legal but denied by policy (e.g. read-only config).
    PolicyDenied,
    Timeout,
    RateLimited,
    Locked,
    Unavailable,
    NotImplemented,
    Internal,
}

impl ErrorCode {
    pub fn http_status(&self) -> u16 {
        use ErrorCode::*;
        match self {
            BadRequest | InvalidPath => 400,
            Unauthorized => 401,
            Forbidden | ScopeViolation | PolicyDenied => 403,
            NotFound => 404,
            Conflict | Locked => 409,
            PayloadTooLarge => 413,
            UnsupportedMediaType => 415,
            RangeNotSatisfiable => 416,
            RateLimited => 429,
            Timeout => 504,
            Unavailable => 503,
            NotImplemented => 501,
            Internal => 500,
        }
    }

    pub fn as_str(&self) -> &'static str {
        use ErrorCode::*;
        match self {
            BadRequest => "bad_request",
            Unauthorized => "unauthorized",
            Forbidden => "forbidden",
            NotFound => "not_found",
            Conflict => "conflict",
            PayloadTooLarge => "payload_too_large",
            UnsupportedMediaType => "unsupported_media_type",
            RangeNotSatisfiable => "range_not_satisfiable",
            InvalidPath => "invalid_path",
            ScopeViolation => "scope_violation",
            PolicyDenied => "policy_denied",
            Timeout => "timeout",
            RateLimited => "rate_limited",
            Locked => "locked",
            Unavailable => "unavailable",
            NotImplemented => "not_implemented",
            Internal => "internal",
        }
    }
}

/// Inner error payload (`{"error": { ... }}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// How long a rate-limited caller should wait.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

/// Outer envelope, so the wire shape is stable and extensible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: ApiErrorDetail,
}

impl ApiErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ApiErrorDetail {
                code,
                message: message.into(),
                detail: None,
                request_id: None,
                retry_after_secs: None,
            },
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.error.detail = Some(detail);
        self
    }

    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.error.request_id = Some(id.into());
        self
    }

    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.error.retry_after_secs = Some(secs);
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.error.code
    }

    pub fn status(&self) -> u16 {
        self.error.code.http_status()
    }
}

/// Convenience alias for handler results.
pub type ApiResult<T> = Result<T, ApiErrorBody>;

/// Generic acknowledgement returned by mutating endpoints that have nothing to say.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Ack {
    pub fn ok() -> Self {
        Self {
            ok: true,
            message: None,
        }
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: Some(msg.into()),
        }
    }
}
