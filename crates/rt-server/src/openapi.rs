//! Hand-written OpenAPI 3.1 description of the HTTP API.
//!
//! The document lives in `openapi.json` next to this file and is parsed once.
//! It is intentionally a summary: every route, the security scheme and the
//! request/response shapes clients care about, without exhaustive schemas.

use std::sync::OnceLock;

use serde_json::{json, Value};

static DOCUMENT: OnceLock<Value> = OnceLock::new();

/// The full OpenAPI document, parsed once and cloned per request.
pub fn document() -> Value {
    DOCUMENT
        .get_or_init(|| match serde_json::from_str::<Value>(include_str!("openapi.json")) {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(target: "server", "bundled openapi.json is invalid: {err}");
                json!({
                    "openapi": "3.1.0",
                    "info": {
                        "title": "RemoteTerminal Server API",
                        "version": rt_protocol::APP_VERSION,
                    },
                    "paths": {},
                })
            }
        })
        .clone()
}
