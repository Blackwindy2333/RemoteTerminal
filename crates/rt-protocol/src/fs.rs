//! File-system wire types: browse, stat, mutate, transfer.

use serde::{Deserialize, Serialize};

use crate::Scope;

/// One directory entry / stat result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    pub name: String,
    /// Client-facing path (absolute on the server, or workspace-relative for
    /// jailed sessions — always usable as input to the other `fs` endpoints).
    pub path: String,
    pub is_dir: bool,
    #[serde(default)]
    pub is_symlink: bool,
    #[serde(default)]
    pub is_reparse_point: bool,
    #[serde(default)]
    pub size: u64,
    /// Unix epoch milliseconds (UTC) so clients need no timezone guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_ms: Option<i64>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub hidden: bool,
    /// Windows file attributes as human-readable names (`directory`, `archive`, …).
    #[serde(default)]
    pub attributes: Vec<String>,
    /// Present when the entry failed permission checks (`<name>` still listed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FsEntry {
    pub fn dir(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            is_dir: true,
            is_symlink: false,
            is_reparse_point: false,
            size: 0,
            modified_ms: None,
            created_ms: None,
            accessed_ms: None,
            readonly: false,
            hidden: false,
            attributes: vec!["directory".into()],
            error: None,
        }
    }
}

/// `GET /api/v1/fs/list`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirResponse {
    /// Echo of the resolved directory (use it as the new "current path").
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub entries: Vec<FsEntry>,
    /// True when `max_entries` cut the listing short.
    #[serde(default)]
    pub truncated: bool,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_entries: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub entry: FsEntry,
    /// Free bytes on the volume that holds the entry (None for pseudo paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_free_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_total_bytes: Option<u64>,
}

/// `POST /api/v1/fs/mkdir`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirRequest {
    pub path: String,
    #[serde(default)]
    pub create_parents: bool,
    /// `mkdir -p` semantics: succeed when the final component already exists.
    #[serde(default)]
    pub allow_existing: bool,
}

/// `POST /api/v1/fs/delete` — batch capable, which is what a GUI wants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub paths: Vec<String>,
    /// Required for directories that are not empty.
    #[serde(default)]
    pub recursive: bool,
    /// When false (default) a directory is only removed if empty.
    #[serde(default)]
    pub even_if_readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsOpFailure {
    pub path: String,
    pub code: crate::ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    pub deleted: Vec<String>,
    #[serde(default)]
    pub failed: Vec<FsOpFailure>,
}

/// `POST /api/v1/fs/rename` (also used for move-on-same-volume).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub overwrite: bool,
}

/// `POST /api/v1/fs/copy`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyRequest {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub recursive: bool,
}

/// Result of an upload or an in-place file write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResult {
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub overwritten: bool,
    pub duration_ms: u64,
}

/// JSON-friendly bounded read (used by MCP/tools and the GUI preview pane).
/// Binary-safe: `content_b64` is always base64; `text` is filled when the bytes
/// decode as text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileResult {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    /// Bytes actually returned in this response.
    pub returned: u64,
    pub truncated: bool,
    pub content_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Detected text encoding when `text` is present (`utf-8`, `gbk`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// True when the response stops at a line boundary cut.
    #[serde(default)]
    pub partial_line: bool,
}

/// Entry point listing for a session: what the UI should show first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsRoots {
    pub scope: Scope,
    /// Only for `workspace` scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub drives: Vec<FsDrive>,
    #[serde(default)]
    pub quick_paths: Vec<QuickPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDrive {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickPath {
    pub label: String,
    pub path: String,
    /// `home`, `desktop`, `downloads`, `temp`, `workspace`, …
    pub kind: String,
}
