//! Filesystem operations, always mediated by a [`PathGuard`].
//!
//! Every public function resolves the caller-supplied *virtual* path through the
//! guard first, so a workspace-scoped session physically cannot name a path
//! outside its jail, and a full-access session still cannot use UNC, device
//! names, alternate data streams or symlink escapes.
//!
//! STATUS: interface stub — bodies are implemented by the files module owner.
//! The public signatures below are the frozen contract used by `rt-server`,
//! `rt-client` and the GUI; add private helpers freely, but do not rename or
//! reshape these without updating the callers.

use std::io::Read;
use std::path::{Path, PathBuf};

use rt_protocol::{
    CopyRequest, DeleteRequest, DeleteResult, FsEntry, FsRoots, ListDirResponse, MkdirRequest,
    ReadFileResult, RenameRequest, StatResponse, WriteResult,
};

use crate::error::{Result, RtError};
use crate::pathscope::PathGuard;

/// Per-deployment ceilings, taken from `[server]` in the config file.
#[derive(Debug, Clone)]
pub struct FsLimits {
    pub max_list_entries: usize,
    pub max_read_bytes: u64,
    pub max_upload_bytes: u64,
}

impl Default for FsLimits {
    fn default() -> Self {
        Self {
            max_list_entries: 5000,
            max_read_bytes: 4 * 1024 * 1024,
            max_upload_bytes: 2048 * 1024 * 1024,
        }
    }
}

impl FsLimits {
    pub fn new(max_list_entries: usize, max_read_bytes: u64, max_upload_bytes: u64) -> Self {
        Self {
            max_list_entries,
            max_read_bytes,
            max_upload_bytes,
        }
    }
}

fn todo<T>(what: &str) -> Result<T> {
    Err(RtError::NotImplemented(format!("fsops::{what}")))
}

/// Lists a directory: metadata per child, sorted directories-first then by name.
pub fn list(_guard: &PathGuard, _path: &str, _limits: &FsLimits) -> Result<ListDirResponse> {
    todo("list")
}

/// Metadata for one path, plus free/total space on its volume.
pub fn stat(_guard: &PathGuard, _path: &str) -> Result<StatResponse> {
    todo("stat")
}

pub fn mkdir(_guard: &PathGuard, _req: &MkdirRequest) -> Result<FsEntry> {
    todo("mkdir")
}

pub fn delete(_guard: &PathGuard, _req: &DeleteRequest) -> Result<DeleteResult> {
    todo("delete")
}

pub fn rename(_guard: &PathGuard, _req: &RenameRequest) -> Result<()> {
    todo("rename")
}

pub fn copy(_guard: &PathGuard, _req: &CopyRequest) -> Result<WriteResult> {
    todo("copy")
}

/// Reads a byte range and returns it both base64-encoded and, when printable,
/// as text. `length == None` means "up to the limit".
pub fn read(
    _guard: &PathGuard,
    _path: &str,
    _offset: u64,
    _length: Option<u64>,
    _limits: &FsLimits,
) -> Result<ReadFileResult> {
    todo("read")
}

pub fn write(
    _guard: &PathGuard,
    _path: &str,
    _data: &[u8],
    _overwrite: bool,
    _create_parents: bool,
    _limits: &FsLimits,
) -> Result<WriteResult> {
    todo("write")
}

/// Streaming upload: never buffers the whole body, enforces `max_upload_bytes`.
pub fn write_stream<R: Read>(
    _guard: &PathGuard,
    _path: &str,
    _reader: R,
    _overwrite: bool,
    _create_parents: bool,
    _limits: &FsLimits,
) -> Result<WriteResult> {
    todo("write_stream")
}

/// Drive letters (full access) or the workspace root (jailed) plus quick paths.
pub fn roots(_guard: &PathGuard) -> Result<FsRoots> {
    todo("roots")
}

/// Opens a file for range download: `(resolved path, file handle, size)`.
pub fn open_for_read(_guard: &PathGuard, _path: &str) -> Result<(PathBuf, std::fs::File, u64)> {
    todo("open_for_read")
}

/// Resolves a client path to a real path (re-exported convenience).
pub fn resolve(_guard: &PathGuard, path: &str) -> Result<PathBuf> {
    _guard.resolve(path)
}

/// True when `path` exists and is a directory inside the guard.
pub fn is_existing_dir(_guard: &PathGuard, _path: &str) -> bool {
    false
}

#[allow(dead_code)]
fn unused(_p: &Path) {}
