//! Filesystem operations, always mediated by a [`PathGuard`].
//!
//! Every public function resolves the caller-supplied *virtual* path through the
//! guard first, so a workspace-scoped session physically cannot name a path
//! outside its jail, and a full-access session still cannot use UNC, device
//! names, alternate data streams or symlink escapes.
//!
//! The public signatures below are the frozen contract used by `rt-server`,
//! `rt-client` and the GUI; add private helpers freely, but do not rename or
//! reshape these without updating the callers.
//!
//! Conventions used throughout:
//! * every path that leaves this module goes through [`PathGuard::display`], so
//!   a jailed session always sees `\a\b.txt` and a full session an absolute path;
//! * every filesystem walk uses `symlink_metadata` / a non-following traversal,
//!   so a junction or symlink can never be used to step outside the jail;
//! * mutations that need to be crash-safe write a sibling temporary file, sync
//!   it and then rename it over the target.

use std::io::Read;
use std::path::{Path, PathBuf};

use rt_protocol::{
    CopyRequest, DeleteRequest, DeleteResult, FsEntry, FsRoots, ListDirResponse, MkdirRequest,
    QuickPath, ReadFileResult, RenameRequest, StatResponse, WriteResult,
};

use crate::error::{Result, RtError};
use crate::pathscope::{self, PathGuard};
use crate::util;

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

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Real (unextended) path -> what `std::fs` should actually be handed.
///
/// [`PathGuard::resolve`] strips the `\\?\` prefix so client-visible strings stay
/// clean; paths near `MAX_PATH` need it back before touching the filesystem.
fn io_path(real: &Path) -> PathBuf {
    pathscope::to_extended(real)
}

/// Attaches the *real* path to an io error so logs and clients can act on it.
fn io_err(real: &Path, err: std::io::Error) -> RtError {
    RtError::io(real.to_path_buf(), err)
}

/// Best client-facing name for a path (the leaf, or the path itself for roots).
fn name_of(guard: &PathGuard, real: &Path) -> String {
    real.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| guard.display(real))
}

fn entry_from_meta(
    guard: &PathGuard,
    real: &Path,
    name: String,
    meta: &std::fs::Metadata,
) -> FsEntry {
    let attrs = util::file_attributes(meta);
    FsEntry {
        name,
        path: guard.display(real),
        is_dir: meta.is_dir(),
        is_symlink: meta.file_type().is_symlink(),
        is_reparse_point: util::is_reparse_point(attrs),
        size: meta.len(),
        modified_ms: util::system_time_ms(meta.modified()),
        created_ms: util::system_time_ms(meta.created()),
        accessed_ms: util::system_time_ms(meta.accessed()),
        readonly: util::is_readonly(attrs),
        hidden: util::is_hidden(attrs),
        attributes: util::attribute_names(attrs),
        error: None,
    }
}

/// Entry built from `symlink_metadata`, i.e. links are described, not followed.
fn entry_for(guard: &PathGuard, real: &Path, name: String) -> Result<FsEntry> {
    let meta = std::fs::symlink_metadata(io_path(real)).map_err(|e| io_err(real, e))?;
    Ok(entry_from_meta(guard, real, name, &meta))
}

/// Placeholder for a directory child whose metadata could not be read: the name
/// stays visible so the listing remains complete, and the reason travels in
/// `error` instead of failing the whole request.
fn failed_entry(guard: &PathGuard, real: &Path, name: String, err: &RtError) -> FsEntry {
    FsEntry {
        name,
        path: guard.display(real),
        is_dir: false,
        is_symlink: false,
        is_reparse_point: false,
        size: 0,
        modified_ms: None,
        created_ms: None,
        accessed_ms: None,
        readonly: false,
        hidden: false,
        attributes: Vec::new(),
        error: Some(err.to_string()),
    }
}

/// Free/total bytes of the volume holding `real`, straight from the Win32 API.
///
/// `sysinfo`'s disk list is a snapshot refreshed on demand and reports mount
/// points rather than the volume under an arbitrary path, so it is not usable
/// here.
#[cfg(windows)]
fn volume_space(real: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            directory_name: *const u16,
            free_bytes_available_to_caller: *mut u64,
            total_number_of_bytes: *mut u64,
            total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    // The API takes a directory on the volume; for a file use its parent.
    let target = if real.is_dir() {
        real.to_path_buf()
    } else {
        real.parent()?.to_path_buf()
    };
    let mut wide: Vec<u16> = io_path(&target).as_os_str().encode_wide().collect();
    wide.push(0);

    let mut available_to_caller = 0u64;
    let mut total_bytes = 0u64;
    let mut total_free_bytes = 0u64;
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call and
    // all three out-pointers reference initialised, distinct `u64` locals.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available_to_caller,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };
    if ok == 0 {
        return None;
    }
    let free = if total_free_bytes > 0 {
        total_free_bytes
    } else {
        available_to_caller
    };
    Some((total_bytes, free))
}

#[cfg(not(windows))]
fn volume_space(_real: &Path) -> Option<(u64, u64)> {
    None
}

// ---------------------------------------------------------------------------
// Browsing
// ---------------------------------------------------------------------------

/// Lists a directory: metadata per child, sorted directories-first then by name.
pub fn list(guard: &PathGuard, path: &str, limits: &FsLimits) -> Result<ListDirResponse> {
    let real = guard.resolve(path)?;
    let io_real = io_path(&real);
    let meta = std::fs::symlink_metadata(&io_real).map_err(|e| io_err(&real, e))?;
    if !meta.is_dir() {
        return Err(RtError::BadRequest(format!(
            "`{}` is not a directory",
            guard.display(&real)
        )));
    }

    let reader = std::fs::read_dir(&io_real).map_err(|e| io_err(&real, e))?;
    let mut entries: Vec<FsEntry> = Vec::new();
    let mut total: u64 = 0;
    let mut truncated = false;

    for item in reader {
        total += 1;
        let item = match item {
            Ok(item) => item,
            Err(err) => {
                // A directory entry we cannot even name is not actionable; the
                // rest of the listing still matters, so skip it.
                tracing::debug!(
                    target: "fsops",
                    path = %real.display(),
                    error = %err,
                    "skipping unreadable directory entry"
                );
                continue;
            }
        };
        if entries.len() >= limits.max_list_entries {
            truncated = true;
            continue;
        }
        let name_os = item.file_name();
        let name = name_os.to_string_lossy().into_owned();
        let child = real.join(&name_os);
        match std::fs::symlink_metadata(io_path(&child)) {
            Ok(meta) => entries.push(entry_from_meta(guard, &child, name, &meta)),
            Err(err) => entries.push(failed_entry(
                guard,
                &child,
                name,
                &RtError::io(child.clone(), err),
            )),
        }
    }

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });

    let is_guard_root = guard
        .root()
        .map(|root| pathscope::path_eq(&real, root))
        .unwrap_or(false);
    let parent = if is_guard_root {
        None
    } else {
        real.parent().map(|p| guard.display(p))
    };

    Ok(ListDirResponse {
        path: guard.display(&real),
        parent,
        entries,
        truncated,
        scope: guard.scope(),
        total_entries: Some(total),
    })
}

/// Metadata for one path, plus free/total space on its volume.
pub fn stat(guard: &PathGuard, path: &str) -> Result<StatResponse> {
    let real = guard.resolve(path)?;
    let name = name_of(guard, &real);
    let entry = entry_for(guard, &real, name)?;
    let (volume_free_bytes, volume_total_bytes) = match volume_space(&real) {
        Some((total, free)) => (Some(free), Some(total)),
        None => (None, None),
    };
    Ok(StatResponse {
        entry,
        volume_free_bytes,
        volume_total_bytes,
    })
}

pub fn mkdir(guard: &PathGuard, req: &MkdirRequest) -> Result<FsEntry> {
    let real = guard.resolve(&req.path)?;
    let io_real = io_path(&real);
    let name = name_of(guard, &real);

    if let Ok(meta) = std::fs::symlink_metadata(&io_real) {
        if meta.is_dir() {
            if req.allow_existing {
                return Ok(entry_from_meta(guard, &real, name, &meta));
            }
            return Err(RtError::Conflict(format!(
                "directory `{}` already exists",
                guard.display(&real)
            )));
        }
        return Err(RtError::Conflict(format!(
            "`{}` already exists and is not a directory",
            guard.display(&real)
        )));
    }

    let outcome = if req.create_parents {
        std::fs::create_dir_all(&io_real)
    } else {
        std::fs::create_dir(&io_real)
    };
    match outcome {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost a race with a concurrent create: still fine for `mkdir -p`.
            if req.allow_existing {
                let meta = std::fs::symlink_metadata(&io_real).map_err(|e| io_err(&real, e))?;
                if meta.is_dir() {
                    return Ok(entry_from_meta(guard, &real, name, &meta));
                }
            }
            return Err(RtError::Conflict(format!(
                "`{}` already exists",
                guard.display(&real)
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(RtError::NotFound(format!(
                "parent of `{}` does not exist (set create_parents=true)",
                guard.display(&real)
            )))
        }
        Err(err) => return Err(io_err(&real, err)),
    }
    entry_for(guard, &real, name)
}

// ---------------------------------------------------------------------------
// Mutation (see later sections)
// ---------------------------------------------------------------------------

pub fn delete(_guard: &PathGuard, _req: &DeleteRequest) -> Result<DeleteResult> {
    todo("delete")
}

pub fn rename(_guard: &PathGuard, _req: &RenameRequest) -> Result<()> {
    todo("rename")
}

pub fn copy(_guard: &PathGuard, _req: &CopyRequest) -> Result<WriteResult> {
    todo("copy")
}

// ---------------------------------------------------------------------------
// Transfer (see later sections)
// ---------------------------------------------------------------------------

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
pub fn roots(guard: &PathGuard) -> Result<FsRoots> {
    match guard.root() {
        Some(root) => Ok(FsRoots {
            scope: guard.scope(),
            workspace_root: Some(guard.display(root)),
            drives: Vec::new(),
            quick_paths: quick_paths_inside(guard),
        }),
        None => {
            let drives = util::disks()
                .into_iter()
                .map(|disk| rt_protocol::FsDrive {
                    label: if disk.name.is_empty() || disk.name == disk.mount_point {
                        None
                    } else {
                        Some(disk.name)
                    },
                    path: disk.mount_point,
                    fs_type: disk.file_system,
                    total_bytes: disk.total_bytes,
                    free_bytes: disk.available_bytes,
                    removable: disk.removable,
                })
                .collect();
            Ok(FsRoots {
                scope: guard.scope(),
                workspace_root: None,
                drives,
                quick_paths: quick_paths_inside(guard),
            })
        }
    }
}

/// Quick paths that a session is actually allowed to open, in client-facing form.
fn quick_paths_inside(guard: &PathGuard) -> Vec<QuickPath> {
    util::quick_path_candidates()
        .into_iter()
        .filter_map(|(label, path, kind)| {
            let real = guard.resolve(&path.to_string_lossy()).ok()?;
            if !guard.is_inside(&real) {
                return None;
            }
            Some(QuickPath {
                label,
                path: guard.display(&real),
                kind,
            })
        })
        .collect()
}

/// Opens a file for range download: `(resolved path, file handle, size)`.
pub fn open_for_read(guard: &PathGuard, path: &str) -> Result<(PathBuf, std::fs::File, u64)> {
    let real = guard.resolve(path)?;
    let io_real = io_path(&real);
    // Follow the link on purpose: the guard already canonicalised the leaf, but
    // a full-scope path may still end in a link to a regular file.
    let meta = std::fs::metadata(&io_real).map_err(|e| io_err(&real, e))?;
    if meta.is_dir() {
        return Err(RtError::BadRequest(format!(
            "`{}` is a directory",
            guard.display(&real)
        )));
    }
    let file = std::fs::File::open(&io_real).map_err(|e| io_err(&real, e))?;
    Ok((real, file, meta.len()))
}

/// Resolves a client path to a real path (re-exported convenience).
pub fn resolve(guard: &PathGuard, path: &str) -> Result<PathBuf> {
    guard.resolve(path)
}

/// True when `path` exists and is a directory inside the guard.
pub fn is_existing_dir(guard: &PathGuard, path: &str) -> bool {
    match guard.resolve(path) {
        Ok(real) => std::fs::metadata(io_path(&real))
            .map(|meta| meta.is_dir())
            .unwrap_or(false),
        Err(_) => false,
    }
}
