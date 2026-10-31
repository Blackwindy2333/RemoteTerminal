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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use rt_protocol::{
    CopyRequest, DeleteRequest, DeleteResult, FsDrive, FsEntry, FsOpFailure, FsRoots,
    ListDirResponse, MkdirRequest, QuickPath, ReadFileResult, RenameRequest, StatResponse,
    WriteResult,
};
use sha2::{Digest, Sha256};

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
// Mutation
// ---------------------------------------------------------------------------

/// Deletes a batch of paths, reporting per-path failures instead of aborting.
///
/// The jail root and volume roots are never deletable, links are removed
/// without being entered (so they cannot smuggle the deletion outside the jail)
/// and a non-empty directory requires `recursive=true`.
pub fn delete(guard: &PathGuard, req: &DeleteRequest) -> Result<DeleteResult> {
    let mut deleted = Vec::new();
    let mut failed: Vec<FsOpFailure> = Vec::new();
    if req.paths.is_empty() {
        return Err(RtError::BadRequest("no paths given".into()));
    }
    for path in &req.paths {
        match delete_one(guard, path, req.recursive, req.even_if_readonly) {
            Ok(shown) => deleted.push(shown),
            Err(err) => failed.push(FsOpFailure {
                path: path.clone(),
                code: err.code(),
                message: err.to_string(),
            }),
        }
    }
    Ok(DeleteResult { deleted, failed })
}

fn delete_one(
    guard: &PathGuard,
    path: &str,
    recursive: bool,
    even_if_readonly: bool,
) -> Result<String> {
    let real = guard.resolve(path)?;
    ensure_deletable(guard, &real)?;
    let io_real = io_path(&real);
    let meta = std::fs::symlink_metadata(&io_real).map_err(|e| io_err(&real, e))?;
    let attrs = util::file_attributes(&meta);
    let is_link = meta.file_type().is_symlink() || util::is_reparse_point(attrs);

    if is_link {
        if even_if_readonly {
            let _ = util::clear_readonly(&io_real);
        }
        remove_link(&io_real).map_err(|e| io_err(&real, e))?;
        return Ok(guard.display(&real));
    }

    if meta.is_dir() {
        if !recursive {
            // Check emptiness ourselves: Windows reports "not empty" as a
            // generic error, which would surface as an opaque `internal_error`.
            let empty = {
                let mut reader = std::fs::read_dir(&io_real).map_err(|e| io_err(&real, e))?;
                reader.next().is_none()
            };
            if !empty {
                return Err(RtError::Conflict(format!(
                    "directory `{}` is not empty (set recursive=true)",
                    guard.display(&real)
                )));
            }
        } else {
            remove_children(&io_real, even_if_readonly)?;
        }
        if even_if_readonly {
            util::clear_readonly(&io_real)?;
        }
        std::fs::remove_dir(&io_real).map_err(|e| io_err(&real, e))?;
        return Ok(guard.display(&real));
    }

    if even_if_readonly {
        util::clear_readonly(&io_real)?;
    }
    std::fs::remove_file(&io_real).map_err(|e| io_err(&real, e))?;
    Ok(guard.display(&real))
}

/// Refuses deletions that would destroy the whole jail or a whole volume.
fn ensure_deletable(guard: &PathGuard, real: &Path) -> Result<()> {
    if let Some(root) = guard.root() {
        if pathscope::path_eq(real, root) {
            return Err(RtError::PolicyDenied(
                "refusing to delete the workspace root".into(),
            ));
        }
    }
    if real.parent().is_none() {
        return Err(RtError::PolicyDenied(format!(
            "refusing to delete volume root `{}`",
            guard.display(real)
        )));
    }
    Ok(())
}

/// Removes a link / junction itself; never descends into it.
fn remove_link(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(dir_err) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(_) => Err(dir_err),
        },
    }
}

/// Recursively deletes the *contents* of `dir`, without following links.
///
/// Links are unlinked as-is (removing the link, not its target), which is what
/// keeps a recursive delete from ever escaping the jail.
fn remove_children(dir: &Path, clear_ro: bool) -> Result<()> {
    let reader = std::fs::read_dir(dir).map_err(|e| io_err(dir, e))?;
    // Snapshot first: the enumeration handle must be closed before removing.
    let mut children: Vec<(PathBuf, std::fs::Metadata)> = Vec::new();
    for item in reader {
        let item = item.map_err(|e| io_err(dir, e))?;
        let child = item.path();
        let meta = std::fs::symlink_metadata(&child).map_err(|e| io_err(&child, e))?;
        children.push((child, meta));
    }
    for (child, meta) in children {
        let attrs = util::file_attributes(&meta);
        if meta.file_type().is_symlink() || util::is_reparse_point(attrs) {
            if clear_ro {
                let _ = util::clear_readonly(&child);
            }
            remove_link(&child).map_err(|e| io_err(&child, e))?;
        } else if meta.is_dir() {
            remove_children(&child, clear_ro)?;
            if clear_ro {
                util::clear_readonly(&child)?;
            }
            std::fs::remove_dir(&child).map_err(|e| io_err(&child, e))?;
        } else {
            if clear_ro {
                util::clear_readonly(&child)?;
            }
            std::fs::remove_file(&child).map_err(|e| io_err(&child, e))?;
        }
    }
    Ok(())
}

pub fn rename(guard: &PathGuard, req: &RenameRequest) -> Result<()> {
    let from = guard.resolve(&req.from)?;
    let to = guard.resolve(&req.to)?;
    if pathscope::path_eq(&from, &to) {
        // Same file (a case-only rename is indistinguishable after
        // canonicalisation); nothing to move.
        return Ok(());
    }
    let io_from = io_path(&from);
    let io_to = io_path(&to);
    let from_meta = std::fs::symlink_metadata(&io_from).map_err(|e| io_err(&from, e))?;

    if let Some(parent) = to.parent() {
        if !io_path(parent).is_dir() {
            return Err(RtError::NotFound(format!(
                "parent directory of `{}` does not exist",
                guard.display(&to)
            )));
        }
    }
    if from_meta.is_dir() && pathscope::path_starts_with(&to, &from) {
        return Err(RtError::BadRequest(format!(
            "cannot move `{}` into its own subtree (`{}`)",
            guard.display(&from),
            guard.display(&to)
        )));
    }

    if let Ok(to_meta) = std::fs::symlink_metadata(&io_to) {
        if !req.overwrite {
            return Err(RtError::Conflict(format!(
                "`{}` already exists (set overwrite=true)",
                guard.display(&to)
            )));
        }
        let to_attrs = util::file_attributes(&to_meta);
        if to_meta.file_type().is_symlink() || util::is_reparse_point(to_attrs) {
            remove_link(&io_to).map_err(|e| io_err(&to, e))?;
        } else if to_meta.is_dir() {
            // `MoveFileEx` replaces files but not directories, so the existing
            // directory has to go first.
            remove_children(&io_to, true)?;
            std::fs::remove_dir(&io_to).map_err(|e| io_err(&to, e))?;
        } else if util::is_readonly(to_attrs) {
            util::clear_readonly(&io_to)?;
        }
    }

    match std::fs::rename(&io_from, &io_to) {
        Ok(()) => Ok(()),
        // ERROR_NOT_SAME_DEVICE: a move is a copy+delete across volumes, which
        // this endpoint does not silently perform.
        Err(err) if err.raw_os_error() == Some(17) => Err(RtError::BadRequest(format!(
            "`{}` and `{}` are on different volumes; use copy instead",
            guard.display(&from),
            guard.display(&to)
        ))),
        Err(err) => Err(io_err(&from, err)),
    }
}

/// Ceiling for a single copy: one request must not be able to move a whole disk.
const COPY_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Ceiling for the number of entries a single copy may create.
const COPY_MAX_ENTRIES: u64 = 200_000;
/// Chunk size for streamed file copies (and for uploads, see [`write_stream`]).
const COPY_CHUNK: usize = 256 * 1024;

/// Copy ceilings; a separate struct so tests can inject tiny limits.
#[derive(Debug, Clone, Copy)]
struct CopyCaps {
    max_bytes: u64,
    max_entries: u64,
}

impl Default for CopyCaps {
    fn default() -> Self {
        Self {
            max_bytes: COPY_MAX_TOTAL_BYTES,
            max_entries: COPY_MAX_ENTRIES,
        }
    }
}

struct CopyState {
    bytes: u64,
    entries: u64,
    caps: CopyCaps,
}

impl CopyState {
    fn count_entry(&mut self) -> Result<()> {
        self.entries += 1;
        if self.entries > self.caps.max_entries {
            return Err(RtError::PayloadTooLarge(format!(
                "copy would create more than {} entries",
                self.caps.max_entries
            )));
        }
        Ok(())
    }
}

pub fn copy(guard: &PathGuard, req: &CopyRequest) -> Result<WriteResult> {
    copy_with_caps(guard, req, CopyCaps::default())
}

fn copy_with_caps(guard: &PathGuard, req: &CopyRequest, caps: CopyCaps) -> Result<WriteResult> {
    let started = Instant::now();
    let from = guard.resolve(&req.from)?;
    let to = guard.resolve(&req.to)?;
    if pathscope::path_eq(&from, &to) {
        return Err(RtError::BadRequest(format!(
            "`{}` is both source and destination",
            guard.display(&from)
        )));
    }
    if pathscope::path_starts_with(&to, &from) {
        return Err(RtError::BadRequest(format!(
            "cannot copy `{}` into its own subtree (`{}`)",
            guard.display(&from),
            guard.display(&to)
        )));
    }
    let io_from = io_path(&from);
    let io_to = io_path(&to);
    let from_meta = std::fs::symlink_metadata(&io_from).map_err(|e| io_err(&from, e))?;
    let from_is_dir = from_meta.is_dir();
    if let Some(parent) = to.parent() {
        if !io_path(parent).is_dir() {
            return Err(RtError::NotFound(format!(
                "parent directory of `{}` does not exist",
                guard.display(&to)
            )));
        }
    }

    let target_meta = std::fs::symlink_metadata(&io_to).ok();
    let overwritten = target_meta.is_some();
    let to_label = guard.display(&to);
    let mut state = CopyState {
        bytes: 0,
        entries: 0,
        caps,
    };

    if from_is_dir {
        if !req.recursive {
            return Err(RtError::BadRequest(format!(
                "`{}` is a directory (set recursive=true)",
                guard.display(&from)
            )));
        }
        if let Some(meta) = &target_meta {
            if !req.overwrite {
                return Err(RtError::Conflict(format!(
                    "`{to_label}` already exists (set overwrite=true)"
                )));
            }
            if !meta.is_dir() {
                return Err(RtError::Conflict(format!(
                    "`{to_label}` exists and is not a directory"
                )));
            }
        }
        copy_dir_tree(&io_from, &io_to, &to_label, req.overwrite, &mut state)?;
    } else {
        if let Some(meta) = &target_meta {
            if !req.overwrite {
                return Err(RtError::Conflict(format!(
                    "`{to_label}` already exists (set overwrite=true)"
                )));
            }
            if meta.is_dir() {
                return Err(RtError::Conflict(format!(
                    "`{to_label}` is a directory"
                )));
            }
        }
        let mut hasher = Sha256::new();
        copy_file(
            &io_from,
            &io_to,
            &to_label,
            req.overwrite,
            &mut state,
            Some(&mut hasher),
        )?;
        let digest = crate::crypto::hex_encode(&hasher.finalize());
        return Ok(WriteResult {
            path: to_label,
            size: state.bytes,
            sha256: Some(digest),
            overwritten,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    Ok(WriteResult {
        path: to_label,
        size: state.bytes,
        sha256: None,
        overwritten,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Copies one file through a fixed-size buffer, optionally hashing as it goes.
fn copy_file(
    from: &Path,
    to: &Path,
    to_label: &str,
    overwrite: bool,
    state: &mut CopyState,
    mut hasher: Option<&mut Sha256>,
) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(to) {
        if !overwrite {
            return Err(RtError::Conflict(format!(
                "`{to_label}` already exists (set overwrite=true)"
            )));
        }
        if meta.is_dir() {
            return Err(RtError::Conflict(format!(
                "`{to_label}` is a directory"
            )));
        }
        if util::is_readonly(util::file_attributes(&meta)) {
            util::clear_readonly(to)?;
        }
    }
    let mut source = std::fs::File::open(from).map_err(|e| io_err(from, e))?;
    let mut target = std::fs::File::create(to).map_err(|e| io_err(to, e))?;
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        let read = source.read(&mut buf).map_err(|e| io_err(from, e))?;
        if read == 0 {
            break;
        }
        state.bytes += read as u64;
        if state.bytes > state.caps.max_bytes {
            return Err(RtError::PayloadTooLarge(format!(
                "copy would move more than {} bytes in one request",
                state.caps.max_bytes
            )));
        }
        if let Some(hasher) = hasher.as_deref_mut() {
            hasher.update(&buf[..read]);
        }
        target
            .write_all(&buf[..read])
            .map_err(|e| io_err(to, e))?;
    }
    target.sync_all().map_err(|e| io_err(to, e))?;
    Ok(())
}

/// Recursively copies a directory tree (links are reported and skipped).
fn copy_dir_tree(
    from: &Path,
    to: &Path,
    to_label: &str,
    overwrite: bool,
    state: &mut CopyState,
) -> Result<()> {
    state.count_entry()?;
    match std::fs::symlink_metadata(to) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(RtError::Conflict(format!(
                "`{to_label}` exists and is not a directory"
            )))
        }
        Err(_) => std::fs::create_dir(to).map_err(|e| io_err(to, e))?,
    }

    let reader = std::fs::read_dir(from).map_err(|e| io_err(from, e))?;
    let mut children = Vec::new();
    for item in reader {
        let item = item.map_err(|e| io_err(from, e))?;
        children.push(item.path());
    }
    for child in children {
        let meta = std::fs::symlink_metadata(&child).map_err(|e| io_err(&child, e))?;
        let attrs = util::file_attributes(&meta);
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let target = to.join(&name);
        let target_label = format!("{to_label}\\{name}");
        if meta.file_type().is_symlink() || util::is_reparse_point(attrs) {
            // Re-creating a link needs privileges, and following one could read
            // outside the jail: report the skip instead of guessing.
            tracing::warn!(
                target: "fsops",
                entry = %child.display(),
                destination = %target_label,
                "skipping reparse point / symlink during recursive copy"
            );
            continue;
        }
        if meta.is_dir() {
            copy_dir_tree(&child, &target, &target_label, overwrite, state)?;
        } else {
            state.count_entry()?;
            copy_file(&child, &target, &target_label, overwrite, state, None)?;
        }
    }
    Ok(())
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
                .map(|disk| FsDrive {
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
