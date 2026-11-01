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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use rt_protocol::{
    CopyRequest, DeleteRequest, DeleteResult, FsDrive, FsEntry, FsOpFailure, FsRoots,
    ListDirResponse, MkdirRequest, OutputEncoding, QuickPath, ReadFileResult, RenameRequest,
    StatResponse, WriteResult,
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
// Destination capacity
// ---------------------------------------------------------------------------

/// Free headroom kept on the destination volume by every write and copy.
///
/// Without it a large upload could fill the disk and take the whole machine
/// (audit log included) down with it, well before the per-request upload limit
/// is reached.
const SPACE_RESERVE_BYTES: u64 = 256 * 1024 * 1024;

/// A streamed write re-checks the free space every this many bytes.
const SPACE_RECHECK_BYTES: u64 = 64 * 1024 * 1024;

/// Free bytes on the volume that holds `target`, straight from Win32.
fn free_bytes(target: &Path) -> Option<u64> {
    volume_space(target).map(|(_, free)| free)
}

/// Refuses a write when the destination volume cannot take `incoming` more
/// bytes while still keeping [`SPACE_RESERVE_BYTES`] free.
///
/// `incoming == None` means the length is unknown (a chunked upload): only the
/// reserve is required up front, and the stream then re-checks itself every
/// [`SPACE_RECHECK_BYTES`]. Volumes that cannot report their free space are
/// trusted, so the check never breaks a working setup.
fn ensure_capacity(target: &Path, incoming: Option<u64>, shown: &str) -> Result<()> {
    let Some(free) = free_bytes(target) else {
        return Ok(());
    };
    let need = match incoming {
        Some(size) => size.saturating_add(SPACE_RESERVE_BYTES),
        None => SPACE_RESERVE_BYTES,
    };
    if free >= need {
        return Ok(());
    }
    Err(RtError::PayloadTooLarge(format!(
        "not enough free space for `{shown}`: need {need} bytes ({SPACE_RESERVE_BYTES} byte reserve included), but only {free} bytes are free on the destination volume"
    )))
}

// ---------------------------------------------------------------------------
// Handle-level re-validation (path swapping)
// ---------------------------------------------------------------------------
//
// `PathGuard::resolve` canonicalises a path, but the caller then performs the
// I/O *by name*: a process that can write inside the jail can, during that
// window, replace a path component with a junction so the later syscall lands
// outside the jail. Remote clients cannot create links through this API
// (`write` creates plain files, `mkdir` plain directories, `copy` skips
// reparse points), so the attacker has to be a local low-privileged account —
// but the window is real (S-31 in `docs/SECURITY.md`).
//
// Every entry point that opens a handle therefore re-checks the *final* path
// the kernel reports for that handle (`GetFinalPathNameByHandleW`) against the
// jail root. `delete` cannot hold the handle it deletes through, so it re-runs
// the canonicalisation immediately before the syscall instead; the microseconds
// in between remain the documented residual window.

#[cfg(windows)]
mod winio {
    //! Minimal `CreateFileW` / `GetFinalPathNameByHandleW` wrapper.
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use crate::pathscope;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: isize,
        ) -> isize;
        fn GetFinalPathNameByHandleW(
            file: isize,
            file_path: *mut u16,
            file_path_len: u32,
            flags: u32,
        ) -> u32;
        fn CloseHandle(object: isize) -> i32;
    }

    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;    const SHARE_ALL: u32 = 0x0000_0007;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    /// Owns a kernel handle and closes it on drop.
    struct Handle(isize);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle is valid and owned by this value.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// NUL-terminated UTF-16 form of `path`.
    fn wide(path: &Path) -> Vec<u16> {
        let mut name: Vec<u16> = pathscope::to_extended(path)
            .as_os_str()
            .encode_wide()
            .collect();
        name.push(0);
        name
    }

    /// Opens attribute-only access, optionally through the last link.
    fn open(path: &Path, follow_links: bool) -> Option<Handle> {
        let name = wide(path);
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow_links {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the
        // call; the remaining arguments are plain constants and null pointers.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_READ_ATTRIBUTES,
                SHARE_ALL,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                0,
            )
        };
        if raw <= 0 || raw == INVALID_HANDLE_VALUE {
            return None;
        }
        Some(Handle(raw))
    }

    /// Final path the kernel associates with `raw`, without the `\\?\` prefix.
    fn final_path(raw: isize) -> Option<PathBuf> {
        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: `buffer` is a writable UTF-16 buffer of `buffer.len()`
            // elements and the handle is valid for the duration of the call.
            let len = unsafe {
                GetFinalPathNameByHandleW(raw, buffer.as_mut_ptr(), buffer.len() as u32, 0)
            } as usize;
            if len == 0 {
                return None;
            }
            if len < buffer.len() {
                let text = String::from_utf16_lossy(&buffer[..len]);
                return Some(pathscope::strip_extended_prefix(Path::new(&text)));
            }
            buffer.resize(len + 1, 0);
        }
    }

    /// Final path of `path`, or `None` when it cannot be opened.
    pub(super) fn real_path(path: &Path, follow_links: bool) -> Option<PathBuf> {
        let handle = open(path, follow_links)?;
        final_path(handle.0)
    }

    /// Final path of an already open file.
    pub(super) fn file_final_path(file: &std::fs::File) -> Option<PathBuf> {
        final_path(file.as_raw_handle() as isize)
    }
}

#[cfg(not(windows))]
mod winio {
    //! No-ops off Windows: the jail only exists on Windows.
    use std::path::{Path, PathBuf};

    pub(super) fn real_path(_path: &Path, _follow_links: bool) -> Option<PathBuf> {
        None
    }

    pub(super) fn file_final_path(_file: &std::fs::File) -> Option<PathBuf> {
        None
    }
}

/// Re-checks an already resolved path against the jail using a kernel handle.
///
/// `follow_links` must be `false` for entries whose links are about to be
/// removed as links (the handle then reports the link itself, not its target).
fn verify_entry(guard: &PathGuard, real: &Path, label: &str, follow_links: bool) -> Result<()> {
    if guard.root().is_none() {
        // Full scope has no jail: nothing to enforce here.
        return Ok(());
    }
    match winio::real_path(real, follow_links) {
        Some(actual) => verify_final_path(guard, &actual, label),
        // The entry cannot be opened (already gone, unsupported provider): fall
        // back to re-running the whole canonicalisation instead of giving up.
        None => revalidate(guard, real, label),
    }
}

/// Rejects a kernel-reported final path that sits outside the jail.
fn verify_final_path(guard: &PathGuard, actual: &Path, label: &str) -> Result<()> {
    match guard.root() {
        Some(root) if !pathscope::path_starts_with(actual, root) => {
            Err(RtError::PolicyDenied(format!(
                "refusing `{label}`: the entry now resolves to `{}`, outside the workspace root `{}` (a path component was swapped after validation)",
                actual.display(),
                root.display()
            )))
        }
        _ => Ok(()),
    }
}

/// Fallback for entries that cannot be opened: canonicalise the path again.
fn revalidate(guard: &PathGuard, real: &Path, label: &str) -> Result<()> {
    let again = guard.resolve(real.to_string_lossy().as_ref());
    match again {
        Ok(fresh) if pathscope::path_eq(&fresh, real) => Ok(()),
        _ => Err(RtError::PolicyDenied(format!(
            "refusing `{label}`: the path could not be re-verified inside the workspace"
        ))),
    }
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

/// Rejects a read-only entry unless the caller allowed clearing the attribute.
///
/// The check cannot be delegated to the OS: `std::fs::remove_file` clears
/// `FILE_ATTRIBUTE_READONLY` and retries on Windows, which would silently
/// discard the attribute and make `even_if_readonly` meaningless.
fn check_readonly(label: &str, attrs: u32, clear_ro: bool) -> Result<()> {
    if !clear_ro && util::is_readonly(attrs) {
        return Err(RtError::Forbidden(format!(
            "`{label}` is read-only (set even_if_readonly=true)"
        )));
    }
    Ok(())
}

fn delete_one(
    guard: &PathGuard,
    path: &str,
    recursive: bool,
    even_if_readonly: bool,
) -> Result<String> {
    let real = guard.resolve(path)?;
    // A directory that merely *contains* a control path resolves fine, but
    // deleting it would take `config.toml` (or the TLS key) with it.
    pathscope::check_protected_subtree(&real)?;
    ensure_deletable(guard, &real)?;
    // `delete` cannot hold the handle it removes through, so the entry is
    // re-verified immediately before each syscall; the residual window is the
    // microseconds in between (see the note on path swapping above).
    verify_entry(guard, &real, &guard.display(&real), false)?;
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
        check_readonly(&guard.display(&real), attrs, even_if_readonly)?;
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
            remove_children(guard, &io_real, even_if_readonly)?;
        }
        if even_if_readonly {
            util::clear_readonly(&io_real)?;
        }
        std::fs::remove_dir(&io_real).map_err(|e| io_err(&real, e))?;
        return Ok(guard.display(&real));
    }

    check_readonly(&guard.display(&real), attrs, even_if_readonly)?;
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
/// keeps a recursive delete from ever escaping the jail; every child is also
/// re-verified through a handle before it is removed.
fn remove_children(guard: &PathGuard, dir: &Path, clear_ro: bool) -> Result<()> {
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
        verify_entry(guard, &child, &child.display().to_string(), false)?;
        let attrs = util::file_attributes(&meta);
        if meta.file_type().is_symlink() || util::is_reparse_point(attrs) {
            if clear_ro {
                let _ = util::clear_readonly(&child);
            }
            remove_link(&child).map_err(|e| io_err(&child, e))?;
        } else if meta.is_dir() {
            check_readonly(&child.display().to_string(), attrs, clear_ro)?;
            remove_children(guard, &child, clear_ro)?;
            if clear_ro {
                util::clear_readonly(&child)?;
            }
            std::fs::remove_dir(&child).map_err(|e| io_err(&child, e))?;
        } else {
            check_readonly(&child.display().to_string(), attrs, clear_ro)?;
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
    // Moving a directory away would drag any control path inside it along.
    pathscope::check_protected_subtree(&from)?;
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
            remove_children(guard, &io_to, true)?;
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

/// Copies a file or (with `recursive`) a directory tree.
///
/// `overwrite` is honoured exactly, a directory may not be copied into its own
/// subtree, one request is capped by [`COPY_MAX_TOTAL_BYTES`] and
/// [`COPY_MAX_ENTRIES`], the destination volume must have room for the source
/// plus [`SPACE_RESERVE_BYTES`], and both ends are re-verified through handles
/// (see the note on path swapping above).
pub fn copy(guard: &PathGuard, req: &CopyRequest) -> Result<WriteResult> {
    copy_with_caps(guard, req, CopyCaps::default())
}

fn copy_with_caps(guard: &PathGuard, req: &CopyRequest, caps: CopyCaps) -> Result<WriteResult> {
    let started = Instant::now();
    let from = guard.resolve(&req.from)?;
    let to = guard.resolve(&req.to)?;
    // Copying a directory tree that holds a control path would duplicate
    // `config.toml` (password hashes) or the TLS private key somewhere the
    // session can read it.
    pathscope::check_protected_subtree(&from)?;
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
    // Estimate the demand on the destination volume before writing anything;
    // `copy_file` re-checks per file so a growing source cannot bypass it.
    let incoming = if from_is_dir {
        tree_bytes(&io_from, caps.max_bytes)?
    } else {
        from_meta.len()
    };
    ensure_capacity(&to, Some(incoming), &to_label)?;
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
        copy_dir_tree(
            guard,
            &io_from,
            &io_to,
            &to_label,
            req.overwrite,
            &mut state,
        )?;
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
            guard,
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
///
/// Both ends are re-verified through handles before a byte moves (see the note
/// on path swapping above) and the destination volume must have room for the
/// source plus the reserve.
fn copy_file(
    guard: &PathGuard,
    from: &Path,
    to: &Path,
    to_label: &str,
    overwrite: bool,
    state: &mut CopyState,
    mut hasher: Option<&mut Sha256>,
) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(to) {
        if meta.file_type().is_symlink() || util::is_reparse_point(util::file_attributes(&meta)) {
            // `File::create` would truncate the link's target, which may be
            // anywhere; refuse instead of writing through it.
            return Err(RtError::PolicyDenied(format!(
                "refusing to write through the link `{to_label}`"
            )));
        }
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
    if let Some(parent) = to.parent() {
        verify_entry(guard, parent, to_label, true)?;
    }
    let mut source = std::fs::File::open(from).map_err(|e| io_err(from, e))?;
    if let Some(actual) = winio::file_final_path(&source) {
        verify_final_path(guard, &actual, to_label)?;
    }
    let source_len = source.metadata().map(|meta| meta.len()).unwrap_or(0);
    ensure_capacity(to, Some(source_len), to_label)?;
    let mut target = std::fs::File::create(to).map_err(|e| io_err(to, e))?;
    if let Some(actual) = winio::file_final_path(&target) {
        verify_final_path(guard, &actual, to_label)?;
    }
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut written = 0u64;
    let mut next_space_check = SPACE_RECHECK_BYTES;
    // A copy that runs the destination volume dry halfway leaves a file that
    // looks complete but is not, so the partial destination is removed.
    let outcome = (|| -> Result<()> {
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
            written += read as u64;
            if written >= next_space_check {
                next_space_check = written + SPACE_RECHECK_BYTES;
                ensure_capacity(to, None, to_label)?;
            }
        }
        target.sync_all().map_err(|e| io_err(to, e))
    })();
    if let Err(err) = outcome {
        drop(target);
        let _ = std::fs::remove_file(to);
        return Err(err);
    }
    Ok(())
}

/// Recursively copies a directory tree (links are reported and skipped).
fn copy_dir_tree(
    guard: &PathGuard,
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
        Err(_) => {
            if let Some(parent) = to.parent() {
                verify_entry(guard, parent, to_label, true)?;
            }
            std::fs::create_dir(to).map_err(|e| io_err(to, e))?;
        }
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
            copy_dir_tree(guard, &child, &target, &target_label, overwrite, state)?;
        } else {
            state.count_entry()?;
            copy_file(
                guard,
                &child,
                &target,
                &target_label,
                overwrite,
                state,
                None,
            )?;
        }
    }
    Ok(())
}

/// Sums the regular-file bytes under `dir` (links skipped, like the copy).
///
/// Used only to size the destination-volume demand up front; the per-file loop
/// re-checks against the real free space.
fn tree_bytes(dir: &Path, limit: u64) -> Result<u64> {
    let mut total: u64 = 0;
    let reader = std::fs::read_dir(dir).map_err(|e| io_err(dir, e))?;
    for item in reader {
        let item = item.map_err(|e| io_err(dir, e))?;
        let child = item.path();
        let meta = std::fs::symlink_metadata(&child).map_err(|e| io_err(&child, e))?;
        if meta.file_type().is_symlink() || util::is_reparse_point(util::file_attributes(&meta)) {
            continue;
        }
        let size = if meta.is_dir() {
            tree_bytes(&child, limit)?
        } else {
            meta.len()
        };
        total = total.saturating_add(size);
        if total > limit {
            return Err(RtError::PayloadTooLarge(format!(
                "copy would move more than {limit} bytes in one request"
            )));
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

/// Reads a byte range and returns it base64-encoded plus decoded text.
///
/// `length == None` means "as much as the limit allows"; the result is always
/// capped by `limits.max_read_bytes`. The entry is re-verified through a
/// handle before reading (see the note on path swapping above).
pub fn read(
    guard: &PathGuard,
    path: &str,
    offset: u64,
    length: Option<u64>,
    limits: &FsLimits,
) -> Result<ReadFileResult> {
    let real = guard.resolve(path)?;
    let io_real = io_path(&real);
    let meta = std::fs::metadata(&io_real).map_err(|e| io_err(&real, e))?;
    if meta.is_dir() {
        return Err(RtError::BadRequest(format!(
            "`{}` is a directory",
            guard.display(&real)
        )));
    }
    let size = meta.len();
    if offset > size {
        return Err(RtError::BadRequest(format!(
            "offset {offset} is past the end of `{}` ({size} bytes)",
            guard.display(&real)
        )));
    }
    // Prove the bytes we are about to return still live inside the jail.
    verify_entry(guard, &real, &guard.display(&real), true)?;
    let budget = limits.max_read_bytes;
    let wanted = length.unwrap_or(budget).min(budget).min(size - offset);
    let bytes = if wanted == 0 {
        Vec::new()
    } else {
        util::read_file_range(&io_real, offset, wanted)?
    };
    // The file may have shrunk between the stat and the read.
    let returned = bytes.len() as u64;
    let truncated = offset + returned < size;
    // A cut that does not end on a line boundary leaves a dangling last line.
    let partial_line = truncated && bytes.last().is_some_and(|byte| *byte != b'\n');
    let (text, encoding) = if util::looks_binary(&bytes) {
        (None, None)
    } else {
        let (text, encoding) = util::decode_output(&bytes, OutputEncoding::Auto);
        (Some(text), Some(encoding))
    };
    Ok(ReadFileResult {
        path: guard.display(&real),
        size,
        offset,
        returned,
        truncated,
        content_b64: BASE64.encode(&bytes),
        text,
        encoding,
        partial_line,
    })
}

/// Writes a whole buffer; the atomic-staging and free-space rules of
/// [`write_stream`] apply, and the known length tightens the capacity check.
pub fn write(
    guard: &PathGuard,
    path: &str,
    data: &[u8],
    overwrite: bool,
    create_parents: bool,
    limits: &FsLimits,
) -> Result<WriteResult> {
    // A `&[u8]` is already a reader, so validation lives in one place only; the
    // declared length lets the capacity check run before a single byte moves.
    write_stream_impl(
        guard,
        path,
        data,
        overwrite,
        create_parents,
        limits,
        Some(data.len() as u64),
    )
}

/// Streaming upload: never buffers the whole body, enforces `max_upload_bytes`.
///
/// The body goes to a sibling temp file first (`sync_all`) and is then renamed
/// into place, so a crash or a mid-transfer failure never leaves a half-written
/// destination behind. The destination volume must keep [`SPACE_RESERVE_BYTES`]
/// free (checked up front and then every [`SPACE_RECHECK_BYTES`] of streamed
/// bytes), and the staged file's handle is re-verified against the jail — see
/// the note on path swapping above.
pub fn write_stream<R: Read>(
    guard: &PathGuard,
    path: &str,
    reader: R,
    overwrite: bool,
    create_parents: bool,
    limits: &FsLimits,
) -> Result<WriteResult> {
    write_stream_impl(
        guard,
        path,
        reader,
        overwrite,
        create_parents,
        limits,
        None,
    )
}

/// Shared body of [`write`] and [`write_stream`].
///
/// `declared` is the body length when the caller knows it (`write` always does,
/// a chunked upload may not); it only tightens the up-front capacity check,
/// while the streamed re-check protects the unknown-length case.
fn write_stream_impl<R: Read>(
    guard: &PathGuard,
    path: &str,
    mut reader: R,
    overwrite: bool,
    create_parents: bool,
    limits: &FsLimits,
    declared: Option<u64>,
) -> Result<WriteResult> {
    let started = Instant::now();
    let real = guard.resolve(path)?;
    let io_real = io_path(&real);
    let shown = guard.display(&real);

    match std::fs::symlink_metadata(&io_real) {
        Ok(meta) if meta.is_dir() => {
            return Err(RtError::BadRequest(format!("`{shown}` is a directory")))
        }
        Ok(_) => {
            if !overwrite {
                return Err(RtError::Conflict(format!(
                    "`{shown}` already exists (set overwrite=true)"
                )));
            }
        }
        Err(_) => {}
    }
    let overwritten = std::fs::symlink_metadata(&io_real).is_ok();

    if let Some(parent) = real.parent() {
        if create_parents {
            std::fs::create_dir_all(io_path(parent)).map_err(|e| io_err(parent, e))?;
        } else if !io_path(parent).is_dir() {
            return Err(RtError::NotFound(format!(
                "parent directory of `{shown}` does not exist (set create_parents=true)"
            )));
        }
    }

    // Refuse before spending the volume's headroom, then make sure the target
    // directory is still the one the guard validated.
    ensure_capacity(&real, declared, &shown)?;
    if let Some(parent) = real.parent() {
        verify_entry(guard, parent, &shown, true)?;
    }

    let tmp = temp_sibling(&real)?;
    let staged = spill_to_temp(
        guard,
        &tmp,
        &real,
        &shown,
        &mut reader,
        limits.max_upload_bytes,
    );
    let (size, sha256) = match staged {
        Ok(staged) => staged,
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
    };
    if let Err(err) = publish(guard, &tmp, &io_real, &real, &shown, overwritten) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(WriteResult {
        path: shown,
        size,
        sha256: Some(sha256),
        overwritten,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Sibling temp path (same volume, so the final rename is atomic).
fn temp_sibling(real: &Path) -> Result<PathBuf> {
    let name = real
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| RtError::BadRequest("cannot write to a filesystem root".into()))?;
    let temp_name = format!(".{name}.rt-{}.tmp", crate::crypto::random_token(8));
    Ok(match real.parent() {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    })
}

/// Streams `reader` into a fresh temp file, hashing as it goes.
///
/// The temp file is created next to the destination (`create_new`, so a planted
/// link cannot redirect it) and its handle is re-verified against the jail. The
/// free space is re-checked every [`SPACE_RECHECK_BYTES`], which stops a
/// chunked upload from eating the volume's headroom; the caller removes the
/// partial file on any error.
fn spill_to_temp<R: Read>(
    guard: &PathGuard,
    tmp: &Path,
    real: &Path,
    shown: &str,
    reader: &mut R,
    limit: u64,
) -> Result<(u64, String)> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .map_err(|e| io_err(tmp, e))?;
    if let Some(actual) = winio::file_final_path(&file) {
        verify_final_path(guard, &actual, shown)?;
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut total: u64 = 0;
    let mut next_space_check = SPACE_RECHECK_BYTES;
    loop {
        let read = reader.read(&mut buf).map_err(|e| io_err(tmp, e))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > limit {
            // Check before writing, so the temp file never exceeds the limit.
            return Err(RtError::PayloadTooLarge(format!(
                "upload exceeds the {limit} byte limit"
            )));
        }
        hasher.update(&buf[..read]);
        file.write_all(&buf[..read]).map_err(|e| io_err(tmp, e))?;
        if total >= next_space_check {
            ensure_capacity(real, None, shown)?;
            next_space_check = total.saturating_add(SPACE_RECHECK_BYTES);
        }
    }
    file.sync_all().map_err(|e| io_err(tmp, e))?;
    Ok((total, crate::crypto::hex_encode(&hasher.finalize())))
}

/// Moves the staged temp file onto the destination.
///
/// The destination directory is verified right before the rename (a swap during
/// a long upload is the remaining window) and the published file afterwards, so
/// an escaped write is reported instead of silently succeeding.
fn publish(
    guard: &PathGuard,
    tmp: &Path,
    target: &Path,
    real: &Path,
    shown: &str,
    overwritten: bool,
) -> Result<()> {
    if let Some(parent) = real.parent() {
        verify_entry(guard, parent, shown, true)?;
    }
    if overwritten {
        // `MoveFileEx` cannot replace a read-only file.
        if let Ok(meta) = std::fs::symlink_metadata(target) {
            if util::is_readonly(util::file_attributes(&meta)) {
                util::clear_readonly(target)?;
            }
        }
    }
    std::fs::rename(tmp, target).map_err(|e| io_err(target, e))?;
    if let Some(actual) = winio::real_path(real, true) {
        verify_final_path(guard, &actual, shown)?;
    }
    Ok(())
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
///
/// The handle's final path is re-checked against the jail (see the note on
/// path swapping above), so a link swapped in after `resolve` cannot turn a
/// download into an out-of-jail read.
pub fn open_for_read(guard: &PathGuard, path: &str) -> Result<(PathBuf, std::fs::File, u64)> {
    let real = guard.resolve(path)?;
    let io_real = io_path(&real);
    let shown = guard.display(&real);
    // Follow the link on purpose: the guard already canonicalised the leaf, but
    // a full-scope path may still end in a link to a regular file.
    let meta = std::fs::metadata(&io_real).map_err(|e| io_err(&real, e))?;
    if meta.is_dir() {
        return Err(RtError::BadRequest(format!("`{shown}` is a directory")));
    }
    let file = std::fs::File::open(&io_real).map_err(|e| io_err(&real, e))?;
    let verified = match winio::file_final_path(&file) {
        Some(actual) => {
            verify_final_path(guard, &actual, &shown)?;
            actual
        }
        None => {
            revalidate(guard, &real, &shown)?;
            real
        }
    };
    Ok((verified, file, meta.len()))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rt_protocol::{ErrorCode, Scope};
    use std::fs;
    use tempfile::TempDir;

    /// A fresh workspace jail rooted at an empty temp directory.
    fn workspace() -> (TempDir, PathGuard) {
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(Scope::Workspace, Some(dir.path())).expect("workspace guard");
        (dir, guard)
    }

    fn limits() -> FsLimits {
        FsLimits::default()
    }

    /// Creates `rel` (relative to the temp root) with the given bytes.
    fn put(dir: &TempDir, rel: &str, data: &[u8]) -> PathBuf {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&path, data).expect("write fixture");
        path
    }

    fn code(err: &RtError) -> ErrorCode {
        err.code()
    }

    fn assert_code<T: std::fmt::Debug>(result: Result<T>, expected: ErrorCode) {
        match result {
            Ok(value) => panic!("expected {expected:?}, got Ok({value:?})"),
            Err(err) => assert_eq!(code(&err), expected, "unexpected error: {err}"),
        }
    }

    /// Names of leftover staging files (a failed write must not leave any).
    fn temp_files(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|item| item.ok())
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    fn body(limit: usize) -> FsLimits {
        FsLimits::new(limit, limit as u64, limit as u64)
    }

    #[test]
    fn rejects_paths_outside_the_jail() {
        let (_dir, guard) = workspace();
        for escaped in ["..\\..\\x", "..\\x", "\\..\\..\\x", "sub\\..\\..\\..\\x"] {
            assert_code(list(&guard, escaped, &limits()), ErrorCode::ScopeViolation);
            assert_code(read(&guard, escaped, 0, None, &limits()), ErrorCode::ScopeViolation);
            assert_code(
                write(&guard, escaped, b"x", true, true, &limits()),
                ErrorCode::ScopeViolation,
            );
            let batch = delete(
                &guard,
                &DeleteRequest {
                    paths: vec![escaped.to_string()],
                    recursive: true,
                    even_if_readonly: true,
                },
            )
            .expect("delete reports failures per path");
            assert_eq!(batch.failed.len(), 1, "{escaped} must not be deletable");
            assert_eq!(batch.failed[0].code, ErrorCode::ScopeViolation);
        }
        // An absolute path outside the workspace root is just as unacceptable.
        assert_code(
            read(&guard, "C:\\Windows\\win.ini", 0, None, &limits()),
            ErrorCode::ScopeViolation,
        );
    }

    #[test]
    fn list_sorts_directories_first_and_reports_parent() {
        let (dir, guard) = workspace();
        put(&dir, "b.txt", b"b");
        put(&dir, "A.txt", b"a");
        fs::create_dir(dir.path().join("beta")).expect("dir");
        fs::create_dir(dir.path().join("Alpha")).expect("dir");

        let response = list(&guard, "\\", &limits()).expect("list root");
        assert_eq!(response.path, "\\");
        assert!(response.parent.is_none(), "root has no parent");
        let names: Vec<&str> = response.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "beta", "A.txt", "b.txt"]);
        assert!(response.entries[0].is_dir && response.entries[1].is_dir);
        assert_eq!(response.total_entries, Some(4));
        assert!(!response.truncated);
        assert_eq!(response.scope, Scope::Workspace);

        // Children report their display path and a parent pointer.
        let child = list(&guard, "\\beta", &limits()).expect("list child");
        assert_eq!(child.path, "\\beta");
        assert_eq!(child.parent.as_deref(), Some("\\"));
    }

    #[test]
    fn list_truncates_at_the_entry_limit() {
        let (dir, guard) = workspace();
        for name in ["a", "b", "c", "d"] {
            put(&dir, &format!("{name}.txt"), b"x");
        }
        let response = list(&guard, "\\", &body(2)).expect("list root");
        assert_eq!(response.entries.len(), 2);
        assert!(response.truncated);
        assert_eq!(response.total_entries, Some(4), "total counts all entries");
    }

    #[test]
    fn list_rejects_a_file_and_a_missing_directory() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"a");
        assert_code(list(&guard, "\\a.txt", &limits()), ErrorCode::BadRequest);
        assert_code(list(&guard, "\\nope", &limits()), ErrorCode::NotFound);
    }

    #[test]
    fn stat_reports_size_and_volume_space() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"hello");

        let response = stat(&guard, "\\a.txt").expect("stat file");
        assert_eq!(response.entry.name, "a.txt");
        assert_eq!(response.entry.path, "\\a.txt");
        assert!(!response.entry.is_dir);
        assert_eq!(response.entry.size, 5);
        assert!(response.entry.error.is_none());
        let total = response.volume_total_bytes.expect("volume total");
        let free = response.volume_free_bytes.expect("volume free");
        assert!(total > 0 && free <= total);

        let directory = stat(&guard, "\\").expect("stat root");
        assert!(directory.entry.is_dir);
        assert_code(stat(&guard, "\\missing"), ErrorCode::NotFound);
    }

    #[test]
    fn mkdir_honours_create_parents_and_allow_existing() {
        let (_dir, guard) = workspace();
        let request = |path: &str, parents: bool, existing: bool| MkdirRequest {
            path: path.to_string(),
            create_parents: parents,
            allow_existing: existing,
        };

        assert_code(
            mkdir(&guard, &request("\\a\\b", false, false)),
            ErrorCode::NotFound,
        );
        let created = mkdir(&guard, &request("\\a\\b", true, false)).expect("mkdir -p");
        assert!(created.is_dir);
        assert_eq!(created.path, "\\a\\b");
        assert_eq!(created.name, "b");

        // Idempotent only when the caller asked for it.
        assert_code(
            mkdir(&guard, &request("\\a\\b", true, false)),
            ErrorCode::Conflict,
        );
        let existing = mkdir(&guard, &request("\\a\\b", true, true)).expect("idempotent");
        assert_eq!(existing.path, "\\a\\b");

        // A file in the way is always a conflict.
        write(&guard, "\\file.txt", b"x", false, true, &limits()).expect("write");
        assert_code(
            mkdir(&guard, &request("\\file.txt", true, true)),
            ErrorCode::Conflict,
        );
    }

    #[test]
    fn delete_reports_per_path_failures() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"a");
        put(&dir, "keep.txt", b"k");

        let response = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\a.txt".into(), "\\missing.txt".into()],
                recursive: false,
                even_if_readonly: false,
            },
        )
        .expect("delete batch");
        assert_eq!(response.deleted, vec!["\\a.txt".to_string()]);
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].path, "\\missing.txt");
        assert_eq!(response.failed[0].code, ErrorCode::NotFound);
        assert!(dir.path().join("keep.txt").exists());
    }

    #[test]
    fn delete_requires_recursive_for_a_non_empty_directory() {
        let (dir, guard) = workspace();
        put(&dir, "tree\\a.txt", b"a");
        put(&dir, "tree\\sub\\b.txt", b"b");

        let response = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\tree".into()],
                recursive: false,
                even_if_readonly: false,
            },
        )
        .expect("delete batch");
        assert!(response.deleted.is_empty());
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].code, ErrorCode::Conflict);
        assert!(dir.path().join("tree\\a.txt").exists(), "nothing was removed");

        delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\tree".into()],
                recursive: true,
                even_if_readonly: false,
            },
        )
        .expect("recursive delete");
        assert!(!dir.path().join("tree").exists());
    }

    #[test]
    fn delete_touches_readonly_only_when_allowed() {
        let (dir, guard) = workspace();
        let path = put(&dir, "ro.txt", b"x");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).expect("set readonly");

        let response = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\ro.txt".into()],
                recursive: false,
                even_if_readonly: false,
            },
        )
        .expect("delete batch");
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].code, ErrorCode::Forbidden);
        assert!(path.exists());

        delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\ro.txt".into()],
                recursive: false,
                even_if_readonly: true,
            },
        )
        .expect("delete readonly");
        assert!(!path.exists());
    }

    #[test]
    fn delete_refuses_the_workspace_root() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"a");
        let response = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\".into()],
                recursive: true,
                even_if_readonly: true,
            },
        )
        .expect("delete batch");
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].code, ErrorCode::PolicyDenied);
        assert!(dir.path().exists());
    }

    #[test]
    fn rename_moves_and_respects_overwrite() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"one");
        put(&dir, "b.txt", b"two");

        rename(
            &guard,
            &RenameRequest {
                from: "\\a.txt".into(),
                to: "\\c.txt".into(),
                overwrite: false,
            },
        )
        .expect("rename to fresh name");
        assert!(!dir.path().join("a.txt").exists());
        assert_eq!(fs::read(dir.path().join("c.txt")).expect("read"), b"one");

        assert_code(
            rename(
                &guard,
                &RenameRequest {
                    from: "\\c.txt".into(),
                    to: "\\b.txt".into(),
                    overwrite: false,
                },
            ),
            ErrorCode::Conflict,
        );
        rename(
            &guard,
            &RenameRequest {
                from: "\\c.txt".into(),
                to: "\\b.txt".into(),
                overwrite: true,
            },
        )
        .expect("rename over existing");
        assert_eq!(fs::read(dir.path().join("b.txt")).expect("read"), b"one");

        assert_code(
            rename(
                &guard,
                &RenameRequest {
                    from: "\\b.txt".into(),
                    to: "\\nope\\b.txt".into(),
                    overwrite: true,
                },
            ),
            ErrorCode::NotFound,
        );
    }

    #[test]
    fn rename_refuses_to_nest_a_directory_in_itself() {
        let (dir, guard) = workspace();
        put(&dir, "tree\\a.txt", b"a");
        assert_code(
            rename(
                &guard,
                &RenameRequest {
                    from: "\\tree".into(),
                    to: "\\tree\\inner".into(),
                    overwrite: false,
                },
            ),
            ErrorCode::BadRequest,
        );
    }

    #[test]
    fn copy_file_hashes_and_respects_overwrite() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"hello");
        put(&dir, "b.txt", b"old");

        let first = copy(
            &guard,
            &CopyRequest {
                from: "\\a.txt".into(),
                to: "\\c.txt".into(),
                overwrite: false,
                recursive: false,
            },
        )
        .expect("copy file");
        assert_eq!(first.path, "\\c.txt");
        assert_eq!(first.size, 5);
        assert!(!first.overwritten);
        assert_eq!(fs::read(dir.path().join("c.txt")).expect("read"), b"hello");
        // sha256("hello")
        assert_eq!(
            first.sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );

        assert_code(
            copy(
                &guard,
                &CopyRequest {
                    from: "\\a.txt".into(),
                    to: "\\b.txt".into(),
                    overwrite: false,
                    recursive: false,
                },
            ),
            ErrorCode::Conflict,
        );
        let replaced = copy(
            &guard,
            &CopyRequest {
                from: "\\a.txt".into(),
                to: "\\b.txt".into(),
                overwrite: true,
                recursive: false,
            },
        )
        .expect("copy over existing");
        assert!(replaced.overwritten);
        assert_eq!(fs::read(dir.path().join("b.txt")).expect("read"), b"hello");
    }

    #[test]
    fn copy_directory_is_recursive_and_contained() {
        let (dir, guard) = workspace();
        put(&dir, "src\\one.txt", b"1");
        put(&dir, "src\\two.txt", b"22");
        put(&dir, "src\\nested\\three.txt", b"333");

        assert_code(
            copy(
                &guard,
                &CopyRequest {
                    from: "\\src".into(),
                    to: "\\dst".into(),
                    overwrite: false,
                    recursive: false,
                },
            ),
            ErrorCode::BadRequest,
        );

        let result = copy(
            &guard,
            &CopyRequest {
                from: "\\src".into(),
                to: "\\dst".into(),
                overwrite: false,
                recursive: true,
            },
        )
        .expect("copy tree");
        assert_eq!(result.size, 6, "1 + 2 + 3 bytes");
        assert!(result.sha256.is_none(), "a tree has no single digest");
        assert_eq!(fs::read(dir.path().join("dst\\one.txt")).expect("read"), b"1");
        assert_eq!(
            fs::read(dir.path().join("dst\\nested\\three.txt")).expect("read"),
            b"333"
        );

        // Copying over an existing tree without overwrite is a conflict.
        assert_code(
            copy(
                &guard,
                &CopyRequest {
                    from: "\\src".into(),
                    to: "\\dst".into(),
                    overwrite: false,
                    recursive: true,
                },
            ),
            ErrorCode::Conflict,
        );

        // A tree cannot be copied into its own subtree.
        assert_code(
            copy(
                &guard,
                &CopyRequest {
                    from: "\\src".into(),
                    to: "\\src\\inner".into(),
                    overwrite: false,
                    recursive: true,
                },
            ),
            ErrorCode::BadRequest,
        );
    }

    #[test]
    fn copy_enforces_byte_and_entry_caps() {
        let (dir, guard) = workspace();
        put(&dir, "big.bin", &vec![7u8; 64]);
        put(&dir, "tree\\a", b"1");
        put(&dir, "tree\\b", b"2");
        put(&dir, "tree\\c", b"3");

        let tight_bytes = CopyCaps {
            max_bytes: 8,
            max_entries: 100,
        };
        assert_code(
            copy_with_caps(
                &guard,
                &CopyRequest {
                    from: "\\big.bin".into(),
                    to: "\\copy.bin".into(),
                    overwrite: false,
                    recursive: false,
                },
                tight_bytes,
            ),
            ErrorCode::PayloadTooLarge,
        );

        let tight_entries = CopyCaps {
            max_bytes: 1024 * 1024,
            max_entries: 2,
        };
        assert_code(
            copy_with_caps(
                &guard,
                &CopyRequest {
                    from: "\\tree".into(),
                    to: "\\tree_copy".into(),
                    overwrite: false,
                    recursive: true,
                },
                tight_entries,
            ),
            ErrorCode::PayloadTooLarge,
        );
    }

    #[test]
    fn read_slices_bytes_and_flags_truncation() {
        let (dir, guard) = workspace();
        let content = b"hello\nworld\n";
        put(&dir, "a.txt", content);

        let whole = read(&guard, "\\a.txt", 0, None, &limits()).expect("read all");
        assert_eq!(whole.path, "\\a.txt");
        assert_eq!(whole.size, 12);
        assert_eq!(whole.offset, 0);
        assert_eq!(whole.returned, 12);
        assert!(!whole.truncated);
        assert!(!whole.partial_line);
        assert_eq!(whole.content_b64, BASE64.encode(content));
        assert_eq!(whole.text.as_deref(), Some("hello\nworld\n"));
        assert_eq!(whole.encoding.as_deref(), Some("utf-8"));

        let head = read(&guard, "\\a.txt", 0, Some(5), &limits()).expect("read head");
        assert_eq!(head.returned, 5);
        assert!(head.truncated);
        assert!(head.partial_line, "the cut lands mid-line");
        assert_eq!(head.content_b64, BASE64.encode(b"hello"));

        let tail = read(&guard, "\\a.txt", 6, Some(5), &limits()).expect("read tail");
        assert_eq!(tail.content_b64, BASE64.encode(b"world"));
        assert!(tail.truncated);

        let newline = read(&guard, "\\a.txt", 11, Some(1), &limits()).expect("read last byte");
        assert_eq!(newline.content_b64, BASE64.encode(b"\n"));
        assert!(!newline.truncated);
        assert!(!newline.partial_line);

        let empty = read(&guard, "\\a.txt", 12, None, &limits()).expect("read at eof");
        assert_eq!(empty.returned, 0);
        assert!(!empty.truncated);

        // The limit wins over the requested length.
        let capped = read(&guard, "\\a.txt", 0, None, &body(5)).expect("capped read");
        assert_eq!(capped.returned, 5);
        assert!(capped.truncated);

        assert_code(
            read(&guard, "\\a.txt", 13, None, &limits()),
            ErrorCode::BadRequest,
        );
    }

    #[test]
    fn read_marks_binary_content_and_rejects_directories() {
        let (dir, guard) = workspace();
        let binary = [0u8, 1, 2, 0xff, 0xfe];
        put(&dir, "blob.bin", &binary);
        fs::create_dir(dir.path().join("sub")).expect("dir");

        let response = read(&guard, "\\blob.bin", 0, None, &limits()).expect("read binary");
        assert_eq!(response.content_b64, BASE64.encode(binary));
        assert!(response.text.is_none());
        assert!(response.encoding.is_none());

        assert_code(read(&guard, "\\sub", 0, None, &limits()), ErrorCode::BadRequest);
        assert_code(
            read(&guard, "\\missing.txt", 0, None, &limits()),
            ErrorCode::NotFound,
        );
    }

    #[test]
    fn write_is_atomic_and_hashes_the_content() {
        let (dir, guard) = workspace();
        let result = write(&guard, "\\new\\a.txt", b"hello", false, true, &limits())
            .expect("write nested file");
        assert_eq!(result.path, "\\new\\a.txt");
        assert_eq!(result.size, 5);
        assert!(!result.overwritten);
        assert_eq!(
            result.sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(fs::read(dir.path().join("new\\a.txt")).expect("read"), b"hello");
        assert!(
            temp_files(&dir.path().join("new")).is_empty(),
            "no staging file left"
        );

        assert_code(
            write(&guard, "\\new\\a.txt", b"other", false, true, &limits()),
            ErrorCode::Conflict,
        );
        let replaced = write(&guard, "\\new\\a.txt", b"other", true, true, &limits())
            .expect("overwrite");
        assert!(replaced.overwritten);
        assert_eq!(
            fs::read(dir.path().join("new\\a.txt")).expect("read"),
            b"other"
        );
    }

    #[test]
    fn write_validates_parent_directory_and_size_limit() {
        let (dir, guard) = workspace();
        assert_code(
            write(&guard, "\\a\\b.txt", b"x", false, false, &limits()),
            ErrorCode::NotFound,
        );
        assert_code(
            write(&guard, "\\", b"x", true, true, &limits()),
            ErrorCode::BadRequest,
        );
        assert_code(
            write(&guard, "\\big.txt", b"1234", false, true, &body(3)),
            ErrorCode::PayloadTooLarge,
        );
        assert!(
            temp_files(dir.path()).is_empty(),
            "a rejected upload leaves no staging file"
        );
    }

    #[test]
    fn write_replaces_a_readonly_file_when_overwriting() {
        let (dir, guard) = workspace();
        let path = put(&dir, "ro.txt", b"old");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).expect("set readonly");

        write(&guard, "\\ro.txt", b"fresh", true, true, &limits()).expect("overwrite readonly");
        assert_eq!(fs::read(&path).expect("read"), b"fresh");
    }

    /// Reader that produces a repeating pattern without ever being buffered.
    struct PatternReader {
        total: usize,
        emitted: usize,
        biggest_request: usize,
    }

    impl PatternReader {
        fn new(total: usize) -> Self {
            Self {
                total,
                emitted: 0,
                biggest_request: 0,
            }
        }
    }

    impl Read for PatternReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                buf.len() <= 1024 * 1024,
                "fsops asked for a {} byte buffer; uploads must stream",
                buf.len()
            );
            self.biggest_request = self.biggest_request.max(buf.len());
            let remaining = self.total - self.emitted;
            let count = remaining.min(buf.len());
            for (offset, slot) in buf.iter_mut().take(count).enumerate() {
                *slot = ((self.emitted + offset) % 251) as u8;
            }
            self.emitted += count;
            Ok(count)
        }
    }

    #[test]
    fn write_stream_never_buffers_the_whole_body() {
        let (dir, guard) = workspace();
        const SIZE: usize = 3 * 1024 * 1024;
        let mut reader = PatternReader::new(SIZE);
        let result = write_stream(&guard, "\\big.bin", &mut reader, false, true, &limits())
            .expect("stream upload");
        assert_eq!(result.size as usize, SIZE);
        assert_eq!(reader.emitted, SIZE);

        // The digest must match an independent hash of the same pattern.
        let mut hasher = Sha256::new();
        let mut chunk = Vec::with_capacity(SIZE);
        for index in 0..SIZE {
            chunk.push((index % 251) as u8);
        }
        hasher.update(&chunk);
        let expected = crate::crypto::hex_encode(&hasher.finalize());
        assert_eq!(result.sha256.as_deref(), Some(expected.as_str()));
        assert_eq!(
            fs::metadata(dir.path().join("big.bin")).expect("metadata").len() as usize,
            SIZE
        );
        assert!(temp_files(dir.path()).is_empty(), "staging file was published");
    }

    #[test]
    fn write_stream_aborts_past_the_upload_limit() {
        let (dir, guard) = workspace();
        const BUDGET: u64 = 1024 * 1024;
        let mut reader = PatternReader::new(8 * 1024 * 1024);
        let limits = FsLimits::new(1000, 1000, BUDGET);
        let error = write_stream(&guard, "\\too_big.bin", &mut reader, false, true, &limits)
            .expect_err("limit is enforced mid-stream");
        assert_eq!(error.code(), ErrorCode::PayloadTooLarge);
        assert!(
            reader.emitted as u64 <= BUDGET + COPY_CHUNK as u64,
            "read {} bytes before giving up",
            reader.emitted
        );
        assert!(!dir.path().join("too_big.bin").exists());
        assert!(temp_files(dir.path()).is_empty(), "staging file cleaned up");
    }

    #[test]
    fn roots_describe_workspace_scope() {
        let (_dir, guard) = workspace();
        let roots = roots(&guard).expect("roots");
        assert_eq!(roots.scope, Scope::Workspace);
        assert_eq!(roots.workspace_root.as_deref(), Some("\\"));
        assert!(roots.drives.is_empty(), "a jailed session cannot browse drives");
        for quick in &roots.quick_paths {
            assert!(guard.is_inside(&guard.resolve(&quick.path).expect("quick path resolves")));
            assert!(quick.path.starts_with('\\'), "virtual path: {}", quick.path);
        }
    }

    #[test]
    fn roots_describe_full_scope() {
        let guard = PathGuard::new(Scope::Full, None).expect("full guard");
        let roots = roots(&guard).expect("roots");
        assert_eq!(roots.scope, Scope::Full);
        assert!(roots.workspace_root.is_none());
        assert!(!roots.drives.is_empty(), "at least the system drive");
        let system = roots
            .drives
            .iter()
            .find(|drive| drive.path.to_uppercase().starts_with("C:"))
            .expect("system drive present");
        assert!(system.total_bytes > 0);
        assert!(system.free_bytes <= system.total_bytes);
        assert!(!roots.quick_paths.is_empty(), "known folders exist");
    }

    #[test]
    fn open_for_read_returns_size_and_rejects_directories() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"12345");
        fs::create_dir(dir.path().join("sub")).expect("dir");

        let (real, file, size) = open_for_read(&guard, "\\a.txt").expect("open file");
        assert_eq!(size, 5);
        assert!(guard.is_inside(&real));
        assert_eq!(file.metadata().expect("metadata").len(), 5);

        assert_code(open_for_read(&guard, "\\sub"), ErrorCode::BadRequest);
        assert_code(open_for_read(&guard, "\\nope"), ErrorCode::NotFound);
    }

    #[test]
    fn is_existing_dir_matches_the_filesystem() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"a");
        fs::create_dir(dir.path().join("sub")).expect("dir");
        assert!(is_existing_dir(&guard, "\\"));
        assert!(is_existing_dir(&guard, "\\sub"));
        assert!(!is_existing_dir(&guard, "\\a.txt"));
        assert!(!is_existing_dir(&guard, "\\nope"));
    }

    #[test]
    fn resolve_returns_absolute_paths_inside_the_jail() {
        let (dir, guard) = workspace();
        put(&dir, "a.txt", b"a");
        let real = resolve(&guard, "\\a.txt").expect("resolve");
        assert!(real.is_absolute());
        assert!(guard.is_inside(&real));
        assert_eq!(guard.display(&real), "\\a.txt");
    }

    // -- destination capacity (S-16) -----------------------------------------

    #[test]
    fn capacity_check_rejects_a_payload_the_volume_cannot_hold() {
        let (dir, _guard) = workspace();
        let target = dir.path().join("payload.bin");
        let free = free_bytes(&target).expect("a local volume reports its free space");
        // Exactly the free space is not enough: the reserve has to survive.
        let err = ensure_capacity(&target, Some(free), "\\payload.bin")
            .expect_err("a payload equal to the free space leaves no reserve");
        assert_eq!(code(&err), ErrorCode::PayloadTooLarge);
        let message = err.to_string();
        assert!(
            message.contains(&free.to_string()),
            "the message states the free space: {message}"
        );
        assert!(
            message.contains(&(free + SPACE_RESERVE_BYTES).to_string()),
            "the message states the demand including the reserve: {message}"
        );
        // A payload that clearly fits still passes.
        ensure_capacity(&target, Some(1024), "\\payload.bin").expect("a small payload fits");
        // An unknown length only has to leave the reserve untouched.
        ensure_capacity(&target, None, "\\payload.bin").expect("streamed writes pass up front");
    }

    #[test]
    fn write_and_copy_still_pass_the_capacity_guard() {
        let (dir, guard) = workspace();
        let written = write(&guard, "\\a.bin", &vec![7u8; 4096], false, true, &limits())
            .expect("a small write fits");
        assert_eq!(written.size, 4096);
        let copied = copy(
            &guard,
            &CopyRequest {
                from: "\\a.bin".into(),
                to: "\\b.bin".into(),
                overwrite: false,
                recursive: false,
            },
        )
        .expect("a small copy fits");
        assert_eq!(copied.size, 4096);
        assert_eq!(
            fs::metadata(dir.path().join("b.bin")).expect("b.bin").len(),
            4096
        );
    }

    // -- kernel-handle re-validation (S-31) ----------------------------------

    #[test]
    fn final_path_check_rejects_paths_outside_the_jail() {
        let (_dir, guard) = workspace();
        let outside = tempfile::tempdir().expect("outside dir");
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"secret").expect("secret fixture");
        assert_code(
            verify_final_path(&guard, &secret, "\\escape"),
            ErrorCode::PolicyDenied,
        );
        // Full scope has no jail, so the same path is fine there.
        let full = PathGuard::new(Scope::Full, None).expect("full guard");
        verify_final_path(&full, &secret, "C:\\Windows\\win.ini").expect("full scope allows it");
    }

    #[test]
    fn a_junction_inside_the_jail_cannot_smuggle_io_outside() {
        let (dir, guard) = workspace();
        let outside = tempfile::tempdir().expect("outside dir");
        fs::write(outside.path().join("secret.txt"), b"secret").expect("secret fixture");
        fs::create_dir(dir.path().join("sub")).expect("sub dir");
        let link = dir.path().join("sub").join("escape");
        // Junctions are created by unprivileged users; if this environment
        // refuses, the direct check in the previous test still covers the logic.
        let created = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(outside.path())
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !created {
            return;
        }
        // The link itself lives inside the jail, so unlinking it is allowed...
        verify_entry(&guard, &link, "\\sub\\escape", false).expect("the link itself is inside");
        // ...but following it ends up outside and must be refused.
        assert_code(
            verify_entry(&guard, &link, "\\sub\\escape", true),
            ErrorCode::PolicyDenied,
        );
        // Resolving through the link is refused even earlier.
        assert_code(
            read(&guard, "\\sub\\escape\\secret.txt", 0, None, &limits()),
            ErrorCode::ScopeViolation,
        );
        // Addressing the link directly is refused at resolve time, so the
        // outside target is never touched.
        let refused = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\sub\\escape".into()],
                recursive: false,
                even_if_readonly: false,
            },
        )
        .expect("delete reports per-path failures");
        assert_eq!(refused.failed.len(), 1, "delete: {refused:?}");
        assert_eq!(refused.failed[0].code, ErrorCode::ScopeViolation);
        assert!(
            outside.path().join("secret.txt").exists(),
            "the link target survives"
        );
        // Deleting the containing directory unlinks the junction without ever
        // descending into it.
        let batch = delete(
            &guard,
            &DeleteRequest {
                paths: vec!["\\sub".into()],
                recursive: true,
                even_if_readonly: false,
            },
        )
        .expect("delete reports per-path failures");
        assert!(batch.failed.is_empty(), "delete failed: {:?}", batch.failed);
        assert!(
            outside.path().join("secret.txt").exists(),
            "the link target survives a recursive delete"
        );
        assert!(
            fs::symlink_metadata(&dir.path().join("sub")).is_err(),
            "the containing directory is gone"
        );
    }
}