//! Path sandbox: every client-supplied path string passes through here.
//!
//! Two scopes:
//! * [`Scope::Full`] — any local path on this machine (but never a UNC/share
//!   path and never a device namespace path).
//! * [`Scope::Workspace`] — a single directory tree. Anything that resolves
//!   outside it is rejected **after** canonicalisation, so `..`, symlinks,
//!   junctions, 8.3 short names and mixed separators cannot escape.
//!
//! Virtual paths for workspace sessions are root-relative and use backslashes:
//! `\` is the root itself, `\sub\a.txt` a child. Absolute paths are accepted as
//! long as they are inside the root.

use std::path::{Component, Path, PathBuf};

use rt_protocol::Scope;

use crate::error::{Result, RtError};

/// Reserved DOS device names (case-insensitive, also with an extension).
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Clone)]
pub struct PathGuard {
    scope: Scope,
    /// Canonicalised workspace root; `None` for full scope.
    root: Option<PathBuf>,
    /// Human-facing form of the root (as configured, for messages).
    root_display: String,
}

impl PathGuard {
    /// Builds a guard for a session.
    ///
    /// For `Scope::Workspace` the root must exist (it is created by the caller
    /// beforehand); the canonical form is captured once so later comparisons
    /// are cheap and consistent.
    pub fn new(scope: Scope, workspace_root: Option<&Path>) -> Result<Self> {
        match scope {
            Scope::Full => Ok(Self {
                scope,
                root: None,
                root_display: String::new(),
            }),
            Scope::Workspace => {
                let root = workspace_root.ok_or_else(|| {
                    RtError::Config(
                        "workspace scope requires server.workspace.root to be configured".into(),
                    )
                })?;
                if !root.exists() {
                    std::fs::create_dir_all(root)
                        .map_err(|e| RtError::io(root.to_path_buf(), e))?;
                }
                let canonical = std::fs::canonicalize(root)
                    .map_err(|e| RtError::io(root.to_path_buf(), e))?;
                Ok(Self {
                    scope,
                    root: Some(strip_extended_prefix(&canonical)),
                    root_display: root.display().to_string(),
                })
            }
        }
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    pub fn root_display(&self) -> &str {
        &self.root_display
    }

    /// Validate and normalise, without requiring the target to exist.
    ///
    /// The returned path is absolute and canonical for every existing
    /// ancestor; the (possibly missing) leaf is appended after validation.
    pub fn resolve(&self, input: &str) -> Result<PathBuf> {
        let raw = validate_syntax(input)?;
        let candidate = self.compose(raw)?;
        let real = deepest_canonical(&candidate)?;
        if let Some(root) = &self.root {
            if !path_starts_with(&real, root) {
                tracing::warn!(
                    target: "rt_core::pathscope",
                    requested = %input,
                    resolved = %real.display(),
                    root = %root.display(),
                    "path outside workspace jail rejected"
                );
                return Err(RtError::scope_violation(format!(
                    "path `{input}` resolves outside the workspace (root: {})",
                    self.root_display
                )));
            }
        }
        Ok(real)
    }

    /// Turns the (syntactically valid) path into an absolute one according to
    /// the scope's rules.
    fn compose(&self, raw: PathBuf) -> Result<PathBuf> {
        let drive_absolute = has_drive_prefix(&raw);
        match &self.root {
            Some(root) => {
                if drive_absolute {
                    Ok(raw)
                } else if raw.has_root() {
                    // `\sub\a.txt` — virtual, root-relative form.
                    Ok(root.join(strip_leading_separators(&raw)))
                } else {
                    Ok(root.join(raw))
                }
            }
            None => absolutize(raw),
        }
    }

    /// Like [`Self::resolve`] but the target must already exist.
    pub fn resolve_existing(&self, input: &str) -> Result<PathBuf> {
        let path = self.resolve(input)?;
        if !path.exists() {
            return Err(RtError::not_found(format!("`{input}` does not exist")));
        }
        Ok(path)
    }

    /// Convert a real path into the client-visible form.
    pub fn display(&self, real: &Path) -> String {
        match &self.root {
            Some(root) => {
                if path_eq(real, root) {
                    "\\".to_string()
                } else {
                    match real.strip_prefix(root) {
                        Ok(rel) => {
                            let mut out = String::from("\\");
                            out.push_str(&rel.to_string_lossy().replace('/', "\\"));
                            out
                        }
                        Err(_) => real.display().to_string(),
                    }
                }
            }
            None => real.display().to_string(),
        }
    }

    /// Explicit membership test, for callers holding an already-resolved path.
    pub fn ensure_inside(&self, real: &Path) -> Result<()> {
        match &self.root {
            Some(root) if !path_starts_with(real, root) => Err(RtError::scope_violation(format!(
                "`{}` is outside the workspace",
                real.display()
            ))),
            _ => Ok(()),
        }
    }

    pub fn is_inside(&self, real: &Path) -> bool {
        match &self.root {
            Some(root) => path_starts_with(real, root),
            None => true,
        }
    }
}

/// Rejects obviously hostile / meaningless input before touching the FS.
fn validate_syntax(input: &str) -> Result<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(RtError::InvalidPath("path must not be empty".into()));
    }
    if trimmed.len() > 32_000 {
        return Err(RtError::InvalidPath("path is too long".into()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(RtError::InvalidPath(
            "path must not contain control characters".into(),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();

    // Device namespaces and raw paths: `\\.\PhysicalDrive0`, `\\?\GLOBALROOT\...`
    if lower.starts_with("\\\\.\\") || lower.starts_with("\\\\.?\\") {
        return Err(RtError::InvalidPath(
            "device namespace paths are not allowed".into(),
        ));
    }
    if lower.starts_with("\\\\?\\globalroot") || lower.starts_with("\\\\.\\globalroot") {
        return Err(RtError::InvalidPath(
            "device namespace paths are not allowed".into(),
        ));
    }
    // Network shares are refused outright: they would make the server act as a
    // credential relay towards third-party SMB hosts.
    if trimmed.starts_with("\\\\") || trimmed.starts_with("//") {
        return Err(RtError::PolicyDenied(
            "UNC / network share paths are not supported".into(),
        ));
    }

    let path = PathBuf::from(trimmed);

    // `C:foo` (drive-relative) has surprising semantics — reject it.
    let s = trimmed.replace('/', "\\");
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let rest = &s[2..];
        if !rest.is_empty() && !rest.starts_with('\\') {
            return Err(RtError::InvalidPath(
                "drive-relative paths (`C:name`) are not allowed; use `C:\\name`".into(),
            ));
        }
    }

    for comp in path.components() {
        match comp {
            Component::Prefix(prefix) => {
                use std::path::Prefix;
                match prefix.kind() {
                    Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
                    Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) => {
                        return Err(RtError::PolicyDenied(
                            "UNC / network share paths are not supported".into(),
                        ))
                    }
                    Prefix::DeviceNS(_) => {
                        return Err(RtError::InvalidPath(
                            "device namespace paths are not allowed".into(),
                        ))
                    }
                    Prefix::Verbatim(_) => {
                        return Err(RtError::InvalidPath(
                            "verbatim paths (`\\\\?\\`) are not accepted".into(),
                        ))
                    }
                }
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.contains(':') {
                    return Err(RtError::InvalidPath(format!(
                        "alternate data streams (`{name}`) are not allowed"
                    )));
                }
                if name.chars().any(|c| matches!(c, '*' | '?' | '<' | '>' | '|' | '"')) {
                    return Err(RtError::InvalidPath(format!(
                        "`{name}` contains characters that are invalid on Windows"
                    )));
                }
                if name.ends_with(' ') || name.ends_with('.') {
                    return Err(RtError::InvalidPath(format!(
                        "`{name}` ends with a space or dot, which Windows silently trims"
                    )));
                }
                let stem = name.split('.').next().unwrap_or(&name).to_ascii_uppercase();
                if RESERVED.contains(&stem.as_str()) {
                    return Err(RtError::InvalidPath(format!(
                        "`{name}` is a reserved device name"
                    )));
                }
            }
            Component::ParentDir | Component::CurDir | Component::RootDir => {}
        }
    }

    Ok(path)
}

fn has_drive_prefix(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let b = text.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn strip_leading_separators(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.trim_start_matches(['\\', '/']).to_string())
}

/// Make a path absolute for full-scope sessions.
fn absolutize(raw: PathBuf) -> Result<PathBuf> {
    if raw.is_absolute() {
        return Ok(raw);
    }
    let cwd = std::env::current_dir()
        .map_err(|e| RtError::Internal(format!("cannot read current dir: {e}")))?;
    if raw.has_root() {
        let drive = cwd
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();
        let rest = strip_leading_separators(&raw);
        if drive.is_empty() {
            Ok(PathBuf::from(format!("\\{}", rest.display())))
        } else {
            Ok(PathBuf::from(format!("{drive}\\{}", rest.display())))
        }
    } else {
        Ok(cwd.join(raw))
    }
}

/// Canonicalise the longest existing ancestor and re-append the rest.
/// This resolves `..` that dangles past a symlink or junction only *after* the
/// link target is known, which a naive lexical normalisation would get wrong.
fn deepest_canonical(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(strip_extended_prefix(&canonical));
    }

    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match std::fs::canonicalize(&cursor) {
            Ok(canonical) => {
                let mut result = strip_extended_prefix(&canonical);
                for name in suffix.iter().rev() {
                    result.push(name);
                }
                return Ok(result);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match cursor.file_name() {
                    Some(name) => {
                        suffix.push(name.to_os_string());
                        if !cursor.pop() {
                            return Err(RtError::io(
                                path.to_path_buf(),
                                std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    "no existing ancestor",
                                ),
                            ));
                        }
                    }
                    None => {
                        return Err(RtError::io(
                            path.to_path_buf(),
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "no existing ancestor",
                            ),
                        ))
                    }
                }
            }
            Err(err) => return Err(RtError::io(cursor, err)),
        }
    }
}

/// Case-insensitive, separator-agnostic prefix test.
pub fn path_starts_with(path: &Path, base: &Path) -> bool {
    if path_eq(path, base) {
        return true;
    }
    let p: Vec<String> = components_ci(path);
    let b: Vec<String> = components_ci(base);
    p.len() > b.len() && p[..b.len()] == b[..]
}

pub fn path_eq(a: &Path, b: &Path) -> bool {
    components_ci(a) == components_ci(b)
}

fn components_ci(path: &Path) -> Vec<String> {
    let raw = path.to_string_lossy().replace('/', "\\");
    raw.split('\\')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Remove the `\\?\` prefix that `canonicalize` adds on Windows.
pub fn strip_extended_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
        return PathBuf::from(format!("\\\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix("\\\\?\\") {
        return PathBuf::from(rest.to_string());
    }
    path.to_path_buf()
}

/// Re-add the extended prefix when a path may exceed MAX_PATH.
pub fn to_extended(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text.starts_with("\\\\?\\") {
        return path.to_path_buf();
    }
    if path.is_absolute() && text.len() >= 240 {
        return PathBuf::from(format!("\\\\?\\{text}"));
    }
    path.to_path_buf()
}

/// Convenience wrapper used by file operations: resolve + extended prefix.
pub fn resolve_for_io(guard: &PathGuard, input: &str) -> Result<PathBuf> {
    Ok(to_extended(&guard.resolve(input)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rt_scope_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
        std::fs::write(dir.join("a.txt"), b"hi").expect("write");
        std::fs::write(dir.join("sub/b.txt"), b"hi").expect("write");
        dir
    }

    #[test]
    fn workspace_scope_resolves_relative_and_absolute() {
        let root = temp_root("rel");
        let guard = PathGuard::new(Scope::Workspace, Some(&root)).expect("guard");
        let p = guard.resolve("a.txt").expect("resolve");
        assert!(p.ends_with("a.txt"));
        assert_eq!(guard.display(&p), "\\a.txt");

        let virt = guard.resolve("\\sub\\b.txt").expect("virtual path");
        assert!(virt.ends_with("b.txt"));
        assert_eq!(guard.display(&virt), "\\sub\\b.txt");

        let abs = root.join("sub").join("b.txt");
        assert!(guard.resolve(&abs.to_string_lossy()).is_ok());

        let root_self = guard.resolve("\\").expect("root");
        assert!(path_eq(&root_self, &root));
        assert_eq!(guard.display(&root_self), "\\");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn workspace_scope_blocks_escape() {
        let root = temp_root("esc");
        let guard = PathGuard::new(Scope::Workspace, Some(&root)).expect("guard");
        assert!(guard.resolve("..\\outside.txt").is_err());
        assert!(guard.resolve("sub\\..\\..\\x").is_err());
        let outside = std::env::temp_dir().join("rt_outside_probe.txt");
        assert!(guard.resolve(&outside.to_string_lossy()).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_hostile_syntax() {
        let guard = PathGuard::new(Scope::Full, None).expect("guard");
        for bad in [
            "",
            "   ",
            "\\\\server\\share\\x",
            "//server/share/x",
            "\\\\.\\PhysicalDrive0",
            "\\\\?\\GLOBALROOT\\Device",
            "C:relative",
            "a:b",
            "CON",
            "sub/con.txt",
            // leading/trailing whitespace around the whole path is tolerated,
            // but a component that internally ends with a space is not.
            "a /b",
            "trailing.",
            "bad*name",
            "bad\"name",
            "ctrl\u{7}char",
        ] {
            assert!(guard.resolve(bad).is_err(), "should reject {bad:?}");
        }
        assert!(guard.resolve("C:\\Windows").is_ok());
        assert!(guard.resolve("C:/Windows/System32").is_ok());
    }

    #[test]
    fn full_scope_allows_any_local_path() {
        let guard = PathGuard::new(Scope::Full, None).expect("guard");
        let p = guard.resolve("C:\\Windows").expect("resolve");
        assert!(p.is_absolute());
        assert!(guard.is_inside(&p));
    }

    #[test]
    fn extended_prefix_helpers() {
        assert_eq!(
            strip_extended_prefix(Path::new("\\\\?\\C:\\temp\\x")),
            Path::new("C:\\temp\\x")
        );
        assert_eq!(
            strip_extended_prefix(Path::new("\\\\?\\UNC\\srv\\share")),
            Path::new("\\\\srv\\share")
        );
        let long = format!("C:\\{}", "a".repeat(300));
        assert!(to_extended(Path::new(&long)).to_string_lossy().starts_with("\\\\?\\"));
    }

    #[test]
    fn case_insensitive_prefix() {
        assert!(path_starts_with(
            Path::new("C:\\Users\\Foo\\Bar"),
            Path::new("c:\\users\\foo")
        ));
        assert!(!path_starts_with(
            Path::new("C:\\Users\\Foobar"),
            Path::new("C:\\Users\\Foo")
        ));
    }
}
