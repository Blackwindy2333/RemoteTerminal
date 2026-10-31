//! Small shared helpers: byte formatting, Windows metadata, output decoding,
//! drive enumeration, file hashing.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rt_protocol::{DiskInfo, OutputEncoding};

use crate::error::{Result, RtError};

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.2} s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

pub fn format_uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn now_rfc3339() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn now_utc_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn timezone_name() -> String {
    // On Windows this yields the IANA name when the tz database is available,
    // otherwise the local offset.
    let offset = chrono::Local::now().offset().to_string();
    std::env::var("TZ")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(offset)
}

// ---------------------------------------------------------------------------
// Output decoding
// ---------------------------------------------------------------------------

/// Decode captured process output.
///
/// Windows console programs emit the OEM code page (936/GBK on zh-CN, 437 on
/// en-US) unless they are Windows Terminal aware, while PowerShell 7 emits
/// UTF-8. `Auto` tries strict UTF-8 first and falls back to GBK, which covers
/// both worlds without asking the user.
pub fn decode_output(bytes: &[u8], encoding: OutputEncoding) -> (String, String) {
    match encoding {
        OutputEncoding::Utf8 => (String::from_utf8_lossy(bytes).into_owned(), "utf-8".into()),
        OutputEncoding::Gbk => {
            let (text, _, had_errors) = encoding_rs::GBK.decode(bytes);
            (
                text.into_owned(),
                if had_errors { "gbk?" } else { "gbk" }.into(),
            )
        }
        OutputEncoding::Raw => (
            String::from_utf8_lossy(bytes).into_owned(),
            "raw".into(),
        ),
        OutputEncoding::Auto => {
            if bytes.is_empty() {
                return (String::new(), "utf-8".into());
            }
            match std::str::from_utf8(bytes) {
                Ok(text) => (text.to_string(), "utf-8".into()),
                Err(_) => {
                    let (text, _, _) = encoding_rs::GBK.decode(bytes);
                    (text.into_owned(), "gbk".into())
                }
            }
        }
    }
}

/// Heuristic: does this buffer look like binary data (NUL bytes, few controls)?
pub fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let sample = &bytes[..bytes.len().min(4096)];
    let mut suspicious = 0usize;
    for &b in sample {
        if b == 0 {
            return true;
        }
        if b < 0x09 || (b > 0x0d && b < 0x20) {
            suspicious += 1;
        }
    }
    suspicious * 100 / sample.len() > 5
}

// ---------------------------------------------------------------------------
// Windows file metadata
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win_attrs {
    pub const READONLY: u32 = 0x0000_0001;
    pub const HIDDEN: u32 = 0x0000_0002;
    pub const SYSTEM: u32 = 0x0000_0004;
    pub const DIRECTORY: u32 = 0x0000_0010;
    pub const ARCHIVE: u32 = 0x0000_0020;
    pub const TEMPORARY: u32 = 0x0000_0100;
    pub const OFFLINE: u32 = 0x0000_1000;
    pub const REPARSE_POINT: u32 = 0x0000_0400;
    pub const COMPRESSED: u32 = 0x0000_0800;
    pub const NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
}

#[cfg(windows)]
pub fn file_attributes(meta: &std::fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}

#[cfg(not(windows))]
pub fn file_attributes(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() {
        0x10
    } else {
        0x20
    }
}

pub fn attribute_names(attrs: u32) -> Vec<String> {
    let mut out = Vec::new();
    let table = [
        (win_attrs::READONLY, "readonly"),
        (win_attrs::HIDDEN, "hidden"),
        (win_attrs::SYSTEM, "system"),
        (win_attrs::DIRECTORY, "directory"),
        (win_attrs::ARCHIVE, "archive"),
        (win_attrs::TEMPORARY, "temporary"),
        (win_attrs::OFFLINE, "offline"),
        (win_attrs::REPARSE_POINT, "reparse_point"),
        (win_attrs::COMPRESSED, "compressed"),
        (win_attrs::NOT_CONTENT_INDEXED, "not_indexed"),
    ];
    for (bit, name) in table {
        if attrs & bit != 0 {
            out.push(name.to_string());
        }
    }
    out
}

pub fn is_hidden(attrs: u32) -> bool {
    attrs & (win_attrs::HIDDEN | win_attrs::SYSTEM) != 0
}

pub fn is_readonly(attrs: u32) -> bool {
    attrs & win_attrs::READONLY != 0
}

pub fn is_reparse_point(attrs: u32) -> bool {
    attrs & win_attrs::REPARSE_POINT != 0
}

/// Clears the read-only bit so a delete can proceed.
pub fn clear_readonly(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| RtError::io(path.to_path_buf(), e))?;
    let mut perms = meta.permissions();
    if perms.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms).map_err(|e| RtError::io(path.to_path_buf(), e))?;
    }
    Ok(())
}

pub fn system_time_ms(t: std::io::Result<std::time::SystemTime>) -> Option<i64> {
    t.ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Streams a file through SHA-256 without loading it into memory.
pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).map_err(|e| RtError::io(path.to_path_buf(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|e| RtError::io(path.to_path_buf(), e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        total += read as u64;
    }
    Ok((crate::crypto::hex_encode(&hasher.finalize()), total))
}

pub fn read_file_range(path: &Path, offset: u64, length: u64) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).map_err(|e| RtError::io(path.to_path_buf(), e))?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| RtError::io(path.to_path_buf(), e))?;
    }
    let mut buf = vec![0u8; length as usize];
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = file
            .read(&mut buf[filled..])
            .map_err(|e| RtError::io(path.to_path_buf(), e))?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Strips characters Windows forbids in a file name and bounds the length.
pub fn sanitize_filename(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    out = out.trim().trim_end_matches('.').to_string();
    if out.is_empty() {
        out = "unnamed".into();
    }
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        out = format!("_{out}");
    }
    if out.len() > 150 {
        let ext = Path::new(&out)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default();
        let keep = 150usize.saturating_sub(ext.len());
        let mut truncated: String = out.chars().take(keep).collect();
        truncated.push_str(&ext);
        out = truncated;
    }
    out
}

// ---------------------------------------------------------------------------
// Machine info
// ---------------------------------------------------------------------------

pub fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "windows".into())
}

pub fn username() -> Option<String> {
    std::env::var("USERNAME")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .filter(|v| !v.trim().is_empty())
}

pub fn os_description() -> (String, Option<String>, Option<String>) {
    let name = sysinfo::System::long_os_version()
        .ok()
        .or_else(|| sysinfo::System::name().ok())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "Windows".to_string());
    let version = sysinfo::System::os_version().ok();
    let build = sysinfo::System::kernel_version().ok();
    (name, version, build)
}

pub fn uptime_secs() -> u64 {
    sysinfo::System::uptime().unwrap_or(0)
}

/// All fixed/removable volumes currently mounted.
pub fn disks() -> Vec<DiskInfo> {
    use sysinfo::Disks;
    let mut out: Vec<DiskInfo> = Disks::new_with_refreshed_list()
        .map(|list| {
            list.iter()
                .map(|d| DiskInfo {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().display().to_string(),
                    file_system: {
                        let fs = d.file_system().to_string_lossy().to_string();
                        if fs.is_empty() {
                            None
                        } else {
                            Some(fs)
                        }
                    },
                    total_bytes: d.total_space(),
                    available_bytes: d.available_space(),
                    removable: d.is_removable(),
                    read_only: d.is_read_only(),
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));

    if out.is_empty() {
        // Fallback: probe drive letters directly (sysinfo can be empty very
        // early during boot or inside a restricted service session).
        for letter in b'A'..=b'Z' {
            let root = PathBuf::from(format!("{}:\\", letter as char));
            if root.exists() {
                out.push(DiskInfo {
                    name: root.display().to_string(),
                    mount_point: root.display().to_string(),
                    file_system: None,
                    total_bytes: 0,
                    available_bytes: 0,
                    removable: false,
                    read_only: false,
                });
            }
        }
    }
    out
}

/// Candidate "interesting" folders, as `(label, real path, kind)`.
///
/// The caller filters them through the session's [`crate::pathscope::PathGuard`]
/// so a workspace session only sees paths inside its jail.
pub fn quick_path_candidates() -> Vec<(String, PathBuf, String)> {
    let mut out = Vec::new();
    let mut push = |label: &str, dir: Option<PathBuf>, kind: &str| {
        if let Some(dir) = dir {
            if dir.exists() {
                out.push((label.to_string(), dir, kind.to_string()));
            }
        }
    };
    push("Desktop", dirs::desktop_dir(), "user");
    push("Documents", dirs::document_dir(), "user");
    push("Downloads", dirs::download_dir(), "user");
    push("Pictures", dirs::picture_dir(), "user");
    push("Home", dirs::home_dir(), "user");
    push("Temp", Some(std::env::temp_dir()), "system");
    push(
        "Program Files",
        Some(PathBuf::from("C:\\Program Files")),
        "system",
    );
    push("Windows", Some(PathBuf::from("C:\\Windows")), "system");
    push("Current dir", std::env::current_dir().ok(), "app");
    out
}

/// Locate a program on PATH (used by the exec module for shell detection).
pub fn which(program: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(program);
    if candidate.is_absolute() && candidate.exists() {
        return Some(candidate);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join(program);
        if full.is_file() {
            return Some(full);
        }
        let exe = dir.join(format!("{program}.exe"));
        if exe.is_file() {
            return Some(exe);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_formatting() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(15 * 1024 * 1024), "15.0 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn duration_and_uptime_formatting() {
        assert_eq!(format_duration_ms(42), "42 ms");
        assert_eq!(format_duration_ms(1500), "1.50 s");
        assert_eq!(format_duration_ms(125_000), "2m 5s");
        assert_eq!(format_uptime(90), "1m");
        assert_eq!(format_uptime(3700), "1h 1m");
        assert_eq!(format_uptime(90_000), "1d 1h 0m");
    }

    #[test]
    fn decoding_prefers_utf8_then_gbk() {
        let (text, enc) = decode_output("你好".as_bytes(), OutputEncoding::Auto);
        assert_eq!(text, "你好");
        assert_eq!(enc, "utf-8");

        // GBK bytes for 你好
        let gbk = [0xC4u8, 0xE3, 0xBA, 0xC3];
        let (text, enc) = decode_output(&gbk, OutputEncoding::Auto);
        assert_eq!(text, "你好");
        assert_eq!(enc, "gbk");

        let (text, _) = decode_output(b"plain ascii", OutputEncoding::Auto);
        assert_eq!(text, "plain ascii");
    }

    #[test]
    fn binary_detection() {
        assert!(looks_binary(&[0, 1, 2, 3, 0, 0]));
        assert!(!looks_binary(b"hello world\n"));
        assert!(!looks_binary(&[]));
    }

    #[test]
    fn filename_sanitising() {
        assert_eq!(sanitize_filename("a<b>c:d"), "a_b_c_d");
        assert_eq!(sanitize_filename("  trailing.  "), "trailing");
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename(""), "unnamed");
        assert!(sanitize_filename(&"x".repeat(400)).len() <= 150);
    }

    #[test]
    fn attribute_names_are_stable_strings() {
        let names = attribute_names(0x1 | 0x2 | 0x10);
        assert!(names.contains(&"readonly".to_string()));
        assert!(names.contains(&"hidden".to_string()));
        assert!(names.contains(&"directory".to_string()));
        assert!(is_hidden(0x2));
        assert!(!is_hidden(0x20));
    }

    #[test]
    fn disks_are_enumerable() {
        let disks = disks();
        assert!(!disks.is_empty(), "expected at least one volume");
        assert!(disks.iter().any(|d| !d.mount_point.is_empty()));
    }

    #[test]
    fn hashing_a_temp_file() {
        let path = std::env::temp_dir().join(format!("rt_hash_{}.txt", std::process::id()));
        std::fs::write(&path, b"abc").expect("write");
        let (digest, size) = sha256_file(&path).expect("hash");
        assert_eq!(size, 3);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&path);
    }
}
