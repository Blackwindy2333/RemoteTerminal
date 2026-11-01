//! Human-in-the-loop approval for destructive MCP tools (S-17).
//!
//! An MCP bridge is driven by a language model: a prompt injected into the
//! remote session's page, a poisoned document, or simply a hallucinated call
//! can turn into `rt_exec` on the target machine. The server-side scope check
//! limits *where* that happens, but nothing asks the human whether this
//! particular command should run at all.
//!
//! This module adds that ask. Tools listed in [`DANGEROUS`] are refused unless
//! the operator has granted them a time-boxed lease:
//!
//! ```text
//! remote-terminal approve rt_exec --minutes 30     # allow for half an hour
//! remote-terminal approve --list                    # what is currently allowed
//! remote-terminal approve rt_exec --revoke          # stop allowing it
//! ```
//!
//! Leases live in `<data_dir>/mcp-approvals.json`, are re-read on every call
//! (cheap: the file is tiny and only accessed when it changes), and expire on
//! their own. Read-only tools are never gated, so an agent can still explore
//! without the operator having to babysit it.
//!
//! `RT_REQUIRE_APPROVAL=0` disables the gate for scripts and test harnesses
//! that already run under their own review process.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Tools that change the remote machine or run code on it.
pub const DANGEROUS: &[&str] = &[
    "rt_exec",
    "rt_fs_write",
    "rt_fs_delete",
    "rt_fs_rename",
    "rt_fs_copy",
    "rt_fs_upload",
];

pub const APPROVAL_FILE: &str = "mcp-approvals.json";

/// Returns true when `tool` needs an explicit operator grant.
pub fn is_dangerous(tool: &str) -> bool {
    DANGEROUS.iter().any(|t| t.eq_ignore_ascii_case(tool))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Interprets `RT_REQUIRE_APPROVAL`: unset means "gated".
fn gate_enabled(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | ""
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub tool: String,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub created_at_ms: i64,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ApprovalFile {
    #[serde(default)]
    grants: Vec<Grant>,
}

/// Lease store backed by a JSON file.
#[derive(Debug, Clone)]
pub struct Approvals {
    path: PathBuf,
}

impl Approvals {
    /// `<data_dir>/mcp-approvals.json`, or `RT_APPROVAL_FILE` when set.
    pub fn resolve(data_dir: &Path) -> Self {
        let path = std::env::var_os("RT_APPROVAL_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join(APPROVAL_FILE));
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The gate is on by default; `RT_REQUIRE_APPROVAL=0|false|no|off` turns it off.
    pub fn enabled(&self) -> bool {
        gate_enabled(std::env::var("RT_REQUIRE_APPROVAL").ok().as_deref())
    }

    fn read(&self) -> ApprovalFile {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|err| {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "approval file is not valid JSON; treating every lease as absent"
                );
                ApprovalFile::default()
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => ApprovalFile::default(),
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "cannot read the approval file; treating every lease as absent"
                );
                ApprovalFile::default()
            }
        }
    }

    fn write(&self, file: &ApprovalFile) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let body = serde_json::to_vec_pretty(file).map_err(|e| format!("encode: {e}"))?;
        let temp = self.path.with_extension("json.tmp");
        std::fs::write(&temp, &body).map_err(|e| format!("write {}: {e}", temp.display()))?;
        std::fs::rename(&temp, &self.path).map_err(|e| format!("replace {}: {e}", self.path.display()))
    }

    /// Live leases (`tool -> expires_at_ms`), expired entries dropped.
    pub fn grants(&self) -> BTreeMap<String, i64> {
        let now = now_ms();
        self.read()
            .grants
            .into_iter()
            .filter(|g| g.expires_at_ms > now)
            .map(|g| (g.tool, g.expires_at_ms))
            .collect()
    }

    /// Grants (or extends) a lease for `minutes`.
    pub fn grant(&self, tool: &str, minutes: u64) -> Result<i64, String> {
        if !is_dangerous(tool) {
            return Err(format!(
                "`{tool}` is not a gated tool; gated tools are: {}",
                DANGEROUS.join(", ")
            ));
        }
        let minutes = minutes.clamp(1, 24 * 60);
        let mut file = self.read();
        let now = now_ms();
        let expires = now + (minutes as i64) * 60_000;
        file.grants.retain(|g| !g.tool.eq_ignore_ascii_case(tool));
        file.grants.push(Grant {
            tool: tool.to_string(),
            expires_at_ms: expires,
            created_at_ms: now,
            note: None,
        });
        self.write(&file)?;
        tracing::info!(tool = %tool, minutes, "granted a destructive MCP tool lease");
        Ok(expires)
    }

    /// Drops the lease for `tool`; returns whether one existed.
    pub fn revoke(&self, tool: &str) -> Result<bool, String> {
        let mut file = self.read();
        let before = file.grants.len();
        file.grants.retain(|g| !g.tool.eq_ignore_ascii_case(tool));
        let removed = file.grants.len() != before;
        if removed {
            self.write(&file)?;
            tracing::info!(tool = %tool, "revoked a destructive MCP tool lease");
        }
        Ok(removed)
    }

    /// Drops every expired lease so the file does not grow forever.
    pub fn prune(&self) -> usize {
        let mut file = self.read();
        let now = now_ms();
        let before = file.grants.len();
        file.grants.retain(|g| g.expires_at_ms > now);
        let removed = before - file.grants.len();
        if removed > 0 {
            let _ = self.write(&file);
        }
        removed
    }

    /// Gate check used before a tool runs.
    pub fn check(&self, tool: &str) -> Result<(), String> {
        self.check_with(tool, self.enabled())
    }

    /// Same as [`Self::check`] with the gate state passed in, which lets tests
    /// exercise both branches without touching process-wide environment state.
    pub fn check_with(&self, tool: &str, gate_enabled: bool) -> Result<(), String> {
        if !gate_enabled || !is_dangerous(tool) {
            return Ok(());
        }
        let now = now_ms();
        let granted = self
            .read()
            .grants
            .iter()
            .any(|g| g.tool.eq_ignore_ascii_case(tool) && g.expires_at_ms > now);
        if granted {
            return Ok(());
        }
        Err(format!(
            "approval required: `{tool}` changes the remote machine and has no active lease.\n\
             Ask the machine's operator to approve it, for example:\n\
             \x20 remote-terminal approve {tool} --minutes 30\n\
             Then retry this call. (Set RT_REQUIRE_APPROVAL=0 to disable this gate for \
             automated runs whose changes are reviewed elsewhere.)"
        ))
    }

    /// Human-readable lease summary: `(tool, expires_at_ms, remaining)`.
    pub fn listing(&self) -> Vec<(String, i64, Duration)> {
        let now = now_ms();
        self.grants()
            .into_iter()
            .map(|(tool, expires)| {
                let remaining = Duration::from_millis((expires - now).max(0) as u64);
                (tool, expires, remaining)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rt-app has no `tempfile` dev-dependency; a uniquely named directory under
    /// the system temp folder is enough for these tests.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static COUNTER: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "rt-approval-{}-{}-{n}",
                std::process::id(),
                now_ms()
            ));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn temp_store() -> (Scratch, Approvals) {
        let dir = Scratch::new();
        let store = Approvals::resolve(dir.path());
        (dir, store)
    }

    #[test]
    fn read_only_tools_are_never_gated() {
        let (_dir, store) = temp_store();
        assert!(store.check_with("rt_info", true).is_ok());
        assert!(store.check_with("rt_fs_read", true).is_ok());
        assert!(store.check_with("rt_exec", true).is_err());
    }

    #[test]
    fn a_grant_unblocks_only_its_tool() {
        let (_dir, store) = temp_store();
        store.grant("rt_exec", 5).expect("grant");
        assert!(store.check_with("rt_exec", true).is_ok());
        assert!(store.check_with("rt_fs_delete", true).is_err());
        assert_eq!(store.listing().len(), 1);
    }

    #[test]
    fn revoking_removes_the_lease() {
        let (_dir, store) = temp_store();
        store.grant("rt_fs_delete", 10).expect("grant");
        assert!(store.revoke("rt_fs_delete").expect("revoke"));
        assert!(!store.revoke("rt_fs_delete").expect("revoke again"));
        assert!(store.check_with("rt_fs_delete", true).is_err());
    }

    #[test]
    fn expired_leases_do_not_count() {
        let (dir, store) = temp_store();
        // Write a lease that expired a minute ago.
        let expired = now_ms() - 60_000;
        let file = serde_json::json!({
            "grants": [{ "tool": "rt_exec", "expires_at_ms": expired }]
        });
        std::fs::write(dir.path().join(APPROVAL_FILE), file.to_string()).expect("write");
        assert!(store.check_with("rt_exec", true).is_err());
        assert!(store.grants().is_empty());
        assert_eq!(store.prune(), 1);
    }

    #[test]
    fn non_gated_tools_cannot_be_granted() {
        let (_dir, store) = temp_store();
        let err = store.grant("rt_info", 5).expect_err("must refuse");
        assert!(err.contains("not a gated tool"));
    }

    #[test]
    fn the_gate_defaults_to_on_and_can_be_switched_off() {
        assert!(gate_enabled(None));
        assert!(gate_enabled(Some("1")));
        assert!(gate_enabled(Some("true")));
        assert!(!gate_enabled(Some("0")));
        assert!(!gate_enabled(Some("FALSE")));
        assert!(!gate_enabled(Some(" off ")));

        let (_dir, store) = temp_store();
        // With the gate off, a destructive tool needs no lease.
        assert!(store.check_with("rt_exec", false).is_ok());
    }
}
