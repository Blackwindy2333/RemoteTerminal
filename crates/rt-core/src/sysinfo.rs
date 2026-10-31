//! Machine information: CPU, memory, disks, networks, displays, battery,
//! processes. CPU usage needs two samples, so the service keeps state and is
//! meant to be created once and shared.
//!
//! STATUS: interface stub — bodies are implemented by the sysinfo module owner.
//! Signatures are the frozen contract used by `rt-server`.

use std::sync::Mutex;

use rt_protocol::{AppInfo, ProcessListResponse, QuickStatus, SysInfoSnapshot};

use crate::error::{Result, RtError};

/// How `processes()` should be sorted / filtered.
#[derive(Debug, Clone)]
pub struct ProcessQuery {
    pub limit: usize,
    pub query: Option<String>,
    /// `cpu` | `memory` | `pid` | `name` | `uptime`
    pub sort: String,
    pub descending: bool,
}

impl Default for ProcessQuery {
    fn default() -> Self {
        Self {
            limit: 200,
            query: None,
            sort: "cpu".into(),
            descending: true,
        }
    }
}

/// Stateful collector. Create one per server and wrap it in an `Arc`.
#[derive(Debug, Default)]
pub struct SysInfoService {
    inner: Mutex<()>,
}

fn todo<T>(what: &str) -> Result<T> {
    Err(RtError::NotImplemented(format!("sysinfo::{what}")))
}

impl SysInfoService {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    /// Refreshes CPU/memory/process samples. Cheap ones (CPU %, RAM) are done on
    /// every call; the expensive full process list only when `deep` is true.
    pub fn refresh(&self, _deep: bool) {}

    /// Full snapshot used by the dashboard. `app` is supplied by the caller so
    /// this module never needs to know about the server.
    pub fn snapshot(&self, _app: AppInfo) -> Result<SysInfoSnapshot> {
        todo("snapshot")
    }

    /// Lightweight status for high-frequency polling (1-5 Hz).
    pub fn quick(&self, _active_sessions: usize) -> Result<QuickStatus> {
        todo("quick")
    }

    /// Process table, filtered and sorted server-side.
    pub fn processes(&self, _query: &ProcessQuery) -> Result<ProcessListResponse> {
        todo("processes")
    }
}
