//! Remote host information: hardware, OS, runtime and process snapshots.

use serde::{Deserialize, Serialize};

use crate::{Scope, ServerInfo};

/// `GET /api/v1/system/info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysInfoSnapshot {
    pub hostname: String,
    pub os_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_build: Option<String>,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    #[serde(default)]
    pub disks: Vec<DiskInfo>,
    #[serde(default)]
    pub networks: Vec<NetInfo>,
    #[serde(default)]
    pub displays: Vec<crate::ScreenInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<BatteryInfo>,

    pub uptime_secs: u64,
    pub boot_time: String,
    pub server_time: String,
    pub timezone: String,
    pub process_count: u32,
    #[serde(default)]
    pub load_average: Option<[f64; 3]>,

    /// Facts about *this app* rather than the host.
    pub app: AppInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub brand: String,
    pub physical_cores: u32,
    pub logical_cores: u32,
    pub usage_percent: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency_mhz: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_system: Option<String>,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub addresses: Vec<NetAddress>,
    pub is_up: bool,
    #[serde(default)]
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetAddress {
    pub address: String,
    /// `ipv4` | `ipv6`
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub percent: f32,
    pub is_charging: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minutes_remaining: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub version: String,
    pub protocol_version: String,
    pub server_enabled: bool,
    pub active_sessions: u32,
    pub uptime_secs: u64,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub config_path: String,
    #[serde(default)]
    pub data_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerInfo>,
}

/// One row of the remote process list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(default)]
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub run_time_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListResponse {
    pub processes: Vec<ProcessEntry>,
    pub total: u32,
    #[serde(default)]
    pub truncated: bool,
    pub sampled_at: String,
}

/// Lightweight poll payload so the dashboard can update without shipping the
/// full snapshot every second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickStatus {
    pub cpu_usage_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub process_count: u32,
    pub uptime_secs: u64,
    pub sampled_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<u32>,
}
