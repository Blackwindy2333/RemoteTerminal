//! Machine information: CPU, memory, disks, networks, displays, battery,
//! processes.
//!
//! CPU usage is a *delta* between two samples, so the service keeps state and
//! is meant to be created once and shared (`Arc<SysInfoService>`).
//!
//! ## Design notes
//!
//! * `sysinfo::System` is not `Sync`, hence the internal `Mutex`. Every public
//!   method takes the lock, performs its refresh and releases it, so concurrent
//!   pollers serialise instead of corrupting each other's deltas.
//! * Expensive/hardware-bound refresh work is split by cost: CPU and RAM on
//!   every call, the full process table only on `deep` requests (`snapshot`,
//!   `processes`). `quick` is safe to poll several times per second.
//! * Facts that cannot change while the process runs (hostname, OS build, core
//!   count) are collected once in [`SysInfoService::new`].
//! * Everything that can fail is tolerated: a missing battery, an unavailable
//!   display or an unsupported counter degrades to `None`/empty instead of an
//!   error, because a partially filled dashboard beats a failed one.

use std::sync::{Mutex, MutexGuard};

use rt_protocol::{
    AppInfo, BatteryInfo, CpuInfo, MemoryInfo, NetAddress, NetInfo, ProcessEntry,
    ProcessListResponse, QuickStatus, SysInfoSnapshot,
};
use sysinfo::{Networks, ProcessesToUpdate, System, Users};

use crate::error::{Result, RtError};
use crate::util;

/// Upper bound for one process listing, so a hostile `limit` cannot allocate
/// unboundedly.
const MAX_PROCESS_LIMIT: usize = 5_000;

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

/// Facts that stay constant for the lifetime of the server process.
struct Identity {
    hostname: String,
    os_name: String,
    os_version: Option<String>,
    os_build: Option<String>,
    arch: String,
    physical_cores: u32,
    /// `USERDOMAIN`: the AD domain or the workgroup name.
    domain: Option<String>,
}

impl Identity {
    fn collect() -> Self {
        let (os_name, os_version, os_build) = util::os_description();
        let hostname = { 
            let from_env = util::hostname();
            if from_env.trim().is_empty() {
                System::host_name().unwrap_or_default()
            } else {
                from_env
            }
        };

        Self {
            hostname,
            os_name,
            os_version,
            os_build,
            arch: System::cpu_arch(),
            physical_cores: System::physical_core_count().unwrap_or(0) as u32,
            domain: std::env::var("USERDOMAIN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
    }
}

struct Inner {
    /// `None` when the platform refused to hand out system state; every read
    /// path then reports `Unavailable` instead of panicking.
    system: Option<System>,
    users: Option<Users>,
    identity: Identity,
}

/// Stateful collector. Create one per server and wrap it in an `Arc`.
pub struct SysInfoService {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for SysInfoService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SysInfoService").finish_non_exhaustive()
    }
}

impl Default for SysInfoService {
    fn default() -> Self {
        Self::new()
    }
}

impl SysInfoService {
    pub fn new() -> Self {
        let identity = Identity::collect();
        let mut inner = Inner {
            system: System::new().ok(),
            users: Users::new_with_refreshed_list().ok(),
            identity,
        };

        if let Some(system) = inner.system.as_mut() {
            // Prime both deltas: the first CPU sample only establishes a
            // baseline, so a second one is taken after the documented minimum
            // interval. This costs ~200ms once, at construction time.
            system.refresh_cpu_usage();
            system.refresh_memory();
            let _ = system.refresh_processes(ProcessesToUpdate::All, true);
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
            system.refresh_cpu_usage();
            system.refresh_memory();
        }

        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Refreshes CPU/memory/process samples. Cheap ones (CPU %, RAM) are done on
    /// every call; the expensive full process list only when `deep` is true.
    pub fn refresh(&self, deep: bool) {
        let mut inner = self.lock();
        Self::refresh_inner(&mut inner, deep);
    }

    /// Full snapshot used by the dashboard. `app` is supplied by the caller so
    /// this module never needs to know about the server.
    pub fn snapshot(&self, app: AppInfo) -> Result<SysInfoSnapshot> {
        let mut guard = self.lock();
        Self::refresh_inner(&mut guard, true);

        let Inner {
            system,
            identity,
            ..
        } = &mut *guard;
        let system = system
            .as_mut()
            .ok_or_else(|| RtError::Unavailable("system information is unavailable".into()))?;
        let identity = &*identity;

        let total_memory = system.total_memory();
        let used_memory = system.used_memory();
        let available_memory = system.available_memory();
        let swap_total = system.total_swap();
        let swap_used = system.used_swap();
        let memory_usage_percent = percent(used_memory, total_memory);

        let cpus = system.cpus();
        let logical_cores = cpus.len() as u32;
        let brand = cpus
            .iter()
            .map(|cpu| cpu.brand().trim())
            .find(|brand| !brand.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| identity.arch.clone());
        let frequency_mhz = current_frequency_mhz(cpus);

        let uptime_secs = System::uptime().unwrap_or(0);
        let boot_time = boot_time_rfc3339(uptime_secs);

        Ok(SysInfoSnapshot {
            hostname: identity.hostname.clone(),
            os_name: identity.os_name.clone(),
            os_version: identity.os_version.clone(),
            os_build: identity.os_build.clone(),
            arch: identity.arch.clone(),
            username: util::username(),
            domain: identity.domain.clone(),
            cpu: CpuInfo {
                brand,
                physical_cores: identity.physical_cores,
                logical_cores,
                usage_percent: round2(system.global_cpu_usage().clamp(0.0, 100.0)),
                frequency_mhz,
            },
            memory: MemoryInfo {
                total_bytes: total_memory,
                used_bytes: used_memory,
                available_bytes: available_memory,
                swap_total_bytes: swap_total,
                swap_used_bytes: swap_used,
                usage_percent: memory_usage_percent,
            },
            disks: util::disks(),
            networks: collect_networks(),
            // The capture module is owned by another agent and may not be ready
            // yet; an empty display list is a valid answer for a headless host.
            displays: crate::capture::list_screens().unwrap_or_default(),
            battery: read_battery(),
            uptime_secs,
            boot_time,
            server_time: util::now_rfc3339(),
            timezone: util::timezone_name(),
            process_count: system.processes().len() as u32,
            // Windows has no load average.
            load_average: None,
            app,
        })
    }

    /// Lightweight status for high-frequency polling (1-5 Hz).
    pub fn quick(&self, active_sessions: usize) -> Result<QuickStatus> {
        let mut guard = self.lock();
        Self::refresh_inner(&mut guard, false);

        let Inner { system, .. } = &mut *guard;
        let system = system
            .as_ref()
            .ok_or_else(|| RtError::Unavailable("system information is unavailable".into()))?;

        Ok(QuickStatus {
            cpu_usage_percent: round2(system.global_cpu_usage().clamp(0.0, 100.0)),
            memory_used_bytes: system.used_memory(),
            memory_total_bytes: system.total_memory(),
            // Uses the process table from the last deep refresh: accurate
            // enough for a 1-5 Hz status and far cheaper than re-enumerating
            // every process on each tick.
            process_count: system.processes().len() as u32,
            uptime_secs: System::uptime().unwrap_or(0),
            sampled_at: util::now_rfc3339(),
            battery_percent: read_battery().map(|battery| battery.percent),
            active_sessions: Some(active_sessions as u32),
        })
    }

    /// Process table, filtered and sorted server-side.
    pub fn processes(&self, query: &ProcessQuery) -> Result<ProcessListResponse> {
        let mut guard = self.lock();
        Self::refresh_inner(&mut guard, true);

        let Inner { system, users, .. } = &mut *guard;
        let system = system
            .as_mut()
            .ok_or_else(|| RtError::Unavailable("system information is unavailable".into()))?;
        let users = users.as_ref();

        let needle = query
            .query
            .as_deref()
            .map(str::trim)
            .filter(|needle| !needle.is_empty())
            .map(str::to_lowercase);

        let mut entries: Vec<ProcessEntry> = Vec::with_capacity(system.processes().len());
        for process in system.processes().values() {
            let entry = process_entry(process, users);
            if let Some(needle) = &needle {
                if !matches_query(&entry, needle) {
                    continue;
                }
            }
            entries.push(entry);
        }

        sort_entries(&mut entries, &query.sort, query.descending);

        let total = entries.len() as u32;
        let limit = query.limit.clamp(1, MAX_PROCESS_LIMIT);
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        Ok(ProcessListResponse {
            processes: entries,
            total,
            truncated,
            sampled_at: util::now_rfc3339(),
        })
    }

    /// Takes the lock, recovering the state if a previous caller panicked.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn refresh_inner(inner: &mut Inner, deep: bool) {
        let Some(system) = inner.system.as_mut() else {
            return;
        };
        system.refresh_cpu_usage();
        system.refresh_memory();
        if deep {
            let _ = system.refresh_processes(ProcessesToUpdate::All, true);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn percent(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        round2((used as f64 / total as f64 * 100.0) as f32)
    }
}

/// Rounds to two decimals, the precision the wire format promises.
fn round2(value: f32) -> f32 {
    if value.is_finite() {
        (value * 100.0).round() / 100.0
    } else {
        0.0
    }
}

/// Mean current frequency across cores, in MHz. Schedulers report `0` on
/// platforms that do not expose it, which maps to `None`.
fn current_frequency_mhz(cpus: &[sysinfo::Cpu]) -> Option<u64> {
    let frequencies: Vec<u64> = cpus
        .iter()
        .map(|cpu| cpu.frequency())
        .filter(|frequency| *frequency > 0)
        .collect();
    if frequencies.is_empty() {
        return None;
    }
    let sum: u64 = frequencies.iter().sum();
    Some(sum / frequencies.len() as u64)
}

fn epoch_to_rfc3339(seconds: u64) -> Option<String> {
    let stamp = chrono::DateTime::from_timestamp(seconds as i64, 0)?;
    Some(
        stamp
            .with_timezone(&chrono::Local)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

fn boot_time_rfc3339(uptime_secs: u64) -> String {
    if let Ok(boot) = System::boot_time() {
        if let Some(stamp) = epoch_to_rfc3339(boot) {
            return stamp;
        }
    }
    // Fall back to "now minus uptime" when the platform cannot report it.
    let now = chrono::Local::now().timestamp().max(0) as u64;
    epoch_to_rfc3339(now.saturating_sub(uptime_secs)).unwrap_or_default()
}

fn collect_networks() -> Vec<NetInfo> {
    let Ok(networks) = Networks::new_with_refreshed_list() else {
        return Vec::new();
    };

    let mut out: Vec<NetInfo> = networks
        .iter()
        .map(|(name, data)| {
            let name = name.to_string_lossy().into_owned();
            let addresses: Vec<NetAddress> = data
                .ip_networks()
                .iter()
                .map(|network| NetAddress {
                    address: network.addr.to_string(),
                    kind: if network.addr.is_ipv4() {
                        "ipv4".to_string()
                    } else {
                        "ipv6".to_string()
                    },
                    prefix: Some(network.prefix),
                })
                .collect();

            let mac = data.mac_address();
            let mac_address = if mac.is_unspecified() {
                None
            } else {
                Some(mac.to_string())
            };

            let is_loopback = name.to_ascii_lowercase().contains("loopback")
                || (!addresses.is_empty()
                    && addresses.iter().all(|address| {
                        address
                            .address
                            .parse::<std::net::IpAddr>()
                            .map(|ip| ip.is_loopback())
                            .unwrap_or(false)
                    }));

            NetInfo {
                name,
                mac_address,
                addresses,
                is_up: matches!(
                    data.operational_state(),
                    sysinfo::InterfaceOperationalState::Up
                ),
                is_loopback,
            }
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn process_entry(process: &sysinfo::Process, users: Option<&Users>) -> ProcessEntry {
    let exe = process
        .exe()
        .map(|path| path.display().to_string())
        .filter(|path| !path.is_empty());

    let args: Vec<String> = process
        .cmd()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let cmd = if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    };

    let user = process
        .user_id()
        .and_then(|uid| users.and_then(|users| users.get_user_by_id(uid)))
        .map(|user| user.name().to_string())
        .filter(|name| !name.is_empty());

    ProcessEntry {
        pid: process.pid().as_u32(),
        parent_pid: process.parent().map(|pid| pid.as_u32()),
        name: process.name().to_string_lossy().into_owned(),
        exe,
        cmd,
        // `cpu_usage()` is already a percentage and, unlike the system-wide
        // value, it may legitimately exceed 100 on multi-core hosts.
        cpu_percent: round2(process.cpu_usage()),
        memory_bytes: process.memory(),
        run_time_secs: process.run_time(),
        user,
        started_at: epoch_to_rfc3339(process.start_time()),
    }
}

/// Case-insensitive substring match over name, executable and command line.
fn matches_query(entry: &ProcessEntry, needle: &str) -> bool {
    entry.name.to_lowercase().contains(needle)
        || entry
            .exe
            .as_deref()
            .is_some_and(|exe| exe.to_lowercase().contains(needle))
        || entry
            .cmd
            .as_deref()
            .is_some_and(|cmd| cmd.to_lowercase().contains(needle))
}

fn sort_entries(entries: &mut [ProcessEntry], sort: &str, descending: bool) {
    match sort.trim().to_ascii_lowercase().as_str() {
        "pid" => entries.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.name.cmp(&b.name))),
        "name" => entries.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.pid.cmp(&b.pid))
        }),
        "memory" | "memory_bytes" | "mem" => {
            entries.sort_by(|a, b| a.memory_bytes.cmp(&b.memory_bytes).then(a.pid.cmp(&b.pid)))
        }
        "uptime" | "runtime" | "run_time" => {
            entries.sort_by(|a, b| a.run_time_secs.cmp(&b.run_time_secs).then(a.pid.cmp(&b.pid)))
        }
        // Unknown keys fall back to the default ordering instead of failing.
        _ => entries.sort_by(|a, b| {
            a.cpu_percent
                .partial_cmp(&b.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.pid.cmp(&b.pid))
        }),
    }

    if descending {
        entries.reverse();
    }
}

/// `SYSTEM_POWER_STATUS` as documented by the Windows SDK.
#[cfg(windows)]
#[repr(C)]
struct SystemPowerStatus {
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
    battery_full_life_time: u32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetSystemPowerStatus(status: *mut SystemPowerStatus) -> i32;
}

/// Reads the battery through `GetSystemPowerStatus`.
///
/// A desktop without a battery, or a failed call, yields `None`; this must
/// never make the snapshot fail.
#[cfg(windows)]
fn read_battery() -> Option<BatteryInfo> {
    let mut status = SystemPowerStatus {
        ac_line_status: 255,
        battery_flag: 255,
        battery_life_percent: 255,
        system_status_flag: 0,
        battery_life_time: 0,
        battery_full_life_time: 0,
    };

    // SAFETY: the pointer refers to a live, correctly laid-out struct for the
    // duration of the call and the function only writes to it.
    let ok = unsafe { GetSystemPowerStatus(&mut status) };
    if ok == 0 {
        return None;
    }

    // Bit 7 = no system battery, 255 = unknown.
    if status.battery_flag & 0x80 != 0 || status.battery_life_percent == 255 {
        return None;
    }

    Some(BatteryInfo {
        percent: f32::from(status.battery_life_percent),
        // Bit 3 = charging.
        is_charging: status.battery_flag & 0x08 != 0,
        minutes_remaining: match status.battery_life_time {
            u32::MAX => None,
            seconds => Some(seconds / 60),
        },
    })
}

#[cfg(not(windows))]
fn read_battery() -> Option<BatteryInfo> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rt_protocol::{Scope, APP_VERSION, PROTOCOL_VERSION};

    use super::*;

    /// One shared service: creation costs ~200ms (CPU baseline), so the whole
    /// test module pays it once. The internal mutex serialises the calls.
    fn service() -> &'static SysInfoService {
        static SERVICE: OnceLock<SysInfoService> = OnceLock::new();
        SERVICE.get_or_init(SysInfoService::new)
    }

    fn app_info() -> AppInfo {
        AppInfo {
            version: APP_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            server_enabled: false,
            active_sessions: 0,
            uptime_secs: 0,
            scope: Scope::Full,
            workspace_root: None,
            config_path: String::new(),
            data_dir: String::new(),
            server: None,
        }
    }

    #[test]
    fn snapshot_fills_the_dashboard_contract() {
        let snapshot = service().snapshot(app_info()).expect("snapshot");

        assert!(!snapshot.hostname.is_empty(), "hostname must be known");
        assert!(!snapshot.os_name.is_empty());
        assert!(!snapshot.arch.is_empty());
        assert!(
            snapshot.memory.total_bytes > 0,
            "physical memory must be readable"
        );
        assert!(snapshot.memory.used_bytes > 0);
        assert!(snapshot.memory.used_bytes <= snapshot.memory.total_bytes);
        assert!(snapshot.cpu.logical_cores >= 1);
        assert!(!snapshot.cpu.brand.is_empty());
        assert!(snapshot.uptime_secs > 0);
        assert!(!snapshot.server_time.is_empty());
        assert!(!snapshot.boot_time.is_empty());
        assert!(!snapshot.timezone.is_empty());
        assert!(snapshot.process_count >= 1);
        assert!(snapshot.load_average.is_none());
        // Networks and disks exist on any Windows host, but a sandboxed CI box
        // may hide them: only require the call to have succeeded.
        let _ = (&snapshot.networks, &snapshot.disks, &snapshot.displays);
        assert_eq!(snapshot.app.version, APP_VERSION);
    }

    #[test]
    fn quick_status_is_cheap_and_callable_repeatedly() {
        let status = service().quick(3).expect("quick");
        assert!(status.memory_total_bytes > 0);
        assert!(status.memory_used_bytes > 0);
        assert!(status.process_count >= 1);
        assert!(status.cpu_usage_percent >= 0.0);
        assert_eq!(status.active_sessions, Some(3));
        assert!(!status.sampled_at.is_empty());

        let again = service().quick(0).expect("quick twice");
        assert_eq!(again.active_sessions, Some(0));
    }

    #[test]
    fn processes_returns_entries_sorted_by_cpu() {
        let query = ProcessQuery {
            limit: 50,
            ..ProcessQuery::default()
        };
        let response = service().processes(&query).expect("processes");

        assert!(!response.processes.is_empty(), "expected some processes");
        assert!(response.total >= 1);
        assert!(response.processes.len() <= 50);
        assert_eq!(response.truncated, response.total as usize > 50);
        assert!(!response.sampled_at.is_empty());

        // Default sort is cpu/descending.
        for pair in response.processes.windows(2) {
            assert!(
                pair[0].cpu_percent >= pair[1].cpu_percent,
                "cpu ordering broken at pid {} -> {}",
                pair[0].pid,
                pair[1].pid
            );
        }
        let any = &response.processes[0];
        assert!(any.pid > 0);
        assert!(!any.name.is_empty());
    }

    #[test]
    fn processes_support_memory_sort_and_name_filter() {
        let by_memory = ProcessQuery {
            limit: 20,
            sort: "memory".into(),
            descending: true,
            ..ProcessQuery::default()
        };
        let response = service().processes(&by_memory).expect("processes");
        for pair in response.processes.windows(2) {
            assert!(pair[0].memory_bytes >= pair[1].memory_bytes);
        }

        // Pick a real process name and filter by a lowercase substring of it,
        // then verify the filter actually narrowed the result.
        let name = response.processes[0].name.clone();
        let needle = name.chars().take(3).collect::<String>().to_lowercase();
        let filtered = ProcessQuery {
            limit: 500,
            query: Some(needle.clone()),
            sort: "pid".into(),
            descending: false,
            ..ProcessQuery::default()
        };
        let matched = service().processes(&filtered).expect("filtered processes");
        assert!(
            !matched.processes.is_empty(),
            "filter `{needle}` should match at least `{name}`"
        );
        assert!(matched.total as usize <= response.total as usize);
        for entry in &matched.processes {
            assert!(
                entry.name.to_lowercase().contains(&needle)
                    || entry
                        .exe
                        .as_deref()
                        .is_some_and(|exe| exe.to_lowercase().contains(&needle))
                    || entry
                        .cmd
                        .as_deref()
                        .is_some_and(|cmd| cmd.to_lowercase().contains(&needle)),
                "entry {} does not match `{needle}`",
                entry.name
            );
        }
        // pid ascending must hold.
        for pair in matched.processes.windows(2) {
            assert!(pair[0].pid <= pair[1].pid);
        }
    }

    #[test]
    fn refresh_and_battery_helpers_do_not_panic() {
        service().refresh(false);
        service().refresh(true);
        // Either a real battery or `None`, both are valid.
        if let Some(battery) = read_battery() {
            assert!((0.0..=100.0).contains(&battery.percent));
        }
    }

    #[test]
    fn frequency_and_rounding_helpers_behave() {
        assert_eq!(round2(12.3456), 12.35);
        assert_eq!(round2(f32::NAN), 0.0);
        assert_eq!(percent(1, 0), 0.0);
        assert_eq!(percent(1, 4), 25.0);
        assert_eq!(current_frequency_mhz(&[]), None);
    }
}
