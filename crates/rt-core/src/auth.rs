//! Authentication and session state.
//!
//! * Passwords are verified against Argon2id PHC hashes from the config.
//! * A successful login mints an opaque bearer token; only its SHA-256 digest
//!   is kept in memory, so a memory disclosure does not yield usable tokens.
//! * Login attempts are throttled per (user, IP) to blunt online guessing.
//! * A coarse per-IP request rate limiter protects the whole API surface.
//! * API keys are long-lived and compared against stored digests in constant
//!   time; they never appear in logs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rt_protocol::{ApiKeyInfo, SessionInfo, Scope};

use crate::config::{ApiKeyConfig, UserConfig};
use crate::crypto;
use crate::error::{Result, RtError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Password,
    ApiKey,
}

impl AuthKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthKind::Password => "password",
            AuthKind::ApiKey => "api_key",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub scope: Scope,
    pub auth_kind: AuthKind,
    pub device_name: Option<String>,
    pub remote_addr: Option<String>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl Session {
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            username: self.username.clone(),
            scope: self.scope,
            expires_at: rfc3339_ms(self.expires_at_ms),
            issued_at: rfc3339_ms(self.issued_at_ms),
            auth_kind: self.auth_kind.as_str().to_string(),
            device_name: self.device_name.clone(),
            remote_addr: self.remote_addr.clone(),
        }
    }

    pub fn expires_in_secs(&self, now_ms: i64) -> u64 {
        ((self.expires_at_ms - now_ms).max(0) / 1000) as u64
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn rfc3339_ms(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).expect("epoch"))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(ttl_secs: u64, max_sessions: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(if ttl_secs == 0 { 86_400 } else { ttl_secs }),
            max_sessions: max_sessions.max(1),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Mints a token. Returns `(plaintext_token, session)`; the plaintext is
    /// shown to the caller exactly once.
    pub fn issue(
        &self,
        username: &str,
        scope: Scope,
        auth_kind: AuthKind,
        device_name: Option<String>,
        remote_addr: Option<String>,
    ) -> (String, Session) {
        let token = crypto::random_token(32);
        let now = now_ms();
        let session = Session {
            username: username.to_string(),
            scope,
            auth_kind,
            device_name,
            remote_addr,
            issued_at_ms: now,
            expires_at_ms: now + self.ttl.as_millis() as i64,
        };
        if let Ok(mut map) = self.inner.lock() {
            self.gc_locked(&mut map, now);
            // Enforce the session cap: drop the soonest-to-expire first.
            while map.len() >= self.max_sessions {
                if let Some(victim) = map
                    .iter()
                    .min_by_key(|(_, s)| s.expires_at_ms)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&victim);
                } else {
                    break;
                }
            }
            map.insert(digest(&token), session.clone());
        }
        (token, session)
    }

    /// Issues a session with an explicit token (used by tests and by the
    /// in-process GUI shortcut where the token never leaves memory).
    pub fn issue_with_token(&self, token: &str, mut session: Session) -> Session {
        let now = now_ms();
        if session.issued_at_ms == 0 {
            session.issued_at_ms = now;
        }
        if session.expires_at_ms == 0 {
            session.expires_at_ms = now + self.ttl.as_millis() as i64;
        }
        if let Ok(mut map) = self.inner.lock() {
            map.insert(digest(token), session.clone());
        }
        session
    }

    pub fn lookup(&self, token: &str) -> Option<Session> {
        if token.is_empty() {
            return None;
        }
        let now = now_ms();
        let mut map = self.inner.lock().ok()?;
        let key = digest(token);
        match map.get(&key) {
            Some(session) if !session.is_expired(now) => Some(session.clone()),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn revoke(&self, token: &str) -> bool {
        self.inner
            .lock()
            .map(|mut m| m.remove(&digest(token)).is_some())
            .unwrap_or(false)
    }

    pub fn revoke_user(&self, username: &str) -> usize {
        let Ok(mut map) = self.inner.lock() else {
            return 0;
        };
        let before = map.len();
        map.retain(|_, s| !s.username.eq_ignore_ascii_case(username));
        before - map.len()
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let now = now_ms();
        let Ok(map) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out: Vec<SessionInfo> = map
            .values()
            .filter(|s| !s.is_expired(now))
            .map(Session::info)
            .collect();
        out.sort_by(|a, b| a.username.cmp(&b.username).then(a.issued_at.cmp(&b.issued_at)));
        out
    }

    pub fn count(&self) -> usize {
        let now = now_ms();
        self.inner
            .lock()
            .map(|m| m.values().filter(|s| !s.is_expired(now)).count())
            .unwrap_or(0)
    }

    pub fn gc(&self) {
        let now = now_ms();
        if let Ok(mut map) = self.inner.lock() {
            self.gc_locked(&mut map, now);
        }
    }

    fn gc_locked(&self, map: &mut HashMap<String, Session>, now: i64) {
        map.retain(|_, s| !s.is_expired(now));
    }
}

fn digest(token: &str) -> String {
    crypto::sha256_hex(token.as_bytes())
}

// ---------------------------------------------------------------------------
// Credential verification
// ---------------------------------------------------------------------------

fn decoy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| {
        crypto::hash_password("decoy-password-never-matches")
            .unwrap_or_else(|_| String::new())
    })
}

/// Verifies a username/password pair against the configured users.
///
/// Always performs a hash comparison (even for unknown users) so that response
/// timing does not reveal which account names exist.
pub fn verify_user<'a>(
    users: &'a [UserConfig],
    username: &str,
    password: &str,
) -> Result<&'a UserConfig> {
    let mut matched: Option<&UserConfig> = None;
    for user in users {
        if !user.enabled || user.password_hash.trim().is_empty() {
            continue;
        }
        if user.name.eq_ignore_ascii_case(username.trim()) {
            matched = Some(user);
        }
    }

    match matched {
        Some(user) => {
            if crypto::verify_password(password, &user.password_hash) {
                Ok(user)
            } else {
                Err(RtError::Auth("invalid username or password".into()))
            }
        }
        None => {
            let _ = crypto::verify_password(password, decoy_hash());
            Err(RtError::Auth("invalid username or password".into()))
        }
    }
}

pub fn scope_of(user: &UserConfig) -> Scope {
    Scope::parse(&user.scope).unwrap_or(Scope::Workspace)
}

/// Resolves a presented API key to `(name, scope)`.
pub fn verify_api_key(keys: &[ApiKeyConfig], presented: &str) -> Option<(String, Scope)> {
    if presented.trim().is_empty() {
        return None;
    }
    let mut found = None;
    for key in keys {
        if !key.enabled || key.key_sha256.trim().is_empty() {
            continue;
        }
        if crypto::verify_api_key_digest(presented, &key.key_sha256) {
            found = Some((
                key.name.clone(),
                Scope::parse(&key.scope).unwrap_or(Scope::Workspace),
            ));
        }
    }
    found
}

pub fn api_key_infos(keys: &[ApiKeyConfig]) -> Vec<ApiKeyInfo> {
    keys.iter()
        .map(|k| ApiKeyInfo {
            name: k.name.clone(),
            scope: Scope::parse(&k.scope).unwrap_or(Scope::Workspace),
            fingerprint: k
                .key_sha256
                .chars()
                .take(8)
                .collect::<String>()
                .to_ascii_lowercase(),
            created_at: k.created_at.clone(),
            last_used_at: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Throttling
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AttemptState {
    failures: u32,
    locked_until: Option<Instant>,
    last_seen: Instant,
}

/// Per-key login throttle: after `max_attempts` failures the key is locked for
/// `lockout_secs`. A success clears the counter.
#[derive(Debug)]
pub struct LoginLimiter {
    max_attempts: u32,
    lockout: Duration,
    state: Mutex<HashMap<String, AttemptState>>,
}

impl LoginLimiter {
    pub fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            lockout: Duration::from_secs(lockout_secs.max(1)),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Fails fast while locked.
    pub fn check(&self, key: &str) -> Result<()> {
        let Ok(mut map) = self.state.lock() else {
            return Ok(());
        };
        let now = Instant::now();
        if let Some(entry) = map.get_mut(key) {
            if let Some(until) = entry.locked_until {
                if now < until {
                    let retry = (until - now).as_secs().max(1);
                    return Err(RtError::RateLimited {
                        message: format!("too many failed attempts; try again in {retry}s"),
                        retry_after_secs: retry,
                    });
                }
                entry.locked_until = None;
                entry.failures = 0;
            }
        }
        Ok(())
    }

    /// Records a failure and returns how many attempts remain before lockout.
    pub fn record_failure(&self, key: &str) -> u32 {
        let Ok(mut map) = self.state.lock() else {
            return 0;
        };
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert(AttemptState {
            failures: 0,
            locked_until: None,
            last_seen: now,
        });
        entry.failures += 1;
        entry.last_seen = now;
        if entry.failures >= self.max_attempts {
            entry.locked_until = Some(now + self.lockout);
            entry.failures = 0;
            0
        } else {
            self.max_attempts - entry.failures
        }
    }

    pub fn record_success(&self, key: &str) {
        if let Ok(mut map) = self.state.lock() {
            map.remove(key);
        }
    }

    /// Drops stale entries so the map cannot grow without bound.
    pub fn gc(&self) {
        let Ok(mut map) = self.state.lock() else {
            return;
        };
        let now = Instant::now();
        map.retain(|_, e| {
            let locked = e.locked_until.map(|u| now < u).unwrap_or(false);
            locked || now.duration_since(e.last_seen) < self.lockout * 4
        });
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket limiter, one bucket per client key.
#[derive(Debug)]
pub struct RateLimiter {
    per_minute: u32,
    state: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.per_minute > 0
    }

    /// Returns `Ok(())` when the request may proceed.
    pub fn check(&self, key: &str) -> Result<()> {
        if self.per_minute == 0 {
            return Ok(());
        }
        let capacity = self.per_minute as f64;
        let refill_per_sec = capacity / 60.0;
        let Ok(mut map) = self.state.lock() else {
            return Ok(());
        };
        let now = Instant::now();
        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let retry_after = ((1.0 - bucket.tokens) / refill_per_sec).ceil().max(1.0) as u64;
            Err(RtError::RateLimited {
                message: "request rate limit exceeded".into(),
                retry_after_secs: retry_after,
            })
        }
    }

    pub fn gc(&self) {
        let Ok(mut map) = self.state.lock() else {
            return;
        };
        let now = Instant::now();
        map.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(300));
    }

    pub fn tracked_keys(&self) -> usize {
        self.state.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Client IP allow-list: entries are prefixes or exact addresses.
/// IPv4-mapped IPv6 (`::ffff:192.168.1.5`) is normalised first.
pub fn ip_allowed(allowlist: &[String], ip: &str) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let ip = normalise_ip(ip);
    allowlist.iter().any(|entry| {
        let entry = normalise_ip(entry.trim());
        if entry.is_empty() {
            return false;
        }
        ip == entry || (ip.starts_with(&entry) && entry.ends_with(['.', ':']))
    })
}

pub fn normalise_ip(ip: &str) -> String {
    let ip = ip.trim();
    if let Some(rest) = ip.strip_prefix("::ffff:") {
        if rest.contains('.') {
            return rest.to_string();
        }
    }
    ip.trim_start_matches('[').trim_end_matches(']').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, password: &str, scope: &str) -> UserConfig {
        UserConfig {
            name: name.into(),
            password_hash: crypto::hash_password(password).expect("hash"),
            scope: scope.into(),
            enabled: true,
        }
    }

    #[test]
    fn sessions_issue_lookup_and_expire() {
        let store = SessionStore::new(1, 4);
        let (token, session) = store.issue(
            "admin",
            Scope::Full,
            AuthKind::Password,
            Some("dsh".into()),
            Some("10.0.0.2".into()),
        );
        assert_eq!(session.scope, Scope::Full);
        let found = store.lookup(&token).expect("session");
        assert_eq!(found.username, "admin");
        assert_eq!(store.count(), 1);
        assert!(store.lookup("not-a-token").is_none());

        let info = found.info();
        assert_eq!(info.auth_kind, "password");
        assert!(info.expires_at.contains('T'));

        assert!(store.revoke(&token));
        assert!(store.lookup(&token).is_none());
    }

    #[test]
    fn session_cap_evicts_oldest_expiry() {
        let store = SessionStore::new(3600, 2);
        store.issue("a", Scope::Full, AuthKind::Password, None, None);
        store.issue("b", Scope::Full, AuthKind::Password, None, None);
        store.issue("c", Scope::Full, AuthKind::Password, None, None);
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn password_verification() {
        let users = vec![user("admin", "s3cret-password", "full")];
        let ok = verify_user(&users, "ADMIN", "s3cret-password").expect("ok");
        assert_eq!(scope_of(ok), Scope::Full);
        assert!(verify_user(&users, "admin", "nope").is_err());
        assert!(verify_user(&users, "ghost", "s3cret-password").is_err());
    }

    #[test]
    fn api_key_lookup() {
        let key = "rt_live_key_value";
        let keys = vec![ApiKeyConfig {
            name: "harness".into(),
            key_sha256: crypto::sha256_hex(key.as_bytes()),
            scope: "workspace".into(),
            enabled: true,
            created_at: None,
        }];
        let (name, scope) = verify_api_key(&keys, key).expect("key");
        assert_eq!(name, "harness");
        assert_eq!(scope, Scope::Workspace);
        assert!(verify_api_key(&keys, "wrong").is_none());
        let infos = api_key_infos(&keys);
        assert_eq!(infos[0].fingerprint.len(), 8);
    }

    #[test]
    fn login_limiter_locks_out() {
        let limiter = LoginLimiter::new(2, 60);
        limiter.check("k").expect("ok");
        assert_eq!(limiter.record_failure("k"), 1);
        assert_eq!(limiter.record_failure("k"), 0);
        assert!(limiter.check("k").is_err());
        limiter.record_success("k");
        assert!(limiter.check("k").is_ok());
    }

    #[test]
    fn rate_limiter_buckets() {
        let limiter = RateLimiter::new(60);
        for _ in 0..60 {
            assert!(limiter.check("ip").is_ok());
        }
        let err = limiter.check("ip").expect_err("limited");
        assert!(matches!(err, RtError::RateLimited { .. }));
        assert_eq!(limiter.tracked_keys(), 1);
    }

    #[test]
    fn rate_limiter_disabled() {
        let limiter = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(limiter.check("ip").is_ok());
        }
    }

    #[test]
    fn ip_allowlist_matching() {
        assert!(ip_allowed(&[], "1.2.3.4"));
        assert!(ip_allowed(&["192.168.1.".into()], "192.168.1.55"));
        assert!(!ip_allowed(&["192.168.1.".into()], "192.168.10.55"));
        assert!(ip_allowed(&["10.0.0.5".into()], "::ffff:10.0.0.5"));
        assert!(ip_allowed(&["::1".into()], "[::1]"));
        assert!(!ip_allowed(&["10.0.0.5".into()], "10.0.0.6"));
    }
}
