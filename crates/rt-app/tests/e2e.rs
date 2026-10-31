//! End-to-end integration test: server + client + protocol over real TCP and TLS.
//!
//! Nothing here is mocked. The test starts the real HTTP/TLS server in-process
//! (`rt_server::serve`), talks to it with the real `rt_client::RemoteClient`,
//! and checks the behaviour a user actually relies on: login, session
//! enforcement, command execution, filesystem round-trips inside the workspace
//! jail, host telemetry, screen capture and clean shutdown.
//!
//! It is deliberately self-contained so `cargo test --workspace` exercises the
//! full stack without needing a machine-specific config file:
//!
//! * the config is built in memory ([`rt_core::config::Config`]),
//! * every directory lives in a throw-away temp dir,
//! * a free loopback port is picked right before the bind,
//! * TLS uses a freshly generated self-signed certificate whose fingerprint is
//!   pinned by the client, which is also what a first-connect (`TOFU`) setup
//!   ends up doing.
//!
//! Environment notes:
//! * `rt-app` has no `[dev-dependencies]`, so `tempfile` is unavailable here;
//!   [`TempDir`] below is a tiny std-only stand-in.
//! * Screen capture depends on an interactive desktop session. Under a service
//!   account, RDP disconnect or a headless CI runner `xcap` may report "not
//!   available"; the capture phase then prints a note and skips instead of
//!   failing, matching how the product degrades.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rt_client::{ClientError, RemoteClient, Target};
use rt_core::config::{Config, ResolvedPaths, UserConfig};
use rt_core::logging::LogEventSink;
use rt_protocol::error::ErrorCode;
use rt_protocol::{
    CaptureRequest, CaptureTarget, DeleteRequest, ExecRequest, ImageFormat, MkdirRequest,
    RenameRequest, Scope, ShellKind,
};

/// Credentials created by this test; never reuse them outside it.
///
/// Two accounts are needed because the server gates host-wide endpoints on
/// scope: `exec`, screen capture and process listing require `full`, while
/// everything that lives inside the workspace jail is available to `workspace`.
/// Exercising both proves the gate instead of bypassing it.
const USER: &str = "e2e-workspace";
const PASSWORD: &str = "e2e-workspace-password";
const FULL_USER: &str = "e2e-full";
const FULL_PASSWORD: &str = "e2e-full-password";
const DEVICE: &str = "e2e-harness";

/// Generous enough for a cold Argon2 verify plus a first TLS handshake, tight
/// enough that a hung server fails the test instead of blocking CI.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// std-only temp directory (rt-app has no `tempfile` dev-dependency)
// ---------------------------------------------------------------------------

/// Process-wide counter so two tests can never pick the same directory.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A throw-away directory under the OS temp dir, removed on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "remote-terminal-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("cannot create the temp directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a lingering handle must not turn a green test red.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Asks the OS for a currently free loopback port.
///
/// The listener is dropped immediately, so the port is only *likely* to still be
/// free when the server binds it a few milliseconds later — good enough for a
/// test, and far more robust than a hard-coded port that may collide with a
/// developer's real server.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("cannot reserve a loopback port for the test");
    listener
        .local_addr()
        .expect("cannot read the reserved port")
        .port()
}

// ---------------------------------------------------------------------------
// fingerprint handling
// ---------------------------------------------------------------------------

/// Normalises a certificate fingerprint to the raw lowercase hex form the
/// client's pinning verifier expects.
///
/// `crypto::format_fingerprint` renders the human form (`AB:CD:…`), while
/// `crypto::client_config_pinned` takes plain hex; accepting both keeps the test
/// independent of which form the handle reports.
fn pin_hex(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '\t'))
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Status code plus protocol error code of a rejected request.
fn api_failure(err: &ClientError) -> (Option<u16>, Option<ErrorCode>) {
    (err.status(), err.api_body().map(|body| body.error.code))
}

// ---------------------------------------------------------------------------
// the end-to-end test
// ---------------------------------------------------------------------------

/// Starts the server on a free port with a workspace-scoped user, then exercises
/// every HTTP surface the client exposes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_tls_end_to_end_round_trip() {
    // --- 1. configuration -------------------------------------------------
    let base = TempDir::new("server");
    // `Config::validate` rejects port 0, so ask the OS for a free port first.
    // The port the server actually binds is read back from the handle below.
    let requested_port = free_port();

    let mut config = Config::default();
    config.server.enabled = true;
    config.server.bind = "127.0.0.1".to_string();
    config.server.port = requested_port;
    config.server.tls = true;
    config.server.auto_cert = true;
    // Two real Argon2id hashes: one account limited to the workspace (used for
    // the jail assertions) and one with the full scope (needed by exec/capture).
    config.server.users = vec![
        UserConfig {
            name: USER.to_string(),
            password_hash: rt_core::crypto::hash_password(PASSWORD)
                .expect("cannot hash the test password"),
            scope: "workspace".to_string(),
            enabled: true,
        },
        UserConfig {
            name: FULL_USER.to_string(),
            password_hash: rt_core::crypto::hash_password(FULL_PASSWORD)
                .expect("cannot hash the test password"),
            scope: "full".to_string(),
            enabled: true,
        },
    ];

    let report = config.validate();
    assert!(
        report.errors.is_empty(),
        "test configuration should be valid, got: {:?}",
        report.errors
    );

    // --- 2. directories ---------------------------------------------------
    let paths = ResolvedPaths::resolve(&config, base.path());
    paths
        .ensure_dirs()
        .expect("cannot create the data directories");
    // `ensure_dirs` deliberately leaves the workspace alone (the app creates it
    // only when `workspace.create` is honoured); the jail must exist up front.
    std::fs::create_dir_all(&paths.workspace_root).expect("cannot create the workspace root");
    let workspace_root = paths.workspace_root.clone();

    // --- 3. start the server ---------------------------------------------
    let state = rt_server::AppState::new(rt_server::ServerOptions {
        config,
        paths: paths.clone(),
        sink: LogEventSink::new(512),
        audit: None,
    })
    .expect("cannot build the shared server state");

    // The test owns the shutdown sender: dropping it would also end the serve
    // loop, so it has to stay alive until `handle.stop()` is called below.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = rt_server::serve(Arc::clone(&state), shutdown_rx)
        .await
        .expect("the server did not start");

    assert!(handle.tls, "server.tls = true must be honoured");
    let fingerprint = handle
        .fingerprint
        .clone()
        .expect("a self-signed certificate must come with a fingerprint");
    let pinned = pin_hex(&fingerprint);
    assert_eq!(
        pinned.len(),
        64,
        "expected a SHA-256 fingerprint, got `{fingerprint}`"
    );
    // Dial the port the socket was really bound to, so a lost race between
    // `free_port()` and the bind can never make the test hit a stranger.
    let port = handle.local_addr.port();
    assert_eq!(
        port, requested_port,
        "the server should honour the configured port"
    );
    assert!(
        handle.url.contains(&port.to_string()),
        "the advertised URL must carry the bound port: {}",
        handle.url
    );

    // --- 4. anonymous callers are refused --------------------------------
    let anonymous = RemoteClient::with_timeout(
        Target::new("127.0.0.1", port).with_fingerprint(pinned.clone()),
        CLIENT_TIMEOUT,
    )
    .expect("cannot build the anonymous client");

    // `/healthz` and `/api/v1/info` are the pre-login handshake endpoints.
    anonymous
        .health()
        .await
        .expect("/healthz must answer without credentials");
    let public_info = anonymous
        .info()
        .await
        .expect("/api/v1/info must answer without credentials");
    assert_eq!(
        pin_hex(public_info.cert_fingerprint.as_deref().unwrap_or_default()),
        pinned,
        "the public server description must advertise the pinned certificate"
    );

    let denied = anonymous
        .sysinfo()
        .await
        .expect_err("an unauthenticated caller must not read the host snapshot");
    let (status, code) = api_failure(&denied);
    assert_eq!(
        status,
        Some(401),
        "expected 401 for an anonymous request, got {denied:?}"
    );
    assert_eq!(
        code,
        Some(ErrorCode::Unauthorized),
        "expected error code `unauthorized`, got {code:?}"
    );

    // --- 5. login ---------------------------------------------------------
    let client = RemoteClient::with_timeout(
        Target::new("127.0.0.1", port).with_fingerprint(pinned.clone()),
        CLIENT_TIMEOUT,
    )
    .expect("cannot build the client");

    let login = client
        .login(USER, PASSWORD, DEVICE)
        .await
        .expect("login with the configured credentials failed");
    assert_eq!(login.username, USER);
    assert_eq!(login.scope, Scope::Workspace);
    assert!(
        !login.access_token.is_empty(),
        "login must return a session token"
    );
    assert!(login.expires_in_secs > 0, "sessions must expire eventually");
    assert!(
        client.is_authenticated(),
        "the client must remember the token"
    );

    let me = client
        .me()
        .await
        .expect("the session should describe itself");
    assert_eq!(me.username, USER);
    assert_eq!(me.scope, Scope::Workspace);

    let info = client.info().await.expect("info failed after login");
    assert_eq!(
        info.hostname,
        rt_core::util::hostname(),
        "the server must report the host it actually runs on"
    );
    assert_eq!(info.protocol_version, rt_protocol::PROTOCOL_VERSION);
    assert!(
        !info.endpoints.is_empty(),
        "the server should advertise endpoints"
    );

    // A second, independent session with the full scope. Host-wide endpoints
    // (exec, capture) refuse workspace-scoped sessions, so they are exercised
    // through this client and the refusal itself is asserted below.
    let full = RemoteClient::with_timeout(
        Target::new("127.0.0.1", port).with_fingerprint(pinned.clone()),
        CLIENT_TIMEOUT,
    )
    .expect("cannot build the privileged client");
    let full_login = full
        .login(FULL_USER, FULL_PASSWORD, DEVICE)
        .await
        .expect("login with the full-scope credentials failed");
    assert_eq!(full_login.scope, Scope::Full);
    assert_eq!(
        full.me()
            .await
            .expect("the full session should describe itself")
            .scope,
        Scope::Full
    );

    // --- 6. exec round-trip ----------------------------------------------
    let denied_exec = client
        .exec(&ExecRequest::new(ShellKind::Cmd, "echo hello"))
        .await
        .expect_err("a workspace-scoped session must not run commands");
    let (status, code) = api_failure(&denied_exec);
    assert_eq!(
        status,
        Some(403),
        "running commands requires the full scope, got {denied_exec:?}"
    );
    assert_eq!(code, Some(ErrorCode::Forbidden));

    let exec = full
        .exec(&ExecRequest::new(ShellKind::Cmd, "echo hello"))
        .await
        .expect("exec failed");
    assert_eq!(
        exec.exit_code, 0,
        "`echo hello` failed: stdout={:?} stderr={:?}",
        exec.stdout, exec.stderr
    );
    assert_eq!(
        exec.stdout.trim(),
        "hello",
        "unexpected exec stdout {:?}",
        exec.stdout
    );
    assert!(!exec.timed_out, "a trivial command must not time out");

    // --- 7. filesystem round-trip ----------------------------------------
    let remote_dir = "e2e-dir";
    let remote_file = "e2e-dir\\hello.txt";
    let remote_moved = "e2e-dir\\renamed.txt";
    let local_file = base.path().join("upload.txt");
    let payload = b"hello from the end-to-end test\n";
    std::fs::write(&local_file, payload).expect("cannot write the local upload file");

    let created = client
        .mkdir(&MkdirRequest {
            path: remote_dir.to_string(),
            create_parents: true,
            allow_existing: true,
        })
        .await
        .expect("mkdir failed");
    assert!(created.is_dir, "mkdir must return a directory entry");

    let uploaded = client
        .upload_file(&local_file, remote_file, true, true)
        .await
        .expect("upload failed");
    assert_eq!(
        uploaded.size,
        payload.len() as u64,
        "uploaded size mismatch"
    );

    let listing = client.list(remote_dir).await.expect("list failed");
    let entry = listing
        .entries
        .iter()
        .find(|entry| entry.name == "hello.txt")
        .expect("the uploaded file must appear in the listing");
    assert!(!entry.is_dir, "the uploaded file must not be a directory");
    assert_eq!(entry.size, payload.len() as u64);

    let read = client
        .read_file(remote_file, None, None)
        .await
        .expect("read_file failed");
    assert_eq!(read.size, payload.len() as u64);
    assert_eq!(
        read.text.as_deref(),
        Some(std::str::from_utf8(payload).expect("payload is valid UTF-8")),
        "the bytes must survive the round-trip unchanged"
    );

    let stat = client.stat(remote_file).await.expect("stat failed");
    assert_eq!(stat.entry.size, payload.len() as u64);
    assert!(!stat.entry.is_dir);

    client
        .rename(&RenameRequest {
            from: remote_file.to_string(),
            to: remote_moved.to_string(),
            overwrite: true,
        })
        .await
        .expect("rename failed");
    assert_eq!(
        client
            .stat(remote_moved)
            .await
            .expect("stat of the moved file failed")
            .entry
            .size,
        payload.len() as u64
    );
    let stale = client
        .stat(remote_file)
        .await
        .expect_err("the old path must be gone after a rename");
    assert_eq!(
        stale.status(),
        Some(404),
        "expected 404 for the stale path, got {stale:?}"
    );

    let deleted = client
        .delete(&DeleteRequest {
            paths: vec![remote_moved.to_string()],
            recursive: false,
            even_if_readonly: true,
        })
        .await
        .expect("delete failed");
    assert_eq!(
        deleted.deleted.len(),
        1,
        "one file should have been deleted"
    );
    assert!(
        deleted.failed.is_empty(),
        "deletion reported failures: {:?}",
        deleted.failed
    );

    // The workspace jail must refuse paths that try to climb out of it.
    for probe in [
        "..\\..\\Windows",
        "..\\..\\..\\..\\Windows\\System32",
        "C:\\Windows\\System32",
    ] {
        let err = client
            .list(probe)
            .await
            .expect_err("a workspace-scoped session must not escape its jail");
        let (status, code) = api_failure(&err);
        assert!(
            matches!(
                code,
                Some(ErrorCode::ScopeViolation) | Some(ErrorCode::InvalidPath)
            ),
            "`{probe}` must be rejected as a scope violation or invalid path, got {code:?}"
        );
        assert!(
            status == Some(400) || status == Some(403),
            "`{probe}` must answer 400/403, got {status:?}"
        );
    }

    // --- 8. telemetry -----------------------------------------------------
    let snapshot = client.sysinfo().await.expect("sysinfo failed");
    assert!(
        !snapshot.hostname.is_empty(),
        "sysinfo must report a hostname"
    );
    assert!(
        !snapshot.os_name.is_empty(),
        "sysinfo must report an OS name"
    );
    assert!(
        !snapshot.arch.is_empty(),
        "sysinfo must report an architecture"
    );

    let quick = client.quick_status().await.expect("quick_status failed");
    assert!(
        quick.memory_total_bytes > 0,
        "the machine must have some memory"
    );
    assert!(
        quick.process_count > 0,
        "at least this process should be counted"
    );
    assert!(
        !quick.sampled_at.is_empty(),
        "quick status must be timestamped"
    );

    // --- 9. scope boundary: host-wide surfaces are full-scope only -------
    // `exec` is covered by the round-trip section above; these are the rest of
    // the host-wide endpoints. A 403 alone would be ambiguous, so the protocol
    // error code and the human explanation are checked too.
    let denials = [
        (
            "capture",
            client
                .capture(&CaptureRequest::png(CaptureTarget::Primary))
                .await
                .err(),
        ),
        (
            "capture/raw",
            client.capture_raw("primary", "png", 75, None).await.err(),
        ),
        ("capture/windows", client.windows().await.err()),
        (
            "sysinfo/processes",
            client.processes(10, None, "cpu", true).await.err(),
        ),
    ];
    for (what, outcome) in denials {
        let err = match outcome {
            Some(err) => err,
            None => panic!("a workspace-scoped session must not reach `{what}`"),
        };
        let (status, code) = api_failure(&err);
        assert_eq!(status, Some(403), "`{what}` must answer 403, got {err:?}");
        assert_eq!(
            code,
            Some(ErrorCode::Forbidden),
            "`{what}` must be forbidden, got {code:?}"
        );
        let message = err
            .api_body()
            .map(|body| body.error.message.clone())
            .unwrap_or_default();
        assert!(
            message.contains("full scope"),
            "`{what}` should explain the missing scope, got {message:?}"
        );
    }

    // Discovery and telemetry stay available to a workspace-only user: browsing
    // the host must not require the power to run commands on it.
    assert!(
        client.shells().await.is_ok(),
        "listing the available shells is discovery, not execution"
    );
    assert!(
        client.screens().await.is_ok(),
        "listing monitors is discovery; only pixels themselves need the full scope"
    );

    // --- 10. capture (skipped when the desktop cannot render pixels) -----
    // `is_available()` only proves that monitors can be *enumerated*: a locked
    // or disconnected session still lists them but then refuses to hand over
    // pixels (`xcap` reports an invalid display handle). Probe the real capture
    // path in-process first, so the suite degrades on such desktops instead of
    // failing the whole round-trip.
    let mut desktop_ready = false;
    if rt_core::capture::is_available() {
        match rt_core::capture::capture(&CaptureRequest::png(CaptureTarget::Primary)) {
            Ok(_) => desktop_ready = true,
            Err(err) => eprintln!("e2e: the desktop cannot hand over pixels right now ({err})"),
        }
    }
    if !desktop_ready {
        eprintln!(
            "e2e: no capturable desktop session (service account, locked/RDP or headless runner); \
             skipping the screen-capture assertions"
        );
    } else {
        let screens = full
            .screens()
            .await
            .expect("the screen list must be readable");
        assert!(
            !screens.is_empty(),
            "an available desktop must report at least one screen"
        );
        assert!(
            screens.iter().any(|screen| screen.is_primary),
            "exactly one screen should be flagged primary"
        );

        let captured = full
            .capture(&CaptureRequest::png(CaptureTarget::Primary))
            .await
            .expect("capturing the primary screen failed");
        assert_eq!(captured.meta.format, ImageFormat::Png);
        assert!(
            captured.meta.bytes > 1000,
            "a full-screen PNG should exceed 1 kB, got {} bytes",
            captured.meta.bytes
        );
        let bytes = captured
            .into_bytes()
            .expect("the base64 payload must decode");
        assert_eq!(
            &bytes[..8],
            b"\x89PNG\r\n\x1a\n",
            "the raw endpoint payload must be a PNG"
        );

        // The raw endpoint streams the image itself (no base64 inside JSON) and
        // must honour the resize caps.
        let raw = full
            .capture_raw("primary", "jpeg", 75, Some(320))
            .await
            .expect("raw capture failed");
        assert_eq!(&raw[..2], &[0xFF, 0xD8], "expected a JPEG header");
        let decoded =
            image::load_from_memory(&raw).expect("the raw payload must decode as an image");
        assert!(
            decoded.width() <= 320,
            "max_width=320 must cap the width, got {}",
            decoded.width()
        );
        eprintln!(
            "e2e: captured {} screen(s), raw JPEG {}x{} ({} bytes)",
            screens.len(),
            decoded.width(),
            decoded.height(),
            raw.len()
        );
    }

    // --- 11. shutdown -----------------------------------------------------
    handle.stop();
    let after = RemoteClient::with_timeout(
        Target::new("127.0.0.1", port).with_fingerprint(pinned),
        Duration::from_secs(3),
    )
    .expect("cannot build the shutdown probe");

    let mut closed = false;
    for _ in 0..30 {
        if after.health().await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(closed, "the server kept answering after `handle.stop()`");

    // The workspace is still readable from the test (we own the files).
    assert!(
        workspace_root.is_dir(),
        "the workspace root must still exist: {workspace_root:?}"
    );
}

// ---------------------------------------------------------------------------
// helpers under test
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_normalisation_accepts_display_and_hex_forms() {
    let hex = "a1b2c3d4".repeat(8); // 64 chars
    let display = rt_core::crypto::format_fingerprint(&hex);
    assert_ne!(display, hex, "the display form is colon separated");
    assert_eq!(
        pin_hex(&display),
        hex,
        "the display form must pin correctly"
    );
    assert_eq!(
        pin_hex(&hex.to_uppercase()),
        hex,
        "uppercase hex must pin correctly"
    );
    assert_eq!(pin_hex(&hex), hex, "hex must pass through unchanged");
}
