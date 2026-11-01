//! Adversarial end-to-end tests for the workspace path jail
//! ([`rt_core::pathscope::PathGuard`]).
//!
//! The single contract these tests enforce is:
//!
//! > For **every** client-supplied string, `resolve` either fails, or returns a
//! > path that really lives inside the configured root.
//!
//! "Accepted *and* outside the root" is the only genuine failure. Every test
//! therefore uses one of two helpers:
//!
//! * [`expect_rejected_or_contained`] — the input may be rejected, or accepted
//!   as long as the result is provably inside the jail;
//! * [`expect_rejected`] — the input belongs to a category the guard documents
//!   as refused (UNC, device namespace, ADS, reserved names, `..` escapes, …);
//!   even here a real escape is diagnosed first, so a vulnerability is reported
//!   as `JAIL ESCAPE` rather than as a wrong expectation.
//!
//! Containment is verified twice: through the public `is_inside` API and,
//! independently, by canonicalising the deepest existing ancestor of the
//! resolved path and comparing it with the canonical root. The second check is
//! deliberately hand-written (it does not reuse guard internals) so a bug in
//! the prefix comparison cannot hide a bug in the resolver.

use std::path::{Path, PathBuf};

use rt_core::pathscope::PathGuard;
use rt_protocol::Scope;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A throw-away workspace jail: `<temp>/` with `sub/b.txt` and `a.txt` inside.
struct Jail {
    /// Kept alive so the directory outlives every assertion.
    _dir: tempfile::TempDir,
    root: PathBuf,
    guard: PathGuard,
}

impl Jail {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary workspace root");
        let root = plain(&std::fs::canonicalize(dir.path()).expect("canonical root"));
        std::fs::create_dir_all(root.join("sub")).expect("create sub");
        std::fs::write(root.join("a.txt"), b"hi").expect("write a.txt");
        std::fs::write(root.join("sub").join("b.txt"), b"hi").expect("write sub/b.txt");
        let guard = PathGuard::new(Scope::Workspace, Some(&root)).expect("workspace guard");
        Self {
            _dir: dir,
            root,
            guard,
        }
    }

    fn resolve(&self, input: &str) -> rt_core::error::Result<PathBuf> {
        self.guard.resolve(input)
    }
}

/// Strips the verbatim `\\?\` prefix that `canonicalize` adds on Windows.
fn plain(path: &Path) -> PathBuf {
    match path.to_string_lossy().strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}

/// Case-insensitive component list, mirroring Windows' path comparison rules.
fn components_ci(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .replace('/', "\\")
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect()
}

fn is_within(path: &Path, root: &Path) -> bool {
    let candidate = components_ci(path);
    let base = components_ci(root);
    candidate.len() >= base.len() && candidate[..base.len()] == base[..]
}

/// Independent containment proof: canonicalise the deepest existing ancestor of
/// `resolved` and require it to sit under `root`.
#[track_caller]
fn assert_truly_inside(resolved: &Path, root: &Path, input: &str) {
    let mut cursor = resolved.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&cursor) {
            let real = plain(&real);
            assert!(
                is_within(&real, root),
                "JAIL ESCAPE: {input:?} resolved to {} whose existing ancestor {} \
                 is outside the workspace root {}",
                resolved.display(),
                real.display(),
                root.display()
            );
            return;
        }
        if !cursor.pop() {
            panic!(
                "{input:?}: resolved path {} has no existing ancestor to verify",
                resolved.display()
            );
        }
    }
}

/// The input may be rejected, otherwise it must resolve inside the jail.
#[track_caller]
fn expect_rejected_or_contained(jail: &Jail, input: &str) {
    if let Ok(resolved) = jail.resolve(input) {
        assert!(
            jail.guard.is_inside(&resolved),
            "JAIL ESCAPE: {input:?} resolved to {} which `is_inside` refuses (root {})",
            resolved.display(),
            jail.root.display()
        );
        assert_truly_inside(&resolved, &jail.root, input);
    }
}

/// The input must be refused; a real escape is reported before the expectation.
#[track_caller]
fn expect_rejected(jail: &Jail, input: &str) {
    if let Ok(resolved) = jail.resolve(input) {
        assert_truly_inside(&resolved, &jail.root, input);
        panic!(
            "{input:?} was accepted as {} but this case must be rejected",
            resolved.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Positive controls — the jail must not be "secure" by refusing everything
// ---------------------------------------------------------------------------

#[test]
fn control_relative_path_inside_root_is_allowed() {
    let jail = Jail::new();
    let resolved = jail.resolve("sub\\b.txt").expect("relative path inside the jail");
    assert_truly_inside(&resolved, &jail.root, "sub\\b.txt");
    assert_eq!(jail.guard.display(&resolved), "\\sub\\b.txt");
}

#[test]
fn control_virtual_root_relative_path_is_allowed() {
    let jail = Jail::new();
    let resolved = jail.resolve("\\sub\\b.txt").expect("virtual root-relative path");
    assert_truly_inside(&resolved, &jail.root, "\\sub\\b.txt");
}

#[test]
fn control_absolute_path_inside_root_is_allowed() {
    let jail = Jail::new();
    let absolute = jail.root.join("a.txt");
    let resolved = jail
        .resolve(&absolute.to_string_lossy())
        .expect("absolute path inside the jail");
    assert_truly_inside(&resolved, &jail.root, "absolute a.txt");
    assert_eq!(jail.guard.display(&resolved), "\\a.txt");
}

#[test]
fn control_dot_resolves_to_the_root() {
    let jail = Jail::new();
    let resolved = jail.resolve(".").expect("`.` must mean the root");
    assert_truly_inside(&resolved, &jail.root, ".");
    assert!(
        is_within(&resolved, &jail.root) && is_within(&jail.root, &resolved),
        "`.` must resolve to the root itself, got {}",
        resolved.display()
    );
}

#[test]
fn control_backslash_resolves_to_the_root() {
    let jail = Jail::new();
    let resolved = jail.resolve("\\").expect("`\\` must mean the root");
    assert_truly_inside(&resolved, &jail.root, "\\");
}

// ---------------------------------------------------------------------------
// `..` traversal
// ---------------------------------------------------------------------------

#[test]
fn traversal_dotdot_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "..");
}

#[test]
fn traversal_dotdot_with_trailing_separator_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "..\\");
}

#[test]
fn traversal_double_dotdot_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "..\\..");
}

#[test]
fn traversal_dotdot_windows_system32_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "..\\..\\..\\windows\\system32");
}

#[test]
fn traversal_from_subdirectory_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "sub\\..\\..\\x");
}

#[test]
fn traversal_with_forward_slashes_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a/../../..");
}

#[test]
fn traversal_through_a_dotdir_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, ".\\..\\..\\Windows");
}

#[test]
fn traversal_with_mixed_separators_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "..\\../..\\../Windows");
}

#[test]
fn traversal_from_root_relative_form_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\..\\..\\x");
}

#[test]
fn traversal_root_relative_to_system32_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\..\\..\\..\\Windows\\System32\\cmd.exe");
}

#[test]
fn traversal_with_leading_slash_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "/../..");
}

#[test]
fn traversal_padded_with_whitespace_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, " .. ");
    expect_rejected(&jail, "  ..\\..\\Windows  ");
    expect_rejected(&jail, " \\..\\..\\x ");
}

// ---------------------------------------------------------------------------
// UNC / network shares
// ---------------------------------------------------------------------------

#[test]
fn unc_backslash_share_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\host\\share");
}

#[test]
fn unc_forward_slash_share_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "//host/share");
}

#[test]
fn unc_file_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\host\\share\\x");
}

#[test]
fn unc_verbatim_form_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\?\\UNC\\host\\share\\x");
}

// ---------------------------------------------------------------------------
// Device namespaces
// ---------------------------------------------------------------------------

#[test]
fn device_namespace_globalroot_is_rejected() {
    let jail = Jail::new();
    expect_rejected(
        &jail,
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\x",
    );
}

#[test]
fn device_namespace_physicaldrive_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\.\\PhysicalDrive0");
}

#[test]
fn device_namespace_drive_form_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\.\\C:\\Windows");
}

#[test]
fn device_question_namespace_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "\\\\.\\?\\C:\\");
}

#[test]
fn verbatim_disk_path_cannot_escape() {
    let jail = Jail::new();
    // `\\?\C:\Windows` is not a device *namespace*, and the resolver may treat
    // it as a literal name under the root — it must never reach C:\Windows.
    expect_rejected_or_contained(&jail, "\\\\?\\C:\\Windows");
    expect_rejected_or_contained(&jail, "\\\\?\\C:\\Windows\\win.ini");
}

// ---------------------------------------------------------------------------
// Drive-absolute and drive-relative paths
// ---------------------------------------------------------------------------

#[test]
fn absolute_path_outside_the_jail_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "C:\\Windows\\win.ini");
}

#[test]
fn absolute_forward_slash_path_outside_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "C:/Windows/win.ini");
}

#[test]
fn drive_root_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "C:\\");
}

#[test]
fn drive_relative_path_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "C:relative");
    expect_rejected(&jail, "C:a\\b");
}

// ---------------------------------------------------------------------------
// Alternate data streams
// ---------------------------------------------------------------------------

#[test]
fn alternate_data_stream_is_rejected() {
    let jail = Jail::new();
    for input in ["file.txt:stream", "a:b", "sub\\b.txt::$DATA", "a.txt:"] {
        expect_rejected(&jail, input);
    }
}

// ---------------------------------------------------------------------------
// Reserved device names
// ---------------------------------------------------------------------------

#[test]
fn reserved_device_names_are_rejected() {
    let jail = Jail::new();
    for input in [
        "CON",
        "con",
        "CON.txt",
        "NUL",
        "nul.txt",
        "COM1",
        "COM9",
        "LPT1",
        "LPT9",
        "AUX",
        "aux.c",
        "PRN",
        "prn.log",
        "sub\\CON",
        "sub\\nul.txt",
        "\\CON",
    ] {
        expect_rejected(&jail, input);
    }
}

// ---------------------------------------------------------------------------
// Trailing dots / spaces (Windows silently trims them)
// ---------------------------------------------------------------------------

#[test]
fn trailing_dot_component_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a.");
}

#[test]
fn trailing_dot_in_nested_component_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a\\b.");
}

#[test]
fn trailing_dot_in_first_component_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a.\\b");
}

#[test]
fn trailing_dot_with_spaces_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a. .");
}

#[test]
fn trailing_space_inside_a_component_is_rejected() {
    let jail = Jail::new();
    expect_rejected(&jail, "a\\b \\c");
}

#[test]
fn trailing_space_of_the_whole_input_is_trimmed_not_escaped() {
    let jail = Jail::new();
    let resolved = jail.resolve("a.txt ").expect("the outer space is trimmed");
    assert_truly_inside(&resolved, &jail.root, "a.txt ");
    assert!(resolved.ends_with("a.txt"));
}

// ---------------------------------------------------------------------------
// Control characters, empty and whitespace input
// ---------------------------------------------------------------------------

#[test]
fn null_and_control_characters_are_rejected() {
    let jail = Jail::new();
    for control in ['\u{0}', '\u{1}', '\u{7}', '\u{1f}', '\u{7f}', '\n', '\r', '\t'] {
        let input = format!("a{control}b");
        expect_rejected(&jail, &input);
    }
    expect_rejected(&jail, "\u{0}");
}

#[test]
fn empty_and_whitespace_input_is_rejected() {
    let jail = Jail::new();
    for input in ["", " ", "   ", "\t", "\r\n", "  \t\r\n  "] {
        expect_rejected(&jail, input);
    }
}

#[test]
fn exotic_whitespace_never_escapes() {
    let jail = Jail::new();
    expect_rejected_or_contained(&jail, "\u{a0}");
    expect_rejected_or_contained(&jail, "\u{3000}");
}

#[test]
fn invalid_windows_characters_are_rejected() {
    let jail = Jail::new();
    for input in ["a|b", "a*b", "a?b", "a<b", "a>b", "a\"b", "sub\\a|b.txt"] {
        expect_rejected(&jail, input);
    }
}

// ---------------------------------------------------------------------------
// Length limits
// ---------------------------------------------------------------------------

#[test]
fn absurdly_long_input_is_rejected() {
    let jail = Jail::new();
    for length in [32_001usize, 33_000, 40_000] {
        expect_rejected(&jail, &"a".repeat(length));
    }
    // Deeply nested but syntactically "normal": same length limit applies.
    expect_rejected(&jail, &"a\\".repeat(17_000));
}

#[test]
fn boundary_length_inputs_stay_inside() {
    let jail = Jail::new();
    let mid = "b".repeat(250);
    let nested = format!("{}\\{}", "c".repeat(120), "d".repeat(120));
    let deep = "a/".repeat(130) + "leaf";
    let checks = [
        "a".repeat(31_900),
        "a".repeat(32_000),
        "a".repeat(32_001), // rejected by the length guard; harmless either way
        mid,
        nested,
        deep,
    ];
    for input in &checks {
        expect_rejected_or_contained(&jail, input);
    }
}

// ---------------------------------------------------------------------------
// Unicode look-alikes and encodings
// ---------------------------------------------------------------------------

#[test]
fn unicode_variants_stay_inside_the_jail() {
    let jail = Jail::new();
    for input in [
        "a\u{ff41}",                 // fullwidth 'a'
        "\u{ff0e}",                  // fullwidth full stop
        "\u{1d2c}",                  // modifier letter capital A
        "\u{202e}txt.exe",           // right-to-left override
        "zero\u{200b}width",         // zero-width space
        "\u{1f642}\\file.txt",       // emoji component
        "\u{ff0e}\\..\\..\\Windows", // fullwidth dot as a raw `..` disguise
        "\u{ff41}\\.\\..\\..\\x",
        "..\u{3002}\\..",            // ideographic full stop
    ] {
        expect_rejected_or_contained(&jail, input);
    }
}

#[test]
fn case_variants_do_not_open_a_hole() {
    let jail = Jail::new();
    expect_rejected(&jail, "C:\\WINDOWS\\win.ini");
    expect_rejected(&jail, "c:\\windows\\WIN.INI");
    expect_rejected_or_contained(&jail, "WINDOWS\\win.ini");
    expect_rejected_or_contained(&jail, "Windows/win.ini");

    // The same root spelled in upper case must still be the root.
    let upper = jail.root.to_string_lossy().to_uppercase();
    expect_rejected_or_contained(&jail, &format!("{upper}\\sub\\b.txt"));
    expect_rejected_or_contained(&jail, &format!("{upper}\\..\\..\\Windows\\win.ini"));
}

// ---------------------------------------------------------------------------
// Short names and non-expanded syntax
// ---------------------------------------------------------------------------

#[test]
fn short_names_and_tildes_stay_inside() {
    let jail = Jail::new();
    for input in [
        "PROGRA~1",
        "PROGRA~1\\x",
        "8dot3~1.txt",
        "sub\\~$doc.docx",
    ] {
        expect_rejected_or_contained(&jail, input);
    }
}

#[test]
fn environment_variables_are_not_expanded() {
    let jail = Jail::new();
    for input in [
        "%WINDIR%\\system32",
        "$env:windir\\x",
        "%TEMP%\\..\\..\\Windows",
        "~\\x",
    ] {
        expect_rejected_or_contained(&jail, input);
    }
}

// ---------------------------------------------------------------------------
// resolve_existing / ensure_inside
// ---------------------------------------------------------------------------

#[test]
fn resolve_existing_rejects_missing_and_outside_paths() {
    let jail = Jail::new();
    assert!(jail
        .guard
        .resolve_existing("sub\\b.txt")
        .is_ok());
    assert!(jail.guard.resolve_existing("missing.txt").is_err());
    assert!(jail.guard.resolve_existing("..\\..\\Windows\\win.ini").is_err());
    assert!(jail
        .guard
        .resolve_existing("C:\\Windows\\win.ini")
        .is_err());
}

#[test]
fn ensure_inside_refuses_outside_paths() {
    let jail = Jail::new();
    assert!(jail.guard.ensure_inside(&jail.root.join("a.txt")).is_ok());
    assert!(jail
        .guard
        .ensure_inside(Path::new("C:\\Windows\\win.ini"))
        .is_err());
}

// ---------------------------------------------------------------------------
// Real symlinks / junctions
// ---------------------------------------------------------------------------

/// Creates a directory link, preferring a real symlink and falling back to a
/// junction (`mklink /J`), which works without the symlink privilege.
fn try_dir_link(link: &Path, target: &Path) -> bool {
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return true;
    }
    let output = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.display().to_string(),
            &target.display().to_string(),
        ])
        .output();
    matches!(output, Ok(out) if out.status.success()) && link.exists()
}

#[test]
fn symlink_or_junction_escape_is_blocked() {
    let jail = Jail::new();

    // A directory that is *outside* the jail and contains a real file.
    let outside = tempfile::tempdir().expect("outside dir");
    let outside_root = plain(&std::fs::canonicalize(outside.path()).expect("canonical outside"));
    std::fs::write(outside_root.join("secret.txt"), b"top secret").expect("write secret");

    let root_link = jail.root.join("escape");
    let nested_link = jail.root.join("sub").join("escape");
    let made_root = try_dir_link(&root_link, &outside_root);
    let made_nested = try_dir_link(&nested_link, &outside_root);
    if !made_root && !made_nested {
        eprintln!(
            "skipping symlink/junction escape checks: cannot create a directory link \
             (needs the symlink privilege or junction support)"
        );
        return;
    }

    let mut cases: Vec<(&str, &str)> = Vec::new();
    if made_root {
        // Sanity: the link really does expose the secret file.
        assert_eq!(
            std::fs::read(root_link.join("secret.txt")).expect("read through the link"),
            b"top secret"
        );
        cases.push(("escape", "the link entry itself"));
        cases.push(("escape\\secret.txt", "a file behind the link"));
        cases.push(("escape\\pwn.txt", "a write target behind the link"));
    }
    if made_nested {
        assert_eq!(
            std::fs::read(nested_link.join("secret.txt")).expect("read through the nested link"),
            b"top secret"
        );
        cases.push(("sub\\escape", "a nested link entry"));
        cases.push(("sub\\escape\\secret.txt", "a file behind a nested link"));
    }

    for (input, what) in cases {
        // Reading through the link must be impossible: there is no resolvable
        // path at all.
        expect_rejected(&jail, input);
        assert!(
            jail.guard.resolve_existing(input).is_err(),
            "{what} must not exist for resolve_existing"
        );
    }

    // The absolute form of the same path must be refused too.
    if made_root {
        let absolute = root_link.join("secret.txt");
        expect_rejected(&jail, &absolute.to_string_lossy());
        // `..` after a link must not silently re-enter the jail either.
        expect_rejected_or_contained(&jail, "escape\\..\\..\\..\\Windows\\win.ini");
    }
}

// ---------------------------------------------------------------------------
// S-08 follow-up: the control-file denylist must also survive *indirect* paths
// ---------------------------------------------------------------------------

/// The denylist protects `config.toml` and the TLS key from being read or
/// overwritten, but a session could still reach them indirectly: delete the
/// install directory recursively, move it elsewhere, or copy the tree (which
/// duplicates the password hashes and the private key somewhere readable).
///
/// `protect_paths` is a process-wide `OnceLock`, which is why this lives in its
/// own integration binary instead of in the `pathscope` unit tests.
#[test]
fn control_paths_cannot_be_reached_through_a_parent_operation() {
    use rt_core::fsops;
    use rt_core::pathscope::{check_protected_subtree, protect_paths};
    use rt_core::RtError;
    use rt_protocol::{CopyRequest, DeleteRequest, RenameRequest};

    let dir = tempfile::tempdir().expect("temp install dir");
    let base = plain(&std::fs::canonicalize(dir.path()).expect("canonical base"));
    let out = tempfile::tempdir().expect("temp destination dir");
    std::fs::create_dir_all(base.join("tls")).expect("create tls");
    std::fs::create_dir_all(base.join("work")).expect("create work");
    std::fs::write(
        base.join("config.toml"),
        b"password_hash = \"$argon2id$v=19$...\"",
    )
    .expect("write");
    std::fs::write(base.join("tls").join("server.key.pem"), b"PRIVATE").expect("write key");

    protect_paths([base.join("config.toml"), base.join("tls")]);

    let guard = PathGuard::new(Scope::Full, None).expect("full guard");
    let shown = |path: &Path| path.to_string_lossy().into_owned();

    // Direct access stays refused, including through the protected directory.
    assert!(guard.resolve(&shown(&base.join("config.toml"))).is_err());
    assert!(guard.resolve(&shown(&base.join("tls"))).is_err());
    assert!(guard.resolve(&shown(&base.join("tls").join("server.key.pem"))).is_err());

    // Reading *around* the control files keeps working: the install directory
    // is listable, and so is a sibling subtree and a drive root.
    assert!(guard.resolve(&shown(&base)).is_ok());
    assert!(guard.resolve(&shown(&base.join("work"))).is_ok());

    // …but the operations that would carry the control files away are refused.
    assert!(check_protected_subtree(&base).is_err());
    assert!(check_protected_subtree(&base.join("work")).is_ok());

    let denied = |err: RtError, what: &str| {
        assert!(
            matches!(err, RtError::PolicyDenied(_)),
            "{what} must be refused as a policy violation, got {err:?}"
        );
    };

    let delete = fsops::delete(
        &guard,
        &DeleteRequest {
            paths: vec![shown(&base)],
            recursive: true,
            even_if_readonly: true,
        },
    )
    .expect("delete reports per-path failures instead of erroring");
    assert!(delete.deleted.is_empty(), "nothing may be deleted");
    assert_eq!(delete.failed.len(), 1, "exactly one path is reported failed");
    assert!(
        delete.failed[0].message.contains("server control path"),
        "unexpected message: {}",
        delete.failed[0].message
    );
    assert!(base.join("config.toml").exists(), "config.toml must survive");

    let err = fsops::rename(
        &guard,
        &RenameRequest {
            from: shown(&base),
            to: shown(&base.with_file_name("moved")),
            overwrite: true,
        },
    )
    .expect_err("moving the install directory must fail");
    denied(err, "rename of the install directory");
    assert!(base.join("config.toml").exists(), "config.toml must survive");

    let elsewhere = plain(
        &std::fs::canonicalize(out.path()).expect("canonical destination root"),
    )
    .join("copy-of-install");
    let err = fsops::copy(
        &guard,
        &CopyRequest {
            from: shown(&base),
            to: shown(&elsewhere),
            overwrite: false,
            recursive: true,
        },
    )
    .expect_err("copying the install directory must fail");
    denied(err, "copy of the install directory");
    assert!(
        !elsewhere.join("config.toml").exists(),
        "the copy must not have produced a readable config.toml"
    );

    // Copying a tree that holds no control file is still allowed.
    std::fs::write(base.join("work").join("notes.txt"), b"hello").expect("write");
    let copied = fsops::copy(
        &guard,
        &CopyRequest {
            from: shown(&base.join("work")),
            to: shown(&elsewhere),
            overwrite: false,
            recursive: true,
        },
    )
    .expect("copying an ordinary directory works");
    assert_eq!(copied.size, 5);
}
