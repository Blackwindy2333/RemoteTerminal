//! Windows ACL hardening for files that must stay private to this account.
//!
//! A file created under `%TEMP%` or a user profile inherits the parent
//! directory's ACEs, which on a default Windows install includes
//! `BUILTIN\Users` (read) and sometimes `Authenticated Users`. For the TLS
//! private key and the configuration file (which holds password hashes and API
//! key digests) that is too permissive: any other local account could read the
//! key and impersonate the server.
//!
//! [`restrict_to_current_user`] replaces the DACL with an explicit, protected
//! list: the owner (`OW`), `SYSTEM` and `BUILTIN\Administrators` get full
//! control, nobody else gets anything, and inheritance is switched off so a
//! later move of the parent directory cannot widen it again. This is the
//! programmatic equivalent of
//! `icacls <path> /inheritance:r /grant:r "%USERNAME%":F SYSTEM:F Administrators:F`.

use std::path::Path;

use crate::error::{Result, RtError};

/// SDDL applied to protected files: a protected DACL (`P`) granting full
/// control (`FA`) to the owner (`OW`), `SYSTEM` (`SY`) and administrators
/// (`BA`). Every inherited ACE is dropped because the DACL is protected.
const PRIVATE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    pub type Bool = i32;
    pub type Dword = u32;
    pub type Handle = *mut c_void;

    pub const SE_FILE_OBJECT: Dword = 1;
    /// `DACL_SECURITY_INFORMATION` — replace the DACL.
    pub const DACL_SECURITY_INFORMATION: Dword = 0x0000_0004;

    #[link(name = "advapi32")]
    extern "system" {
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: Dword,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut Dword,
        ) -> Bool;

        pub fn GetSecurityDescriptorDacl(
            security_descriptor: *const c_void,
            dacl_present: *mut Bool,
            dacl: *mut *mut c_void,
            dacl_defaulted: *mut Bool,
        ) -> Bool;

        pub fn SetNamedSecurityInfoW(
            object_name: *mut u16,
            object_type: Dword,
            security_info: Dword,
            sid_owner: *mut c_void,
            sid_group: *mut c_void,
            dacl: *mut c_void,
            sacl: *mut c_void,
        ) -> Dword;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(mem: Handle) -> Handle;
        pub fn GetLastError() -> Dword;
    }

    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

/// Remove inherited permissions from `path` and leave full control to the
/// current user, `SYSTEM` and administrators only.
///
/// Works for files and directories. The path must already exist.
#[cfg(windows)]
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    use win::*;

    if !path.exists() {
        return Err(RtError::not_found(format!(
            "cannot harden permissions of {}: no such file",
            path.display()
        )));
    }

    // 1. Build a security descriptor from the SDDL template.
    let sddl = win::wide(PRIVATE_SDDL);
    let mut sd: Handle = std::ptr::null_mut();
    let mut sd_size: Dword = 0;
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` receives an
    // owned buffer that we release with `LocalFree` below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut sd,
            &mut sd_size,
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(RtError::Internal(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed (Win32 {})",
            unsafe { GetLastError() }
        )));
    }
    // From here on the descriptor must be freed on every path.
    struct Descriptor(Handle);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the pointer came from the SDDL conversion above and is
            // released exactly once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let descriptor = Descriptor(sd);

    // 2. Pull the DACL out of it.
    let mut present: Bool = 0;
    let mut defaulted: Bool = 0;
    let mut dacl: Handle = std::ptr::null_mut();
    // SAFETY: `descriptor.0` is a valid absolute security descriptor; the
    // out-parameters are stack locals.
    let ok = unsafe {
        GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
    };
    if ok == 0 || present == 0 || dacl.is_null() {
        return Err(RtError::Internal(
            "the generated security descriptor has no DACL".into(),
        ));
    }

    // 3. Apply it, replacing the inherited list.
    let mut target = win::wide_path(path);
    // SAFETY: `target` is NUL-terminated and lives for the call; `dacl` belongs
    // to the descriptor, which outlives this call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            target.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(RtError::Internal(format!(
            "SetNamedSecurityInfoW({}) failed (Win32 {status})",
            path.display()
        )));
    }
    Ok(())
}

/// Non-Windows stub: POSIX permissions are handled by the umask, so there is
/// nothing to tighten here.
#[cfg(not(windows))]
pub fn restrict_to_current_user(_path: &Path) -> Result<()> {
    Ok(())
}

/// Best-effort variant: logs a warning instead of failing the caller.
///
/// Used where the file itself is already written and a permission failure
/// should not undo useful work (for example a rotated log file).
pub fn restrict_or_warn(path: &Path) {
    if let Err(err) = restrict_to_current_user(path) {
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "could not restrict file permissions to the current account"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardens_an_existing_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("secret.pem");
        std::fs::write(&file, b"top secret").expect("write");

        restrict_to_current_user(&file).expect("harden");

        // The owner can still use the file: our own DACL grants `OW` full
        // control. A working read is the observable proof.
        let text = std::fs::read_to_string(&file).expect("owner can still read");
        assert_eq!(text, "top secret");
        // Re-applying is idempotent (protected DACL, same ACEs).
        restrict_to_current_user(&file).expect("harden twice");
    }

    #[test]
    fn hardens_a_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let nested = dir.path().join("tls");
        std::fs::create_dir(&nested).expect("mkdir");
        restrict_to_current_user(&nested).expect("harden dir");
        // Creating a child still works for the owner.
        std::fs::write(nested.join("server.crt.pem"), b"cert").expect("write child");
    }

    #[test]
    fn missing_path_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let err = restrict_to_current_user(&dir.path().join("nope"))
            .expect_err("missing path must fail");
        assert!(matches!(err, RtError::NotFound { .. }), "got {err:?}");
        // The best-effort wrapper must not panic on the same input.
        restrict_or_warn(&dir.path().join("nope"));
    }
}
