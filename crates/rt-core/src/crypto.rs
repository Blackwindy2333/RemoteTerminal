//! Cryptography helpers: password hashing, token generation, constant-time
//! comparison, and TLS material (self-signed certificate + fingerprint pinning).
//!
//! Nothing here is home-grown: Argon2id comes from `argon2`, hashing from
//! `sha2`, randomness from the OS CSPRNG, and certificate verification goes
//! through `rustls` with a *pin-only* verifier (trust is a SHA-256 fingerprint,
//! not a CA chain — appropriate for a LAN appliance).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Result, RtError};

// ---------------------------------------------------------------------------
// Hashing / randomness
// ---------------------------------------------------------------------------

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_bytes(data))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parses a hex string, ignoring separators (`:`/`-`/space) and case.
pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '\t' | '\n' | '\r'))
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err(RtError::BadRequest("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| RtError::BadRequest("invalid hex digit".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| RtError::BadRequest("invalid hex digit".into()))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Uniform display form for fingerprints: lowercase, colon separated.
pub fn format_fingerprint(hex: &str) -> String {
    match hex_decode(hex) {
        Ok(bytes) => bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        Err(_) => hex.to_string(),
    }
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// URL-safe random token (no padding).
pub fn random_token(n_bytes: usize) -> String {
    use base64::Engine as _;
    let mut buf = vec![0u8; n_bytes.max(16)];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Short human-typable code (used for the one-time pairing flow).
pub fn random_code(len: usize) -> String {
    // Crockford-ish alphabet without look-alikes.
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

pub fn hash_password(password: &str) -> Result<String> {
    if password.len() < 8 {
        return Err(RtError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }
    let salt = SaltString::generate(&mut ArgonOsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| RtError::Internal(format!("argon2 hashing failed: {e}")))
}

/// Constant-time verification. Malformed hashes are treated as "no match"
/// (they cannot be exploited, and an attacker cannot distinguish them).
pub fn verify_password(password: &str, phc: &str) -> bool {
    if phc.trim().is_empty() {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// API keys are stored as digests; comparison is constant time.
pub fn verify_api_key_digest(presented: &str, stored_hex: &str) -> bool {
    if stored_hex.trim().is_empty() {
        return false;
    }
    let digest = sha256_bytes(presented.as_bytes());
    match hex_decode(stored_hex) {
        Ok(expected) => ct_eq(&digest, &expected),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Everything needed to run a TLS server, plus what clients must pin.
#[derive(Debug, Clone)]
pub struct TlsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// SHA-256 of the DER leaf certificate, lowercase hex.
    pub fingerprint: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// True when a fresh self-signed certificate was generated this run.
    pub generated: bool,
}

impl TlsMaterial {
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        ensure_crypto_provider();
        let mut cert_reader = &self.cert_pem[..];
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RtError::Tls(format!("failed to parse certificate PEM: {e}")))?;
        if certs.is_empty() {
            return Err(RtError::Tls("certificate PEM contains no certificate".into()));
        }
        let mut key_reader = &self.key_pem[..];
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| RtError::Tls(format!("failed to parse private key PEM: {e}")))?
            .ok_or_else(|| RtError::Tls("private key PEM contains no key".into()))?;

        let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| RtError::Tls(format!("invalid certificate/key pair: {e}")))?;
        Ok(Arc::new(config))
    }
}

fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Errors here only mean another provider is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

const CERT_FILE: &str = "server.crt.pem";
const KEY_FILE: &str = "server.key.pem";
const FP_FILE: &str = "fingerprint.txt";

/// Load an operator-supplied certificate pair.
pub fn load_custom_tls(cert_path: &Path, key_path: &Path) -> Result<TlsMaterial> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| RtError::io(cert_path.to_path_buf(), e))?;
    let key_pem = std::fs::read(key_path).map_err(|e| RtError::io(key_path.to_path_buf(), e))?;
    let mut reader = &cert_pem[..];
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .map_err(|e| RtError::Tls(format!("invalid certificate: {e}")))?
        .ok_or_else(|| RtError::Tls("certificate file is empty".into()))?;
    let fingerprint = sha256_hex(first.as_ref());
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        fingerprint,
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        generated: false,
    })
}

/// Load the existing self-signed pair, or generate one bound to `hostnames`.
pub fn ensure_self_signed_tls(dir: &Path, hostnames: &[String]) -> Result<TlsMaterial> {
    std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.to_path_buf(), e))?;
    // The directory that holds the private key stays readable only by this
    // account (S-15): a sibling local user must not be able to read it.
    crate::acl::restrict_or_warn(dir);
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    let fp_path = dir.join(FP_FILE);

    if cert_path.exists() && key_path.exists() {
        match load_custom_tls(&cert_path, &key_path) {
            Ok(material) => {
                // Keep the sidecar in sync; it is what the GUI shows as a QR/string.
                let _ = std::fs::write(&fp_path, &material.fingerprint);
                crate::acl::restrict_or_warn(&cert_path);
                crate::acl::restrict_or_warn(&key_path);
                crate::acl::restrict_or_warn(&fp_path);
                return Ok(material);
            }
            Err(err) => {
                tracing::warn!(
                    target: "rt_core::crypto",
                    "existing TLS material at {} is unusable ({err}); regenerating",
                    dir.display()
                );
            }
        }
    }

    let material = generate_self_signed(dir, &cert_path, &key_path, hostnames)?;
    let _ = std::fs::write(&fp_path, &material.fingerprint);
    crate::acl::restrict_or_warn(&fp_path);
    Ok(material)
}

/// Regenerate the self-signed pair, keeping the previous files as
/// `<name>.<timestamp>.old` (S-40).
///
/// Rotation invalidates every pinned client: they must re-run
/// `remote-terminal fingerprint <host>` and update their pin, so this is a
/// deliberate operator action rather than something that happens on its own.
pub fn rotate_self_signed_tls(dir: &Path, hostnames: &[String]) -> Result<TlsMaterial> {
    std::fs::create_dir_all(dir).map_err(|e| RtError::io(dir.to_path_buf(), e))?;
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    for name in [CERT_FILE, KEY_FILE, FP_FILE] {
        let path = dir.join(name);
        if path.exists() {
            let backup = dir.join(format!("{name}.{stamp}.old"));
            std::fs::rename(&path, &backup).map_err(|e| RtError::io(path.clone(), e))?;
            crate::acl::restrict_or_warn(&backup);
        }
    }
    tracing::info!(target: "rt_core::crypto", dir = %dir.display(), "rotated the self-signed TLS pair");
    ensure_self_signed_tls(dir, hostnames)
}

fn generate_self_signed(
    _dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    hostnames: &[String],
) -> Result<TlsMaterial> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let mut sans: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for h in hostnames {
        let h = h.trim();
        if !h.is_empty() && !sans.iter().any(|s| s.eq_ignore_ascii_case(h)) {
            sans.push(h.to_string());
        }
    }

    let mut params = CertificateParams::new(sans.clone())
        .map_err(|e| RtError::Tls(format!("invalid subject alternative names: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{}-{}", rt_protocol::APP_NAME, params.subject_alt_names.len()));
    dn.push(DnType::OrganizationName, "RemoteTerminal (self-signed)");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::NoCa;
    // Long validity: pinning is by fingerprint, so expiry only adds breakage.
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);

    let key_pair =
        KeyPair::generate().map_err(|e| RtError::Tls(format!("key generation failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RtError::Tls(format!("certificate signing failed: {e}")))?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    let fingerprint = sha256_hex(cert.der().as_ref());

    crate::config::write_atomic(cert_path, &cert_pem)?;
    crate::config::write_atomic(key_path, &key_pem)?;
    // Tighten the private key to this account only (S-15). Best effort: the
    // key is already written, so a failure here is logged rather than turned
    // into a startup error.
    crate::acl::restrict_or_warn(cert_path);
    crate::acl::restrict_or_warn(key_path);
    tracing::info!(
        target: "rt_core::crypto",
        fingerprint = %fingerprint,
        "generated self-signed TLS certificate"
    );

    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        fingerprint,
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        generated: true,
    })
}

/// Records the fingerprint a server presented during a trust-on-first-use
/// connection, so the UI can show it before the user pins it.
#[derive(Debug, Clone, Default)]
pub struct FingerprintProbe {
    inner: Arc<Mutex<Option<String>>>,
}

impl FingerprintProbe {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, fp: String) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(fp);
        }
    }

    pub fn get(&self) -> Option<String> {
        self.inner.lock().ok().and_then(|g| g.clone())
    }
}

#[derive(Debug)]
enum PinMode {
    /// Only this exact certificate is accepted.
    Pinned([u8; 32]),
    /// Accept anything but remember the fingerprint (trust-on-first-use UI).
    Tofu(FingerprintProbe),
}

#[derive(Debug)]
struct FingerprintVerifier {
    mode: PinMode,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest = sha256_bytes(end_entity.as_ref());
        match &self.mode {
            PinMode::Pinned(expected) => {
                if ct_eq(&digest, expected) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    tracing::warn!(
                        target: "rt_core::crypto",
                        presented = %hex_encode(&digest),
                        "TLS certificate fingerprint mismatch — refusing connection"
                    );
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            PinMode::Tofu(probe) => {
                probe.set(hex_encode(&digest));
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn base_client_config(
    verifier: Arc<dyn ServerCertVerifier>,
) -> rustls::ClientConfig {
    ensure_crypto_provider();
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Client TLS config that trusts exactly one certificate fingerprint.
pub fn client_config_pinned(fingerprint_hex: &str) -> Result<rustls::ClientConfig> {
    let bytes = hex_decode(fingerprint_hex)
        .map_err(|_| RtError::Tls("fingerprint must be a hex SHA-256 digest".into()))?;
    if bytes.len() != 32 {
        return Err(RtError::Tls(
            "fingerprint must be 32 bytes (SHA-256), e.g. output of `remote-terminal.exe fingerprint`"
                .into(),
        ));
    }
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&bytes);
    Ok(base_client_config(Arc::new(FingerprintVerifier {
        mode: PinMode::Pinned(expected),
    })))
}

/// Client TLS config that accepts any certificate but records the fingerprint.
/// Only used by the explicit "trust this server" flow in the GUI.
pub fn client_config_tofu(probe: FingerprintProbe) -> rustls::ClientConfig {
    base_client_config(Arc::new(FingerprintVerifier {
        mode: PinMode::Tofu(probe),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let phc = hash_password("correct horse battery").expect("hash");
        assert!(phc.starts_with("$argon2"));
        assert!(verify_password("correct horse battery", &phc));
        assert!(!verify_password("wrong", &phc));
        assert!(!verify_password("correct horse battery", "garbage"));
        assert!(hash_password("short").is_err());
    }

    #[test]
    fn api_key_digest_verifies() {
        let key = "rt_abcdefghijklmnop";
        let digest = sha256_hex(key.as_bytes());
        assert!(verify_api_key_digest(key, &digest));
        assert!(!verify_api_key_digest("rt_other", &digest));
        assert!(!verify_api_key_digest(key, ""));
    }

    #[test]
    fn hex_helpers_roundtrip_and_format() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");
        assert_eq!(hex_decode("DE:AD:BE:EF").unwrap(), bytes);
        assert_eq!(format_fingerprint("deadbeef"), "DE:AD:BE:EF");
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn tokens_are_unique() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert!(a.len() >= 32);
        let code = random_code(8);
        assert_eq!(code.len(), 8);
        assert!(!code.contains('0') && !code.contains('O'));
    }

    #[test]
    fn self_signed_tls_generates_and_pins() {
        let dir = std::env::temp_dir().join(format!("rt_tls_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let material = ensure_self_signed_tls(&dir, &["test-host".into()]).expect("tls material");
        assert!(material.generated);
        assert_eq!(material.fingerprint.len(), 64);
        assert!(material.server_config().is_ok());

        // Second call loads instead of regenerating.
        let again = ensure_self_signed_tls(&dir, &[]).expect("reload");
        assert!(!again.generated);
        assert_eq!(again.fingerprint, material.fingerprint);

        assert!(client_config_pinned(&material.fingerprint).is_ok());
        assert!(client_config_pinned("zzzz").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
