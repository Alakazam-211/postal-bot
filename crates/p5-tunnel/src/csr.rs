//! ECDSA P-256 key + CSR for `{label}.postal.bot` only.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};

use crate::san::{hostname_for_label, sans_for_label, SanError};

/// Directory under the Postal root that holds tunnel TLS material.
pub const TUNNEL_DIR: &str = "tunnel";
/// ECDSA private key (PEM, 0600). Not the pairing Ed25519 identity.
pub const TUNNEL_KEY_FILE: &str = "key.pem";
/// Broker-issued (or test) leaf chain.
pub const TUNNEL_CERT_FILE: &str = "cert.pem";

#[derive(Debug)]
pub enum CsrError {
    San(SanError),
    Io(io::Error),
    Build(String),
}

impl fmt::Display for CsrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::San(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "tunnel key io: {err}"),
            Self::Build(msg) => write!(f, "tunnel CSR: {msg}"),
        }
    }
}

impl std::error::Error for CsrError {}

impl From<SanError> for CsrError {
    fn from(err: SanError) -> Self {
        Self::San(err)
    }
}

impl From<io::Error> for CsrError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn generate_key() -> Result<KeyPair, CsrError> {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CsrError::Build(format!("generate ECDSA P-256: {e}")))
}

pub fn key_path(root: &Path) -> std::path::PathBuf {
    root.join(TUNNEL_DIR).join(TUNNEL_KEY_FILE)
}

pub fn cert_path(root: &Path) -> std::path::PathBuf {
    root.join(TUNNEL_DIR).join(TUNNEL_CERT_FILE)
}

/// Renew the leaf when it has less than this left (or can't be read).
pub const RENEW_BEFORE_SECS: i64 = 30 * 24 * 3600;

/// Seconds until the leaf at `tunnel/cert.pem` expires (negative once it
/// has). None when the file is missing or isn't a PEM certificate.
pub fn cert_secs_left(root: &Path, now_unix: i64) -> Option<i64> {
    let pem = std::fs::read(cert_path(root)).ok()?;
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).ok()?;
    let cert = block.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp() - now_unix)
}

/// Whether the leaf needs a new CSR: missing, unreadable, expired, or
/// expiring within [`RENEW_BEFORE_SECS`].
pub fn cert_needs_renewal(root: &Path, now_unix: i64) -> bool {
    match cert_secs_left(root, now_unix) {
        Some(left) => left < RENEW_BEFORE_SECS,
        None => true,
    }
}

/// Last renewal failure, cleared on success. `p5 status` shows it.
pub const RENEW_ERROR_FILE: &str = "renew-error.txt";

fn renew_error_path(root: &Path) -> std::path::PathBuf {
    root.join(TUNNEL_DIR).join(RENEW_ERROR_FILE)
}

pub fn record_renew_error(root: &Path, err: &str) {
    let _ = ensure_tunnel_dir(root);
    let one_line: String = err.chars().filter(|c| !c.is_control()).take(300).collect();
    let _ = fs::write(renew_error_path(root), one_line);
}

pub fn clear_renew_error(root: &Path) {
    let _ = fs::remove_file(renew_error_path(root));
}

/// A line for `p5 status` when the leaf needs attention, else None:
/// `tunnel certificate expired 3 days ago, renewal failing: …` or
/// `tunnel certificate expires in 12 days, renewal failing: …`.
pub fn cert_status_line(root: &Path, now_unix: i64) -> Option<String> {
    if !cert_path(root).is_file() {
        return None;
    }
    let err = fs::read_to_string(renew_error_path(root)).ok();
    let mut line = match cert_secs_left(root, now_unix) {
        None => "tunnel certificate unreadable".to_string(),
        Some(left) if left < 0 => {
            format!("tunnel certificate expired {} days ago", (-left) / 86_400)
        }
        Some(left) if left < RENEW_BEFORE_SECS => {
            format!("tunnel certificate expires in {} days", left / 86_400)
        }
        Some(_) if err.is_none() => return None,
        Some(left) => format!("tunnel certificate valid for {} days", left / 86_400),
    };
    if let Some(e) = err.filter(|e| !e.trim().is_empty()) {
        line.push_str(&format!(", renewal failing: {}", e.trim()));
    }
    Some(line)
}

/// Check a broker answer before installing it: it parses, carries our
/// public key, names `hostname`, and is valid at `now_unix`.
pub fn check_leaf(pem: &str, key: &KeyPair, hostname: &str, now_unix: i64) -> Result<(), String> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("not a PEM cert: {e}"))?;
    let cert = block
        .parse_x509()
        .map_err(|e| format!("bad certificate: {e}"))?;
    if cert.public_key().raw != key.public_key_der().as_slice() {
        return Err("certificate is not for our key".into());
    }
    let named = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|san| {
            san.value.general_names.iter().any(|n| {
                matches!(n, x509_parser::extensions::GeneralName::DNSName(d) if d.eq_ignore_ascii_case(hostname))
            })
        });
    if !named {
        return Err(format!("certificate does not name {hostname}"));
    }
    let v = cert.validity();
    if now_unix < v.not_before.timestamp() || now_unix > v.not_after.timestamp() {
        return Err("certificate is not currently valid".into());
    }
    Ok(())
}

fn tunnel_dir(root: &Path) -> std::path::PathBuf {
    root.join(TUNNEL_DIR)
}

fn ensure_tunnel_dir(root: &Path) -> io::Result<()> {
    let dir = tunnel_dir(root);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Load `{root}/tunnel/key.pem` or create it (0600). Never silently rotate a
/// key that might already be certified.
pub fn load_or_generate_key(root: &Path) -> Result<KeyPair, CsrError> {
    ensure_tunnel_dir(root)?;
    let path = key_path(root);
    if path.exists() {
        let pem = fs::read_to_string(&path)?;
        return KeyPair::from_pem(&pem)
            .map_err(|e| CsrError::Build(format!("parse tunnel key: {e}")));
    }
    let key = generate_key()?;
    write_private_pem(&path, &key.serialize_pem())?;
    Ok(key)
}

fn write_private_pem(path: &Path, pem: &str) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let tmp = path.with_extension("pem.tmp");
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(pem.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Install a PEM chain (0644 — public). The private key stays 0600.
pub fn install_cert(root: &Path, cert_pem: &str) -> Result<(), CsrError> {
    ensure_tunnel_dir(root)?;
    let dest = cert_path(root);
    let tmp = dest.with_extension("pem.tmp");
    fs::write(&tmp, cert_pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
    }
    fs::rename(&tmp, &dest).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

/// PEM CSR whose SAN list is exactly [`sans_for_label`].
pub fn build_csr_pem(label: &str, key: &KeyPair) -> Result<String, CsrError> {
    let hostname = hostname_for_label(label)?;
    let sans = sans_for_label(label)?;
    // Policy is the constructor: one name, no wildcard, no k2.dev.
    debug_assert_eq!(sans, vec![hostname.clone()]);

    let mut params = CertificateParams::default();
    let dns: rcgen::Ia5String = hostname
        .as_str()
        .try_into()
        .map_err(|e| CsrError::Build(format!("invalid DNS SAN {hostname:?}: {e}")))?;
    params.subject_alt_names = vec![SanType::DnsName(dns)];
    if params.subject_alt_names.len() != 1 {
        return Err(CsrError::Build(
            "internal: Postal CSR must carry exactly one SAN".into(),
        ));
    }

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname.as_str());
    params.distinguished_name = dn;

    let csr = params
        .serialize_request(key)
        .map_err(|e| CsrError::Build(format!("serialize CSR: {e}")))?;
    csr.pem()
        .map_err(|e| CsrError::Build(format!("encode CSR PEM: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_pem_body(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        // Minimal base64 (CSR tests only need ASCII SAN needles in DER).
        fn val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let bytes: Vec<u8> = b64.bytes().filter_map(val).collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            if chunk.len() < 2 {
                break;
            }
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            if chunk.len() > 2 {
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
            }
            if chunk.len() > 3 {
                out.push((chunk[2] << 6) | chunk[3]);
            }
        }
        out
    }

    fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn csr_san_is_base_postal_only() {
        let key = generate_key().unwrap();
        let pem = build_csr_pem("acme", &key).unwrap();
        assert!(
            pem.contains("BEGIN CERTIFICATE REQUEST"),
            "must be a PEM CSR\n{pem}"
        );
        let der = decode_pem_body(&pem);
        assert!(
            contains_ascii(&der, b"acme.postal.bot"),
            "base SAN missing from CSR DER"
        );
        assert!(
            !contains_ascii(&der, b"*.acme.postal.bot"),
            "nested wildcard must not appear on a Postal CSR"
        );
        assert!(
            !contains_ascii(&der, b"k2.dev"),
            "k2.dev must not appear on a Postal CSR"
        );
    }

    #[test]
    fn csr_refuses_bad_label() {
        let key = generate_key().unwrap();
        assert!(build_csr_pem("*.acme", &key).is_err());
        assert!(build_csr_pem("foo.acme", &key).is_err());
        assert!(build_csr_pem("", &key).is_err());
    }

    #[test]
    fn key_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let a = load_or_generate_key(tmp.path()).unwrap();
        let b = load_or_generate_key(tmp.path()).unwrap();
        assert_eq!(a.serialize_pem(), b.serialize_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(key_path(tmp.path()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "tunnel key must be 0600, got {mode:o}");
        }
    }
}
