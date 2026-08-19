//! Ed25519 pairing identity (RFC 8410 SPKI). Private file is 0600.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use spki::{DecodePublicKey, EncodePublicKey};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::{to_hex, CryptoError};

/// Directory under the Postal root that holds the identity key.
pub const KEYS_DIR: &str = "keys";
/// PKCS#8 PEM of the Ed25519 private key.
pub const IDENTITY_FILE: &str = "identity.pem";
const SAS_SEP: &[u8] = b"::k2-federation-sas::";

/// Local pairing identity. The X25519 twin is derived; it is never stored.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load `<root>/keys/identity.pem`, or create it (0600) if missing.
    pub fn load_or_create(root: &Path) -> Result<Self, CryptoError> {
        let path = identity_path(root);
        match fs::read_to_string(&path) {
            Ok(pem) => Self::from_pkcs8_pem(&pem),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let kp = Self::generate();
                kp.save_private(&path)?;
                Ok(kp)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let signing = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::Key(format!("invalid identity PEM: {e}")))?;
        Ok(Self { signing })
    }

    fn save_private(&self, path: &Path) -> Result<(), CryptoError> {
        let pem = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Key(format!("encode PKCS#8: {e}")))?;
        write_private_pem(path, pem.as_str())?;
        Ok(())
    }

    /// RFC 8410 `PUBLIC KEY` PEM. This is what `PUT /postal/me` uploads.
    pub fn public_key_pem(&self) -> String {
        self.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("ed25519 SPKI PEM encode")
    }

    /// SHA-256 of the SPKI DER, lowercase hex.
    pub fn fingerprint(&self) -> String {
        fingerprint_verifying_key(&self.verifying_key())
    }

    /// Montgomery public key twin (ECDH only; not a second identity).
    pub fn to_x25519(&self) -> [u8; 32] {
        X25519Public::from(&self.static_secret()).to_bytes()
    }

    pub(crate) fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.signing.to_scalar_bytes())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// Order-independent 6-digit SAS (k2-dev-web `sas_code`).
pub fn sas_code(fp_a: &str, fp_b: &str) -> String {
    let (lo, hi) = if fp_a <= fp_b {
        (fp_a, fp_b)
    } else {
        (fp_b, fp_a)
    };
    let mut data = Vec::with_capacity(lo.len() + SAS_SEP.len() + hi.len());
    data.extend_from_slice(lo.as_bytes());
    data.extend_from_slice(SAS_SEP);
    data.extend_from_slice(hi.as_bytes());
    let hash = Sha256::digest(&data);
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    format!("{:06}", n % 1_000_000)
}

pub(crate) fn parse_spki_pem(pem: &str) -> Result<VerifyingKey, CryptoError> {
    VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| CryptoError::Key(format!("invalid Ed25519 SPKI PEM: {e}")))
}

pub(crate) fn fingerprint_verifying_key(vk: &VerifyingKey) -> String {
    let der = vk.to_public_key_der().expect("ed25519 SPKI DER encode");
    let hash = Sha256::digest(der.as_bytes());
    to_hex(&hash)
}

pub(crate) fn x25519_public_from_ed25519(vk: &VerifyingKey) -> X25519Public {
    X25519Public::from(vk.to_montgomery().to_bytes())
}

fn identity_path(root: &Path) -> PathBuf {
    root.join(KEYS_DIR).join(IDENTITY_FILE)
}

fn write_private_pem(path: &Path, pem: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    let tmp = match path.file_name() {
        Some(name) => path.with_file_name(format!(".{}.tmp", name.to_string_lossy())),
        None => path.with_extension("tmp"),
    };

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(pem.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_persists_and_unix_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let a = KeyPair::load_or_create(dir.path()).unwrap();
        let path = identity_path(dir.path());
        assert!(path.is_file());
        let pem = fs::read_to_string(&path).unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(!pem.contains("BEGIN PUBLIC KEY"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let b = KeyPair::load_or_create(dir.path()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.public_key_pem(), b.public_key_pem());
        assert_eq!(a.to_x25519(), b.to_x25519());
    }

    #[test]
    fn fingerprint_stable_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let first = KeyPair::load_or_create(dir.path()).unwrap();
        let fp = first.fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        drop(first);
        let again = KeyPair::load_or_create(dir.path()).unwrap();
        assert_eq!(again.fingerprint(), fp);
    }

    #[test]
    fn sas_order_independent_six_digits() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let fa = a.fingerprint();
        let fb = b.fingerprint();
        let left = sas_code(&fa, &fb);
        let right = sas_code(&fb, &fa);
        assert_eq!(left, right);
        assert_eq!(left.len(), 6);
        assert!(left.chars().all(|c| c.is_ascii_digit()));
        let same = sas_code(&fa, &fa);
        assert_eq!(same.len(), 6);
        assert!(same.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn spki_pem_parses_as_public_key() {
        let kp = KeyPair::generate();
        let pem = kp.public_key_pem();
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "expected RFC 8410 SPKI PEM, got {pem:?}"
        );
        assert!(pem.contains("-----END PUBLIC KEY-----"));
        assert!(!pem.contains("PRIVATE"));
        let vk = VerifyingKey::from_public_key_pem(&pem).unwrap();
        assert_eq!(vk.to_bytes(), kp.verifying_key().to_bytes());
        assert_eq!(fingerprint_verifying_key(&vk), kp.fingerprint());
    }

    #[test]
    fn x25519_twin_matches_static_secret() {
        let kp = KeyPair::generate();
        let from_secret = X25519Public::from(&kp.static_secret());
        let from_ed = x25519_public_from_ed25519(&kp.verifying_key());
        assert_eq!(from_secret.to_bytes(), from_ed.to_bytes());
        assert_eq!(kp.to_x25519(), from_secret.to_bytes());
    }
}
