//! In-memory Ed25519 pairing identity. Hosts keep the private key; this
//! crate never touches the disk.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::LineEnding;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use spki::{DecodePublicKey, EncodePublicKey};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::pairing::Fingerprint;

/// An Ed25519 pairing identity. The X25519 twin is derived; it is never stored.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Build from a 32-byte seed. Tests and hosts that already have the key.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// RFC 8410 `PUBLIC KEY` PEM.
    #[must_use]
    pub fn public_key_pem(&self) -> String {
        self.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("ed25519 SPKI PEM encode")
    }

    /// SHA-256 of the SPKI DER.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_verifying_key(&self.verifying_key())
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub(crate) fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.signing.to_scalar_bytes())
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// Parse an Ed25519 RFC 8410 SPKI PEM.
///
/// # Errors
/// [`IdentityError::Key`] if the PEM is not an Ed25519 public key.
pub fn parse_spki_pem(pem: &str) -> Result<VerifyingKey, IdentityError> {
    VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| IdentityError::Key(format!("invalid Ed25519 SPKI PEM: {e}")))
}

/// SHA-256 of a peer's SPKI DER.
///
/// # Errors
/// [`IdentityError::Key`] if the PEM is not an Ed25519 public key.
pub fn fingerprint_spki_pem(pem: &str) -> Result<Fingerprint, IdentityError> {
    Ok(fingerprint_verifying_key(&parse_spki_pem(pem)?))
}

/// B2: fingerprint from the PEM **this box pins**. Never from a plane
/// `peer_fingerprint` field.
///
/// # Errors
/// [`IdentityError::Key`] if the PEM is not an Ed25519 public key.
pub fn pin_fingerprint(pem: &str) -> Result<Fingerprint, IdentityError> {
    fingerprint_spki_pem(pem)
}

pub(crate) fn fingerprint_verifying_key(vk: &VerifyingKey) -> Fingerprint {
    let der = vk.to_public_key_der().expect("ed25519 SPKI DER encode");
    let hash: [u8; 32] = Sha256::digest(der.as_bytes()).into();
    Fingerprint::from_bytes(hash)
}

pub(crate) fn x25519_public_from_ed25519(vk: &VerifyingKey) -> X25519Public {
    X25519Public::from(vk.to_montgomery().to_bytes())
}

pub(crate) fn verify_sig(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), IdentityError> {
    vk.verify(msg, &Signature::from_bytes(sig))
        .map_err(|_| IdentityError::Sig)
}

/// Fail-closed identity / signature error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    Key(String),
    Sig,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(msg) => write!(f, "postal identity: {msg}"),
            Self::Sig => f.write_str("signature verification failed"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_stable_pem_and_fingerprint() {
        let id = Identity::from_seed([0x11; 32]);
        let pem = id.public_key_pem();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
        assert_eq!(
            id.fingerprint().to_hex(),
            fingerprint_spki_pem(&pem).unwrap().to_hex()
        );
        assert!(!format!("{id:?}").contains("17, 17"), "{id:?}");
    }

    #[test]
    fn sign_verify_roundtrip_and_wrong_key_fails() {
        let a = Identity::from_seed([0x11; 32]);
        let b = Identity::from_seed([0x22; 32]);
        let msg = b"postal-envelope-v1-digest";
        let sig = a.sign(msg);
        verify_sig(&a.verifying_key(), msg, &sig).unwrap();
        assert_eq!(
            verify_sig(&b.verifying_key(), msg, &sig),
            Err(IdentityError::Sig)
        );
    }

    #[test]
    fn bad_pem_is_refused() {
        assert!(matches!(
            parse_spki_pem("not a key"),
            Err(IdentityError::Key(_))
        ));
    }
}
