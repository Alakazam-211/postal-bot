//! HoldSeal-v1 for Postal (`postal.bot`).
//!
//! Pairing identity is Ed25519 (RFC 8410 SPKI PEM). Hold blobs are
//! X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305. Private keys stay
//! on disk (0600).

mod error;
mod keys;
mod proof;
mod seal;

pub use error::CryptoError;
pub use keys::{fingerprint_spki_pem, sas_code, KeyPair, IDENTITY_FILE, KEYS_DIR};
pub use proof::{proof_create, proof_verify};
pub use seal::{seal, SealAad};

/// Hold blob version byte.
pub const HOLDSEAL_V1: u8 = 1;
/// Domain tag for hold seal HKDF + AAD.
pub const TAG_HOLD: &str = "p5-hold-v1";
/// Domain tag for `/p5/msg` pairing-key proofs.
pub const TAG_MSG: &str = "p5-msg-v1";
/// Refuse plaintext larger than this before seal.
pub const MAX_PLAINTEXT: usize = 256 * 1024;

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
