//! Provenance badge: a short tag both ends compute from **signed** fields
//! only, so body text can't fake who sent a message.
//!
//! `p_` + the first 12 hex digits of
//! `SHA-256("postal-badge-v1" || len(id) || id || len(fp) || fp || body_sha256)`,
//! where `len` is a 4-byte big-endian length. Length framing keeps
//! `("ab","c")` and `("a","bc")` apart. Never derived from display names,
//! `from` text, or anything the plane asserts.

use sha2::{Digest, Sha256};

/// Domain prefix of the badge.
pub const BADGE_PREFIX: &[u8] = b"postal-badge-v1";

/// Badge for a verified message.
pub fn badge(id: &str, sender_fingerprint: &str, body_sha256: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(BADGE_PREFIX);
    for field in [id.as_bytes(), sender_fingerprint.as_bytes()] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    h.update(body_sha256);
    let d = h.finalize();
    format!("p_{}", &crate::hex::to_hex(&d)[..12])
}

/// `SHA-256(body)`, the digest a badge and a signature cover.
pub fn body_sha256(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_keeps_fields_apart() {
        let d = body_sha256(b"hi");
        assert_ne!(badge("ab", "c", &d), badge("a", "bc", &d));
        assert!(badge("id", "fp", &d).starts_with("p_"));
        assert_eq!(badge("id", "fp", &d).len(), 14);
    }

    #[test]
    fn any_signed_field_changes_it() {
        let d = body_sha256(b"hi");
        let base = badge("01J", "fp", &d);
        assert_ne!(base, badge("01K", "fp", &d));
        assert_ne!(base, badge("01J", "fq", &d));
        assert_ne!(base, badge("01J", "fp", &body_sha256(b"ho")));
    }
}
