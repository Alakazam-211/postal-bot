//! Commit-then-reveal pairing code (SAS v2).
//!
//! Ported from K2's `k2-core/src/federation/sas.rs` (K2 commit `434c822c38`,
//! MIT). Copyright (c) 2025-2026 Alakazam Labs. The MIT permission notice is
//! in this crate's `NOTICE` file. Changes from K2: Postal's own domain tags
//! (`postal-pair-commit-v1` / `postal-pair-v1`, never K2's), so a code from
//! one protocol can't pass in the other; nonces come from `getrandom`.
//!
//! p5's v1 code hashed only the two key fingerprints, so anyone able to
//! substitute a key during pairing could generate keys offline until the
//! 6-digit code matched. v2 binds the code to two fresh random nonces and
//! fixes their order of disclosure (the numeric-comparison pattern of ZRTP,
//! RFC 6189, and Bluetooth Secure Simple Pairing; Vaudenay's SAS-MCA):
//!
//! 1. The initiator A picks a 32-byte nonce `Na` and sends only its
//!    commitment `C = SHA-256("postal-pair-commit-v1" || fp_a || Na)`.
//! 2. The responder B picks `Nb` and sends it in clear only after it has C.
//! 3. A reveals `Na`; B checks it against C and aborts on a mismatch.
//! 4. Both show `SAS = SHA-256("postal-pair-v1" || fp_a || fp_b || Na || Nb)`
//!    reduced to 6 decimal digits, initiator first.
//!
//! A party in the middle must fix its key and nonce before it can learn the
//! other side's nonce, so it gets one guess per pairing attempt (1 in 10^6)
//! instead of unlimited offline tries. Nonces are secrets until revealed;
//! callers never log them.

use sha2::{Digest, Sha256};

/// Domain prefix of the commitment. Postal's own; never K2's.
pub const COMMIT_PREFIX: &[u8] = b"postal-pair-commit-v1";
/// Domain prefix of the code. Postal's own; never K2's.
pub const SAS_PREFIX: &[u8] = b"postal-pair-v1";
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 32;
/// Nonces (and the pairing sessions holding them) are single-use and expire
/// after this many seconds.
pub const NONCE_TTL_SECS: i64 = 600;

/// A pairing nonce.
pub type Nonce = [u8; NONCE_LEN];

/// A fresh random nonce from the OS.
pub fn new_nonce() -> Result<Nonce, getrandom::Error> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n)?;
    Ok(n)
}

/// `SHA-256(COMMIT_PREFIX || fp_a || Na)`.
pub fn commitment(fp_a: &str, na: &Nonce) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_PREFIX);
    h.update(fp_a.as_bytes());
    h.update(na);
    h.finalize().into()
}

/// Whether `na` opens commitment `c` for initiator `fp_a` (constant time).
pub fn verify_commitment(c: &[u8; 32], fp_a: &str, na: &Nonce) -> bool {
    use subtle::ConstantTimeEq;
    commitment(fp_a, na).ct_eq(c).into()
}

/// The 6-digit code: the first 4 bytes of
/// `SHA-256(SAS_PREFIX || fp_a || fp_b || Na || Nb)` as a big-endian u32,
/// mod 10^6, zero-padded. `fp_a`/`Na` are always the initiator's.
pub fn sas(fp_a: &str, fp_b: &str, na: &Nonce, nb: &Nonce) -> String {
    let mut h = Sha256::new();
    h.update(SAS_PREFIX);
    h.update(fp_a.as_bytes());
    h.update(fp_b.as_bytes());
    h.update(na);
    h.update(nb);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    format!("{:06}", n % 1_000_000)
}

/// Constant-time compare of two codes (length is public).
pub fn sas_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    let (a, b) = (a.trim().as_bytes(), b.trim().as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{from_hex32, to_hex};

    const NA: Nonce = [0x11; 32];
    const NB: Nonce = [0x22; 32];

    #[test]
    fn both_sides_compute_the_same_code() {
        let (fa, fb) = ("aa".repeat(32), "bb".repeat(32));
        let c = commitment(&fa, &NA);
        // B, after A's reveal:
        assert!(verify_commitment(&c, &fa, &NA));
        let at_b = sas(&fa, &fb, &NA, &NB);
        let at_a = sas(&fa, &fb, &NA, &NB);
        assert_eq!(at_a, at_b);
        assert_eq!(at_a.len(), 6);
        assert!(at_a.chars().all(|c| c.is_ascii_digit()));
        assert!(sas_eq(&at_a, &at_b));
        assert!(!sas_eq(&at_a, "12345"), "a different length never matches");
    }

    #[test]
    fn our_tags_are_not_k2s() {
        // A code computed under K2's tags must not equal ours for the same
        // inputs (it could, by 1-in-10^6 chance, for one vector; these are fixed).
        let (fa, fb) = ("aa".repeat(32), "bb".repeat(32));
        assert_ne!(COMMIT_PREFIX, b"k2-sas-commit-v2");
        assert_ne!(SAS_PREFIX, b"k2-sas-v2");
        assert_ne!(sas(&fa, &fb, &NA, &NB), "632758", "K2's literal vector for these inputs");
    }

    #[test]
    fn a_wrong_reveal_or_another_initiator_does_not_open_the_commitment() {
        let fa = "aa".repeat(32);
        let c = commitment(&fa, &NA);
        let mut wrong = NA;
        wrong[31] ^= 1;
        assert!(!verify_commitment(&c, &fa, &wrong));
        assert!(!verify_commitment(&c, &"cc".repeat(32), &NA), "the commitment binds fp_a");
    }

    #[test]
    fn the_code_depends_on_both_nonces_and_both_keys() {
        let (fa, fb, fm) = ("aa".repeat(32), "bb".repeat(32), "ee".repeat(32));
        let real = sas(&fa, &fb, &NA, &NB);
        let mut na2 = NA;
        na2[0] ^= 0x80;
        let mut nb2 = NB;
        nb2[0] ^= 0x80;
        let variants = [
            sas(&fa, &fm, &NA, &NB),
            sas(&fa, &fb, &na2, &NB),
            sas(&fa, &fb, &NA, &nb2),
            sas(&fb, &fa, &NA, &NB),
        ];
        for v in &variants {
            assert_ne!(v, &real, "changing any input must change the code (fixed vectors)");
        }
        // Order is fixed: initiator first.
        assert_ne!(sas(&fa, &fb, &NA, &NB), sas(&fa, &fb, &NB, &NA));
    }

    #[test]
    fn nonces_are_fresh_and_round_trip_as_hex() {
        let n = new_nonce().expect("nonce");
        assert_eq!(from_hex32(&to_hex(&n)).expect("parse"), n);
        assert_ne!(new_nonce().expect("a"), new_nonce().expect("b"));
    }
}
