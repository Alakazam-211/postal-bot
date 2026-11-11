//! Commit-then-reveal pairing code (SAS v2), as typed state machines.
//!
//! Ported from K2's `k2-core/src/federation/sas.rs` (K2 commit `434c822c38`,
//! MIT, Copyright (c) 2025-2026 Alakazam Labs; the permission notice is in
//! this crate's `NOTICE` file). Changes from K2:
//! - Postal's own domain tags (`postal-pair-commit-v1` / `postal-pair-v1`,
//!   never K2's), so a code from one protocol can't pass in the other.
//! - Fingerprints are exactly 32 raw bytes ([`Fingerprint`]) and the pairing
//!   context is length-framed, so no two inputs hash the same.
//! - The pair id and both handles are bound into the code.
//! - The protocol order and the nonce lifetime are enforced by the types
//!   below, not left to the host.
//! - Nonces come from `getrandom`.
//!
//! The numeric-comparison pattern of ZRTP (RFC 6189) and Bluetooth Secure
//! Simple Pairing (Vaudenay's SAS-MCA):
//!
//! 1. A ([`Initiator::start`]) picks a 32-byte nonce `Na` and sends only its
//!    [`Commitment`] `C = SHA-256("postal-pair-commit-v1" || ctx || fp_a || Na)`.
//! 2. B ([`Responder::respond`]) fixes its own key `fp_b`, picks `Nb`, and
//!    sends both together ([`Response`]), only after it has `C`.
//! 3. A ([`Initiator::finish`]) reveals `Na` only after it has B's response.
//! 4. B ([`Responder::finish`]) accepts `Na` only after it sent `Nb`, and
//!    checks it against `C`.
//! 5. Both show `SAS = SHA-256("postal-pair-v1" || ctx || fp_a || fp_b || Na || Nb)`
//!    reduced to 6 decimal digits.
//!
//! Each step consumes the previous state, so the order can't be changed and
//! a nonce can't be used twice. Each state expires [`NONCE_TTL_SECS`] after
//! it was made.
//!
//! **Host rules the types can't enforce:** answer at most one
//! [`Response`] per commitment and per pair id, and limit how many pairing
//! attempts a peer may start (say, a few per hour). Every extra response is
//! another 1-in-10^6 guess for a party in the middle.
//!
//! A party in the middle must fix its key and nonce before it
//! can learn the other side's nonce, so it gets one guess per pairing
//! attempt (1 in 10^6). Nonces are secrets until revealed; never log them.

use sha2::{Digest, Sha256};

use crate::hex::{from_hex32, to_hex};

/// Domain prefix of the commitment. Postal's own; never K2's.
pub const COMMIT_PREFIX: &[u8] = b"postal-pair-commit-v1";
/// Domain prefix of the code. Postal's own; never K2's.
pub const SAS_PREFIX: &[u8] = b"postal-pair-v1";
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 32;
/// A pairing state is single-use and expires this many seconds after it was made.
pub const NONCE_TTL_SECS: i64 = 600;

type Nonce = [u8; NONCE_LEN];

/// Why a pairing step was refused. Any error ends this pairing attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairError {
    /// Not exactly 64 lowercase hex characters.
    BadFingerprint,
    /// Not exactly 64 hex characters.
    BadHex,
    /// A pairing context field is longer than 4 GiB.
    TooLong,
    /// More than [`NONCE_TTL_SECS`] since this state was made (or a clock
    /// that went backwards).
    Expired,
    /// The revealed nonce doesn't open the commitment.
    Mismatch,
    /// The OS random source failed.
    Random(String),
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFingerprint => f.write_str("fingerprint must be 64 lowercase hex characters"),
            Self::BadHex => f.write_str("expected 64 hex characters"),
            Self::TooLong => f.write_str("pairing context field too long"),
            Self::Expired => f.write_str("pairing step expired; start again"),
            Self::Mismatch => f.write_str("revealed nonce does not match the commitment"),
            Self::Random(e) => write!(f, "system random source failed: {e}"),
        }
    }
}

impl std::error::Error for PairError {}

/// A key fingerprint: SHA-256 of the key's SPKI DER, as 32 raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Parse the 64-lowercase-hex form p5 prints. Anything else (uppercase, a
    /// `SHA256:` prefix, base64, another length) is refused, so two hosts
    /// can't feed the same key in two spellings.
    ///
    /// # Errors
    /// [`PairError::BadFingerprint`] for any other form.
    pub fn parse(s: &str) -> Result<Self, PairError> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(PairError::BadFingerprint);
        }
        from_hex32(s).map(Self).map_err(|_| PairError::BadFingerprint)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

/// What this pairing is about. Bound into both the commitment and the code,
/// so a code from one pairing can't be replayed into another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairContext {
    pub pair_id: String,
    /// Initiator's address, `handle::label.postal.bot`.
    pub initiator: String,
    /// Responder's address.
    pub responder: String,
}

impl PairContext {
    fn framed(&self) -> Result<Vec<u8>, PairError> {
        let mut out = Vec::new();
        for field in [&self.pair_id, &self.initiator, &self.responder] {
            let len = u32::try_from(field.len()).map_err(|_| PairError::TooLong)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        Ok(out)
    }
}

/// Step 1, A → B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment([u8; 32]);

/// Step 2, B → A: B's key and nonce, together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub fp_b: Fingerprint,
    nb: Nonce,
}

/// Step 3, A → B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reveal(Nonce);

impl Commitment {
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
    /// # Errors
    /// [`PairError::BadHex`].
    pub fn from_hex(s: &str) -> Result<Self, PairError> {
        from_hex32(s).map(Self).map_err(|_| PairError::BadHex)
    }
}

impl Response {
    #[must_use]
    pub fn nb_hex(&self) -> String {
        to_hex(&self.nb)
    }
    /// # Errors
    /// [`PairError::BadFingerprint`] or [`PairError::BadHex`].
    pub fn from_parts(fp_b: &str, nb_hex: &str) -> Result<Self, PairError> {
        Ok(Self {
            fp_b: Fingerprint::parse(fp_b)?,
            nb: from_hex32(nb_hex).map_err(|_| PairError::BadHex)?,
        })
    }
}

impl Reveal {
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
    /// # Errors
    /// [`PairError::BadHex`].
    pub fn from_hex(s: &str) -> Result<Self, PairError> {
        from_hex32(s).map(Self).map_err(|_| PairError::BadHex)
    }
}

/// The 6 digits both people compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time compare with what a person typed (length is public).
    #[must_use]
    pub fn matches(&self, typed: &str) -> bool {
        use subtle::ConstantTimeEq;
        let (a, b) = (self.0.as_bytes(), typed.trim().as_bytes());
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

/// A's side, after step 1. No `Clone`, and `Debug` never prints `Na`.
pub struct Initiator {
    ctx: PairContext,
    fp_a: Fingerprint,
    na: Nonce,
    made_at: i64,
}

impl Initiator {
    /// Step 1. Returns the state to keep and the commitment to send.
    /// `now` is unix seconds from the host's clock.
    ///
    /// # Errors
    /// [`PairError::Random`] or [`PairError::TooLong`].
    pub fn start(ctx: PairContext, fp_a: Fingerprint, now: i64) -> Result<(Self, Commitment), PairError> {
        Self::start_with(ctx, fp_a, new_nonce()?, now)
    }

    fn start_with(ctx: PairContext, fp_a: Fingerprint, na: Nonce, now: i64) -> Result<(Self, Commitment), PairError> {
        let c = commitment(&ctx, &fp_a, &na)?;
        Ok((Self { ctx, fp_a, na, made_at: now }, c))
    }

    /// Step 3, once B's response is in. Returns the reveal to send and the
    /// code to show. Consumes the state: `Na` is revealed once.
    ///
    /// # Errors
    /// [`PairError::Expired`] or [`PairError::TooLong`].
    pub fn finish(self, resp: Response, now: i64) -> Result<(Reveal, Code), PairError> {
        fresh(self.made_at, now)?;
        let code = code(&self.ctx, &self.fp_a, &resp.fp_b, &self.na, &resp.nb)?;
        Ok((Reveal(self.na), code))
    }
}

/// B's side, after step 2. No `Clone`, and `Debug` never prints `Nb`.
pub struct Responder {
    ctx: PairContext,
    fp_a: Fingerprint,
    fp_b: Fingerprint,
    c: Commitment,
    nb: Nonce,
    made_at: i64,
}

impl Responder {
    /// Step 2, once A's commitment is in. B's key is fixed here, with `Nb`.
    ///
    /// # Errors
    /// [`PairError::Random`].
    pub fn respond(
        ctx: PairContext,
        fp_a: Fingerprint,
        c: Commitment,
        fp_b: Fingerprint,
        now: i64,
    ) -> Result<(Self, Response), PairError> {
        Ok(Self::respond_with(ctx, fp_a, c, fp_b, new_nonce()?, now))
    }

    fn respond_with(
        ctx: PairContext,
        fp_a: Fingerprint,
        c: Commitment,
        fp_b: Fingerprint,
        nb: Nonce,
        now: i64,
    ) -> (Self, Response) {
        (Self { ctx, fp_a, fp_b, c, nb, made_at: now }, Response { fp_b, nb })
    }

    /// Step 4, once A reveals. Checks `Na` against the commitment (constant
    /// time) and returns the code to show. Consumes the state.
    ///
    /// # Errors
    /// [`PairError::Expired`], [`PairError::Mismatch`] or [`PairError::TooLong`].
    pub fn finish(self, reveal: Reveal, now: i64) -> Result<Code, PairError> {
        use subtle::ConstantTimeEq;
        fresh(self.made_at, now)?;
        let expect = commitment(&self.ctx, &self.fp_a, &reveal.0)?;
        if !bool::from(expect.0.ct_eq(&self.c.0)) {
            return Err(PairError::Mismatch);
        }
        code(&self.ctx, &self.fp_a, &self.fp_b, &reveal.0, &self.nb)
    }
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("ctx", &self.ctx)
            .field("fp_a", &self.fp_a)
            .field("na", &"<secret>")
            .field("made_at", &self.made_at)
            .finish()
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("ctx", &self.ctx)
            .field("fp_a", &self.fp_a)
            .field("fp_b", &self.fp_b)
            .field("c", &self.c)
            .field("nb", &"<secret>")
            .field("made_at", &self.made_at)
            .finish()
    }
}

/// A state is good for strictly less than [`NONCE_TTL_SECS`]. A clock that
/// went backwards, or values that overflow, count as expired.
fn fresh(made_at: i64, now: i64) -> Result<(), PairError> {
    match now.checked_sub(made_at) {
        Some(age) if (0..NONCE_TTL_SECS).contains(&age) => Ok(()),
        _ => Err(PairError::Expired),
    }
}

fn new_nonce() -> Result<Nonce, PairError> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).map_err(|e| PairError::Random(e.to_string()))?;
    Ok(n)
}

fn commitment(ctx: &PairContext, fp_a: &Fingerprint, na: &Nonce) -> Result<Commitment, PairError> {
    let mut h = Sha256::new();
    h.update(COMMIT_PREFIX);
    h.update(ctx.framed()?);
    h.update(fp_a.0);
    h.update(na);
    Ok(Commitment(h.finalize().into()))
}

fn code(ctx: &PairContext, fp_a: &Fingerprint, fp_b: &Fingerprint, na: &Nonce, nb: &Nonce) -> Result<Code, PairError> {
    let mut h = Sha256::new();
    h.update(SAS_PREFIX);
    h.update(ctx.framed()?);
    h.update(fp_a.0);
    h.update(fp_b.0);
    h.update(na);
    h.update(nb);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    Ok(Code(format!("{:06}", n % 1_000_000)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NA: Nonce = [0x11; 32];
    const NB: Nonce = [0x22; 32];
    const T0: i64 = 1_800_000_000;

    fn ctx() -> PairContext {
        PairContext {
            pair_id: "pair-1".into(),
            initiator: "alice::acme.postal.bot".into(),
            responder: "scout::acme.postal.bot".into(),
        }
    }

    fn fp(c: char) -> Fingerprint {
        Fingerprint::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// Run the whole protocol with fixed nonces. Returns (A's code, B's code).
    fn run(ctx_a: PairContext, ctx_b: PairContext) -> (Code, Code) {
        let (a, c) = Initiator::start_with(ctx_a, fp('a'), NA, T0).unwrap();
        let (b, resp) = Responder::respond_with(ctx_b, fp('a'), c, fp('b'), NB, T0 + 1);
        let (reveal, code_a) = a.finish(resp, T0 + 2).unwrap();
        let code_b = b.finish(reveal, T0 + 3).unwrap();
        (code_a, code_b)
    }

    #[test]
    fn both_sides_compute_the_same_code() {
        let (a, b) = run(ctx(), ctx());
        assert_eq!(a, b);
        assert_eq!(a.as_str().len(), 6);
        assert!(a.as_str().chars().all(|c| c.is_ascii_digit()));
        assert!(a.matches(b.as_str()));
        assert!(!a.matches("12345"), "a different length never matches");
    }

    #[test]
    fn real_nonces_agree_too() {
        let (a, c) = Initiator::start(ctx(), fp('a'), T0).unwrap();
        let (b, resp) = Responder::respond(ctx(), fp('a'), c, fp('b'), T0).unwrap();
        let (reveal, code_a) = a.finish(resp, T0).unwrap();
        assert_eq!(b.finish(reveal, T0).unwrap(), code_a);
    }

    #[test]
    fn fingerprints_have_one_spelling() {
        assert!(Fingerprint::parse(&"a".repeat(64)).is_ok());
        for bad in ["A".repeat(64), format!("SHA256:{}", "a".repeat(57)), "a".repeat(63), "a".repeat(65), "g".repeat(64)] {
            assert_eq!(Fingerprint::parse(&bad), Err(PairError::BadFingerprint), "{bad}");
        }
    }

    #[test]
    fn a_wrong_reveal_is_refused() {
        let (_a, c) = Initiator::start_with(ctx(), fp('a'), NA, T0).unwrap();
        let (b, _) = Responder::respond_with(ctx(), fp('a'), c, fp('b'), NB, T0);
        let mut wrong = NA;
        wrong[31] ^= 1;
        assert_eq!(b.finish(Reveal(wrong), T0), Err(PairError::Mismatch));
    }

    #[test]
    fn the_commitment_binds_the_initiator_key_and_context() {
        let (_a, c) = Initiator::start_with(ctx(), fp('a'), NA, T0).unwrap();
        // B believes the initiator is someone else.
        let (b, _) = Responder::respond_with(ctx(), fp('c'), c, fp('b'), NB, T0);
        assert_eq!(b.finish(Reveal(NA), T0), Err(PairError::Mismatch));
        let mut other = ctx();
        other.pair_id = "pair-2".into();
        let (b, _) = Responder::respond_with(other, fp('a'), c, fp('b'), NB, T0);
        assert_eq!(b.finish(Reveal(NA), T0), Err(PairError::Mismatch));
    }

    #[test]
    fn states_expire() {
        let (a, c) = Initiator::start_with(ctx(), fp('a'), NA, T0).unwrap();
        let (b, resp) = Responder::respond_with(ctx(), fp('a'), c, fp('b'), NB, T0);
        assert_eq!(a.finish(resp, T0 + NONCE_TTL_SECS).unwrap_err(), PairError::Expired, "exactly the TTL is too old");
        assert_eq!(b.finish(Reveal(NA), T0 - 1), Err(PairError::Expired), "clock went backwards");
        assert_eq!(fresh(i64::MIN, i64::MAX), Err(PairError::Expired), "overflow is expired, not a panic");
        assert_eq!(fresh(i64::MAX, i64::MIN), Err(PairError::Expired));
        assert_eq!(fresh(T0, T0 + NONCE_TTL_SECS - 1), Ok(()));
    }

    #[test]
    fn debug_never_prints_nonces() {
        let (a, c) = Initiator::start_with(ctx(), fp('a'), NA, T0).unwrap();
        let (b, _) = Responder::respond_with(ctx(), fp('a'), c, fp('b'), NB, T0);
        for s in [format!("{a:?}"), format!("{b:?}")] {
            assert!(!s.contains("17, 17"), "{s}");
            assert!(!s.contains("34, 34"), "{s}");
            assert!(s.contains("<secret>"));
        }
    }

    #[test]
    fn the_code_depends_on_every_input() {
        let real = code(&ctx(), &fp('a'), &fp('b'), &NA, &NB).unwrap();
        let mut na2 = NA;
        na2[0] ^= 0x80;
        let mut nb2 = NB;
        nb2[0] ^= 0x80;
        let mut other = ctx();
        other.responder = "scout::evil.postal.bot".into();
        let variants = [
            code(&ctx(), &fp('a'), &fp('e'), &NA, &NB).unwrap(),
            code(&ctx(), &fp('a'), &fp('b'), &na2, &NB).unwrap(),
            code(&ctx(), &fp('a'), &fp('b'), &NA, &nb2).unwrap(),
            code(&ctx(), &fp('b'), &fp('a'), &NA, &NB).unwrap(),
            code(&other, &fp('a'), &fp('b'), &NA, &NB).unwrap(),
            code(&ctx(), &fp('a'), &fp('b'), &NB, &NA).unwrap(),
        ];
        for v in &variants {
            assert_ne!(v, &real, "changing any input must change the code (fixed vectors)");
        }
    }

    #[test]
    fn context_framing_keeps_fields_apart() {
        let a = PairContext { pair_id: "ab".into(), initiator: "c".into(), responder: "d".into() };
        let b = PairContext { pair_id: "a".into(), initiator: "bc".into(), responder: "d".into() };
        assert_ne!(a.framed().unwrap(), b.framed().unwrap());
    }

    #[test]
    fn wire_forms_round_trip() {
        let (a, c) = Initiator::start_with(ctx(), fp('a'), NA, T0).unwrap();
        assert_eq!(Commitment::from_hex(&c.to_hex()).unwrap(), c);
        let (_b, resp) = Responder::respond_with(ctx(), fp('a'), c, fp('b'), NB, T0);
        assert_eq!(Response::from_parts(&resp.fp_b.to_hex(), &resp.nb_hex()).unwrap(), resp);
        let (reveal, _) = a.finish(resp, T0).unwrap();
        assert_eq!(Reveal::from_hex(&reveal.to_hex()).unwrap(), reveal);
    }

    /// Golden vectors, computed with Python's hashlib (`vectors/postal-v1.json`).
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        for v in all["pairing"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let ctx = PairContext { pair_id: s("pair_id"), initiator: s("initiator"), responder: s("responder") };
            let fa = Fingerprint::parse(&s("fp_a")).unwrap();
            let fb = Fingerprint::parse(&s("fp_b")).unwrap();
            let na = from_hex32(&s("na_hex")).unwrap();
            let nb = from_hex32(&s("nb_hex")).unwrap();
            let (a, c) = Initiator::start_with(ctx.clone(), fa, na, T0).unwrap();
            assert_eq!(c.to_hex(), s("commitment_hex"));
            let (b, resp) = Responder::respond_with(ctx, fa, c, fb, nb, T0);
            let (reveal, code_a) = a.finish(resp, T0).unwrap();
            assert_eq!(code_a.as_str(), s("sas"));
            assert_eq!(b.finish(reveal, T0).unwrap().as_str(), s("sas"));
        }
        for v in all["pairing_refused"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            match s("case").as_str() {
                "bad_fingerprint" => assert_eq!(Fingerprint::parse(&s("fp")), Err(PairError::BadFingerprint)),
                "wrong_reveal" => {
                    let ctx = PairContext { pair_id: s("pair_id"), initiator: s("initiator"), responder: s("responder") };
                    let fa = Fingerprint::parse(&s("fp_a")).unwrap();
                    let fb = Fingerprint::parse(&s("fp_b")).unwrap();
                    let c = Commitment::from_hex(&s("commitment_hex")).unwrap();
                    let (b, _) = Responder::respond_with(ctx, fa, c, fb, NB, T0);
                    let reveal = Reveal::from_hex(&s("reveal_hex")).unwrap();
                    assert_eq!(b.finish(reveal, T0), Err(PairError::Mismatch));
                }
                other => panic!("unknown refused case {other}"),
            }
        }
    }
}
