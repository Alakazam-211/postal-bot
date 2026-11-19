//! Commit-then-reveal pairing code (SAS v2) and the signed confirmation that
//! ends it, as typed state machines.
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
//! - Keys come in as SPKI PEM and the SDK derives every fingerprint itself.
//! - Each box signs a confirmation, and pins its peer only after both its
//!   own owner's check and the peer's signed accept.
//!
//! The numeric-comparison pattern of ZRTP (RFC 6189) and Bluetooth Secure
//! Simple Pairing (Vaudenay's SAS-MCA):
//!
//! 1. A ([`Initiator::start`]) picks a 32-byte nonce `Na` and sends only its
//!    [`Commitment`] `C = SHA-256("postal-pair-commit-v1" || ctx || fp_a || Na)`.
//! 2. B ([`Responder::respond`]) keeps `C`, fixes its own key, picks `Nb`,
//!    and sends both together ([`Response`]), only after it has `C`.
//! 3. A ([`Initiator::finish`]) reveals `Na` only after it has B's response.
//! 4. B ([`Responder::finish`]) checks `Na` against the `C` it kept, so a
//!    plane that saw `Nb` can't pick a new `Na` to steer the code.
//! 5. Both get a [`Handshake`] that shows
//!    `SAS = SHA-256("postal-pair-v1" || ctx || fp_a || fp_b || Na || Nb)`
//!    reduced to 6 decimal digits, and binds the transcript
//!    `T = SHA-256("postal-pair-transcript-v1" || ctx || fp_a || fp_b || C || Na || Nb)`.
//! 6. Each owner reads the code on the **other** box (aloud, or off the
//!    other person's screen) and types it into their own. [`Handshake::confirm`]
//!    checks it in constant time and only then signs `accept`. A wrong code
//!    signs `mismatch`. The signed message is
//!    `"postal-pair-confirm-v1" || frame(pair_id) || frame(side) || frame(decision) || T`,
//!    under that side's handle key (Ed25519).
//! 7. The box pins the peer ([`AwaitingPeer::peer_confirmation`]) only when
//!    the peer's `accept` verifies against the peer key over this box's own `T`.
//!
//! The plane relays all of this and never sees or judges a code. A plane in
//! the middle runs two handshakes with two different codes. Each owner then
//! types a code their own box doesn't show, and both boxes sign `mismatch`.
//!
//! **Host rules the types can't enforce:** keep one [`Attempts`] per
//! (local handle, peer), persisted, and pass it to every start and respond.
//! Show a person the code from [`Handshake::code`]; never accept the code
//! from the plane, an agent or this box's own display as the typed value.
//! Nonces are secrets until revealed; never log them.

use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::hex::{from_hex32, to_hex};

/// Domain prefix of the commitment. Postal's own; never K2's.
pub const COMMIT_PREFIX: &[u8] = b"postal-pair-commit-v1";
/// Domain prefix of the code. Postal's own; never K2's.
pub const SAS_PREFIX: &[u8] = b"postal-pair-v1";
/// Domain prefix of the transcript hash.
pub const TRANSCRIPT_PREFIX: &[u8] = b"postal-pair-transcript-v1";
/// Domain prefix of a signed confirmation.
pub const CONFIRM_PREFIX: &[u8] = b"postal-pair-confirm-v1";
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 32;
/// A pairing state is single-use and expires this many seconds after it was made.
pub const NONCE_TTL_SECS: i64 = 600;
/// Pairing attempts allowed with one peer per [`ATTEMPT_WINDOW_SECS`].
pub const MAX_ATTEMPTS: usize = 5;
/// The window [`MAX_ATTEMPTS`] counts over.
pub const ATTEMPT_WINDOW_SECS: i64 = 3600;

type Nonce = [u8; NONCE_LEN];

/// Why a pairing step was refused. Any error ends this pairing attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairError {
    /// Not exactly 64 lowercase hex characters.
    BadFingerprint,
    /// Not exactly 64 hex characters.
    BadHex,
    /// Not a plane v2 pair id (16 to 64 ASCII letters and digits).
    BadPairId,
    /// Not an Ed25519 `PUBLIC KEY` (SPKI) PEM, or a weak key.
    BadKey,
    /// Not standard padded base64 of exactly 64 bytes, or it doesn't verify.
    BadSignature,
    /// The host's signer doesn't hold this side's handle key.
    WrongSigner,
    /// A pairing context field is longer than 4 GiB.
    TooLong,
    /// More than [`NONCE_TTL_SECS`] since this state was made (or a clock
    /// that went backwards).
    Expired,
    /// The revealed nonce doesn't open the commitment.
    Mismatch,
    /// [`MAX_ATTEMPTS`] already used with this peer in the window.
    TooManyAttempts,
    /// This pair id was already used with this peer.
    Replayed,
    /// The peer signed something other than `accept`.
    PeerRefused(Decision),
    /// The OS random source failed.
    Random(String),
}

impl std::fmt::Display for PairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadFingerprint => f.write_str("fingerprint must be 64 lowercase hex characters"),
            Self::BadHex => f.write_str("expected 64 hex characters"),
            Self::BadPairId => f.write_str("pair id must be 16 to 64 ASCII letters and digits"),
            Self::BadKey => f.write_str("not an Ed25519 PUBLIC KEY PEM"),
            Self::BadSignature => {
                f.write_str("confirmation signature is malformed or does not verify")
            }
            Self::WrongSigner => f.write_str("the signer does not hold this handle's key"),
            Self::TooLong => f.write_str("pairing context field too long"),
            Self::Expired => f.write_str("pairing step expired; start again"),
            Self::Mismatch => f.write_str("revealed nonce does not match the commitment"),
            Self::TooManyAttempts => {
                f.write_str("too many pairing attempts with this peer; wait an hour")
            }
            Self::Replayed => f.write_str("this pair id was already used with this peer"),
            Self::PeerRefused(d) => write!(f, "the peer signed {}", d.as_str()),
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
    /// Pairing never takes a fingerprint from outside: peers come in as
    /// [`PublicKey`] and the SDK derives theirs. This is for display and for
    /// comparing against a stored pin.
    ///
    /// # Errors
    /// [`PairError::BadFingerprint`] for any other form.
    pub fn parse(s: &str) -> Result<Self, PairError> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PairError::BadFingerprint);
        }
        from_hex32(s)
            .map(Self)
            .map_err(|_| PairError::BadFingerprint)
    }

    /// Raw SHA-256 bytes. For a stored pin, never for a pairing input.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

/// An Ed25519 handle key. Its fingerprint is always derived from the key,
/// never taken from the plane.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    vk: VerifyingKey,
    fp: Fingerprint,
    pem: String,
}

impl PublicKey {
    /// # Errors
    /// [`PairError::BadKey`] unless it's an Ed25519 SPKI PEM of a key that
    /// isn't of small order.
    pub fn from_pem(pem: &str) -> Result<Self, PairError> {
        let pem = pem.trim();
        let vk = VerifyingKey::from_public_key_pem(pem).map_err(|_| PairError::BadKey)?;
        if vk.is_weak() {
            return Err(PairError::BadKey);
        }
        let der = vk.to_public_key_der().map_err(|_| PairError::BadKey)?;
        let fp = Fingerprint(Sha256::digest(der.as_bytes()).into());
        Ok(Self {
            vk,
            fp,
            pem: pem.to_string(),
        })
    }

    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.fp
    }

    #[must_use]
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// Strict Ed25519 verification (RFC 8032 with the small-order and
    /// non-canonical checks).
    #[must_use]
    pub fn verifies(&self, message: &[u8], sig: &[u8; 64]) -> bool {
        self.vk
            .verify_strict(message, &Signature::from_bytes(sig))
            .is_ok()
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey").field(&self.fp.to_hex()).finish()
    }
}

/// What this pairing is about. Bound into the commitment, the code, the
/// transcript and every confirmation, so nothing from one pairing can be
/// replayed into another.
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
            frame_into(&mut out, field.as_bytes())?;
        }
        Ok(out)
    }
}

fn frame_into(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PairError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PairError::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Which end of the pair a box is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The initiator (`from`).
    From,
    /// The responder (`to`).
    To,
}

impl Side {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::From => "from",
            Self::To => "to",
        }
    }
    const fn other(self) -> Self {
        match self {
            Self::From => Self::To,
            Self::To => Self::From,
        }
    }
}

/// What a confirmation says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The owner typed the other box's code and it matched.
    Accept,
    /// The owner said no.
    Reject,
    /// The owner typed a code that didn't match: a misread, or a party in
    /// the middle. Both owners are alerted.
    Mismatch,
}

impl Decision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Mismatch => "mismatch",
        }
    }

    /// The wire spelling, as the plane relays a stored confirmation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "accept" => Some(Self::Accept),
            "reject" => Some(Self::Reject),
            "mismatch" => Some(Self::Mismatch),
            _ => None,
        }
    }
}

/// Pairing attempts with one peer, kept by the box (not the plane, which
/// may be the attacker). Every start and respond takes one, so each extra
/// try a party in the middle gets is counted here. The host keeps one per
/// (local handle, peer) and persists [`Attempts::log`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attempts {
    log: Vec<(i64, String)>,
}

impl Attempts {
    #[must_use]
    pub fn from_log(log: Vec<(i64, String)>) -> Self {
        Self { log }
    }

    /// `(unix seconds, pair id)` of each attempt still in the window.
    #[must_use]
    pub fn log(&self) -> &[(i64, String)] {
        &self.log
    }

    fn take(&mut self, pair_id: &str, now: i64) -> Result<(), PairError> {
        // Entries from the future (a clock that went back) still count.
        self.log.retain(|(at, _)| {
            now.checked_sub(*at)
                .is_none_or(|age| age < ATTEMPT_WINDOW_SECS)
        });
        if self.log.iter().any(|(_, id)| id == pair_id) {
            return Err(PairError::Replayed);
        }
        if self.log.len() >= MAX_ATTEMPTS {
            return Err(PairError::TooManyAttempts);
        }
        self.log.push((now, pair_id.to_string()));
        Ok(())
    }
}

/// Step 1, A → B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment([u8; 32]);

/// Step 2, B → A: B's key and nonce, together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    key: PublicKey,
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
    /// B's key exactly as it will be pinned.
    #[must_use]
    pub fn key(&self) -> &PublicKey {
        &self.key
    }
    #[must_use]
    pub fn nb_hex(&self) -> String {
        to_hex(&self.nb)
    }
    /// From the plane's `/respond` fields. The fingerprint is derived from
    /// the PEM, never read from the plane.
    ///
    /// # Errors
    /// [`PairError::BadKey`] or [`PairError::BadHex`].
    pub fn from_parts(public_key_pem: &str, nb_hex: &str) -> Result<Self, PairError> {
        Ok(Self {
            key: PublicKey::from_pem(public_key_pem)?,
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

/// The 6 digits this box shows its owner, to read out to the other side.
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
        let (a, b) = (self.0.as_bytes(), typed.trim().as_bytes());
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

/// A's side, after step 1. No `Clone`, and `Debug` never prints `Na`.
pub struct Initiator {
    ctx: PairContext,
    me: PublicKey,
    c: Commitment,
    na: Nonce,
    made_at: i64,
}

impl Initiator {
    /// Step 1. Returns the state to keep and the commitment to send.
    /// `me` is this handle's own key; `now` is unix seconds.
    ///
    /// # Errors
    /// [`PairError::TooManyAttempts`], [`PairError::Replayed`],
    /// [`PairError::Random`] or [`PairError::TooLong`].
    pub fn start(
        ctx: PairContext,
        me: PublicKey,
        attempts: &mut Attempts,
        now: i64,
    ) -> Result<(Self, Commitment), PairError> {
        Self::start_with(ctx, me, attempts, new_nonce()?, now)
    }

    fn start_with(
        ctx: PairContext,
        me: PublicKey,
        attempts: &mut Attempts,
        na: Nonce,
        now: i64,
    ) -> Result<(Self, Commitment), PairError> {
        let c = commitment(&ctx, &me.fp, &na)?;
        attempts.take(&ctx.pair_id, now)?;
        Ok((
            Self {
                ctx,
                me,
                c,
                na,
                made_at: now,
            },
            c,
        ))
    }

    /// Step 3, once B's response is in. Returns the reveal to send and the
    /// handshake. Consumes the state: `Na` is revealed once.
    ///
    /// # Errors
    /// [`PairError::Expired`] or [`PairError::TooLong`].
    pub fn finish(self, resp: Response, now: i64) -> Result<(Reveal, Handshake), PairError> {
        fresh(self.made_at, now)?;
        let hs = Handshake::new(
            self.ctx,
            Side::From,
            self.me,
            resp.key,
            self.c,
            &self.na,
            &resp.nb,
        )?;
        Ok((Reveal(self.na), hs))
    }
}

/// B's side, after step 2. No `Clone`, and `Debug` never prints `Nb`.
pub struct Responder {
    ctx: PairContext,
    peer: PublicKey,
    me: PublicKey,
    c: Commitment,
    nb: Nonce,
    made_at: i64,
}

impl Responder {
    /// Step 2, once A's commitment is in. `C` is kept here, before `Nb`
    /// leaves, and B's key is fixed with `Nb`. `initiator` is A's key from
    /// the plane's pair row; its fingerprint is derived here.
    ///
    /// # Errors
    /// [`PairError::TooManyAttempts`], [`PairError::Replayed`] or
    /// [`PairError::Random`].
    pub fn respond(
        ctx: PairContext,
        initiator: PublicKey,
        c: Commitment,
        me: PublicKey,
        attempts: &mut Attempts,
        now: i64,
    ) -> Result<(Self, Response), PairError> {
        Self::respond_with(ctx, initiator, c, me, attempts, new_nonce()?, now)
    }

    fn respond_with(
        ctx: PairContext,
        initiator: PublicKey,
        c: Commitment,
        me: PublicKey,
        attempts: &mut Attempts,
        nb: Nonce,
        now: i64,
    ) -> Result<(Self, Response), PairError> {
        attempts.take(&ctx.pair_id, now)?;
        let resp = Response {
            key: me.clone(),
            nb,
        };
        Ok((
            Self {
                ctx,
                peer: initiator,
                me,
                c,
                nb,
                made_at: now,
            },
            resp,
        ))
    }

    /// Step 4, once A reveals. Checks `Na` against the commitment kept in
    /// step 2 (constant time) and returns the handshake. Consumes the state.
    ///
    /// # Errors
    /// [`PairError::Expired`], [`PairError::Mismatch`] or [`PairError::TooLong`].
    pub fn finish(self, reveal: Reveal, now: i64) -> Result<Handshake, PairError> {
        fresh(self.made_at, now)?;
        let expect = commitment(&self.ctx, &self.peer.fp, &reveal.0)?;
        if !bool::from(expect.0.ct_eq(&self.c.0)) {
            return Err(PairError::Mismatch);
        }
        Handshake::new(
            self.ctx,
            Side::To,
            self.me,
            self.peer,
            self.c,
            &reveal.0,
            &self.nb,
        )
    }
}

/// Signs with this handle's private key. The SDK never holds private keys.
pub trait Signer {
    /// Ed25519 (RFC 8032) signature over `message`.
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

impl Signer for ed25519_dalek::SigningKey {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        ed25519_dalek::Signer::sign(self, message).to_bytes()
    }
}

/// A finished handshake, waiting for this box's owner. No `Clone`: it
/// confirms once.
pub struct Handshake {
    ctx: PairContext,
    side: Side,
    me: PublicKey,
    peer: PublicKey,
    transcript: [u8; 32],
    code: Code,
}

impl Handshake {
    fn new(
        ctx: PairContext,
        side: Side,
        me: PublicKey,
        peer: PublicKey,
        c: Commitment,
        na: &Nonce,
        nb: &Nonce,
    ) -> Result<Self, PairError> {
        let (fp_a, fp_b) = match side {
            Side::From => (me.fp, peer.fp),
            Side::To => (peer.fp, me.fp),
        };
        let code = code(&ctx, &fp_a, &fp_b, na, nb)?;
        let transcript = transcript(&ctx, &fp_a, &fp_b, &c, na, nb)?;
        Ok(Self {
            ctx,
            side,
            me,
            peer,
            transcript,
            code,
        })
    }

    /// Show this to **this** box's owner, to read out to the other side.
    /// It is never the value to type into this box.
    #[must_use]
    pub fn code(&self) -> &Code {
        &self.code
    }
    #[must_use]
    pub fn side(&self) -> Side {
        self.side
    }
    #[must_use]
    pub fn context(&self) -> &PairContext {
        &self.ctx
    }
    #[must_use]
    pub fn peer_key(&self) -> &PublicKey {
        &self.peer
    }
    /// `T`, as the plane's `transcript_sha256`.
    #[must_use]
    pub fn transcript_hex(&self) -> String {
        to_hex(&self.transcript)
    }

    /// The owner typed the code shown on the **other** box. If it matches
    /// this box's code, sign `accept` and wait for the peer's. If not, sign
    /// `mismatch`. There is no other way to get a signed accept.
    ///
    /// # Errors
    /// [`PairError::WrongSigner`] or [`PairError::TooLong`].
    pub fn confirm(
        self,
        typed_other_code: &str,
        signer: &dyn Signer,
    ) -> Result<Confirmed, PairError> {
        if self.code.matches(typed_other_code) {
            let confirmation = self.sign(Decision::Accept, signer)?;
            Ok(Confirmed::Accept {
                confirmation,
                awaiting: Box::new(AwaitingPeer {
                    ctx: self.ctx,
                    side: self.side,
                    peer: self.peer,
                    transcript: self.transcript,
                }),
            })
        } else {
            Ok(Confirmed::Mismatch {
                confirmation: self.sign(Decision::Mismatch, signer)?,
            })
        }
    }

    /// The owner said no.
    ///
    /// # Errors
    /// [`PairError::WrongSigner`] or [`PairError::TooLong`].
    pub fn reject(self, signer: &dyn Signer) -> Result<Confirmation, PairError> {
        self.sign(Decision::Reject, signer)
    }

    fn sign(&self, decision: Decision, signer: &dyn Signer) -> Result<Confirmation, PairError> {
        let msg = confirm_message(&self.ctx.pair_id, self.side, decision, &self.transcript)?;
        let sig = signer.sign(&msg);
        // A signer holding another key would make a confirmation the plane
        // and the peer refuse; catch it here.
        self.me
            .vk
            .verify_strict(&msg, &Signature::from_bytes(&sig))
            .map_err(|_| PairError::WrongSigner)?;
        Ok(Confirmation {
            pair_id: self.ctx.pair_id.clone(),
            side: self.side,
            decision,
            transcript: self.transcript,
            sig,
        })
    }
}

impl std::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("ctx", &self.ctx)
            .field("side", &self.side)
            .field("peer", &self.peer)
            .field("transcript", &self.transcript_hex())
            .finish_non_exhaustive()
    }
}

/// What [`Handshake::confirm`] gives back.
#[derive(Debug)]
pub enum Confirmed {
    /// Send `confirmation`, then wait for the peer's with `awaiting`.
    Accept {
        confirmation: Confirmation,
        awaiting: Box<AwaitingPeer>,
    },
    /// Send `confirmation`; the pair fails and both owners are told.
    Mismatch { confirmation: Confirmation },
}

/// One side's signed confirmation, for `POST /v1/pairs/{id}/confirm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pair_id: String,
    side: Side,
    decision: Decision,
    transcript: [u8; 32],
    sig: [u8; 64],
}

impl Confirmation {
    #[must_use]
    pub fn side(&self) -> Side {
        self.side
    }
    #[must_use]
    pub fn decision(&self) -> Decision {
        self.decision
    }
    #[must_use]
    pub fn transcript_hex(&self) -> String {
        to_hex(&self.transcript)
    }
    /// Standard padded base64 (RFC 4648 §4), 64 bytes decoded.
    #[must_use]
    pub fn sig_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.sig)
    }

    /// `POST {base}/api/postal/v1/pairs/{id}/confirm`.
    ///
    /// # Errors
    /// [`PairError::BadPairId`].
    pub fn path(&self) -> Result<String, PairError> {
        confirm_path(&self.pair_id)
    }

    /// The request body, exactly the plane's
    /// `{side, decision, transcript_sha256, sig}`. Every value is a fixed
    /// word, hex or base64, so nothing needs escaping.
    #[must_use]
    pub fn body_json(&self) -> String {
        format!(
            r#"{{"side":"{}","decision":"{}","transcript_sha256":"{}","sig":"{}"}}"#,
            self.side.as_str(),
            self.decision.as_str(),
            self.transcript_hex(),
            self.sig_base64()
        )
    }

    /// The plane answered 409 (this side already confirmed). Ed25519 is
    /// deterministic, so a retry of the same confirmation carries the same
    /// signature: if the stored one is ours, the earlier send landed and
    /// this one is done. Anything else is a real conflict.
    #[must_use]
    pub fn same_as_stored(&self, stored_sig_base64: &str) -> bool {
        stored_sig_base64.trim() == self.sig_base64()
    }
}

/// Plane pair routes (K2 Web plane v1). The base URL is host config.
pub const PAIRS_PATH: &str = "/api/postal/v1/pairs";
/// Body of a revoke: unsigned, owner credentials of either side.
pub const REVOKE_BODY: &str = "{}";

/// The plane's v2 pair ids (a ULID in practice). Also keeps the id a safe
/// path segment.
fn check_pair_id(id: &str) -> Result<(), PairError> {
    if (16..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(PairError::BadPairId)
    }
}

/// `POST {base}/api/postal/v1/pairs/{id}/confirm`.
///
/// # Errors
/// [`PairError::BadPairId`].
pub fn confirm_path(pair_id: &str) -> Result<String, PairError> {
    check_pair_id(pair_id)?;
    Ok(format!("{PAIRS_PATH}/{pair_id}/confirm"))
}

/// `POST {base}/api/postal/v1/pairs/{id}/revoke` with [`REVOKE_BODY`].
///
/// # Errors
/// [`PairError::BadPairId`].
pub fn revoke_path(pair_id: &str) -> Result<String, PairError> {
    check_pair_id(pair_id)?;
    Ok(format!("{PAIRS_PATH}/{pair_id}/revoke"))
}

/// This box's owner accepted. The peer isn't trusted until its own signed
/// accept verifies here. No `Clone`.
pub struct AwaitingPeer {
    ctx: PairContext,
    side: Side,
    peer: PublicKey,
    transcript: [u8; 32],
}

impl AwaitingPeer {
    /// The peer's confirmation, as relayed by the plane. It's checked against
    /// the peer key and **this box's** transcript, never the plane's.
    ///
    /// # Errors
    /// [`PairError::BadSignature`] if it doesn't verify, or
    /// [`PairError::PeerRefused`] if it verifies but isn't `accept`.
    pub fn peer_confirmation(
        self,
        decision: Decision,
        sig_base64: &str,
    ) -> Result<Pinned, PairError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sig_base64.trim())
            .map_err(|_| PairError::BadSignature)?;
        let sig: [u8; 64] = raw.try_into().map_err(|_| PairError::BadSignature)?;
        let msg = confirm_message(
            &self.ctx.pair_id,
            self.side.other(),
            decision,
            &self.transcript,
        )?;
        self.peer
            .vk
            .verify_strict(&msg, &Signature::from_bytes(&sig))
            .map_err(|_| PairError::BadSignature)?;
        if decision != Decision::Accept {
            return Err(PairError::PeerRefused(decision));
        }
        let (local, peer) = match self.side {
            Side::From => (self.ctx.initiator, self.ctx.responder),
            Side::To => (self.ctx.responder, self.ctx.initiator),
        };
        Ok(Pinned {
            local,
            peer,
            key: self.peer,
        })
    }
}

impl std::fmt::Debug for AwaitingPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwaitingPeer")
            .field("ctx", &self.ctx)
            .field("side", &self.side)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Both owners confirmed. The only value a host should pin from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// This box's handle.
    pub local: String,
    /// The friend's address.
    pub peer: String,
    /// The friend's key; its fingerprint was derived by the SDK.
    pub key: PublicKey,
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("ctx", &self.ctx)
            .field("me", &self.me)
            .field("na", &"<secret>")
            .field("made_at", &self.made_at)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("ctx", &self.ctx)
            .field("peer", &self.peer)
            .field("me", &self.me)
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

fn code(
    ctx: &PairContext,
    fp_a: &Fingerprint,
    fp_b: &Fingerprint,
    na: &Nonce,
    nb: &Nonce,
) -> Result<Code, PairError> {
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

fn transcript(
    ctx: &PairContext,
    fp_a: &Fingerprint,
    fp_b: &Fingerprint,
    c: &Commitment,
    na: &Nonce,
    nb: &Nonce,
) -> Result<[u8; 32], PairError> {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_PREFIX);
    h.update(ctx.framed()?);
    h.update(fp_a.0);
    h.update(fp_b.0);
    h.update(c.0);
    h.update(na);
    h.update(nb);
    Ok(h.finalize().into())
}

fn confirm_message(
    pair_id: &str,
    side: Side,
    decision: Decision,
    t: &[u8; 32],
) -> Result<Vec<u8>, PairError> {
    let mut m = CONFIRM_PREFIX.to_vec();
    frame_into(&mut m, pair_id.as_bytes())?;
    frame_into(&mut m, side.as_str().as_bytes())?;
    frame_into(&mut m, decision.as_str().as_bytes())?;
    m.extend_from_slice(t);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

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

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk(k: &SigningKey) -> PublicKey {
        let pem = k
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        PublicKey::from_pem(&pem).unwrap()
    }

    /// One honest handshake with fixed nonces. Returns (A's, B's).
    fn handshake(
        ctx_a: PairContext,
        ctx_b: PairContext,
        a: &SigningKey,
        b: &SigningKey,
    ) -> Result<(Handshake, Handshake), PairError> {
        let (st_a, c) = Initiator::start_with(ctx_a, pk(a), &mut Attempts::default(), NA, T0)?;
        let (st_b, resp) =
            Responder::respond_with(ctx_b, pk(a), c, pk(b), &mut Attempts::default(), NB, T0 + 1)?;
        let (reveal, hs_a) = st_a.finish(resp, T0 + 2)?;
        let hs_b = st_b.finish(reveal, T0 + 3)?;
        Ok((hs_a, hs_b))
    }

    fn accept(hs: Handshake, typed: &str, k: &SigningKey) -> (Confirmation, AwaitingPeer) {
        match hs.confirm(typed, k).unwrap() {
            Confirmed::Accept {
                confirmation,
                awaiting,
            } => (confirmation, *awaiting),
            Confirmed::Mismatch { .. } => panic!("expected accept"),
        }
    }

    #[test]
    fn both_sides_compute_the_same_code_and_transcript() {
        let (a, b) = handshake(ctx(), ctx(), &sk(1), &sk(2)).unwrap();
        assert_eq!(a.code(), b.code());
        assert_eq!(a.transcript_hex(), b.transcript_hex());
        assert_eq!(a.code().as_str().len(), 6);
        assert!(a.code().as_str().chars().all(|c| c.is_ascii_digit()));
        assert!(
            !a.code().matches("12345"),
            "a different length never matches"
        );
    }

    /// Both owners type the code on the other box: both sign accept, and
    /// each pins the other only after the other's accept verifies.
    #[test]
    fn both_confirmed_pairs() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, b) = handshake(ctx(), ctx(), &ka, &kb).unwrap();
        let (code_a, code_b) = (a.code().clone(), b.code().clone());
        let (conf_a, wait_a) = accept(a, code_b.as_str(), &ka);
        let (conf_b, wait_b) = accept(b, code_a.as_str(), &kb);
        assert_eq!(conf_a.side(), Side::From);
        assert_eq!(conf_b.side(), Side::To);
        let pinned_a = wait_a
            .peer_confirmation(conf_b.decision(), &conf_b.sig_base64())
            .unwrap();
        let pinned_b = wait_b
            .peer_confirmation(conf_a.decision(), &conf_a.sig_base64())
            .unwrap();
        assert_eq!(pinned_a.peer, "scout::acme.postal.bot");
        assert_eq!(pinned_a.local, "alice::acme.postal.bot");
        assert_eq!(pinned_a.key.fingerprint(), pk(&kb).fingerprint());
        assert_eq!(pinned_b.peer, "alice::acme.postal.bot");
        assert_eq!(pinned_b.key.fingerprint(), pk(&ka).fingerprint());
    }

    /// A plane in the middle runs A↔M and M↔B with the same pair id and
    /// addresses. Each owner types the code the other box shows; neither
    /// matches, so both boxes sign mismatch and nothing is pinned.
    #[test]
    fn plane_in_the_middle_fails_to_pair() {
        let (ka, kb, km1, km2) = (sk(1), sk(2), sk(3), sk(4));
        let (a, _m_as_b) = handshake(ctx(), ctx(), &ka, &km1).unwrap();
        let (_m_as_a, b) = handshake(ctx(), ctx(), &km2, &kb).unwrap();
        assert_ne!(a.code(), b.code(), "two handshakes, two codes");
        assert_ne!(a.transcript_hex(), b.transcript_hex());
        let (code_a, code_b) = (a.code().clone(), b.code().clone());
        for (hs, typed, k) in [(a, code_b, &ka), (b, code_a, &kb)] {
            match hs.confirm(typed.as_str(), k).unwrap() {
                Confirmed::Mismatch { confirmation } => {
                    assert_eq!(confirmation.decision(), Decision::Mismatch)
                }
                Confirmed::Accept { .. } => panic!("a plane in the middle must not pair"),
            }
        }
    }

    /// B4: a wrong code on either side signs mismatch, never accept.
    #[test]
    fn a_wrong_code_on_either_side_is_mismatch() {
        let (ka, kb) = (sk(1), sk(2));
        for side in [Side::From, Side::To] {
            let (a, b) = handshake(ctx(), ctx(), &ka, &kb).unwrap();
            let (hs, k) = if side == Side::From {
                (a, &ka)
            } else {
                (b, &kb)
            };
            let wrong = format!(
                "{:06}",
                (hs.code().as_str().parse::<u32>().unwrap() + 1) % 1_000_000
            );
            match hs.confirm(&wrong, k).unwrap() {
                Confirmed::Mismatch { confirmation } => {
                    assert_eq!(confirmation.side(), side);
                    assert_eq!(confirmation.decision(), Decision::Mismatch);
                }
                Confirmed::Accept { .. } => panic!("wrong code on {side:?} accepted"),
            }
        }
    }

    /// One side only: an AwaitingPeer pins nothing without a valid peer
    /// accept over its own transcript, from the peer's own key.
    #[test]
    fn one_side_only_stays_unpinned() {
        let (ka, kb, kx) = (sk(1), sk(2), sk(9));
        let msg =
            |side, d, t: &str| confirm_message("pair-1", side, d, &from_hex32(t).unwrap()).unwrap();
        let b64 = |s: [u8; 64]| base64::engine::general_purpose::STANDARD.encode(s);
        let fresh_wait = || {
            let (a, b) = handshake(ctx(), ctx(), &ka, &kb).unwrap();
            let t = a.transcript_hex();
            let code_b = b.code().clone();
            (accept(a, code_b.as_str(), &ka).1, t)
        };
        // The peer refused, signed properly.
        let (w, t) = fresh_wait();
        let sig = Signer::sign(&kb, &msg(Side::To, Decision::Reject, &t));
        assert_eq!(
            w.peer_confirmation(Decision::Reject, &b64(sig))
                .unwrap_err(),
            PairError::PeerRefused(Decision::Reject)
        );
        let (w, t) = fresh_wait();
        let sig = Signer::sign(&kb, &msg(Side::To, Decision::Mismatch, &t));
        assert_eq!(
            w.peer_confirmation(Decision::Mismatch, &b64(sig))
                .unwrap_err(),
            PairError::PeerRefused(Decision::Mismatch)
        );
        // A plane claiming "accept" for a reject signature.
        let (w, t) = fresh_wait();
        let sig = Signer::sign(&kb, &msg(Side::To, Decision::Reject, &t));
        assert_eq!(
            w.peer_confirmation(Decision::Accept, &b64(sig))
                .unwrap_err(),
            PairError::BadSignature
        );
        // Signed by a key that isn't the peer's (the plane has no handle key).
        let (w, t) = fresh_wait();
        let sig = Signer::sign(&kx, &msg(Side::To, Decision::Accept, &t));
        assert_eq!(
            w.peer_confirmation(Decision::Accept, &b64(sig))
                .unwrap_err(),
            PairError::BadSignature
        );
        // The peer's accept over a different transcript.
        let (w, _t) = fresh_wait();
        let sig = Signer::sign(&kb, &msg(Side::To, Decision::Accept, &"ee".repeat(32)));
        assert_eq!(
            w.peer_confirmation(Decision::Accept, &b64(sig))
                .unwrap_err(),
            PairError::BadSignature
        );
        // This box's own accept echoed back as the peer's.
        let (w, t) = fresh_wait();
        let sig = Signer::sign(&ka, &msg(Side::From, Decision::Accept, &t));
        assert_eq!(
            w.peer_confirmation(Decision::Accept, &b64(sig))
                .unwrap_err(),
            PairError::BadSignature
        );
        // Malformed signatures.
        for bad in ["", "AAAA", &b64([0; 64])[..80], "not base64!"] {
            let (w, _) = fresh_wait();
            assert_eq!(
                w.peer_confirmation(Decision::Accept, bad).unwrap_err(),
                PairError::BadSignature,
                "{bad:?}"
            );
        }
    }

    fn ulid_ctx() -> PairContext {
        PairContext {
            pair_id: "01JCONFIRMROUTE0000000000A".into(),
            ..ctx()
        }
    }

    /// K2 Web's FINAL route: `POST /api/postal/v1/pairs/{id}/confirm` with
    /// exactly `{side, decision, transcript_sha256, sig}`.
    #[test]
    fn confirm_route_and_body_match_the_plane() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, b) = handshake(ulid_ctx(), ulid_ctx(), &ka, &kb).unwrap();
        let t = a.transcript_hex();
        let code_b = b.code().clone();
        let (conf, _) = accept(a, code_b.as_str(), &ka);
        assert_eq!(
            conf.path().unwrap(),
            "/api/postal/v1/pairs/01JCONFIRMROUTE0000000000A/confirm"
        );
        let body: serde_json::Value = serde_json::from_str(&conf.body_json()).unwrap();
        let obj = body.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["decision", "side", "sig", "transcript_sha256"]);
        assert_eq!(obj["side"], "from");
        assert_eq!(obj["decision"], "accept");
        assert_eq!(obj["transcript_sha256"], t.as_str());
        let sig = base64::engine::general_purpose::STANDARD
            .decode(obj["sig"].as_str().unwrap())
            .unwrap();
        assert_eq!(sig.len(), 64);
        assert!(
            obj["sig"].as_str().unwrap().ends_with("=="),
            "standard padded base64"
        );
        assert_eq!(
            revoke_path("01JCONFIRMROUTE0000000000A").unwrap(),
            "/api/postal/v1/pairs/01JCONFIRMROUTE0000000000A/revoke"
        );
        assert_eq!(REVOKE_BODY, "{}");
    }

    #[test]
    fn pair_ids_must_be_plane_ids_and_safe_path_segments() {
        for bad in [
            "",
            "pair-1",
            "short",
            "../../etc/passwd",
            "01JCONFIRMROUTE00000000/0A",
            "01JCONFIRMROUTE0000000000A?x=1",
            &"A".repeat(65),
            "01JCONFIRMROUTÉ000000000A",
        ] {
            assert_eq!(confirm_path(bad), Err(PairError::BadPairId), "{bad:?}");
            assert_eq!(revoke_path(bad), Err(PairError::BadPairId), "{bad:?}");
        }
        assert!(confirm_path(&"A".repeat(16)).is_ok());
        assert!(confirm_path(&"A".repeat(64)).is_ok());
    }

    /// From #17: a retry of the same confirmation is idempotent, a different
    /// one conflicts. Ed25519 is deterministic, so the same handshake and
    /// decision always give the same signature.
    #[test]
    fn same_sig_is_idempotent_different_sig_conflicts() {
        let (ka, kb) = (sk(1), sk(2));
        let first = {
            let (a, b) = handshake(ulid_ctx(), ulid_ctx(), &ka, &kb).unwrap();
            let code_b = b.code().clone();
            accept(a, code_b.as_str(), &ka).0
        };
        let retry = {
            let (a, b) = handshake(ulid_ctx(), ulid_ctx(), &ka, &kb).unwrap();
            let code_b = b.code().clone();
            accept(a, code_b.as_str(), &ka).0
        };
        assert_eq!(
            retry.body_json(),
            first.body_json(),
            "a resend is byte for byte the same"
        );
        assert!(
            retry.same_as_stored(&first.sig_base64()),
            "409 with our own sig: done"
        );
        let mismatch = {
            let (a, _) = handshake(ulid_ctx(), ulid_ctx(), &ka, &kb).unwrap();
            match a.confirm("000000", &ka).unwrap() {
                Confirmed::Mismatch { confirmation } => confirmation,
                Confirmed::Accept { .. } => panic!("000000 happened to match; pick another"),
            }
        };
        assert!(
            !mismatch.same_as_stored(&first.sig_base64()),
            "a different decision conflicts"
        );
        let rejected = {
            let (a, _) = handshake(ulid_ctx(), ulid_ctx(), &ka, &kb).unwrap();
            a.reject(&ka).unwrap()
        };
        assert!(!rejected.same_as_stored(&first.sig_base64()));
        assert!(!first.same_as_stored(""));
    }

    /// B4: the SDK only signs with this handle's key.
    #[test]
    fn a_signer_with_another_key_is_refused() {
        let (a, b) = handshake(ctx(), ctx(), &sk(1), &sk(2)).unwrap();
        let code_b = b.code().clone();
        assert_eq!(
            a.confirm(code_b.as_str(), &sk(7)).unwrap_err(),
            PairError::WrongSigner
        );
    }

    /// B1: B keeps C before Nb leaves and checks Na against it. A plane that
    /// saw Nb and tries other Na values to steer the code gets nothing.
    #[test]
    fn a_ground_reveal_is_refused() {
        let (ka, kb) = (sk(1), sk(2));
        let (_a, c) =
            Initiator::start_with(ctx(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        for i in 0..256u32 {
            let (b, _resp) = Responder::respond_with(
                ctx(),
                pk(&ka),
                c,
                pk(&kb),
                &mut Attempts::default(),
                NB,
                T0,
            )
            .unwrap();
            let mut ground = NA;
            ground[..4].copy_from_slice(&i.to_be_bytes());
            ground[31] ^= 1;
            assert_eq!(
                b.finish(Reveal(ground), T0).unwrap_err(),
                PairError::Mismatch
            );
        }
    }

    /// B2: fingerprints come from the key. There is no way to hand pairing
    /// a fingerprint, and a key's fingerprint is SHA-256 of its SPKI DER.
    #[test]
    fn fingerprints_are_derived_from_the_pem() {
        let k = sk(1);
        let der = k.verifying_key().to_public_key_der().unwrap();
        let expect: [u8; 32] = Sha256::digest(der.as_bytes()).into();
        assert_eq!(pk(&k).fingerprint(), Fingerprint(expect));
        for bad in [
            "",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            "not a pem",
        ] {
            assert_eq!(PublicKey::from_pem(bad).unwrap_err(), PairError::BadKey);
        }
        // A small-order (weak) key is refused: its SPKI is valid.
        let weak = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----";
        assert_eq!(PublicKey::from_pem(weak).unwrap_err(), PairError::BadKey);
        // The responder's key arrives as a PEM; its fingerprint is ours to compute.
        let pem = k
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let resp = Response::from_parts(&pem, &"22".repeat(32)).unwrap();
        assert_eq!(resp.key().fingerprint(), Fingerprint(expect));
    }

    /// B3: the box counts attempts per peer, whatever the plane allows.
    #[test]
    fn the_box_limits_attempts_per_peer() {
        let ka = sk(1);
        let mut log = Attempts::default();
        for i in 0..MAX_ATTEMPTS {
            let mut c = ctx();
            c.pair_id = format!("p{i}");
            Initiator::start_with(c, pk(&ka), &mut log, NA, T0 + i64::try_from(i).unwrap())
                .unwrap();
        }
        let mut c = ctx();
        c.pair_id = "p-extra".into();
        assert_eq!(
            Initiator::start_with(c.clone(), pk(&ka), &mut log, NA, T0 + 10).unwrap_err(),
            PairError::TooManyAttempts
        );
        // The responder side is counted the same way.
        let mut rlog = Attempts::from_log(log.log().to_vec());
        let (_, com) =
            Initiator::start_with(c.clone(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        assert_eq!(
            Responder::respond_with(c.clone(), pk(&ka), com, pk(&sk(2)), &mut rlog, NB, T0 + 10)
                .unwrap_err(),
            PairError::TooManyAttempts
        );
        // After the window, allowed again; a reused pair id never is.
        let later = T0 + ATTEMPT_WINDOW_SECS + 10;
        Initiator::start_with(c.clone(), pk(&ka), &mut log, NA, later).unwrap();
        assert_eq!(
            Initiator::start_with(c, pk(&ka), &mut log, NA, later + 1).unwrap_err(),
            PairError::Replayed
        );
        // A clock that went back doesn't free up attempts.
        let mut back = Attempts::from_log((0..5).map(|i| (T0 + 100, format!("f{i}"))).collect());
        let mut c = ctx();
        c.pair_id = "p-back".into();
        assert_eq!(
            Initiator::start_with(c, pk(&ka), &mut back, NA, T0).unwrap_err(),
            PairError::TooManyAttempts
        );
    }

    /// Domain separation from K2 is a condition of the Kessel Steward's
    /// ruling on this port: the same inputs must never give the same
    /// commitment or code under K2's public tags.
    #[test]
    fn our_tags_are_not_k2s() {
        const K2_COMMIT: &[u8] = b"k2-sas-commit-v2";
        const K2_SAS: &[u8] = b"k2-sas-v2";
        assert_ne!(COMMIT_PREFIX, K2_COMMIT);
        assert_ne!(SAS_PREFIX, K2_SAS);
        for ours in [COMMIT_PREFIX, SAS_PREFIX, TRANSCRIPT_PREFIX, CONFIRM_PREFIX] {
            for theirs in [K2_COMMIT, K2_SAS] {
                assert!(!ours.starts_with(theirs) && !theirs.starts_with(ours));
            }
        }
        let (fa, fb) = ("aa".repeat(32), "bb".repeat(32));
        let mut h = Sha256::new();
        h.update(K2_COMMIT);
        h.update(fa.as_bytes());
        h.update(NA);
        let k2_commit: [u8; 32] = h.finalize().into();
        assert_ne!(commitment(&ctx(), &fp('a'), &NA).unwrap().0, k2_commit);
        let mut h = Sha256::new();
        h.update(K2_SAS);
        h.update(fa.as_bytes());
        h.update(fb.as_bytes());
        h.update(NA);
        h.update(NB);
        let d = h.finalize();
        let k2_code = format!(
            "{:06}",
            u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000
        );
        assert_eq!(
            k2_code, "632758",
            "K2's own published vector for these inputs"
        );
        assert_ne!(
            code(&ctx(), &fp('a'), &fp('b'), &NA, &NB).unwrap().as_str(),
            k2_code
        );
    }

    #[test]
    fn real_nonces_agree_too() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, c) = Initiator::start(ctx(), pk(&ka), &mut Attempts::default(), T0).unwrap();
        let (b, resp) =
            Responder::respond(ctx(), pk(&ka), c, pk(&kb), &mut Attempts::default(), T0).unwrap();
        let (reveal, hs_a) = a.finish(resp, T0).unwrap();
        let hs_b = b.finish(reveal, T0).unwrap();
        assert_eq!(hs_b.code(), hs_a.code());
        assert_eq!(hs_b.transcript_hex(), hs_a.transcript_hex());
    }

    #[test]
    fn fingerprints_have_one_spelling() {
        assert!(Fingerprint::parse(&"a".repeat(64)).is_ok());
        for bad in [
            "A".repeat(64),
            format!("SHA256:{}", "a".repeat(57)),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            assert_eq!(
                Fingerprint::parse(&bad),
                Err(PairError::BadFingerprint),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_commitment_binds_the_initiator_key_and_context() {
        let (ka, kb) = (sk(1), sk(2));
        let (_a, c) =
            Initiator::start_with(ctx(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        // B believes the initiator is someone else.
        let (b, _) = Responder::respond_with(
            ctx(),
            pk(&sk(3)),
            c,
            pk(&kb),
            &mut Attempts::default(),
            NB,
            T0,
        )
        .unwrap();
        assert_eq!(b.finish(Reveal(NA), T0).unwrap_err(), PairError::Mismatch);
        let mut other = ctx();
        other.pair_id = "pair-2".into();
        let (b, _) =
            Responder::respond_with(other, pk(&ka), c, pk(&kb), &mut Attempts::default(), NB, T0)
                .unwrap();
        assert_eq!(b.finish(Reveal(NA), T0).unwrap_err(), PairError::Mismatch);
    }

    #[test]
    fn states_expire() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, c) =
            Initiator::start_with(ctx(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        let (b, resp) =
            Responder::respond_with(ctx(), pk(&ka), c, pk(&kb), &mut Attempts::default(), NB, T0)
                .unwrap();
        assert_eq!(
            a.finish(resp, T0 + NONCE_TTL_SECS).unwrap_err(),
            PairError::Expired,
            "exactly the TTL is too old"
        );
        assert_eq!(
            b.finish(Reveal(NA), T0 - 1).unwrap_err(),
            PairError::Expired,
            "clock went backwards"
        );
        assert_eq!(
            fresh(i64::MIN, i64::MAX),
            Err(PairError::Expired),
            "overflow is expired, not a panic"
        );
        assert_eq!(fresh(i64::MAX, i64::MIN), Err(PairError::Expired));
        assert_eq!(fresh(T0, T0 + NONCE_TTL_SECS - 1), Ok(()));
    }

    #[test]
    fn debug_never_prints_nonces_or_codes() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, c) =
            Initiator::start_with(ctx(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        let (b, _) =
            Responder::respond_with(ctx(), pk(&ka), c, pk(&kb), &mut Attempts::default(), NB, T0)
                .unwrap();
        for s in [format!("{a:?}"), format!("{b:?}")] {
            assert!(!s.contains("17, 17"), "{s}");
            assert!(!s.contains("34, 34"), "{s}");
            assert!(s.contains("<secret>"));
        }
        let (hs, _) = handshake(ctx(), ctx(), &ka, &kb).unwrap();
        let code = hs.code().as_str().to_string();
        assert!(
            !format!("{hs:?}").contains(&code),
            "the code is for a person, not a log"
        );
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
            assert_ne!(
                v, &real,
                "changing any input must change the code (fixed vectors)"
            );
        }
    }

    #[test]
    fn context_framing_keeps_fields_apart() {
        let a = PairContext {
            pair_id: "ab".into(),
            initiator: "c".into(),
            responder: "d".into(),
        };
        let b = PairContext {
            pair_id: "a".into(),
            initiator: "bc".into(),
            responder: "d".into(),
        };
        assert_ne!(a.framed().unwrap(), b.framed().unwrap());
    }

    #[test]
    fn wire_forms_round_trip() {
        let (ka, kb) = (sk(1), sk(2));
        let (a, c) =
            Initiator::start_with(ctx(), pk(&ka), &mut Attempts::default(), NA, T0).unwrap();
        assert_eq!(Commitment::from_hex(&c.to_hex()).unwrap(), c);
        let (_b, resp) =
            Responder::respond_with(ctx(), pk(&ka), c, pk(&kb), &mut Attempts::default(), NB, T0)
                .unwrap();
        assert_eq!(
            Response::from_parts(resp.key().pem(), &resp.nb_hex()).unwrap(),
            resp
        );
        let (reveal, _) = a.finish(resp, T0).unwrap();
        assert_eq!(Reveal::from_hex(&reveal.to_hex()).unwrap(), reveal);
    }

    /// Golden vectors, computed with Python's hashlib and `cryptography`
    /// (`vectors/postal-v1.json`).
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        for v in all["pairing"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let ctx = PairContext {
                pair_id: s("pair_id"),
                initiator: s("initiator"),
                responder: s("responder"),
            };
            let fa = Fingerprint::parse(&s("fp_a")).unwrap();
            let fb = Fingerprint::parse(&s("fp_b")).unwrap();
            let na = from_hex32(&s("na_hex")).unwrap();
            let nb = from_hex32(&s("nb_hex")).unwrap();
            assert_eq!(
                commitment(&ctx, &fa, &na).unwrap().to_hex(),
                s("commitment_hex")
            );
            assert_eq!(code(&ctx, &fa, &fb, &na, &nb).unwrap().as_str(), s("sas"));
        }
        for v in all["pairing_refused"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            match s("case").as_str() {
                "bad_fingerprint" => {
                    assert_eq!(Fingerprint::parse(&s("fp")), Err(PairError::BadFingerprint))
                }
                "wrong_reveal" => {
                    let ctx = PairContext {
                        pair_id: s("pair_id"),
                        initiator: s("initiator"),
                        responder: s("responder"),
                    };
                    let fa = Fingerprint::parse(&s("fp_a")).unwrap();
                    let c = Commitment::from_hex(&s("commitment_hex")).unwrap();
                    let reveal = from_hex32(&s("reveal_hex")).unwrap();
                    assert_ne!(commitment(&ctx, &fa, &reveal).unwrap(), c);
                }
                other => panic!("unknown refused case {other}"),
            }
        }
        for v in all["confirm"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let seed = |k: &str| SigningKey::from_bytes(&from_hex32(&s(k)).unwrap());
            let (ka, kb) = (seed("seed_a_hex"), seed("seed_b_hex"));
            let (pa, pb) = (
                PublicKey::from_pem(&s("public_key_pem_a")).unwrap(),
                PublicKey::from_pem(&s("public_key_pem_b")).unwrap(),
            );
            assert_eq!(pa, pk(&ka));
            assert_eq!(pb, pk(&kb));
            assert_eq!(pa.fingerprint().to_hex(), s("fp_a"));
            assert_eq!(pb.fingerprint().to_hex(), s("fp_b"));
            let ctx = PairContext {
                pair_id: s("pair_id"),
                initiator: s("initiator"),
                responder: s("responder"),
            };
            let na = from_hex32(&s("na_hex")).unwrap();
            let nb = from_hex32(&s("nb_hex")).unwrap();
            let (st_a, c) =
                Initiator::start_with(ctx.clone(), pa.clone(), &mut Attempts::default(), na, T0)
                    .unwrap();
            assert_eq!(c.to_hex(), s("commitment_hex"));
            let (st_b, resp) =
                Responder::respond_with(ctx, pa, c, pb, &mut Attempts::default(), nb, T0).unwrap();
            let (reveal, hs_a) = st_a.finish(resp, T0).unwrap();
            let hs_b = st_b.finish(reveal, T0).unwrap();
            assert_eq!(hs_a.code().as_str(), s("sas"));
            assert_eq!(hs_a.transcript_hex(), s("transcript_hex"));
            assert_eq!(hs_b.transcript_hex(), s("transcript_hex"));
            for conf in v["signatures"].as_array().unwrap() {
                let side = if conf["side"] == "from" {
                    Side::From
                } else {
                    Side::To
                };
                let decision = match conf["decision"].as_str().unwrap() {
                    "accept" => Decision::Accept,
                    "reject" => Decision::Reject,
                    _ => Decision::Mismatch,
                };
                let msg =
                    confirm_message(&hs_a.ctx.pair_id, side, decision, &hs_a.transcript).unwrap();
                assert_eq!(to_hex(&msg), conf["message_hex"].as_str().unwrap());
                let k = if side == Side::From { &ka } else { &kb };
                let sig = base64::engine::general_purpose::STANDARD.encode(Signer::sign(k, &msg));
                assert_eq!(sig, conf["sig_b64"].as_str().unwrap());
            }
            // The full flow gives the same signatures.
            let sas = s("sas");
            let (conf_a, wait_a) = accept(hs_a, &sas, &ka);
            let (conf_b, _wait_b) = accept(hs_b, &sas, &kb);
            let sigs = v["signatures"].as_array().unwrap();
            assert_eq!(conf_a.sig_base64(), sigs[0]["sig_b64"].as_str().unwrap());
            assert_eq!(conf_b.sig_base64(), sigs[1]["sig_b64"].as_str().unwrap());
            wait_a
                .peer_confirmation(Decision::Accept, &conf_b.sig_base64())
                .unwrap();
        }
    }
}
