//! Both-sides pairing confirm (pairs v2).
//!
//! Each owner types the code the **other** box shows. This box checks it
//! against the locally derived SAS, then signs a decide body that carries
//! **no SAS**. The plane records one signed confirmation per side and never
//! judges a code.
//!
//! Replaces k2-dev-web #76 `{decision, sas?}` on
//! `POST /postal/v1/pairs/{id}/decide`. Unversioned `/accept {sas}` stays
//! for p5 0.1.x.
//!
//! B4: [`decide_typed`] signs confirm only after [`Code::matches`].
//! B2: fingerprints in the message come from pinned PEMs, not the plane.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{
    parse_spki_pem, pin_fingerprint, verify_sig, Identity, IdentityError,
};
use crate::pairing::Code;
use crate::plane::is_safe_id;

/// Domain prefix of a confirmation.
pub const CONFIRM_PREFIX: &[u8] = b"postal-pair-confirm-v1";
/// Domain prefix of a refusal.
pub const REFUSE_PREFIX: &[u8] = b"postal-pair-refuse-v1";
/// Decide JSON `v`.
pub const CONFIRM_VERSION: u32 = 2;
/// `|now - at|` allowed, seconds (same as SAS nonce TTL).
pub const MAX_CONFIRM_SKEW_SECS: i64 = 600;
/// `POST /postal/v1/pairs/{id}/decide`
pub const DECIDE_PATH_PREFIX: &str = "/postal/v1/pairs";
/// Path suffix on [`DECIDE_PATH_PREFIX`] `/{id}`.
pub const DECIDE_ACTION: &str = "decide";

/// Which row of the pair this box is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    From,
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
}

/// Local outcome. `confirm` is one side; the pair is accepted only after both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Confirm,
    Reject,
}

impl Decision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Reject => "reject",
        }
    }
}

/// Why this box rejected. Never a SAS. Plane status becomes `rejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefuseReason {
    SasMismatch,
    Expired,
}

impl RefuseReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SasMismatch => "sas_mismatch",
            Self::Expired => "expired",
        }
    }
}

/// `POST /postal/v1/pairs/{id}/decide` body. No SAS, no `na`, no `nb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideMessage {
    pub v: u32,
    pub pair_id: String,
    pub from: String,
    pub to: String,
    pub side: Side,
    pub decision: Decision,
    pub fp_from: String,
    pub fp_to: String,
    pub at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefuseReason>,
    pub sig: String,
}

/// Inputs the box already has. Peer fingerprint is taken from `peer_spki_pem`.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmInput<'a> {
    pub pair_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub side: Side,
    pub local: &'a Identity,
    pub peer_spki_pem: &'a str,
    pub at: i64,
}

/// After a local SAS check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decide {
    Confirm(DecideMessage),
    Reject(DecideMessage),
}

impl Decide {
    #[must_use]
    pub fn message(&self) -> &DecideMessage {
        match self {
            Self::Confirm(m) | Self::Reject(m) => m,
        }
    }
}

/// Why confirm/reject failed to *build* (mismatch is [`Decide::Reject`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmError {
    BadKey(String),
    BadSig,
    BadHex,
    BadId,
    TooLong,
    Skew,
    Fingerprint,
    /// Same side, different signature (plane 409).
    Conflict,
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey(msg) => write!(f, "confirm key: {msg}"),
            Self::BadSig => f.write_str("confirmation signature failed"),
            Self::BadHex => f.write_str("sig is not 64-byte hex"),
            Self::BadId => f.write_str("pair id is not a safe path segment or does not match the body"),
            Self::TooLong => f.write_str("confirm field longer than 4 GiB"),
            Self::Skew => f.write_str("at outside allowed skew"),
            Self::Fingerprint => f.write_str("fingerprints do not match pinned PEMs"),
            Self::Conflict => f.write_str("same side already confirmed with a different signature"),
        }
    }
}

impl std::error::Error for ConfirmError {}

impl From<IdentityError> for ConfirmError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::Sig => Self::BadSig,
            IdentityError::Key(msg) => Self::BadKey(msg),
        }
    }
}

/// `POST /postal/v1/pairs/{id}/decide`.
///
/// # Errors
/// [`ConfirmError::BadId`] if `id` is not a safe path segment.
pub fn decide_path(id: &str) -> Result<String, ConfirmError> {
    if !is_safe_id(id) {
        return Err(ConfirmError::BadId);
    }
    Ok(format!("{DECIDE_PATH_PREFIX}/{id}/{DECIDE_ACTION}"))
}

/// Path id must equal the signed `pair_id`.
///
/// # Errors
/// [`ConfirmError::BadId`].
pub fn check_path_id(path_id: &str, body: &DecideMessage) -> Result<(), ConfirmError> {
    if path_id == body.pair_id && is_safe_id(path_id) {
        Ok(())
    } else {
        Err(ConfirmError::BadId)
    }
}

/// Same-sig 200, different-sig 409. Hosts map the rest.
#[must_use]
pub fn classify_decide_status(status: u16) -> Option<ConfirmError> {
    match status {
        409 => Some(ConfirmError::Conflict),
        _ => None,
    }
}

/// B4: check the digits the owner read from the **other** box, then sign.
/// Hosts pass what the person typed, never [`crate::host::PairingPrompt::show`].
///
/// # Errors
/// Key or framing errors. A SAS mismatch is [`Decide::Reject`], not an error.
pub fn decide_typed(
    local_sas: &Code,
    typed_other: &str,
    input: ConfirmInput<'_>,
) -> Result<Decide, ConfirmError> {
    if local_sas.matches(typed_other) {
        Ok(Decide::Confirm(sign_decide(input, Decision::Confirm, None)?))
    } else {
        Ok(Decide::Reject(sign_decide(
            input,
            Decision::Reject,
            Some(RefuseReason::SasMismatch),
        )?))
    }
}

/// Sign a reject without a typed code (expired handshake).
///
/// # Errors
/// Key or framing errors.
pub fn reject(input: ConfirmInput<'_>, reason: RefuseReason) -> Result<DecideMessage, ConfirmError> {
    sign_decide(input, Decision::Reject, Some(reason))
}

/// Verify a decide body against the **pinned PEMs** (B2), not plane hex.
///
/// # Errors
/// Signature, skew, fingerprint, or decision/reason mismatch.
pub fn verify_decide(
    msg: &DecideMessage,
    from_pem: &str,
    to_pem: &str,
    now: i64,
) -> Result<(), ConfirmError> {
    if msg.v != CONFIRM_VERSION {
        return Err(ConfirmError::BadSig);
    }
    match (msg.decision, msg.reason) {
        (Decision::Confirm, None) | (Decision::Reject, Some(_)) => {}
        _ => return Err(ConfirmError::BadSig),
    }
    check_skew(msg.at, now)?;
    let fps = fps_from_pems(from_pem, to_pem)?;
    if msg.fp_from != fps.0.to_hex() || msg.fp_to != fps.1.to_hex() {
        return Err(ConfirmError::Fingerprint);
    }
    let digest = decide_digest(DigestParts {
        pair_id: &msg.pair_id,
        from: &msg.from,
        to: &msg.to,
        side: msg.side,
        decision: msg.decision,
        reason: msg.reason,
        fp_from: &msg.fp_from,
        fp_to: &msg.fp_to,
        at: msg.at,
    })?;
    let sig = sig_bytes(&msg.sig)?;
    let pem = match msg.side {
        Side::From => from_pem,
        Side::To => to_pem,
    };
    verify_sig(&parse_spki_pem(pem)?, &digest, &sig)?;
    Ok(())
}

fn sign_decide(
    input: ConfirmInput<'_>,
    decision: Decision,
    reason: Option<RefuseReason>,
) -> Result<DecideMessage, ConfirmError> {
    if !is_safe_id(input.pair_id) {
        return Err(ConfirmError::BadId);
    }
    let (fp_from, fp_to) = fps_for_side(input)?;
    let digest = decide_digest(DigestParts {
        pair_id: input.pair_id,
        from: input.from,
        to: input.to,
        side: input.side,
        decision,
        reason,
        fp_from: &fp_from,
        fp_to: &fp_to,
        at: input.at,
    })?;
    Ok(DecideMessage {
        v: CONFIRM_VERSION,
        pair_id: input.pair_id.to_string(),
        from: input.from.to_string(),
        to: input.to.to_string(),
        side: input.side,
        decision,
        fp_from,
        fp_to,
        at: input.at,
        reason,
        sig: crate::hex::to_hex(&input.local.sign(&digest)),
    })
}

fn fps_for_side(input: ConfirmInput<'_>) -> Result<(String, String), ConfirmError> {
    let local = input.local.fingerprint().to_hex();
    let peer = pin_fingerprint(input.peer_spki_pem)?.to_hex();
    Ok(match input.side {
        Side::From => (local, peer),
        Side::To => (peer, local),
    })
}

fn fps_from_pems(
    from_pem: &str,
    to_pem: &str,
) -> Result<(crate::pairing::Fingerprint, crate::pairing::Fingerprint), ConfirmError> {
    Ok((pin_fingerprint(from_pem)?, pin_fingerprint(to_pem)?))
}

fn check_skew(at: i64, now: i64) -> Result<(), ConfirmError> {
    let skew = now.checked_sub(at).unwrap_or(i64::MIN);
    if skew.unsigned_abs() > MAX_CONFIRM_SKEW_SECS.unsigned_abs() {
        Err(ConfirmError::Skew)
    } else {
        Ok(())
    }
}

fn sig_bytes(hex: &str) -> Result<[u8; 64], ConfirmError> {
    let v = crate::hex::from_hex(hex).map_err(|_| ConfirmError::BadHex)?;
    v.try_into().map_err(|_| ConfirmError::BadHex)
}

struct DigestParts<'a> {
    pair_id: &'a str,
    from: &'a str,
    to: &'a str,
    side: Side,
    decision: Decision,
    reason: Option<RefuseReason>,
    fp_from: &'a str,
    fp_to: &'a str,
    at: i64,
}

fn decide_digest(p: DigestParts<'_>) -> Result<[u8; 32], ConfirmError> {
    let mut h = Sha256::new();
    match p.decision {
        Decision::Confirm => h.update(CONFIRM_PREFIX),
        Decision::Reject => h.update(REFUSE_PREFIX),
    }
    h.update(CONFIRM_VERSION.to_be_bytes());
    frame(&mut h, p.pair_id.as_bytes())?;
    frame(&mut h, p.from.as_bytes())?;
    frame(&mut h, p.to.as_bytes())?;
    frame(&mut h, p.side.as_str().as_bytes())?;
    frame(&mut h, p.decision.as_str().as_bytes())?;
    if let Some(reason) = p.reason {
        frame(&mut h, reason.as_str().as_bytes())?;
    }
    frame(&mut h, p.fp_from.as_bytes())?;
    frame(&mut h, p.fp_to.as_bytes())?;
    h.update(p.at.to_be_bytes());
    Ok(h.finalize().into())
}

fn frame(h: &mut Sha256, bytes: &[u8]) -> Result<(), ConfirmError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ConfirmError::TooLong)?;
    h.update(len.to_be_bytes());
    h.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::{Fingerprint, Initiator, PairContext, Responder};

    const T0: i64 = 1_800_000_000;
    const PAIR: &str = "pair-1";
    const FROM: &str = "alice::acme.postal.bot";
    const TO: &str = "scout::acme.postal.bot";

    fn alice() -> Identity {
        Identity::from_seed([0x11; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed([0x22; 32])
    }
    fn mallory() -> Identity {
        Identity::from_seed([0x33; 32])
    }

    fn ctx() -> PairContext {
        PairContext {
            pair_id: PAIR.into(),
            initiator: FROM.into(),
            responder: TO.into(),
        }
    }

    fn handshake(a: &Identity, b: &Identity, na: [u8; 32], nb: [u8; 32]) -> (Code, Code) {
        let fa = a.fingerprint();
        let fb = b.fingerprint();
        let (ia, c) = Initiator::start_with(ctx(), fa, na, T0).unwrap();
        let (rb, resp) = Responder::respond_with(ctx(), fa, c, fb, nb, T0);
        let (reveal, code_a) = ia.finish(resp, T0).unwrap();
        let code_b = rb.finish(reveal, T0).unwrap();
        (code_a, code_b)
    }

    fn input<'a>(side: Side, local: &'a Identity, peer_pem: &'a str) -> ConfirmInput<'a> {
        ConfirmInput {
            pair_id: PAIR,
            from: FROM,
            to: TO,
            side,
            local,
            peer_spki_pem: peer_pem,
            at: T0,
        }
    }

    fn no_secrets(m: &DecideMessage) {
        let v: serde_json::Value = serde_json::to_value(m).unwrap();
        for forbidden in ["sas", "na", "nb", "decided_sas"] {
            assert!(
                v.get(forbidden).is_none(),
                "{forbidden} must not be on the wire"
            );
        }
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("\"sas\""), "{s}");
    }

    #[test]
    fn decide_path_is_v1_pairs_id_decide() {
        assert_eq!(
            decide_path(PAIR).unwrap(),
            "/postal/v1/pairs/pair-1/decide"
        );
        assert!(decide_path("../x").is_err());
        assert_eq!(classify_decide_status(409), Some(ConfirmError::Conflict));
        assert_eq!(classify_decide_status(200), None);
    }

    #[test]
    fn honest_both_sides_confirm() {
        let alice = alice();
        let bob = bob();
        let (sa, sb) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        assert_eq!(sa, sb);
        let da = decide_typed(&sa, sb.as_str(), input(Side::From, &alice, &bob.public_key_pem()))
            .unwrap();
        let db = decide_typed(&sb, sa.as_str(), input(Side::To, &bob, &alice.public_key_pem()))
            .unwrap();
        let Decide::Confirm(ca) = da else { panic!("alice") };
        let Decide::Confirm(cb) = db else { panic!("bob") };
        verify_decide(&ca, &alice.public_key_pem(), &bob.public_key_pem(), T0).unwrap();
        verify_decide(&cb, &alice.public_key_pem(), &bob.public_key_pem(), T0).unwrap();
        assert_eq!(ca.decision, Decision::Confirm);
        assert!(ca.reason.is_none());
        no_secrets(&ca);
        no_secrets(&cb);
        check_path_id(PAIR, &ca).unwrap();
    }

    /// Two handshakes (plane in the middle). Each owner types the other
    /// box's digits. Local SAS differs → reject, never accepted.
    #[test]
    fn plane_in_the_middle_two_handshakes_fails_to_pair() {
        let alice = alice();
        let bob = bob();
        let mallory = mallory();
        let (sas_am, _) = handshake(&alice, &mallory, [0x11; 32], [0xaa; 32]);
        let (_, sas_mb) = handshake(&mallory, &bob, [0xbb; 32], [0x22; 32]);
        assert_ne!(sas_am.as_str(), sas_mb.as_str());
        let da = decide_typed(
            &sas_am,
            sas_mb.as_str(),
            input(Side::From, &alice, &mallory.public_key_pem()),
        )
        .unwrap();
        let db = decide_typed(
            &sas_mb,
            sas_am.as_str(),
            input(Side::To, &bob, &mallory.public_key_pem()),
        )
        .unwrap();
        match (da, db) {
            (Decide::Reject(ra), Decide::Reject(rb)) => {
                assert_eq!(ra.reason, Some(RefuseReason::SasMismatch));
                assert_eq!(rb.reason, Some(RefuseReason::SasMismatch));
                verify_decide(&ra, &alice.public_key_pem(), &mallory.public_key_pem(), T0)
                    .unwrap();
                verify_decide(&rb, &mallory.public_key_pem(), &bob.public_key_pem(), T0)
                    .unwrap();
                no_secrets(&ra);
                let mut store = PairStore::default();
                assert_eq!(
                    store.apply(&ra, &alice, &mallory).unwrap(),
                    PairStatus::Rejected
                );
            }
            other => panic!("MITM must reject both sides, got {other:?}"),
        }
    }

    #[test]
    fn b4_does_not_sign_confirm_on_a_wrong_code() {
        let alice = alice();
        let bob = bob();
        let (sa, sb) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        let from_wrong =
            decide_typed(&sa, "000000", input(Side::From, &alice, &bob.public_key_pem()))
                .unwrap();
        let to_wrong =
            decide_typed(&sb, "999999", input(Side::To, &bob, &alice.public_key_pem()))
                .unwrap();
        assert!(matches!(from_wrong, Decide::Reject(_)));
        assert!(matches!(to_wrong, Decide::Reject(_)));
    }

    #[test]
    fn b2_fingerprints_come_from_pinned_pems_not_plane_hex() {
        let alice = alice();
        let bob = bob();
        let plane_lie = Fingerprint::parse(&"ab".repeat(32)).unwrap();
        assert_ne!(plane_lie.to_hex(), bob.fingerprint().to_hex());
        let (sa, _) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        let Decide::Confirm(c) =
            decide_typed(&sa, sa.as_str(), input(Side::From, &alice, &bob.public_key_pem()))
                .unwrap()
        else {
            panic!("confirm");
        };
        assert_eq!(c.fp_from, alice.fingerprint().to_hex());
        assert_eq!(
            c.fp_to,
            pin_fingerprint(&bob.public_key_pem()).unwrap().to_hex()
        );
        assert_ne!(c.fp_to, plane_lie.to_hex());
        let mut lying = c.clone();
        lying.fp_to = plane_lie.to_hex();
        assert_eq!(
            verify_decide(&lying, &alice.public_key_pem(), &bob.public_key_pem(), T0),
            Err(ConfirmError::Fingerprint)
        );
    }

    #[test]
    fn one_side_only_stays_pending() {
        let alice = alice();
        let bob = bob();
        let (sa, _) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        let Decide::Confirm(ca) =
            decide_typed(&sa, sa.as_str(), input(Side::From, &alice, &bob.public_key_pem()))
                .unwrap()
        else {
            panic!();
        };
        let mut store = PairStore::default();
        assert_eq!(
            store.apply(&ca, &alice, &bob).unwrap(),
            PairStatus::Pending
        );
        assert_eq!(store.status, PairStatus::Pending);
    }

    #[test]
    fn both_confirmed_is_accepted() {
        let alice = alice();
        let bob = bob();
        let (sa, sb) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        let Decide::Confirm(ca) =
            decide_typed(&sa, sb.as_str(), input(Side::From, &alice, &bob.public_key_pem()))
                .unwrap()
        else {
            panic!();
        };
        let Decide::Confirm(cb) =
            decide_typed(&sb, sa.as_str(), input(Side::To, &bob, &alice.public_key_pem()))
                .unwrap()
        else {
            panic!();
        };
        let mut store = PairStore::default();
        store.apply(&ca, &alice, &bob).unwrap();
        assert_eq!(
            store.apply(&cb, &alice, &bob).unwrap(),
            PairStatus::Accepted
        );
    }

    #[test]
    fn same_sig_is_idempotent_different_sig_conflicts() {
        let alice = alice();
        let bob = bob();
        let (sa, _) = handshake(&alice, &bob, [0x11; 32], [0x22; 32]);
        let Decide::Confirm(ca) =
            decide_typed(&sa, sa.as_str(), input(Side::From, &alice, &bob.public_key_pem()))
                .unwrap()
        else {
            panic!();
        };
        let bob_pem = bob.public_key_pem();
        let mut later = input(Side::From, &alice, &bob_pem);
        later.at = T0 + 1;
        let Decide::Confirm(cb) = decide_typed(&sa, sa.as_str(), later).unwrap() else {
            panic!();
        };
        assert_ne!(ca.sig, cb.sig);
        let mut store = PairStore::default();
        assert_eq!(
            store.apply(&ca, &alice, &bob).unwrap(),
            PairStatus::Pending
        );
        assert_eq!(
            store.apply(&ca, &alice, &bob).unwrap(),
            PairStatus::Pending
        );
        assert_eq!(
            store.apply(&cb, &alice, &bob),
            Err(ConfirmError::Conflict)
        );
    }

    #[derive(Default)]
    struct PairStore {
        from: Option<DecideMessage>,
        to: Option<DecideMessage>,
        status: PairStatus,
    }

    /// Box-side mock. Plane names: `pending_in` / `pending_out` for
    /// [`PairStatus::Pending`], `rejected` for [`PairStatus::Rejected`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    enum PairStatus {
        #[default]
        Pending,
        Accepted,
        Rejected,
    }

    impl PairStore {
        fn apply(
            &mut self,
            m: &DecideMessage,
            from: &Identity,
            to: &Identity,
        ) -> Result<PairStatus, ConfirmError> {
            verify_decide(m, &from.public_key_pem(), &to.public_key_pem(), T0)?;
            if m.decision == Decision::Reject {
                self.status = PairStatus::Rejected;
                return Ok(self.status);
            }
            if self.status == PairStatus::Rejected {
                return Ok(self.status);
            }
            let slot = match m.side {
                Side::From => &mut self.from,
                Side::To => &mut self.to,
            };
            if let Some(existing) = slot.as_ref() {
                if existing.sig == m.sig {
                    return Ok(self.status);
                }
                return Err(ConfirmError::Conflict);
            }
            *slot = Some(m.clone());
            if self.from.is_some() && self.to.is_some() {
                self.status = PairStatus::Accepted;
            }
            Ok(self.status)
        }
    }
}
