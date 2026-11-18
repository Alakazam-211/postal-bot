//! HoldSeal-v2: held mail, sealed to the recipient and signed by the sender
//! (F4).
//!
//! The plane stores `{v:2, from, to, client_id, sealed}` and can't read
//! `sealed`. Inside is the sender's signed [`WireMessage`], so a held message
//! is authenticated by the same signature as a live one, not by what the
//! plane says `from` is. Opening checks that the signed `from`, `to` and `id`
//! equal the outer ones, so the plane can't relabel, redirect or re-id a
//! message, and can't splice one sender's signed message under another.
//!
//! ```text
//! blob   = 0x02 || eph_pub(32) || nonce(12) || ChaCha20-Poly1305(pt) || tag(16)
//! key    = HKDF-SHA256(salt = "postal-hold-v2", ikm = X25519(eph, R),
//!                      info = "postal-hold-v2" || eph_pub || R)
//! aad    = "postal-hold-v2" || 0x02 || frame(from) || frame(to) || frame(client_id)
//! pt     = wire v2 JSON
//! ```
//!
//! `R` is the recipient's X25519 key, the Montgomery form of its Ed25519
//! handle key; `frame` is a u32 big-endian length then the bytes. A v1 blob
//! (`p5-hold-v1`, [`crate::seal`]) never goes to the v2 routes and isn't
//! opened here.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::address::Address;
use crate::host::{Arrival, VerifiedMessage};
use crate::pairing::PublicKey;
use crate::replay::SeenStore;
use crate::wire::{decode_json, encode_json, verify, Expect, WireError, WireMessage};

/// Version byte, and the `v` of a hold item.
pub const HOLDSEAL_V2: u8 = 2;
/// Domain tag for the key and the AAD.
pub const TAG: &str = "postal-hold-v2";
/// The plane's cap on decoded `sealed`.
pub const MAX_SEALED: usize = 512 * 1024;

const EPH: usize = 32;
const NONCE: usize = 12;
const AEAD_TAG: usize = 16;
const HEADER: usize = 1 + EPH + NONCE;
/// Smallest possible blob (empty plaintext).
pub const MIN_SEALED: usize = HEADER + AEAD_TAG;

/// The hold key's private half, held by the host (K2: the vault). The SDK
/// only asks for one X25519 agreement per blob.
pub trait Opener {
    /// X25519 of this handle's key (Ed25519 scalar, as a Montgomery secret)
    /// with `their_public`.
    fn agree(&self, their_public: &[u8; 32]) -> [u8; 32];
}

impl Opener for ed25519_dalek::SigningKey {
    fn agree(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(self.to_scalar_bytes());
        *secret
            .diffie_hellman(&XPublic::from(*their_public))
            .as_bytes()
    }
}

/// The plane-visible fields of a hold item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outer {
    pub from: Address,
    pub to: Address,
    /// The message's ULID: the same id the signature covers.
    pub client_id: String,
}

impl Outer {
    #[must_use]
    pub fn of(msg: &WireMessage) -> Self {
        Self {
            from: msg.from.clone(),
            to: msg.to.clone(),
            client_id: msg.id.clone(),
        }
    }
}

/// Why sealing or opening failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldError {
    /// Sealed bytes over [`MAX_SEALED`].
    TooLarge,
    /// The recipient key is weak or isn't X25519-convertible.
    BadKey,
    /// Not a v2 blob, wrong recipient, tampered, or the outer fields differ
    /// from what was sealed. One error on purpose.
    Open,
    /// It opened, but the plaintext isn't a wire v2 message.
    NotWire,
    /// The signed `from`, `to` or `id` differ from the outer ones.
    Relabelled,
    /// The signed message itself was refused.
    Wire(WireError),
}

impl HoldError {
    /// Whether retrying the same item could succeed (only a seen-list
    /// storage error). Anything else is permanent: refuse it.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Wire(w) if w.is_retryable())
    }
}

impl std::fmt::Display for HoldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("sealed hold item over 512 KiB"),
            Self::BadKey => f.write_str("recipient key unusable for a hold seal"),
            Self::Open => f.write_str("hold item failed to open"),
            Self::NotWire => f.write_str("hold plaintext is not a wire v2 message"),
            Self::Relabelled => f.write_str("hold outer fields differ from the signed message"),
            Self::Wire(e) => write!(f, "held message: {e}"),
        }
    }
}

impl std::error::Error for HoldError {}

/// Seal a signed message to its recipient. `nonce` and `eph` come from
/// [`seal`]; this is the deterministic core, for vectors.
fn seal_with(
    recipient: &PublicKey,
    msg: &WireMessage,
    eph: [u8; 32],
    nonce: [u8; NONCE],
) -> Result<Vec<u8>, HoldError> {
    let r = recipient_x(recipient)?;
    let eph = StaticSecret::from(eph);
    let eph_pub = XPublic::from(&eph);
    let shared = eph.diffie_hellman(&XPublic::from(r));
    if !shared.was_contributory() {
        return Err(HoldError::BadKey);
    }
    let key = derive_key(shared.as_bytes(), eph_pub.as_bytes(), &r);
    let pt = encode_json(msg).map_err(|_| HoldError::NotWire)?;
    let ct = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &aad(&Outer::of(msg)),
            },
        )
        .map_err(|_| HoldError::TooLarge)?;
    let mut blob = Vec::with_capacity(HEADER + ct.len());
    blob.push(HOLDSEAL_V2);
    blob.extend_from_slice(eph_pub.as_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    if blob.len() > MAX_SEALED {
        return Err(HoldError::TooLarge);
    }
    Ok(blob)
}

/// Seal a signed message to `recipient` (the pinned key of `msg.to`).
///
/// # Errors
/// [`HoldError::BadKey`], [`HoldError::TooLarge`], or
/// [`HoldError::NotWire`] if the OS RNG fails.
pub fn seal(recipient: &PublicKey, msg: &WireMessage) -> Result<Vec<u8>, HoldError> {
    let mut eph = [0u8; 32];
    let mut nonce = [0u8; NONCE];
    getrandom::getrandom(&mut eph).map_err(|_| HoldError::NotWire)?;
    getrandom::getrandom(&mut nonce).map_err(|_| HoldError::NotWire)?;
    seal_with(recipient, msg, eph, nonce)
}

/// What [`open`] needs from the host.
pub struct OpenWith<'a> {
    /// This handle's hold key.
    pub opener: &'a dyn Opener,
    /// This handle's public key (the one the sender sealed to).
    pub me: &'a PublicKey,
    /// This handle's address. A hold item for another handle is refused.
    pub to: &'a Address,
    /// The sender's pinned key, looked up by `outer.from`. No pinned key
    /// (not a friend, or `rekey_pending`): don't call `open`.
    pub sender: &'a PublicKey,
    /// Unix seconds, this box's clock.
    pub now: i64,
}

/// Open a held item and verify the message inside. On success it is recorded
/// in `seen`, and the host stores it before ACKing the plane.
///
/// # Errors
/// [`HoldError`]. Only [`HoldError::is_retryable`] errors should be left on
/// the plane; refuse the rest.
pub fn open(
    outer: &Outer,
    sealed: &[u8],
    with: &OpenWith<'_>,
    seen: &mut dyn SeenStore,
) -> Result<VerifiedMessage, HoldError> {
    if sealed.len() > MAX_SEALED {
        return Err(HoldError::TooLarge);
    }
    if sealed.len() < MIN_SEALED || sealed[0] != HOLDSEAL_V2 {
        return Err(HoldError::Open);
    }
    let eph_pub: [u8; 32] = sealed[1..1 + EPH].try_into().map_err(|_| HoldError::Open)?;
    let nonce = &sealed[1 + EPH..HEADER];
    let r = recipient_x(with.me)?;
    let shared = with.opener.agree(&eph_pub);
    if shared == [0u8; 32] {
        return Err(HoldError::Open);
    }
    let key = derive_key(&shared, &eph_pub, &r);
    let pt = ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &sealed[HEADER..],
                aad: &aad(outer),
            },
        )
        .map_err(|_| HoldError::Open)?;
    let msg = decode_json(&pt).map_err(|_| HoldError::NotWire)?;
    if Outer::of(&msg) != *outer {
        return Err(HoldError::Relabelled);
    }
    verify(
        &msg,
        &Expect {
            sender: with.sender,
            to: with.to,
            now: with.now,
            arrival: Arrival::Held,
        },
        seen,
    )
    .map_err(HoldError::Wire)
}

fn recipient_x(pk: &PublicKey) -> Result<[u8; 32], HoldError> {
    let x = pk.verifying_key().to_montgomery().to_bytes();
    if x == [0u8; 32] {
        return Err(HoldError::BadKey);
    }
    Ok(x)
}

fn derive_key(shared: &[u8; 32], eph_pub: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut info = Vec::with_capacity(TAG.len() + 64);
    info.extend_from_slice(TAG.as_bytes());
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(r);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(TAG.as_bytes()), shared)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

fn aad(o: &Outer) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG.len() + 128);
    out.extend_from_slice(TAG.as_bytes());
    out.push(HOLDSEAL_V2);
    for field in [o.from.to_string(), o.to.to_string(), o.client_id.clone()] {
        // Addresses are at most 64 + 2 + 74 bytes and ids 26; never truncated.
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::MemorySeen;
    use crate::wire::tests::{key, scout_addr, signed, ID, T0};

    const EPH_SEED: [u8; 32] = [0x33; 32];
    const NONCE_SEED: [u8; 12] = [0x44; 12];

    fn open_as_scout(outer: &Outer, blob: &[u8]) -> Result<VerifiedMessage, HoldError> {
        let (scout_sk, scout) = key(0x22);
        let (_, alice) = key(0x11);
        let to = scout_addr();
        open(
            outer,
            blob,
            &OpenWith {
                opener: &scout_sk,
                me: &scout,
                to: &to,
                sender: &alice,
                now: T0 + 3600,
            },
            &mut MemorySeen::default(),
        )
    }

    fn sealed() -> (Outer, Vec<u8>) {
        let msg = signed(&[]);
        let (_, scout) = key(0x22);
        (Outer::of(&msg), seal(&scout, &msg).unwrap())
    }

    #[test]
    fn seal_open_roundtrip() {
        let (outer, blob) = sealed();
        assert_eq!(blob[0], HOLDSEAL_V2);
        let v = open_as_scout(&outer, &blob).unwrap();
        assert_eq!(v.body(), b"hello scout");
        assert_eq!(v.arrival(), Arrival::Held);
        assert_eq!(v.id(), ID);
    }

    #[test]
    fn the_plane_cannot_relabel() {
        let (outer, blob) = sealed();
        let mallory = Address::parse("mallory::acme.postal.bot").unwrap();
        for o in [
            Outer {
                from: mallory.clone(),
                ..outer.clone()
            },
            Outer {
                to: mallory,
                ..outer.clone()
            },
            Outer {
                client_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
                ..outer.clone()
            },
        ] {
            assert_eq!(
                open_as_scout(&o, &blob).unwrap_err(),
                HoldError::Open,
                "{o:?}"
            );
        }
    }

    /// Anyone can seal to the recipient, so the plane can reseal a copied
    /// signed message under new outer fields. The signed fields catch it.
    #[test]
    fn a_resealed_message_under_new_fields_is_refused() {
        let msg = signed(&[]);
        let (_, scout) = key(0x22);
        let mut relabelled = msg.clone();
        relabelled.from = Address::parse("bob::acme.postal.bot").unwrap();
        let blob = seal(&scout, &relabelled).unwrap();
        // Outer matches the (unsigned) relabel; the signature doesn't.
        let err = open_as_scout(&Outer::of(&relabelled), &blob).unwrap_err();
        assert_eq!(err, HoldError::Wire(WireError::BadSig));
        // And a signed message sealed under another outer id: the AAD binds
        // the outer fields to what was sealed, the check binds them to the
        // signature.
        let mut forged = msg;
        forged.id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
        let blob = seal(&scout, &forged).unwrap();
        let err = open_as_scout(&Outer::of(&forged), &blob).unwrap_err();
        assert_eq!(err, HoldError::Wire(WireError::BadSig));
    }

    #[test]
    fn wrong_recipient_tamper_and_version_fail() {
        let (outer, blob) = sealed();
        let (other_sk, other) = key(0x55);
        let (_, alice) = key(0x11);
        let to = scout_addr();
        let err = open(
            &outer,
            &blob,
            &OpenWith {
                opener: &other_sk,
                me: &other,
                to: &to,
                sender: &alice,
                now: T0,
            },
            &mut MemorySeen::default(),
        );
        assert_eq!(err.unwrap_err(), HoldError::Open);
        for i in [0, 1, HEADER - 1, HEADER, blob.len() - 1] {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert_eq!(
                open_as_scout(&outer, &t).unwrap_err(),
                HoldError::Open,
                "byte {i}"
            );
        }
        assert_eq!(
            open_as_scout(&outer, &blob[..MIN_SEALED - 1]).unwrap_err(),
            HoldError::Open
        );
        let big = vec![HOLDSEAL_V2; MAX_SEALED + 1];
        assert_eq!(
            open_as_scout(&outer, &big).unwrap_err(),
            HoldError::TooLarge
        );
    }

    #[test]
    fn a_held_message_opens_once() {
        let (outer, blob) = sealed();
        let (scout_sk, scout) = key(0x22);
        let (_, alice) = key(0x11);
        let to = scout_addr();
        let with = OpenWith {
            opener: &scout_sk,
            me: &scout,
            to: &to,
            sender: &alice,
            now: T0 + 60,
        };
        let mut seen = MemorySeen::default();
        open(&outer, &blob, &with, &mut seen).unwrap();
        let again = open(
            &outer,
            &seal(&scout, &signed(&[])).unwrap(),
            &with,
            &mut seen,
        );
        assert_eq!(again.unwrap_err(), HoldError::Wire(WireError::Replayed));
    }

    #[test]
    fn a_wire_max_message_fits_the_plane_cap() {
        use crate::wire::{sign, Draft, FileBytes, MAX_WIRE_JSON};
        let (alice_sk, alice) = key(0x11);
        let (_, scout) = key(0x22);
        let (from, to) = (crate::wire::tests::alice_addr(), scout_addr());
        let make = |n: usize| {
            let files = [FileBytes {
                name: "f".into(),
                content: vec![0xff; n],
            }];
            sign(
                &alice_sk,
                &alice,
                &Draft {
                    id: ID,
                    from: &from,
                    to: &to,
                    sent_at: T0,
                    mode: crate::host::Mode::Live,
                    content_type: "application/octet-stream",
                    body: "",
                    files: &files,
                    wake: true,
                },
            )
        };
        // Largest raw attachment whose message still signs.
        let (mut lo, mut hi) = (0usize, 448 * 1024);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if make(mid).is_ok() {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        assert!(lo > 380 * 1024, "{lo}");
        assert_eq!(make(lo + 3).unwrap_err(), WireError::TooLarge);
        let msg = make(lo).unwrap();
        assert!(encode_json(&msg).unwrap().len() <= MAX_WIRE_JSON);
        let blob = seal(&scout, &msg).unwrap();
        assert!(blob.len() <= MAX_SEALED, "{}", blob.len());
        // A JSON-escaped body is the other way to grow: also refused at sign.
        let body = "\u{1}".repeat(100 * 1024);
        let err = sign(
            &alice_sk,
            &alice,
            &Draft {
                id: ID,
                from: &from,
                to: &to,
                sent_at: T0,
                mode: crate::host::Mode::Live,
                content_type: "text/plain",
                body: &body,
                files: &[],
                wake: true,
            },
        );
        assert_eq!(err.unwrap_err(), WireError::TooLarge);
    }

    #[test]
    fn deterministic_core_is_stable() {
        let msg = signed(&[]);
        let (_, scout) = key(0x22);
        let a = seal_with(&scout, &msg, EPH_SEED, NONCE_SEED).unwrap();
        let b = seal_with(&scout, &msg, EPH_SEED, NONCE_SEED).unwrap();
        assert_eq!(a, b);
        open_as_scout(&Outer::of(&msg), &a).unwrap();
    }

    /// Golden vector (`vectors/postal-v1.json`, section `hold_v2`),
    /// computed independently with Python's `cryptography`: the X25519 key,
    /// shared secret, HKDF key, AAD and the sealed bytes.
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        let wire0 = &all["wire"][0];
        for v in all["hold_v2"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let h = |k: &str| crate::hex::from_hex32(&s(k)).unwrap();
            let recipient = PublicKey::from_pem(&s("recipient_pem")).unwrap();
            let r = recipient_x(&recipient).unwrap();
            assert_eq!(r, h("recipient_x25519_hex"));
            let sk = ed25519_dalek::SigningKey::from_bytes(&h("recipient_seed_hex"));
            let eph_pub = h("eph_pub_hex");
            let shared = sk.agree(&eph_pub);
            assert_eq!(shared, h("shared_hex"));
            assert_eq!(derive_key(&shared, &eph_pub, &r), h("key_hex"));
            let msg: WireMessage = serde_json::from_value(wire0["message"].clone()).unwrap();
            let outer = Outer::of(&msg);
            assert_eq!(v["outer"]["client_id"], msg.id.as_str());
            assert_eq!(crate::hex::to_hex(&aad(&outer)), s("aad_hex"));
            let nonce: [u8; 12] = crate::hex::from_hex(&s("nonce_hex"))
                .unwrap()
                .try_into()
                .unwrap();
            let blob = seal_with(&recipient, &msg, h("eph_secret_hex"), nonce).unwrap();
            assert_eq!(crate::b64::encode(&blob), s("sealed_b64"));
            let sender = PublicKey::from_pem(wire0["sender_pem"].as_str().unwrap()).unwrap();
            open(
                &outer,
                &blob,
                &OpenWith {
                    opener: &sk,
                    me: &recipient,
                    to: &msg.to,
                    sender: &sender,
                    now: msg.sent_at + 86_400,
                },
                &mut MemorySeen::default(),
            )
            .unwrap();
        }
    }
}
