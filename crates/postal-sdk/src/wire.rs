//! Wire v2: the signed message. `v` is [`crate::WIRE_VERSION`].
//!
//! The same JSON goes out live (`POST /p5/msg`) and, sealed, into the hold
//! ([`crate::seal`]). The signature is Ed25519 over the envelope digest
//! ([`crate::badge::envelope_digest`], tag `postal-envelope-v1`), raw, sent as
//! standard padded base64, like a pair confirmation.
//!
//! The hop-auth proof on `POST /p5/msg` (`p5-msg-v1`) is separate: it
//! authenticates the HTTP request. [`WireMessage::sig`] authenticates the mail.
//!
//! `wake` is carried but not signed (the envelope digest is shared with the
//! badge and its vectors). A receiver must treat `wake` as a hint it may make
//! quieter, never louder than its own rules.

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::badge::{envelope_digest, sha256, Envelope, FileDigest, TooLong};
use crate::host::{Arrival, Attachment, Mode, VerifiedMessage, VerifiedParts};
use crate::pairing::{PublicKey, Signer};
use crate::replay::{in_window, SeenEntry, SeenStore};

/// Largest body plus attachments (decoded).
pub const MAX_CONTENT: usize = 448 * 1024;
/// Largest encoded message (the JSON), so a sealed message always fits the
/// plane's 512 KiB hold cap: 512 KiB less the seal's 61 bytes. Attachments
/// travel as base64, so with files the real limit is this one, about
/// 380 KiB of raw attachment bytes.
pub const MAX_WIRE_JSON: usize = 512 * 1024 - 61;
/// Longest `content_type`.
pub const MAX_CONTENT_TYPE: usize = 255;
/// Most attachments on one message.
pub const MAX_FILES: usize = 32;

/// One attachment on the wire. `content` is standard base64 of the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFile {
    pub name: String,
    pub content: String,
}

/// A signed v2 message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireMessage {
    pub v: u32,
    /// ULID, canonical (26 characters of uppercase Crockford base32).
    pub id: String,
    pub from: Address,
    pub to: Address,
    /// Unix seconds, sender's clock.
    pub sent_at: i64,
    pub mode: Mode,
    pub content_type: String,
    #[serde(default = "default_wake")]
    pub wake: bool,
    pub body: String,
    #[serde(default)]
    pub files: Vec<WireFile>,
    /// Ed25519 signature over the envelope digest, standard padded base64.
    pub sig: String,
}

fn default_wake() -> bool {
    true
}

/// What the sender signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft<'a> {
    pub id: &'a str,
    pub from: &'a Address,
    pub to: &'a Address,
    pub sent_at: i64,
    pub mode: Mode,
    pub content_type: &'a str,
    pub body: &'a str,
    pub files: &'a [FileBytes],
    pub wake: bool,
}

/// Attachment bytes before base64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBytes {
    pub name: String,
    pub content: Vec<u8>,
}

/// Why sign or verify failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// `v` isn't 2.
    BadVersion,
    /// `id` isn't a canonical ULID.
    BadId,
    /// Body plus attachments over [`MAX_CONTENT`], too many files, or a
    /// field too long to frame.
    TooLarge,
    /// `sig` isn't 64 bytes of canonical base64, or doesn't verify.
    BadSig,
    /// The signer holds a key other than the sender's.
    WrongSigner,
    /// `sent_at` is outside the window for this arrival.
    Stale,
    /// Addressed to another handle than the one delivering it.
    NotForUs,
    /// Already delivered: same `(from, id)`.
    Replayed,
    /// An attachment isn't canonical base64.
    BadFile,
    /// The host's seen list failed; retry later, nothing was delivered.
    Store(String),
}

impl WireError {
    /// Whether the same message could succeed later. Only a storage error is.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Store(_))
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVersion => f.write_str("wire version is not 2"),
            Self::BadId => f.write_str("message id is not a canonical ULID"),
            Self::TooLarge => f.write_str("message too large"),
            Self::BadSig => f.write_str("wire signature verification failed"),
            Self::WrongSigner => f.write_str("signer key is not the sender's"),
            Self::Stale => f.write_str("sent_at outside the allowed window"),
            Self::NotForUs => f.write_str("message is addressed to another handle"),
            Self::Replayed => f.write_str("message already delivered"),
            Self::BadFile => f.write_str("file content is not standard base64"),
            Self::Store(e) => write!(f, "seen list: {e}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<TooLong> for WireError {
    fn from(_: TooLong) -> Self {
        Self::TooLarge
    }
}

/// Sign `draft`. `me` is the sender's own public key; a signer holding
/// another key is refused, since every receiver would refuse the message.
///
/// # Errors
/// [`WireError::BadId`], [`WireError::TooLarge`] or [`WireError::WrongSigner`].
pub fn sign(
    signer: &dyn Signer,
    me: &PublicKey,
    draft: &Draft<'_>,
) -> Result<WireMessage, WireError> {
    check_shape(draft.id, draft.content_type, draft.body, draft.files)?;
    let digest = digest_of(draft)?;
    let sig = signer.sign(&digest);
    if !me.verifies(&digest, &sig) {
        return Err(WireError::WrongSigner);
    }
    Ok::<_, WireError>(WireMessage {
        v: crate::WIRE_VERSION,
        id: draft.id.to_string(),
        from: draft.from.clone(),
        to: draft.to.clone(),
        sent_at: draft.sent_at,
        mode: draft.mode,
        content_type: draft.content_type.to_string(),
        wake: draft.wake,
        body: draft.body.to_string(),
        files: draft
            .files
            .iter()
            .map(|f| WireFile {
                name: f.name.clone(),
                content: crate::b64::encode(&f.content),
            })
            .collect(),
        sig: crate::b64::encode(&sig),
    })
    .and_then(|msg| match encode_json(&msg) {
        Ok(json) if json.len() <= MAX_WIRE_JSON => Ok(msg),
        _ => Err(WireError::TooLarge),
    })
}

/// What [`verify`] checks a message against.
pub struct Expect<'a> {
    /// The sender's pinned key, looked up by `msg.from` in the friend store.
    pub sender: &'a PublicKey,
    /// The local handle this message is being delivered to.
    pub to: &'a Address,
    /// Unix seconds, this box's clock.
    pub now: i64,
    pub arrival: Arrival,
}

/// Verify `msg` and record it as seen. In order: version, id, sizes,
/// recipient, time window, signature, then the seen list, so a forged or
/// stale message never takes a slot in it.
///
/// # Errors
/// See [`WireError`]. Only [`WireError::Store`] is worth retrying.
pub fn verify(
    msg: &WireMessage,
    expect: &Expect<'_>,
    seen: &mut dyn SeenStore,
) -> Result<VerifiedMessage, WireError> {
    if msg.v != crate::WIRE_VERSION {
        return Err(WireError::BadVersion);
    }
    let files = decode_files(&msg.files)?;
    check_shape(&msg.id, &msg.content_type, &msg.body, &files)?;
    if &msg.to != expect.to {
        return Err(WireError::NotForUs);
    }
    if !in_window(msg.sent_at, expect.now, expect.arrival) {
        return Err(WireError::Stale);
    }
    let draft = Draft {
        id: &msg.id,
        from: &msg.from,
        to: &msg.to,
        sent_at: msg.sent_at,
        mode: msg.mode,
        content_type: &msg.content_type,
        body: &msg.body,
        files: &files,
        wake: msg.wake,
    };
    let digest = digest_of(&draft)?;
    let sig: [u8; 64] = crate::b64::decode(&msg.sig)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(WireError::BadSig)?;
    if !expect.sender.verifies(&digest, &sig) {
        return Err(WireError::BadSig);
    }
    let entry = SeenEntry::new(&msg.from.to_string(), &msg.id, msg.sent_at);
    if !seen.insert_new(&entry).map_err(WireError::Store)? {
        return Err(WireError::Replayed);
    }
    Ok(VerifiedMessage::new(VerifiedParts {
        id: msg.id.clone(),
        from: msg.from.to_string(),
        to: msg.to.to_string(),
        sender_fingerprint: expect.sender.fingerprint(),
        body: msg.body.as_bytes().to_vec(),
        content_type: msg.content_type.clone(),
        sent_at: msg.sent_at,
        arrival: expect.arrival,
        mode: msg.mode,
        wake: msg.wake,
        files: files
            .into_iter()
            .map(|f| Attachment::new(&f.name, f.content))
            .collect(),
    })?)
}

/// Whether `id` is a canonical ULID.
#[must_use]
pub fn is_canonical_ulid(id: &str) -> bool {
    id.parse::<ulid::Ulid>().is_ok_and(|u| u.to_string() == id)
}

fn check_shape(
    id: &str,
    content_type: &str,
    body: &str,
    files: &[FileBytes],
) -> Result<(), WireError> {
    if !is_canonical_ulid(id) {
        return Err(WireError::BadId);
    }
    let content = files
        .iter()
        .try_fold(body.len(), |n, f| n.checked_add(f.content.len()));
    if files.len() > MAX_FILES
        || content_type.len() > MAX_CONTENT_TYPE
        || content.is_none_or(|n| n > MAX_CONTENT)
    {
        return Err(WireError::TooLarge);
    }
    Ok(())
}

fn decode_files(files: &[WireFile]) -> Result<Vec<FileBytes>, WireError> {
    if files.len() > MAX_FILES {
        return Err(WireError::TooLarge);
    }
    files
        .iter()
        .map(|f| {
            Ok(FileBytes {
                name: f.name.clone(),
                content: crate::b64::decode(&f.content).map_err(|_| WireError::BadFile)?,
            })
        })
        .collect()
}

fn digest_of(draft: &Draft<'_>) -> Result<[u8; 32], WireError> {
    let file_digests: Vec<FileDigest> = draft
        .files
        .iter()
        .map(|f| FileDigest {
            name: f.name.clone(),
            sha256: sha256(&f.content),
        })
        .collect();
    let (from, to) = (draft.from.to_string(), draft.to.to_string());
    Ok(envelope_digest(&Envelope {
        version: crate::WIRE_VERSION,
        id: draft.id,
        from: &from,
        to: &to,
        sent_at: draft.sent_at,
        mode: draft.mode,
        content_type: draft.content_type,
        files: &file_digests,
        body_sha256: sha256(draft.body.as_bytes()),
    })?)
}

/// JSON encoding of a wire message (live body, hold plaintext).
///
/// # Errors
/// [`serde_json::Error`] if the message cannot be encoded.
pub fn encode_json(msg: &WireMessage) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}

/// JSON decoding of a wire message. Unknown fields and non-canonical
/// addresses are refused.
///
/// # Errors
/// [`serde_json::Error`] if the bytes are not a v2 message object.
pub fn decode_json(bytes: &[u8]) -> Result<WireMessage, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::replay::{MemorySeen, HOLD_TTL_SECS, MAX_SKEW_SECS};
    use ed25519_dalek::SigningKey;

    pub(crate) const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    pub(crate) const T0: i64 = 1_800_000_000;

    pub(crate) fn key(seed: u8) -> (SigningKey, PublicKey) {
        use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePublicKey};
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (sk, PublicKey::from_pem(&pem).unwrap())
    }

    pub(crate) fn alice_addr() -> Address {
        Address::parse("alice::acme.postal.bot").unwrap()
    }

    pub(crate) fn scout_addr() -> Address {
        Address::parse("scout::bravo.postal.bot").unwrap()
    }

    pub(crate) fn signed(files: &[FileBytes]) -> WireMessage {
        let (sk, pk) = key(0x11);
        let (from, to) = (alice_addr(), scout_addr());
        sign(
            &sk,
            &pk,
            &Draft {
                id: ID,
                from: &from,
                to: &to,
                sent_at: T0,
                mode: Mode::Live,
                content_type: "text/plain; charset=utf-8",
                body: "hello scout",
                files,
                wake: true,
            },
        )
        .unwrap()
    }

    fn check(msg: &WireMessage, now: i64, arrival: Arrival) -> Result<VerifiedMessage, WireError> {
        let (_, alice) = key(0x11);
        let to = scout_addr();
        verify(
            msg,
            &Expect {
                sender: &alice,
                to: &to,
                now,
                arrival,
            },
            &mut MemorySeen::default(),
        )
    }

    #[test]
    fn sign_verify_roundtrip() {
        let files = [FileBytes {
            name: "a.txt".into(),
            content: b"x".to_vec(),
        }];
        let msg = signed(&files);
        assert_eq!(msg.v, 2);
        assert_eq!(crate::b64::decode(&msg.sig).unwrap().len(), 64);
        let v = check(&msg, T0, Arrival::Live).unwrap();
        assert_eq!(v.body(), b"hello scout");
        assert_eq!(v.files()[0].wire_name(), "a.txt");
        assert_eq!(v.sender_fingerprint(), &key(0x11).1.fingerprint());
        assert!(v.badge().starts_with("p_"));
    }

    #[test]
    fn wrong_key_tamper_and_version_fail() {
        let msg = signed(&[]);
        let (_, bob) = key(0x22);
        let to = scout_addr();
        let other = verify(
            &msg,
            &Expect {
                sender: &bob,
                to: &to,
                now: T0,
                arrival: Arrival::Live,
            },
            &mut MemorySeen::default(),
        );
        assert_eq!(other.unwrap_err(), WireError::BadSig);
        let mut m = msg.clone();
        m.body = "hello scouT".into();
        assert_eq!(check(&m, T0, Arrival::Live).unwrap_err(), WireError::BadSig);
        let mut m = msg.clone();
        m.from = Address::parse("mallory::acme.postal.bot").unwrap();
        assert_eq!(check(&m, T0, Arrival::Live).unwrap_err(), WireError::BadSig);
        let mut m = msg.clone();
        m.v = 1;
        assert_eq!(
            check(&m, T0, Arrival::Live).unwrap_err(),
            WireError::BadVersion
        );
        let mut m = msg.clone();
        m.sig = format!(" {}", msg.sig);
        assert_eq!(check(&m, T0, Arrival::Live).unwrap_err(), WireError::BadSig);
        let mut m = msg;
        m.sig = crate::b64::encode(&[0u8; 63]);
        assert_eq!(check(&m, T0, Arrival::Live).unwrap_err(), WireError::BadSig);
    }

    #[test]
    fn a_signer_with_another_key_is_refused() {
        let (_, alice) = key(0x11);
        let (bob_sk, _) = key(0x22);
        let (from, to) = (alice_addr(), scout_addr());
        let err = sign(
            &bob_sk,
            &alice,
            &Draft {
                id: ID,
                from: &from,
                to: &to,
                sent_at: T0,
                mode: Mode::Live,
                content_type: "text/plain",
                body: "x",
                files: &[],
                wake: true,
            },
        );
        assert_eq!(err.unwrap_err(), WireError::WrongSigner);
    }

    #[test]
    fn addressed_to_another_handle_is_refused() {
        let msg = signed(&[]);
        let (_, alice) = key(0x11);
        let other = Address::parse("other::bravo.postal.bot").unwrap();
        let err = verify(
            &msg,
            &Expect {
                sender: &alice,
                to: &other,
                now: T0,
                arrival: Arrival::Live,
            },
            &mut MemorySeen::default(),
        );
        assert_eq!(err.unwrap_err(), WireError::NotForUs);
    }

    #[test]
    fn live_and_held_windows() {
        let msg = signed(&[]);
        check(&msg, T0 + MAX_SKEW_SECS, Arrival::Live).unwrap();
        assert_eq!(
            check(&msg, T0 + MAX_SKEW_SECS + 1, Arrival::Live).unwrap_err(),
            WireError::Stale
        );
        check(&msg, T0 + HOLD_TTL_SECS, Arrival::Held).unwrap();
        assert_eq!(
            check(&msg, T0 + HOLD_TTL_SECS + MAX_SKEW_SECS + 1, Arrival::Held).unwrap_err(),
            WireError::Stale
        );
        assert_eq!(
            check(&msg, T0 - MAX_SKEW_SECS - 1, Arrival::Held).unwrap_err(),
            WireError::Stale
        );
    }

    #[test]
    fn delivered_once_and_forgeries_take_no_slot() {
        let msg = signed(&[]);
        let (_, alice) = key(0x11);
        let to = scout_addr();
        let expect = Expect {
            sender: &alice,
            to: &to,
            now: T0,
            arrival: Arrival::Live,
        };
        let mut seen = MemorySeen::default();
        let mut forged = msg.clone();
        forged.body = "evil".into();
        assert_eq!(
            verify(&forged, &expect, &mut seen).unwrap_err(),
            WireError::BadSig
        );
        assert!(seen.is_empty(), "a forgery must not take the id");
        verify(&msg, &expect, &mut seen).unwrap();
        assert_eq!(
            verify(&msg, &expect, &mut seen).unwrap_err(),
            WireError::Replayed
        );
        struct Broken;
        impl SeenStore for Broken {
            fn insert_new(&mut self, _: &SeenEntry) -> Result<bool, String> {
                Err("disk full".into())
            }
        }
        let err = verify(&msg, &expect, &mut Broken).unwrap_err();
        assert!(err.is_retryable(), "{err}");
    }

    #[test]
    fn shape_limits() {
        let (sk, pk) = key(0x11);
        let (from, to) = (alice_addr(), scout_addr());
        let big = [FileBytes {
            name: "big".into(),
            content: vec![0; MAX_CONTENT],
        }];
        let draft = |id: &'static str, files: &'static [FileBytes]| Draft {
            id,
            from: &from,
            to: &to,
            sent_at: T0,
            mode: Mode::Live,
            content_type: "text/plain",
            body: "x",
            files,
            wake: true,
        };
        let big: &'static [FileBytes] = Box::leak(Box::new(big));
        assert_eq!(
            sign(&sk, &pk, &draft(ID, big)).unwrap_err(),
            WireError::TooLarge
        );
        for id in ["01arz3ndektsv4rrffq69g5fav", "not-a-ulid", ""] {
            assert_eq!(
                sign(&sk, &pk, &draft(id, &[])).unwrap_err(),
                WireError::BadId
            );
        }
        let mut m = signed(&[]);
        m.id = ID.to_lowercase();
        assert_eq!(check(&m, T0, Arrival::Live).unwrap_err(), WireError::BadId);
    }

    #[test]
    fn json_roundtrip_wake_default_and_strictness() {
        let msg = signed(&[]);
        let bytes = encode_json(&msg).unwrap();
        assert_eq!(decode_json(&bytes).unwrap(), msg);
        let mut obj: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(obj["v"], 2);
        obj.as_object_mut().unwrap().remove("wake");
        let no_wake: WireMessage = serde_json::from_value(obj.clone()).unwrap();
        assert!(no_wake.wake, "missing wake defaults on");
        let mut extra = obj.clone();
        extra["admin"] = true.into();
        assert!(serde_json::from_value::<WireMessage>(extra).is_err());
        let mut upper = obj;
        upper["from"] = "Alice::acme.postal.bot".into();
        assert!(serde_json::from_value::<WireMessage>(upper).is_err());
    }

    #[test]
    fn digest_matches_badge_module() {
        let msg = signed(&[]);
        let v = check(&msg, T0, Arrival::Live).unwrap();
        let d = crate::badge::envelope_digest(&crate::badge::Envelope {
            version: 2,
            id: ID,
            from: "alice::acme.postal.bot",
            to: "scout::bravo.postal.bot",
            sent_at: T0,
            mode: Mode::Live,
            content_type: "text/plain; charset=utf-8",
            files: &[],
            body_sha256: crate::badge::sha256(b"hello scout"),
        })
        .unwrap();
        assert_eq!(v.badge(), crate::badge::badge(&d));
    }

    /// Golden vectors, computed independently with Python's `cryptography`
    /// (`vectors/postal-v1.json`, section `wire`): digest, signature and the
    /// exact JSON bytes.
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        let wires = all["wire"].as_array().unwrap();
        assert!(!wires.is_empty());
        for v in wires {
            let seed: [u8; 32] =
                crate::hex::from_hex32(v["sender_seed_hex"].as_str().unwrap()).unwrap();
            let sk = SigningKey::from_bytes(&seed);
            let pk = PublicKey::from_pem(v["sender_pem"].as_str().unwrap()).unwrap();
            let want: WireMessage = serde_json::from_value(v["message"].clone()).unwrap();
            let json = v["json"].as_str().unwrap();
            assert_eq!(decode_json(json.as_bytes()).unwrap(), want);
            assert_eq!(
                encode_json(&want).unwrap(),
                json.as_bytes(),
                "byte-exact JSON"
            );
            let files = decode_files(&want.files).unwrap();
            let draft = Draft {
                id: &want.id,
                from: &want.from,
                to: &want.to,
                sent_at: want.sent_at,
                mode: want.mode,
                content_type: &want.content_type,
                body: &want.body,
                files: &files,
                wake: want.wake,
            };
            assert_eq!(
                crate::hex::to_hex(&digest_of(&draft).unwrap()),
                v["digest_hex"].as_str().unwrap()
            );
            assert_eq!(sign(&sk, &pk, &draft).unwrap(), want, "same signature");
            verify(
                &want,
                &Expect {
                    sender: &pk,
                    to: &want.to,
                    now: want.sent_at,
                    arrival: Arrival::Live,
                },
                &mut MemorySeen::default(),
            )
            .unwrap();
        }
    }
}
