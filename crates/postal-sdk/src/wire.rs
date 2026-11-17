//! Wire v2: signed envelope. `v` is [`crate::WIRE_VERSION`].
//!
//! The hop-auth proof on `POST /p5/msg` (`p5-msg-v1`) is separate: that
//! authenticates the HTTP request. [`WireMessage::sig`] authenticates the mail.

use serde::{Deserialize, Serialize};

use crate::badge::{envelope_digest, sha256, Envelope, FileDigest, TooLong};
use crate::host::{Arrival, Attachment, Mode, VerifiedMessage, VerifiedParts};
use crate::identity::{fingerprint_spki_pem, parse_spki_pem, verify_sig, Identity, IdentityError};

/// Default `|now - sent_at|` allowed, in seconds.
pub const MAX_SKEW_SECS: i64 = 300;

/// One attachment on the wire. `content` is standard base64 of the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFile {
    pub name: String,
    pub content: String,
}

/// A signed v2 message, as JSON on live `POST /p5/msg` and as the plaintext
/// inside a HoldSeal-v1 blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub v: u32,
    pub id: String,
    pub from: String,
    pub to: String,
    pub sent_at: i64,
    pub mode: Mode,
    pub content_type: String,
    #[serde(default = "default_wake")]
    pub wake: bool,
    pub body: String,
    #[serde(default)]
    pub files: Vec<WireFile>,
    /// 64-byte Ed25519 signature over the envelope digest, lowercase hex.
    pub sig: String,
}

fn default_wake() -> bool {
    true
}

/// Fields the sender signs. `wake` is carried on the wire but not digested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft<'a> {
    pub id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
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
    TooLong,
    BadVersion,
    BadSig,
    Skew,
    BadKey(String),
    BadHex,
    BadFile,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => f.write_str("envelope field longer than 4 GiB"),
            Self::BadVersion => f.write_str("wire version is not 2"),
            Self::BadSig => f.write_str("wire signature verification failed"),
            Self::Skew => f.write_str("sent_at outside allowed skew"),
            Self::BadKey(msg) => write!(f, "wire key: {msg}"),
            Self::BadHex => f.write_str("sig is not 64-byte hex"),
            Self::BadFile => f.write_str("file content is not standard base64"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<TooLong> for WireError {
    fn from(_: TooLong) -> Self {
        Self::TooLong
    }
}

impl From<IdentityError> for WireError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::Sig => Self::BadSig,
            IdentityError::Key(msg) => Self::BadKey(msg),
        }
    }
}

/// Sign `draft` with the sender's identity.
///
/// # Errors
/// [`WireError::TooLong`] if a field doesn't fit the digest frame.
pub fn sign(identity: &Identity, draft: Draft<'_>) -> Result<WireMessage, WireError> {
    let files: Vec<WireFile> = draft
        .files
        .iter()
        .map(|f| WireFile {
            name: f.name.clone(),
            content: crate::b64::encode(&f.content),
        })
        .collect();
    let digest = digest_of(&draft)?;
    Ok(WireMessage {
        v: crate::WIRE_VERSION,
        id: draft.id.to_string(),
        from: draft.from.to_string(),
        to: draft.to.to_string(),
        sent_at: draft.sent_at,
        mode: draft.mode,
        content_type: draft.content_type.to_string(),
        wake: draft.wake,
        body: draft.body.to_string(),
        files,
        sig: crate::hex::to_hex(&identity.sign(&digest)),
    })
}

/// Verify `msg` against the sender's pinned SPKI. `now` is unix seconds.
/// Replay is the host's job (mailbox already-id).
///
/// # Errors
/// Version, skew, signature, key, or framing errors.
pub fn verify(
    msg: &WireMessage,
    pinned_spki_pem: &str,
    now: i64,
) -> Result<VerifiedMessage, WireError> {
    verify_with_skew(msg, pinned_spki_pem, now, MAX_SKEW_SECS, Arrival::Live)
}

/// Same as [`verify`], with an explicit skew and arrival.
///
/// # Errors
/// Version, skew, signature, key, or framing errors.
pub fn verify_with_skew(
    msg: &WireMessage,
    pinned_spki_pem: &str,
    now: i64,
    max_skew: i64,
    arrival: Arrival,
) -> Result<VerifiedMessage, WireError> {
    if msg.v != crate::WIRE_VERSION {
        return Err(WireError::BadVersion);
    }
    let skew = now.checked_sub(msg.sent_at).unwrap_or(i64::MIN);
    if skew.unsigned_abs() > max_skew.unsigned_abs() {
        return Err(WireError::Skew);
    }
    let files = decode_files(&msg.files)?;
    let digest = digest_of(&Draft {
        id: &msg.id,
        from: &msg.from,
        to: &msg.to,
        sent_at: msg.sent_at,
        mode: msg.mode,
        content_type: &msg.content_type,
        body: &msg.body,
        files: &files,
        wake: msg.wake,
    })?;
    let sig = sig_bytes(&msg.sig)?;
    let vk = parse_spki_pem(pinned_spki_pem)?;
    verify_sig(&vk, &digest, &sig)?;
    let attachments: Vec<Attachment> = files
        .into_iter()
        .map(|f| Attachment::new(&f.name, f.content))
        .collect();
    Ok(VerifiedMessage::new(VerifiedParts {
        id: msg.id.clone(),
        from: msg.from.clone(),
        to: msg.to.clone(),
        sender_fingerprint: fingerprint_spki_pem(pinned_spki_pem)?,
        body: msg.body.as_bytes().to_vec(),
        content_type: msg.content_type.clone(),
        sent_at: msg.sent_at,
        arrival,
        mode: msg.mode,
        wake: msg.wake,
        files: attachments,
    })?)
}

fn sig_bytes(hex: &str) -> Result<[u8; 64], WireError> {
    let v = crate::hex::from_hex(hex).map_err(|_| WireError::BadHex)?;
    v.try_into().map_err(|_| WireError::BadHex)
}

fn decode_files(files: &[WireFile]) -> Result<Vec<FileBytes>, WireError> {
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
    Ok(envelope_digest(&Envelope {
        version: crate::WIRE_VERSION,
        id: draft.id,
        from: draft.from,
        to: draft.to,
        sent_at: draft.sent_at,
        mode: draft.mode,
        content_type: draft.content_type,
        files: &file_digests,
        body_sha256: sha256(draft.body.as_bytes()),
    })?)
}

/// JSON encoding of a wire message (live body / hold plaintext).
///
/// # Errors
/// [`serde_json::Error`] if the message cannot be encoded.
pub fn encode_json(msg: &WireMessage) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(msg)
}

/// JSON decoding of a wire message.
///
/// # Errors
/// [`serde_json::Error`] if the bytes are not a v2 message object.
pub fn decode_json(bytes: &[u8]) -> Result<WireMessage, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const FROM: &str = "alice::acme.postal.bot";
    const TO: &str = "scout::acme.postal.bot";
    const T0: i64 = 1_800_000_000;

    fn alice() -> Identity {
        Identity::from_seed([0x11; 32])
    }

    fn draft<'a>(files: &'a [FileBytes]) -> Draft<'a> {
        Draft {
            id: ID,
            from: FROM,
            to: TO,
            sent_at: T0,
            mode: Mode::Live,
            content_type: "text/plain; charset=utf-8",
            body: "hello scout",
            files,
            wake: true,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let alice = alice();
        let files = [FileBytes {
            name: "a.txt".into(),
            content: b"x".to_vec(),
        }];
        let msg = sign(&alice, draft(&files)).unwrap();
        assert_eq!(msg.v, 2);
        assert_eq!(msg.sig.len(), 128);
        let verified = verify(&msg, &alice.public_key_pem(), T0).unwrap();
        assert_eq!(verified.body(), b"hello scout");
        assert_eq!(verified.files()[0].wire_name(), "a.txt");
        assert_eq!(verified.sender_fingerprint(), &alice.fingerprint());
        assert!(verified.badge().starts_with("p_"));
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let alice = alice();
        let bob = Identity::from_seed([0x22; 32]);
        let none: [FileBytes; 0] = [];
        let msg = sign(&alice, draft(&none)).unwrap();
        assert_eq!(
            verify(&msg, &bob.public_key_pem(), T0).unwrap_err(),
            WireError::BadSig
        );
        let mut tampered = msg.clone();
        tampered.body = "hello scouT".into();
        assert_eq!(
            verify(&tampered, &alice.public_key_pem(), T0).unwrap_err(),
            WireError::BadSig
        );
        let mut bad_v = msg;
        bad_v.v = 1;
        assert_eq!(
            verify(&bad_v, &alice.public_key_pem(), T0).unwrap_err(),
            WireError::BadVersion
        );
    }

    #[test]
    fn skew_is_refused() {
        let alice = alice();
        let none: [FileBytes; 0] = [];
        let msg = sign(&alice, draft(&none)).unwrap();
        assert_eq!(
            verify(&msg, &alice.public_key_pem(), T0 + MAX_SKEW_SECS + 1).unwrap_err(),
            WireError::Skew
        );
        verify(&msg, &alice.public_key_pem(), T0 + MAX_SKEW_SECS).unwrap();
    }

    #[test]
    fn json_roundtrip_and_wake_default() {
        let alice = alice();
        let none: [FileBytes; 0] = [];
        let msg = sign(&alice, draft(&none)).unwrap();
        let bytes = encode_json(&msg).unwrap();
        let parsed = decode_json(&bytes).unwrap();
        assert_eq!(parsed, msg);
        assert!(
            bytes.windows(5).any(|w| w == b"\"v\":2") || bytes.windows(6).any(|w| w == br#""v":2"#)
        );
        let mut obj: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        obj.as_object_mut().unwrap().remove("wake");
        let no_wake: WireMessage = serde_json::from_value(obj).unwrap();
        assert!(no_wake.wake, "missing wake defaults on");
    }

    #[test]
    fn hold_plaintext_is_the_signed_wire_json() {
        let alice = alice();
        let bob = Identity::generate();
        let none: [FileBytes; 0] = [];
        let msg = sign(&alice, draft(&none)).unwrap();
        let json = encode_json(&msg).unwrap();
        let blob = crate::seal::seal(
            &bob.public_key_pem(),
            &json,
            &crate::seal::SealAad {
                id: ID.into(),
                from: FROM.into(),
                to: TO.into(),
            },
        )
        .unwrap();
        let opened = bob
            .open(
                &blob,
                &crate::seal::SealAad {
                    id: ID.into(),
                    from: FROM.into(),
                    to: TO.into(),
                },
            )
            .unwrap();
        let parsed = decode_json(&opened).unwrap();
        verify_with_skew(
            &parsed,
            &alice.public_key_pem(),
            T0,
            MAX_SKEW_SECS,
            Arrival::Held,
        )
        .unwrap();
    }

    #[test]
    fn digest_matches_badge_module() {
        let alice = alice();
        let none: [FileBytes; 0] = [];
        let msg = sign(&alice, draft(&none)).unwrap();
        let verified = verify(&msg, &alice.public_key_pem(), T0).unwrap();
        let d = crate::badge::envelope_digest(&crate::badge::Envelope {
            version: 2,
            id: ID,
            from: FROM,
            to: TO,
            sent_at: T0,
            mode: Mode::Live,
            content_type: "text/plain; charset=utf-8",
            files: &[],
            body_sha256: crate::badge::sha256(b"hello scout"),
        })
        .unwrap();
        assert_eq!(verified.badge(), crate::badge::badge(&d));
    }
}
