//! What a host implements: where verified mail goes, how it's announced,
//! where friends and keys live, and how a person answers a human gate.
//!
//! The SDK core is sans-IO and synchronous. A host on an async runtime
//! adapts with a blocking task or a channel; there is one trait set.
//!
//! Addresses are `handle::label.postal.bot` strings in this skeleton. They
//! become a typed `PostalAddr` when p5's address code moves into the SDK.

use std::time::Duration;

/// How the message reached us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// HTTPS straight from the sender's agent.
    Live,
    /// Held ciphertext pulled from the plane after the sender couldn't reach us.
    Held,
}

/// What the sender asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Put it in front of the agent now if it's up.
    Live,
    /// File it; no interruption.
    Tray,
}

impl Mode {
    /// Wire spelling, as covered by the envelope digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Tray => "tray",
        }
    }
}

/// A file that came with the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    wire_name: String,
    storage_name: String,
    bytes: Vec<u8>,
}

impl Attachment {
    #[must_use]
    pub fn new(wire_name: &str, bytes: Vec<u8>) -> Self {
        Self {
            wire_name: wire_name.to_string(),
            storage_name: crate::filename::sanitize(wire_name),
            bytes,
        }
    }
    /// The name exactly as the sender sent it. This is what the envelope
    /// digest and the signature cover. Never use it as a path.
    #[must_use]
    pub fn wire_name(&self) -> &str {
        &self.wire_name
    }
    /// A safe name to write to disk ([`crate::filename::sanitize`]).
    #[must_use]
    pub fn storage_name(&self) -> &str {
        &self.storage_name
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One message the SDK has verified (signature over the envelope digest,
/// sender key pinned for this local handle, not a replay) and decrypted. The
/// SDK calls the host once per message id. Only the SDK builds these, and it
/// computes the body hash and badge itself, so they always match the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessage {
    id: String,
    from: String,
    to: String,
    sender_fingerprint: crate::pairing::Fingerprint,
    body: Vec<u8>,
    content_type: String,
    body_sha256: [u8; 32],
    sent_at: i64,
    arrival: Arrival,
    mode: Mode,
    wake: bool,
    files: Vec<Attachment>,
    badge: String,
}

/// Inputs for [`VerifiedMessage`]; the SDK fills them after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedParts {
    pub id: String,
    pub from: String,
    pub to: String,
    pub sender_fingerprint: crate::pairing::Fingerprint,
    pub body: Vec<u8>,
    pub content_type: String,
    pub sent_at: i64,
    pub arrival: Arrival,
    pub mode: Mode,
    pub wake: bool,
    pub files: Vec<Attachment>,
}

impl VerifiedMessage {
    #[allow(dead_code)] // first caller is wire v2 verification
    pub(crate) fn new(p: VerifiedParts) -> Result<Self, crate::badge::TooLong> {
        use crate::badge::{badge, envelope_digest, sha256, Envelope, FileDigest};
        let body_sha256 = sha256(&p.body);
        let files: Vec<FileDigest> = p
            .files
            .iter()
            .map(|f| FileDigest { name: f.wire_name.clone(), sha256: sha256(&f.bytes) })
            .collect();
        let digest = envelope_digest(&Envelope {
            version: crate::WIRE_VERSION,
            id: &p.id,
            from: &p.from,
            to: &p.to,
            sent_at: p.sent_at,
            mode: p.mode,
            content_type: &p.content_type,
            files: &files,
            body_sha256,
        })?;
        Ok(Self {
            badge: badge(&digest),
            body_sha256,
            id: p.id,
            from: p.from,
            to: p.to,
            sender_fingerprint: p.sender_fingerprint,
            body: p.body,
            content_type: p.content_type,
            sent_at: p.sent_at,
            arrival: p.arrival,
            mode: p.mode,
            wake: p.wake,
            files: p.files,
        })
    }

    /// ULID, covered by the signature.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }
    /// The local handle it's for. Trust is per local handle.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }
    #[must_use]
    pub fn sender_fingerprint(&self) -> &crate::pairing::Fingerprint {
        &self.sender_fingerprint
    }
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Declared by the sender, e.g. `text/plain; charset=utf-8`.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
    #[must_use]
    pub fn body_sha256(&self) -> &[u8; 32] {
        &self.body_sha256
    }
    /// Sender's clock, unix seconds. Already checked against skew.
    #[must_use]
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
    #[must_use]
    pub fn arrival(&self) -> Arrival {
        self.arrival
    }
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }
    /// False when the sender passed `--no-wake`.
    #[must_use]
    pub fn wake(&self) -> bool {
        self.wake
    }
    #[must_use]
    pub fn files(&self) -> &[Attachment] {
        &self.files
    }
    /// Display-only provenance badge ([`crate::badge`]). Show it out of band,
    /// never in the same text stream as the body.
    #[must_use]
    pub fn badge(&self) -> &str {
        &self.badge
    }
}

/// Proof the host has kept a message durably. The SDK ACKs the plane only
/// after it gets one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub id: String,
    pub to: String,
}

/// Why the host won't keep a message now. A closed set, so both ends and
/// the plane agree on what each code means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseCode {
    /// No agent or home for this handle on this box.
    NoAgent,
    /// The host's policy for this friend says no (files off, tray only, …).
    Gated,
    /// Bigger than the host accepts.
    TooLarge,
}

impl RefuseCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAgent => "no_agent",
            Self::Gated => "gated",
            Self::TooLarge => "too_large",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliverError {
    /// Not kept; try again. `after` is the host's hint (busy agent, disk
    /// pressure). Held mail stays held.
    Retry { after: Option<Duration>, reason: String },
    /// Never keep it. The SDK dead-letters it with this code.
    Refuse(RefuseCode),
}

/// The nudge failed. The message is still stored; the SDK retries `notify`
/// with backoff and gives up without losing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyError {
    pub reason: String,
    pub retry_after: Option<Duration>,
}

/// Where verified mail goes. `deliver` is the durable step; `notify` is the
/// best-effort nudge (type into a terminal, post a Thread line, …). The SDK
/// owns retries for both, so a host never re-implements them.
pub trait DeliverySink {
    /// Keep the message durably.
    ///
    /// # Errors
    /// [`DeliverError::Retry`] to be called again later (held mail stays
    /// held), or [`DeliverError::Refuse`] to dead-letter it.
    fn deliver(&self, msg: &VerifiedMessage) -> Result<Stored, DeliverError>;

    /// Nudge the agent about a stored message.
    ///
    /// # Errors
    /// [`NotifyError`]; the SDK retries with backoff, and the message stays stored.
    fn notify(&self, stored: &Stored) -> Result<(), NotifyError>;
}

/// A friend as seen from one local handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Friend {
    pub local_handle: String,
    pub peer: String,
    pub pinned_fingerprint: String,
    pub pinned_public_key_pem: String,
    /// A different key the plane reported. Never used to verify.
    pub rekey_pending: Option<String>,
    pub trusted: bool,
}

/// Friend rows, keyed by `(local_handle, peer)`. A friend of one handle is
/// not a friend of another handle on the same box.
pub trait FriendStore {
    fn get(&self, local_handle: &str, peer: &str) -> Option<Friend>;

    /// # Errors
    /// [`StoreError`] when the host's storage fails.
    fn put(&self, friend: Friend) -> Result<(), StoreError>;

    /// # Errors
    /// [`StoreError`] when the host's storage fails.
    fn remove(&self, local_handle: &str, peer: &str) -> Result<(), StoreError>;
}

/// The host's storage failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

/// An incoming friend request, waiting for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRequest {
    pub pair_id: String,
    pub local_handle: String,
    pub peer: String,
    pub peer_owner_name: Option<String>,
}

/// A friend's key changed on the plane, waiting for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyPending {
    pub local_handle: String,
    pub peer: String,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
}

/// Human gates record and return. They never decide: a person answers later
/// (a K2 permission card, a click on the account page), and the host calls
/// back into the SDK with the answer and the typed pairing code. A hook that
/// returned the decision would invite an agent to answer it.
pub trait HumanGate {
    fn friend_request(&self, req: &FriendRequest);
    fn rekey(&self, pending: &RekeyPending);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_message_derives_hash_and_badge_from_the_body() {
        let parts = VerifiedParts {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            from: "alice::acme.postal.bot".into(),
            to: "scout::acme.postal.bot".into(),
            sender_fingerprint: crate::pairing::Fingerprint::parse(&"aa".repeat(32)).unwrap(),
            body: b"hello scout".to_vec(),
            content_type: "text/plain; charset=utf-8".into(),
            sent_at: 1_800_000_000,
            arrival: Arrival::Live,
            mode: Mode::Live,
            wake: true,
            files: vec![Attachment::new("../../x y.txt", b"x".to_vec())],
        };
        let m = VerifiedMessage::new(parts.clone()).unwrap();
        assert_eq!(m.body_sha256(), &crate::badge::sha256(b"hello scout"));
        assert_eq!(m.files()[0].storage_name(), "x_y.txt");
        assert_eq!(m.files()[0].wire_name(), "../../x y.txt");
        let mut changed = parts.clone();
        changed.files = vec![Attachment::new("../../x y.txt", b"y".to_vec())];
        assert_ne!(VerifiedMessage::new(changed).unwrap().badge(), m.badge());
        // The digest covers the raw wire name: names that sanitize alike differ.
        let mut renamed = parts;
        renamed.files = vec![Attachment::new("x_y.txt", b"x".to_vec())];
        assert_ne!(VerifiedMessage::new(renamed).unwrap().badge(), m.badge());
    }
}
