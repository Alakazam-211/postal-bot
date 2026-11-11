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

/// A file that came with the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Already sanitized: no path parts, no `..`.
    pub name: String,
    pub bytes: Vec<u8>,
}

/// One message the SDK has verified (signature, sender key pinned for this
/// local handle, not a replay) and decrypted. The SDK calls the host once
/// per message id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessage {
    /// ULID, covered by the signature.
    pub id: String,
    pub from: String,
    /// The local handle it's for. Trust is per local handle.
    pub to: String,
    pub sender_fingerprint: String,
    pub body: Vec<u8>,
    /// Declared by the sender, e.g. `text/plain; charset=utf-8`.
    pub content_type: String,
    pub body_sha256: [u8; 32],
    /// Sender's clock, unix seconds. Already checked against skew.
    pub sent_at: i64,
    pub arrival: Arrival,
    pub mode: Mode,
    /// False when the sender passed `--no-wake`.
    pub wake: bool,
    pub files: Vec<Attachment>,
    /// [`crate::badge::badge`] of `(id, sender_fingerprint, body_sha256)`.
    pub badge: String,
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
    fn deliver(&self, msg: &VerifiedMessage) -> Result<Stored, DeliverError>;
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
    fn put(&self, friend: Friend) -> Result<(), StoreError>;
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
