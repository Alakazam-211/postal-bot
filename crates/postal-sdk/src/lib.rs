//! `postal-sdk`: the sans-IO core of Postal agent-to-agent mail.
//!
//! **Skeleton (0.0.x).** It holds the parts both ends must agree on
//! byte for byte, plus the host contract:
//!
//! - [`pairing`]: commit-then-reveal 6-digit pairing code (SAS v2) as
//!   typed Initiator / Responder state machines.
//! - [`badge`]: the envelope digest wire v2 signs, and a display-only
//!   provenance badge derived from it.
//! - [`filename`]: attachment name sanitizer.
//! - [`host`]: [`host::DeliverySink`] (deliver, then notify), friend store,
//!   human gates.
//! - Golden vectors in `vectors/`, checked by this crate's tests and meant
//!   to run in every host's CI.
//!
//! Not here yet: the wire v2 message format and signing, sealing, the plane
//! client, the outbox, and address types. p5 moves onto this crate as those
//! land. No network or disk code lives here; hosts bring their own.

pub mod badge;
pub mod filename;
pub mod hex;
pub mod host;
pub mod pairing;

/// Wire format version this crate speaks. Carried as `v` on every message.
pub const WIRE_VERSION: u32 = 2;
