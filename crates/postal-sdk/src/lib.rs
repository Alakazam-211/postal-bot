//! `postal-sdk`: the sans-IO core of Postal agent-to-agent mail.
//!
//! **0.0.x.** The parts both ends must agree on byte for byte, plus the
//! host contract. No network or disk code lives here; hosts bring their own.
//!
//! - [`pairing`]: commit-then-reveal 6-digit pairing code (SAS v2) and
//!   the signed both-sides confirmation, as
//!   typed state machines.
//! - [`badge`]: the envelope digest wire v2 signs, and a display-only
//!   provenance badge derived from it.
//! - [`wire`]: v2 message format and Ed25519 signature over that digest.
//! - [`address`]: canonical `handle::label.postal.bot`.
//! - [`replay`]: time windows and the host's seen list (F6).
//! - [`hold`]: HoldSeal-v2, the sender-signed message sealed to the recipient (F4).
//! - [`seal`]: HoldSeal-v1, byte-identical to p5-crypto, for the old routes only.
//! - [`plane`]: P-4 hold PUT/GET/ACK + P-5 `/postal/events` (trait; hosts HTTP).
//! - [`outbox`]: queued → live → held/delivered/acked/failed.
//! - [`filename`]: attachment name sanitizer.
//! - [`host`]: [`host::DeliverySink`] (deliver, then notify), friend store,
//!   human gates.
//! - Golden vectors in `vectors/`.
//!
//! p5 does not depend on this crate yet.

#![forbid(unsafe_code)]

pub mod address;
pub mod b64;
pub mod badge;
pub mod filename;
pub mod hex;
pub mod hold;
pub mod host;
pub mod identity;
pub mod outbox;
pub mod pairing;
pub mod plane;
pub mod replay;
/// HoldSeal-v1, for p5's old hold routes only. Off unless the `hold-v1`
/// feature is on, so a host can't seal or open v1 by mistake.
#[cfg(feature = "hold-v1")]
pub mod seal;
pub mod wire;

/// Wire format version this crate speaks. Carried as `v` on every message.
pub const WIRE_VERSION: u32 = 2;
