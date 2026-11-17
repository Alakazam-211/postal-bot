//! `postal-sdk`: the sans-IO core of Postal agent-to-agent mail.
//!
//! **0.0.x.** The parts both ends must agree on byte for byte, plus the
//! host contract. No network or disk code lives here; hosts bring their own.
//!
//! - [`pairing`]: commit-then-reveal 6-digit pairing code (SAS v2).
//! - [`badge`]: envelope digest wire v2 signs, and a display-only badge.
//! - [`wire`]: v2 message format and Ed25519 signature over that digest.
//! - [`seal`]: HoldSeal-v1 (X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305).
//! - [`plane`]: P-4 hold PUT/GET/ACK + P-5 `/postal/events` (trait; hosts HTTP).
//! - [`outbox`]: queued → live → held/delivered/acked/failed.
//! - [`filename`]: attachment name sanitizer.
//! - [`host`]: [`host::DeliverySink`] (deliver, then notify), friend store,
//!   human gates.
//! - Golden vectors in `vectors/`.
//!
//! Not here yet: typed addresses. p5 does not depend on this crate yet.

pub mod b64;
pub mod badge;
pub mod filename;
pub mod hex;
pub mod host;
pub mod identity;
pub mod outbox;
pub mod pairing;
pub mod plane;
pub mod seal;
pub mod wire;

/// Wire format version this crate speaks. Carried as `v` on every message.
pub const WIRE_VERSION: u32 = 2;
