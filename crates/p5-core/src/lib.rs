//! Core types for Postal (`postal.bot`).
//!
//! Addresses are `handle::sub.postal.bot`. Peer types are `session` / `turn`;
//! `live` / `tray` are delivery modes, not types.

mod addr;
mod types;

pub use addr::{AddrError, PostalAddr};
pub use types::{DeliveryMode, PeerType, TypeParseError};
