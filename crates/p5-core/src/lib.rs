//! Core types for Postal (`postal.bot`).
//!
//! Addresses are `handle::sub.postal.bot`. Peer types are `session` / `turn`;
//! `live` / `tray` are delivery modes, not types. Homes and roster persist as
//! JSON under `~/.postal` (0700). The live session map is not on disk.

mod addr;
mod homes;
mod roster;
mod store;
mod tools;
mod types;

pub use addr::{AddrError, PostalAddr};
pub use homes::{HomeRow, Homes};
pub use roster::{Roster, RosterEntry, Trust};
pub use store::{ensure_dir, postal_dir, StoreError, HOMES_FILE, ROSTER_FILE};
pub use tools::ToolFlags;
pub use types::{DeliveryMode, PeerType, TypeParseError};
