//! HTTP client for the Postal control plane (CP-3 pairing, CP-4 hold).
//!
//! Default base is `P5_PLANE_URL` or `https://k2.dev`. Auth is
//! `Authorization: Bearer k2c_…` from `P5_CONNECT_TOKEN` or
//! `~/.postal/config.toml` `connect_token`. Private keys and plaintext
//! never leave the CLI.

mod client;
mod config;
mod error;
mod hold;
mod live;
mod types;

pub use client::PlaneClient;
pub use config::{PlaneConfig, PostalFile, CONFIG_FILE};
pub use error::PlaneError;
pub use hold::{
    decode_ciphertext, encode_ciphertext, hold_poll_delay, refuse_plaintext, seal_envelope,
    HOLD_POLL_JITTER_SECS, HOLD_POLL_SECS, HOLD_TTL_SECS,
};
pub use live::{live_send, LiveSend};
pub use types::{
    AcceptRequest, HoldEnvelope, HoldList, HoldPutResponse, MeRequest, MeResponse, PairAddRequest,
    PairAddResponse, PairLists, PairView,
};

/// Default plane origin (K2 Web).
pub const DEFAULT_PLANE_URL: &str = "https://k2.dev";
/// Owner-facing pairing chrome on the same site.
pub const DASHBOARD_PAIR: &str = "/dashboard?tab=postal";
