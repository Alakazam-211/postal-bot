//! HTTP client for the Postal control plane (CP-3 pairing).
//!
//! Default base is `P5_PLANE_URL` or `https://k2.dev`. Auth is
//! `Authorization: Bearer k2c_…` from `P5_CONNECT_TOKEN` or
//! `~/.postal/config.toml` `connect_token`. Private keys never leave the CLI.

mod client;
mod config;
mod error;
mod types;

pub use client::PlaneClient;
pub use config::{PlaneConfig, PostalFile, CONFIG_FILE};
pub use error::PlaneError;
pub use types::{
    AcceptRequest, MeRequest, MeResponse, PairAddRequest, PairAddResponse, PairLists, PairView,
};

/// Default plane origin (K2 Web).
pub const DEFAULT_PLANE_URL: &str = "https://k2.dev";
/// Owner-facing pairing chrome on the same site.
pub const DASHBOARD_PAIR: &str = "/dashboard?tab=postal";
