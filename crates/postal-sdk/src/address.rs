//! Postal addresses: `handle::label.postal.bot`, one spelling only.
//!
//! An address is signed into every wire message and bound into every seal, so
//! the SDK accepts only the canonical form: lowercase, no whitespace, nothing
//! to normalise. A host that takes user input lowercases and trims it first,
//! then calls [`Address::parse`]; what comes off the wire is never normalised.

use std::fmt;
use std::str::FromStr;

/// The one zone a v2 address may live under.
pub const ZONE: &str = "postal.bot";
/// Longest handle.
pub const MAX_HANDLE: usize = 64;

/// A canonical Postal address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    handle: String,
    label: String,
}

impl Address {
    /// Parse `handle::label.postal.bot`.
    ///
    /// - handle: 1–64 of `[a-z0-9_-]`, starting with `[a-z0-9]`;
    /// - label: 3–63 of `[a-z0-9-]`, starting and ending with `[a-z0-9]`;
    /// - exactly one `::`, and the host is exactly `<label>.postal.bot`.
    ///
    /// # Errors
    /// [`AddressError`] for anything else, including uppercase, whitespace,
    /// `@`, a bare label and a nested name.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let (handle, host) = s.split_once("::").ok_or(AddressError::Separator)?;
        if !is_handle(handle) {
            return Err(AddressError::Handle);
        }
        let label = host
            .strip_suffix(ZONE)
            .and_then(|l| l.strip_suffix('.'))
            .ok_or(AddressError::Host)?;
        if !is_label(label) {
            return Err(AddressError::Host);
        }
        Ok(Self {
            handle: handle.to_string(),
            label: label.to_string(),
        })
    }

    /// Build from parts, with the same rules as [`Address::parse`].
    ///
    /// # Errors
    /// [`AddressError::Handle`] or [`AddressError::Host`].
    pub fn new(handle: &str, label: &str) -> Result<Self, AddressError> {
        Self::parse(&format!("{handle}::{label}.{ZONE}"))
    }

    /// `scout` in `scout::acme.postal.bot`.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// `acme` in `scout::acme.postal.bot`.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// `acme.postal.bot`, where live delivery goes (`https://<host>`).
    #[must_use]
    pub fn host(&self) -> String {
        format!("{}.{ZONE}", self.label)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}.{ZONE}", self.handle, self.label)
    }
}

impl FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Why a string isn't a canonical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// No `::`.
    Separator,
    /// The handle breaks the rules (or has a second `::`).
    Handle,
    /// The host isn't `<label>.postal.bot` with a valid label.
    Host,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Separator => "address must be handle::label.postal.bot",
            Self::Handle => "handle must be 1-64 of a-z 0-9 _ -, starting a-z or 0-9",
            Self::Host => "host must be <label>.postal.bot (label 3-63 of a-z 0-9 -)",
        })
    }
}

impl std::error::Error for AddressError {}

fn is_handle(h: &str) -> bool {
    let b = h.as_bytes();
    (1..=MAX_HANDLE).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

fn is_label(l: &str) -> bool {
    let b = l.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&b.len())
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| edge(c) || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_addresses_parse_and_round_trip() {
        for s in [
            "scout::acme.postal.bot",
            "a::abc.postal.bot",
            "0_x-y::a-1.postal.bot",
            &format!("{}::{}.postal.bot", "h".repeat(64), "l".repeat(63)),
        ] {
            let a = Address::parse(s).unwrap();
            assert_eq!(a.to_string(), s);
            assert_eq!(Address::new(a.handle(), a.label()).unwrap(), a);
            let json = serde_json::to_string(&a).unwrap();
            assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), a);
        }
        let a = Address::parse("scout::acme.postal.bot").unwrap();
        assert_eq!((a.handle(), a.label()), ("scout", "acme"));
        assert_eq!(a.host(), "acme.postal.bot");
    }

    #[test]
    fn only_one_spelling() {
        for s in [
            "",
            "scout",
            "scout@acme.postal.bot",
            "scout.acme.postal.bot",
            "Scout::acme.postal.bot",
            "scout::ACME.postal.bot",
            "scout::acme.POSTAL.bot",
            " scout::acme.postal.bot",
            "scout::acme.postal.bot ",
            "scout::acme.postal.bot.",
            "::acme.postal.bot",
            "_s::acme.postal.bot",
            "-s::acme.postal.bot",
            "s c::acme.postal.bot",
            "s::t::acme.postal.bot",
            "scout::acme.k2.dev",
            "scout::acme",
            "scout::postal.bot",
            "scout::.postal.bot",
            "scout::ab.postal.bot",
            "scout::-ab.postal.bot",
            "scout::ab-.postal.bot",
            "scout::a.b.postal.bot",
            "scout::a_b.postal.bot",
            "scout::acmepostal.bot",
            "sc\u{f6}ut::acme.postal.bot",
            &format!("{}::acme.postal.bot", "h".repeat(65)),
            &format!("scout::{}.postal.bot", "l".repeat(64)),
        ] {
            assert!(Address::parse(s).is_err(), "{s:?}");
        }
        assert!(serde_json::from_str::<Address>("\"Scout::acme.postal.bot\"").is_err());
    }
}
