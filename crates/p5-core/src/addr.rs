//! Canonical Postal address: `handle::sub.postal.bot`.

use std::fmt;
use std::str::FromStr;

/// Enrolled-server suffix. Live HTTPS always targets `https://<label>.postal.bot`.
const HOST_SUFFIX: &str = ".postal.bot";

/// Canonical Postal address. Display form and map key.
///
/// Example: `scout::acme.postal.bot`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PostalAddr {
    /// Application identity (`scout`). Not a DNS label.
    pub handle: String,
    /// Enrolled server (`acme.postal.bot`).
    pub host: String,
}

impl PostalAddr {
    /// Accepts `handle::host`. Rejects `@`, a bare DNS name as the *address*,
    /// and empty handle / empty host.
    ///
    /// Bare `handle` is allowed only when `default_host` is configured.
    pub fn parse(input: &str, default_host: Option<&str>) -> Result<Self, AddrError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(AddrError::EmptyHandle);
        }
        // K2 retired `@` for federation; Postal keeps `::`.
        if input.contains('@') {
            return Err(AddrError::AtSign);
        }

        let (handle, host) = if let Some((handle, host)) = input.split_once("::") {
            if host.contains("::") {
                return Err(AddrError::InvalidHost);
            }
            (handle, host)
        } else if looks_like_nested_dns(input) {
            return Err(AddrError::NestedDns);
        } else {
            match default_host {
                Some(host) => (input, host),
                None => return Err(AddrError::MissingSeparator),
            }
        };

        let handle = parse_handle(handle)?;
        let host = parse_host(host)?;
        Ok(Self { handle, host })
    }

    pub fn live_base_url(&self) -> String {
        format!("https://{}", self.host)
    }
}

impl fmt::Display for PostalAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.handle, self.host)
    }
}

impl FromStr for PostalAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, None)
    }
}

/// Why an address string is not a Postal address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrError {
    /// `@` is not a Postal separator.
    AtSign,
    /// Nested DNS used as the address, e.g. `scout.acme.postal.bot`.
    NestedDns,
    /// Missing `::` and no default host configured.
    MissingSeparator,
    EmptyHandle,
    EmptyHost,
    /// Handle is not a single application identity token.
    InvalidHandle,
    /// Host is not `{label}.postal.bot` with a non-blank label.
    InvalidHost,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtSign => f.write_str("address uses @; Postal addresses are handle::host"),
            Self::NestedDns => {
                f.write_str("address looks like nested DNS; use handle::sub.postal.bot")
            }
            Self::MissingSeparator => f.write_str("address is missing :: (handle::sub.postal.bot)"),
            Self::EmptyHandle => f.write_str("address has an empty handle"),
            Self::EmptyHost => f.write_str("address has an empty host"),
            Self::InvalidHandle => f.write_str("handle contains invalid characters"),
            Self::InvalidHost => f.write_str("host must be {label}.postal.bot"),
        }
    }
}

impl std::error::Error for AddrError {}

fn looks_like_nested_dns(input: &str) -> bool {
    input.contains('.')
}

fn parse_handle(handle: &str) -> Result<String, AddrError> {
    let handle = handle.trim();
    if handle.is_empty() {
        return Err(AddrError::EmptyHandle);
    }
    if !is_handle(handle) {
        return Err(AddrError::InvalidHandle);
    }
    Ok(handle.to_string())
}

fn is_handle(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_host(host: &str) -> Result<String, AddrError> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(AddrError::EmptyHost);
    }
    let Some(label) = host.strip_suffix(HOST_SUFFIX) else {
        return Err(AddrError::InvalidHost);
    };
    // Blank / apex / extra dots are permanently unroutable (3-label guard).
    if !is_base_label(label) {
        return Err(AddrError::InvalidHost);
    }
    Ok(host)
}

fn is_base_label(label: &str) -> bool {
    if label.len() < 3 || label.len() > 63 || label.contains('.') {
        return false;
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[label.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_good_addr() {
        let addr = PostalAddr::parse("scout::acme.postal.bot", None).unwrap();
        assert_eq!(addr.handle, "scout");
        assert_eq!(addr.host, "acme.postal.bot");
        assert_eq!(addr.to_string(), "scout::acme.postal.bot");
        assert_eq!(addr.live_base_url(), "https://acme.postal.bot");
    }

    #[test]
    fn reject_at_sign() {
        assert_eq!(
            PostalAddr::parse("scout@acme.postal.bot", None).unwrap_err(),
            AddrError::AtSign
        );
        assert_eq!(
            PostalAddr::parse("scout::acme@postal.bot", None).unwrap_err(),
            AddrError::AtSign
        );
    }

    #[test]
    fn reject_missing_separator() {
        assert_eq!(
            PostalAddr::parse("scout", None).unwrap_err(),
            AddrError::MissingSeparator
        );
    }

    #[test]
    fn reject_empty_handle() {
        assert_eq!(
            PostalAddr::parse("::acme.postal.bot", None).unwrap_err(),
            AddrError::EmptyHandle
        );
        assert_eq!(
            PostalAddr::parse("  ::acme.postal.bot", None).unwrap_err(),
            AddrError::EmptyHandle
        );
    }

    #[test]
    fn reject_nested_dns_as_address() {
        assert_eq!(
            PostalAddr::parse("scout.acme.postal.bot", None).unwrap_err(),
            AddrError::NestedDns
        );
        // Still not a handle, even if a default host is set.
        assert_eq!(
            PostalAddr::parse("scout.acme.postal.bot", Some("acme.postal.bot")).unwrap_err(),
            AddrError::NestedDns
        );
    }

    #[test]
    fn bare_handle_uses_default_host() {
        let addr = PostalAddr::parse("scout", Some("acme.postal.bot")).unwrap();
        assert_eq!(addr.to_string(), "scout::acme.postal.bot");
    }

    #[test]
    fn reject_blank_and_apex_host() {
        assert_eq!(
            PostalAddr::parse("scout::", None).unwrap_err(),
            AddrError::EmptyHost
        );
        assert_eq!(
            PostalAddr::parse("scout::.postal.bot", None).unwrap_err(),
            AddrError::InvalidHost
        );
        assert_eq!(
            PostalAddr::parse("scout::postal.bot", None).unwrap_err(),
            AddrError::InvalidHost
        );
        assert_eq!(
            PostalAddr::parse("scout::foo.acme.postal.bot", None).unwrap_err(),
            AddrError::InvalidHost
        );
    }

    #[test]
    fn from_str_matches_parse() {
        let addr: PostalAddr = "scout::acme.postal.bot".parse().unwrap();
        assert_eq!(addr.handle, "scout");
        assert!("scout".parse::<PostalAddr>().is_err());
    }
}
