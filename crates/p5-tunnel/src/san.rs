//! CSR SAN policy for Postal v0.
//!
//! One name: `{label}.postal.bot`. Nested wildcards and k2.dev names are
//! refused here so a caller cannot copy K2's `{sub}.k2.dev` + `*.{sub}.k2.dev`
//! pair into a Postal CSR.

use std::fmt;

/// Enrolled-server suffix. Live HTTPS is `https://{label}.postal.bot`.
pub const HOST_SUFFIX: &str = ".postal.bot";

/// Why a SAN list is not a Postal v0 cert name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanError {
    Empty,
    EmptyLabel,
    InvalidLabel,
    /// `*.{label}.postal.bot` (K2's nested Pro wildcard) is v0-out.
    Wildcard,
    /// Extra labels, e.g. `foo.acme.postal.bot`.
    Nested,
    /// Anything not `{label}.postal.bot` (including k2.dev).
    ForeignZone,
    ExtraNames,
}

impl fmt::Display for SanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("CSR SAN list is empty"),
            Self::EmptyLabel => f.write_str("tunnel label is empty"),
            Self::InvalidLabel => f.write_str("tunnel label is not a postal.bot base label"),
            Self::Wildcard => {
                f.write_str("wildcard SAN is not allowed; Postal CSR is {label}.postal.bot only")
            }
            Self::Nested => {
                f.write_str("nested SAN is not allowed; Postal CSR is {label}.postal.bot only")
            }
            Self::ForeignZone => f.write_str("SAN must be {label}.postal.bot (no k2.dev)"),
            Self::ExtraNames => f.write_str("Postal CSR allows exactly one SAN"),
        }
    }
}

impl std::error::Error for SanError {}

/// `{label}.postal.bot` for a valid base label.
pub fn hostname_for_label(label: &str) -> Result<String, SanError> {
    let label = normalize_label(label)?;
    Ok(format!("{label}{HOST_SUFFIX}"))
}

/// The single SAN Postal will put on a CSR.
pub fn sans_for_label(label: &str) -> Result<Vec<String>, SanError> {
    Ok(vec![hostname_for_label(label)?])
}

/// Pull the base label off `{label}.postal.bot`.
pub fn label_from_host(host: &str) -> Result<String, SanError> {
    let host = host.trim().to_ascii_lowercase();
    if host.contains('*') {
        return Err(SanError::Wildcard);
    }
    if host.contains("k2.dev") {
        return Err(SanError::ForeignZone);
    }
    let Some(label) = host.strip_suffix(HOST_SUFFIX) else {
        return Err(SanError::ForeignZone);
    };
    if label.contains('.') {
        return Err(SanError::Nested);
    }
    normalize_label(label)
}

/// Accept `{label}.postal.bot` alone. Refuse wildcards, extra names, k2.dev.
pub fn check_sans(sans: &[String]) -> Result<String, SanError> {
    if sans.is_empty() {
        return Err(SanError::Empty);
    }
    for s in sans {
        let n = s.trim().to_ascii_lowercase();
        if n.contains("k2.dev") {
            return Err(SanError::ForeignZone);
        }
        if n.contains('*') {
            return Err(SanError::Wildcard);
        }
    }
    if sans.len() != 1 {
        return Err(SanError::ExtraNames);
    }
    let host = sans[0].trim().to_ascii_lowercase();
    let label = label_from_host(&host)?;
    hostname_for_label(&label)
}

pub(crate) fn normalize_label(label: &str) -> Result<String, SanError> {
    let label = label.trim().to_ascii_lowercase();
    if label.is_empty() {
        return Err(SanError::EmptyLabel);
    }
    if !is_base_label(&label) {
        return Err(SanError::InvalidLabel);
    }
    Ok(label)
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
    fn accept_base_only() {
        assert_eq!(sans_for_label("acme").unwrap(), vec!["acme.postal.bot"]);
        assert_eq!(
            check_sans(&["acme.postal.bot".into()]).unwrap(),
            "acme.postal.bot"
        );
        assert_eq!(
            check_sans(&["ACME.POSTAL.BOT".into()]).unwrap(),
            "acme.postal.bot"
        );
        assert_eq!(hostname_for_label("Www").unwrap(), "www.postal.bot");
    }

    #[test]
    fn refuse_nested_wildcard() {
        assert_eq!(
            check_sans(&["*.acme.postal.bot".into()]).unwrap_err(),
            SanError::Wildcard
        );
        assert_eq!(
            check_sans(&["acme.postal.bot".into(), "*.acme.postal.bot".into()]).unwrap_err(),
            SanError::Wildcard
        );
        assert!(!sans_for_label("acme")
            .unwrap()
            .iter()
            .any(|s| s.contains('*')));
        assert_eq!(
            check_sans(&["foo.acme.postal.bot".into()]).unwrap_err(),
            SanError::Nested
        );
    }

    #[test]
    fn refuse_k2_dev_mix() {
        assert_eq!(
            check_sans(&["acme.k2.dev".into()]).unwrap_err(),
            SanError::ForeignZone
        );
        assert_eq!(
            check_sans(&["acme.postal.bot".into(), "acme.k2.dev".into()]).unwrap_err(),
            SanError::ForeignZone
        );
        assert_eq!(
            check_sans(&["acme.postal.bot".into(), "*.acme.k2.dev".into()]).unwrap_err(),
            SanError::ForeignZone
        );
        assert_eq!(
            label_from_host("acme.k2.dev").unwrap_err(),
            SanError::ForeignZone
        );
    }

    #[test]
    fn refuse_empty_and_apex() {
        assert_eq!(check_sans(&[]).unwrap_err(), SanError::Empty);
        assert_eq!(hostname_for_label("").unwrap_err(), SanError::EmptyLabel);
        assert_eq!(
            check_sans(&["postal.bot".into()]).unwrap_err(),
            SanError::ForeignZone
        );
        assert_eq!(
            check_sans(&[".postal.bot".into()]).unwrap_err(),
            SanError::EmptyLabel
        );
        assert_eq!(
            hostname_for_label("ab").unwrap_err(),
            SanError::InvalidLabel
        );
    }

    #[test]
    fn extra_postal_name_is_refused() {
        assert_eq!(
            check_sans(&["acme.postal.bot".into(), "other.postal.bot".into()]).unwrap_err(),
            SanError::ExtraNames
        );
    }
}
