//! Standard base64 for hold ciphertext and wire file contents.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Standard base64 (not URL-safe).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard padded base64, canonical only: no whitespace, no
/// missing padding, no stray trailing bits, so a value has one spelling.
///
/// # Errors
/// [`B64Error`] if the input is not standard base64.
pub fn decode(s: &str) -> Result<Vec<u8>, B64Error> {
    STANDARD.decode(s).map_err(|_| B64Error)
}

/// Not standard base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct B64Error;

impl std::fmt::Display for B64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid standard base64")
    }
}

impl std::error::Error for B64Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_spelling() {
        assert_eq!(decode("aGk=").unwrap(), b"hi");
        for bad in [" aGk=", "aGk=\n", "aGk", "aGl=", "aG-=", "aGk==", "aGk_"] {
            assert_eq!(decode(bad), Err(B64Error), "{bad:?}");
        }
    }
}
