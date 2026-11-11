//! Lowercase hex for nonces, commitments and digests on the wire.

/// Lowercase hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse exactly 32 bytes of hex.
///
/// # Errors
/// [`HexError`] unless the input is exactly 64 hex characters.
pub fn from_hex32(s: &str) -> Result<[u8; 32], HexError> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return Err(HexError);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| HexError)?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| HexError)?;
    }
    Ok(out)
}

/// Not 64 hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexError;

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expected 64 hex characters")
    }
}

impl std::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_input() {
        assert!(from_hex32("zz").is_err());
        assert!(from_hex32(&"g".repeat(64)).is_err());
        assert_eq!(from_hex32(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }
}
