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

/// Parse exactly 32 bytes of lowercase hex: 64 characters of `[0-9a-f]`,
/// nothing else. Uppercase, a sign, whitespace and any other length are
/// refused, so a value has one spelling on the wire (the plane refuses the
/// same inputs).
///
/// # Errors
/// [`HexError`] unless the input is exactly 64 lowercase hex characters.
pub fn from_hex32(s: &str) -> Result<[u8; 32], HexError> {
    fn nibble(c: u8) -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(HexError),
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(HexError);
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
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

    /// One spelling only (K2 re-review low): no uppercase, no sign that
    /// `u8::from_str_radix` would take, no whitespace.
    #[test]
    fn only_lowercase_hex() {
        let ok = "0123456789abcdef".repeat(4);
        assert_eq!(
            from_hex32(&ok).unwrap()[..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        for bad in [
            "AB".repeat(32),
            format!("+f{}", "ab".repeat(31)),
            format!("-f{}", "ab".repeat(31)),
            format!(" {}", "ab".repeat(32)),
            format!("{}\n", "ab".repeat(32)),
            format!(" {} ", &"ab".repeat(32)[..62]),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("é{}", "a".repeat(62)),
        ] {
            assert_eq!(from_hex32(&bad), Err(HexError), "{bad:?}");
        }
    }
}
