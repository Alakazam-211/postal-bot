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

/// Parse lowercase hex of any even length: only `[0-9a-f]`. Uppercase, a
/// sign, whitespace and an odd length are refused, so a value has one
/// spelling on the wire.
///
/// # Errors
/// [`HexError`] unless the input is even-length lowercase hex.
pub fn from_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(HexError);
    }
    pairs
        .iter()
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Parse exactly 32 bytes of lowercase hex: 64 characters of `[0-9a-f]`,
/// nothing else (the plane refuses the same inputs).
///
/// # Errors
/// [`HexError`] unless the input is exactly 64 lowercase hex characters.
pub fn from_hex32(s: &str) -> Result<[u8; 32], HexError> {
    if s.len() != 64 {
        return Err(HexError);
    }
    from_hex(s)?.try_into().map_err(|_| HexError)
}

fn nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HexError),
    }
}

/// Not lowercase hex of the expected length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexError;

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expected lowercase hex")
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

    #[test]
    fn from_hex_is_as_strict() {
        assert_eq!(from_hex("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
        for bad in ["abc", "AbCd", "+f", "-f", " ab", "ab\n", "é0"] {
            assert_eq!(from_hex(bad), Err(HexError), "{bad:?}");
        }
    }
}
