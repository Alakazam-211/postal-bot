use std::fmt;
use std::io;

/// Fail-closed crypto / key-store error.
#[derive(Debug)]
pub enum CryptoError {
    Io(io::Error),
    Key(String),
    TooLarge,
    Seal(String),
    Open,
    Proof,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "postal crypto io: {e}"),
            Self::Key(msg) => write!(f, "postal key: {msg}"),
            Self::TooLarge => write!(f, "plaintext exceeds 256 KiB"),
            Self::Seal(msg) => write!(f, "hold seal: {msg}"),
            Self::Open => write!(f, "hold open failed"),
            Self::Proof => write!(f, "msg proof failed"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Key(_) | Self::TooLarge | Self::Seal(_) | Self::Open | Self::Proof => None,
        }
    }
}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
