use std::fmt;
use std::io;

/// Fail-closed plane / config error.
#[derive(Debug)]
pub enum PlaneError {
    Io(io::Error),
    Json(serde_json::Error),
    Toml(String),
    /// No `connect_token` / `P5_CONNECT_TOKEN`.
    NoToken,
    Unauthorized,
    Forbidden(String),
    NotFound,
    Http {
        status: u16,
        message: String,
    },
    Transport(String),
    /// Wire lock: never PUT/POST a private PEM.
    PrivateKey,
    /// Pair id is interpolated into the URL path.
    BadPairId,
    /// Hold id is interpolated into the URL path.
    BadHoldId,
    /// Wire lock: never PUT plaintext; hold store is ciphertext only.
    Plaintext,
    Crypto(String),
    /// RFC 8628: human has not approved the device code yet. Poll again.
    AuthorizationPending,
    /// RFC 8628: increase poll interval.
    SlowDown,
    /// RFC 8628: user denied the device.
    AccessDenied,
    /// RFC 8628: device/user code expired.
    ExpiredToken,
}

impl PlaneError {
    pub fn exit_code(&self) -> i32 {
        1
    }
}

impl fmt::Display for PlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "postal plane io: {e}"),
            Self::Json(e) => write!(f, "postal plane json: {e}"),
            Self::Toml(msg) => write!(f, "postal config: {msg}"),
            Self::NoToken => {
                f.write_str("no connect token; run p5 login or pass --token")
            }
            Self::Unauthorized => f.write_str("plane: unauthorized"),
            Self::Forbidden(msg) => write!(f, "plane: {msg}"),
            Self::NotFound => f.write_str("plane: not found"),
            Self::Http { status, message } => write!(f, "plane {status}: {message}"),
            Self::Transport(msg) => write!(f, "plane transport: {msg}"),
            Self::PrivateKey => f.write_str("refusing to upload a private key"),
            Self::BadPairId => f.write_str("pair id contains invalid characters"),
            Self::BadHoldId => f.write_str("hold id contains invalid characters"),
            Self::Plaintext => f.write_str("refusing to upload plaintext hold body"),
            Self::Crypto(msg) => write!(f, "postal hold crypto: {msg}"),
            Self::AuthorizationPending => f.write_str("authorization_pending"),
            Self::SlowDown => f.write_str("slow_down"),
            Self::AccessDenied => f.write_str("device login denied"),
            Self::ExpiredToken => f.write_str("device code expired; run p5 login again"),
        }
    }
}

impl std::error::Error for PlaneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PlaneError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for PlaneError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
