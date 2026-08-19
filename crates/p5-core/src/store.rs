//! On-disk Postal state under `~/.postal` (0700). JSON, not sqlite.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::PostalAddr;

pub const HOMES_FILE: &str = "homes.json";
pub const ROSTER_FILE: &str = "roster.json";

/// `~/.postal`. Callers that persist pass an explicit root so tests can use a temp dir.
pub fn postal_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".postal")
}

/// Create `root` if needed and set mode 0700 (pairing-adjacent state).
pub fn ensure_dir(root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Load/save failure for homes and roster JSON.
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Json(serde_json::Error),
    DuplicateHome(PostalAddr),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "postal store io: {e}"),
            Self::Json(e) => write!(f, "postal store json: {e}"),
            Self::DuplicateHome(addr) => write!(f, "duplicate homes row for {addr}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::DuplicateHome(_) => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub(crate) fn load_json<T>(root: &Path, name: &str) -> Result<T, StoreError>
where
    T: DeserializeOwned + Default,
{
    let path = root.join(name);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn save_json<T: Serialize>(
    root: &Path,
    name: &str,
    value: &T,
) -> Result<(), StoreError> {
    ensure_dir(root)?;
    let path = root.join(name);
    // Rename over the live file so a crash does not leave truncated JSON.
    let tmp = root.join(format!(".{name}.tmp"));
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    fs::write(&tmp, &data)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}
