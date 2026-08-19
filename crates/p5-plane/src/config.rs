use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{PlaneError, DEFAULT_PLANE_URL};

pub const CONFIG_FILE: &str = "config.toml";

/// On-disk `~/.postal/config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostalFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
}

impl PostalFile {
    pub fn load(root: &Path) -> Result<Self, PlaneError> {
        let path = root.join(CONFIG_FILE);
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        toml::from_str(&raw).map_err(|e| PlaneError::Toml(e.to_string()))
    }

    pub fn save(&self, root: &Path) -> Result<(), PlaneError> {
        p5_core::ensure_dir(root)?;
        let path = root.join(CONFIG_FILE);
        let data = toml::to_string_pretty(self).map_err(|e| PlaneError::Toml(e.to_string()))?;
        fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// Resolved plane settings. Env wins over the file.
#[derive(Debug, Clone)]
pub struct PlaneConfig {
    pub base_url: String,
    pub token: Option<String>,
    pub addr: Option<String>,
    pub typ: Option<String>,
    pub file: PostalFile,
}

impl PlaneConfig {
    pub fn load(root: &Path) -> Result<Self, PlaneError> {
        let file = PostalFile::load(root)?;
        let base_url =
            env_nonempty("P5_PLANE_URL").unwrap_or_else(|| DEFAULT_PLANE_URL.to_string());
        let token = env_nonempty("P5_CONNECT_TOKEN").or_else(|| file.connect_token.clone());
        let addr = env_nonempty("P5_FROM").or_else(|| file.addr.clone());
        let typ = env_nonempty("P5_TYP").or_else(|| file.typ.clone());
        Ok(Self {
            base_url,
            token,
            addr,
            typ,
            file,
        })
    }

    pub fn require_token(&self) -> Result<&str, PlaneError> {
        match self
            .token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(t) => Ok(t),
            None => Err(PlaneError::NoToken),
        }
    }
}

pub(crate) fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = PostalFile::load(dir.path()).unwrap();
        assert_eq!(f, PostalFile::default());
    }

    #[test]
    fn token_roundtrip_unix_0600() {
        let dir = tempfile::tempdir().unwrap();
        let f = PostalFile {
            connect_token: Some("k2c_test".into()),
            addr: Some("alice::acme.postal.bot".into()),
            typ: Some("session".into()),
        };
        f.save(dir.path()).unwrap();
        let loaded = PostalFile::load(dir.path()).unwrap();
        assert_eq!(loaded, f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(CONFIG_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
