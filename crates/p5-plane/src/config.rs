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
    #[serde(default, skip_serializing_if = "BillingFile::is_empty")]
    pub billing: BillingFile,
}

/// Local paid-plan entitlement + meter start.
///
/// Plane `GET /postal/usage` is source of truth when it exists. This file
/// holds a Stripe Checkout redeem and the local free-tier epoch so mail
/// from before billing shipped does not eat the 100/month cap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingFile {
    /// `free` or `unlimited`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Enrolled host the entitlement applies to (`label.postal.bot`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Unix seconds; subscription current period end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix: Option<u64>,
    /// Stripe Checkout session id (`cs_…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Unix seconds; sent rows created before this do not count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter_from_unix: Option<u64>,
}

impl BillingFile {
    pub fn is_empty(&self) -> bool {
        self.plan.is_none()
            && self.host.is_none()
            && self.until_unix.is_none()
            && self.session.is_none()
            && self.meter_from_unix.is_none()
    }

    pub fn is_unlimited_now(&self, now_unix: u64) -> bool {
        let plan = self.plan.as_deref().map(str::trim).unwrap_or("free");
        if !plan.eq_ignore_ascii_case("unlimited") {
            return false;
        }
        match self.until_unix {
            None => true,
            Some(until) => until > now_unix,
        }
    }
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
            billing: BillingFile::default(),
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

    #[test]
    fn billing_roundtrip_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let f = PostalFile {
            billing: BillingFile {
                plan: Some("unlimited".into()),
                host: Some("acme.postal.bot".into()),
                until_unix: Some(1_800_000_000),
                session: Some("cs_test".into()),
                meter_from_unix: Some(1_787_248_800),
            },
            ..Default::default()
        };
        f.save(dir.path()).unwrap();
        let loaded = PostalFile::load(dir.path()).unwrap();
        assert_eq!(loaded, f);
        assert!(loaded.billing.is_unlimited_now(1_787_248_800));
        assert!(!loaded.billing.is_unlimited_now(1_900_000_000));
    }
}
