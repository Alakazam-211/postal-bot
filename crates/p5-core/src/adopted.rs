//! Handles another host has adopted (S7). p5 stands down for them: no live
//! receive, no hold pull or ACK, no knock, no send, no pair changes.
//!
//! One file, `adopted.json`, separate from `homes.json` so a re-claim can't
//! wipe the state. A missing file means nothing is adopted.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::addr::PostalAddr;
use crate::store::{load_json, save_json, StoreError};

pub const ADOPTED_FILE: &str = "adopted.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandDown {
    /// Who took the handle over (`k2`).
    pub by: String,
    /// Unix seconds.
    pub since: i64,
    /// Set when the box key went out with `export-key`. After that,
    /// `resume` refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_exported_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyReleased {
    /// SHA-256 of the SPKI DER, hex, as confirmed by the adopter.
    pub fingerprint: String,
    pub at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adopted {
    #[serde(default)]
    pub handles: BTreeMap<String, StandDown>,
    /// p5 deleted its copy of the box key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_released: Option<KeyReleased>,
}

impl Adopted {
    /// Missing file is an empty table.
    pub fn load(root: &Path) -> Result<Self, StoreError> {
        load_json(root, ADOPTED_FILE)
    }

    pub fn save(&self, root: &Path) -> Result<(), StoreError> {
        save_json(root, ADOPTED_FILE, self)
    }

    pub fn get(&self, addr: &PostalAddr) -> Option<&StandDown> {
        self.handles.get(&addr.to_string())
    }

    pub fn is_stood_down(&self, addr: &PostalAddr) -> bool {
        self.get(addr).is_some()
    }

    /// Fail closed: an unreadable file stands every handle down, since the
    /// adopter may already be receiving for them.
    pub fn stood_down(root: &Path, addr: &PostalAddr) -> bool {
        match Self::load(root) {
            Ok(a) => a.is_stood_down(addr),
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> PostalAddr {
        PostalAddr::parse(s, None).unwrap()
    }

    #[test]
    fn missing_file_is_empty_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let a = Adopted::load(dir.path()).unwrap();
        assert!(a.handles.is_empty());
        let mut a = a;
        a.handles.insert(
            "scout::acme.postal.bot".into(),
            StandDown {
                by: "k2".into(),
                since: 1,
                key_exported_at: None,
            },
        );
        a.save(dir.path()).unwrap();
        let b = Adopted::load(dir.path()).unwrap();
        assert_eq!(a, b);
        assert!(Adopted::stood_down(
            dir.path(),
            &addr("scout::acme.postal.bot")
        ));
        assert!(!Adopted::stood_down(
            dir.path(),
            &addr("other::acme.postal.bot")
        ));
    }

    #[test]
    fn unreadable_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ADOPTED_FILE), b"{not json").unwrap();
        assert!(Adopted::stood_down(
            dir.path(),
            &addr("scout::acme.postal.bot")
        ));
    }
}
