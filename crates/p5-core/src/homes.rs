//! Durable wake table (`~/.postal/homes.json`).
//!
//! Session-only. No peer `typ` (K22). The live session map is not stored here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::{load_json, save_json, StoreError, HOMES_FILE};
use crate::{PostalAddr, ToolFlags};

/// One local session home. Wake uses `cwd` + `launch` + `session_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeRow {
    pub address: PostalAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub launch: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default)]
    pub tools: ToolFlags,
    pub enrolled_host: String,
}

impl HomeRow {
    /// `enrolled_host` is the denormalized `::` host; it must equal `address.host()`.
    pub fn check_enrolled_host(&self) -> Result<(), StoreError> {
        if self.enrolled_host != self.address.host() {
            return Err(StoreError::HostMismatch {
                address: self.address.clone(),
                enrolled_host: self.enrolled_host.clone(),
            });
        }
        Ok(())
    }
}

/// Durable homes table. JSON array on disk, keyed in memory by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Homes {
    rows: BTreeMap<PostalAddr, HomeRow>,
}

impl Homes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn get(&self, addr: &PostalAddr) -> Option<&HomeRow> {
        self.rows.get(addr)
    }

    /// Insert or replace the row for `row.address`.
    pub fn insert(&mut self, row: HomeRow) -> Result<Option<HomeRow>, StoreError> {
        row.check_enrolled_host()?;
        Ok(self.rows.insert(row.address.clone(), row))
    }

    pub fn remove(&mut self, addr: &PostalAddr) -> Option<HomeRow> {
        self.rows.remove(addr)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PostalAddr, &HomeRow)> {
        self.rows.iter()
    }

    /// Missing file is an empty table (v0 first write).
    pub fn load(root: &Path) -> Result<Self, StoreError> {
        let rows: Vec<HomeRow> = load_json(root, HOMES_FILE)?;
        let mut map = BTreeMap::new();
        for row in rows {
            row.check_enrolled_host()?;
            let addr = row.address.clone();
            if map.insert(addr.clone(), row).is_some() {
                return Err(StoreError::DuplicateHome(addr));
            }
        }
        Ok(Self { rows: map })
    }

    pub fn save(&self, root: &Path) -> Result<(), StoreError> {
        let rows: Vec<&HomeRow> = self.rows.values().collect();
        for row in &rows {
            row.check_enrolled_host()?;
        }
        save_json(root, HOMES_FILE, &rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn addr(s: &str) -> PostalAddr {
        PostalAddr::parse(s, None).unwrap()
    }

    fn sample_row() -> HomeRow {
        HomeRow {
            address: addr("scout::acme.postal.bot"),
            session_id: Some("sess-1".into()),
            cwd: PathBuf::from("/srv/scout"),
            inbox_root: None,
            launch: vec!["claude".into(), "--resume".into()],
            harness: Some("claude".into()),
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake: true,
            },
            enrolled_host: "acme.postal.bot".into(),
        }
    }

    #[test]
    fn homes_roundtrip_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut homes = Homes::new();
        let row = sample_row();
        let key = row.address.clone();
        homes.insert(row.clone()).unwrap();
        homes.save(dir.path()).unwrap();
        assert!(dir.path().join(HOMES_FILE).is_file());
        let loaded = Homes::load(dir.path()).unwrap();
        assert_eq!(loaded.get(&key), Some(&row));
        assert_eq!(loaded.get(&key).unwrap().enrolled_host, key.host());
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn load_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let homes = Homes::load(dir.path()).unwrap();
        assert!(homes.is_empty());
    }

    #[test]
    fn homes_json_has_no_peer_typ() {
        let dir = tempfile::tempdir().unwrap();
        let mut homes = Homes::new();
        homes.insert(sample_row()).unwrap();
        homes.save(dir.path()).unwrap();
        let raw = fs::read_to_string(dir.path().join(HOMES_FILE)).unwrap();
        assert!(!raw.contains("\"typ\""));
        assert!(raw.contains("\"address\""));
        assert!(raw.contains("\"session_id\""));
        assert!(raw.contains("\"cwd\""));
        assert!(raw.contains("\"launch\""));
        assert!(raw.contains("\"harness\""));
        assert!(raw.contains("\"tools\""));
        assert!(raw.contains("\"enrolled_host\""));
        assert!(raw.contains("\"live_inject\""));
        assert!(raw.contains("\"wake\""));
    }

    #[test]
    fn files_defaults_false() {
        assert!(!ToolFlags::default().files);
        let flags: ToolFlags = serde_json::from_str("{}").unwrap();
        assert!(!flags.files);
        assert!(!flags.live_inject);
        assert!(!flags.wake);
    }

    #[test]
    fn duplicate_address_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"
        [
          {
            "address": "scout::acme.postal.bot",
            "cwd": "/srv/scout",
            "enrolled_host": "acme.postal.bot"
          },
          {
            "address": "scout::acme.postal.bot",
            "cwd": "/other",
            "enrolled_host": "acme.postal.bot"
          }
        ]
        "#;
        fs::write(dir.path().join(HOMES_FILE), json).unwrap();
        match Homes::load(dir.path()) {
            Err(StoreError::DuplicateHome(a)) => {
                assert_eq!(a, addr("scout::acme.postal.bot"));
            }
            other => panic!("expected DuplicateHome, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_dir_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dot-postal");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Homes::new().save(&root).unwrap();
        let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn persist_does_not_write_session_map() {
        let dir = tempfile::tempdir().unwrap();
        Homes::new().save(dir.path()).unwrap();
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec![HOMES_FILE]);
    }

    #[test]
    fn enrolled_host_must_match_address_host() {
        let mut row = sample_row();
        row.enrolled_host = "evil.postal.bot".into();
        let mut homes = Homes::new();
        match homes.insert(row.clone()) {
            Err(StoreError::HostMismatch {
                address,
                enrolled_host,
            }) => {
                assert_eq!(address, row.address);
                assert_eq!(enrolled_host, "evil.postal.bot");
            }
            other => panic!("expected HostMismatch, got {other:?}"),
        }

        let dir = tempfile::tempdir().unwrap();
        let json = r#"
        [
          {
            "address": "scout::acme.postal.bot",
            "cwd": "/srv/scout",
            "enrolled_host": "evil.postal.bot"
          }
        ]
        "#;
        fs::write(dir.path().join(HOMES_FILE), json).unwrap();
        match Homes::load(dir.path()) {
            Err(StoreError::HostMismatch {
                address,
                enrolled_host,
            }) => {
                assert_eq!(address, addr("scout::acme.postal.bot"));
                assert_eq!(enrolled_host, "evil.postal.bot");
            }
            other => panic!("expected HostMismatch, got {other:?}"),
        }
    }

    #[test]
    fn load_invalid_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(HOMES_FILE), "not-json").unwrap();
        assert!(matches!(Homes::load(dir.path()), Err(StoreError::Json(_))));
    }
}
