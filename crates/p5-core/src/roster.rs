//! Local copy of paired peers (`~/.postal/roster.json`).
//!
//! `typ` is peer-declared (K22), copied from the pair record.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::store::{load_json, save_json, StoreError, ROSTER_FILE};
use crate::{PeerType, PostalAddr, ToolFlags};

/// Directed pair status (K21). Mail is allowed only when `trusted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    None,
    Pending,
    Trusted,
    Rejected,
    Revoked,
    Blocked,
}

impl Trust {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Trusted => "trusted",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Blocked => "blocked",
        }
    }

    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// Map a plane pair-dir string. Unknown values stay off the roster.
    pub fn from_pair_status(s: &str) -> Option<Self> {
        match s.trim() {
            "none" => Some(Self::None),
            "pending" => Some(Self::Pending),
            "trusted" => Some(Self::Trusted),
            "rejected" => Some(Self::Rejected),
            "revoked" => Some(Self::Revoked),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }
}

impl fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One peer on the local roster. `typ` is not guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub typ: PeerType,
    pub fingerprint: String,
    pub public_key_pem: String,
    pub trust: Trust,
    pub pair_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sand_uuid: Option<String>,
    #[serde(default)]
    pub tools: ToolFlags,
}

/// Address → peer record. JSON object on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    entries: BTreeMap<PostalAddr, RosterEntry>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, addr: &PostalAddr) -> Option<&RosterEntry> {
        self.entries.get(addr)
    }

    pub fn insert(&mut self, addr: PostalAddr, entry: RosterEntry) -> Option<RosterEntry> {
        self.entries.insert(addr, entry)
    }

    /// Merge a plane-observed peer. Empty pem/fp leave whatever was already stored.
    ///
    /// New rows need a declared `typ` (K22 — do not guess session/turn).
    pub fn merge_peer(
        &mut self,
        addr: PostalAddr,
        typ: Option<PeerType>,
        fingerprint: Option<String>,
        public_key_pem: Option<String>,
        trust: Trust,
        pair_id: String,
    ) -> bool {
        let existing = self.entries.get(&addr).cloned();
        let typ = match typ.or_else(|| existing.as_ref().map(|e| e.typ)) {
            Some(t) => t,
            None => return false,
        };
        let mut entry = existing.unwrap_or(RosterEntry {
            typ,
            fingerprint: String::new(),
            public_key_pem: String::new(),
            trust,
            pair_id: pair_id.clone(),
            sand_uuid: None,
            tools: ToolFlags::default(),
        });
        entry.typ = typ;
        entry.trust = trust;
        entry.pair_id = pair_id;
        if let Some(fp) = fingerprint.filter(|s| !s.is_empty()) {
            entry.fingerprint = fp;
        }
        if let Some(pem) = public_key_pem.filter(|s| !s.is_empty()) {
            entry.public_key_pem = pem;
        }
        self.entries.insert(addr, entry);
        true
    }

    pub fn remove(&mut self, addr: &PostalAddr) -> Option<RosterEntry> {
        self.entries.remove(addr)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PostalAddr, &RosterEntry)> {
        self.entries.iter()
    }

    /// Missing file is an empty roster (v0 first write).
    pub fn load(root: &Path) -> Result<Self, StoreError> {
        // String keys first: PostalAddr parse lowercases, so mixed-case aliases
        // would otherwise last-win in a BTreeMap<PostalAddr, _>.
        let raw: BTreeMap<String, RosterEntry> = load_json(root, ROSTER_FILE)?;
        let mut entries = BTreeMap::new();
        for (key, entry) in raw {
            let addr = PostalAddr::parse(&key, None)?;
            if entries.insert(addr.clone(), entry).is_some() {
                return Err(StoreError::DuplicateRoster(addr));
            }
        }
        Ok(Self { entries })
    }

    pub fn save(&self, root: &Path) -> Result<(), StoreError> {
        save_json(root, ROSTER_FILE, &self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn addr(s: &str) -> PostalAddr {
        PostalAddr::parse(s, None).unwrap()
    }

    fn sample_entry() -> RosterEntry {
        RosterEntry {
            typ: PeerType::Session,
            fingerprint: "fp-scout".into(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n".into(),
            trust: Trust::Trusted,
            pair_id: "pair-1".into(),
            sand_uuid: None,
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake: true,
            },
        }
    }

    #[test]
    fn roster_roundtrip_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut roster = Roster::new();
        let key = addr("scout::acme.postal.bot");
        roster.insert(key.clone(), sample_entry());
        roster.save(dir.path()).unwrap();
        assert!(dir.path().join(ROSTER_FILE).is_file());
        let loaded = Roster::load(dir.path()).unwrap();
        assert_eq!(loaded.get(&key), Some(&sample_entry()));
        assert_eq!(loaded.get(&key).unwrap().typ, PeerType::Session);
        assert!(loaded.get(&key).unwrap().trust.is_trusted());
    }

    #[test]
    fn load_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let roster = Roster::load(dir.path()).unwrap();
        assert!(roster.is_empty());
    }

    #[test]
    fn roster_json_is_addr_map_with_peer_typ() {
        let dir = tempfile::tempdir().unwrap();
        let mut roster = Roster::new();
        roster.insert(addr("scout::acme.postal.bot"), sample_entry());
        roster.save(dir.path()).unwrap();
        let raw = fs::read_to_string(dir.path().join(ROSTER_FILE)).unwrap();
        assert!(raw.contains("\"scout::acme.postal.bot\""));
        assert!(raw.contains("\"typ\""));
        assert!(raw.contains("\"session\""));
        assert!(raw.contains("\"fingerprint\""));
        assert!(raw.contains("\"public_key_pem\""));
        assert!(raw.contains("\"trust\""));
        assert!(raw.contains("\"trusted\""));
        assert!(raw.contains("\"pair_id\""));
        assert!(raw.contains("\"tools\""));
        assert!(!raw.contains("sand_uuid"));
    }

    #[test]
    fn sand_uuid_roundtrips_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut entry = sample_entry();
        entry.typ = PeerType::Turn;
        entry.sand_uuid = Some("sand-uuid-1".into());
        let mut roster = Roster::new();
        let key = addr("jarvis::acme.postal.bot");
        roster.insert(key.clone(), entry.clone());
        roster.save(dir.path()).unwrap();
        let loaded = Roster::load(dir.path()).unwrap();
        assert_eq!(loaded.get(&key), Some(&entry));
    }

    #[test]
    fn roster_rejects_missing_typ() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{
            "scout::acme.postal.bot": {
                "fingerprint": "fp",
                "public_key_pem": "pem",
                "trust": "trusted",
                "pair_id": "p1",
                "tools": {}
            }
        }"#;
        fs::write(dir.path().join(ROSTER_FILE), json).unwrap();
        assert!(matches!(Roster::load(dir.path()), Err(StoreError::Json(_))));
    }

    #[test]
    fn roster_rejects_invalid_addr_key() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{
            "scout@acme.postal.bot": {
                "typ": "session",
                "fingerprint": "fp",
                "public_key_pem": "pem",
                "trust": "trusted",
                "pair_id": "p1"
            }
        }"#;
        fs::write(dir.path().join(ROSTER_FILE), json).unwrap();
        assert!(matches!(Roster::load(dir.path()), Err(StoreError::Addr(_))));
    }

    #[test]
    fn roster_rejects_canonical_duplicate_keys() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{
            "Scout::acme.postal.bot": {
                "typ": "session",
                "fingerprint": "fp-mixed",
                "public_key_pem": "pem",
                "trust": "pending",
                "pair_id": "p1"
            },
            "scout::acme.postal.bot": {
                "typ": "turn",
                "fingerprint": "fp-lower",
                "public_key_pem": "pem",
                "trust": "trusted",
                "pair_id": "p2"
            }
        }"#;
        fs::write(dir.path().join(ROSTER_FILE), json).unwrap();
        match Roster::load(dir.path()) {
            Err(StoreError::DuplicateRoster(a)) => {
                assert_eq!(a, addr("scout::acme.postal.bot"));
            }
            other => panic!("expected DuplicateRoster, got {other:?}"),
        }
    }

    #[test]
    fn trust_serde_is_snake_case() {
        for (trust, wire) in [
            (Trust::None, "none"),
            (Trust::Pending, "pending"),
            (Trust::Trusted, "trusted"),
            (Trust::Rejected, "rejected"),
            (Trust::Revoked, "revoked"),
            (Trust::Blocked, "blocked"),
        ] {
            let s = serde_json::to_string(&trust).unwrap();
            assert_eq!(s, format!("\"{wire}\""));
            let back: Trust = serde_json::from_str(&s).unwrap();
            assert_eq!(back, trust);
            assert_eq!(trust.as_str(), wire);
        }
        assert!(!Trust::Pending.is_trusted());
        assert_eq!(Trust::from_pair_status("trusted"), Some(Trust::Trusted));
        assert_eq!(Trust::from_pair_status("pending"), Some(Trust::Pending));
        assert_eq!(Trust::from_pair_status("nope"), None);
    }

    #[test]
    fn merge_peer_does_not_guess_typ() {
        let mut roster = Roster::new();
        let key = addr("scout::acme.postal.bot");
        assert!(!roster.merge_peer(
            key.clone(),
            None,
            Some("fp".into()),
            Some("pem".into()),
            Trust::Pending,
            "p1".into(),
        ));
        assert!(roster.is_empty());
        assert!(roster.merge_peer(
            key.clone(),
            Some(PeerType::Turn),
            Some("fp".into()),
            Some("pem".into()),
            Trust::Pending,
            "p1".into(),
        ));
        assert!(roster.merge_peer(key.clone(), None, None, None, Trust::Trusted, "p1".into(),));
        let e = roster.get(&key).unwrap();
        assert_eq!(e.typ, PeerType::Turn);
        assert_eq!(e.trust, Trust::Trusted);
        assert_eq!(e.fingerprint, "fp");
        assert_eq!(e.public_key_pem, "pem");
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_dir_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dot-postal");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Roster::new().save(&root).unwrap();
        let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn persist_does_not_write_session_map() {
        let dir = tempfile::tempdir().unwrap();
        Roster::new().save(dir.path()).unwrap();
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec![ROSTER_FILE]);
    }
}
