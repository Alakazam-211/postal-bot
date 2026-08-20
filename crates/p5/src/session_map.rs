//! In-process live session map.
//!
//! Job of K2 `v2_session_map`: is this handle running? Postal types this as
//! `PostalAddr → LiveSession` and never persists it. Do not copy the Kessel
//! PTY map.

use std::collections::HashMap;

use p5_core::PostalAddr;

/// Live attach record. No cwd — that lives on the homes row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession {
    pub session_id: String,
    /// READY to inject. v0 local deliver writes inbox either way.
    #[allow(dead_code)]
    pub ready: bool,
}

/// Process-local map. Dies with the process. Never written under `~/.postal/`.
#[derive(Debug, Clone, Default)]
pub struct SessionMap {
    entries: HashMap<PostalAddr, LiveSession>,
}

impl SessionMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, addr: &PostalAddr) -> Option<&LiveSession> {
        self.entries.get(addr)
    }

    pub fn insert(&mut self, addr: PostalAddr, session: LiveSession) -> Option<LiveSession> {
        self.entries.insert(addr, session)
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, addr: &PostalAddr) -> Option<LiveSession> {
        self.entries.remove(addr)
    }

    #[allow(dead_code)]
    pub fn contains(&self, addr: &PostalAddr) -> bool {
        self.entries.contains_key(addr)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scout() -> PostalAddr {
        "scout::acme.postal.bot".parse().unwrap()
    }

    #[test]
    fn insert_get_remove() {
        let mut map = SessionMap::new();
        assert!(map.is_empty());
        map.insert(
            scout(),
            LiveSession {
                session_id: "sess-1".into(),
                ready: true,
            },
        );
        assert_eq!(map.len(), 1);
        assert!(map.contains(&scout()));
        assert_eq!(map.get(&scout()).unwrap().session_id, "sess-1");
        assert!(map.remove(&scout()).is_some());
        assert!(map.is_empty());
    }
}
