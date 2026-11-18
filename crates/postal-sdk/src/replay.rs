//! Replay protection (F6): a time window plus a durable seen-id list.
//!
//! A message is accepted once per `(from, id)`. The window bounds how long an
//! id must be remembered: anything older than the window is refused on time
//! alone, so the host may forget an entry once [`SeenEntry::forget_after`]
//! has passed.
//!
//! The seen list is the host's to keep, durably, and apart from the inbox:
//! deleting a mailbox file must not make an old message deliverable again.

use crate::host::Arrival;

/// Clock skew allowed either way, in seconds.
pub const MAX_SKEW_SECS: i64 = 300;
/// How long the plane keeps held mail (7 days); a held message may be this
/// old when it arrives.
pub const HOLD_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// The oldest `sent_at` accepted for an arrival, relative to `now`.
#[must_use]
pub fn max_age(arrival: Arrival) -> i64 {
    match arrival {
        Arrival::Live => MAX_SKEW_SECS,
        Arrival::Held => HOLD_TTL_SECS + MAX_SKEW_SECS,
    }
}

/// Whether `sent_at` is inside the window for `arrival`: no more than
/// [`MAX_SKEW_SECS`] in the future, and no older than [`max_age`].
#[must_use]
pub fn in_window(sent_at: i64, now: i64, arrival: Arrival) -> bool {
    let Some(age) = now.checked_sub(sent_at) else {
        return false;
    };
    (-MAX_SKEW_SECS..=max_age(arrival)).contains(&age)
}

/// One remembered message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenEntry {
    /// The sender's address, as signed.
    pub from: String,
    /// The message id (ULID), as signed.
    pub id: String,
    /// Unix seconds after which the host may drop this entry: past it, the
    /// message is refused by [`in_window`] anyway.
    pub forget_after: i64,
}

impl SeenEntry {
    #[must_use]
    pub fn new(from: &str, id: &str, sent_at: i64) -> Self {
        Self {
            from: from.to_string(),
            id: id.to_string(),
            forget_after: sent_at
                .saturating_add(HOLD_TTL_SECS)
                .saturating_add(2 * MAX_SKEW_SECS),
        }
    }
}

/// The host's durable seen list.
pub trait SeenStore {
    /// Record `entry` if `(from, id)` is new and return `Ok(true)`; return
    /// `Ok(false)` if it was already there. Must be atomic and durable
    /// before it returns `true`.
    ///
    /// # Errors
    /// A storage error. The SDK then refuses the message as retryable; it
    /// never delivers without a record.
    fn insert_new(&mut self, entry: &SeenEntry) -> Result<bool, String>;
}

/// An in-memory [`SeenStore`], for tests and hosts that only want dedupe
/// within one process. Not durable.
#[derive(Debug, Default)]
pub struct MemorySeen {
    seen: std::collections::HashMap<(String, String), i64>,
}

impl MemorySeen {
    /// Drop entries whose `forget_after` is before `now`.
    pub fn sweep(&mut self, now: i64) {
        self.seen.retain(|_, forget_after| *forget_after >= now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl SeenStore for MemorySeen {
    fn insert_new(&mut self, e: &SeenEntry) -> Result<bool, String> {
        use std::collections::hash_map::Entry;
        match self.seen.entry((e.from.clone(), e.id.clone())) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(v) => {
                v.insert(e.forget_after);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    #[test]
    fn windows() {
        assert!(in_window(T0, T0, Arrival::Live));
        assert!(in_window(T0 - MAX_SKEW_SECS, T0, Arrival::Live));
        assert!(!in_window(T0 - MAX_SKEW_SECS - 1, T0, Arrival::Live));
        assert!(in_window(T0 + MAX_SKEW_SECS, T0, Arrival::Live));
        assert!(!in_window(T0 + MAX_SKEW_SECS + 1, T0, Arrival::Live));
        assert!(in_window(T0 - HOLD_TTL_SECS, T0, Arrival::Held));
        assert!(!in_window(
            T0 - HOLD_TTL_SECS - MAX_SKEW_SECS - 1,
            T0,
            Arrival::Held
        ));
        assert!(!in_window(T0 + MAX_SKEW_SECS + 1, T0, Arrival::Held));
        assert!(!in_window(i64::MIN, T0, Arrival::Held));
        assert!(!in_window(i64::MAX, T0, Arrival::Held));
        assert!(!in_window(T0, i64::MIN, Arrival::Held));
    }

    #[test]
    fn forgetting_is_safe() {
        let e = SeenEntry::new("a::abc.postal.bot", "01J", T0);
        // Once the host may forget, the window already refuses it.
        assert!(!in_window(T0, e.forget_after, Arrival::Held));
        assert!(!in_window(T0, e.forget_after - 1, Arrival::Held));
    }

    #[test]
    fn memory_seen_dedupes_per_sender() {
        let mut s = MemorySeen::default();
        let a = SeenEntry::new("a::abc.postal.bot", "01J", T0);
        let b = SeenEntry::new("b::abc.postal.bot", "01J", T0);
        assert!(s.insert_new(&a).unwrap());
        assert!(!s.insert_new(&a).unwrap());
        assert!(s.insert_new(&b).unwrap());
        s.sweep(a.forget_after + 1);
        assert!(s.is_empty());
    }
}
