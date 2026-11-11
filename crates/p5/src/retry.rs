//! Retries after a message is safely on disk (F11).
//!
//! Two queues, one loop in the resident agent:
//! - **outbox**: our own queued sends ([`crate::sm::flush_outbox`]).
//! - **knocks**: mail already in *our* inbox whose last-mile knock failed
//!   (K2 busy or declined, a plugin miss, a turn gateway hiccup). The mail
//!   is delivered; only the nudge to the agent is retried. Kept in
//!   `~/.postal/knock-retry.json`, written atomically.
//!
//! Both back off with [`p5_core::backoff_secs`] and give up after
//! [`p5_core::MAX_AUTO_ATTEMPTS`]. Giving up on a knock never loses mail: the
//! cover stays in `~/.postal/inbox`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p5_core::{backoff_secs, PeerType, MAX_AUTO_ATTEMPTS};
use serde::{Deserialize, Serialize};

use crate::last_mile;
use crate::sm::{Inbound, SmContext};

pub const KNOCKS_FILE: &str = "knock-retry.json";
/// How often the agent looks for due work.
const TICK: Duration = Duration::from_secs(5);

/// One knock waiting to be tried again. Keyed by inbox id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKnock {
    pub attempts: u32,
    /// Unix seconds.
    pub next_at: u64,
    #[serde(default)]
    pub no_wake: bool,
    #[serde(default)]
    pub last_error: String,
}

/// Serializes read-modify-write of the knock file inside this process (the
/// HTTP receive thread and the retry loop).
static KNOCKS_LOCK: Mutex<()> = Mutex::new(());

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn load_knocks(root: &Path) -> BTreeMap<String, PendingKnock> {
    std::fs::read_to_string(root.join(KNOCKS_FILE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_knocks(root: &Path, knocks: &BTreeMap<String, PendingKnock>) -> std::io::Result<()> {
    let path = root.join(KNOCKS_FILE);
    if knocks.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = root.join(format!("{KNOCKS_FILE}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(serde_json::to_string_pretty(knocks)?.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

/// Remember a failed knock for `id` (already in our inbox). First retry soon.
pub fn queue_knock(root: &Path, id: &str, no_wake: bool, error: &str, now: SystemTime) {
    let _guard = KNOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut knocks = load_knocks(root);
    knocks.entry(id.to_string()).or_insert(PendingKnock {
        attempts: 0,
        next_at: unix(now) + backoff_secs(1),
        no_wake,
        last_error: error.chars().take(240).collect(),
    });
    if let Err(err) = save_knocks(root, &knocks) {
        eprintln!("p5: knock retry not saved for {id}: {err}");
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KnockReport {
    pub tried: usize,
    pub knocked: usize,
    pub gave_up: usize,
}

/// Try every due knock once.
pub fn flush_knocks(ctx: &SmContext, now: SystemTime) -> KnockReport {
    let root = ctx.mailbox.root().to_path_buf();
    let _guard = KNOCKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut knocks = load_knocks(&root);
    let mut report = KnockReport::default();
    let due: Vec<String> = knocks
        .iter()
        .filter(|(_, k)| k.next_at <= unix(now))
        .map(|(id, _)| id.clone())
        .collect();
    for id in due {
        report.tried += 1;
        let entry = knocks.get(&id).cloned().expect("due id present");
        match knock_once(ctx, &id, entry.no_wake) {
            Ok(()) => {
                knocks.remove(&id);
                report.knocked += 1;
            }
            Err(KnockMiss::Gone) => {
                // No inbox item or no home row any more: nothing to nudge.
                knocks.remove(&id);
            }
            Err(KnockMiss::Again(err)) => {
                let attempts = entry.attempts + 1;
                if attempts >= MAX_AUTO_ATTEMPTS {
                    eprintln!("p5: gave up knocking {id} after {attempts} tries ({err}); it stays in the inbox");
                    knocks.remove(&id);
                    report.gave_up += 1;
                } else {
                    knocks.insert(
                        id.clone(),
                        PendingKnock {
                            attempts,
                            next_at: unix(now) + backoff_secs(attempts + 1),
                            no_wake: entry.no_wake,
                            last_error: err.chars().take(240).collect(),
                        },
                    );
                }
            }
        }
    }
    if report.tried > 0 {
        if let Err(err) = save_knocks(&root, &knocks) {
            eprintln!("p5: knock retry state not saved: {err}");
        }
    }
    report
}

enum KnockMiss {
    Gone,
    Again(String),
}

fn knock_once(ctx: &SmContext, id: &str, no_wake: bool) -> Result<(), KnockMiss> {
    let item = ctx.mailbox.read_inbox(id).map_err(|_| KnockMiss::Gone)?;
    let Some(home) = ctx.homes.get(&item.to) else {
        return Err(KnockMiss::Gone);
    };
    let typ = if item.typ == PeerType::Turn { PeerType::Turn } else { PeerType::Session };
    let inbound = Inbound {
        id: item.id.clone(),
        to: item.to.clone(),
        from: item.from.clone(),
        body: item.body.clone(),
        mode: item.mode,
        typ,
        files: Vec::new(),
        no_wake,
    };
    last_mile::after_inbox_fsync(ctx, home, &inbound).map_err(|e| KnockMiss::Again(e.to_string()))
}

/// Resident-agent loop: every few seconds, retry due sends and due knocks.
/// `P5_RETRY=0` turns it off.
pub fn spawn_loop<F>(stop: Arc<AtomicBool>, context: F) -> Option<thread::JoinHandle<()>>
where
    F: Fn() -> Option<SmContext> + Send + 'static,
{
    if crate::sm::env_flag_off("P5_RETRY") {
        return None;
    }
    Some(thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            if let Some(ctx) = context() {
                let now = SystemTime::now();
                match crate::sm::flush_outbox(&ctx, now) {
                    Ok(r) if r.tried > 0 => eprintln!(
                        "p5: outbox retry: {} tried, {} delivered, {} failed, {} still queued",
                        r.tried, r.delivered, r.failed, r.queued
                    ),
                    Ok(_) => {}
                    Err(err) => eprintln!("p5: outbox retry: {err}"),
                }
                let k = flush_knocks(&ctx, now);
                if k.tried > 0 {
                    eprintln!(
                        "p5: knock retry: {} tried, {} knocked, {} gave up",
                        k.tried, k.knocked, k.gave_up
                    );
                }
            }
            let until = std::time::Instant::now() + TICK;
            while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < until {
                thread::sleep(Duration::from_millis(200));
            }
        }
    }))
}
