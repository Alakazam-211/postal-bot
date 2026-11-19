//! The sender's outbox: one [`Item`] per message, a pure state machine. The
//! host stores items (K2: `postal-outbox/`, 0600), runs the HTTP calls the
//! item asks for, and feeds the outcome back. Nothing here does I/O.
//!
//! ```text
//! Queued ──live 2xx──────────────────────────▶ Delivered
//!   │ ──definite miss (refused, 404, 503 host_down, 429)──▶ hold
//!   │ ──soft miss (timeout, 408, other 5xx)──▶ Queued, backoff;
//!   │        still missing after SOFT_HOLD_AFTER ──▶ hold
//!   └─ hold: POST /hold ─▶ Held ── receipt delivered ─▶ Delivered
//!                          │      receipt refused:x  ─▶ Dead(Refused x)
//!                          └───── receipt expired    ─▶ Dead(Expired)
//! any state past MAX_AGE without delivery ─▶ Dead(Expired)
//! a permanent plane error ─▶ Dead(Plane code)
//! ```
//!
//! The item keeps no signed message. For every try, live or hold, the
//! host signs the message again ([`crate::wire::sign`]) with the same `id`
//! and a fresh `sent_at`: a signed copy older than
//! [`crate::replay::MAX_SKEW_SECS`] would be refused live as stale. The
//! receiver dedupes on `(from, id)`, so re-signing never delivers twice.
//!
//! A message is never held once live delivery succeeded. Holding after a
//! soft miss is safe because receivers dedupe on `(from, id)`
//! ([`crate::replay`]); a copy that also arrived live is dropped there.

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::plane::{PlaneError, Receipt, RefuseCode};

/// First retry delay, in seconds.
pub const BACKOFF_BASE_SECS: i64 = 15;
/// Longest retry delay.
pub const BACKOFF_MAX_SECS: i64 = 30 * 60;
/// A peer missing softly this long (and at least [`SOFT_MISSES`] times) gets
/// the message held instead.
pub const SOFT_HOLD_AFTER_SECS: i64 = 10 * 60;
/// Soft misses before holding.
pub const SOFT_MISSES: u32 = 3;
/// Past this age an undelivered message is dead (the hold TTL).
pub const MAX_AGE_SECS: i64 = crate::replay::HOLD_TTL_SECS;

/// Where a message is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    /// Waiting for a live try (or a hold, see [`Item::next`]).
    Queued,
    /// On the plane, sealed. `hold_id` is the plane's id.
    Held { hold_id: String, expires_at: String },
    /// On the recipient's disk (live 2xx, or an ACKed hold).
    Delivered,
    /// Given up. The owner should see why.
    Dead { why: DeadReason },
}

/// Why a message died.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DeadReason {
    /// Not delivered within [`MAX_AGE_SECS`], or the hold expired.
    Expired,
    /// The recipient refused it for good.
    Refused { code: RefuseCode },
    /// The plane refused the hold for good (`code` as the plane spelled it).
    Plane { code: String },
    /// The live endpoint refused it for good (4xx other than 404/408/429).
    /// See `docs/postal-wire-v2.md` for the reply table.
    Live { status: u16 },
}

/// The result of `POST https://<label>.postal.bot/postal/v2/msg`, as the host saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Live {
    /// Any HTTP status.
    Status(u16, String),
    /// Connection refused: nothing listens, so definitely not delivered.
    Refused,
    /// Timeout, DNS, TLS, reset: the peer may or may not have it.
    Transport(String),
}

/// What the host should do for an item now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Try live delivery.
    Live,
    /// Seal and `POST /hold` (see [`crate::hold::seal`], [`crate::plane::hold_put`]).
    Hold,
    /// Ask the plane for this item's receipt (`/hold/sent`), or wait for a
    /// receipt event. Not before `at`.
    Receipt { at: i64 },
    /// Nothing until `at`.
    Wait { at: i64 },
    /// Final.
    Done,
}

/// One outgoing message. Serde, so the host can store it as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// The message id (ULID), also the hold's `client_id`.
    pub id: String,
    pub to: Address,
    /// Unix seconds when queued.
    pub created_at: i64,
    pub state: State,
    /// Tries so far (live and hold).
    pub tries: u32,
    /// Live tries that ended in a soft miss.
    pub soft_misses: u32,
    /// Not before this (unix seconds).
    pub next_at: i64,
    /// When set, hold on the next step instead of trying live.
    pub hold_next: bool,
    /// Last error, for the owner.
    pub last_error: Option<String>,
}

impl Item {
    #[must_use]
    pub fn new(id: &str, to: Address, now: i64) -> Self {
        Self {
            id: id.to_string(),
            to,
            created_at: now,
            state: State::Queued,
            tries: 0,
            soft_misses: 0,
            next_at: now,
            hold_next: false,
            last_error: None,
        }
    }

    /// The next step at `now`. Also expires an item that's too old.
    pub fn next(&mut self, now: i64) -> Step {
        if matches!(self.state, State::Delivered | State::Dead { .. }) {
            return Step::Done;
        }
        if now.saturating_sub(self.created_at) > MAX_AGE_SECS {
            self.state = State::Dead {
                why: DeadReason::Expired,
            };
            return Step::Done;
        }
        if now < self.next_at {
            return match self.state {
                State::Held { .. } => Step::Receipt { at: self.next_at },
                _ => Step::Wait { at: self.next_at },
            };
        }
        match self.state {
            State::Held { .. } => Step::Receipt { at: now },
            _ if self.hold_next => Step::Hold,
            _ => Step::Live,
        }
    }

    /// Feed back a live try. `jitter` in `[0, 1)` spreads retries.
    pub fn on_live(&mut self, live: &Live, now: i64, jitter: f64) {
        self.tries += 1;
        match live {
            Live::Status(s, _) if (200..300).contains(s) => {
                self.state = State::Delivered;
                self.last_error = None;
            }
            Live::Refused => self.definite_miss("connection refused".into(), now),
            Live::Status(404, _) => self.definite_miss("404".into(), now),
            // The receiver is up but won't take more now: hold rather than
            // keep knocking (docs/postal-wire-v2.md). Its pull drains the hold
            // at its own pace.
            Live::Status(429, _) => self.definite_miss("429 rate_limited".into(), now),
            Live::Status(503, body) if body.contains("host_down") => {
                self.definite_miss("503 host_down".into(), now);
            }
            Live::Status(s, _) if (400..500).contains(s) && !matches!(s, 408 | 429) => {
                self.state = State::Dead {
                    why: DeadReason::Live { status: *s },
                };
                self.last_error = Some(format!("live {s}"));
            }
            Live::Status(s, _) => self.soft_miss(format!("live {s}"), now, jitter),
            Live::Transport(e) => self.soft_miss(e.chars().take(120).collect(), now, jitter),
        }
    }

    fn definite_miss(&mut self, why: String, now: i64) {
        self.last_error = Some(why);
        self.hold_next = true;
        self.next_at = now;
    }

    fn soft_miss(&mut self, why: String, now: i64, jitter: f64) {
        self.soft_misses += 1;
        self.last_error = Some(why);
        if self.soft_misses >= SOFT_MISSES
            && now.saturating_sub(self.created_at) >= SOFT_HOLD_AFTER_SECS
        {
            self.hold_next = true;
            self.next_at = now;
        } else {
            self.next_at = now + backoff(self.tries, jitter);
        }
    }

    /// Feed back `POST /hold`: the parsed answer or the error.
    pub fn on_hold(
        &mut self,
        res: Result<&crate::plane::HoldPutOk, &PlaneError>,
        now: i64,
        jitter: f64,
    ) {
        self.tries += 1;
        match res {
            Ok(ok) => {
                self.state = State::Held {
                    hold_id: ok.id.clone(),
                    expires_at: ok.expires_at.clone(),
                };
                self.last_error = None;
                self.next_at = now + BACKOFF_MAX_SECS;
            }
            Err(e) if e.is_retryable() => {
                self.last_error = Some(e.to_string());
                let wait = e
                    .retry_after()
                    .and_then(|s| i64::try_from(s).ok())
                    .unwrap_or_else(|| backoff(self.tries, jitter));
                self.next_at = now + wait.clamp(1, BACKOFF_MAX_SECS);
            }
            Err(e) => {
                let code = match e.code() {
                    Some(crate::plane::Code::Other(c)) => c.clone(),
                    Some(c) => format!("{c:?}"),
                    None => "bad_input".into(),
                };
                self.last_error = Some(e.to_string());
                self.state = State::Dead {
                    why: DeadReason::Plane { code },
                };
            }
        }
    }

    /// Feed back a receipt for a held item. Still held: ask again in
    /// [`BACKOFF_MAX_SECS`] (a receipt event usually comes first).
    pub fn on_receipt(&mut self, r: &Receipt, now: i64) {
        if !matches!(self.state, State::Held { .. }) {
            return;
        }
        match r {
            Receipt::Delivered => self.state = State::Delivered,
            Receipt::Refused(code) => {
                self.state = State::Dead {
                    why: DeadReason::Refused { code: *code },
                }
            }
            Receipt::Expired => {
                self.state = State::Dead {
                    why: DeadReason::Expired,
                }
            }
            Receipt::Held | Receipt::Other(_) => self.next_at = now + BACKOFF_MAX_SECS,
        }
    }

    /// Whether this item is final.
    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Delivered | State::Dead { .. })
    }
}

/// `BACKOFF_BASE · 2^(tries-1)`, capped, then scaled into `[0.5, 1.0]` of
/// that by `jitter` so senders don't retry in step.
#[must_use]
pub fn backoff(tries: u32, jitter: f64) -> i64 {
    let exp = tries.saturating_sub(1).min(16);
    let full = (BACKOFF_BASE_SECS << exp).min(BACKOFF_MAX_SECS);
    let j = jitter.clamp(0.0, 0.999_999);
    // Truncation is fine: whole seconds.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let scaled = (full as f64 * (0.5 + j / 2.0)) as i64;
    scaled.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::{parse, HoldPutOk};

    const T0: i64 = 1_800_000_000;

    fn item() -> Item {
        Item::new(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            Address::parse("scout::bravo.postal.bot").unwrap(),
            T0,
        )
    }

    fn held(i: &mut Item, now: i64) {
        assert_eq!(i.next(now), Step::Hold);
        let ok: HoldPutOk = parse(200, br#"{"id":"h1","expires_at":"x"}"#).unwrap();
        i.on_hold(Ok(&ok), now, 0.0);
        assert!(matches!(i.state, State::Held { .. }));
    }

    #[test]
    fn live_success_is_final_and_never_held() {
        let mut i = item();
        assert_eq!(i.next(T0), Step::Live);
        i.on_live(&Live::Status(202, String::new()), T0, 0.0);
        assert_eq!(i.state, State::Delivered);
        assert_eq!(i.next(T0 + 1), Step::Done);
    }

    #[test]
    fn a_definite_miss_holds_at_once() {
        for live in [
            Live::Refused,
            Live::Status(404, String::new()),
            Live::Status(503, r#"{"error":"host_down"}"#.into()),
            Live::Status(
                429,
                r#"{"error":{"code":"rate_limited","message":"","retry_after_s":30}}"#.into(),
            ),
        ] {
            let mut i = item();
            i.on_live(&live, T0, 0.0);
            held(&mut i, T0);
        }
    }

    #[test]
    fn soft_misses_back_off_then_hold() {
        let mut i = item();
        let mut now = T0;
        for _ in 0..SOFT_MISSES {
            assert_eq!(i.next(now), Step::Live);
            i.on_live(&Live::Transport("timed out".into()), now, 0.0);
            let Step::Wait { at } = i.next(now) else {
                panic!("{:?}", i.next(now))
            };
            assert!(at > now);
            now = at;
        }
        // Enough misses but not yet long enough: still live.
        assert!(now - T0 < SOFT_HOLD_AFTER_SECS);
        while now - T0 < SOFT_HOLD_AFTER_SECS {
            assert_eq!(i.next(now), Step::Live);
            i.on_live(&Live::Status(502, String::new()), now, 0.0);
            if let Step::Wait { at } = i.next(now) {
                now = at;
            }
        }
        // Past the deadline, the next soft miss holds.
        assert_eq!(i.next(now), Step::Live);
        i.on_live(&Live::Transport("timed out".into()), now, 0.0);
        held(&mut i, now);
    }

    #[test]
    fn a_permanent_live_refusal_is_dead() {
        let mut i = item();
        i.on_live(&Live::Status(403, String::new()), T0, 0.0);
        assert_eq!(
            i.state,
            State::Dead {
                why: DeadReason::Live { status: 403 }
            }
        );
    }

    #[test]
    fn hold_errors() {
        let mut i = item();
        i.on_live(&Live::Refused, T0, 0.0);
        let quota = parse::<HoldPutOk>(
            429,
            br#"{"error":{"code":"hold_quota","message":"","retry_after_s":90}}"#,
        )
        .unwrap_err();
        i.on_hold(Err(&quota), T0, 0.0);
        assert_eq!(i.next(T0), Step::Wait { at: T0 + 90 });
        assert_eq!(i.next(T0 + 90), Step::Hold);
        let big =
            parse::<HoldPutOk>(413, br#"{"error":{"code":"too_large","message":""}}"#).unwrap_err();
        i.on_hold(Err(&big), T0 + 90, 0.0);
        assert!(matches!(
            i.state,
            State::Dead {
                why: DeadReason::Plane { .. }
            }
        ));
    }

    #[test]
    fn receipts_finish_a_held_item() {
        for (r, want) in [
            (Receipt::Delivered, State::Delivered),
            (
                Receipt::Refused(RefuseCode::Gated),
                State::Dead {
                    why: DeadReason::Refused {
                        code: RefuseCode::Gated,
                    },
                },
            ),
            (
                Receipt::Expired,
                State::Dead {
                    why: DeadReason::Expired,
                },
            ),
        ] {
            let mut i = item();
            i.on_live(&Live::Refused, T0, 0.0);
            held(&mut i, T0);
            assert!(matches!(i.next(T0), Step::Receipt { .. }));
            i.on_receipt(&r, T0 + 5);
            assert_eq!(i.state, want);
        }
        let mut i = item();
        i.on_live(&Live::Refused, T0, 0.0);
        held(&mut i, T0);
        i.on_receipt(&Receipt::Held, T0 + 5);
        assert!(matches!(i.state, State::Held { .. }));
    }

    #[test]
    fn too_old_is_dead() {
        let mut i = item();
        i.on_live(&Live::Transport("dns".into()), T0, 0.0);
        assert_eq!(i.next(T0 + MAX_AGE_SECS + 1), Step::Done);
        assert_eq!(
            i.state,
            State::Dead {
                why: DeadReason::Expired
            }
        );
    }

    #[test]
    fn backoff_grows_caps_and_jitters() {
        assert_eq!(backoff(1, 0.0), 7);
        assert_eq!(backoff(1, 0.999_999), 14);
        assert!(backoff(2, 0.0) >= BACKOFF_BASE_SECS);
        assert!(backoff(100, 0.999_999) <= BACKOFF_MAX_SECS);
        assert_eq!(backoff(100, 0.0), BACKOFF_MAX_SECS / 2);
        assert!(backoff(0, 0.0) >= 1);
    }

    #[test]
    fn items_store_as_json() {
        let mut i = item();
        i.on_live(&Live::Refused, T0, 0.0);
        held(&mut i, T0);
        let j = serde_json::to_string(&i).unwrap();
        assert_eq!(serde_json::from_str::<Item>(&j).unwrap(), i);
    }
}
