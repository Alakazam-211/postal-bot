//! Outbox state machine. Hosts own disk; this crate decides the next status.
//!
//! Never HOLD if live succeeded. Never HOLD on a soft miss (429, timeout,
//! DNS). HOLD only on a definite miss when the plane accepts the PUT.

use serde::{Deserialize, Serialize};

/// Sender statuses. `held` here means ciphertext on the plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Queued,
    Held,
    Delivered,
    Acked,
    Failed,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Held => "held",
            Self::Delivered => "delivered",
            Self::Acked => "acked",
            Self::Failed => "failed",
        }
    }
}

/// Outcome of `POST https://<label>.postal.bot/p5/msg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveOutcome {
    /// Bytes already on the peer. Never HOLD after this.
    Delivered { status: u16 },
    /// Tunnel / host is known down: TCP refuse, 404, 503 `host_down`.
    DefiniteMiss { why: String },
    /// Ambiguous: timeout, 429, DNS, other HTTP. Never HOLD — peer may be live.
    SoftMiss { why: String },
}

/// Outcome of `PUT /postal/hold`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneOutcome {
    /// Ciphertext stored. Same id + same blob is also this (200).
    Accepted { id: String },
    /// Same id, different ciphertext (409).
    Conflict,
    /// Cannot reach the plane. Stay queued.
    Unreachable { why: String },
    /// Terminal: not paired, gated, too large, bad id.
    Refuse { why: String },
}

/// What to do after a live attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    Done(Status),
    PutHold,
    StayQueued,
}

/// Classify a live HTTP result. `http_status` is set on any HTTP response
/// (including 4xx/5xx). `transport` is the error text when there was no
/// status (connect/timeout/DNS).
#[must_use]
pub fn classify_live(http_status: Option<u16>, body: &str, transport: Option<&str>) -> LiveOutcome {
    if let Some(code) = http_status {
        if (200..300).contains(&code) {
            return LiveOutcome::Delivered { status: code };
        }
        return classify_status(code, body);
    }
    if let Some(msg) = transport {
        return classify_transport(msg);
    }
    LiveOutcome::SoftMiss {
        why: "unknown".into(),
    }
}

fn classify_status(code: u16, body: &str) -> LiveOutcome {
    match code {
        404 => LiveOutcome::DefiniteMiss { why: "404".into() },
        429 => LiveOutcome::SoftMiss { why: "429".into() },
        503 if is_host_down(body) => LiveOutcome::DefiniteMiss {
            why: "503 host_down".into(),
        },
        code => LiveOutcome::SoftMiss {
            why: format!("{code}"),
        },
    }
}

fn is_host_down(body: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["error", "reason", "status"] {
            if v.get(key).and_then(|e| e.as_str()) == Some("host_down") {
                return true;
            }
        }
    }
    body.contains("host_down")
}

fn classify_transport(msg: &str) -> LiveOutcome {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("connection refused") {
        return LiveOutcome::DefiniteMiss {
            why: "connection refused".into(),
        };
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return LiveOutcome::SoftMiss {
            why: "timeout".into(),
        };
    }
    LiveOutcome::SoftMiss {
        why: msg.chars().take(120).collect(),
    }
}

/// After live: deliver, stay queued, or PUT hold.
#[must_use]
pub fn after_live(live: &LiveOutcome) -> Next {
    match live {
        LiveOutcome::Delivered { .. } => Next::Done(Status::Delivered),
        LiveOutcome::SoftMiss { .. } => Next::StayQueued,
        LiveOutcome::DefiniteMiss { .. } => Next::PutHold,
    }
}

/// After PUT hold.
#[must_use]
pub fn after_hold(plane: &PlaneOutcome) -> Status {
    match plane {
        PlaneOutcome::Accepted { .. } => Status::Held,
        // 409: plane still has a different blob for this id. Do not claim held.
        PlaneOutcome::Conflict => Status::Failed,
        PlaneOutcome::Unreachable { .. } => Status::Queued,
        PlaneOutcome::Refuse { .. } => Status::Failed,
    }
}

/// After the receiving host fsynced and ACK returned 200.
#[must_use]
pub fn after_ack() -> Status {
    Status::Acked
}

/// ACK 404: the blob is already gone. Treat as acked if we already fsynced.
#[must_use]
pub fn after_ack_not_found(fsynced: bool) -> Status {
    if fsynced {
        Status::Acked
    } else {
        Status::Queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_2xx_never_holds() {
        let live = classify_live(Some(200), r#"{"status":"delivered"}"#, None);
        assert!(matches!(live, LiveOutcome::Delivered { status: 200 }));
        assert_eq!(after_live(&live), Next::Done(Status::Delivered));
    }

    #[test]
    fn live_429_and_timeout_stay_queued() {
        let r = classify_live(Some(429), "", None);
        assert!(matches!(r, LiveOutcome::SoftMiss { .. }));
        assert_eq!(after_live(&r), Next::StayQueued);
        let t = classify_live(None, "", Some("timed out"));
        assert!(matches!(t, LiveOutcome::SoftMiss { .. }));
        assert_eq!(after_live(&t), Next::StayQueued);
        let dns = classify_live(None, "", Some("dns error"));
        assert_eq!(after_live(&dns), Next::StayQueued);
    }

    #[test]
    fn definite_miss_puts_hold() {
        for live in [
            classify_live(Some(404), "", None),
            classify_live(Some(503), r#"{"error":"host_down"}"#, None),
            classify_live(None, "", Some("Connection refused")),
        ] {
            assert!(matches!(live, LiveOutcome::DefiniteMiss { .. }), "{live:?}");
            assert_eq!(after_live(&live), Next::PutHold);
        }
    }

    #[test]
    fn hold_accepted_is_held_unreachable_stays_queued() {
        assert_eq!(
            after_hold(&PlaneOutcome::Accepted { id: "x".into() }),
            Status::Held
        );
        assert_eq!(after_hold(&PlaneOutcome::Conflict), Status::Failed);
        assert_eq!(
            after_hold(&PlaneOutcome::Unreachable { why: "down".into() }),
            Status::Queued
        );
        assert_eq!(
            after_hold(&PlaneOutcome::Refuse {
                why: "not paired".into()
            }),
            Status::Failed
        );
    }

    #[test]
    fn ack_after_fsync() {
        assert_eq!(after_ack(), Status::Acked);
        assert_eq!(after_ack_not_found(true), Status::Acked);
        assert_eq!(after_ack_not_found(false), Status::Queued);
    }

    #[test]
    fn status_spellings() {
        for (s, w) in [
            (Status::Queued, "queued"),
            (Status::Held, "held"),
            (Status::Delivered, "delivered"),
            (Status::Acked, "acked"),
            (Status::Failed, "failed"),
        ] {
            assert_eq!(s.as_str(), w);
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{w}\""));
        }
    }
}
