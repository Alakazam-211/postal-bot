//! Sans-IO plane contract: P-4 hold v2 and P-5 events.
//!
//! Locked with k2-dev-web (`m_lqHkCWz0rZ`). Hosts bring HTTP. Hold is not
//! shipped until they ping.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::seal::{is_holdseal_v1, seal, SealAad, SealError};

/// Hold TTL we send. Plane may GC after this.
pub const HOLD_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Agent poll target when events are down and `P5_HOLD=1`.
pub const HOLD_POLL_SECS: u64 = 30;
/// Jitter around [`HOLD_POLL_SECS`] so pollers do not sync.
pub const HOLD_POLL_JITTER_SECS: u64 = 10;
/// Minimum HoldSeal-v1 blob: version + eph_pub + nonce + tag.
pub const MIN_BLOB_LEN: usize = 61;
/// P-4 PUT / GET.
pub const HOLD_PATH: &str = "/postal/hold";
/// P-5 long-poll / poll. Cursor is opaque; not a unix `since`.
pub const EVENTS_PATH: &str = "/postal/events";

/// `PUT /postal/hold` body. `ciphertext` is opaque HoldSeal-v1 (standard base64).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldEnvelope {
    pub id: String,
    pub to: String,
    pub from: String,
    pub size: u64,
    /// Unix seconds (TTL). Opaque to the plane besides GC.
    pub expiry: u64,
    pub ciphertext: String,
}

/// `PUT /postal/hold` or `POST /postal/hold/{id}/ack` 200 body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldOk {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub id: String,
}

/// `GET /postal/hold` — `{items:[…]}` only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldList {
    #[serde(default)]
    pub items: Vec<HoldEnvelope>,
}

/// Content-blind P-5 event. No body, no ciphertext, no SAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Hold,
    Pair,
}

/// One content-blind notify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub id: String,
    pub from: String,
    pub to: String,
}

/// `GET /postal/events` 200 body. Timeout is 200 with `events: []`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaitPage {
    pub cursor: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// Fail-closed plane error. HTTP mapping is the host's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneError {
    /// Decoded blob is not HoldSeal-v1 (wrong version or shorter than 61).
    Plaintext,
    /// Hold/pair id would be interpolated into a URL path.
    BadHoldId,
    /// PUT same id, different ciphertext (plane 409).
    Conflict,
    /// ACK of an id that is not this bearer (plane 404).
    NotFound,
    /// Host transport / HTTP.
    Host(String),
    Crypto(String),
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("refusing to upload plaintext hold body"),
            Self::BadHoldId => f.write_str("hold id contains invalid characters"),
            Self::Conflict => f.write_str("hold id already stored with a different ciphertext"),
            Self::NotFound => f.write_str("hold not found for this bearer"),
            Self::Host(msg) => write!(f, "plane: {msg}"),
            Self::Crypto(msg) => write!(f, "postal hold crypto: {msg}"),
        }
    }
}

impl std::error::Error for PlaneError {}

impl From<SealError> for PlaneError {
    fn from(e: SealError) -> Self {
        Self::Crypto(e.to_string())
    }
}

/// `id` is interpolated into `/postal/hold/{id}/ack`.
#[must_use]
pub fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// `POST /postal/hold/{id}/ack`.
///
/// # Errors
/// [`PlaneError::BadHoldId`].
pub fn hold_ack_path(id: &str) -> Result<String, PlaneError> {
    if !is_safe_id(id) {
        return Err(PlaneError::BadHoldId);
    }
    Ok(format!("{HOLD_PATH}/{id}/ack"))
}

/// `GET /postal/events?cursor=&wait=`.
#[must_use]
pub fn events_path(cursor: Option<&str>, wait: u64) -> String {
    let wait = wait.min(60);
    match cursor {
        Some(c) if !c.is_empty() => {
            format!("{EVENTS_PATH}?cursor={}&wait={wait}", url_query(c))
        }
        _ => format!("{EVENTS_PATH}?wait={wait}"),
    }
}

fn url_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// `30s ± 10s`. `unit` is in `[0, 1)`.
#[must_use]
pub fn hold_poll_delay(unit: f64) -> Duration {
    let unit = unit.clamp(0.0, 0.999_999);
    let lo = (HOLD_POLL_SECS.saturating_sub(HOLD_POLL_JITTER_SECS)) as f64;
    let span = (2 * HOLD_POLL_JITTER_SECS) as f64;
    Duration::from_secs_f64(lo + unit * span)
}

/// `expiry = now + ttl`. Host passes unix seconds.
#[must_use]
pub fn expiry_unix(now: u64, ttl: u64) -> u64 {
    now.saturating_add(ttl)
}

/// Fail closed: PUT body must be HoldSeal-v1, never the cover text.
/// Blob must start with `0x01` and be at least [`MIN_BLOB_LEN`] bytes.
///
/// # Errors
/// [`PlaneError::Plaintext`] if it is not a HoldSeal-v1 blob, or `size` disagrees.
pub fn refuse_plaintext(env: &HoldEnvelope) -> Result<Vec<u8>, PlaneError> {
    let blob = crate::b64::decode(&env.ciphertext).map_err(|_| PlaneError::Plaintext)?;
    if blob.len() < MIN_BLOB_LEN || !is_holdseal_v1(&blob) {
        return Err(PlaneError::Plaintext);
    }
    if env.size != 0 && env.size != blob.len() as u64 {
        return Err(PlaneError::Plaintext);
    }
    Ok(blob)
}

/// Seal plaintext and build a PUT envelope. `now` is unix seconds.
///
/// # Errors
/// Crypto or id errors.
pub fn seal_envelope(
    id: &str,
    to: &str,
    from: &str,
    plaintext: &[u8],
    peer_spki_pem: &str,
    now: u64,
    ttl: u64,
) -> Result<HoldEnvelope, PlaneError> {
    if !is_safe_id(id) {
        return Err(PlaneError::BadHoldId);
    }
    let aad = SealAad {
        id: id.to_string(),
        from: from.to_string(),
        to: to.to_string(),
    };
    let blob = seal(peer_spki_pem, plaintext, &aad)?;
    Ok(HoldEnvelope {
        id: id.to_string(),
        to: to.to_string(),
        from: from.to_string(),
        size: blob.len() as u64,
        expiry: expiry_unix(now, ttl),
        ciphertext: crate::b64::encode(&blob),
    })
}

/// Parse GET `/postal/hold`. Only `{items:[…]}` is accepted.
///
/// # Errors
/// [`PlaneError::Host`] if the JSON is another shape.
pub fn parse_hold_list(v: &serde_json::Value) -> Result<HoldList, PlaneError> {
    if v.get("items").is_some() && v.get("holds").is_none() && !v.is_array() {
        return serde_json::from_value(v.clone())
            .map_err(|e| PlaneError::Host(format!("hold list: {e}")));
    }
    Err(PlaneError::Host(
        "GET /postal/hold must be {items:[...]} only".into(),
    ))
}

/// What a host implements. No sockets here.
pub trait Plane {
    /// `PUT /postal/hold`. Call [`refuse_plaintext`] first.
    ///
    /// # Errors
    /// [`PlaneError::Conflict`] on 409 (same id, different ciphertext).
    fn put_hold(&self, env: &HoldEnvelope) -> Result<HoldOk, PlaneError>;

    /// `GET /postal/hold`.
    ///
    /// # Errors
    /// [`PlaneError::Host`] on transport or a non-`{items}` body.
    fn list_hold(&self) -> Result<HoldList, PlaneError>;

    /// `POST /postal/hold/{id}/ack` with `{}`. Only after the host fsynced.
    ///
    /// # Errors
    /// [`PlaneError::NotFound`] on 404 (not this bearer).
    fn ack_hold(&self, id: &str) -> Result<HoldOk, PlaneError>;

    /// `GET /postal/events?cursor=&wait=`. Timeout is 200 empty events.
    ///
    /// # Errors
    /// [`PlaneError::Host`].
    fn wait(&self, cursor: Option<&str>, wait: Duration) -> Result<WaitPage, PlaneError>;
}

/// Map a PUT status to a plane error. 200 is the host's to parse.
#[must_use]
pub fn classify_put_status(status: u16) -> Option<PlaneError> {
    match status {
        409 => Some(PlaneError::Conflict),
        404 => Some(PlaneError::NotFound),
        _ => None,
    }
}

/// Map an ACK status. 200 is the host's to parse.
#[must_use]
pub fn classify_ack_status(status: u16) -> Option<PlaneError> {
    match status {
        404 => Some(PlaneError::NotFound),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::seal::HOLDSEAL_V1;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const T0: u64 = 1_800_000_000;

    struct MemoryPlane {
        holds: RefCell<BTreeMap<String, HoldEnvelope>>,
        events: RefCell<Vec<Event>>,
        cursor: RefCell<String>,
    }

    impl MemoryPlane {
        fn new() -> Self {
            Self {
                holds: RefCell::new(BTreeMap::new()),
                events: RefCell::new(Vec::new()),
                cursor: RefCell::new("0".into()),
            }
        }
    }

    impl Plane for MemoryPlane {
        fn put_hold(&self, env: &HoldEnvelope) -> Result<HoldOk, PlaneError> {
            refuse_plaintext(env)?;
            if !is_safe_id(&env.id) {
                return Err(PlaneError::BadHoldId);
            }
            let mut holds = self.holds.borrow_mut();
            if let Some(existing) = holds.get(&env.id) {
                if existing.ciphertext != env.ciphertext {
                    return Err(PlaneError::Conflict);
                }
                return Ok(HoldOk {
                    ok: true,
                    id: env.id.clone(),
                });
            }
            holds.insert(env.id.clone(), env.clone());
            Ok(HoldOk {
                ok: true,
                id: env.id.clone(),
            })
        }

        fn list_hold(&self) -> Result<HoldList, PlaneError> {
            Ok(HoldList {
                items: self.holds.borrow().values().cloned().collect(),
            })
        }

        fn ack_hold(&self, id: &str) -> Result<HoldOk, PlaneError> {
            if !is_safe_id(id) {
                return Err(PlaneError::BadHoldId);
            }
            match self.holds.borrow_mut().remove(id) {
                Some(_) => Ok(HoldOk {
                    ok: true,
                    id: id.to_string(),
                }),
                None => Err(PlaneError::NotFound),
            }
        }

        fn wait(&self, _cursor: Option<&str>, _wait: Duration) -> Result<WaitPage, PlaneError> {
            let events = self.events.replace(Vec::new());
            Ok(WaitPage {
                cursor: self.cursor.borrow().clone(),
                events,
            })
        }
    }

    #[test]
    fn refuse_plaintext_catches_cover_text_and_short_blobs() {
        let env = HoldEnvelope {
            id: ID.into(),
            to: "scout::acme.postal.bot".into(),
            from: "alice::acme.postal.bot".into(),
            size: 5,
            expiry: expiry_unix(T0, 60),
            ciphertext: crate::b64::encode(b"hello"),
        };
        assert_eq!(refuse_plaintext(&env), Err(PlaneError::Plaintext));
        let raw = HoldEnvelope {
            ciphertext: "hello world".into(),
            size: 0,
            ..env.clone()
        };
        assert_eq!(refuse_plaintext(&raw), Err(PlaneError::Plaintext));
        let mut short = vec![HOLDSEAL_V1; MIN_BLOB_LEN - 1];
        short[0] = HOLDSEAL_V1;
        let too_short = HoldEnvelope {
            ciphertext: crate::b64::encode(&short),
            size: short.len() as u64,
            ..env
        };
        assert_eq!(refuse_plaintext(&too_short), Err(PlaneError::Plaintext));
    }

    #[test]
    fn seal_envelope_is_holdseal_v1_and_min_61() {
        let bob = Identity::generate();
        let env = seal_envelope(
            ID,
            "scout::acme.postal.bot",
            "alice::acme.postal.bot",
            b"secret cover",
            &bob.public_key_pem(),
            T0,
            HOLD_TTL_SECS,
        )
        .unwrap();
        let blob = refuse_plaintext(&env).unwrap();
        assert!(is_holdseal_v1(&blob));
        assert!(blob.len() >= MIN_BLOB_LEN);
        assert_eq!(env.size, blob.len() as u64);
        assert!(!env.ciphertext.contains("secret cover"));
        assert_eq!(env.expiry, T0 + HOLD_TTL_SECS);
        assert_eq!(
            bob.open(
                &blob,
                &SealAad {
                    id: ID.into(),
                    from: env.from.clone(),
                    to: env.to.clone(),
                }
            )
            .unwrap(),
            b"secret cover"
        );
    }

    #[test]
    fn put_same_ciphertext_is_ok_different_is_conflict() {
        let plane = MemoryPlane::new();
        let bob = Identity::generate();
        let a = seal_envelope(
            ID,
            "scout::acme.postal.bot",
            "alice::acme.postal.bot",
            b"one",
            &bob.public_key_pem(),
            T0,
            60,
        )
        .unwrap();
        let b = seal_envelope(
            ID,
            "scout::acme.postal.bot",
            "alice::acme.postal.bot",
            b"two",
            &bob.public_key_pem(),
            T0,
            60,
        )
        .unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(plane.put_hold(&a).unwrap().id, ID);
        assert!(plane.put_hold(&a).unwrap().ok);
        assert_eq!(plane.put_hold(&b), Err(PlaneError::Conflict));
        assert_eq!(classify_put_status(409), Some(PlaneError::Conflict));
    }

    #[test]
    fn ack_deletes_or_404() {
        let plane = MemoryPlane::new();
        let bob = Identity::generate();
        let env = seal_envelope(
            ID,
            "scout::acme.postal.bot",
            "alice::acme.postal.bot",
            b"x",
            &bob.public_key_pem(),
            T0,
            60,
        )
        .unwrap();
        plane.put_hold(&env).unwrap();
        assert_eq!(
            plane.ack_hold(ID).unwrap(),
            HoldOk {
                ok: true,
                id: ID.into()
            }
        );
        assert_eq!(plane.ack_hold(ID), Err(PlaneError::NotFound));
        assert!(plane.list_hold().unwrap().items.is_empty());
        assert_eq!(classify_ack_status(404), Some(PlaneError::NotFound));
        assert_eq!(
            hold_ack_path(ID).unwrap(),
            "/postal/hold/01ARZ3NDEKTSV4RRFFQ69G5FAV/ack"
        );
        assert!(hold_ack_path("../x").is_err());
    }

    #[test]
    fn parse_hold_list_items_only() {
        let env = serde_json::json!({
            "id": ID,
            "to": "scout::acme.postal.bot",
            "from": "alice::acme.postal.bot",
            "size": 61,
            "expiry": 1,
            "ciphertext": "YQ=="
        });
        let ok = parse_hold_list(&serde_json::json!({"items":[env.clone()]})).unwrap();
        assert_eq!(ok.items.len(), 1);
        assert!(parse_hold_list(&serde_json::json!([env.clone()])).is_err());
        assert!(parse_hold_list(&serde_json::json!({"holds":[env]})).is_err());
        assert!(parse_hold_list(&serde_json::json!({"ok":true})).is_err());
    }

    #[test]
    fn events_path_and_empty_wait() {
        assert_eq!(events_path(None, 0), "/postal/events?wait=0");
        assert_eq!(
            events_path(Some("abc+def"), 30),
            "/postal/events?cursor=abc%2Bdef&wait=30"
        );
        assert_eq!(
            events_path(Some("x"), 99),
            "/postal/events?cursor=x&wait=60"
        );
        let plane = MemoryPlane::new();
        let page = plane.wait(None, Duration::from_secs(0)).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.cursor, "0");
    }

    #[test]
    fn poll_delay_is_30s_plus_or_minus_10() {
        let lo = Duration::from_secs(20);
        let hi = Duration::from_secs(40);
        assert_eq!(hold_poll_delay(0.0), lo);
        let top = hold_poll_delay(0.999_999);
        assert!(top >= lo && top <= hi, "{top:?}");
        assert!(hold_poll_delay(0.5) > lo && hold_poll_delay(0.5) < hi);
    }
}
