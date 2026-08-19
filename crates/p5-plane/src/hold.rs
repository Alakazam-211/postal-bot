//! Hold envelope helpers. Cloud never sees plaintext.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p5_crypto::{is_holdseal_v1, seal, SealAad};
use serde_json::Value;

use crate::{HoldEnvelope, HoldList, PlaneError};

/// Hold TTL. Plane may GC after this.
pub const HOLD_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Agent poll target when `P5_HOLD=1`.
pub const HOLD_POLL_SECS: u64 = 30;
/// Jitter around [`HOLD_POLL_SECS`] so pollers do not sync.
pub const HOLD_POLL_JITTER_SECS: u64 = 10;

/// `30s ± 10s`. `unit` is in `[0, 1)`.
pub fn hold_poll_delay(unit: f64) -> Duration {
    let unit = unit.clamp(0.0, 0.999_999);
    let lo = (HOLD_POLL_SECS.saturating_sub(HOLD_POLL_JITTER_SECS)) as f64;
    let span = (2 * HOLD_POLL_JITTER_SECS) as f64;
    Duration::from_secs_f64(lo + unit * span)
}

pub fn encode_ciphertext(blob: &[u8]) -> String {
    B64.encode(blob)
}

pub fn decode_ciphertext(s: &str) -> Result<Vec<u8>, PlaneError> {
    B64.decode(s.trim()).map_err(|_| PlaneError::Plaintext)
}

/// Fail closed: PUT body must be HoldSeal-v1, never the cover text.
pub fn refuse_plaintext(env: &HoldEnvelope) -> Result<Vec<u8>, PlaneError> {
    let blob = decode_ciphertext(&env.ciphertext)?;
    if !is_holdseal_v1(&blob) {
        return Err(PlaneError::Plaintext);
    }
    if env.size != 0 && env.size != blob.len() as u64 {
        return Err(PlaneError::Plaintext);
    }
    Ok(blob)
}

pub fn expiry_unix(ttl: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(ttl)
        .as_secs()
}

pub fn seal_envelope(
    id: &str,
    to: &str,
    from: &str,
    plaintext: &[u8],
    peer_spki_pem: &str,
    ttl: Duration,
) -> Result<HoldEnvelope, PlaneError> {
    let aad = SealAad {
        id: id.to_string(),
        from: from.to_string(),
        to: to.to_string(),
    };
    let blob =
        seal(peer_spki_pem, plaintext, &aad).map_err(|e| PlaneError::Crypto(e.to_string()))?;
    Ok(HoldEnvelope {
        id: id.to_string(),
        to: to.to_string(),
        from: from.to_string(),
        size: blob.len() as u64,
        expiry: expiry_unix(ttl),
        ciphertext: encode_ciphertext(&blob),
    })
}

pub fn parse_hold_list(v: Value) -> Result<HoldList, PlaneError> {
    if v.is_array() {
        return Ok(HoldList {
            items: serde_json::from_value(v)?,
        });
    }
    if let Some(items) = v.get("items").cloned() {
        return Ok(HoldList {
            items: serde_json::from_value(items)?,
        });
    }
    if let Some(holds) = v.get("holds").cloned() {
        return Ok(HoldList {
            items: serde_json::from_value(holds)?,
        });
    }
    Ok(HoldList::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p5_crypto::KeyPair;

    const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    #[test]
    fn poll_delay_is_30s_plus_or_minus_10() {
        let lo = Duration::from_secs(20);
        let hi = Duration::from_secs(40);
        assert_eq!(hold_poll_delay(0.0), lo);
        let top = hold_poll_delay(0.999_999);
        assert!(top >= lo && top <= hi, "{top:?}");
        assert!(hold_poll_delay(0.5) > lo);
        assert!(hold_poll_delay(0.5) < hi);
    }

    #[test]
    fn refuse_plaintext_catches_cover_text() {
        let env = HoldEnvelope {
            id: ID.into(),
            to: "scout::acme.postal.bot".into(),
            from: "alice::acme.postal.bot".into(),
            size: 5,
            expiry: expiry_unix(Duration::from_secs(60)),
            ciphertext: encode_ciphertext(b"hello"),
        };
        assert!(matches!(refuse_plaintext(&env), Err(PlaneError::Plaintext)));
        let raw = HoldEnvelope {
            ciphertext: "hello world".into(),
            size: 0,
            ..env
        };
        assert!(matches!(refuse_plaintext(&raw), Err(PlaneError::Plaintext)));
    }

    #[test]
    fn seal_envelope_is_holdseal_v1() {
        let bob = KeyPair::generate();
        let env = seal_envelope(
            ID,
            "scout::acme.postal.bot",
            "alice::acme.postal.bot",
            b"secret cover",
            &bob.public_key_pem(),
            Duration::from_secs(HOLD_TTL_SECS),
        )
        .unwrap();
        let blob = refuse_plaintext(&env).unwrap();
        assert!(is_holdseal_v1(&blob));
        assert_eq!(env.size, blob.len() as u64);
        assert!(!env.ciphertext.contains("secret cover"));
    }

    #[test]
    fn parse_hold_list_shapes() {
        let env = serde_json::json!({
            "id": ID,
            "to": "scout::acme.postal.bot",
            "from": "alice::acme.postal.bot",
            "size": 1,
            "expiry": 1,
            "ciphertext": "YQ=="
        });
        let a = parse_hold_list(serde_json::json!([env.clone()])).unwrap();
        assert_eq!(a.items.len(), 1);
        let b = parse_hold_list(serde_json::json!({"items":[env.clone()]})).unwrap();
        assert_eq!(b.items.len(), 1);
        let c = parse_hold_list(serde_json::json!({"holds":[env]})).unwrap();
        assert_eq!(c.items.len(), 1);
        assert!(parse_hold_list(serde_json::json!({"ok":true}))
            .unwrap()
            .items
            .is_empty());
    }
}
