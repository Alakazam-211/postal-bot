//! Outbound live HTTPS: `POST https://<host>/p5/msg` with pairing-key proof.
//!
//! This crate never HOLDs. Ambiguous misses (timeout / 429 / no status) and
//! definite misses (TCP refuse / 404 / 503 `host_down`) both stay queued;
//! `hold_later` only records that P5-9 *may* HOLD.

use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p5_crypto::{proof_create, proof_verify, CryptoError, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ureq::ErrorKind;

#[cfg(any(test, feature = "test-util"))]
pub mod mock;

pub const MSG_PATH: &str = "/p5/msg";
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
pub const PROOF_HEADER: &str = "X-P5-Proof";
pub const TIMESTAMP_HEADER: &str = "X-P5-Timestamp";
pub const NONCE_HEADER: &str = "X-P5-Nonce";
pub const FROM_HEADER: &str = "X-P5-From";
pub const AUTH_SCHEME: &str = "P5-Msg";

/// Default live POST deadline. Flaps look like this, so it must not HOLD.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct LiveRequest {
    pub base_url: String,
    pub to: String,
    pub from: String,
    pub id: String,
    pub wake: bool,
    pub mode: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveResult {
    Delivered {
        already: bool,
    },
    Queued {
        last_error: String,
        /// TCP refuse / 404 / 503 `host_down`. Never HOLD here.
        hold_later: bool,
    },
    Permanent {
        reason: &'static str,
        hint: String,
    },
}

#[derive(Clone)]
pub struct LiveClient {
    agent: ureq::Agent,
}

impl fmt::Debug for LiveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiveClient")
    }
}

impl Default for LiveClient {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveClient {
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .build();
        Self { agent }
    }

    pub fn with_tls(timeout: Duration, tls: Arc<rustls::ClientConfig>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .tls_config(tls)
            .build();
        Self { agent }
    }

    /// Trust a single test CA/leaf DER. Production uses webpki roots.
    pub fn with_root_der(timeout: Duration, der: &[u8]) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(der.to_vec()))
            .map_err(|e| format!("live tls root: {e}"))?;
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self::with_tls(timeout, Arc::new(cfg)))
    }

    /// Sign then POST. Caller must not invoke this without a pairing key.
    pub fn send(&self, key: &KeyPair, req: &LiveRequest) -> LiveResult {
        let url = msg_url(&req.base_url);
        let payload = MsgBody {
            to: req.to.clone(),
            from: req.from.clone(),
            id: req.id.clone(),
            wake: req.wake,
            mode: req.mode.clone(),
            body: req.body.clone(),
        };
        let bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(_) => return queued("no_status", false),
        };
        let content_sha = to_hex(&Sha256::digest(&bytes));
        let timestamp = unix_secs().to_string();
        let nonce = ulid::Ulid::new().to_string();
        let proof = match proof_create(key, "POST", MSG_PATH, &content_sha, &timestamp, &nonce) {
            Ok(sig) => sig,
            Err(_) => {
                // No proof → never dial public (or any) hosts.
                return queued("no_proof", false);
            }
        };
        let proof_hex = to_hex(&proof);

        let result = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .set(IDEMPOTENCY_HEADER, &req.id)
            .set(PROOF_HEADER, &proof_hex)
            .set(TIMESTAMP_HEADER, &timestamp)
            .set(NONCE_HEADER, &nonce)
            .set(FROM_HEADER, &req.from)
            .set("Authorization", &format!("{AUTH_SCHEME} {proof_hex}"))
            .send_bytes(&bytes);

        match result {
            Ok(resp) => classify_http(resp.status(), read_body(resp)),
            Err(ureq::Error::Status(code, resp)) => classify_http(code, read_body(resp)),
            Err(ureq::Error::Transport(t)) => classify_transport(t),
        }
    }
}

#[derive(Serialize)]
struct MsgBody {
    to: String,
    from: String,
    id: String,
    wake: bool,
    mode: String,
    body: String,
}

fn msg_url(base: &str) -> String {
    let base = base.trim().trim_end_matches('/');
    format!("{base}{MSG_PATH}")
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_body(resp: ureq::Response) -> String {
    resp.into_string().unwrap_or_default()
}

fn classify_http(code: u16, body: String) -> LiveResult {
    if (200..300).contains(&code) {
        let already = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("already").and_then(|a| a.as_bool()))
            .unwrap_or(false);
        return LiveResult::Delivered { already };
    }
    if code == 429 {
        return queued("429", false);
    }
    if code == 404 {
        return queued("404", true);
    }
    if code == 503 {
        let host_down = body.contains("host_down");
        let err = if host_down { "host_down" } else { "503" };
        return queued(err, host_down);
    }
    if code == 401 || code == 403 {
        // Bare unauthorized (no proof / WAF) is retryable. Pairing rejection
        // is `reason`/`error` = `not_connected` after a proof was checked.
        if json_eq(&body, "not_connected") {
            return LiveResult::Permanent {
                reason: "not_connected",
                hint: body,
            };
        }
        if json_eq(&body, "gated") {
            return LiveResult::Permanent {
                reason: "gated",
                hint: body,
            };
        }
        let err = if code == 401 { "401" } else { "403" };
        return queued(err, false);
    }
    if code == 409 {
        return LiveResult::Permanent {
            reason: "no_agent",
            hint: body,
        };
    }
    queued(format!("http_{code}"), false)
}

fn classify_transport(t: ureq::Transport) -> LiveResult {
    if let Some(ioe) = transport_io(&t) {
        match ioe.kind() {
            io::ErrorKind::ConnectionRefused => {
                return queued("connection_refused", true);
            }
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                return queued("timeout", false);
            }
            _ => {}
        }
    }
    let kind = t.kind();
    let lower = t.to_string().to_lowercase();
    if kind == ErrorKind::ConnectionFailed || lower.contains("connection refused") {
        return queued("connection_refused", true);
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return queued("timeout", false);
    }
    queued("no_status", false)
}

fn transport_io(t: &ureq::Transport) -> Option<&io::Error> {
    let mut src = t.source();
    while let Some(err) = src {
        if let Some(ioe) = err.downcast_ref::<io::Error>() {
            return Some(ioe);
        }
        src = err.source();
    }
    None
}

fn queued(last_error: impl Into<String>, hold_later: bool) -> LiveResult {
    LiveResult::Queued {
        last_error: last_error.into(),
        hold_later,
    }
}

fn json_eq(body: &str, want: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    ["reason", "error"]
        .iter()
        .any(|k| v.get(*k).and_then(|x| x.as_str()) == Some(want))
}

/// SHA-256 of the exact POST body, lowercase hex (proof transcript).
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// Verify a `POST /p5/msg` pairing-key proof against the peer's SPKI.
pub fn verify_post_msg(
    spki_pem: &str,
    body: &[u8],
    proof_hex: &str,
    timestamp: &str,
    nonce: &str,
) -> Result<(), CryptoError> {
    let sha = sha256_hex(body);
    let proof = from_hex(proof_hex).ok_or(CryptoError::Proof)?;
    proof_verify(spki_pem, "POST", MSG_PATH, &sha, timestamp, nonce, &proof)
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Hang TCP (no TLS reply). Used to force a live timeout.
pub fn spawn_hang() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("hang bind");
    let addr = listener.local_addr().expect("hang addr");
    std::thread::spawn(move || {
        if let Ok((_stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(60));
        }
    });
    format!("https://{addr}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use p5_crypto::{proof_verify, KeyPair};

    #[test]
    fn two_xx_is_delivered_and_sends_proof() {
        let key = KeyPair::generate();
        let peer = mock::HttpsPeer::spawn(
            200,
            r#"{"already":false,"status":"delivered","typ":"session"}"#,
        );
        let client = LiveClient::with_root_der(Duration::from_secs(2), &peer.cert_der).unwrap();
        let req = sample(&peer.base_url);
        let got = client.send(&key, &req);
        assert_eq!(got, LiveResult::Delivered { already: false });
        let rec = peer.recorded();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].method, "POST");
        assert_eq!(rec[0].path, MSG_PATH);
        let proof = rec[0].header(PROOF_HEADER).expect("X-P5-Proof");
        assert_eq!(proof.len(), 128);
        assert!(proof
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(rec[0].header(IDEMPOTENCY_HEADER), Some(req.id.as_str()));
        assert_eq!(rec[0].header(FROM_HEADER), Some(req.from.as_str()));
        let ts = rec[0].header(TIMESTAMP_HEADER).unwrap();
        let nonce = rec[0].header(NONCE_HEADER).unwrap();
        let auth = rec[0].header("authorization").unwrap();
        assert_eq!(auth, format!("{AUTH_SCHEME} {proof}"));
        let sha = sha256_hex(rec[0].body.as_bytes());
        let sig = from_hex(proof).unwrap();
        proof_verify(
            &key.public_key_pem(),
            "POST",
            MSG_PATH,
            &sha,
            ts,
            nonce,
            &sig,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&rec[0].body).unwrap();
        assert_eq!(v["id"], req.id);
        assert_eq!(v["to"], req.to);
        assert_eq!(v["from"], req.from);
    }

    #[test]
    fn timeout_stays_queued_not_hold() {
        let key = KeyPair::generate();
        let base = spawn_hang();
        let client = LiveClient::with_timeout(Duration::from_millis(250));
        let got = client.send(&key, &sample(&base));
        match got {
            LiveResult::Queued {
                last_error,
                hold_later,
            } => {
                assert!(!hold_later, "timeout must never HOLD");
                assert!(
                    last_error == "timeout" || last_error == "no_status",
                    "{last_error}"
                );
            }
            other => panic!("expected queued, got {other:?}"),
        }
    }

    #[test]
    fn host_down_503_queued_not_held() {
        let key = KeyPair::generate();
        let peer = mock::HttpsPeer::spawn(503, r#"{"error":"host_down"}"#);
        let client = LiveClient::with_root_der(Duration::from_secs(2), &peer.cert_der).unwrap();
        let got = client.send(&key, &sample(&peer.base_url));
        assert_eq!(
            got,
            LiveResult::Queued {
                last_error: "host_down".into(),
                hold_later: true,
            }
        );
    }

    #[test]
    fn refuse_is_queued_hold_later() {
        let key = KeyPair::generate();
        let client = LiveClient::with_timeout(Duration::from_secs(1));
        let got = client.send(&key, &sample("https://127.0.0.1:1"));
        match got {
            LiveResult::Queued {
                last_error,
                hold_later,
            } => {
                assert!(hold_later);
                assert_eq!(last_error, "connection_refused");
            }
            other => panic!("expected refused queued, got {other:?}"),
        }
    }

    #[test]
    fn four_two_nine_queued_never_hold() {
        let key = KeyPair::generate();
        let peer = mock::HttpsPeer::spawn(429, r#"{"error":"rate"}"#);
        let client = LiveClient::with_root_der(Duration::from_secs(2), &peer.cert_der).unwrap();
        let got = client.send(&key, &sample(&peer.base_url));
        assert_eq!(
            got,
            LiveResult::Queued {
                last_error: "429".into(),
                hold_later: false,
            }
        );
    }

    #[test]
    fn unauthorized_401_stays_queued() {
        let key = KeyPair::generate();
        let peer = mock::HttpsPeer::spawn(401, r#"{"error":"unauthorized"}"#);
        let client = LiveClient::with_root_der(Duration::from_secs(2), &peer.cert_der).unwrap();
        let got = client.send(&key, &sample(&peer.base_url));
        assert_eq!(
            got,
            LiveResult::Queued {
                last_error: "401".into(),
                hold_later: false,
            }
        );
    }

    #[test]
    fn not_connected_401_is_permanent() {
        let key = KeyPair::generate();
        let peer =
            mock::HttpsPeer::spawn(401, r#"{"error":"not_connected","reason":"not_connected"}"#);
        let client = LiveClient::with_root_der(Duration::from_secs(2), &peer.cert_der).unwrap();
        match client.send(&key, &sample(&peer.base_url)) {
            LiveResult::Permanent { reason, .. } => assert_eq!(reason, "not_connected"),
            other => panic!("expected permanent, got {other:?}"),
        }
    }

    fn sample(base: &str) -> LiveRequest {
        LiveRequest {
            base_url: base.into(),
            to: "scout::peer.postal.bot".into(),
            from: "alice::acme.postal.bot".into(),
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            wake: true,
            mode: "live".into(),
            body: "hello scout".into(),
        }
    }
}
