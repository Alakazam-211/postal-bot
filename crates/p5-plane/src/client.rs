use std::time::Duration;

use p5_core::PeerType;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{
    AcceptRequest, CheckoutView, DeviceAuth, DevicePollRequest, DeviceStartRequest, DeviceToken,
    HoldEnvelope, HoldList, HoldPutResponse, HostList, MeRequest, MeResponse, PairAddRequest,
    PairAddResponse, PairLists, PlaneError, UsageReport,
};

const TIMEOUT_SECS: u64 = 30;

/// HTTP client for CP-3 `/postal/*`.
#[derive(Debug, Clone)]
pub struct PlaneClient {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

impl PlaneClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build();
        Self {
            base_url: trim_slash(base_url.into()),
            token: token.into(),
            agent,
        }
    }

    pub fn put_me(
        &self,
        addr: &str,
        public_key_pem: &str,
        typ: PeerType,
    ) -> Result<MeResponse, PlaneError> {
        refuse_private_pem(public_key_pem)?;
        self.send_json(
            "PUT",
            "/postal/me",
            Some(&MeRequest {
                addr: addr.to_string(),
                public_key_pem: public_key_pem.to_string(),
                typ,
            }),
        )
    }

    pub fn list_pairs(&self, inbox_only: bool) -> Result<PairLists, PlaneError> {
        let path = if inbox_only {
            "/postal/pairs?inbox=1"
        } else {
            "/postal/pairs"
        };
        self.send_json("GET", path, None::<&()>)
    }

    pub fn add_pair(
        &self,
        from: &str,
        to: &str,
        typ: PeerType,
        public_key_pem: &str,
    ) -> Result<PairAddResponse, PlaneError> {
        refuse_private_pem(public_key_pem)?;
        self.send_json(
            "POST",
            "/postal/pair",
            Some(&PairAddRequest {
                from: from.to_string(),
                to: to.to_string(),
                typ,
                public_key_pem: public_key_pem.to_string(),
            }),
        )
    }

    pub fn accept(&self, id: &str, sas: &str) -> Result<(), PlaneError> {
        let path = pair_action_path(id, "accept")?;
        let _: serde_json::Value = self.send_json(
            "POST",
            &path,
            Some(&AcceptRequest {
                sas: sas.to_string(),
            }),
        )?;
        Ok(())
    }

    pub fn reject(&self, id: &str) -> Result<(), PlaneError> {
        let path = pair_action_path(id, "reject")?;
        let _: serde_json::Value = self.send_json("POST", &path, Some(&serde_json::json!({})))?;
        Ok(())
    }

    pub fn revoke(&self, id: &str) -> Result<(), PlaneError> {
        let path = pair_action_path(id, "revoke")?;
        let _: serde_json::Value = self.send_json("POST", &path, Some(&serde_json::json!({})))?;
        Ok(())
    }

    /// `PUT /postal/hold` upsert-by-id. Refuses plaintext before any socket.
    pub fn put_hold(&self, env: &HoldEnvelope) -> Result<HoldPutResponse, PlaneError> {
        crate::hold::refuse_plaintext(env)?;
        if !is_safe_id(&env.id) {
            return Err(PlaneError::BadHoldId);
        }
        self.send_json("PUT", "/postal/hold", Some(env))
    }

    /// Seal then PUT. Same plaintext lock as [`Self::put_hold`].
    pub fn put_hold_sealed(
        &self,
        id: &str,
        to: &str,
        from: &str,
        plaintext: &[u8],
        peer_spki_pem: &str,
    ) -> Result<HoldPutResponse, PlaneError> {
        let env = crate::hold::seal_envelope(
            id,
            to,
            from,
            plaintext,
            peer_spki_pem,
            Duration::from_secs(crate::hold::HOLD_TTL_SECS),
        )?;
        self.put_hold(&env)
    }

    pub fn list_hold(&self) -> Result<HoldList, PlaneError> {
        let v: serde_json::Value = self.send_json("GET", "/postal/hold", None::<&()>)?;
        crate::hold::parse_hold_list(v)
    }

    pub fn ack_hold(&self, id: &str) -> Result<(), PlaneError> {
        let path = hold_ack_path(id)?;
        let _: serde_json::Value = self.send_json("POST", &path, Some(&serde_json::json!({})))?;
        Ok(())
    }

    /// `GET /postal/usage` for this Connect label. 404 → plane has not cut the meter.
    pub fn usage(&self) -> Result<UsageReport, PlaneError> {
        self.send_json("GET", "/postal/usage", None::<&()>)
    }

    /// `GET /postal/hosts` — postal.bot labels this bearer may bind to a computer.
    pub fn list_hosts(&self) -> Result<HostList, PlaneError> {
        self.send_json("GET", "/postal/hosts", None::<&()>)
    }

    /// `POST /postal/cli/device` — start RFC 8628 device login (no bearer).
    pub fn start_device(&self) -> Result<DeviceAuth, PlaneError> {
        self.send_json(
            "POST",
            "/postal/cli/device",
            Some(&DeviceStartRequest {
                client: "p5".into(),
            }),
        )
    }

    /// `POST /postal/cli/device/token` — poll until the human approves.
    pub fn poll_device(&self, device_code: &str) -> Result<DeviceToken, PlaneError> {
        let code = device_code.trim();
        if code.is_empty() {
            return Err(PlaneError::Http {
                status: 400,
                message: "empty device_code".into(),
            });
        }
        self.send_json(
            "POST",
            "/postal/cli/device/token",
            Some(&DevicePollRequest {
                device_code: code.to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".into(),
            }),
        )
    }

    /// Verify a Stripe Checkout session against the Postal site (no Connect token).
    pub fn checkout_session(
        api_base: impl Into<String>,
        session_id: &str,
    ) -> Result<CheckoutView, PlaneError> {
        fetch_checkout_session(&api_base.into(), session_id)
    }

    fn send_json<T, B>(&self, method: &str, path: &str, body: Option<&B>) -> Result<T, PlaneError>
    where
        T: DeserializeOwned,
        B: Serialize,
    {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.agent.request(method, &url).set("Accept", "application/json");
        if !self.token.trim().is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.token));
        }
        let result = match body {
            Some(b) => req.set("Content-Type", "application/json").send_json(b),
            None => req.call(),
        };
        match result {
            Ok(resp) => resp.into_json().map_err(PlaneError::from),
            Err(ureq::Error::Status(code, resp)) => Err(status_err(code, resp)),
            Err(ureq::Error::Transport(t)) => Err(PlaneError::Transport(t.to_string())),
        }
    }
}

fn trim_slash(s: String) -> String {
    s.trim_end_matches('/').to_string()
}

fn is_checkout_session_id(id: &str) -> bool {
    let id = id.trim();
    id.starts_with("cs_")
        && id.len() < 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn fetch_checkout_session(api_base: &str, session_id: &str) -> Result<CheckoutView, PlaneError> {
    if !is_checkout_session_id(session_id) {
        return Err(PlaneError::Http {
            status: 400,
            message: "bad checkout session id".into(),
        });
    }
    let base = trim_slash(api_base.trim().to_string());
    let url = format!("{base}/api/session?id={session_id}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build();
    match agent.get(&url).set("Accept", "application/json").call() {
        Ok(resp) => resp.into_json().map_err(PlaneError::from),
        Err(ureq::Error::Status(code, resp)) => Err(status_err(code, resp)),
        Err(ureq::Error::Transport(t)) => Err(PlaneError::Transport(t.to_string())),
    }
}

fn refuse_private_pem(pem: &str) -> Result<(), PlaneError> {
    if pem.contains("PRIVATE") || pem.contains("BEGIN PRIVATE") {
        return Err(PlaneError::PrivateKey);
    }
    Ok(())
}

/// Pair ids are a path segment. Reject anything that could change the target.
fn pair_action_path(id: &str, action: &str) -> Result<String, PlaneError> {
    if !is_safe_id(id) {
        return Err(PlaneError::BadPairId);
    }
    Ok(format!("/postal/pair/{id}/{action}"))
}

fn hold_ack_path(id: &str) -> Result<String, PlaneError> {
    if !is_safe_id(id) {
        return Err(PlaneError::BadHoldId);
    }
    Ok(format!("/postal/hold/{id}/ack"))
}

fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn status_err(code: u16, resp: ureq::Response) -> PlaneError {
    let message = resp
        .into_string()
        .ok()
        .and_then(|s| {
            serde_json::from_str::<serde_json::Value>(&s)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.as_str())
                        .map(ToOwned::to_owned)
                })
                .or_else(|| {
                    let t = s.trim();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_string())
                    }
                })
        })
        .unwrap_or_else(|| "error".into());
    let err = message.trim();
    if err == "authorization_pending" {
        return PlaneError::AuthorizationPending;
    }
    if err == "slow_down" {
        return PlaneError::SlowDown;
    }
    if err == "access_denied" {
        return PlaneError::AccessDenied;
    }
    if err == "expired_token" {
        return PlaneError::ExpiredToken;
    }
    match code {
        401 => PlaneError::Unauthorized,
        403 => PlaneError::Forbidden(message),
        404 => PlaneError::NotFound,
        _ => PlaneError::Http {
            status: code,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MeRequest;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    struct Recorded {
        method: String,
        path: String,
        auth: String,
        body: String,
    }

    fn parse_http(buf: &[u8]) -> Option<Recorded> {
        let raw = std::str::from_utf8(buf).ok()?;
        let (head, rest) = raw.split_once("\r\n\r\n")?;
        let mut lines = head.split("\r\n");
        let start = lines.next()?;
        let mut parts = start.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let mut auth = String::new();
        let mut content_len = 0usize;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("authorization") {
                    auth = v.trim().to_string();
                }
                if k.eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse().unwrap_or(0);
                }
            }
        }
        if rest.len() < content_len {
            return None;
        }
        Some(Recorded {
            method,
            path,
            auth,
            body: rest[..content_len].to_string(),
        })
    }

    fn spawn_ok(status: u16, body: &str) -> (String, Arc<Mutex<Vec<Recorded>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rec = Arc::new(Mutex::new(Vec::new()));
        let rec2 = rec.clone();
        let body = body.to_string();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = ready_tx.send(());
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_nonblocking(false);
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                let rec = loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break parse_http(&buf),
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(r) = parse_http(&buf) {
                                break Some(r);
                            }
                        }
                        Err(_) => break parse_http(&buf),
                    }
                };
                if let Some(r) = rec {
                    rec2.lock().unwrap().push(r);
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        ready_rx.recv().unwrap();
        (format!("http://{addr}"), rec)
    }

    #[test]
    fn put_me_sends_public_pem_and_bearer() {
        let (url, rec) = spawn_ok(
            200,
            r#"{"ok":true,"addr":"alice::acme.postal.bot","fingerprint":"aa"}"#,
        );
        let c = PlaneClient::new(url, "k2c_test");
        let pem = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n";
        let out = c
            .put_me("alice::acme.postal.bot", pem, PeerType::Session)
            .unwrap();
        assert_eq!(out.addr, "alice::acme.postal.bot");
        assert_eq!(out.fingerprint, "aa");
        let got = rec.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].method, "PUT");
        assert_eq!(got[0].path, "/postal/me");
        assert_eq!(got[0].auth, "Bearer k2c_test");
        assert!(got[0].body.contains("BEGIN PUBLIC KEY"));
        assert!(!got[0].body.contains("PRIVATE"));
        let v: serde_json::Value = serde_json::from_str(&got[0].body).unwrap();
        assert_eq!(v["addr"], "alice::acme.postal.bot");
        assert_eq!(v["typ"], "session");
        assert!(v["public_key_pem"].as_str().unwrap().contains("PUBLIC KEY"));
    }

    #[test]
    fn put_me_body_is_public_only() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n";
        let body = serde_json::to_value(MeRequest {
            addr: "alice::acme.postal.bot".into(),
            public_key_pem: pem.into(),
            typ: PeerType::Session,
        })
        .unwrap();
        assert_eq!(body["typ"], "session");
        assert!(body["public_key_pem"].as_str().unwrap().contains("PUBLIC"));
        assert!(!body.to_string().contains("PRIVATE"));
        assert_eq!(body.as_object().unwrap().len(), 3);
    }

    #[test]
    fn put_me_refuses_private_pem_without_http() {
        let c = PlaneClient::new("http://127.0.0.1:1", "k2c_test");
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
        let err = c
            .put_me("alice::acme.postal.bot", pem, PeerType::Session)
            .unwrap_err();
        assert!(matches!(err, PlaneError::PrivateKey));
        assert!(matches!(
            c.add_pair(
                "alice::acme.postal.bot",
                "scout::acme.postal.bot",
                PeerType::Session,
                pem
            )
            .unwrap_err(),
            PlaneError::PrivateKey
        ));
    }

    #[test]
    fn pair_id_rejects_path_escape() {
        let c = PlaneClient::new("http://127.0.0.1:1", "k2c_test");
        for id in ["../x", "a/b", "a?b", "a#b", "", "pair/1", "id with space"] {
            assert!(
                matches!(c.accept(id, "000000").unwrap_err(), PlaneError::BadPairId),
                "{id}"
            );
            assert!(matches!(c.reject(id).unwrap_err(), PlaneError::BadPairId));
            assert!(matches!(c.revoke(id).unwrap_err(), PlaneError::BadPairId));
        }
        assert!(is_safe_id("pair-1"));
        assert!(is_safe_id("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!is_safe_id("../x"));
    }

    #[test]
    fn put_hold_refuses_plaintext_without_http() {
        let c = PlaneClient::new("http://127.0.0.1:1", "k2c_test");
        let env = HoldEnvelope {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: "scout::acme.postal.bot".into(),
            from: "alice::acme.postal.bot".into(),
            size: 12,
            expiry: 1,
            ciphertext: crate::hold::encode_ciphertext(b"secret cover"),
        };
        assert!(matches!(
            c.put_hold(&env).unwrap_err(),
            PlaneError::Plaintext
        ));
        let raw = HoldEnvelope {
            ciphertext: "hello world".into(),
            size: 0,
            ..env.clone()
        };
        assert!(matches!(
            c.put_hold(&raw).unwrap_err(),
            PlaneError::Plaintext
        ));
        let escaped = HoldEnvelope {
            id: "../x".into(),
            ciphertext: crate::hold::encode_ciphertext(b"nope"),
            ..env
        };
        // Plaintext is checked first so we never open a socket on either lock.
        assert!(matches!(
            c.put_hold(&escaped).unwrap_err(),
            PlaneError::Plaintext
        ));
    }

    #[test]
    fn put_hold_sends_sealed_blob_and_bearer() {
        let bob = p5_crypto::KeyPair::generate();
        let (url, rec) = spawn_ok(200, r#"{"ok":true,"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}"#);
        let c = PlaneClient::new(url, "k2c_test");
        let out = c
            .put_hold_sealed(
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "scout::acme.postal.bot",
                "alice::acme.postal.bot",
                b"secret cover",
                &bob.public_key_pem(),
            )
            .unwrap();
        assert_eq!(out.id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let got = rec.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].method, "PUT");
        assert_eq!(got[0].path, "/postal/hold");
        assert_eq!(got[0].auth, "Bearer k2c_test");
        assert!(!got[0].body.contains("secret cover"));
        let v: serde_json::Value = serde_json::from_str(&got[0].body).unwrap();
        assert_eq!(v["id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(v["to"], "scout::acme.postal.bot");
        assert_eq!(v["from"], "alice::acme.postal.bot");
        assert!(v["size"].as_u64().unwrap() > 0);
        assert!(v["expiry"].as_u64().unwrap() > 0);
        let blob = crate::hold::decode_ciphertext(v["ciphertext"].as_str().unwrap()).unwrap();
        assert!(p5_crypto::is_holdseal_v1(&blob));
    }

    #[test]
    fn list_hold_and_ack_paths() {
        let (url, rec) = spawn_ok(
            200,
            r#"{"items":[{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","to":"a::acme.postal.bot","from":"b::acme.postal.bot","size":1,"expiry":1,"ciphertext":"YQ=="}]}"#,
        );
        let c = PlaneClient::new(&url, "k2c_test");
        let list = c.list_hold().unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(rec.lock().unwrap()[0].method, "GET");
        assert_eq!(rec.lock().unwrap()[0].path, "/postal/hold");

        let (url, rec) = spawn_ok(200, r#"{"ok":true}"#);
        let c = PlaneClient::new(url, "k2c_test");
        c.ack_hold("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let got = rec.lock().unwrap();
        assert_eq!(got[0].method, "POST");
        assert_eq!(got[0].path, "/postal/hold/01ARZ3NDEKTSV4RRFFQ69G5FAV/ack");
        assert_eq!(got[0].auth, "Bearer k2c_test");

        let c = PlaneClient::new("http://127.0.0.1:1", "k2c_test");
        assert!(matches!(
            c.ack_hold("../x").unwrap_err(),
            PlaneError::BadHoldId
        ));
    }
}
