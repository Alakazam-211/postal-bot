use std::time::Duration;

use p5_core::PeerType;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{
    AcceptRequest, MeRequest, MeResponse, PairAddRequest, PairAddResponse, PairLists, PlaneError,
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
        debug_assert!(
            !public_key_pem.contains("PRIVATE"),
            "refusing to even construct a private-key PUT"
        );
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
        debug_assert!(!public_key_pem.contains("PRIVATE"));
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
        let path = format!("/postal/pair/{id}/accept");
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
        let path = format!("/postal/pair/{id}/reject");
        let _: serde_json::Value = self.send_json("POST", &path, Some(&serde_json::json!({})))?;
        Ok(())
    }

    pub fn revoke(&self, id: &str) -> Result<(), PlaneError> {
        let path = format!("/postal/pair/{id}/revoke");
        let _: serde_json::Value = self.send_json("POST", &path, Some(&serde_json::json!({})))?;
        Ok(())
    }

    fn send_json<T, B>(&self, method: &str, path: &str, body: Option<&B>) -> Result<T, PlaneError>
    where
        T: DeserializeOwned,
        B: Serialize,
    {
        let url = format!("{}{path}", self.base_url);
        let req = self
            .agent
            .request(method, &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/json");
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

    struct Recorded {
        method: String,
        path: String,
        auth: String,
        body: String,
    }

    fn spawn_ok(status: u16, body: &str) -> (String, Arc<Mutex<Vec<Recorded>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rec = Arc::new(Mutex::new(Vec::new()));
        let rec2 = rec.clone();
        let body = body.to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..n]);
                let mut lines = raw.split("\r\n");
                let start = lines.next().unwrap_or("");
                let mut parts = start.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut auth = String::new();
                let mut content_len = 0usize;
                for line in lines.by_ref() {
                    if line.is_empty() {
                        break;
                    }
                    if let Some(v) = line
                        .split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                        .map(|(_, v)| v.trim().to_string())
                    {
                        auth = v;
                    }
                    if let Some(v) = line
                        .split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse().ok())
                    {
                        content_len = v;
                    }
                }
                let rest = lines.next().unwrap_or("");
                let req_body = if content_len > 0 {
                    rest.chars().take(content_len).collect()
                } else {
                    rest.to_string()
                };
                rec2.lock().unwrap().push(Recorded {
                    method,
                    path,
                    auth,
                    body: req_body,
                });
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
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
}
