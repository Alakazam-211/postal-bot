//! Live HTTPS to the peer. Not the control plane.

use std::time::Duration;

use serde::Serialize;

/// Outcome of `POST {live}/p5/msg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveSend {
    /// Bytes already on the peer. Never HOLD after this.
    Delivered { status: u16 },
    /// Tunnel / host is known down: TCP refuse, 404, 503 `host_down`.
    DefiniteMiss { why: String },
    /// Ambiguous: timeout, 429, DNS, other HTTP. Never HOLD — peer may be live.
    SoftMiss { why: String },
}

impl LiveSend {
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered { .. })
    }
}

/// POST JSON to `url` (already includes `/p5/msg`).
pub fn live_send(url: &str, timeout: Duration, payload: &impl Serialize) -> LiveSend {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    match agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(payload)
    {
        Ok(resp) => LiveSend::Delivered {
            status: resp.status(),
        },
        Err(ureq::Error::Status(code, resp)) => classify_status(code, &read_body(resp)),
        Err(ureq::Error::Transport(t)) => classify_transport(&t.to_string()),
    }
}

fn read_body(resp: ureq::Response) -> String {
    resp.into_string().unwrap_or_default()
}

fn classify_status(code: u16, body: &str) -> LiveSend {
    match code {
        404 => LiveSend::DefiniteMiss { why: "404".into() },
        429 => LiveSend::SoftMiss { why: "429".into() },
        503 if is_host_down(body) => LiveSend::DefiniteMiss {
            why: "503 host_down".into(),
        },
        code => LiveSend::SoftMiss {
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

fn classify_transport(msg: &str) -> LiveSend {
    let lower = msg.to_ascii_lowercase();
    // Only a refused connect is a definite miss. Timeout/DNS stay soft.
    if lower.contains("connection refused") {
        return LiveSend::DefiniteMiss {
            why: "connection refused".into(),
        };
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return LiveSend::SoftMiss {
            why: "timeout".into(),
        };
    }
    LiveSend::SoftMiss { why: msg.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn spawn_status(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                // Drain the full request (headers + Content-Length) before
                // writing. A short read + close resets ureq mid-POST.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if request_complete(&buf) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/p5/msg")
    }

    fn request_complete(buf: &[u8]) -> bool {
        let raw = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let (head, rest) = match raw.split_once("\r\n\r\n") {
            Some(p) => p,
            None => return false,
        };
        let mut content_len = 0usize;
        for line in head.split("\r\n").skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse().unwrap_or(0);
                }
            }
        }
        rest.len() >= content_len
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "to": "scout::acme.postal.bot",
            "from": "alice::acme.postal.bot",
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "body": "hi"
        })
    }

    #[test]
    fn live_2xx_is_delivered() {
        let url = spawn_status(200, r#"{"status":"delivered"}"#);
        match live_send(&url, Duration::from_secs(2), &payload()) {
            LiveSend::Delivered { status } => assert_eq!(status, 200),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn live_404_is_definite() {
        let url = spawn_status(404, r#"{"error":"not_found"}"#);
        assert!(matches!(
            live_send(&url, Duration::from_secs(2), &payload()),
            LiveSend::DefiniteMiss { .. }
        ));
    }

    #[test]
    fn live_503_host_down_is_definite() {
        let url = spawn_status(503, r#"{"error":"host_down"}"#);
        assert!(matches!(
            live_send(&url, Duration::from_secs(2), &payload()),
            LiveSend::DefiniteMiss { why } if why.contains("host_down")
        ));
    }

    #[test]
    fn live_503_other_is_soft() {
        let url = spawn_status(503, r#"{"error":"overloaded"}"#);
        assert!(matches!(
            live_send(&url, Duration::from_secs(2), &payload()),
            LiveSend::SoftMiss { .. }
        ));
    }

    #[test]
    fn live_429_is_soft() {
        let url = spawn_status(429, r#"{"error":"rate"}"#);
        assert!(matches!(
            live_send(&url, Duration::from_secs(2), &payload()),
            LiveSend::SoftMiss { why } if why == "429"
        ));
    }

    #[test]
    fn live_refuse_is_definite() {
        match live_send(
            "http://127.0.0.1:1/p5/msg",
            Duration::from_secs(2),
            &payload(),
        ) {
            LiveSend::DefiniteMiss { why } => assert!(why.contains("refused")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn live_timeout_is_soft() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept so connect succeeds, then stall so the client times out.
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(2));
                drop(stream);
            }
        });
        let url = format!("http://{addr}/p5/msg");
        match live_send(&url, Duration::from_millis(150), &payload()) {
            LiveSend::SoftMiss { why } => {
                assert!(
                    why.contains("timeout") || why.contains("timed out"),
                    "{why}"
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
