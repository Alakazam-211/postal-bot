//! Local Sand / Grok Bot hop for type `turn`.
//!
//! Public path is HTTP `sendPrompt` on the loopback gateway. Never invent a
//! PTY and never call SendToAgent (in-app only).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};

use p5_core::PostalAddr;
use serde_json::json;

pub const DEFAULT_TURN_HEALTH: &str = "http://127.0.0.1:1340/health";
pub const TURN_LIMIT_PER_HOUR: usize = 12;
const TURN_WINDOW: Duration = Duration::from_secs(60 * 60);
const TURN_HTTP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnConfig {
    pub health_url: String,
    pub prompt_url: String,
    pub agent_id: String,
    pub token: Option<String>,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self::loopback_default()
    }
}

impl TurnConfig {
    pub fn loopback_default() -> Self {
        Self {
            health_url: DEFAULT_TURN_HEALTH.into(),
            prompt_url: prompt_url_from_health(DEFAULT_TURN_HEALTH),
            agent_id: String::new(),
            token: None,
        }
    }

    pub fn from_env() -> Self {
        let health = std::env::var("P5_TURN_HEALTH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_TURN_HEALTH.to_string());
        let prompt = std::env::var("P5_TURN_PROMPT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| prompt_url_from_health(&health));
        let agent_id = std::env::var("P5_TURN_AGENT_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
        let token = std::env::var("P5_TURN_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            health_url: health,
            prompt_url: prompt,
            agent_id,
            token,
        }
    }

    pub fn resolve_agent_id(&self, fallback: Option<&str>) -> String {
        if !self.agent_id.is_empty() {
            return self.agent_id.clone();
        }
        fallback.unwrap_or("").to_string()
    }
}

pub fn prompt_url_from_health(health: &str) -> String {
    match parse_http_url(health) {
        Ok(u) => format!("http://{}:{}/api/sendPrompt", u.host, u.port),
        Err(_) => "http://127.0.0.1:1340/api/sendPrompt".into(),
    }
}

/// Sliding window: 12 successful turns / hour / sending peer.
#[derive(Debug, Default)]
pub struct TurnLimiter {
    events: HashMap<PostalAddr, Vec<Instant>>,
}

impl TurnLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, from: &PostalAddr, now: Instant) -> bool {
        self.prune(from, now);
        self.events.get(from).map(|v| v.len()).unwrap_or(0) < TURN_LIMIT_PER_HOUR
    }

    pub fn record(&mut self, from: &PostalAddr, now: Instant) {
        self.events.entry(from.clone()).or_default().push(now);
    }

    /// Check and consume one slot under the caller's lock (HTTP + UDS share this map).
    pub fn try_reserve(&mut self, from: &PostalAddr, now: Instant) -> bool {
        if !self.allow(from, now) {
            return false;
        }
        self.record(from, now);
        true
    }

    /// Drop a reservation that did not become a billed sendPrompt.
    pub fn release(&mut self, from: &PostalAddr, at: Instant) {
        if let Some(times) = self.events.get_mut(from) {
            if let Some(i) = times.iter().rposition(|t| *t == at) {
                times.remove(i);
            }
            if times.is_empty() {
                self.events.remove(from);
            }
        }
    }

    fn prune(&mut self, from: &PostalAddr, now: Instant) {
        if let Some(times) = self.events.get_mut(from) {
            times.retain(|t| now.duration_since(*t) < TURN_WINDOW);
            if times.is_empty() {
                self.events.remove(from);
            }
        }
    }
}

#[derive(Debug)]
pub enum TurnNetError {
    Url(String),
    Connect(String),
    Status(u16),
}

impl std::fmt::Display for TurnNetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(msg) | Self::Connect(msg) => f.write_str(msg),
            Self::Status(code) => write!(f, "turn gateway HTTP {code}"),
        }
    }
}

impl std::error::Error for TurnNetError {}

pub fn health_up(cfg: &TurnConfig) -> Result<(), TurnNetError> {
    let (status, _) = http_exchange("GET", &cfg.health_url, None, None, TURN_HTTP_TIMEOUT)?;
    if status == 200 {
        Ok(())
    } else {
        Err(TurnNetError::Status(status))
    }
}

pub fn send_prompt(
    cfg: &TurnConfig,
    from: &PostalAddr,
    body: &str,
    agent_id: &str,
    nonce: &str,
) -> Result<(), TurnNetError> {
    let prompt = format!("[from {from}] [p5] {body}");
    let payload = json!({
        "agentId": agent_id,
        "prompt": prompt,
        "clientNonce": nonce,
    })
    .to_string();
    let (status, _) = http_exchange(
        "POST",
        &cfg.prompt_url,
        Some(payload.as_bytes()),
        cfg.token.as_deref(),
        Duration::from_secs(10),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(TurnNetError::Status(status))
    }
}

struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(raw: &str) -> Result<HttpUrl, TurnNetError> {
    let raw = raw.trim();
    let rest = raw
        .strip_prefix("http://")
        .ok_or_else(|| TurnNetError::Url("turn URL must be http:// on loopback".into()))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        return Err(TurnNetError::Url("turn URL missing host".into()));
    }
    let (host, port) = if let Some((h, p)) = split_host_port(hostport) {
        let port: u16 = p
            .parse()
            .map_err(|_| TurnNetError::Url(format!("bad turn URL port {p:?}")))?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 80)
    };
    if !host_is_loopback(&host) {
        return Err(TurnNetError::Url(
            "turn gateway must be loopback (never dial a remote Sand)".into(),
        ));
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Ok(HttpUrl { host, port, path })
}

fn split_host_port(hostport: &str) -> Option<(&str, &str)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host, port));
    }
    hostport.rsplit_once(':')
}

fn host_is_loopback(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn http_exchange(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), TurnNetError> {
    let parsed = parse_http_url(url)?;
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port)).map_err(|e| {
        TurnNetError::Connect(format!("turn gateway {}:{}: {e}", parsed.host, parsed.port))
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n",
        path = parsed.path,
        host = parsed.host,
        port = parsed.port,
    );
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        req.push_str("Authorization: Bearer ");
        req.push_str(token);
        req.push_str("\r\n");
    }
    if let Some(body) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream
            .write_all(req.as_bytes())
            .and_then(|_| stream.write_all(body))
            .map_err(|e| TurnNetError::Connect(e.to_string()))?;
    } else {
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .map_err(|e| TurnNetError::Connect(e.to_string()))?;
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| TurnNetError::Connect(e.to_string()))?;
    parse_http_response(&buf)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), TurnNetError> {
    let text = String::from_utf8_lossy(raw);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| TurnNetError::Connect("turn gateway returned no HTTP headers".into()))?;
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TurnNetError::Connect(format!("bad HTTP status line {status_line:?}")))?;
    Ok((status, rest.as_bytes().to_vec()))
}

#[cfg(test)]
pub(crate) struct MockSand {
    pub prompts: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl MockSand {
    pub fn spawn(health: u16, prompt: u16) -> Self {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;

        let health = Arc::new(AtomicU16::new(health));
        let prompt = Arc::new(AtomicU16::new(prompt));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&prompts);
        let stop_flag = Arc::clone(&stop);
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let req = read_http_request(&mut stream);
                        let (status, body) = if req.starts_with("GET /health") {
                            (health.load(Ordering::Relaxed), r#"{"ok":true}"#)
                        } else if req.contains("POST /api/sendPrompt") {
                            if let Some(json) = request_json(&req) {
                                captured.lock().unwrap().push(json);
                            }
                            (prompt.load(Ordering::Relaxed), r#"{"ok":true}"#)
                        } else {
                            (404, r#"{"error":"not_found"}"#)
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            prompts,
            addr,
            stop,
            handle: Some(handle),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn config(&self) -> TurnConfig {
        TurnConfig {
            health_url: self.url("/health"),
            prompt_url: self.url("/api/sendPrompt"),
            agent_id: "sand-1".into(),
            token: None,
        }
    }
}

#[cfg(test)]
impl Drop for MockSand {
    fn drop(&mut self) {
        use std::io::Write;
        use std::sync::atomic::Ordering;

        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut s) = TcpStream::connect(self.addr) {
            let _ = s
                .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_headers_end(&buf) {
                    let head = String::from_utf8_lossy(&buf[..pos]);
                    let want = head.lines().find_map(|l| {
                        l.split_once(':').and_then(|(k, v)| {
                            k.eq_ignore_ascii_case("content-length")
                                .then_some(v.trim().parse::<usize>().unwrap_or(0))
                        })
                    });
                    if let Some(len) = want {
                        while buf.len() < pos + len {
                            match stream.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => break,
                            }
                        }
                    }
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

#[cfg(test)]
fn request_json(req: &str) -> Option<serde_json::Value> {
    let body = req
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| req.split("\n\n").nth(1))?;
    serde_json::from_str(body.trim_end_matches('\0').trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_200_and_prompt_roundtrip() {
        let sand = MockSand::spawn(200, 200);
        let cfg = sand.config();
        health_up(&cfg).unwrap();
        send_prompt(
            &cfg,
            &"alice::acme.postal.bot".parse().unwrap(),
            "ship it",
            "sand-1",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        .unwrap();
        let prompts = sand.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["agentId"], "sand-1");
        assert_eq!(
            prompts[0]["prompt"],
            "[from alice::acme.postal.bot] [p5] ship it"
        );
        assert_eq!(prompts[0]["clientNonce"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn health_non_200_is_down() {
        let sand = MockSand::spawn(503, 200);
        assert!(health_up(&sand.config()).is_err());
        assert!(sand.prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn refuse_non_loopback_gateway() {
        let cfg = TurnConfig {
            health_url: "http://1.2.3.4:1340/health".into(),
            prompt_url: "http://1.2.3.4:1340/api/sendPrompt".into(),
            agent_id: "x".into(),
            token: None,
        };
        match health_up(&cfg) {
            Err(TurnNetError::Url(msg)) => assert!(msg.contains("loopback"), "{msg}"),
            other => panic!("expected Url, got {other:?}"),
        }
    }

    #[test]
    fn limiter_is_12_per_hour_per_peer() {
        let mut lim = TurnLimiter::new();
        let a: PostalAddr = "alice::acme.postal.bot".parse().unwrap();
        let b: PostalAddr = "bob::acme.postal.bot".parse().unwrap();
        let now = Instant::now();
        for _ in 0..TURN_LIMIT_PER_HOUR {
            assert!(lim.try_reserve(&a, now));
        }
        assert!(!lim.try_reserve(&a, now));
        assert!(lim.try_reserve(&b, now));
        lim.release(&a, now);
        assert!(lim.try_reserve(&a, now));
        assert!(!lim.try_reserve(&a, now));
    }

    #[test]
    fn prompt_url_derives_from_health() {
        assert_eq!(
            prompt_url_from_health("http://127.0.0.1:1340/health"),
            "http://127.0.0.1:1340/api/sendPrompt"
        );
        assert_eq!(
            prompt_url_from_health("http://127.0.0.1:9999/health"),
            "http://127.0.0.1:9999/api/sendPrompt"
        );
    }
}
