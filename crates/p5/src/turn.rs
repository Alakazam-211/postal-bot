//! Local Sand / Grok Bot hop for type `turn`.
//!
//! Public path is HTTP `sendPrompt` on the loopback gateway. Never invent a
//! PTY and never call SendToAgent (in-app only).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use p5_core::PostalAddr;
use serde_json::json;

pub const DEFAULT_TURN_HEALTH: &str = "http://127.0.0.1:1340/health";
pub const TURN_LIMIT_PER_HOUR: usize = 12;
const TURN_WINDOW: Duration = Duration::from_secs(60 * 60);
const TURN_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
/// k2g `sand_api(..., timeout=90)` for sendPrompt.
const SEND_PROMPT_TIMEOUT: Duration = Duration::from_secs(90);
const SAND_API_TIMEOUT: Duration = Duration::from_secs(15);

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
        let gw = load_sand_gateway();
        let health = std::env::var("P5_TURN_HEALTH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let host = gw
                    .host
                    .as_deref()
                    .filter(|h| host_is_loopback(h))
                    .unwrap_or("127.0.0.1");
                gw.port
                    .map(|p| format!("http://{host}:{p}/health"))
                    .unwrap_or_else(|| DEFAULT_TURN_HEALTH.to_string())
            });
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
            .filter(|s| !s.is_empty())
            .or(gw.token);
        Self {
            health_url: health,
            prompt_url: prompt,
            agent_id,
            token,
        }
    }
}

struct SandGateway {
    port: Option<u16>,
    host: Option<String>,
    token: Option<String>,
}

fn sand_data_root() -> Option<PathBuf> {
    std::env::var("SAND_DATA_ROOT")
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join("sand-data")))
}

/// Same file k2g reads (`$SAND_DATA_ROOT/gateway.json`, default `~/sand-data/gateway.json`).
fn load_sand_gateway() -> SandGateway {
    let empty = SandGateway {
        port: None,
        host: None,
        token: None,
    };
    let Some(path) = sand_data_root().map(|r| r.join("gateway.json")) else {
        return empty;
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return empty;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return empty;
    };
    let token = v
        .get("token")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let port = v
        .get("port")
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok());
    let host = v
        .get("host")
        .and_then(|x| x.as_str())
        .map(rewrite_gateway_host)
        .filter(|h| !h.is_empty());
    SandGateway { port, host, token }
}

fn rewrite_gateway_host(host: &str) -> String {
    let host = host.trim();
    if host.is_empty() || host == "0.0.0.0" || host == "::" || host == "[::]" {
        return "127.0.0.1".into();
    }
    host.trim_matches(|c| c == '[' || c == ']').to_string()
}

fn api_url(health: &str, command: &str) -> String {
    match parse_http_url(health) {
        Ok(u) => format!("http://{}:{}/api/{command}", u.host, u.port),
        Err(_) => format!("http://127.0.0.1:1340/api/{command}"),
    }
}

/// k2g `sand_api`: always POST `/api/{command}` with Bearer. Token required.
fn sand_api(
    cfg: &TurnConfig,
    command: &str,
    body: &serde_json::Value,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), TurnNetError> {
    let token = cfg
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            TurnNetError::Auth(
                "Grok Bot gateway token missing; need ~/sand-data/gateway.json (or P5_TURN_TOKEN)"
                    .into(),
            )
        })?;
    let url = api_url(&cfg.health_url, command);
    let payload = body.to_string();
    http_exchange("POST", &url, Some(payload.as_bytes()), Some(token), timeout)
}

#[derive(Debug, Clone)]
pub struct SandAgent {
    pub id: String,
    pub name: String,
    pub active: bool,
}

/// `POST /api/listAgents` then disk profiles under `sand-data/agents/<uuid>/`.
pub fn list_agents(cfg: &TurnConfig) -> Result<Vec<SandAgent>, TurnNetError> {
    let (status, body) = sand_api(cfg, "listAgents", &json!({}), SAND_API_TIMEOUT)?;
    if status != 200 {
        return Err(TurnNetError::Status(status));
    }
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap_or_default();
    let mut agents = Vec::new();
    for row in rows {
        let id = row
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim();
        if id.is_empty() {
            continue;
        }
        agents.push(SandAgent {
            id: id.to_string(),
            name: row
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string(),
            active: row
                .get("isActive")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
        });
    }
    merge_disk_agents(&mut agents);
    Ok(agents)
}

fn merge_disk_agents(agents: &mut Vec<SandAgent>) {
    let Some(root) = sand_data_root() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(root.join("agents")) else {
        return;
    };
    let have: std::collections::HashSet<String> = agents.iter().map(|a| a.id.clone()).collect();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if !looks_like_agent_uuid(&id) || have.contains(&id) {
            continue;
        }
        let name = std::fs::read_to_string(path.join("profile.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| {
                v.get("name")
                    .and_then(|x| x.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| id.chars().take(8).collect());
        agents.push(SandAgent {
            id,
            name,
            active: false,
        });
    }
}

pub fn looks_like_agent_uuid(s: &str) -> bool {
    let s = s.trim();
    let b = s.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && s.bytes()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

/// Sand addressing is UUID / listAgents, never a Postal handle.
///
/// Order: `P5_TURN_AGENT_ID`, homes `session_id` if UUID, listAgents name
/// match (k2g), disk profiles, then `GET /health` `activeAgentId`.
pub fn resolve_sand_agent(
    cfg: &TurnConfig,
    session_id: Option<&str>,
    handle: Option<&str>,
) -> Result<String, TurnNetError> {
    let explicit = cfg.agent_id.trim();
    if !explicit.is_empty() {
        if looks_like_agent_uuid(explicit) {
            return Ok(explicit.to_string());
        }
        if let Some(id) = match_listed_agent(cfg, explicit) {
            return Ok(id);
        }
        return Ok(explicit.to_string());
    }
    if let Some(sid) = session_id.map(str::trim).filter(|s| !s.is_empty()) {
        if looks_like_agent_uuid(sid) {
            return Ok(sid.to_string());
        }
        if let Some(id) = match_listed_agent(cfg, sid) {
            return Ok(id);
        }
    }
    if let Some(h) = handle.map(str::trim).filter(|s| !s.is_empty()) {
        if looks_like_agent_uuid(h) {
            return Ok(h.to_string());
        }
        if let Some(id) = match_listed_agent(cfg, h) {
            return Ok(id);
        }
    }
    if let Some(id) = active_agent_id(cfg) {
        return Ok(id);
    }
    Err(TurnNetError::Agent(
        "no Sand UUID; POST /api/listAgents with Bearer from gateway.json (handle is not an agentId)"
            .into(),
    ))
}

fn match_listed_agent(cfg: &TurnConfig, needle: &str) -> Option<String> {
    let needle = needle.to_ascii_lowercase();
    let agents = list_agents(cfg).ok()?;
    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    for a in agents {
        let name = a.name.to_ascii_lowercase();
        let id = a.id.to_ascii_lowercase();
        if id == needle || name == needle {
            exact.push(a);
        } else if !needle.is_empty() && (name.starts_with(&needle) || id.starts_with(&needle)) {
            prefix.push(a);
        }
    }
    let pool = if !exact.is_empty() { exact } else { prefix };
    if pool.len() == 1 {
        return Some(pool[0].id.clone());
    }
    let live: Vec<_> = pool.iter().filter(|a| a.active).collect();
    if live.len() == 1 {
        return Some(live[0].id.clone());
    }
    None
}

/// `GET /health` `activeAgentId` (the live Grok Bot). Health is public; Bearer optional.
pub fn active_agent_id(cfg: &TurnConfig) -> Option<String> {
    let (status, body) = http_exchange(
        "GET",
        &cfg.health_url,
        None,
        cfg.token.as_deref(),
        TURN_HTTP_TIMEOUT,
    )
    .ok()?;
    if status != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
    v.get("activeAgentId")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn prompt_url_from_health(health: &str) -> String {
    api_url(health, "sendPrompt")
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
    Auth(String),
    Agent(String),
}

impl std::fmt::Display for TurnNetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(msg) | Self::Connect(msg) | Self::Auth(msg) | Self::Agent(msg) => {
                f.write_str(msg)
            }
            Self::Status(code) => write!(f, "turn gateway HTTP {code}"),
        }
    }
}

impl std::error::Error for TurnNetError {}

pub fn health_up(cfg: &TurnConfig) -> Result<(), TurnNetError> {
    let (status, _) = http_exchange(
        "GET",
        &cfg.health_url,
        None,
        cfg.token.as_deref(),
        TURN_HTTP_TIMEOUT,
    )?;
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
    });
    let (status, _) = sand_api(cfg, "sendPrompt", &payload, SEND_PROMPT_TIMEOUT)?;
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
    pub auths: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>,
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    token: Option<String>,
}

#[cfg(test)]
impl MockSand {
    pub fn spawn(health: u16, prompt: u16) -> Self {
        Self::spawn_inner(health, prompt, Some("test-token".into()), None, false)
    }

    pub fn spawn_authed(health: u16, prompt: u16, token: &str, agents: serde_json::Value) -> Self {
        Self::spawn_inner(
            health,
            prompt,
            Some(token.to_string()),
            Some(agents),
            true,
        )
    }

    fn spawn_inner(
        health: u16,
        prompt: u16,
        token: Option<String>,
        agents: Option<serde_json::Value>,
        require_auth: bool,
    ) -> Self {
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
        let auths = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&prompts);
        let captured_auth = Arc::clone(&auths);
        let stop_flag = Arc::clone(&stop);
        let need = if require_auth { token.clone() } else { None };
        let roster = agents
            .unwrap_or_else(|| json!([{"id":"sand-1","name":"Grok","isActive":true}]));
        let roster_body = roster.to_string();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let req = read_http_request(&mut stream);
                        let bearer = request_bearer(&req);
                        captured_auth.lock().unwrap().push(bearer.clone());
                        let api = req.contains("POST /api/");
                        let (status, body) = if req.starts_with("GET /health") {
                            (
                                health.load(Ordering::Relaxed),
                                r#"{"ok":true,"activeAgentId":"0e5f5de8-7619-4ba4-9753-32c5470b2346"}"#
                                    .to_string(),
                            )
                        } else if api && need.as_ref().is_some_and(|t| bearer.as_deref() != Some(t.as_str()))
                        {
                            (401, r#"{"error":"unauthorized"}"#.to_string())
                        } else if req.contains("POST /api/listAgents") {
                            (200, roster_body.clone())
                        } else if req.contains("POST /api/sendPrompt") {
                            if let Some(json) = request_json(&req) {
                                captured.lock().unwrap().push(json);
                            }
                            (
                                prompt.load(Ordering::Relaxed),
                                r#"{"ok":true,"accepted":true}"#.to_string(),
                            )
                        } else {
                            (404, r#"{"error":"not_found"}"#.to_string())
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
            auths,
            addr,
            stop,
            handle: Some(handle),
            token,
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
            token: self.token.clone(),
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
fn request_bearer(req: &str) -> Option<String> {
    let head = req.split("\r\n\r\n").next().or_else(|| req.split("\n\n").next())?;
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if !k.eq_ignore_ascii_case("authorization") {
            return None;
        }
        let v = v.trim();
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
            .map(|s| s.trim().to_string())
    })
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
        assert!(!prompts[0]["prompt"].as_str().unwrap().contains("[k2g]"));
        let auths = sand.auths.lock().unwrap();
        assert!(
            auths.iter().any(|a| a.as_deref() == Some("test-token")),
            "sendPrompt must send Bearer like k2g sand_api, got {auths:?}"
        );
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

    #[test]
    fn send_prompt_without_token_does_not_hit_gateway() {
        let sand = MockSand::spawn(200, 200);
        let mut cfg = sand.config();
        cfg.token = None;
        match send_prompt(
            &cfg,
            &"alice::acme.postal.bot".parse().unwrap(),
            "nope",
            "sand-1",
            "n1",
        ) {
            Err(TurnNetError::Auth(msg)) => assert!(msg.contains("token"), "{msg}"),
            other => panic!("expected Auth, got {other:?}"),
        }
        assert!(sand.prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn list_agents_is_post_and_resolves_handle() {
        let uuid = "0e5f5de8-7619-4ba4-9753-32c5470b2346";
        let sand = MockSand::spawn_authed(
            200,
            200,
            "secret",
            json!([{"id": uuid, "name": "Grok", "isActive": true}]),
        );
        let mut cfg = sand.config();
        cfg.agent_id.clear();
        cfg.token = Some("secret".into());
        let id = resolve_sand_agent(&cfg, None, Some("grok")).unwrap();
        assert_eq!(id, uuid);
        send_prompt(
            &cfg,
            &"postal-bot::acme.postal.bot".parse().unwrap(),
            "hello grok",
            &id,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        .unwrap();
        let prompts = sand.prompts.lock().unwrap();
        assert_eq!(prompts[0]["agentId"], uuid);
        assert_eq!(
            prompts[0]["prompt"],
            "[from postal-bot::acme.postal.bot] [p5] hello grok"
        );
    }

    #[test]
    fn missing_bearer_on_strict_gateway_is_401() {
        let sand = MockSand::spawn_authed(
            200,
            200,
            "secret",
            json!([{"id":"sand-1","name":"Grok","isActive":true}]),
        );
        let mut cfg = sand.config();
        cfg.token = Some("wrong".into());
        match send_prompt(
            &cfg,
            &"alice::acme.postal.bot".parse().unwrap(),
            "hi",
            "sand-1",
            "n1",
        ) {
            Err(TurnNetError::Status(401)) => {}
            other => panic!("expected Status(401), got {other:?}"),
        }
    }

    #[test]
    fn from_env_loads_gateway_json() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("gateway.json"),
            r#"{"port":1340,"host":"0.0.0.0","token":"gw-token-1","scheme":"http"}"#,
        )
        .unwrap();
        let prev_root = std::env::var_os("SAND_DATA_ROOT");
        let prev_token = std::env::var_os("P5_TURN_TOKEN");
        let prev_health = std::env::var_os("P5_TURN_HEALTH");
        let prev_prompt = std::env::var_os("P5_TURN_PROMPT");
        std::env::set_var("SAND_DATA_ROOT", dir.path());
        std::env::remove_var("P5_TURN_TOKEN");
        std::env::remove_var("P5_TURN_HEALTH");
        std::env::remove_var("P5_TURN_PROMPT");
        let cfg = TurnConfig::from_env();
        match prev_root {
            Some(v) => std::env::set_var("SAND_DATA_ROOT", v),
            None => std::env::remove_var("SAND_DATA_ROOT"),
        }
        match prev_token {
            Some(v) => std::env::set_var("P5_TURN_TOKEN", v),
            None => std::env::remove_var("P5_TURN_TOKEN"),
        }
        match prev_health {
            Some(v) => std::env::set_var("P5_TURN_HEALTH", v),
            None => std::env::remove_var("P5_TURN_HEALTH"),
        }
        match prev_prompt {
            Some(v) => std::env::set_var("P5_TURN_PROMPT", v),
            None => std::env::remove_var("P5_TURN_PROMPT"),
        }
        assert_eq!(cfg.token.as_deref(), Some("gw-token-1"));
        assert_eq!(cfg.health_url, "http://127.0.0.1:1340/health");
        assert_eq!(cfg.prompt_url, "http://127.0.0.1:1340/api/sendPrompt");
    }

    #[test]
    fn uuid_shape() {
        assert!(looks_like_agent_uuid("0e5f5de8-7619-4ba4-9753-32c5470b2346"));
        assert!(!looks_like_agent_uuid("grok"));
        assert!(!looks_like_agent_uuid("Grok"));
    }
}
