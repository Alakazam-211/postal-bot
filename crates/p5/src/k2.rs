//! Built-in `k2` last-mile plugin: `POST /cli/workspace/msg` (the route `k2 msg` uses).
//!
//! Not a peer type. Loopback k2-daemon only. Package stays in `~/.postal/inbox`.
//! Dispatch lives in [`crate::last_mile`].

use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(25);
const MSG_PATH: &str = "/cli/workspace/msg";

/// One knock to k2-daemon. Display `from` is the Postal peer, not a K2 workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnockRequest {
    pub workspace: String,
    pub text: String,
    pub from: String,
    pub wake: bool,
    pub project: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K2MsgResponse {
    pub success: bool,
    pub target_session_id: Option<String>,
    pub reason: Option<String>,
    pub hint: Option<String>,
}

#[derive(Debug)]
pub enum K2MsgError {
    Disabled,
    Connect(String),
    Status(u16, String),
    Failed { reason: String, hint: String },
}

impl fmt::Display for K2MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("k2 last-mile is off"),
            Self::Connect(msg) => f.write_str(msg),
            Self::Status(code, body) => write!(f, "k2-daemon HTTP {code}: {body}"),
            Self::Failed { reason, hint } if hint.is_empty() => f.write_str(reason),
            Self::Failed { reason, hint } => write!(f, "{reason}: {hint}"),
        }
    }
}

impl std::error::Error for K2MsgError {}

/// Knock text for a K2 cell. Cover stays in the Postal tray.
#[cfg(test)]
pub fn knock_text(id: &str, title: &str) -> String {
    crate::last_mile::pointer_text(id, title)
}

/// Address without a sidecar segment → K2 canonical handle (`k2 msg postal-bot`).
pub fn workspace_target(handle: &str) -> String {
    handle.to_string()
}

/// Percent-encode for query + form bodies (python `quote(safe='')`).
pub fn form_encode(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Clone)]
pub struct K2MsgClient {
    inner: Inner,
}

#[derive(Clone)]
enum Inner {
    Off,
    Loopback {
        port: u16,
        token: String,
        timeout: Duration,
    },
    #[cfg(test)]
    Capture(Arc<Mutex<Vec<KnockRequest>>>),
}

impl fmt::Debug for K2MsgClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Inner::Off => f.write_str("K2MsgClient::Off"),
            Inner::Loopback { port, .. } => {
                f.debug_struct("K2MsgClient::Loopback").field("port", port).finish()
            }
            #[cfg(test)]
            Inner::Capture(v) => f
                .debug_struct("K2MsgClient::Capture")
                .field("n", &v.lock().map(|g| g.len()).unwrap_or(0))
                .finish(),
        }
    }
}

impl Default for K2MsgClient {
    fn default() -> Self {
        Self::off()
    }
}

impl K2MsgClient {
    pub fn off() -> Self {
        Self { inner: Inner::Off }
    }

    pub fn is_off(&self) -> bool {
        matches!(self.inner, Inner::Off)
    }

    #[cfg(test)]
    pub fn capture() -> Self {
        Self {
            inner: Inner::Capture(Arc::new(Mutex::new(Vec::new()))),
        }
    }

    #[cfg(test)]
    pub fn recorded(&self) -> Vec<KnockRequest> {
        match &self.inner {
            Inner::Capture(v) => v.lock().map(|g| g.clone()).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub fn loopback(port: u16, token: impl Into<String>) -> Self {
        Self {
            inner: Inner::Loopback {
                port,
                token: token.into(),
                timeout: DEFAULT_TIMEOUT,
            },
        }
    }

    /// `P5_K2_MSG=0` disables. Missing `~/.k2/daemon.port` is off, not an error.
    pub fn from_k2_home() -> Self {
        if env_disabled("P5_K2_MSG") {
            return Self::off();
        }
        let home = k2_home();
        let port = read_port(&home.join("daemon.port"));
        let token = read_trimmed(&home.join("daemon.token"));
        match (port, token) {
            (Some(port), Some(token)) if !token.is_empty() => Self::loopback(port, token),
            _ => Self::off(),
        }
    }

    pub fn knock(&self, req: &KnockRequest) -> Result<K2MsgResponse, K2MsgError> {
        match &self.inner {
            Inner::Off => Err(K2MsgError::Disabled),
            #[cfg(test)]
            Inner::Capture(v) => {
                v.lock().unwrap_or_else(|e| e.into_inner()).push(req.clone());
                Ok(K2MsgResponse {
                    success: true,
                    target_session_id: None,
                    reason: None,
                    hint: None,
                })
            }
            Inner::Loopback {
                port,
                token,
                timeout,
            } => post_msg(*port, token, req, *timeout),
        }
    }
}

fn env_disabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "0" || v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

fn k2_home() -> PathBuf {
    if let Ok(p) = std::env::var("K2_HOME") {
        let p = p.trim();
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h).join(".k2"),
        None => PathBuf::from(".k2"),
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_port(path: &Path) -> Option<u16> {
    read_trimmed(path)?.parse().ok()
}

fn post_msg(
    port: u16,
    token: &str,
    req: &KnockRequest,
    timeout: Duration,
) -> Result<K2MsgResponse, K2MsgError> {
    let query = format!(
        "token={}&project={}",
        form_encode(token),
        form_encode(&req.project)
    );
    let path = format!("{MSG_PATH}?{query}");
    let body = format!(
        "workspace={}&text={}&from={}&wake={}",
        form_encode(&req.workspace),
        form_encode(&req.text),
        form_encode(&req.from),
        if req.wake { "true" } else { "false" }
    );
    let (status, resp) = http_post(port, &path, body.as_bytes(), timeout)?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    if !(200..300).contains(&status) {
        return Err(K2MsgError::Status(status, clip(&text, 240)));
    }
    parse_msg_json(&text)
}

fn parse_msg_json(text: &str) -> Result<K2MsgResponse, K2MsgError> {
    #[derive(Deserialize)]
    struct Wire {
        success: Option<bool>,
        target_session_id: Option<String>,
        reason: Option<String>,
        hint: Option<String>,
        error: Option<String>,
    }
    let wire: Wire = serde_json::from_str(text).map_err(|e| {
        K2MsgError::Connect(format!("k2-daemon returned non-JSON: {e}"))
    })?;
    let success = wire.success.unwrap_or(false);
    if !success {
        let reason = wire
            .reason
            .or(wire.error)
            .unwrap_or_else(|| "k2_msg_failed".into());
        return Err(K2MsgError::Failed {
            hint: wire.hint.unwrap_or_default(),
            reason,
        });
    }
    Ok(K2MsgResponse {
        success: true,
        target_session_id: wire.target_session_id,
        reason: None,
        hint: wire.hint,
    })
}

fn http_post(
    port: u16,
    path: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>), K2MsgError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        K2MsgError::Connect(format!("k2-daemon 127.0.0.1:{port}: {e}"))
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| K2MsgError::Connect(e.to_string()))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| K2MsgError::Connect(e.to_string()))?;
    parse_http_response(&buf)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), K2MsgError> {
    let text = String::from_utf8_lossy(raw);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| K2MsgError::Connect("k2-daemon returned no HTTP headers".into()))?;
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| K2MsgError::Connect(format!("bad HTTP status line {status_line:?}")))?;
    Ok((status, rest.as_bytes().to_vec()))
}

fn clip(s: &str, n: usize) -> String {
    let mut chars = s.chars();
    let out: String = chars.by_ref().take(n).collect();
    if chars.next().is_some() {
        format!("{out}…")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[test]
    fn knock_text_is_p5_pointer_not_k2_inbox() {
        let t = knock_text("01ARZ3NDEKTSV4RRFFQ69G5FAV", "Brief");
        assert_eq!(
            t,
            "[p5:01ARZ3NDEKTSV4RRFFQ69G5FAV] Brief\nOpen: p5 inbox read 01ARZ3NDEKTSV4RRFFQ69G5FAV"
        );
        assert!(!t.contains("k2 inbox"));
        assert!(!t.contains("[inbox:"));
    }

    #[test]
    fn workspace_target_is_the_handle() {
        assert_eq!(workspace_target("postal-bot"), "postal-bot");
    }

    #[test]
    fn form_encode_matches_python_quote() {
        assert_eq!(form_encode("postal-bot"), "postal-bot");
        assert_eq!(form_encode("a b"), "a%20b");
        assert_eq!(form_encode("x=y&z"), "x%3Dy%26z");
        assert_eq!(
            form_encode("/Users/z3thon/DevProjects/Kessel"),
            "%2FUsers%2Fz3thon%2FDevProjects%2FKessel"
        );
    }

    #[test]
    fn capture_records_knock() {
        let client = K2MsgClient::capture();
        let req = KnockRequest {
            workspace: "postal-bot".into(),
            text: knock_text("01ARZ3NDEKTSV4RRFFQ69G5FAV", "hi"),
            from: "alice::acme.postal.bot".into(),
            wake: true,
            project: "/srv/scout".into(),
        };
        client.knock(&req).unwrap();
        assert_eq!(client.recorded(), vec![req]);
    }

    #[test]
    fn off_does_not_dial() {
        let err = K2MsgClient::off()
            .knock(&KnockRequest {
                workspace: "postal-bot".into(),
                text: "x".into(),
                from: "a::acme.postal.bot".into(),
                wake: true,
                project: String::new(),
            })
            .unwrap_err();
        assert!(matches!(err, K2MsgError::Disabled));
    }

    #[test]
    fn loopback_posts_form_to_workspace_msg() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let got = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = Arc::clone(&got);
        let stop_flag = Arc::clone(&stop);
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = vec![0; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                        *captured.lock().unwrap() = Some(req);
                        let body = r#"{"success":true,"target_session_id":"sess-1","attempts":1}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        let client = K2MsgClient::loopback(addr.port(), "tok_secret");
        let resp = client
            .knock(&KnockRequest {
                workspace: "postal-bot".into(),
                text: knock_text("01ARZ3NDEKTSV4RRFFQ69G5FAV", "Brief"),
                from: "alice::acme.postal.bot".into(),
                wake: true,
                project: "/srv/scout".into(),
            })
            .unwrap();
        assert!(resp.success);
        assert_eq!(resp.target_session_id.as_deref(), Some("sess-1"));
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let raw = got.lock().unwrap().clone().expect("request");
        assert!(raw.starts_with("POST /cli/workspace/msg?"));
        assert!(raw.contains("token=tok_secret"));
        assert!(raw.contains("project=%2Fsrv%2Fscout"));
        assert!(raw.contains("Content-Type: application/x-www-form-urlencoded"));
        assert!(raw.contains("workspace=postal-bot"));
        assert!(raw.contains("from=alice%3A%3Aacme.postal.bot"));
        assert!(raw.contains("wake=true"));
        assert!(raw.contains("text=%5Bp5%3A01ARZ3NDEKTSV4RRFFQ69G5FAV%5D%20Brief%0AOpen%3A%20p5%20inbox%20read%2001ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!raw.contains("tok_secret\r\n"));
    }

    #[test]
    fn daemon_failure_is_not_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let mut buf = vec![0; 2048];
                        let _ = stream.read(&mut buf);
                        let body = r#"{"success":false,"reason":"dormant_no_wake","hint":"asleep"}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        let err = K2MsgClient::loopback(addr.port(), "t")
            .knock(&KnockRequest {
                workspace: "postal-bot".into(),
                text: "x".into(),
                from: "a::acme.postal.bot".into(),
                wake: false,
                project: String::new(),
            })
            .unwrap_err();
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        match err {
            K2MsgError::Failed { reason, .. } => assert_eq!(reason, "dormant_no_wake"),
            other => panic!("{other:?}"),
        }
    }
}
