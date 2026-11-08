//! Built-in `k2` last-mile plugin: `POST /v1/w/<ws>/message` on the loopback
//! k2-daemon, with a K2 API key scoped to that one workspace.
//!
//! Never reads K2's owner token (`~/.k2/daemon.token`). The scoped route runs
//! K2's own gates: the workspace's "allow remote instruction" opt-in and the
//! busy check. A person mints the key in K2 and hands it to
//! `p5 k2 link <ws> --key-stdin`; links live in `~/.postal/k2-links.json`
//! (0600). No link for a workspace means no knock; the package stays in
//! `~/.postal/inbox`. Dispatch lives in [`crate::last_mile`].

use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(25);
pub const LINKS_FILE: &str = "k2-links.json";

/// One knock to k2-daemon. Display `from` is the Postal peer, not a K2 workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnockRequest {
    /// K2 workspace slug, or the claimed absolute cwd.
    pub workspace: String,
    pub text: String,
    pub from: String,
    pub wake: bool,
    /// Claimed cwd (matches a link's `path`).
    pub project: String,
    /// Packed at `p5 handle claim`. The `/v1` route has no sidecar target yet,
    /// so this is not sent; mail goes to the workspace's canonical chat.
    pub session_id: Option<String>,
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
    /// No scoped key for this workspace.
    NotLinked(String),
    Connect(String),
    Status(u16, String),
    Failed { reason: String, hint: String },
}

impl fmt::Display for K2MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("k2 last-mile is off"),
            Self::NotLinked(ws) => write!(
                f,
                "no K2 key for {ws}; kept in the Postal tray. A person links it in K2, \
                 which runs: p5 k2 link <workspace> --key-stdin"
            ),
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

/// Percent-encode a path segment (python `quote(safe='')`).
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

/// One K2 workspace p5 may deliver into, with its scoped API key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K2Link {
    /// K2 workspace slug (the `<ws>` in `/v1/w/<ws>/message`).
    pub workspace: String,
    /// Workspace folder, to match a handle's claimed cwd.
    pub path: String,
    pub key: String,
}

impl fmt::Debug for K2Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("K2Link")
            .field("workspace", &self.workspace)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Missing file is no links. A file that doesn't parse is an error, so a
/// later `link` can't silently wipe the others.
pub fn try_load_links(root: &Path) -> Result<Vec<K2Link>, String> {
    match std::fs::read_to_string(root.join(LINKS_FILE)) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{LINKS_FILE}: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{LINKS_FILE}: {e}")),
    }
}

/// Knock path: anything unreadable means no links (fail closed, tray only).
pub fn load_links(root: &Path) -> Vec<K2Link> {
    try_load_links(root).unwrap_or_default()
}

/// Write `k2-links.json` created 0600 (never world-readable, even briefly).
pub fn save_links(root: &Path, links: &[K2Link]) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    let tmp = root.join(format!("{LINKS_FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(serde_json::to_string_pretty(links)?.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, root.join(LINKS_FILE))
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
        links: Vec<K2Link>,
        timeout: Duration,
    },
    #[cfg(test)]
    Capture(Arc<Mutex<Vec<KnockRequest>>>),
}

impl fmt::Debug for K2MsgClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Inner::Off => f.write_str("K2MsgClient::Off"),
            Inner::Loopback { port, links, .. } => f
                .debug_struct("K2MsgClient::Loopback")
                .field("port", port)
                .field("links", &links.len())
                .finish(),
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

    pub fn loopback(port: u16, links: Vec<K2Link>) -> Self {
        Self {
            inner: Inner::Loopback {
                port,
                links,
                timeout: DEFAULT_TIMEOUT,
            },
        }
    }

    /// `P5_K2_MSG=0` disables. Missing `~/.k2/daemon.port` is off, not an error.
    /// The port file is not a secret; the owner token next to it is never read.
    pub fn from_k2_home(postal_root: &Path) -> Self {
        if env_disabled("P5_K2_MSG") {
            return Self::off();
        }
        match read_port(&k2_home().join("daemon.port")) {
            Some(port) => Self::loopback(port, load_links(postal_root)),
            None => Self::off(),
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
                links,
                timeout,
            } => {
                let link = find_link(links, req)
                    .ok_or_else(|| K2MsgError::NotLinked(req.workspace.clone()))?;
                post_msg(*port, link, req, *timeout)
            }
        }
    }
}

/// Claimed cwd first (exact folder), then the workspace slug.
fn find_link<'a>(links: &'a [K2Link], req: &KnockRequest) -> Option<&'a K2Link> {
    let cwd = req.project.trim().trim_end_matches('/');
    links
        .iter()
        .find(|l| !cwd.is_empty() && l.path.trim_end_matches('/') == cwd)
        .or_else(|| links.iter().find(|l| l.workspace == req.workspace))
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
    link: &K2Link,
    req: &KnockRequest,
    timeout: Duration,
) -> Result<K2MsgResponse, K2MsgError> {
    let path = format!("/v1/w/{}/message", form_encode(&link.workspace));
    let body = serde_json::json!({
        "text": req.text,
        "from": req.from,
        "onBehalfOf": req.from,
        "wake": req.wake,
        "kind": "postal",
    })
    .to_string();
    let (status, resp) = http_post(port, &path, &link.key, body.as_bytes(), timeout)?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    if status == 409 {
        return Err(K2MsgError::Failed {
            reason: "agent_busy".into(),
            hint: clip(&text, 240),
        });
    }
    if !(200..300).contains(&status) {
        return Err(K2MsgError::Status(status, clip(&text, 240)));
    }
    parse_msg_json(&text)
}

/// `/v1/w/<ws>/message` answers `{delivered, mode, reason?, result?}`.
fn parse_msg_json(text: &str) -> Result<K2MsgResponse, K2MsgError> {
    #[derive(Deserialize)]
    struct Wire {
        delivered: Option<bool>,
        reason: Option<String>,
        result: Option<WireResult>,
    }
    #[derive(Deserialize)]
    struct WireResult {
        target_session_id: Option<String>,
        reason: Option<String>,
        hint: Option<String>,
    }
    let wire: Wire = serde_json::from_str(text).map_err(|e| {
        K2MsgError::Connect(format!("k2-daemon returned non-JSON: {e}"))
    })?;
    let result = wire.result;
    if !wire.delivered.unwrap_or(false) {
        let reason = wire
            .reason
            .or_else(|| result.as_ref().and_then(|r| r.reason.clone()))
            .unwrap_or_else(|| "k2_msg_failed".into());
        return Err(K2MsgError::Failed {
            hint: result.and_then(|r| r.hint).unwrap_or_default(),
            reason,
        });
    }
    Ok(K2MsgResponse {
        success: true,
        target_session_id: result.as_ref().and_then(|r| r.target_session_id.clone()),
        reason: None,
        hint: result.and_then(|r| r.hint),
    })
}

fn http_post(
    port: u16,
    path: &str,
    key: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>), K2MsgError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        K2MsgError::Connect(format!("k2-daemon 127.0.0.1:{port}: {e}"))
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
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
            form_encode("/home/user/project"),
            "%2Fhome%2Fuser%2Fproject"
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
            session_id: None,
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
                session_id: None,
            })
            .unwrap_err();
        assert!(matches!(err, K2MsgError::Disabled));
    }

    type Served = (u16, Arc<Mutex<Option<String>>>, thread::JoinHandle<()>, Arc<AtomicBool>);

    /// One-shot loopback server: records the raw request, answers `status` + `body`.
    fn serve_once(status: &'static str, body: &'static str) -> Served {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
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
                        let raw = read_request(&mut stream);
                        *captured.lock().unwrap() = Some(raw);
                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        (port, got, handle, stop)
    }

    /// Read headers, then exactly Content-Length body bytes. The client writes
    /// headers and body separately, so one read() can stop short.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            if let Some(end) = text.find("\r\n\r\n") {
                let want = text[..end]
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= end + 4 + want {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn link() -> K2Link {
        K2Link {
            workspace: "postal-bot".into(),
            path: "/srv/scout".into(),
            key: "k2ak_scoped".into(),
        }
    }

    fn req(text: &str) -> KnockRequest {
        KnockRequest {
            workspace: "/srv/scout".into(),
            text: text.into(),
            from: "alice::acme.postal.bot".into(),
            wake: true,
            project: "/srv/scout".into(),
            session_id: Some("sess-claim".into()),
        }
    }

    #[test]
    fn loopback_posts_json_to_scoped_v1_route() {
        let (port, got, handle, stop) = serve_once(
            "200 OK",
            r#"{"delivered":true,"mode":"live","result":{"success":true,"target_session_id":"sess-1"}}"#,
        );
        let resp = K2MsgClient::loopback(port, vec![link()]).knock(&req("hi")).unwrap();
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        assert!(resp.success);
        assert_eq!(resp.target_session_id.as_deref(), Some("sess-1"));
        let raw = got.lock().unwrap().clone().expect("request");
        assert!(raw.starts_with("POST /v1/w/postal-bot/message HTTP/1.1"), "{raw}");
        assert!(raw.contains("Authorization: Bearer k2ak_scoped"));
        assert!(raw.contains("Content-Type: application/json"));
        assert!(!raw.contains("token="), "no owner token in the query");
        let body = raw.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["kind"], "postal");
        assert_eq!(v["from"], "alice::acme.postal.bot");
        assert_eq!(v["text"], "hi");
        assert_eq!(v["wake"], true);
    }

    #[test]
    fn unlinked_workspace_does_not_dial() {
        let err = K2MsgClient::loopback(1, Vec::new()).knock(&req("hi")).unwrap_err();
        assert!(matches!(err, K2MsgError::NotLinked(_)), "{err:?}");
    }

    #[test]
    fn declined_is_not_success() {
        let (port, _got, handle, stop) = serve_once(
            "200 OK",
            r#"{"delivered":false,"mode":"declined","reason":"remote_instruction_disabled"}"#,
        );
        let err = K2MsgClient::loopback(port, vec![link()]).knock(&req("x")).unwrap_err();
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        match err {
            K2MsgError::Failed { reason, .. } => assert_eq!(reason, "remote_instruction_disabled"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn busy_is_not_success() {
        let (port, _got, handle, stop) = serve_once(
            "409 Conflict",
            r#"{"delivered":false,"reason":"agent_busy","agentStatus":"working"}"#,
        );
        let err = K2MsgClient::loopback(port, vec![link()]).knock(&req("x")).unwrap_err();
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        match err {
            K2MsgError::Failed { reason, .. } => assert_eq!(reason, "agent_busy"),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn links_file_is_0600_and_key_not_in_debug() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        save_links(tmp.path(), &[link()]).unwrap();
        let mode = std::fs::metadata(tmp.path().join(LINKS_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_links(tmp.path()), vec![link()]);
        std::fs::write(tmp.path().join(LINKS_FILE), "{not json").unwrap();
        assert!(try_load_links(tmp.path()).is_err());
        assert!(load_links(tmp.path()).is_empty());
        assert!(!format!("{:?}", link()).contains("k2ak_scoped"));
    }
}
