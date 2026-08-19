//! Loopback inbound HTTP. Never binds a public address.

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p5_core::{DeliveryMode, PeerType, PostalAddr};
use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::session_map::SessionMap;
use crate::sm::{
    declared_typ, receive_msg, Inbound, ReceiveError, SmContext, SmError, REASON_NO_AGENT,
};

pub const PRODUCT: &str = "Postal";
pub const SITE: &str = "postal.bot";
pub const COMMAND: &str = "p5";
pub const DEFAULT_HTTP_BIND: &str = "127.0.0.1:8443";
pub const DEV_SECRET_HEADER: &str = "x-p5-dev-secret";
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

const HEADER_LIMIT: usize = 64 * 1024;

#[derive(Debug)]
pub enum BindError {
    Invalid(String),
    NotLoopback(SocketAddr),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(raw) => write!(f, "invalid P5_HTTP_BIND {raw:?}"),
            Self::NotLoopback(addr) => write!(
                f,
                "refusing non-loopback bind {addr}; Postal inbound is loopback only"
            ),
        }
    }
}

impl std::error::Error for BindError {}

/// Parse `P5_HTTP_BIND`. Default `127.0.0.1:8443`. Unspecified / public IPs fail.
pub fn parse_http_bind(raw: Option<&str>) -> Result<SocketAddr, BindError> {
    let raw = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_HTTP_BIND);
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| BindError::Invalid(raw.to_string()))?;
    if !addr.ip().is_loopback() {
        return Err(BindError::NotLoopback(addr));
    }
    Ok(addr)
}

pub fn bind_from_env() -> Result<SocketAddr, BindError> {
    parse_http_bind(std::env::var("P5_HTTP_BIND").ok().as_deref())
}

#[derive(Debug)]
pub struct HttpOut {
    pub status: u16,
    pub body: String,
}

impl HttpOut {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            body: value.to_string(),
        }
    }
}

pub struct AgentState {
    pub root: PathBuf,
    pub sessions: Mutex<SessionMap>,
    pub http_bind: SocketAddr,
    pub dev_secret: Option<String>,
    pub stop: Arc<AtomicBool>,
}

impl AgentState {
    pub fn new(
        root: impl Into<PathBuf>,
        http_bind: SocketAddr,
        dev_secret: Option<String>,
    ) -> Self {
        Self {
            root: root.into(),
            sessions: Mutex::new(SessionMap::new()),
            http_bind,
            dev_secret,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn context(&self) -> Result<SmContext, SmError> {
        let mut ctx = SmContext::load(&self.root)?;
        ctx.sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // Authenticated loopback secret; pairing-key proof is a later PR.
        if self.dev_secret.as_deref().is_some_and(|s| !s.is_empty()) {
            ctx.dev_secret = true;
        }
        Ok(ctx)
    }

    pub fn our_typ(&self) -> Option<String> {
        let ctx = self.context().ok()?;
        ctx.homes.iter().next()?;
        Some(PeerType::Session.as_str().to_string())
    }
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn secrets_match(expected: &str, got: &str) -> bool {
    if expected.len() != got.len() {
        return false;
    }
    expected
        .bytes()
        .zip(got.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn authorize_msg(state: &AgentState, headers: &[(String, String)]) -> Result<(), HttpOut> {
    let Some(expected) = state.dev_secret.as_deref().filter(|s| !s.is_empty()) else {
        return Err(HttpOut::json(401, json!({"error":"unauthorized"})));
    };
    let Some(got) = header_value(headers, DEV_SECRET_HEADER) else {
        return Err(HttpOut::json(401, json!({"error":"unauthorized"})));
    };
    if !secrets_match(expected, got) {
        return Err(HttpOut::json(401, json!({"error":"unauthorized"})));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct MsgBody {
    to: String,
    from: String,
    id: String,
    #[serde(default = "default_wake")]
    wake: bool,
    #[serde(default = "default_mode")]
    mode: String,
    body: String,
}

fn default_wake() -> bool {
    true
}

fn default_mode() -> String {
    "live".into()
}

fn handle_msg(state: &AgentState, headers: &[(String, String)], body: &[u8]) -> HttpOut {
    if let Err(out) = authorize_msg(state, headers) {
        return out;
    }
    let parsed: MsgBody = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return HttpOut::json(400, json!({"error":"bad_request"})),
    };
    if let Some(key) = header_value(headers, IDEMPOTENCY_HEADER) {
        if key != parsed.id {
            return HttpOut::json(400, json!({"error":"idempotency_mismatch"}));
        }
    }

    let ctx = match state.context() {
        Ok(ctx) => ctx,
        Err(err) => {
            return HttpOut::json(500, json!({"error": err.to_string()}));
        }
    };

    let default_host = ctx
        .homes
        .iter()
        .next()
        .map(|(_, row)| row.enrolled_host.clone());
    let to = match PostalAddr::parse(&parsed.to, default_host.as_deref()) {
        Ok(addr) => addr,
        Err(err) => {
            return HttpOut::json(400, json!({"error":"bad_address","hint": err.to_string()}));
        }
    };
    let from = match PostalAddr::parse(&parsed.from, default_host.as_deref()) {
        Ok(addr) => addr,
        Err(err) => {
            return HttpOut::json(400, json!({"error":"bad_address","hint": err.to_string()}));
        }
    };
    let mode = match parsed.mode.parse::<DeliveryMode>() {
        Ok(m) => m,
        Err(_) => {
            return HttpOut::json(400, json!({"error":"bad_mode"}));
        }
    };
    let typ = declared_typ(&ctx, &to).unwrap_or(PeerType::Session);
    let inbound = Inbound {
        id: parsed.id,
        to,
        from,
        body: parsed.body,
        mode,
        typ,
        files: Vec::new(),
        no_wake: !parsed.wake,
    };

    match receive_msg(&ctx, &inbound) {
        Ok(rx) => {
            let typ = declared_typ(&ctx, &inbound.to).map(|t| t.as_str().to_string());
            HttpOut::json(
                200,
                json!({
                    "already": rx.already,
                    "typ": typ,
                    "status": "delivered",
                }),
            )
        }
        Err(ReceiveError::Permanent { reason, hint }) if reason == REASON_NO_AGENT => {
            HttpOut::json(
                409,
                json!({
                    "already": false,
                    "typ": declared_typ(&ctx, &inbound.to).map(|t| t.as_str().to_string()),
                    "status": "failed",
                    "reason": reason,
                    "hint": hint,
                }),
            )
        }
        Err(ReceiveError::Permanent { reason, hint }) => HttpOut::json(
            400,
            json!({
                "already": false,
                "status": "failed",
                "reason": reason,
                "hint": hint,
            }),
        ),
        Err(ReceiveError::Mailbox(err)) => HttpOut::json(500, json!({"error": err.to_string()})),
    }
}

pub fn handle_http(
    state: &AgentState,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> HttpOut {
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET", "/health") => HttpOut::json(200, json!({"ok": true})),
        ("GET", "/p5/whoami") => HttpOut::json(
            200,
            json!({
                "product": PRODUCT,
                "command": COMMAND,
                "site": SITE,
                "typ": state.our_typ(),
            }),
        ),
        ("POST", "/p5/msg") => handle_msg(state, headers, body),
        _ => HttpOut::json(404, json!({"error":"not_found"})),
    }
}

pub fn tls_paths_from_env() -> Result<Option<(PathBuf, PathBuf)>, String> {
    let cert = std::env::var_os("P5_TLS_CERT").map(PathBuf::from);
    let key = std::env::var_os("P5_TLS_KEY").map(PathBuf::from);
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) if cert.as_os_str().is_empty() && key.as_os_str().is_empty() => {
            Ok(None)
        }
        (Some(cert), Some(key)) if cert.exists() && key.exists() => Ok(Some((cert, key))),
        (Some(_), Some(_)) => Err("P5_TLS_CERT / P5_TLS_KEY must both exist".into()),
        _ => Err("set both P5_TLS_CERT and P5_TLS_KEY, or neither".into()),
    }
}

fn ssl_config(cert: &Path, key: &Path) -> Result<tiny_http::SslConfig, String> {
    let certificate = std::fs::read(cert).map_err(|e| format!("read P5_TLS_CERT: {e}"))?;
    let private_key = std::fs::read(key).map_err(|e| format!("read P5_TLS_KEY: {e}"))?;
    Ok(tiny_http::SslConfig {
        certificate,
        private_key,
    })
}

pub fn bind_http(
    addr: SocketAddr,
    ssl: Option<tiny_http::SslConfig>,
) -> Result<(Server, SocketAddr), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("http bind {addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("http local addr: {e}"))?;
    let server = Server::from_listener(listener, ssl).map_err(|e| format!("http server: {e}"))?;
    Ok((server, local))
}

pub fn serve_http(server: Arc<Server>, state: Arc<AgentState>) {
    while !state.stop.load(Ordering::Relaxed) {
        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(mut request)) => {
                let method = method_str(request.method());
                let url = request.url().to_string();
                let headers: Vec<(String, String)> = request
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_string(),
                            h.value.as_str().to_string(),
                        )
                    })
                    .collect();
                let mut body = Vec::new();
                if body_too_large(request.body_length()) {
                    let _ = request.respond(
                        Response::from_string(json!({"error":"too_large"}).to_string())
                            .with_status_code(StatusCode(413))
                            .with_header(json_header()),
                    );
                    continue;
                }
                if Read::read_to_end(request.as_reader(), &mut body).is_err() {
                    let _ = request.respond(
                        Response::from_string(json!({"error":"bad_request"}).to_string())
                            .with_status_code(StatusCode(400))
                            .with_header(json_header()),
                    );
                    continue;
                }
                let out = handle_http(&state, &method, &url, &headers, &body);
                let _ = request.respond(
                    Response::from_string(out.body)
                        .with_status_code(StatusCode(out.status))
                        .with_header(json_header()),
                );
            }
            Ok(None) => {}
            Err(_) => {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
}

fn body_too_large(len: Option<usize>) -> bool {
    match len {
        Some(n) => n > HEADER_LIMIT + p5_core::MAX_BODY_BYTES as usize,
        None => false,
    }
}

fn method_str(method: &Method) -> String {
    match method {
        Method::Get => "GET".into(),
        Method::Post => "POST".into(),
        Method::Put => "PUT".into(),
        Method::Delete => "DELETE".into(),
        Method::Head => "HEAD".into(),
        Method::Options => "OPTIONS".into(),
        Method::Patch => "PATCH".into(),
        other => other.to_string(),
    }
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("header")
}

pub fn load_ssl_from_env() -> Result<Option<tiny_http::SslConfig>, String> {
    match tls_paths_from_env()? {
        Some((cert, key)) => ssl_config(&cert, &key).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpStream};
    use std::thread;

    use p5_core::{HomeRow, Homes, Mailbox, ToolFlags};

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    fn home_row() -> HomeRow {
        HomeRow {
            address: addr("scout::acme.postal.bot"),
            session_id: Some("sess-1".into()),
            cwd: PathBuf::from("/srv/scout"),
            inbox_root: None,
            launch: vec!["claude".into()],
            harness: Some("claude".into()),
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake: true,
            },
            enrolled_host: "acme.postal.bot".into(),
        }
    }

    fn state_with_home(root: &Path, secret: Option<&str>) -> AgentState {
        let mut homes = Homes::new();
        homes.insert(home_row()).unwrap();
        homes.save(root).unwrap();
        AgentState::new(
            root,
            "127.0.0.1:0".parse().unwrap(),
            secret.map(str::to_string),
        )
    }

    #[test]
    fn refuse_unspecified_and_public_bind() {
        for raw in ["0.0.0.0:8443", "[::]:8443", "1.2.3.4:8443", "8.8.8.8:18765"] {
            match parse_http_bind(Some(raw)) {
                Err(BindError::NotLoopback(addr)) => {
                    assert!(!addr.ip().is_loopback(), "{raw}");
                    match addr.ip() {
                        IpAddr::V4(ip) => assert!(ip.is_unspecified() || !ip.is_loopback()),
                        IpAddr::V6(ip) => assert!(ip.is_unspecified() || !ip.is_loopback()),
                    }
                }
                other => panic!("{raw}: expected NotLoopback, got {other:?}"),
            }
        }
    }

    #[test]
    fn allow_loopback_default_and_dev_port() {
        assert_eq!(
            parse_http_bind(None).unwrap(),
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(
            parse_http_bind(Some("127.0.0.1:18765")).unwrap(),
            "127.0.0.1:18765".parse().unwrap()
        );
        assert_eq!(
            parse_http_bind(Some("[::1]:8443")).unwrap(),
            "[::1]:8443".parse().unwrap()
        );
    }

    #[test]
    fn health_and_whoami() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_home(tmp.path(), Some("s3cret"));
        let health = handle_http(&state, "GET", "/health", &[], b"");
        assert_eq!(health.status, 200);
        let v: Value = serde_json::from_str(&health.body).unwrap();
        assert_eq!(v["ok"], true);

        let who = handle_http(&state, "GET", "/p5/whoami", &[], b"");
        assert_eq!(who.status, 200);
        let v: Value = serde_json::from_str(&who.body).unwrap();
        assert_eq!(v["product"], "Postal");
        assert_eq!(v["command"], "p5");
        assert_eq!(v["site"], "postal.bot");
        assert_eq!(v["typ"], "session");
    }

    fn msg_headers(secret: &str, id: &str) -> Vec<(String, String)> {
        vec![
            (DEV_SECRET_HEADER.into(), secret.into()),
            (IDEMPOTENCY_HEADER.into(), id.into()),
        ]
    }

    fn sample_msg(id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "to": "scout",
            "from": "jarvis::other.postal.bot",
            "id": id,
            "wake": true,
            "mode": "live",
            "body": "hello scout",
        }))
        .unwrap()
    }

    const SAMPLE_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    #[test]
    fn post_msg_writes_inbox_and_dedupes() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_home(tmp.path(), Some("s3cret"));
        let headers = msg_headers("s3cret", SAMPLE_ID);
        let first = handle_http(&state, "POST", "/p5/msg", &headers, &sample_msg(SAMPLE_ID));
        assert_eq!(first.status, 200, "{}", first.body);
        let v: Value = serde_json::from_str(&first.body).unwrap();
        assert_eq!(v["already"], false);
        assert_eq!(v["status"], "delivered");
        assert_eq!(v["typ"], "session");

        let mb = Mailbox::new(tmp.path());
        let item = mb.read_inbox(SAMPLE_ID).unwrap();
        assert_eq!(item.body, "hello scout");
        assert_eq!(item.from, addr("jarvis::other.postal.bot"));

        let second = handle_http(&state, "POST", "/p5/msg", &headers, &sample_msg(SAMPLE_ID));
        assert_eq!(second.status, 200, "{}", second.body);
        let v: Value = serde_json::from_str(&second.body).unwrap();
        assert_eq!(v["already"], true);
        assert_eq!(v["status"], "delivered");
        assert_eq!(mb.read_inbox(SAMPLE_ID).unwrap().body, "hello scout");
    }

    #[test]
    fn post_msg_wrong_or_missing_secret_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_home(tmp.path(), Some("s3cret"));
        let body = sample_msg(SAMPLE_ID);

        let missing = handle_http(&state, "POST", "/p5/msg", &[], &body);
        assert_eq!(missing.status, 401);

        let wrong = handle_http(
            &state,
            "POST",
            "/p5/msg",
            &[("x-p5-dev-secret".into(), "nope".into())],
            &body,
        );
        assert_eq!(wrong.status, 401);
        assert!(Mailbox::new(tmp.path())
            .list_inbox(None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn post_msg_rejects_when_secret_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_home(tmp.path(), None);
        let headers = msg_headers("s3cret", SAMPLE_ID);
        let out = handle_http(&state, "POST", "/p5/msg", &headers, &sample_msg(SAMPLE_ID));
        assert_eq!(out.status, 401);
    }

    #[test]
    fn post_msg_no_homes_is_409() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AgentState::new(
            tmp.path(),
            "127.0.0.1:0".parse().unwrap(),
            Some("s3cret".into()),
        );
        let headers = msg_headers("s3cret", SAMPLE_ID);
        let body = serde_json::to_vec(&json!({
            "to": "scout::acme.postal.bot",
            "from": "jarvis::other.postal.bot",
            "id": SAMPLE_ID,
            "wake": true,
            "mode": "live",
            "body": "hello scout",
        }))
        .unwrap();
        let out = handle_http(&state, "POST", "/p5/msg", &headers, &body);
        assert_eq!(out.status, 409, "{}", out.body);
        let v: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(v["reason"], "no_agent");
    }

    fn raw_http(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        buf
    }

    #[test]
    fn tcp_health_whoami_and_msg() {
        let tmp = tempfile::tempdir().unwrap();
        let mut homes = Homes::new();
        homes.insert(home_row()).unwrap();
        homes.save(tmp.path()).unwrap();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (server, addr) = bind_http(bind, None).unwrap();
        let state = Arc::new(AgentState::new(tmp.path(), addr, Some("s3cret".into())));
        let stop = Arc::clone(&state);
        let server = Arc::new(server);
        let serve = {
            let server = Arc::clone(&server);
            let state = Arc::clone(&state);
            thread::spawn(move || serve_http(server, state))
        };

        let health = raw_http(
            addr,
            "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(health.contains("200"), "{health}");
        assert!(
            health.contains("\"ok\":true") || health.contains("\"ok\": true"),
            "{health}"
        );

        let who = raw_http(
            addr,
            "GET /p5/whoami HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(who.contains("Postal"), "{who}");
        assert!(who.contains("p5"), "{who}");
        assert!(who.contains("postal.bot"), "{who}");

        let body = String::from_utf8(sample_msg(SAMPLE_ID)).unwrap();
        let req = format!(
            "POST /p5/msg HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nx-p5-dev-secret: s3cret\r\nIdempotency-Key: {SAMPLE_ID}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let resp = raw_http(addr, &req);
        assert!(resp.contains("200"), "{resp}");
        assert!(
            resp.contains("\"already\":false") || resp.contains("\"already\": false"),
            "{resp}"
        );

        let resp2 = raw_http(addr, &req);
        assert!(resp2.contains("200"), "{resp2}");
        assert!(
            resp2.contains("\"already\":true") || resp2.contains("\"already\": true"),
            "{resp2}"
        );

        let bad = format!(
            "POST /p5/msg HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nx-p5-dev-secret: wrong\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let unauthorized = raw_http(addr, &bad);
        assert!(unauthorized.contains("401"), "{unauthorized}");

        stop.stop.store(true, Ordering::Relaxed);
        server.unblock();
        serve.join().unwrap();
    }
}
