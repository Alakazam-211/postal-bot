//! Pairing CLI against a local mock plane (never hits k2.dev).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use p5_core::{PeerType, PostalAddr, Roster, Trust};
use p5_crypto::{fingerprint_spki_pem, sas_code, KeyPair};
use p5_plane::PairView;

fn p5() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p5"))
}

fn run_home(home: &Path, url: &str, args: &[&str], extra: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = p5();
    cmd.env("P5_HOME", home)
        .env("P5_PLANE_URL", url)
        .env("P5_CONNECT_TOKEN", "k2c_test")
        .env("P5_FROM", "alice::acme.postal.bot")
        .args(args);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|err| panic!("run p5 {args:?}: {err}"))
}

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    auth: String,
    body: String,
}

struct MockPlane {
    url: String,
    state: Arc<Mutex<MockState>>,
}

struct MockState {
    requests: Vec<Recorded>,
    inbox: Vec<PairView>,
    friends: Vec<PairView>,
    sent: Vec<PairView>,
    pair_id: String,
    pair_sas: Option<String>,
}

impl MockPlane {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(MockState {
            requests: Vec::new(),
            inbox: Vec::new(),
            friends: Vec::new(),
            sent: Vec::new(),
            pair_id: "pair-1".into(),
            pair_sas: Some("482193".into()),
        }));
        let state2 = state.clone();
        thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            for _ in 0..2_000 {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_conn(stream, &state2);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    fn set_inbox(&self, inbox: Vec<PairView>) {
        self.state.lock().unwrap().inbox = inbox;
    }
}

fn handle_conn(
    mut stream: std::net::TcpStream,
    state: &Arc<Mutex<MockState>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let rec = match read_http(&mut stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let (status, body) = {
        let mut st = state.lock().unwrap();
        let reply = route(&rec, &st);
        st.requests.push(rec);
        reply
    };
    let resp = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        if (200..300).contains(&status) {
            "OK"
        } else {
            "ERR"
        },
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    Ok(())
}

fn read_http(stream: &mut std::net::TcpStream) -> Option<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(rec) = parse_http(&buf) {
                    return Some(rec);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => return None,
        }
    }
    parse_http(&buf)
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

fn route(rec: &Recorded, st: &MockState) -> (u16, String) {
    if !rec.auth.starts_with("Bearer k2c_") {
        return (401, r#"{"error":"unauthorized"}"#.into());
    }
    if rec.body.contains("PRIVATE") || rec.body.contains("BEGIN PRIVATE") {
        return (400, r#"{"error":"private key refused"}"#.into());
    }
    let (path, query) = rec.path.split_once('?').unwrap_or((rec.path.as_str(), ""));
    match (rec.method.as_str(), path) {
        ("PUT", "/postal/me") => {
            let v: serde_json::Value = serde_json::from_str(&rec.body).unwrap_or_default();
            let addr = v.get("addr").and_then(|a| a.as_str()).unwrap_or("");
            (
                200,
                format!(r#"{{"ok":true,"addr":"{addr}","fingerprint":"aa"}}"#),
            )
        }
        ("POST", "/postal/pair") => {
            let sas = st
                .pair_sas
                .as_deref()
                .map(|s| format!("\"{s}\""))
                .unwrap_or_else(|| "null".into());
            (
                200,
                format!(
                    r#"{{"ok":true,"id":"{}","created":true,"sas":{sas}}}"#,
                    st.pair_id
                ),
            )
        }
        ("GET", "/postal/pairs") => {
            let inbox = serde_json::to_string(&st.inbox).unwrap();
            if query.contains("inbox=1") {
                (200, format!(r#"{{"inbox":{inbox}}}"#))
            } else {
                let friends = serde_json::to_string(&st.friends).unwrap();
                let sent = serde_json::to_string(&st.sent).unwrap();
                (
                    200,
                    format!(r#"{{"inbox":{inbox},"friends":{friends},"sent":{sent}}}"#),
                )
            }
        }
        ("POST", p) if p.starts_with("/postal/pair/") && p.ends_with("/accept") => {
            (200, r#"{"ok":true}"#.into())
        }
        ("POST", p) if p.starts_with("/postal/pair/") && p.ends_with("/reject") => {
            (200, r#"{"ok":true}"#.into())
        }
        ("POST", p) if p.starts_with("/postal/pair/") && p.ends_with("/revoke") => {
            (200, r#"{"ok":true}"#.into())
        }
        _ => (404, r#"{"error":"not found"}"#.into()),
    }
}

fn view(
    id: &str,
    from: &str,
    to: &str,
    status: &str,
    sas: &str,
    typ: PeerType,
    pem: &str,
) -> PairView {
    PairView {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        from_handle: Some(from.split("::").next().unwrap_or(from).into()),
        from_host: Some(from.split("::").nth(1).unwrap_or("").into()),
        from_typ: Some(typ),
        owner_email: None,
        owner_name: None,
        sas: Some(sas.into()),
        status: status.into(),
        epoch: 0,
        public_key_pem: Some(pem.into()),
        fingerprint: fingerprint_spki_pem(pem).ok(),
    }
}

fn tmp_home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn pair_add_publishes_me_then_pair() {
    let home = tmp_home();
    let mock = MockPlane::start();
    let out = run_home(
        home.path(),
        &mock.url,
        &["pair", "add", "scout::acme.postal.bot"],
        &[],
    );
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("pair-1"));
    assert!(text.contains("alice::acme.postal.bot"));
    assert!(text.contains("scout::acme.postal.bot"));
    assert!(text.contains("sas=482193"));

    let reqs = mock.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "PUT" && r.path == "/postal/me"),
        "expected PUT /postal/me, got {reqs:?}"
    );
    assert!(reqs
        .iter()
        .any(|r| r.method == "POST" && r.path == "/postal/pair"));
    for r in &reqs {
        assert_eq!(r.auth, "Bearer k2c_test");
        assert!(
            !r.body.contains("PRIVATE"),
            "private key leaked on {} {}: {}",
            r.method,
            r.path,
            r.body
        );
        if r.path == "/postal/me" || r.path == "/postal/pair" {
            assert!(r.body.contains("BEGIN PUBLIC KEY"));
            let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            assert!(v["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY"));
            assert!(!v.to_string().contains("PRIVATE"));
        }
    }
}

#[test]
fn pair_me_public_only() {
    let home = tmp_home();
    let mock = MockPlane::start();
    let out = run_home(home.path(), &mock.url, &["me"], &[]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("alice::acme.postal.bot"));
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "PUT");
    assert_eq!(reqs[0].path, "/postal/me");
    assert!(reqs[0].body.contains("BEGIN PUBLIC KEY"));
    assert!(!reqs[0].body.contains("PRIVATE"));
    let v: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
    assert_eq!(v["addr"], "alice::acme.postal.bot");
    assert_eq!(v["typ"], "session");
    assert!(v.get("private_key_pem").is_none());
}

#[test]
fn pair_list_and_show_sas() {
    let home = tmp_home();
    let mock = MockPlane::start();
    let local = KeyPair::load_or_create(home.path()).unwrap();
    let peer = KeyPair::generate();
    let sas = sas_code(&local.fingerprint(), &peer.fingerprint());
    mock.set_inbox(vec![view(
        "pair-9",
        "scout::acme.postal.bot",
        "alice::acme.postal.bot",
        "pending",
        &sas,
        PeerType::Session,
        &peer.public_key_pem(),
    )]);

    let list = run_home(home.path(), &mock.url, &["pair", "list", "--inbox"], &[]);
    assert!(
        list.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed = String::from_utf8_lossy(&list.stdout);
    assert!(listed.contains("pair-9"));
    assert!(listed.contains("scout::acme.postal.bot"));
    assert!(listed.contains(&format!("sas={sas}")));

    let show = run_home(home.path(), &mock.url, &["pair", "show", "pair-9"], &[]);
    assert!(
        show.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("from    scout::acme.postal.bot"));
    assert!(shown.contains("to      alice::acme.postal.bot"));
    assert!(shown.contains("status  pending"));
    assert!(shown.contains(&format!("sas     {sas}")));
    assert!(shown.contains(&local.fingerprint()));
    assert!(shown.contains(&peer.fingerprint()));

    let roster = Roster::load(home.path()).unwrap();
    let peer_addr: PostalAddr = "scout::acme.postal.bot".parse().unwrap();
    let row = roster.get(&peer_addr).expect("roster updated");
    assert_eq!(row.typ, PeerType::Session);
    assert_eq!(row.trust, Trust::Pending);
    assert_eq!(row.pair_id, "pair-9");
    assert_eq!(row.public_key_pem, peer.public_key_pem());
    assert_eq!(row.fingerprint, peer.fingerprint());
}

#[test]
fn pair_accept_gated_without_owner_flag() {
    let home = tmp_home();
    let mock = MockPlane::start();
    let out = run_home(
        home.path(),
        &mock.url,
        &["pair", "accept", "pair-1"],
        &[("P5_OWNER_PAIR", "0")],
    );
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("gated"));
    assert!(err.contains("/dashboard?tab=postal"));
    assert!(
        mock.requests().is_empty(),
        "gated accept must not hit the plane"
    );
}

#[test]
fn pair_accept_with_owner_flag() {
    let home = tmp_home();
    let mock = MockPlane::start();
    let peer = KeyPair::generate();
    mock.set_inbox(vec![view(
        "pair-1",
        "scout::acme.postal.bot",
        "alice::acme.postal.bot",
        "pending",
        "482193",
        PeerType::Turn,
        &peer.public_key_pem(),
    )]);
    let out = run_home(
        home.path(),
        &mock.url,
        &["pair", "accept", "pair-1", "--sas", "482193"],
        &[("P5_OWNER_PAIR", "1")],
    );
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = mock.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "POST" && r.path == "/postal/pair/pair-1/accept"),
        "expected accept POST, got {reqs:?}"
    );
    let accept = reqs.iter().find(|r| r.path.ends_with("/accept")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&accept.body).unwrap();
    assert_eq!(v["sas"], "482193");
    assert!(!accept.body.contains("PRIVATE"));
}

#[test]
fn pair_reject_and_revoke_are_gated() {
    let home = tmp_home();
    let mock = MockPlane::start();
    for verb in ["reject", "revoke"] {
        let out = run_home(home.path(), &mock.url, &["pair", verb, "pair-1"], &[]);
        assert_eq!(out.status.code(), Some(3), "{verb}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("gated"), "{verb}");
    }
    assert!(mock.requests().is_empty());
}

#[test]
fn login_writes_connect_token() {
    let home = tmp_home();
    let out = p5()
        .env("P5_HOME", home.path())
        .env("P5_LOGIN_NO_START", "1")
        .args(["login", "--token", "k2c_saved"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(cfg.contains("k2c_saved"));
}
