//! Hold CLI against a local mock plane (never hits k2.dev).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use p5_core::{
    HomeRow, Homes, Mailbox, PeerType, PostalAddr, Roster, RosterEntry, ToolFlags, Trust,
};
use p5_crypto::{is_holdseal_v1, KeyPair};
use p5_plane::{decode_ciphertext, seal_envelope, HoldEnvelope};

fn p5() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p5"))
}

fn isolate(cmd: &mut Command) {
    cmd.env_remove("P5_HOLD")
        .env_remove("P5_TYP")
        .env_remove("P5_FROM")
        .env_remove("P5_CONNECT_TOKEN")
        .env_remove("P5_PLANE_URL")
        .env_remove("P5_LIVE_URL");
}

fn run_home(home: &Path, url: &str, args: &[&str], extra: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = p5();
    isolate(&mut cmd);
    cmd.env("P5_HOME", home)
        .env("P5_PLANE_URL", url)
        .env("P5_CONNECT_TOKEN", "k2c_test")
        .env("P5_FROM", "alice::acme.postal.bot")
        .env("P5_HOLD", "1")
        .env("P5_LIVE_URL", "http://127.0.0.1:1")
        .args(args);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|err| panic!("run p5 {args:?}: {err}"))
}

#[derive(Default)]
struct HoldState {
    requests: Vec<(String, String, String)>,
    items: Vec<HoldEnvelope>,
}

struct MockPlane {
    url: String,
    state: Arc<Mutex<HoldState>>,
}

impl MockPlane {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(HoldState::default()));
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
}

fn handle_conn(
    mut stream: std::net::TcpStream,
    state: &Arc<Mutex<HoldState>>,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let rec = match read_http(&mut stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let (status, body) = {
        let mut st = state.lock().unwrap();
        st.requests
            .push((rec.method.clone(), rec.path.clone(), rec.body.clone()));
        route(&rec, &mut st)
    };
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    Ok(())
}

struct Rec {
    method: String,
    path: String,
    body: String,
}

fn read_http(stream: &mut std::net::TcpStream) -> Option<Rec> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(r) = parse_http(&buf) {
                    return Some(r);
                }
            }
            Err(_) => break,
        }
    }
    parse_http(&buf)
}

fn parse_http(buf: &[u8]) -> Option<Rec> {
    let raw = std::str::from_utf8(buf).ok()?;
    let (head, rest) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if rest.len() < content_len {
        return None;
    }
    Some(Rec {
        method,
        path,
        body: rest[..content_len].to_string(),
    })
}

fn route(rec: &Rec, st: &mut HoldState) -> (u16, String) {
    let path = rec.path.split('?').next().unwrap_or(&rec.path);
    match (rec.method.as_str(), path) {
        ("PUT", "/postal/hold") => {
            let env: HoldEnvelope = match serde_json::from_str(&rec.body) {
                Ok(e) => e,
                Err(_) => return (400, r#"{"error":"bad"}"#.into()),
            };
            match decode_ciphertext(&env.ciphertext) {
                Ok(b) if is_holdseal_v1(&b) => {}
                _ => return (400, r#"{"error":"plaintext"}"#.into()),
            }
            st.items.retain(|e| e.id != env.id);
            let id = env.id.clone();
            st.items.push(env);
            (200, format!(r#"{{"ok":true,"id":"{id}"}}"#))
        }
        ("GET", "/postal/hold") => {
            let items = serde_json::to_string(&st.items).unwrap();
            (200, format!(r#"{{"items":{items}}}"#))
        }
        (m, p) if m == "POST" && p.starts_with("/postal/hold/") && p.ends_with("/ack") => {
            let id = p
                .trim_start_matches("/postal/hold/")
                .trim_end_matches("/ack");
            st.items.retain(|e| e.id != id);
            (200, r#"{"ok":true}"#.into())
        }
        _ => (404, r#"{"error":"not_found"}"#.into()),
    }
}

fn add_home(root: &Path, address: &str) {
    let address: PostalAddr = address.parse().unwrap();
    let host = address.host().to_string();
    let mut homes = Homes::load(root).unwrap();
    homes
        .insert(HomeRow {
            address,
            session_id: Some("sess-1".into()),
            cwd: root.to_path_buf(),
            inbox_root: None,
            launch: vec!["claude".into()],
            harness: Some("claude".into()),
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake: true,
            },
            enrolled_host: host,
        })
        .unwrap();
    homes.save(root).unwrap();
}

fn add_peer(root: &Path, address: &str, kp: &KeyPair) {
    let mut roster = Roster::load(root).unwrap();
    roster.insert(
        address.parse().unwrap(),
        RosterEntry {
            typ: PeerType::Session,
            fingerprint: kp.fingerprint(),
            public_key_pem: kp.public_key_pem(),
            trust: Trust::Trusted,
            pair_id: "p1".into(),
            sand_uuid: None,
            tools: ToolFlags::default(),
        },
    );
    roster.save(root).unwrap();
}

#[test]
fn msg_tunnel_down_plane_up_is_held() {
    let home = tempfile::tempdir().unwrap();
    let bob = KeyPair::generate();
    add_peer(home.path(), "scout::acme.postal.bot", &bob);
    let plane = MockPlane::start();
    let out = run_home(
        home.path(),
        &plane.url,
        &[
            "msg",
            "scout::acme.postal.bot",
            "secret cover",
            "--from",
            "alice::acme.postal.bot",
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("held"), "{text}");
    let puts: Vec<_> = plane
        .state
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(m, p, _)| m == "PUT" && p == "/postal/hold")
        .cloned()
        .collect();
    assert_eq!(puts.len(), 1);
    assert!(!puts[0].2.contains("secret cover"));
}

#[test]
fn recv_pulls_decrypts_and_acks() {
    let home = tempfile::tempdir().unwrap();
    add_home(home.path(), "alice::acme.postal.bot");
    let alice = KeyPair::load_or_create(home.path()).unwrap();
    let bob = KeyPair::generate();
    add_peer(home.path(), "bob::acme.postal.bot", &bob);
    let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let env = seal_envelope(
        id,
        "alice::acme.postal.bot",
        "bob::acme.postal.bot",
        b"held body",
        &alice.public_key_pem(),
        Duration::from_secs(60),
    )
    .unwrap();
    let plane = MockPlane::start();
    plane.state.lock().unwrap().items.push(env);
    let out = run_home(home.path(), &plane.url, &["recv"], &[]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("pulled 1"), "{text}");
    let mb = Mailbox::new(home.path());
    assert_eq!(mb.read_inbox(id).unwrap().body, "held body");
    assert!(plane.state.lock().unwrap().items.is_empty());
}
