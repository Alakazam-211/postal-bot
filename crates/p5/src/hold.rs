//! Hold send (after a definite live miss) and pull (poll / `p5 recv`).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p5_core::{
    default_root, DeliveryMode, DeliveryStatus, MailItem, MailboxError, PostalAddr, ReceiveRequest,
    Trust,
};
use p5_crypto::{is_holdseal_v1, KeyPair, SealAad};
use p5_plane::{
    decode_ciphertext, hold_poll_delay, live_send, HoldEnvelope, LiveSend, PlaneClient,
    PlaneConfig, PlaneError,
};

use crate::sm::{declared_typ, env_flag, MsgResponse, SmContext, SmError};

pub fn hold_enabled() -> bool {
    env_flag("P5_HOLD")
}

/// Live HTTP target is the enrolled host (`https://acme.postal.bot/p5/msg`).
/// Handle stays in the JSON `to`; nested `handle.host` DNS is not a route.
pub fn live_msg_url(to: &PostalAddr, override_base: Option<&str>) -> String {
    let base = match override_base.map(str::trim).filter(|s| !s.is_empty()) {
        Some(b) => b.trim_end_matches('/').to_string(),
        None => to.live_base_url(),
    };
    if base.ends_with("/p5/msg") {
        base
    } else {
        format!("{base}/p5/msg")
    }
}

fn queued(item: &MailItem, to: &PostalAddr) -> MsgResponse {
    MsgResponse::ok_status(
        item.id.clone(),
        to,
        DeliveryStatus::Queued,
        item.attempts,
        None,
        false,
    )
}

/// Live first. HOLD only on TCP refuse / 404 / 503 `host_down`, never after 2xx
/// and never on timeout/429 (peer may still be live).
pub fn finish_remote(
    ctx: &SmContext,
    item: &MailItem,
    to: &PostalAddr,
    from: &PostalAddr,
    body: &str,
) -> Result<MsgResponse, SmError> {
    if !ctx.hold {
        return Ok(queued(item, to));
    }

    let url = live_msg_url(to, ctx.live_url.as_deref());
    let payload = serde_json::json!({
        "to": to.to_string(),
        "from": from.to_string(),
        "id": item.id,
        "wake": true,
        "mode": item.mode.as_str(),
        "body": body,
    });
    match live_send(&url, ctx.live_timeout, &payload) {
        LiveSend::Delivered { .. } => {
            let marked = ctx
                .mailbox
                .mark(&item.id, DeliveryStatus::Delivered, None)?;
            Ok(MsgResponse::ok_status(
                marked.id,
                to,
                DeliveryStatus::Delivered,
                marked.attempts,
                None,
                false,
            ))
        }
        LiveSend::SoftMiss { .. } => Ok(queued(item, to)),
        LiveSend::DefiniteMiss { .. } => try_hold(ctx, item, to, from, body),
    }
}

fn try_hold(
    ctx: &SmContext,
    item: &MailItem,
    to: &PostalAddr,
    from: &PostalAddr,
    body: &str,
) -> Result<MsgResponse, SmError> {
    let Some(client) = plane_client(ctx) else {
        return Ok(queued(item, to));
    };
    let Some(pem) = peer_hold_pem(ctx, to) else {
        return Ok(queued(item, to));
    };
    match client.put_hold_sealed(
        &item.id,
        &to.to_string(),
        &from.to_string(),
        body.as_bytes(),
        pem,
    ) {
        Ok(_) => {
            let marked = ctx.mailbox.mark_held(&item.id, &item.id)?;
            Ok(MsgResponse::ok_status(
                marked.id,
                to,
                DeliveryStatus::Held,
                marked.attempts,
                None,
                false,
            ))
        }
        Err(_) => Ok(queued(item, to)),
    }
}

fn plane_client(ctx: &SmContext) -> Option<PlaneClient> {
    let token = ctx.plane_token.as_deref()?.trim();
    if token.is_empty() {
        return None;
    }
    Some(PlaneClient::new(&ctx.plane_url, token))
}

fn peer_hold_pem<'a>(ctx: &'a SmContext, to: &PostalAddr) -> Option<&'a str> {
    let entry = ctx.roster.get(to)?;
    if entry.trust != Trust::Trusted {
        return None;
    }
    let pem = entry.public_key_pem.trim();
    if pem.is_empty() || pem.contains("PRIVATE") {
        return None;
    }
    Some(pem)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullReport {
    pub pulled: usize,
    pub acked: usize,
    pub skipped: usize,
}

#[derive(Debug)]
pub enum PullError {
    Plane(PlaneError),
    Crypto(p5_crypto::CryptoError),
    Mailbox(MailboxError),
    Sm(SmError),
    Utf8,
    /// `p5 recv` / poll must not dial the plane unless `P5_HOLD=1`.
    HoldOff,
}

impl PullError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Plane(e) => e.exit_code(),
            Self::Mailbox(e) => e.exit_code(),
            Self::Sm(e) => e.exit_code(),
            _ => 1,
        }
    }
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plane(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Mailbox(e) => write!(f, "{e}"),
            Self::Sm(e) => write!(f, "{e}"),
            Self::Utf8 => f.write_str("hold plaintext is not utf-8"),
            Self::HoldOff => f.write_str("hold client is off; set P5_HOLD=1"),
        }
    }
}

impl std::error::Error for PullError {}

impl From<PlaneError> for PullError {
    fn from(e: PlaneError) -> Self {
        Self::Plane(e)
    }
}

impl From<p5_crypto::CryptoError> for PullError {
    fn from(e: p5_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<MailboxError> for PullError {
    fn from(e: MailboxError) -> Self {
        Self::Mailbox(e)
    }
}

impl From<SmError> for PullError {
    fn from(e: SmError) -> Self {
        Self::Sm(e)
    }
}

/// One GET → decrypt → fsync inbox → ACK. ACK only after the cover is on disk.
pub fn pull_held(root: &Path) -> Result<PullReport, PullError> {
    if !hold_enabled() {
        return Err(PullError::HoldOff);
    }
    let ctx = SmContext::load(root)?;
    let cfg = PlaneConfig::load(root)?;
    let client = PlaneClient::new(&cfg.base_url, cfg.require_token()?);
    let keys = KeyPair::load_or_create(root)?;
    pull_with(&ctx, &client, &keys)
}

pub fn pull_with(
    ctx: &SmContext,
    client: &PlaneClient,
    keys: &KeyPair,
) -> Result<PullReport, PullError> {
    let list = client.list_hold()?;
    let mut report = PullReport::default();
    for env in list.items {
        match take_one(ctx, client, keys, &env) {
            Ok(Take::Pulled) => {
                report.pulled += 1;
                report.acked += 1;
            }
            Ok(Take::AckedAlready) => report.acked += 1,
            Ok(Take::Skipped) => report.skipped += 1,
            Err(PullError::Plane(_)) => report.skipped += 1,
            Err(err) => return Err(err),
        }
    }
    Ok(report)
}

enum Take {
    Pulled,
    AckedAlready,
    Skipped,
}

fn take_one(
    ctx: &SmContext,
    client: &PlaneClient,
    keys: &KeyPair,
    env: &HoldEnvelope,
) -> Result<Take, PullError> {
    let Ok(to) = PostalAddr::parse(&env.to, None) else {
        return Ok(Take::Skipped);
    };
    let Ok(from) = PostalAddr::parse(&env.from, None) else {
        return Ok(Take::Skipped);
    };
    if !is_ours(ctx, &to) {
        return Ok(Take::Skipped);
    }
    if !from_trusted(ctx, &from) {
        return Ok(Take::Skipped);
    }
    if inbox_has(ctx, &env.id)? {
        client.ack_hold(&env.id)?;
        return Ok(Take::AckedAlready);
    }
    let blob = match decode_ciphertext(&env.ciphertext) {
        Ok(b) if is_holdseal_v1(&b) => b,
        _ => return Ok(Take::Skipped),
    };
    let aad = SealAad {
        id: env.id.clone(),
        from: from.to_string(),
        to: to.to_string(),
    };
    let pt = match keys.open(&blob, &aad) {
        Ok(pt) => pt,
        Err(_) => return Ok(Take::Skipped),
    };
    let body = String::from_utf8(pt).map_err(|_| PullError::Utf8)?;
    let typ = declared_typ(ctx, &to).unwrap_or(p5_core::PeerType::Session);
    ctx.mailbox.receive(ReceiveRequest {
        id: env.id.clone(),
        to,
        from,
        body,
        mode: DeliveryMode::Tray,
        typ,
        files: Vec::new(),
        files_allowed: false,
        title: None,
        hold_id: Some(env.id.clone()),
    })?;
    client.ack_hold(&env.id)?;
    Ok(Take::Pulled)
}

fn is_ours(ctx: &SmContext, to: &PostalAddr) -> bool {
    ctx.dest_is_local(to) || ctx.homes.get(to).is_some()
}

fn from_trusted(ctx: &SmContext, from: &PostalAddr) -> bool {
    ctx.roster
        .get(from)
        .is_some_and(|e| e.trust == Trust::Trusted)
}

fn inbox_has(ctx: &SmContext, id: &str) -> Result<bool, PullError> {
    match ctx.mailbox.read_inbox(id) {
        Ok(_) => Ok(true),
        Err(MailboxError::NotFound { .. }) | Err(MailboxError::InvalidId) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

pub fn poll_loop(root: PathBuf, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        if let Err(err) = pull_held(&root) {
            eprintln!("postal hold poll: {err}");
        }
        let delay = hold_poll_delay(random_unit());
        let start = Instant::now();
        while start.elapsed() < delay {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn random_unit() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    h.write_u64(nanos);
    h.write_u32(std::process::id());
    (h.finish() as f64) / (u64::MAX as f64)
}

pub fn run_recv() -> Result<PullReport, PullError> {
    pull_held(&default_root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use p5_core::{HomeRow, PeerType, RosterEntry, ToolFlags};
    use p5_plane::seal_envelope;

    use crate::sm::{send_msg, MsgRequest};

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    fn roster_peer(kp: &KeyPair) -> RosterEntry {
        RosterEntry {
            typ: PeerType::Session,
            fingerprint: kp.fingerprint(),
            public_key_pem: kp.public_key_pem(),
            trust: Trust::Trusted,
            pair_id: "p1".into(),
            sand_uuid: None,
            tools: ToolFlags::default(),
        }
    }

    fn home_row(address: &str) -> HomeRow {
        let address = addr(address);
        let host = address.host().to_string();
        HomeRow {
            address,
            session_id: Some("sess-1".into()),
            cwd: PathBuf::from("/srv"),
            inbox_root: None,
            launch: vec!["claude".into()],
            harness: Some("claude".into()),
            terminal: None,
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake: true,
            },
            enrolled_host: host,
        }
    }

    fn msg(to: &str, body: &str) -> MsgRequest {
        MsgRequest {
            to: to.into(),
            body: body.into(),
            no_wake: false,
            cwd: None,
            session_ids: Vec::new(),
        }
    }

    #[derive(Default)]
    struct HoldState {
        requests: Vec<(String, String, String)>,
        items: Vec<HoldEnvelope>,
    }

    fn spawn_hold_plane(state: Arc<Mutex<HoldState>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            for _ in 0..2_000 {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_hold(stream, &state);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        format!("http://{addr}")
    }

    fn handle_hold(
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
            route_hold(&rec, &mut st)
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

    fn route_hold(rec: &Rec, st: &mut HoldState) -> (u16, String) {
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

    fn spawn_live(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let rec = match read_http(&mut stream) {
                    Some(r) => r,
                    None => continue,
                };
                let _ = rec;
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn hold_ctx(root: &Path, live: Option<String>, plane: &str, peer: &KeyPair) -> SmContext {
        let mut ctx = SmContext::new(root);
        ctx.hold = true;
        ctx.live_url = live;
        ctx.plane_url = plane.into();
        ctx.plane_token = Some("k2c_test".into());
        ctx.live_timeout = Duration::from_secs(2);
        ctx.homes.insert(home_row("alice::acme.postal.bot")).unwrap();
        ctx.roster
            .insert(addr("scout::acme.postal.bot"), roster_peer(peer));
        ctx
    }

    #[test]
    fn live_2xx_never_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state.clone());
        let live = spawn_live(200, r#"{"status":"delivered"}"#);
        let ctx = hold_ctx(tmp.path(), Some(live), &plane, &bob);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "hello live")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("delivered"));
        let puts: Vec<_> = state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(m, p, _)| m == "PUT" && p == "/postal/hold")
            .cloned()
            .collect();
        assert!(puts.is_empty(), "live 2xx must not HOLD: {puts:?}");
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Delivered
        );
    }

    #[test]
    fn timeout_never_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(2));
                drop(stream);
            }
        });
        let mut ctx = hold_ctx(tmp.path(), Some(format!("http://{addr}")), &plane, &bob);
        ctx.live_timeout = Duration::from_millis(150);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "maybe live")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert!(state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|(m, p, _)| !(m == "PUT" && p == "/postal/hold")));
    }

    #[test]
    fn rate_limit_429_never_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state.clone());
        let live = spawn_live(429, r#"{"error":"rate"}"#);
        let ctx = hold_ctx(tmp.path(), Some(live), &plane, &bob);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "slow down")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert!(state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|(m, p, _)| !(m == "PUT" && p == "/postal/hold")));
    }

    #[test]
    fn definite_miss_plane_up_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state.clone());
        // Port 1: TCP refuse is a definite tunnel-down miss.
        let ctx = hold_ctx(tmp.path(), Some("http://127.0.0.1:1".into()), &plane, &bob);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "secret cover")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("held"));
        let id = resp.id.as_deref().unwrap();
        let sent = ctx.mailbox.read_sent(id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Held);
        assert_eq!(sent.hold_id.as_deref(), Some(id));
        assert!(ctx.mailbox.list_outbox().unwrap().is_empty());
        let st = state.lock().unwrap();
        let put = st
            .requests
            .iter()
            .find(|(m, p, _)| m == "PUT" && p == "/postal/hold")
            .expect("hold PUT");
        assert!(!put.2.contains("secret cover"));
        assert_eq!(st.items.len(), 1);
        let blob = decode_ciphertext(&st.items[0].ciphertext).unwrap();
        assert!(is_holdseal_v1(&blob));
        assert_eq!(
            bob.open(
                &blob,
                &SealAad {
                    id: id.into(),
                    from: "alice::acme.postal.bot".into(),
                    to: "scout::acme.postal.bot".into(),
                }
            )
            .unwrap(),
            b"secret cover"
        );
    }

    #[test]
    fn definite_miss_plane_down_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let ctx = hold_ctx(
            tmp.path(),
            Some("http://127.0.0.1:1".into()),
            "http://127.0.0.1:1",
            &bob,
        );
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "later")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("queued"));
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Queued
        );
        assert_eq!(ctx.mailbox.list_outbox().unwrap().len(), 1);
    }

    #[test]
    fn host_down_503_holds_when_plane_up() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state.clone());
        let live = spawn_live(503, r#"{"error":"host_down"}"#);
        let ctx = hold_ctx(tmp.path(), Some(live), &plane, &bob);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "tray me")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("held"));
    }

    #[test]
    fn live_404_holds_when_plane_up() {
        let tmp = tempfile::tempdir().unwrap();
        let bob = KeyPair::generate();
        let state = Arc::new(Mutex::new(HoldState::default()));
        let plane = spawn_hold_plane(state);
        let live = spawn_live(404, r#"{"error":"not_found"}"#);
        let ctx = hold_ctx(tmp.path(), Some(live), &plane, &bob);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "gone")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("held"));
    }

    #[test]
    fn hold_off_does_not_touch_live_or_plane() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.homes
            .insert(home_row("alice::acme.postal.bot"))
            .unwrap();
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "offline")).unwrap();
        assert_eq!(resp.status.as_deref(), Some("queued"));
    }

    #[test]
    fn pull_decrypts_fsyncs_and_acks() {
        let tmp = tempfile::tempdir().unwrap();
        let alice = KeyPair::load_or_create(tmp.path()).unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.homes
            .insert(home_row("alice::acme.postal.bot"))
            .unwrap();
        let bob = KeyPair::generate();
        ctx.roster
            .insert(addr("bob::acme.postal.bot"), roster_peer(&bob));
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
        let state = Arc::new(Mutex::new(HoldState {
            items: vec![env],
            requests: Vec::new(),
        }));
        let plane = spawn_hold_plane(state.clone());
        let client = PlaneClient::new(plane, "k2c_test");
        let report = pull_with(&ctx, &client, &alice).unwrap();
        assert_eq!(report.pulled, 1);
        assert_eq!(report.acked, 1);
        let item = ctx.mailbox.read_inbox(id).unwrap();
        assert_eq!(item.body, "held body");
        assert_eq!(item.hold_id.as_deref(), Some(id));
        assert!(state.lock().unwrap().items.is_empty());
        assert!(state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|(m, p, _)| m == "POST" && p.ends_with("/ack")));
    }

    #[test]
    fn pull_does_not_ack_if_open_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let alice = KeyPair::load_or_create(tmp.path()).unwrap();
        let other = KeyPair::generate();
        let mut ctx = SmContext::new(tmp.path());
        ctx.homes
            .insert(home_row("alice::acme.postal.bot"))
            .unwrap();
        let bob = KeyPair::generate();
        ctx.roster
            .insert(addr("bob::acme.postal.bot"), roster_peer(&bob));
        let env = seal_envelope(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "alice::acme.postal.bot",
            "bob::acme.postal.bot",
            b"nope",
            &other.public_key_pem(),
            Duration::from_secs(60),
        )
        .unwrap();
        let state = Arc::new(Mutex::new(HoldState {
            items: vec![env],
            requests: Vec::new(),
        }));
        let plane = spawn_hold_plane(state.clone());
        let client = PlaneClient::new(plane, "k2c_test");
        let report = pull_with(&ctx, &client, &alice).unwrap();
        assert_eq!(report.pulled, 0);
        assert_eq!(report.skipped, 1);
        assert_eq!(state.lock().unwrap().items.len(), 1);
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn live_url_uses_enrolled_host_not_nested_handle() {
        let to = addr("scout::acme.postal.bot");
        assert_eq!(to.live_base_url(), "https://acme.postal.bot");
        assert_eq!(live_msg_url(&to, None), "https://acme.postal.bot/p5/msg");
        assert!(
            !live_msg_url(&to, None).contains("scout.acme"),
            "handle must not become a DNS label"
        );
        assert_eq!(
            live_msg_url(&to, Some("http://127.0.0.1:9")),
            "http://127.0.0.1:9/p5/msg"
        );
    }
}
