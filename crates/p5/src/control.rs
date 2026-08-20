//! UDS control plane (`agent.sock`). Framed JSON, mode 0600.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::http::AgentState;
use crate::sm::{send_msg, MsgRequest, MsgResponse};

pub const SOCK_NAME: &str = "agent.sock";
pub const PID_NAME: &str = "agent.pid";
const MAX_FRAME: u32 = 1024 * 1024;
/// Must outlive a live POST so the CLI waits for the agent's MsgResponse.
pub const UDS_TIMEOUT: Duration = Duration::from_secs(p5_live::DEFAULT_TIMEOUT.as_secs() + 2);

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlReq {
    Status,
    Stop,
    Send {
        to: String,
        body: String,
        #[serde(default)]
        no_wake: bool,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        session_ids: Vec<String>,
    },
    /// Pack a live session onto the in-memory map (`p5 handle claim`).
    Register {
        addr: String,
        session_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub agent: String,
    pub tunnel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ControlResp {
    Status {
        ok: bool,
        agent: String,
        tunnel: String,
        http: String,
    },
    Stop {
        ok: bool,
        stopped: bool,
    },
    Send(MsgResponse),
    Register {
        ok: bool,
        live: bool,
    },
    Error {
        ok: bool,
        error: String,
    },
}

pub fn sock_path(root: &Path) -> PathBuf {
    root.join(SOCK_NAME)
}

pub fn pid_path(root: &Path) -> PathBuf {
    root.join(PID_NAME)
}

pub fn bind_uds(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        // Stale socket from a dead agent; live agents accept immediately.
        if UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("agent already running at {}", path.display()),
            ));
        }
        let _ = std::fs::remove_file(path);
    }
    if let Some(parent) = path.parent() {
        p5_core::ensure_dir(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub fn serve_uds(listener: UnixListener, state: Arc<AgentState>) {
    while !state.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(UDS_TIMEOUT));
                let _ = stream.set_write_timeout(Some(UDS_TIMEOUT));
                if let Err(err) = handle_client(&mut stream, &state) {
                    let _ = write_frame(
                        &mut stream,
                        &ControlResp::Error {
                            ok: false,
                            error: err,
                        },
                    );
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn handle_client(stream: &mut UnixStream, state: &AgentState) -> Result<(), String> {
    let bytes = read_frame(stream).map_err(|e| e.to_string())?;
    let req: ControlReq = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let resp = match req {
        ControlReq::Status => ControlResp::Status {
            ok: true,
            agent: "up".into(),
            tunnel: if state.tunnel_up.load(Ordering::Relaxed) {
                "up".into()
            } else {
                "down".into()
            },
            http: state.http_bind.to_string(),
        },
        ControlReq::Stop => {
            state.stop.store(true, Ordering::Relaxed);
            ControlResp::Stop {
                ok: true,
                stopped: true,
            }
        }
        ControlReq::Send {
            to,
            body,
            no_wake,
            cwd,
            session_ids,
        } => {
            let resp = match state.context() {
                Ok(ctx) => match send_msg(
                    &ctx,
                    &MsgRequest {
                        to,
                        body,
                        no_wake,
                        cwd: cwd.map(PathBuf::from),
                        session_ids,
                    },
                ) {
                    Ok(resp) => resp,
                    Err(err) => MsgResponse::from_error(err.to_string()),
                },
                Err(err) => MsgResponse::from_error(err.to_string()),
            };
            ControlResp::Send(resp)
        }
        ControlReq::Register { addr, session_id } => {
            match addr.parse::<p5_core::PostalAddr>() {
                Ok(parsed) => {
                    let mut map = state.sessions.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(
                        parsed,
                        crate::session_map::LiveSession {
                            session_id,
                            ready: true,
                        },
                    );
                    ControlResp::Register {
                        ok: true,
                        live: true,
                    }
                }
                Err(err) => ControlResp::Error {
                    ok: false,
                    error: err.to_string(),
                },
            }
        }
    };
    write_frame(stream, &resp).map_err(|e| e.to_string())
}

pub fn write_frame(stream: &mut UnixStream, value: &impl Serialize) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame too large",
        ));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

pub fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut lenb = [0u8; 4];
    stream.read_exact(&mut lenb)?;
    let len = u32::from_be_bytes(lenb);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn connect(root: &Path) -> io::Result<UnixStream> {
    let path = sock_path(root);
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(UDS_TIMEOUT))?;
    stream.set_write_timeout(Some(UDS_TIMEOUT))?;
    Ok(stream)
}

fn connect_down(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrNotAvailable
    )
}

/// Result of asking a running agent to send. Connect-refused is [`TrySend::Down`].
#[derive(Debug)]
pub enum TrySend {
    Down,
    Up(MsgResponse),
}

pub fn try_send_msg(root: &Path, req: &MsgRequest) -> TrySend {
    let mut stream = match connect(root) {
        Ok(s) => s,
        Err(err) if connect_down(&err) => return TrySend::Down,
        Err(err) => return TrySend::Up(MsgResponse::from_error(err.to_string())),
    };
    let payload = serde_json::json!({
        "op": "send",
        "to": req.to,
        "body": req.body,
        "no_wake": req.no_wake,
        "cwd": req.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "session_ids": req.session_ids,
    });
    if let Err(err) = write_frame(&mut stream, &payload) {
        return TrySend::Up(MsgResponse::from_error(err.to_string()));
    }
    match read_frame(&mut stream) {
        Ok(bytes) => match serde_json::from_slice::<MsgResponse>(&bytes) {
            Ok(resp) => TrySend::Up(resp),
            Err(_) => TrySend::Up(MsgResponse::from_error("agent send failed")),
        },
        Err(err) => TrySend::Up(MsgResponse::from_error(err.to_string())),
    }
}

/// Register a live session on a running agent. Connect-refused is `false`.
pub fn try_register(root: &Path, addr: &str, session_id: &str) -> bool {
    let mut stream = match connect(root) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let payload = serde_json::json!({
        "op": "register",
        "addr": addr,
        "session_id": session_id,
    });
    if write_frame(&mut stream, &payload).is_err() {
        return false;
    }
    match read_frame(&mut stream) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("ok").and_then(|o| o.as_bool()))
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub fn request(root: &Path, req: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut stream = connect(root)?;
    write_frame(&mut stream, req)?;
    read_frame(&mut stream)
}

pub fn try_status(root: &Path) -> Option<StatusReport> {
    let bytes = request(root, &serde_json::json!({"op":"status"})).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if v.get("agent").and_then(|a| a.as_str()) == Some("up") {
        Some(StatusReport {
            agent: "up".into(),
            tunnel: v
                .get("tunnel")
                .and_then(|t| t.as_str())
                .unwrap_or("down")
                .to_string(),
            http: v.get("http").and_then(|h| h.as_str()).map(str::to_string),
        })
    } else {
        None
    }
}

pub fn try_stop(root: &Path) -> bool {
    request(root, &serde_json::json!({"op":"stop"}))
        .ok()
        .is_some()
}

/// Hint printed when the resident agent is down and `p5 msg` stays local.
pub fn agent_down_hint() -> &'static str {
    "agent is not running; start with `p5 login` or `p5 agent run`"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn sample_req() -> MsgRequest {
        MsgRequest {
            to: "scout::acme.postal.bot".into(),
            body: "hi".into(),
            no_wake: false,
            cwd: None,
            session_ids: Vec::new(),
        }
    }

    #[test]
    fn uds_timeout_outlives_live_http() {
        assert!(UDS_TIMEOUT >= p5_live::DEFAULT_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn send_is_down_when_socket_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            try_send_msg(tmp.path(), &sample_req()),
            TrySend::Down
        ));
    }

    #[test]
    fn send_does_not_fallback_after_connect() {
        let tmp = tempfile::tempdir().unwrap();
        let path = sock_path(tmp.path());
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.set_read_timeout(Some(UDS_TIMEOUT));
            let _ = s.set_write_timeout(Some(UDS_TIMEOUT));
            let _ = read_frame(&mut s);
            let _ = write_frame(&mut s, &serde_json::json!({"ok": false, "error": "boom"}));
        });
        match try_send_msg(tmp.path(), &sample_req()) {
            TrySend::Up(resp) => {
                assert!(!resp.success);
                assert_eq!(resp.reason.as_deref(), Some("error"));
            }
            TrySend::Down => panic!("live UDS must not fall back to local send"),
        }
        handle.join().unwrap();
    }
}
