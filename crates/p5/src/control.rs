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
        from: Option<String>,
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
            tunnel: "down".into(),
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
            from,
        } => {
            let ctx = state.context().map_err(|e| e.to_string())?;
            match send_msg(
                &ctx,
                &MsgRequest {
                    to,
                    body,
                    no_wake,
                    from,
                },
            ) {
                Ok(resp) => ControlResp::Send(resp),
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
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
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

pub fn try_send_msg(root: &Path, req: &MsgRequest) -> Option<MsgResponse> {
    let payload = serde_json::json!({
        "op": "send",
        "to": req.to,
        "body": req.body,
        "no_wake": req.no_wake,
        "from": req.from,
    });
    let bytes = request(root, &payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Hint printed when the resident agent is down and `p5 msg` stays local.
pub fn agent_down_hint() -> &'static str {
    "agent is not running; start with `p5 login` or `p5 agent run`"
}
