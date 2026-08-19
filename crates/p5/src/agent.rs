//! Resident agent process: loopback HTTP + UDS control + pid file.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use p5_core::default_root;

use crate::control::{self, pid_path, sock_path, StatusReport};
use crate::http::{bind_from_env, bind_http, load_ssl_from_env, serve_http, AgentState, BindError};
use crate::service::{self, ServiceError};

#[derive(Debug)]
pub enum AgentError {
    Bind(BindError),
    Io(io::Error),
    Http(String),
    Tls(String),
    Service(ServiceError),
    AlreadyRunning(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Http(msg) | Self::Tls(msg) | Self::AlreadyRunning(msg) => write!(f, "{msg}"),
            Self::Service(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<BindError> for AgentError {
    fn from(err: BindError) -> Self {
        Self::Bind(err)
    }
}

impl From<io::Error> for AgentError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<ServiceError> for AgentError {
    fn from(err: ServiceError) -> Self {
        Self::Service(err)
    }
}

pub fn env_secret() -> Option<String> {
    std::env::var("P5_DEV_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn run() -> Result<(), AgentError> {
    run_at(&default_root())
}

pub fn run_at(root: &Path) -> Result<(), AgentError> {
    p5_core::ensure_dir(root)?;
    let bind = bind_from_env()?;
    let ssl = load_ssl_from_env().map_err(AgentError::Tls)?;
    let (server, local) = bind_http(bind, ssl).map_err(AgentError::Http)?;
    let state = Arc::new(AgentState::new(root, local, env_secret()));
    let listener = match control::bind_uds(&sock_path(root)) {
        Ok(l) => l,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            return Err(AgentError::AlreadyRunning(err.to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    write_pid(root)?;

    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&state.stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&state.stop));

    let http_server = Arc::new(server);
    let http_state = Arc::clone(&state);
    let http_handle = {
        let server = Arc::clone(&http_server);
        thread::spawn(move || serve_http(server, http_state))
    };
    let uds_state = Arc::clone(&state);
    let uds_handle = thread::spawn(move || control::serve_uds(listener, uds_state));

    eprintln!(
        "postal agent listening http={local} uds={}",
        sock_path(root).display()
    );

    while !state.stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    http_server.unblock();
    // Wake a blocking UDS accept.
    let _ = std::os::unix::net::UnixStream::connect(sock_path(root));
    let _ = http_handle.join();
    let _ = uds_handle.join();
    cleanup(root);
    Ok(())
}

fn write_pid(root: &Path) -> io::Result<()> {
    let path = pid_path(root);
    fs::write(&path, format!("{}\n", std::process::id()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn cleanup(root: &Path) {
    let _ = fs::remove_file(sock_path(root));
    let _ = fs::remove_file(pid_path(root));
}

pub fn stop() -> Result<(), AgentError> {
    stop_at(&default_root())
}

pub fn stop_at(root: &Path) -> Result<(), AgentError> {
    if control::try_stop(root) {
        wait_gone(root);
        cleanup(root);
        return Ok(());
    }
    if let Some(pid) = read_pid(root) {
        kill_pid(pid);
        wait_gone(root);
    }
    cleanup(root);
    Ok(())
}

fn wait_gone(root: &Path) {
    for _ in 0..50 {
        if !sock_path(root).exists() {
            return;
        }
        if control::try_status(root).is_none() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_pid(root: &Path) -> Option<i32> {
    let text = fs::read_to_string(pid_path(root)).ok()?;
    text.trim().parse().ok()
}

fn kill_pid(pid: i32) {
    if pid <= 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

pub fn status_text() -> String {
    status_text_at(&default_root())
}

pub fn status_text_at(root: &Path) -> String {
    match control::try_status(root) {
        Some(StatusReport {
            agent,
            tunnel,
            http,
        }) => {
            let mut out = format!("agent: {agent}\ntunnel: {tunnel}\n");
            if let Some(http) = http {
                out.push_str(&format!("http: {http}\n"));
            }
            out
        }
        None => "agent: down\ntunnel: down\n".into(),
    }
}

pub fn login(no_start: bool) -> Result<PathBuf, AgentError> {
    Ok(service::login(no_start)?)
}

pub fn logout() -> Result<(), AgentError> {
    let _ = stop();
    service::logout()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_when_agent_not_running_is_down() {
        let tmp = tempfile::tempdir().unwrap();
        let text = status_text_at(tmp.path());
        assert!(text.contains("agent: down"));
        assert!(text.contains("tunnel: down"));
        assert!(!text.contains("agent: up"));
    }
}
