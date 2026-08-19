//! Resident agent process: loopback HTTP + UDS control + pid file.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use p5_core::default_root;

use crate::control::{self, pid_path, sock_path, StatusReport};
use crate::http::{bind_from_env, bind_http, load_ssl, serve_http, AgentState, BindError};
use crate::service::{self, ServiceError};

const STOP_GRACE: Duration = Duration::from_secs(2);
const STOP_KILL_WAIT: Duration = Duration::from_millis(500);

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

/// Login already wrote the Connect token. Don't make the user export P5_TUNNEL.
fn arm_tunnel_env(root: &Path) {
    if std::env::var_os("P5_CONNECT_TOKEN").is_none() {
        if let Ok(cfg) = p5_plane::PlaneConfig::load(root) {
            if let Some(t) = cfg.token.filter(|s| !s.is_empty()) {
                std::env::set_var("P5_CONNECT_TOKEN", t);
            }
        }
    }
    if std::env::var_os("P5_TUNNEL").is_none() && std::env::var_os("P5_CONNECT_TOKEN").is_some() {
        std::env::set_var("P5_TUNNEL", "1");
    }
}

pub fn run() -> Result<(), AgentError> {
    run_at(&default_root())
}

pub fn run_at(root: &Path) -> Result<(), AgentError> {
    p5_core::ensure_dir(root)?;
    if let Some(pid) = read_pid(root) {
        if is_our_agent(pid) {
            return Err(AgentError::AlreadyRunning(format!(
                "agent already running (pid {pid})"
            )));
        }
    }
    let bind = bind_from_env()?;
    arm_tunnel_env(root);
    // Issue the leaf before bind so loopback can speak TLS for passthrough.
    let mut tunnel = p5_tunnel::start_from_env(root, bind.port());
    let ssl = load_ssl(root).map_err(AgentError::Tls)?;
    let (server, local) = match bind_http(bind, ssl) {
        Ok(v) => v,
        Err(err) => {
            tunnel.stop();
            return Err(AgentError::Http(err));
        }
    };
    let state = Arc::new(AgentState::new(root, local, env_secret()));
    let listener = match control::bind_uds(&sock_path(root)) {
        Ok(l) => l,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            return Err(AgentError::AlreadyRunning(err.to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    if let Err(err) = write_pid_exclusive(root) {
        let _ = fs::remove_file(sock_path(root));
        if err.kind() == io::ErrorKind::AlreadyExists {
            return Err(AgentError::AlreadyRunning(err.to_string()));
        }
        return Err(err.into());
    }

    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&state.stop));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&state.stop));
    // frpc is in its own process group, so a tty hangup would otherwise
    // skip Drop and leave the tunnel child. Same flag as TERM/INT.
    #[cfg(unix)]
    {
        let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&state.stop));
    }

    let http_server = Arc::new(server);
    let http_state = Arc::clone(&state);
    let http_handle = {
        let server = Arc::clone(&http_server);
        thread::spawn(move || serve_http(server, http_state))
    };
    let uds_state = Arc::clone(&state);
    let uds_handle = thread::spawn(move || control::serve_uds(listener, uds_state));
    let hold_handle = if crate::hold::hold_enabled() {
        let root = root.to_path_buf();
        let stop = Arc::clone(&state.stop);
        Some(thread::spawn(move || crate::hold::poll_loop(root, stop)))
    } else {
        None
    };

    state.tunnel_up.store(tunnel.is_up(), Ordering::Relaxed);
    if tunnel.is_up() {
        eprintln!("postal tunnel up");
    } else if p5_tunnel::enabled() {
        eprintln!(
            "postal tunnel down: {}",
            tunnel.reason().unwrap_or("unknown")
        );
    }

    eprintln!(
        "postal agent listening http={local} uds={}",
        sock_path(root).display()
    );

    while !state.stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
        state.tunnel_up.store(tunnel.is_up(), Ordering::Relaxed);
    }
    tunnel.stop();
    state.tunnel_up.store(false, Ordering::Relaxed);
    http_server.unblock();
    let _ = http_handle.join();
    let _ = uds_handle.join();
    if let Some(h) = hold_handle {
        let _ = h.join();
    }
    cleanup_ours(root);
    Ok(())
}

fn write_pid_exclusive(root: &Path) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let path = pid_path(root);
    if path.exists() {
        if let Some(pid) = read_pid(root) {
            if is_our_agent(pid) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("agent already running (pid {pid})"),
                ));
            }
        }
        let _ = fs::remove_file(&path);
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(f, "{}", std::process::id())?;
    Ok(())
}

/// Unlink sock/pid only if they still name this process.
fn cleanup_ours(root: &Path) {
    let me = std::process::id() as i32;
    match read_pid(root) {
        Some(pid) if pid != me => return,
        _ => {}
    }
    let _ = fs::remove_file(pid_path(root));
    let _ = fs::remove_file(sock_path(root));
}

pub fn stop() -> Result<(), AgentError> {
    stop_at(&default_root())
}

pub fn stop_at(root: &Path) -> Result<(), AgentError> {
    let target = read_pid(root).filter(|pid| is_our_agent(*pid));
    let _ = control::try_stop(root);
    if let Some(pid) = target {
        reap_pid(pid);
    }
    reap_stale_files(root);
    Ok(())
}

fn reap_pid(pid: i32) {
    wait_pid(pid, STOP_GRACE);
    if pid_alive(pid) && is_our_agent(pid) {
        signal_pid(pid, libc::SIGTERM);
        wait_pid(pid, STOP_GRACE);
    }
    if pid_alive(pid) && is_our_agent(pid) {
        signal_pid(pid, libc::SIGKILL);
        wait_pid(pid, STOP_KILL_WAIT);
    }
}

fn reap_stale_files(root: &Path) {
    if let Some(pid) = read_pid(root) {
        if pid_alive(pid) {
            // Live process owns the files — ours or not. Do not unlink.
            return;
        }
    }
    let _ = fs::remove_file(sock_path(root));
    let _ = fs::remove_file(pid_path(root));
}

fn wait_pid(pid: i32, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !pid_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_pid(root: &Path) -> Option<i32> {
    let text = fs::read_to_string(pid_path(root)).ok()?;
    text.trim().parse().ok()
}

fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn signal_pid(pid: i32, sig: i32) {
    if pid <= 1 {
        return;
    }
    unsafe {
        libc::kill(pid, sig);
    }
}

/// True when `pid` is a live `p5 agent run` (this binary). Never SIGTERM a stranger.
pub fn is_our_agent(pid: i32) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    let Some(exe) = process_exe(pid) else {
        return false;
    };
    if !exe_looks_like_p5(&exe) {
        return false;
    }
    let Some(args) = process_args(pid) else {
        return false;
    };
    args_have_agent_run(&args)
}

fn exe_looks_like_p5(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name == "p5" || name.starts_with("p5-") {
        return true;
    }
    if let Ok(me) = std::env::current_exe() {
        if me == *path {
            return true;
        }
        if let (Ok(a), Ok(b)) = (me.canonicalize(), path.canonicalize()) {
            return a == b;
        }
    }
    false
}

fn args_have_agent_run(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some("agent")
        && args.get(2).map(String::as_str) == Some("run")
}

#[cfg(target_os = "macos")]
fn process_exe(pid: i32) -> Option<PathBuf> {
    let mut buf = [0u8; 4096];
    let n =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..n as usize]).ok()?;
    Some(PathBuf::from(s))
}

#[cfg(target_os = "linux")]
fn process_exe(pid: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_exe(_pid: i32) -> Option<PathBuf> {
    None
}

#[cfg(target_os = "linux")]
fn process_args(pid: i32) -> Option<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

#[cfg(target_os = "macos")]
fn process_args(pid: i32) -> Option<Vec<String>> {
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0usize;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return None;
    }
    buf.truncate(size);
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?);
    if argc <= 0 {
        return None;
    }
    // Skip the executable path, then take argc NUL-separated arguments.
    let mut parts = buf[4..].split(|b| *b == 0).filter(|s| !s.is_empty());
    let _exe = parts.next()?;
    let args: Vec<String> = parts
        .take(argc as usize)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_args(_pid: i32) -> Option<Vec<String>> {
    None
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
    // Unload KeepAlive first so a clean stop cannot be restarted.
    service::unload()?;
    let _ = stop_at(&default_root());
    service::remove_unit()?;
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

    #[test]
    fn is_our_agent_rejects_self_without_agent_run() {
        assert!(!is_our_agent(std::process::id() as i32));
        assert!(!is_our_agent(1));
        assert!(!is_our_agent(-1));
    }

    #[test]
    fn cleanup_skips_foreign_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(pid_path(tmp.path()), "1\n").unwrap();
        fs::write(sock_path(tmp.path()), b"").unwrap();
        cleanup_ours(tmp.path());
        assert!(pid_path(tmp.path()).exists());
        assert!(sock_path(tmp.path()).exists());
    }

    #[test]
    fn cleanup_unlinks_our_pid() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(pid_path(tmp.path()), format!("{}\n", std::process::id())).unwrap();
        fs::write(sock_path(tmp.path()), b"").unwrap();
        cleanup_ours(tmp.path());
        assert!(!pid_path(tmp.path()).exists());
        assert!(!sock_path(tmp.path()).exists());
    }

    #[test]
    fn args_detect_agent_run() {
        assert!(args_have_agent_run(&[
            "/usr/local/bin/p5".into(),
            "agent".into(),
            "run".into()
        ]));
        assert!(!args_have_agent_run(&["p5".into(), "status".into()]));
        assert!(
            !args_have_agent_run(&["p5".into(), "msg".into(), "agent".into(), "run".into()]),
            "body/handle tokens must not look like the agent subcommand"
        );
        assert!(!args_have_agent_run(&[
            "p5".into(),
            "inbox".into(),
            "agent".into(),
            "list".into(),
            "run".into()
        ]));
    }
}
