//! Postal tunnel client (`postal.bot`).
//!
//! CSR SAN is `{label}.postal.bot` only — never a nested wildcard and never
//! a k2.dev name. frpc is a child of `p5 agent run`, not a second supervisor.

mod broker;
mod child;
mod csr;
mod render;
mod san;

pub use broker::{
    broker_url, request_cert, request_cert_at, BrokerError, BROKER_URL_ENV, DEFAULT_BROKER_URL,
};
pub use child::{resolve_frpc, spawn_frpc, FrpcBinary, TunnelChild};
pub use csr::{
    build_csr_pem, generate_key, load_or_generate_key, CsrError, TUNNEL_CERT_FILE, TUNNEL_DIR,
    TUNNEL_KEY_FILE,
};
pub use render::{
    render_frpc_toml, write_frpc_toml, FrpcSpec, DEFAULT_FRP_PORT, DEFAULT_FRP_SERVER,
    FRPC_TOML_FILE,
};
pub use san::{
    check_sans, hostname_for_label, label_from_host, sans_for_label, SanError, HOST_SUFFIX,
};

use std::path::{Path, PathBuf};

use p5_core::Homes;

/// Loopback port frpc forwards to when the agent does not pass a bind port.
pub const DEFAULT_LOCAL_PORT: u16 = 8443;
/// Env flag that arms the tunnel child from `p5 agent run`.
pub const TUNNEL_ENV: &str = "P5_TUNNEL";
/// Optional label override (`acme` → `acme.postal.bot`).
pub const LABEL_ENV: &str = "P5_TUNNEL_LABEL";
/// Connect token posted to the cert broker (same shape as k2-connect `/cert`).
pub const TOKEN_ENV: &str = "P5_CONNECT_TOKEN";
/// Explicit `frpc` path (tests inject a stub).
pub const FRPC_ENV: &str = "P5_FRPC";
/// frps host override. Default is the shared k2e-01 relay.
pub const FRP_SERVER_ENV: &str = "P5_FRP_SERVER";
/// frps bindPort override.
pub const FRP_PORT_ENV: &str = "P5_FRP_PORT";

/// Outcome of an optional tunnel start. Never fails the agent.
#[derive(Debug)]
pub struct TunnelHandle {
    child: Option<TunnelChild>,
    reason: Option<String>,
}

impl TunnelHandle {
    pub fn down(reason: impl Into<String>) -> Self {
        Self {
            child: None,
            reason: Some(reason.into()),
        }
    }

    pub fn is_up(&mut self) -> bool {
        self.child.as_mut().is_some_and(TunnelChild::is_alive)
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.stop();
        }
        if self.reason.is_none() {
            self.reason = Some("stopped".into());
        }
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// True when `P5_TUNNEL` is an explicit truthy value.
pub fn enabled() -> bool {
    env_truthy(TUNNEL_ENV)
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// First homes row's enrolled host, mapped to a Postal tunnel label.
pub fn label_from_homes(root: &Path) -> Option<String> {
    let homes = Homes::load(root).ok()?;
    let (_, row) = homes.iter().next()?;
    label_from_host(&row.enrolled_host).ok()
}

/// Inputs for [`try_start`]. Broker / frpc failures become [`TunnelHandle::down`].
pub struct StartOpts<'a> {
    pub root: &'a Path,
    pub label: &'a str,
    pub local_port: u16,
    pub broker_url: Option<&'a str>,
    pub token: Option<&'a str>,
    pub frpc: Option<&'a Path>,
    pub server_addr: Option<&'a str>,
    pub server_port: Option<u16>,
}

/// Provision a cert, render `frpc.toml`, spawn the child. On any failure the
/// agent must still serve loopback — this returns [`TunnelHandle::down`].
pub fn try_start(opts: StartOpts<'_>) -> TunnelHandle {
    let hostname = match hostname_for_label(opts.label) {
        Ok(h) => h,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };
    let label = match label_from_host(&hostname) {
        Ok(l) => l,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };

    let key = match load_or_generate_key(opts.root) {
        Ok(k) => k,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };
    let csr = match build_csr_pem(&label, &key) {
        Ok(c) => c,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };

    let url = opts
        .broker_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(broker_url);
    let token = opts.token.unwrap_or("");
    let cert = match request_cert_at(&url, &csr, &label, token) {
        Ok(c) => c,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };
    if let Err(err) = csr::install_cert(opts.root, &cert) {
        return TunnelHandle::down(err.to_string());
    }

    let port = if opts.local_port == 0 {
        DEFAULT_LOCAL_PORT
    } else {
        opts.local_port
    };
    let spec = FrpcSpec {
        label: label.clone(),
        local_port: port,
        server_addr: opts.server_addr.unwrap_or(DEFAULT_FRP_SERVER).to_string(),
        server_port: opts.server_port.unwrap_or(DEFAULT_FRP_PORT),
        token: opts
            .token
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    };
    let toml_path = match write_frpc_toml(opts.root, &spec) {
        Ok(p) => p,
        Err(err) => return TunnelHandle::down(err.to_string()),
    };

    let bin = match opts.frpc {
        Some(p) => FrpcBinary::Explicit(p.to_path_buf()),
        None => FrpcBinary::Auto,
    };
    match spawn_frpc(&bin, &toml_path) {
        Ok(child) => TunnelHandle {
            child: Some(child),
            reason: None,
        },
        Err(err) => TunnelHandle::down(err),
    }
}

/// Agent entry: no-op unless `P5_TUNNEL=1`. Broker miss → down, not an error.
pub fn start_from_env(root: &Path, local_port: u16) -> TunnelHandle {
    if !enabled() {
        return TunnelHandle::down("disabled");
    }
    let label = match env_nonempty(LABEL_ENV) {
        Some(raw) => match hostname_for_label(&raw) {
            Ok(host) => match label_from_host(&host) {
                Ok(l) => l,
                Err(err) => return TunnelHandle::down(err.to_string()),
            },
            Err(err) => return TunnelHandle::down(err.to_string()),
        },
        None => match label_from_homes(root) {
            Some(l) => l,
            None => return TunnelHandle::down("no tunnel label (set P5_TUNNEL_LABEL)"),
        },
    };
    let broker = env_nonempty(BROKER_URL_ENV);
    let token = env_nonempty(TOKEN_ENV);
    let frpc = env_nonempty(FRPC_ENV).map(PathBuf::from);
    let server = env_nonempty(FRP_SERVER_ENV);
    let port = env_nonempty(FRP_PORT_ENV).and_then(|s| s.parse().ok());
    try_start(StartOpts {
        root,
        label: &label,
        local_port,
        broker_url: broker.as_deref(),
        token: token.as_deref(),
        frpc: frpc.as_deref(),
        server_addr: server.as_deref(),
        server_port: port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn stub_frpc(dir: &Path) -> PathBuf {
        let path = dir.join("frpc-stub");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$2.args\"\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn read_http_request(sock: &mut std::net::TcpStream) -> String {
        use std::io::{BufRead, Read};
        let mut reader = std::io::BufReader::new(sock);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            headers.push_str(&line);
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        let len = headers
            .lines()
            .find_map(|l| {
                l.split_once(':').and_then(|(k, v)| {
                    k.eq_ignore_ascii_case("content-length")
                        .then_some(v.trim().parse::<usize>().unwrap_or(0))
                })
            })
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if len > 0 {
            let _ = reader.read_exact(&mut body);
        }
        headers.push_str(&String::from_utf8_lossy(&body));
        headers
    }

    fn spawn_mock_broker(status_line: &str, body: &str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let status_line = status_line.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = read_http_request(&mut sock);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/cert")
    }

    #[test]
    fn start_from_env_disabled_is_down() {
        let _g = env_lock();
        let prev = std::env::var_os(TUNNEL_ENV);
        std::env::remove_var(TUNNEL_ENV);
        let tmp = tempfile::tempdir().unwrap();
        let mut h = start_from_env(tmp.path(), 8443);
        assert!(!h.is_up());
        assert_eq!(h.reason(), Some("disabled"));
        match prev {
            Some(p) => std::env::set_var(TUNNEL_ENV, p),
            None => std::env::remove_var(TUNNEL_ENV),
        }
    }

    #[test]
    fn try_start_broker_unreachable_is_down() {
        let tmp = tempfile::tempdir().unwrap();
        let dead = {
            let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            format!("http://127.0.0.1:{p}/cert")
        };
        let mut h = try_start(StartOpts {
            root: tmp.path(),
            label: "acme",
            local_port: 8443,
            broker_url: Some(&dead),
            token: Some("tok"),
            frpc: None,
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
        });
        assert!(!h.is_up());
        let reason = h.reason().unwrap_or("");
        assert!(
            reason.contains("unreachable") || reason.contains("cert broker"),
            "{reason}"
        );
        assert!(!tmp.path().join(TUNNEL_DIR).join(TUNNEL_CERT_FILE).exists());
    }

    #[test]
    fn try_start_mock_broker_and_stub_frpc_is_up() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        let body = serde_json::json!({ "cert": "-----BEGIN CERTIFICATE-----\nUEs=\n-----END CERTIFICATE-----\n" })
            .to_string();
        let url = spawn_mock_broker("200 OK", &body);
        let mut h = try_start(StartOpts {
            root: tmp.path(),
            label: "acme",
            local_port: 18765,
            broker_url: Some(&url),
            token: Some("tok"),
            frpc: Some(&stub),
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
        });
        assert!(h.is_up(), "{:?}", h.reason());
        assert!(tmp.path().join(TUNNEL_DIR).join(TUNNEL_CERT_FILE).exists());
        let toml =
            std::fs::read_to_string(tmp.path().join(TUNNEL_DIR).join(FRPC_TOML_FILE)).unwrap();
        assert!(toml.contains("localPort = 18765"), "{toml}");
        assert!(toml.contains("type = \"https\""), "{toml}");
    }
}
