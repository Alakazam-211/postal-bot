//! Postal tunnel client (`postal.bot`).
//!
//! CSR SAN is `{label}.postal.bot` only — never a nested wildcard and never
//! a k2.dev name. frpc is a child of `p5 agent run`, not a second supervisor.

mod broker;
mod child;
mod csr;
mod relays;
mod render;
mod san;

pub use broker::{
    broker_url, request_cert, request_cert_at, BrokerError, BROKER_URL_ENV, DEFAULT_BROKER_URL,
};
pub use child::{resolve_frpc, spawn_frpc, FrpcBinary, TunnelChild};
pub use csr::{
    build_csr_pem, cert_status_line, check_leaf, RENEW_ERROR_FILE, generate_key, load_or_generate_key, CsrError, TUNNEL_CERT_FILE, TUNNEL_DIR,
    TUNNEL_KEY_FILE,
};
pub use render::{
    render_frpc_toml, write_frpc_toml, FrpcSpec, DEFAULT_FRP_PORT, DEFAULT_FRP_SERVER,
    FRPC_TOML_FILE,
};
pub use relays::{choose as choose_relay, Choice as RelayChoice, Relay, RelayList, DEFAULT_RELAYS_BASE, RELAYS_BASE_ENV, RELAYS_FILE};
pub use san::{
    check_sans, hostname_for_label, label_from_host, sans_for_label, SanError, HOST_SUFFIX,
};

use std::path::{Path, PathBuf};

use p5_core::Homes;

/// Loopback port frpc forwards to when the agent does not pass a bind port.
pub const DEFAULT_LOCAL_PORT: u16 = 8443;
/// Env flag that arms the tunnel child from `p5 agent run`.
pub const TUNNEL_ENV: &str = "P5_TUNNEL";
/// Force a new CSR even when `tunnel/cert.pem` already exists.
pub const REISSUE_ENV: &str = "P5_TUNNEL_REISSUE";
/// Optional label override (`acme` → `acme.postal.bot`).
pub const LABEL_ENV: &str = "P5_TUNNEL_LABEL";
/// Connect token posted to the cert broker (same shape as k2-connect `/cert`).
pub const TOKEN_ENV: &str = "P5_CONNECT_TOKEN";
/// Explicit `frpc` path (tests inject a stub).
pub const FRPC_ENV: &str = "P5_FRPC";
/// frps host override. Without it p5 follows the plane's relay list
/// (see `relays`), falling back to `frp.postal.bot`.
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
    /// The running p5's version, sent to frps as `metadatas.p5_version`.
    pub p5_version: Option<&'a str>,
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
    // Reuse the leaf while it has 30+ days left; otherwise ask the broker
    // for a new one (same key). A failed renewal keeps the old leaf.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let has_leaf = csr::cert_path(opts.root).is_file() && csr::key_path(opts.root).is_file();
    let reuse = has_leaf && !env_truthy(REISSUE_ENV) && !csr::cert_needs_renewal(opts.root, now);
    if !reuse {
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
        let issued = request_cert_at(&url, &csr, &label, token)
            .map_err(|e| e.to_string())
            .and_then(|cert| csr::check_leaf(&cert, &key, &hostname, now).map(|()| cert));
        match issued {
            Ok(cert) => {
                if let Err(err) = csr::install_cert(opts.root, &cert) {
                    return TunnelHandle::down(err.to_string());
                }
                csr::clear_renew_error(opts.root);
            }
            // Renewing: keep serving the old leaf, say so in `p5 status`,
            // and try again next start.
            Err(err) if has_leaf => {
                eprintln!("postal: tunnel cert renewal failed, keeping the current one: {err}");
                csr::record_renew_error(opts.root, &err);
            }
            Err(err) => {
                csr::record_renew_error(opts.root, &err);
                return TunnelHandle::down(err);
            }
        }
    }

    let port = if opts.local_port == 0 {
        DEFAULT_LOCAL_PORT
    } else {
        opts.local_port
    };
    let (server_addr, list_port) = match opts.server_addr.map(str::trim).filter(|s| !s.is_empty()) {
        Some(addr) => (addr.to_string(), DEFAULT_FRP_PORT),
        None => {
            let c = relays::choose(opts.root, opts.token);
            (c.host, c.port)
        }
    };
    let spec = FrpcSpec {
        label: label.clone(),
        local_port: port,
        server_addr,
        server_port: opts.server_port.unwrap_or(list_port),
        token: opts
            .token
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        p5_version: opts.p5_version.map(str::to_string),
        log_file: Some(opts.root.join(csr::TUNNEL_DIR).join(render::FRPC_LOG_FILE)),
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
pub fn start_from_env(root: &Path, local_port: u16, p5_version: &str) -> TunnelHandle {
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
        p5_version: Some(p5_version),
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

    /// A leaf for `host` with the tunnel key under `root` (created if
    /// missing), expiring on 1 Jan `year`.
    fn leaf_for(root: &Path, host: &str, year: i32) -> String {
        let kp = crate::csr::load_or_generate_key(root).unwrap();
        let mut p = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(year, 1, 1);
        p.self_signed(&kp).unwrap().pem()
    }

    fn leaf_pem_at(root: &Path, year: i32) -> String {
        leaf_for(root, "acme.postal.bot", year)
    }

    #[test]
    fn cert_expiry_drives_renewal() {
        let tmp = tempfile::tempdir().unwrap();
        crate::csr::load_or_generate_key(tmp.path()).unwrap();
        let now = 1_795_000_000; // Nov 2026
        assert!(crate::csr::cert_needs_renewal(tmp.path(), now), "missing");
        std::fs::write(crate::csr::cert_path(tmp.path()), leaf_pem_at(tmp.path(), 2099)).unwrap();
        assert!(!crate::csr::cert_needs_renewal(tmp.path(), now));
        std::fs::write(crate::csr::cert_path(tmp.path()), leaf_pem_at(tmp.path(), 2026)).unwrap();
        assert!(crate::csr::cert_needs_renewal(tmp.path(), now), "expired");
        // 20 days before expiry is inside the 30-day window; 40 is not.
        let expiry = now + crate::csr::cert_secs_left(tmp.path(), now).unwrap();
        assert!(crate::csr::cert_needs_renewal(tmp.path(), expiry - 20 * 86_400));
        assert!(!crate::csr::cert_needs_renewal(tmp.path(), expiry - 40 * 86_400));
        std::fs::write(crate::csr::cert_path(tmp.path()), "junk").unwrap();
        assert!(crate::csr::cert_needs_renewal(tmp.path(), now), "unreadable");
    }

    #[test]
    fn expired_leaf_is_renewed_from_the_broker() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        crate::csr::load_or_generate_key(tmp.path()).unwrap();
        std::fs::write(crate::csr::cert_path(tmp.path()), leaf_pem_at(tmp.path(), 2026)).unwrap();
        let fresh = leaf_pem_at(tmp.path(), 2099);
        let body = serde_json::json!({ "cert": fresh }).to_string();
        let url = spawn_mock_broker("200 OK", &body);
        let mut h = try_start(StartOpts {
            root: tmp.path(),
            label: "acme",
            local_port: 8443,
            broker_url: Some(&url),
            token: Some("tok"),
            frpc: Some(&stub),
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
        });
        assert!(h.is_up(), "{:?}", h.reason());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(!crate::csr::cert_needs_renewal(tmp.path(), now), "new leaf installed");
        h.stop();
    }

    #[test]
    fn failed_renewal_keeps_the_old_leaf_up() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        crate::csr::load_or_generate_key(tmp.path()).unwrap();
        let old = leaf_pem_at(tmp.path(), 2026);
        std::fs::write(crate::csr::cert_path(tmp.path()), &old).unwrap();
        let url = spawn_mock_broker("503 Service Unavailable", r#"{"error":"down"}"#);
        let mut h = try_start(StartOpts {
            root: tmp.path(),
            label: "acme",
            local_port: 8443,
            broker_url: Some(&url),
            token: Some("tok"),
            frpc: Some(&stub),
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
        });
        assert!(h.is_up(), "{:?}", h.reason());
        assert_eq!(std::fs::read_to_string(crate::csr::cert_path(tmp.path())).unwrap(), old);
        h.stop();
    }

    #[test]
    fn start_from_env_disabled_is_down() {
        let _g = env_lock();
        let prev = std::env::var_os(TUNNEL_ENV);
        std::env::remove_var(TUNNEL_ENV);
        let tmp = tempfile::tempdir().unwrap();
        let mut h = start_from_env(tmp.path(), 8443, "0.0.0-test");
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
            p5_version: Some("0.0.0-test"),
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
    fn try_start_reuses_existing_leaf_without_broker() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        crate::csr::load_or_generate_key(tmp.path()).unwrap();
        std::fs::write(crate::csr::cert_path(tmp.path()), leaf_pem_at(tmp.path(), 2099)).unwrap();
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
            frpc: Some(&stub),
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
            p5_version: Some("0.0.0-test"),
        });
        assert!(
            h.is_up(),
            "reuse leaf should not dial broker: {:?}",
            h.reason()
        );
    }

    #[test]
    fn try_start_mock_broker_and_stub_frpc_is_up() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        let body = serde_json::json!({ "cert": leaf_pem_at(tmp.path(), 2099) }).to_string();
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
            p5_version: Some("0.0.0-test"),
        });
        assert!(h.is_up(), "{:?}", h.reason());
        assert!(tmp.path().join(TUNNEL_DIR).join(TUNNEL_CERT_FILE).exists());
        let toml =
            std::fs::read_to_string(tmp.path().join(TUNNEL_DIR).join(FRPC_TOML_FILE)).unwrap();
        assert!(toml.contains("localPort = 18765"), "{toml}");
        assert!(toml.contains("type = \"https\""), "{toml}");
    }

    fn start_with_broker(root: &Path, stub: &Path, url: &str) -> TunnelHandle {
        try_start(StartOpts {
            root,
            label: "acme",
            local_port: 8443,
            broker_url: Some(url),
            token: Some("tok"),
            frpc: Some(stub),
            server_addr: Some("127.0.0.1"),
            server_port: Some(7000),
        })
    }

    #[test]
    fn a_broker_answer_that_fails_the_leaf_check_is_not_installed() {
        let now = 1_795_000_000;
        // Wrong key, wrong host, expired: each keeps the old leaf.
        let other = tempfile::tempdir().unwrap();
        let bad = |tmp: &tempfile::TempDir| -> Vec<(&'static str, String)> {
            vec![
                ("not for our key", leaf_for(other.path(), "acme.postal.bot", 2099)),
                ("does not name", leaf_for(tmp.path(), "evil.postal.bot", 2099)),
                ("not currently valid", leaf_for(tmp.path(), "acme.postal.bot", 2026)),
            ]
        };
        for i in 0..3 {
            let tmp = tempfile::tempdir().unwrap();
            let stub = stub_frpc(tmp.path());
            let old = leaf_pem_at(tmp.path(), 2026);
            std::fs::write(crate::csr::cert_path(tmp.path()), &old).unwrap();
            let (want, answer) = bad(&tmp).swap_remove(i);
            let body = serde_json::json!({ "cert": answer }).to_string();
            let url = spawn_mock_broker("200 OK", &body);
            let mut h = start_with_broker(tmp.path(), &stub, &url);
            assert!(h.is_up(), "{:?}", h.reason());
            assert_eq!(std::fs::read_to_string(crate::csr::cert_path(tmp.path())).unwrap(), old);
            let line = crate::csr::cert_status_line(tmp.path(), now).unwrap();
            assert!(line.starts_with("tunnel certificate expired"), "{line}");
            assert!(line.contains("renewal failing") && line.contains(want), "{line}");
            h.stop();
        }
    }

    #[test]
    fn status_line_names_expiry_and_clears_after_renewal() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = stub_frpc(tmp.path());
        std::fs::write(crate::csr::cert_path(tmp.path()), leaf_pem_at(tmp.path(), 2026)).unwrap();
        let now = 1_795_000_000;
        // Expired, no failure recorded yet.
        let line = crate::csr::cert_status_line(tmp.path(), now).unwrap();
        assert!(line.starts_with("tunnel certificate expired"), "{line}");
        // Expiring soon, renewal failing.
        let expiry = now + crate::csr::cert_secs_left(tmp.path(), now).unwrap();
        crate::csr::record_renew_error(tmp.path(), "cert broker unreachable");
        let line = crate::csr::cert_status_line(tmp.path(), expiry - 12 * 86_400 - 60).unwrap();
        assert_eq!(line, "tunnel certificate expires in 12 days, renewal failing: cert broker unreachable");
        // A good renewal clears it.
        let body = serde_json::json!({ "cert": leaf_pem_at(tmp.path(), 2099) }).to_string();
        let url = spawn_mock_broker("200 OK", &body);
        let mut h = start_with_broker(tmp.path(), &stub, &url);
        assert!(h.is_up());
        assert_eq!(crate::csr::cert_status_line(tmp.path(), now), None);
        h.stop();
    }

    #[test]
    fn broker_url_must_be_https_or_loopback() {
        for ok in ["https://cert.postal.bot/cert", "http://127.0.0.1:8080/cert", "http://localhost:1"] {
            assert!(crate::broker::safe_url(ok), "{ok}");
        }
        for bad in ["http://cert.postal.bot/cert", "http://localhost:1@evil.com/cert", "http://127.0.0.1.evil.com/", "ftp://x", "https://"] {
            assert!(!crate::broker::safe_url(bad), "{bad}");
        }
        let err = request_cert_at("http://cert.postal.bot/cert", "csr", "acme", "tok").unwrap_err();
        assert!(err.to_string().contains("https only"), "{err}");
    }

    #[test]
    fn a_broker_redirect_is_a_failed_renewal() {
        let url = spawn_mock_broker("302 Found\r\nLocation: http://127.0.0.1:1/steal", "");
        assert!(request_cert_at(&url, "csr", "acme", "tok").is_err());
    }
}
