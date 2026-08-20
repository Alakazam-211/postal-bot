//! Device-code login + hostname picker.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn p5() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p5"))
}

struct Mock {
    url: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn spawn_mock(hosts_body: &'static str) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(12);
        while !stop2.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        match stream.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let first = head.lines().next().unwrap_or("");
                    let (status, body) = if first.contains("POST /postal/cli/device/token") {
                        (200u16, r#"{"token":"k2c_from_device"}"#)
                    } else if first.contains("POST /postal/cli/device") {
                        (
                            200,
                            r#"{"device_code":"dev1","user_code":"WXYZ-1234","verification_uri":"https://www.postal.bot/cli/approve","verification_uri_complete":"https://www.postal.bot/cli/approve?code=WXYZ-1234","expires_in":60,"interval":0}"#,
                        )
                    } else if first.contains("GET /postal/hosts") {
                        if hosts_body.is_empty() {
                            (404, r#"{"error":"not_found"}"#)
                        } else {
                            (200, hosts_body)
                        }
                    } else {
                        (404, r#"{"error":"not_found"}"#)
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Mock {
        url: format!("http://{addr}"),
        stop,
        handle: Some(handle),
    }
}

fn tmp_home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn login_token_label_when_plane_has_no_list() {
    let home = tmp_home();
    let mock = spawn_mock("");
    let out = p5()
        .env("P5_HOME", home.path())
        .env("HOME", home.path())
        .env("P5_PLANE_URL", &mock.url)
        .env("P5_LOGIN_NO_START", "1")
        .env_remove("P5_CONNECT_TOKEN")
        .args([
            "login",
            "--token",
            "k2c_saved",
            "--label",
            "studio",
            "--no-start",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(cfg.contains("k2c_saved"), "{cfg}");
    assert!(cfg.contains("studio"), "{cfg}");
}

#[test]
fn login_token_auto_picks_single_host() {
    let home = tmp_home();
    let mock = spawn_mock(r#"{"hosts":[{"label":"acme","plan":"free"}]}"#);
    let out = p5()
        .env("P5_HOME", home.path())
        .env("HOME", home.path())
        .env("P5_PLANE_URL", &mock.url)
        .env_remove("P5_CONNECT_TOKEN")
        .args(["login", "--token", "k2c_one", "--no-start"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(cfg.contains("acme"), "{cfg}");
}

#[test]
fn login_token_two_hosts_requires_label_without_tty() {
    let home = tmp_home();
    let mock = spawn_mock(r#"{"hosts":[{"label":"acme"},{"label":"studio","plan":"paid"}]}"#);
    let out = p5()
        .env("P5_HOME", home.path())
        .env("HOME", home.path())
        .env("P5_PLANE_URL", &mock.url)
        .env_remove("P5_CONNECT_TOKEN")
        .stdin(Stdio::null())
        .args(["login", "--token", "k2c_many", "--no-start"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--label"), "{err}");
    assert!(err.contains("acme"), "{err}");
    assert!(err.contains("studio"), "{err}");
}

#[test]
fn login_device_code_polls_then_auto_picks() {
    let home = tmp_home();
    let mock = spawn_mock(r#"{"hosts":[{"label":"acme"}]}"#);
    let out = p5()
        .env("P5_HOME", home.path())
        .env("HOME", home.path())
        .env("P5_PLANE_URL", &mock.url)
        .env("P5_LOGIN_TIMEOUT_SECS", "8")
        .env_remove("P5_CONNECT_TOKEN")
        .args(["login", "--no-browser", "--no-start"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("https://www.postal.bot/cli/approve?code=WXYZ-1234"),
        "{err}"
    );
    assert!(err.contains("any device"), "{err}");
    let cfg = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(cfg.contains("k2c_from_device"), "{cfg}");
    assert!(cfg.contains("acme"), "{cfg}");
}
