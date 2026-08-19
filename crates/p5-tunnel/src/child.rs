//! frpc child of `p5-agent`. Tests inject a stub binary — no live frpc.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Where to find the `frpc` binary.
#[derive(Debug, Clone)]
pub enum FrpcBinary {
    Auto,
    Explicit(PathBuf),
}

pub fn resolve_frpc(bin: &FrpcBinary) -> Result<PathBuf, String> {
    match bin {
        FrpcBinary::Explicit(p) => {
            if p.exists() {
                Ok(p.clone())
            } else {
                Err(format!("frpc not found at {}", p.display()))
            }
        }
        FrpcBinary::Auto => {
            if let Some(found) = which_in_path("frpc") {
                return Ok(found);
            }
            for cand in common_frpc_locations() {
                if is_executable(&cand) {
                    return Ok(cand);
                }
            }
            Err(
                "frpc not installed: Postal tunnel needs the frp client on PATH \
                 (or set P5_FRPC)"
                    .into(),
            )
        }
    }
}

fn common_frpc_locations() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/opt/homebrew/bin/frpc"),
        PathBuf::from("/usr/local/bin/frpc"),
        PathBuf::from("/usr/bin/frpc"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        v.push(home.join(".local/bin/frpc"));
        v.push(home.join(".postal/bin/frpc"));
    }
    v
}

fn which_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Supervised `frpc -c <toml>` (or a test stub with the same argv).
#[derive(Debug)]
pub struct TunnelChild {
    child: Option<Child>,
    pid: u32,
}

impl TunnelChild {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> bool {
        if self.child.is_none() {
            return false;
        }
        pid_alive(self.pid)
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for TunnelChild {
    fn drop(&mut self) {
        self.stop();
    }
}

fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as i32, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Spawn `bin -c config`. The binary may be a stub; argv matches real frpc.
pub fn spawn_frpc(bin: &FrpcBinary, config: &Path) -> Result<TunnelChild, String> {
    let path = resolve_frpc(bin)?;
    if !config.exists() {
        return Err(format!("frpc config missing: {}", config.display()));
    }
    let mut cmd = Command::new(&path);
    cmd.arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn frpc {}: {e}", path.display()))?;
    let pid = child.id();
    Ok(TunnelChild {
        child: Some(child),
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn stub(dir: &Path) -> PathBuf {
        let path = dir.join("frpc-stub");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$2.args\"\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn spawn_stub_no_live_frpc() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = stub(tmp.path());
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "serverAddr = \"127.0.0.1\"\n").unwrap();
        let mut child = spawn_frpc(&FrpcBinary::Explicit(bin), &cfg).unwrap();
        // Give the stub a moment to write argv.
        for _ in 0..20 {
            if cfg.with_extension("toml.args").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(child.is_alive(), "stub child should still be sleeping");
        let args = std::fs::read_to_string(cfg.with_extension("toml.args")).unwrap();
        assert!(args.contains("-c"), "{args}");
        assert!(args.contains("frpc.toml"), "{args}");
        child.stop();
        assert!(!child.is_alive());
    }

    #[test]
    fn missing_stub_is_err() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "x\n").unwrap();
        let err = spawn_frpc(&FrpcBinary::Explicit(tmp.path().join("nope")), &cfg).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }
}
